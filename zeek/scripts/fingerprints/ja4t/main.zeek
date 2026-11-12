@load ../config
@load base/protocols/conn
@load base/protocols/conn/thresholds

module FINGERPRINT::JA4T;

export {
  type TCP_Options: record {
    option_kinds: vector of count &default=vector();
    max_segment_size: count &default=0;
    window_scale: count &default=0;
  };

  type Info: record {
    syn_window_size: count &default=0;
    syn_opts: TCP_Options &default=TCP_Options();

    synack_window_size: count &default=0;
    synack_opts: TCP_Options &default=TCP_Options();
    synack_delays: vector of count &default=vector();
    synack_done: bool &default=F;
    last_ts: double &default=0;
    rst_ts: double &default=0;

    # Packet timestamps (usec) of the opening SYN and the first SYN-ACK.
    # Zero means not seen yet.
    syn_ts: double &default=0;
    synack_ts: double &default=0;

    # Zeek raises connection_SYN_packet and tcp_options as two separate
    # events for the same packet. Whichever arrives first parks its data
    # here, and the second one claims it when the packet timestamps match.
    syn_opts_done: bool &default=F;
    synack_opts_done: bool &default=F;
    orig_pending_opts: TCP::OptionList &optional;
    orig_pending_ts: double &default=0;
    resp_pending_opts: TCP::OptionList &optional;
    resp_pending_ts: double &default=0;
  };
}

redef record FINGERPRINT::Info += {
  ja4t: FINGERPRINT::JA4T::Info &default=Info();
};

redef record Conn::Info += {
  ja4t: string &log &default = "";
  ja4ts: string &log &default = "";
};

# The packet timestamp is the same for the outer and inner packet, so this
# stays correct for tunneled connections. Packet *headers* do not: the
# raw_pkt_hdr from get_current_packet_header() always describes the outermost
# packet, which is why everything below gets its TCP data from events.
function get_current_packet_timestamp(): double {
  local cp = get_current_packet();
  return cp$ts_sec * 1000000.0 + cp$ts_usec;
}

function options_to_ja4t(options: TCP::OptionList): TCP_Options {
  local opts: TCP_Options;
  for ( _, opt in options ) {
    if ( opt$kind == 0 ) {
      break;  # EOL
    }
    opts$option_kinds += opt$kind;
    if ( opt$kind == 2 && opt?$mss ) {
      opts$max_segment_size = opt$mss;
    }
    if ( opt$kind == 3 && opt?$window_scale ) {
      opts$window_scale = opt$window_scale;
    }
  }
  return opts;
}

event new_connection(c: connection) {
  if ( ! c?$fp ) { c$fp = FINGERPRINT::Info(); }
}

event connection_SYN_packet(c: connection, pkt: SYN_packet) {
  if ( ! c?$fp ) { c$fp = FINGERPRINT::Info(); }
  local j = c$fp$ja4t;
  local ts = get_current_packet_timestamp();

  if ( pkt$is_orig ) {
    # Only the SYN that opened the connection counts. This skips SYN
    # retransmissions and connections picked up mid-stream.
    if ( j$syn_ts != 0 || c$orig$num_pkts > 1 ) {
      return;
    }
    j$syn_ts = ts;
    j$last_ts = ts;
    j$syn_window_size = pkt$win_size;
    if ( j?$orig_pending_opts ) {
      if ( j$orig_pending_ts == ts ) {
        j$syn_opts = options_to_ja4t(j$orig_pending_opts);
        j$syn_opts_done = T;
      }
      delete j$orig_pending_opts;
    }
    # The client's next packet ends SYN-ACK retransmission tracking.
    ConnThreshold::set_packets_threshold(c, 2, T);
    return;
  }

  if ( j$syn_ts == 0 || j$synack_done ) {
    return;
  }

  if ( ts - j$last_ts > 120000000 ) {
    j$synack_done = T;
    return;
  }

  if ( j$synack_ts == 0 ) {
    # The SYN-ACK has to be the responder's first packet.
    if ( c$resp$num_pkts > 1 ) {
      j$synack_done = T;
      return;
    }
    j$synack_ts = ts;
    j$synack_window_size = pkt$win_size;
    if ( j?$resp_pending_opts ) {
      if ( j$resp_pending_ts == ts ) {
        j$synack_opts = options_to_ja4t(j$resp_pending_opts);
        j$synack_opts_done = T;
      }
      delete j$resp_pending_opts;
    }
  } else {
    j$synack_delays += double_to_count(ts - j$last_ts) / 1000000;
  }

  j$last_ts = ts;

  if ( ! FINGERPRINT::JA4TS_enabled || |j$synack_delays| == 10 ) {
    j$synack_done = T;
  }
}

# Raised for every TCP packet carrying options, so each branch bails out as
# early as it can once the handshake options are settled.
event tcp_options(c: connection, is_orig: bool, options: TCP::OptionList) {
  if ( ! c?$fp ) {
    return;
  }
  local j = c$fp$ja4t;

  if ( is_orig ) {
    if ( j$syn_opts_done ) {
      return;
    }
    if ( j$syn_ts != 0 ) {
      # connection_SYN_packet ran first. Keep these options only if they
      # came from that same SYN. Either way the SYN's options are settled.
      if ( j$syn_ts == get_current_packet_timestamp() ) {
        j$syn_opts = options_to_ja4t(options);
      }
      j$syn_opts_done = T;
      return;
    }
    if ( c$orig$num_pkts > 1 ) {
      j$syn_opts_done = T;  # no opening SYN, nothing to wait for
      return;
    }
    j$orig_pending_opts = options;
    j$orig_pending_ts = get_current_packet_timestamp();
  } else {
    if ( j$synack_opts_done ) {
      return;
    }
    if ( j$synack_ts != 0 ) {
      if ( j$synack_ts == get_current_packet_timestamp() ) {
        j$synack_opts = options_to_ja4t(options);
      }
      j$synack_opts_done = T;
      return;
    }
    if ( j$syn_ts == 0 || c$resp$num_pkts > 1 ) {
      j$synack_opts_done = T;
      return;
    }
    j$resp_pending_opts = options;
    j$resp_pending_ts = get_current_packet_timestamp();
  }
}

event connection_reset(c: connection) {
  if ( ! c?$fp ) {
    return;
  }
  local j = c$fp$ja4t;
  if ( j$synack_ts == 0 || j$synack_done ) {
    return;
  }
  # Only a responder RST counts ("r" in history), same as the old
  # packet-header check.
  if ( "r" !in c$history ) {
    return;
  }
  local ts = get_current_packet_timestamp();
  if ( ts - j$last_ts <= 120000000 ) {
    j$rst_ts = ts;
  }
  j$synack_done = T;
}

event ConnThreshold::packets_threshold_crossed(c: connection, threshold: count, is_orig: bool) {
  # Any further packet from the client means the handshake moved on.
  if ( is_orig && c?$fp ) {
    c$fp$ja4t$synack_done = T;
  }
}

event connection_state_remove(c: connection) {
  if ( ! FINGERPRINT::JA4T_enabled || ! c?$fp ) {
    return;
  }
  if(c$fp$ja4t$syn_window_size > 0) {
    c$conn$ja4t =  fmt("%d", c$fp$ja4t$syn_window_size);
    c$conn$ja4t += FINGERPRINT::delimiter;
    if(|c$fp$ja4t$syn_opts$option_kinds| > 0) {
      c$conn$ja4t += FINGERPRINT::vector_of_count_to_str(c$fp$ja4t$syn_opts$option_kinds, "%d", "-");
    } else {
      c$conn$ja4t += "00";
    }
    c$conn$ja4t += FINGERPRINT::delimiter;
    c$conn$ja4t += fmt("%02d", c$fp$ja4t$syn_opts$max_segment_size);
    c$conn$ja4t += FINGERPRINT::delimiter;
    if(c$fp$ja4t$syn_opts$window_scale == 0) {
      c$conn$ja4t += "00";
    } else {
      c$conn$ja4t += fmt("%d", c$fp$ja4t$syn_opts$window_scale);
    }
  }
  if (FINGERPRINT::JA4TS_enabled) {
    if(c$fp$ja4t$synack_window_size > 0) {
      c$conn$ja4ts =  fmt("%d", c$fp$ja4t$synack_window_size);
      c$conn$ja4ts += FINGERPRINT::delimiter;
      if(|c$fp$ja4t$synack_opts$option_kinds| > 0) {
        c$conn$ja4ts += FINGERPRINT::vector_of_count_to_str(c$fp$ja4t$synack_opts$option_kinds, "%d", "-");
      } else {
        c$conn$ja4ts += "00";
      }
      c$conn$ja4ts += FINGERPRINT::delimiter;
      c$conn$ja4ts += fmt("%02d", c$fp$ja4t$synack_opts$max_segment_size);
      c$conn$ja4ts += FINGERPRINT::delimiter;
      if(c$fp$ja4t$synack_opts$window_scale == 0) {
        c$conn$ja4ts += "00";
      } else {
        c$conn$ja4ts += fmt("%d", c$fp$ja4t$synack_opts$window_scale);
      }
      if(|c$fp$ja4t$synack_delays| > 0) {
        c$conn$ja4ts += FINGERPRINT::delimiter;
        c$conn$ja4ts += FINGERPRINT::vector_of_count_to_str(c$fp$ja4t$synack_delays, "%d", "-");
        if(c$fp$ja4t$rst_ts > 0) {
          c$conn$ja4ts += fmt("-R%d", double_to_count(c$fp$ja4t$rst_ts - c$fp$ja4t$last_ts)/1000000);
        }
      }
    }
  }
}
