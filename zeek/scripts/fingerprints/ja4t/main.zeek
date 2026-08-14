@load ../config
@load base/protocols/conn

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
  };
}

redef record FINGERPRINT::Info += {
  ja4t: FINGERPRINT::JA4T::Info &default=Info();
};

redef record Conn::Info += {
  ja4t: string &log &default = "";
  ja4ts: string &log &default = "";
};

function get_current_packet_timestamp(): double {
  local cp = get_current_packet();
  return cp$ts_sec * 1000000.0 + cp$ts_usec;
}

function do_get_tcp_options(): TCP_Options {
  local opts: TCP_Options;
  local rph = get_current_packet_header();
  if (!rph?$tcp || rph$tcp$hl <= 20) {
    return opts;
  }

  local pkt = get_current_packet();

  if (rph$l2$encap != LINK_ETHERNET) {
    return opts;
  }

  local ip_hl: count = 0;
  if (rph?$ip) {
    ip_hl = rph$ip$hl;
  }

  # Call the C++ BiF for raw packet byte parsing
  return JA4::parse_tcp_options(pkt$data, pkt$caplen, ip_hl, rph$tcp$hl);
}

event new_connection(c: connection) {
  local rph = get_current_packet_header();
  if (!rph?$tcp || rph$tcp$flags != TH_SYN) {
    return;
  }

  if(!c?$fp) { c$fp = FINGERPRINT::Info(); }

  c$fp$ja4t$syn_window_size = rph$tcp$win;
  c$fp$ja4t$syn_opts = do_get_tcp_options();
  c$fp$ja4t$last_ts = get_current_packet_timestamp();

  ConnThreshold::set_packets_threshold(c,1,F);
  ConnThreshold::set_packets_threshold(c,2,T);
}

event ConnThreshold::packets_threshold_crossed(c: connection, threshold: count, is_orig: bool) {
  if(is_orig) {
    if(c?$fp) {
      c$fp$ja4t$synack_done = T;
    }
    return;
  }

  if(!c?$fp || c$fp$ja4t$synack_done) {
    return;
  }

  local rph = get_current_packet_header();
  if (!rph?$tcp) {
    return;
  }

  local ts = get_current_packet_timestamp();
  if (ts - c$fp$ja4t$last_ts > 120000000) {
    c$fp$ja4t$synack_done = T;
    return;
  }

  if (rph$tcp$flags & TH_RST != 0) {
    c$fp$ja4t$rst_ts = ts;
    c$fp$ja4t$synack_done = T;
    return;
  } else if (rph$tcp$flags == (TH_SYN | TH_ACK)) {
  } else {
    return;
  }

  if (threshold == 1) {
    c$fp$ja4t$synack_window_size = rph$tcp$win;
    c$fp$ja4t$synack_opts = do_get_tcp_options();
  } else {
    c$fp$ja4t$synack_delays += double_to_count(ts - c$fp$ja4t$last_ts)/1000000;
  }

  c$fp$ja4t$last_ts = ts;

  if (|c$fp$ja4t$synack_delays| == 10) {
    return;
  }
  if (FINGERPRINT::JA4TS_enabled) {
    ConnThreshold::set_packets_threshold(c,threshold + 1,F);
  }
}

event connection_state_remove(c: connection) {
  if (!FINGERPRINT::JA4T_enabled) {
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
