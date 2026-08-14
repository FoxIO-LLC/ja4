@load ../config
@load base/protocols/conn/thresholds

module FINGERPRINT::JA4SSH;

export {
  # The fingerprint context and logging format
  type Info: record {
    # The connection uid which this fingerprint represents
    ts: time &log &optional;
    uid: string &log &optional;
    id: conn_id &log &optional;

    # The ssh fingerprint
    ja4ssh: string &log &default="";
    is_ssh: bool &default = F;
    orig_pack_len: vector of count &default = vector();
    resp_pack_len: vector of count &default = vector();
    orig_ack: count &default = 0;
    resp_ack: count &default = 0;
    ja4ssh_fingerprint_count: count &default = 0;
  };

  option ja4_ssh_packet_count = 200;

  # Maximum number of fingerprints to produce, 0 means no maximum.
  option ja4_ssh_max_fingerprints: count = 0;

  # Logging boilerplate
  redef enum Log::ID += { LOG };
  global log_fingerprint_ja4ssh: event(rec: Info);
  global log_policy: Log::PolicyHook;

}

redef record FINGERPRINT::Info += {
  ja4ssh: FINGERPRINT::JA4SSH::Info &default=Info();
};

# Create the log stream and file
event zeek_init() &priority=5 {
  Log::create_stream(FINGERPRINT::JA4SSH::LOG,
    [$columns=FINGERPRINT::JA4SSH::Info, $ev=log_fingerprint_ja4ssh, $path="ja4ssh", $policy=log_policy]
  );
}

function do_ja4ssh(c: connection) {
  ++c$fp$ja4ssh$ja4ssh_fingerprint_count;
  c$fp$ja4ssh$ja4ssh = JA4::calculate_ja4ssh(c);

  Log::write(FINGERPRINT::JA4SSH::LOG, c$fp$ja4ssh);
  c$fp$ja4ssh$resp_pack_len = vector();
  c$fp$ja4ssh$orig_pack_len = vector();
  c$fp$ja4ssh$orig_ack = 0;
  c$fp$ja4ssh$resp_ack = 0;
}

event ConnThreshold::packets_threshold_crossed(c: connection, threshold: count, is_orig: bool) {
    if (!FINGERPRINT::JA4SSH_enabled) {
        return;
    }
    if (ja4_ssh_max_fingerprints != 0 && c$fp$ja4ssh$ja4ssh_fingerprint_count == ja4_ssh_max_fingerprints) {
        return;
    }
    if (!c$fp$ja4ssh$is_ssh && threshold > 5) {   # TODO: does this need to be configurable?
        return;
    }
    local rp = get_current_packet_header();
    if(!rp?$tcp) {
      return;  # not us
    }
    if (is_orig) {
        ConnThreshold::set_packets_threshold(c,threshold + 1,T);

        if (rp$tcp$dl == 0) {
          if (rp$tcp$flags == 0x10) {
            ++c$fp$ja4ssh$orig_ack;
          }
        } else {
          c$fp$ja4ssh$orig_pack_len += rp$tcp$dl;
        }
    } else {
        ConnThreshold::set_packets_threshold(c,threshold + 1,F);

        if (rp$tcp$dl == 0) {
          if (rp$tcp$flags == 0x10) {
            ++c$fp$ja4ssh$resp_ack;
          }
        } else {
          c$fp$ja4ssh$resp_pack_len += rp$tcp$dl;
        }
    }
    if(|c$fp$ja4ssh$orig_pack_len| + |c$fp$ja4ssh$resp_pack_len| >= ja4_ssh_packet_count) {
      do_ja4ssh(c);
    }
}

event connection_state_remove(c: connection) {
  if (!FINGERPRINT::JA4SSH_enabled) {
    return;
  }
  if(c?$fp && c$fp?$ja4ssh && c$fp$ja4ssh$is_ssh && (ja4_ssh_max_fingerprints == 0 || c$fp$ja4ssh$ja4ssh_fingerprint_count < ja4_ssh_max_fingerprints)) {
    do_ja4ssh(c);
  }
}
