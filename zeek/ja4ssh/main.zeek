# Copyright (c) 2024, FoxIO, LLC.
# All rights reserved.
# Licensed under FoxIO License 1.1
# For full license text and more details, see the repo root https://github.com/FoxIO-LLC/ja4
# JA4+ by John Althouse
# Zeek script by Jo Johnson

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
    
  };

  option ja4_ssh_packet_count = 200;

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

function get_mode(vec: vector of count): count {
  local freqs: table[count] of count = table();
   
  for (idx in vec) {
    local v = vec[idx];
    if(v in freqs) {
      ++freqs[v];
    } else {
      freqs[v] = 1;
    }
  }
  local max = 0;
  local mode = 0;
  for (idx in freqs) {
    local freq = freqs[idx];
    if (freq > max) {
      max = freq;
      mode = idx;
    }
  }

  return mode;
}

function do_ja4ssh(c: connection) {
  c$fp$ja4ssh$ja4ssh = fmt("c%ds%d_c%ds%d_c%ds%d", 
      get_mode(c$fp$ja4ssh$orig_pack_len),
      get_mode(c$fp$ja4ssh$resp_pack_len),
        |c$fp$ja4ssh$orig_pack_len|, 
        |c$fp$ja4ssh$resp_pack_len|, 
        c$fp$ja4ssh$orig_ack, 
        c$fp$ja4ssh$resp_ack);

      Log::write(FINGERPRINT::JA4SSH::LOG, c$fp$ja4ssh);
      c$fp$ja4ssh$resp_pack_len = vector();
      c$fp$ja4ssh$orig_pack_len = vector();  
      c$fp$ja4ssh$orig_ack = 0;
      c$fp$ja4ssh$resp_ack = 0;
}

event new_connection(c: connection) {
    
    if(!c?$fp) { c$fp = []; }

     # filter incomplete\out of order connections
    local rp = get_current_packet_header();
    if (!rp?$tcp || rp$tcp$flags != TH_SYN) {
        return;  
    }

    ConnThreshold::set_packets_threshold(c,1,F);  # start watching responses
    ConnThreshold::set_packets_threshold(c,2,T);  # start watching new orig packets after this one
}

event ConnThreshold::packets_threshold_crossed(c: connection, threshold: count, is_orig: bool) {
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
          ++c$fp$ja4ssh$orig_ack;
        } else {
          c$fp$ja4ssh$orig_pack_len += rp$tcp$dl;
        }
    } else {
        ConnThreshold::set_packets_threshold(c,threshold + 1,F); 

        if (rp$tcp$dl == 0) {
          ++c$fp$ja4ssh$resp_ack;
        } else {
          c$fp$ja4ssh$resp_pack_len += rp$tcp$dl;
        }
    }
    if(|c$fp$ja4ssh$orig_pack_len| + |c$fp$ja4ssh$resp_pack_len| >= ja4_ssh_packet_count) {
      do_ja4ssh(c);
    }
}

event ssh_client_version(c: connection, version: string) {
    c$fp$ja4ssh$is_ssh = T;
    c$fp$ja4ssh$ts = c$start_time;
    c$fp$ja4ssh$uid = c$uid;
    c$fp$ja4ssh$id = c$id;
}


event ssh_server_version(c: connection, version: string) {
    c$fp$ja4ssh$is_ssh = T;
    c$fp$ja4ssh$ts = c$start_time;
    c$fp$ja4ssh$uid = c$uid;
    c$fp$ja4ssh$id = c$id;
}

event connection_state_remove(c: connection) {
  if(c?$fp && c$fp?$ja4ssh && c$fp$ja4ssh$is_ssh) {
    do_ja4ssh(c);
  }
}
