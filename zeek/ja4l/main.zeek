# Copyright (c) 2024, FoxIO, LLC.
# All rights reserved.
# Licensed under FoxIO License 1.1
# For full license text and more details, see the repo root https://github.com/FoxIO-LLC/ja4
# JA4+ by John Althouse
# Zeek script by Johanna Johnson

module FINGERPRINT::JA4L;

export {
  # The fingerprint context and logging format
  type Info: record {
    # The connection uid which this fingerprint represents
    ts: time &log &optional;
    uid: string &log &optional;
    id: conn_id &log &optional;

    # The lightspeed fingerprints
    ja4l_c: string &log &default="";
    ja4l_s: string &log &default="";

    syn: double &default = 0;   # A
    synack: double &default = 0; # B
    ack: double &default = 0;  # C

    ttl_c: count &default = 0;
    ttl_s: count &default = 0;
  };

  # Logging boilerplate
  redef enum Log::ID += { LOG };
  global log_fingerprint_ja4l: event(rec: Info);
  global log_policy: Log::PolicyHook;

}

redef record FINGERPRINT::Info += {
  ja4l: FINGERPRINT::JA4L::Info &default=[];
};

# Create the log stream and file
event zeek_init() &priority=5 {
  Log::create_stream(FINGERPRINT::JA4L::LOG,
    [$columns=FINGERPRINT::JA4L::Info, $ev=log_fingerprint_ja4l, $path="fingerprint_ja4l", $policy=log_policy]
  );
}

function get_current_packet_timestamp(): double {
    local cp = get_current_packet();
    return cp$ts_sec * 1000000.0 + cp$ts_usec;
}

event new_connection(c: connection) {
    
    if(!c?$fp) { c$fp = []; }

    c$fp$ja4l$syn = get_current_packet_timestamp();
    
    # client TTL will be the flag for if lightspeed can be calculated
    local rp = get_current_packet_header();
    if (rp?$tcp && rp$tcp$flags != TH_SYN) {
        return;  
    }
    if (rp?$ip) {
        c$fp$ja4l$ttl_c = rp$ip$ttl;
    } else if (rp?$ip6) {
        c$fp$ja4l$ttl_c = rp$ip6$hlim;    
    } else {
        return;  # TODO: IPv6
    }

    ConnThreshold::set_packets_threshold(c,1,F);
}

event ConnThreshold::packets_threshold_crossed(c: connection, threshold: count, is_orig: bool) {
    if (is_orig && threshold == 2) {
        c$fp$ja4l$ack = get_current_packet_timestamp();
        c$fp$ja4l$ja4l_c = cat(double_to_count( (c$fp$ja4l$ack - c$fp$ja4l$synack) / 2.0));
        c$fp$ja4l$ja4l_c += FINGERPRINT::delimiter;
        c$fp$ja4l$ja4l_c += cat(c$fp$ja4l$ttl_c);
        c$fp$ja4l$uid = c$uid;
        c$fp$ja4l$ts = c$start_time;
        c$fp$ja4l$id = c$id;
        Log::write(FINGERPRINT::JA4L::LOG, c$fp$ja4l);
    } else if (threshold != 1) {
        return; 
    } else {
        c$fp$ja4l$synack = get_current_packet_timestamp();
        local rp = get_current_packet_header();
        if (rp?$ip) {
            c$fp$ja4l$ttl_s = rp$ip$ttl;
        } else if (rp?$ip6) {
            c$fp$ja4l$ttl_s = rp$ip6$hlim;
        } else {
            return;   #breaks the chain
        }
        c$fp$ja4l$ja4l_s = cat(double_to_count((c$fp$ja4l$synack - c$fp$ja4l$syn) / 2.0 ));
        c$fp$ja4l$ja4l_s += FINGERPRINT::delimiter;
        c$fp$ja4l$ja4l_s += cat(c$fp$ja4l$ttl_s);
        ConnThreshold::set_packets_threshold(c,threshold + 1,T);
    }
}
