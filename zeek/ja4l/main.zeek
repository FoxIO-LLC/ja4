# Copyright (c) 2024, FoxIO, LLC.
# All rights reserved.
# Licensed under FoxIO License 1.1
# For full license text and more details, see the repo root https://github.com/FoxIO-LLC/ja4
# JA4+ by John Althouse
# Zeek script by Jo Johnson
# NOTE: JA4L can not work when traffic is out of order

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

    # Timestamps for TCP
    syn: double &default = 0;   # A
    synack: double &default = 0; # B
    ack: double &default = 0;  # C
    client_hello: double &default=0; # D  
    server_hello: double &default=0; # E
    first_client_data: double &default=0; # F

    # Timestamps for QUIC
    client_init: double &default = 0;
    server_init: double &default = 0;
    client_handshake: double &default = 0;
    server_handshake: double &default = 0;



    ttl_c: count &default = 0;
    ttl_s: count &default = 0;
  };

  # Logging boilerplate
  redef enum Log::ID += { LOG };
  global log_fingerprint_ja4l: event(rec: Info);
  global log_policy: Log::PolicyHook;

}

redef record FINGERPRINT::Info += {
  ja4l: FINGERPRINT::JA4L::Info &default=Info();
};

redef record Conn::Info += {
    ja4l: string &log &default = "";
    ja4ls: string &log &default = "";
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
    
    if(!c?$fp) { c$fp = FINGERPRINT::Info(); }
    
    local rp = get_current_packet_header();
    if (rp?$tcp && rp$tcp$flags != TH_SYN) {
        return;  
    }

    c$fp$ja4l$syn = get_current_packet_timestamp();
    if (rp?$ip) {
        c$fp$ja4l$ttl_c = rp$ip$ttl;
    } else if (rp?$ip6) {
        c$fp$ja4l$ttl_c = rp$ip6$hlim;    
    } else {
        return;  
    }

    ConnThreshold::set_packets_threshold(c,1,F);
}

event ConnThreshold::packets_threshold_crossed(c: connection, threshold: count, is_orig: bool) {
    local rp = get_current_packet_header();
    if (is_orig && threshold == 2) {
        c$fp$ja4l$ack = get_current_packet_timestamp();
        c$fp$ja4l$ja4l_c = cat(double_to_count( (c$fp$ja4l$ack - c$fp$ja4l$synack) / 2.0));
        c$fp$ja4l$ja4l_c += FINGERPRINT::delimiter;
        c$fp$ja4l$ja4l_c += cat(c$fp$ja4l$ttl_c);
        c$fp$ja4l$uid = c$uid;
        c$fp$ja4l$ts = c$start_time;
        c$fp$ja4l$id = c$id;
    } else if (is_orig && c?$fp && c$fp$ja4l$server_hello != 0 && c$fp$ja4l$first_client_data == 0) {
        if (rp?$tcp && rp$tcp$dl == 0) {
            # wait for actual  data
            ConnThreshold::set_packets_threshold(c,threshold + 1,T);              
            return;
        }
        c$fp$ja4l$first_client_data = get_current_packet_timestamp(); 
        c$fp$ja4l$ja4l_c += FINGERPRINT::delimiter;
        c$fp$ja4l$ja4l_c += cat(double_to_count( (c$fp$ja4l$first_client_data - c$fp$ja4l$server_hello) / 2.0));
    } else if (threshold != 1) {
        return; 
    } else {
        c$fp$ja4l$synack = get_current_packet_timestamp();
        if(!rp?$tcp) {
            # UDP only works for QUIC that is handled separately
            return;
        }
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

        ConnThreshold::set_packets_threshold(c,c$orig$num_pkts + 1,T);  
    }
}

event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time,
 client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec) 
{
    if (c?$fp && c$fp$ja4l$client_hello == 0) {
        c$fp$ja4l$client_hello = get_current_packet_timestamp();
    }
}

event ssl_server_hello(c: connection, version: count, record_version: count, possible_ts: time, 
  server_random: string, session_id: string, cipher: count, comp_method: count) 
{
    local rp = get_current_packet_header();
    if(!rp?$tcp) {
            # UDP only works for QUIC that is handled separately
            return;
        }
    if (c?$fp && c$fp$ja4l$server_hello == 0) {
        c$fp$ja4l$server_hello = get_current_packet_timestamp();
        c$fp$ja4l$ja4l_s += FINGERPRINT::delimiter;
        c$fp$ja4l$ja4l_s += cat(double_to_count((c$fp$ja4l$server_hello - c$fp$ja4l$client_hello) / 2.0 ));
        # get F on next orig packet
        ConnThreshold::set_packets_threshold(c,c$orig$num_pkts + 1,T);
    }
}

event QUIC::initial_packet(c: connection, is_orig: bool, version: count, dcid: string, scid: string) {

    if(!c?$fp) { c$fp = FINGERPRINT::Info(); }

    local rp = get_current_packet_header();
    if (is_orig) {
        if (rp?$ip) {
            c$fp$ja4l$ttl_c = rp$ip$ttl;
        } else if (rp?$ip6) {
            c$fp$ja4l$ttl_c = rp$ip6$hlim;    
        } else {
            return;  
        }
        c$fp$ja4l$client_init = get_current_packet_timestamp();
        
    } else {
        if (rp?$ip) {
            c$fp$ja4l$ttl_s = rp$ip$ttl;
        } else if (rp?$ip6) {
            c$fp$ja4l$ttl_s = rp$ip6$hlim;    
        } else {
            return;  
        }
        c$fp$ja4l$server_init = get_current_packet_timestamp();
        c$fp$ja4l$ja4l_s = cat(double_to_count( (c$fp$ja4l$server_init - c$fp$ja4l$client_init) / 2.0));
        c$fp$ja4l$ja4l_s += FINGERPRINT::delimiter;
        c$fp$ja4l$ja4l_s += cat(c$fp$ja4l$ttl_s);
        c$fp$ja4l$ja4l_s += FINGERPRINT::delimiter;
        c$fp$ja4l$ja4l_s += "q";
    }
}

event QUIC::handshake_packet(c: connection, is_orig: bool, version: count, dcid: string, scid: string) {
    if(!c?$fp || c$fp$ja4l$client_handshake != 0)  { 
        # No init packet, or client handshake already seen and logged
        return;
    }
    if (is_orig) {
        c$fp$ja4l$client_handshake = get_current_packet_timestamp();
        c$fp$ja4l$ja4l_c = cat(double_to_count( (c$fp$ja4l$client_handshake - c$fp$ja4l$server_handshake) / 2.0));
        c$fp$ja4l$ja4l_c += FINGERPRINT::delimiter;
        c$fp$ja4l$ja4l_c += cat(c$fp$ja4l$ttl_c);
        c$fp$ja4l$ja4l_c += FINGERPRINT::delimiter;
        c$fp$ja4l$ja4l_c += "q";
    } else {
            c$fp$ja4l$server_handshake = get_current_packet_timestamp();
        
    }

}

event connection_state_remove(c: connection) {
        c$conn$ja4l =  c$fp$ja4l$ja4l_c;
        c$conn$ja4ls = c$fp$ja4l$ja4l_s;
}
