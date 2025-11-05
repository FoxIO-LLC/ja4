# Copyright (c) 2025, FoxIO, LLC.
# All rights reserved.
# Licensed under FoxIO License 1.1
# For full license text and more details, see the repo root https://github.com/FoxIO-LLC/ja4
# JA4+ by John Althouse
# Zeek script by Jo Johnson

module FINGERPRINT::JA4D;

export {
  # The fingerprint context and logging format
  type Info: record {
    # The connection uid which this fingerprint represents
    ts: time &log &optional;
    uid: string &log &optional;
    id: conn_id &log &optional;

    # The ssh fingerprint
    ja4d: string &log &default="";
    vendor_class_id: string &log &default="";
    hostname: string &log &optional &default="";
  };


  # Logging boilerplate
  redef enum Log::ID += { LOG };
  global log_fingerprint_ja4d: event(rec: Info);
  global log_policy: Log::PolicyHook;

}

# Create the log stream and file
event zeek_init() &priority=5 {
  Log::create_stream(FINGERPRINT::JA4D::LOG,
    [$columns=FINGERPRINT::JA4D::Info, $ev=log_fingerprint_ja4d, $path="ja4d", $policy=log_policy]
  );
}


function get_dhcp_message_type(msg: DHCP::Msg): string {
  if (!msg?$m_type) {
    return "00000";
  }

  if (msg$m_type in FINGERPRINT::JA4D::DHCP_MESSAGE_MAP) {
    return FINGERPRINT::JA4D::DHCP_MESSAGE_MAP[msg$m_type];
  }
  
  return fmt("%05d", msg$m_type); 

}

function get_max_message_size(options: DHCP::Options): string {
  if (options?$max_msg_size) {
    if (options$max_msg_size > 9999) {
      return "9999";
    }
    return fmt("%04d", options$max_msg_size);
  }
  return "0000";
}

function get_request_ip(options: DHCP::Options): string {
  if (options?$addr_request) {
    return "i";
  }
  return "n";
}

function get_FQDN(options: DHCP::Options): string {
  if (options?$client_fqdn) {
    return "d";
  }
  return "n";
}

function get_option_list(options: DHCP::Options): string {
  if (!options?$options) {
    # Not sure this is actually possible since you need at least option 53 to be DHCP and not just BOOTP
    return "00";
  }
  return FINGERPRINT::vector_of_count_to_str(options$options, "%d", "-", FINGERPRINT::JA4D::DHCP_SKIP_OPTIONS);
}

function get_parameter_list(options: DHCP::Options): string {
  if(!options?$param_list || |options$param_list| == 0) {
    return "00";
  }
  return FINGERPRINT::vector_of_count_to_str(options$param_list, "%d", "-");
}

function do_ja4d(c: connection, msg: DHCP::Msg, options: DHCP::Options) {
  local ja4d: FINGERPRINT::JA4D::Info;
  ja4d$ts = c$start_time;
  ja4d$uid = c$uid;
  ja4d$id = c$id;
  
  if (options?$host_name) {
    ja4d$hostname = options$host_name;
  }
  if (options?$vendor_class) {
    ja4d$vendor_class_id = options$vendor_class;
  }

  ja4d$ja4d += get_dhcp_message_type(msg) + get_max_message_size(options);
  ja4d$ja4d += get_request_ip(options)+get_FQDN(options);
  ja4d$ja4d += FINGERPRINT::delimiter;
  ja4d$ja4d += get_option_list(options);
  ja4d$ja4d += FINGERPRINT::delimiter;
  ja4d$ja4d += get_parameter_list(options);


#  print(options);
  
  Log::write(FINGERPRINT::JA4D::LOG, ja4d);
}

# We log per DHCP message for this fingerprint instead of aggregating across a 
# DHCP conversation
event dhcp_message(c: connection, is_orig: bool, msg: DHCP::Msg, options: DHCP::Options) {
    # This is where we can add throttling or message type filtering
    do_ja4d(c, msg, options);
}
