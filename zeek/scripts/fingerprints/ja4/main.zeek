# Copyright (c) 2024, FoxIO, All rights reserved.
# Portions Copyright 2023 Anthony Kasza
# JA4 TLS Client Fingerprinting is Open-Source, Licensed under BSD 3-Clause
# For full license text and more details, see the repo root https://github.com/FoxIO-LLC/ja4
# JA4 by John Althouse
# Script contributions by Caleb Yu, and Jo Johnson

@load ../config
@load base/protocols/ssl

module FINGERPRINT::JA4;

export {
  # The client fingerprint context and logging format
  type Info: record {
    # The connection uid which this fingerprint represents
    uid: string &log &optional;

    # The client hello fingerprint
    ja4: string &log &default="";

    # The client hello fingerprint with the client offered ordering
    o: string &log &default="";

    # The client hello fingerprint with the raw array output
    r: string &log &default="";

    # The client hello fingerprint with both the raw array output and with the client offered ordering
    ro: string &log &default="";

    # If this context is ready to be logged
    done: bool &default=F;
  };

  # Logging boilerplate
  redef enum Log::ID += { LOG };
  global log_fingerprint_ja4: event(rec: Info);
  global log_policy: Log::PolicyHook;
}

redef record FINGERPRINT::Info += {
  ja4: FINGERPRINT::JA4::Info &default=Info();
};

redef record SSL::Info += {
  ja4: string &log &default="";
};

@if(FINGERPRINT::JA4_raw) 
  redef record SSL::Info += {
    ja4_o: string &log &default="";
    ja4_r: string &log &default="";
    ja4_ro: string &log &default="";
  };
@endif

# Create the log stream and file
event zeek_init() &priority=5 {
  Log::create_stream(FINGERPRINT::JA4::LOG,
    [$columns=FINGERPRINT::JA4::Info, $ev=log_fingerprint_ja4, $path="fingerprint_ja4", $policy=log_policy]
  );
}

function do_ja4(c: connection) {
  if (!c?$fp || !c$fp?$client_hello || !c$fp$client_hello?$version || c$fp$ja4$done || !FINGERPRINT::JA4_enabled) {
    return;
  }

  # Call the C++ BiF — returns a FINGERPRINT::JA4::Info record with ja4, o, r, ro populated
  c$fp$ja4 = JA4::calculate_ja4(c, FINGERPRINT::delimiter);
  c$fp$ja4$uid = c$uid;
  c$fp$ja4$done = T;

  if(c?$ssl) {
    c$ssl$ja4 = c$fp$ja4$ja4;
    @if(FINGERPRINT::JA4_raw)
        c$ssl$ja4_o = c$fp$ja4$o;
        c$ssl$ja4_r = c$fp$ja4$r;
        c$ssl$ja4_ro = c$fp$ja4$ro;
    @endif
  }
}

event connection_state_remove(c: connection) {
  # TODO: Make this only for SSL connections
  do_ja4(c);
}

#  Just before the SSL log is written
#  Conduct operations on ClientHello record in c$fp to create JA4 record as c$fp$ja4

hook SSL::log_policy(rec: SSL::Info, id: Log::ID, filter: Log::Filter) {
  if(connection_exists(rec$id)) {
    local c = lookup_connection(rec$id);
    do_ja4(c);
  }
}
