# Copyright (c) 2024, FoxIO, LLC.
# All rights reserved.
# Licensed under FoxIO License 1.1
# For full license text and more details, see the repo root https://github.com/FoxIO-LLC/ja4
# JA4+ by John Althouse
# Zeek script by Jo Johnson

@load ../config
module FINGERPRINT::JA4S;

export {
  # The server fingerprint context and logging format
  type Info: record {
    # The connection uid which this fingerprint represents
    uid: string &log &optional;

    # The server hello fingerprint
    ja4s: string &log &default="";

    # The server hello fingerprint with the raw array output
    r: string &log &default="";

    # If this context is ready to be logged
    done: bool &default=F;
  };

  # Logging boilerplate
  redef enum Log::ID += { LOG };
  global log_fingerprint_ja4s: event(rec: Info);
  global log_policy: Log::PolicyHook;
}

redef record FINGERPRINT::Info += {
  ja4s: FINGERPRINT::JA4S::Info &default=Info();
};

export {
  type ServerHello: record {

    # The highest TLS version found in the supported versions extension
    # or the TLS record
    version: count &optional;

    cipher: count &optional;

    # The extensions present in the ServerHello, GREASE removed
    extension_codes: vector of count &default=vector();

    alpn: string &default = "00";

    is_complete: bool &default=F;
  };
}

redef record FINGERPRINT::Info += {
  server_hello: ServerHello &default=ServerHello();
};

redef record SSL::Info += {
  ja4s: string &log &default="";
};

@if(FINGERPRINT::JA4S_raw) 
  redef record SSL::Info += {
    ja4s_r: string &log &default="";
  };
@endif

# Create the log stream and file
event zeek_init() &priority=5 {
  Log::create_stream(FINGERPRINT::JA4S::LOG,
    [$columns=FINGERPRINT::JA4S::Info, $ev=log_fingerprint_ja4s, $path="fingerprint_ja4s", $policy=log_policy]
  );
}

event ssl_server_hello(c: connection, version: count, record_version: count, possible_ts: time, 
  server_random: string, session_id: string, cipher: count, comp_method: count) {
  if(!c?$fp) { c$fp = FINGERPRINT::Info(); }
  if(c$fp$server_hello$is_complete) { return; }
  
  if (!c$fp$server_hello?$version) {
    c$fp$server_hello$version = version;
  }
  c$fp$server_hello$cipher = cipher;
  c$fp$server_hello$is_complete = T;
}

# For each extension, ignoring GREASE, build up an array of code in the order they appear
event ssl_extension(c: connection, is_client: bool, code: count, val: string) {
  if(!c?$fp) { c$fp = FINGERPRINT::Info(); }
  if (code in FINGERPRINT::TLS_GREASE_TYPES) { return; }  # Will we see grease from the server?
  if (!is_client) {
    if(c$fp$server_hello$is_complete) { return; }
    c$fp$server_hello$extension_codes += code;
  }
}

# Grab the server selected ALPN
event ssl_extension_application_layer_protocol_negotiation(c: connection, is_client: bool, protocols: string_vec) {
  if(!c?$fp) { c$fp = FINGERPRINT::Info(); }
  if (!is_client && |protocols| > 0) {
    if(c$fp$server_hello$is_complete) { return; }
    # NOTE:  Assumes the server only returns one ALPN, there might be a bypass if multiple are returned and the last
    # or a random one is used
    c$fp$server_hello$alpn = protocols[0];
  }
}

# If the supported versions extension is present, find the largest offered version and store it
event ssl_extension_supported_versions(c: connection, is_client: bool, versions: index_vec) {
  if(!c?$fp) { c$fp = FINGERPRINT::Info(); }
  if (!is_client) {
    local largest: count = 0;
    for (idx in versions) {
      local val = versions[idx];
      if (val in FINGERPRINT::TLS_GREASE_TYPES) {
        next;
      }
      if (val > largest) {
        largest = val;
      }
    }
    c$fp$server_hello$version = largest;
  }
}

# Make the JA4S_a string
function make_a(c: connection): string {
  local proto: string = "t";
  if ("QUIC" in c$service) {
    proto = "q";
  }

  # TODO - Investigate zeek bug returning invalid versions (testing\tls-bad-version.pcapng)
  local version: string = "00";
  if ( c$fp$server_hello$version in FINGERPRINT::TLS_VERSION_MAPPER ) {
    version = FINGERPRINT::TLS_VERSION_MAPPER[c$fp$server_hello$version];
  } 

  local ec_count = "00";
  if (|c$fp$server_hello$extension_codes| > 99) {
    ec_count = "99";
  } else {
    ec_count = fmt("%02d", |c$fp$server_hello$extension_codes|);
  }

  local alpn: string = "00";
  if (c$fp$server_hello?$alpn && |c$fp$server_hello$alpn| > 0) {
    alpn = c$fp$server_hello$alpn[0] + c$fp$server_hello$alpn[-1];
  }

  local a: string = "";  
  a = proto;
  a += version;
  a += ec_count;
  a += alpn;

  return a;
}

function do_ja4s(c: connection) {
  if (!c?$fp || !c$fp?$server_hello || !c$fp$server_hello?$version|| c$fp$ja4s$done) { return; }

  local ja4s_a = make_a(c);
  local ja4s_b = fmt("%04x", c$fp$server_hello$cipher);
  local ja4s_c = FINGERPRINT::vector_of_count_to_str(c$fp$server_hello$extension_codes);
  local delim =  FINGERPRINT::delimiter;

  c$fp$ja4s$uid = c$uid;  
  c$fp$ja4s$r = ja4s_a + delim + ja4s_b + delim + ja4s_c;
  c$fp$ja4s$ja4s = ja4s_a + delim + ja4s_b + delim + FINGERPRINT::sha256_or_null__12(ja4s_c);

  if(c?$ssl) {
    c$ssl$ja4s = c$fp$ja4s$ja4s;
    @if(FINGERPRINT::JA4S_raw) 
      c$ssl$ja4s_r = c$fp$ja4s$r;
    @endif
  }
  c$fp$ja4s$done = T;

  #Log::write(FINGERPRINT::JA4S::LOG, c$fp$ja4s);
}

event connection_state_remove(c: connection) {
  # TODO: Make this only for SSL connections
  do_ja4s(c);
}

hook SSL::log_policy(rec: SSL::Info, id: Log::ID, filter: Log::Filter) {
  if(connection_exists(rec$id)) {
    local c = lookup_connection(rec$id);
    do_ja4s(c);
  }
}
