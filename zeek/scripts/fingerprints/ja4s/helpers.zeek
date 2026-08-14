module FINGERPRINT::JA4S;

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

# For each extension, ignoring GREASE, build up an array of codes in the order they appear
event ssl_extension(c: connection, is_client: bool, code: count, val: string) {
  if(!c?$fp) { c$fp = FINGERPRINT::Info(); }
  if (code in FINGERPRINT::TLS_GREASE_TYPES) { return; }
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
