# Copyright (c) 2024, FoxIO, All rights reserved.
# Portions Copyright 2023 Anthony Kasza
# JA4 TLS Client Fingerprinting is Open-Source, Licensed under BSD 3-Clause
# For full license text and more details, see the repo root https://github.com/FoxIO-LLC/ja4
# JA4 by John Althouse
# Script contributions by Caleb Yu, and Jo Johnson

@load ../config

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

# Make the JA4_a string
function make_a(c: connection): string {
  local proto: string = "0";
  if (c?$conn && c$conn$proto == udp && "QUIC" in c$service) {
    proto = "q";
  } else {
    # HACK: If  it's not quic, assume it's TCP since we can't get here without SSL
    # TODO: Try to note the protocol when it's available in the fp$ja4 object
    proto = "t";
  }

  # I wonder why the standard doesn't differential between an IP and the lack of an SNI extension?
  local sni: string = "i";
  if (c$fp$client_hello?$sni && |c$fp$client_hello$sni| > 0) {
    # This doesn't actually validate that the SNI value is a domain name.
    #  Doign that would require checking that the string has a value TLD, a valid number of 
    #  subdomains, only valid characters, and likely other checks too.
    #  Consider the example SNI value of "foo.localhost", it's not a real domain but is also not an IP address
      sni = "d";
  }

  local alpn: string = "00";
  if (c$fp$client_hello?$alpns && |c$fp$client_hello$alpns| > 0) {
    alpn = c$fp$client_hello$alpns[0][0] + c$fp$client_hello$alpns[0][-1];
  }

  local cs_count = "00";
  if (|c$fp$client_hello$cipher_suites| > 99) {
    cs_count = cat(99);
  } else {
    cs_count = fmt("%02d", |c$fp$client_hello$cipher_suites|);
  }

  local ec_count = "00";
  if (|c$fp$client_hello$extension_codes| > 99) {
    ec_count = cat(99);
  } else {
    ec_count = fmt("%02d", |c$fp$client_hello$extension_codes|);
  }

  # TODO - Investigate zeek bug returning invalid versions (testing\tls-bad-version.pcapng)
  local version: string = "00";
  if ( c$fp$client_hello$version in FINGERPRINT::TLS_VERSION_MAPPER ) {
    version = FINGERPRINT::TLS_VERSION_MAPPER[c$fp$client_hello$version];
  } 

  local a: string = "";  
  a = proto;
  a += version;
  a += sni;
  a += cs_count;
  a += ec_count;
  a += alpn;
  return a;
}

# Produce the JA4_b hash value
function b_hash(input: vector of count): string {
  return FINGERPRINT::sha256_or_null__12(FINGERPRINT::vector_of_count_to_str(input));
}

# Produce the JA4_c hash value
function c_hash(input: string): string {  
  return FINGERPRINT::sha256_or_null__12(input);
}

function do_ja4(c: connection) {
  if (!c?$fp || !c$fp?$client_hello || !c$fp$client_hello?$version || c$fp$ja4$done) { return; }
  

  c$fp$ja4$uid = c$uid;

  local ja4_a: string = FINGERPRINT::JA4::make_a(c);
  local ja4_b: vector of count = c$fp$client_hello$cipher_suites;

  local extensions: vector of count = vector();
  for (idx in c$fp$client_hello$extension_codes) {
    local code = c$fp$client_hello$extension_codes[idx];
    if (code == SSL::SSL_EXTENSION_SERVER_NAME || code == SSL::SSL_EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION) {
      next;
    }
    extensions += code;
  }

  local ja4_c: string = FINGERPRINT::vector_of_count_to_str(
    FINGERPRINT::order_vector_of_count(extensions));
  if (|c$fp$client_hello$signature_algos| > 0) {
    ja4_c += FINGERPRINT::delimiter;
    ja4_c += FINGERPRINT::vector_of_count_to_str(c$fp$client_hello$signature_algos);
  }

  # ja4, ja4, ja4, ja4, ja4, ja4. say it some more. ja4, ja4, ja4.
  c$fp$ja4$ja4 = ja4_a;
  c$fp$ja4$ja4 += FINGERPRINT::delimiter;
  c$fp$ja4$ja4 += b_hash(FINGERPRINT::order_vector_of_count(ja4_b));
  c$fp$ja4$ja4 += FINGERPRINT::delimiter;
  c$fp$ja4$ja4 += c_hash(ja4_c);

  # ja4_r
  c$fp$ja4$r = ja4_a;
  c$fp$ja4$r += FINGERPRINT::delimiter;
  c$fp$ja4$r += FINGERPRINT::vector_of_count_to_str(
    FINGERPRINT::order_vector_of_count(ja4_b));
  c$fp$ja4$r += FINGERPRINT::delimiter;
  c$fp$ja4$r += ja4_c;

  # original extensions ordering, including APPLN and SNI
  ja4_c = FINGERPRINT::vector_of_count_to_str(c$fp$client_hello$extension_codes);
  if (|c$fp$client_hello$signature_algos| > 0) {
    ja4_c += FINGERPRINT::delimiter;
    ja4_c += FINGERPRINT::vector_of_count_to_str(c$fp$client_hello$signature_algos);
  }

  # ja4_o
  c$fp$ja4$o = ja4_a;
  c$fp$ja4$o += FINGERPRINT::delimiter;
  c$fp$ja4$o += b_hash(ja4_b);
  c$fp$ja4$o += FINGERPRINT::delimiter;
  c$fp$ja4$o += c_hash(ja4_c);

  # ja4_ro
  c$fp$ja4$ro = ja4_a;
  c$fp$ja4$ro += FINGERPRINT::delimiter;
  c$fp$ja4$ro += FINGERPRINT::vector_of_count_to_str(ja4_b);
  c$fp$ja4$ro += FINGERPRINT::delimiter;
  c$fp$ja4$ro += ja4_c;

  # fingerprinting is marked as done and it is logged
  
  if(c?$ssl) {
    c$ssl$ja4 = c$fp$ja4$ja4;
    @if(FINGERPRINT::JA4_raw) 
        c$ssl$ja4_o = c$fp$ja4$o;
        c$ssl$ja4_r = c$fp$ja4$r;
        c$ssl$ja4_ro = c$fp$ja4$ro;
    @endif
  }
  c$fp$ja4$done = T;
  # uncomment for detailed separate log
  # Log::write(FINGERPRINT::JA4::LOG, c$fp$ja4);
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
