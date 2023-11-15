# Copyright (c) 2023, FoxIO, LLC.
# All rights reserved.
# JA4 TLS Client Fingerprinting is Open-Source, Licensed under BSD 3-Clause
# For full license text and more details, see the repo root https://github.com/FoxIO-LLC/ja4
# JA4 by John Althouse
# Zeek script by Anthony Kasza and Caleb Yu

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
  ja4: FINGERPRINT::JA4::Info &default=[];
};

redef record SSL::Info += {
  ja4: string &optional &log;
  # Uncomment if you wish to log raw and/or unsorted here and at the bottom of script
  # ja4_r: string &optional &log;
  # ja4_o: string &optional &log;
  # ja4_ro: string &optional &log;
};

# Create the log stream and file
event zeek_init() &priority=5 {
  Log::create_stream(FINGERPRINT::JA4::LOG,
    [$columns=FINGERPRINT::JA4::Info, $ev=log_fingerprint_ja4, $path="fingerprint_ja4", $policy=log_policy]
  );
}

# Make the JA4_a string
function make_a(c: connection): string {
  local proto: string = "0";
  local proto_string: string = fmt("%s",c$id$orig_p);
  proto_string = proto_string[-3:];
  if (proto_string == "tcp") {
    proto = "t";
  # TODO - does this eeven work? which quic analzyer do i need to use?
  # TODO - DTLS is not TCP but its also not QUIC. The standard doesn't handle DTLS?
  } else if (proto_string == "udp") {
    proto = "q";
  }

  # I wonder why the standard doesn't differential between an IP and the lack of an SNI extension?
  local sni: string = "i";
  if (c$fp$client_hello?$sni && |c$fp$client_hello$sni| > 0) {
    # This doesn't actually validate that the SNI value is a domain name.
    #  Doign that would require checking that the string has a value TLD, a valid number of 
    #  subdomains, only valid characters, and likely other checks too.
    #  Consider the example SNI value of "foo.localhost", it's not a real domain but is also not an IP address
    if (c$fp$client_hello$sni[0] != fmt("%s", c$id$resp_h)) {
      sni = "d";
    }
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

  local version = FINGERPRINT::TLS_VERSION_MAPPER[c$fp$client_hello$version];

  local a: string = "";  
  a = proto;
  a += version;
  a += sni;
  a += cs_count;
  a += ec_count;
  a += alpn;
  return a;
}

# Format a vector of count type to a string type
function vector_of_count_to_str(input: vector of count, format_str: string &default="%04x", dlimit: string &default=","): string {
  local output: string = "";
  for (idx, val in input) {
    output += fmt(format_str, val);
    if (idx < |input|-1) {
      output += dlimit;
    }
  }
  return output;
}

# Sort a vector of count by the count values
function order_them(input: vector of count): vector of count {
  local ordering: vector of count = order(input);
  local output: vector of count = vector();
  for (idx, val in ordering) {
    output += input[val];
  }
  return output;
}

# Produce the JA4_b hash value
function b_hash(input: vector of count): string {
  local sha256_object = sha256_hash_init();
  sha256_hash_update(sha256_object, vector_of_count_to_str(input));
  return sha256_hash_finish(sha256_object)[:12];
}

# Produce the JA4_c hash value
function c_hash(input: string): string {
  local sha256_object = sha256_hash_init();
  sha256_hash_update(sha256_object, input);
  return sha256_hash_finish(sha256_object)[:12];
}

# Just before the connection's state is flushed from the sensor's memory...
# Conduct operations on ClientHello record in c$fp to create JA4 record as c$fp$ja4
event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time,
 client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec) {
  if (!c?$fp || !c$fp?$client_hello) { return; }

  c$fp$ja4$uid = c$uid;

  local ja4_a: string = FINGERPRINT::JA4::make_a(c);
  local ja4_b: vector of count = c$fp$client_hello$cipher_suites;

  local extensions: vector of count = vector();
  for (idx, code in c$fp$client_hello$extension_codes) {
    if (code == SSL::SSL_EXTENSION_SERVER_NAME || code == SSL::SSL_EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION) {
      next;
    }
    extensions += code;
  }

  local ja4_c: string = vector_of_count_to_str(order_them(extensions));
  ja4_c += FINGERPRINT::delimiter;
  ja4_c += vector_of_count_to_str(c$fp$client_hello$signature_algos);

  # ja4, ja4, ja4, ja4, ja4, ja4. say it some more. ja4, ja4, ja4.
  c$fp$ja4$ja4 = ja4_a;
  c$fp$ja4$ja4 += FINGERPRINT::delimiter;
  c$fp$ja4$ja4 += b_hash(order_them(ja4_b));
  c$fp$ja4$ja4 += FINGERPRINT::delimiter;
  c$fp$ja4$ja4 += c_hash(ja4_c);

  # ja4_r
  c$fp$ja4$r = ja4_a;
  c$fp$ja4$r += FINGERPRINT::delimiter;
  c$fp$ja4$r += vector_of_count_to_str(order_them(ja4_b));
  c$fp$ja4$r += FINGERPRINT::delimiter;
  c$fp$ja4$r += ja4_c;

  # original extensions ordering
  ja4_c = vector_of_count_to_str(extensions);
  ja4_c += FINGERPRINT::delimiter;
  ja4_c += vector_of_count_to_str(c$fp$client_hello$signature_algos);

  # ja4_o
  c$fp$ja4$o = ja4_a;
  c$fp$ja4$o += FINGERPRINT::delimiter;
  c$fp$ja4$o += b_hash(ja4_b);
  c$fp$ja4$o += FINGERPRINT::delimiter;
  c$fp$ja4$o += c_hash(ja4_c);

  # ja4_ro
  c$fp$ja4$ro = ja4_a;
  c$fp$ja4$ro += FINGERPRINT::delimiter;
  c$fp$ja4$ro += vector_of_count_to_str(ja4_b);
  c$fp$ja4$ro += FINGERPRINT::delimiter;
  c$fp$ja4$ro += ja4_c;

  # fingerprinting is marked as done and it is logged
  c$fp$ja4$done = T;
  Log::write(FINGERPRINT::JA4::LOG, c$fp$ja4);
  c$ssl$ja4 = c$fp$ja4$ja4;
  # Uncomment for logging raw and unsorted JA4
  # c$ssl$ja4_r = c$fp$ja4$r; # JA4_r (raw fingerprint)
  # c$ssl$ja4_o = c$fp$ja4$o; # JA4_o (Original Ordering, not sorted, fingerprint)
  # c$ssl$ja4_ro = c$fp$ja4$ro; # JA4_ro (raw fingerprint with original ordering, closest to what was seen on the wire)
}
