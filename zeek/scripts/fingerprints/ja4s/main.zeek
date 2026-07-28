@load ../config
@load base/protocols/ssl

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

function do_ja4s(c: connection) {
  if (!c?$fp || !c$fp?$server_hello || !c$fp$server_hello?$version || c$fp$ja4s$done || !FINGERPRINT::JA4S_enabled) {
    return;
  }

  # Call the C++ BiF — returns a FINGERPRINT::JA4S::Info record with ja4s and r populated
  c$fp$ja4s = JA4::calculate_ja4s(c, FINGERPRINT::delimiter);
  c$fp$ja4s$uid = c$uid;
  c$fp$ja4s$done = T;

  if(c?$ssl) {
    c$ssl$ja4s = c$fp$ja4s$ja4s;
    @if(FINGERPRINT::JA4S_raw)
      c$ssl$ja4s_r = c$fp$ja4s$r;
    @endif
  }
}

event connection_state_remove(c: connection) {
  do_ja4s(c);
}

# Just before the SSL log is written
hook SSL::log_policy(rec: SSL::Info, id: Log::ID, filter: Log::Filter) {
  if(connection_exists(rec$id)) {
    local c = lookup_connection(rec$id);
    do_ja4s(c);
  }
}
