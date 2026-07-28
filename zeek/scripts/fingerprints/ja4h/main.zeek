# Copyright (c) 2024, FoxIO, LLC.
# All rights reserved.
# Licensed under FoxIO License 1.1
# For full license text and more details, see the repo root https://github.com/FoxIO-LLC/ja4
# JA4+ by John Althouse
# Zeek script by Jo Johnson

@load ../config
@load base/protocols/http/main

module FINGERPRINT::JA4H;

export {
  # The fingerprint context and logging format
  type Info: record {
    # The connection uid which this fingerprint represents
    uid: string &log &optional;

    # The HTTP client fingerprints
    ja4h: string &log &default="";
    ja4h_r: string &log &default="";
    ja4h_ro: string &log &default="";
  };

  # Logging boilerplate
  redef enum Log::ID += { LOG };
  global log_fingerprint_ja4h: event(rec: Info);
  global log_policy: Log::PolicyHook;

}

redef record FINGERPRINT::Info += {
  ja4h: FINGERPRINT::JA4H::Info &default=Info();
};

redef record HTTP::Info += {
    ja4h: string &log &default="";
};

@if(FINGERPRINT::JA4H_raw) 
    redef record HTTP::Info += {
        ja4h_r: string &log &default="";
        ja4h_ro: string &log &default="";
    };
@endif

export {
  type HttpClient: record {

    method: string &default="un";
    version: string &default="00";
    cookie: string &default="";
    referer: string &default="";
    language: string &default = "0000";
    header_names: vector of string &default=vector();
    header_names_o: vector of string &default=vector();

    cookie_names: vector of string &default=string_vec();
    cookie_values: vector of string &default=string_vec();
    
  };
}

redef record FINGERPRINT::Info += {
  http_client: HttpClient &default=HttpClient();
};

# Create the log stream and file
event zeek_init() &priority=5 {
  Log::create_stream(FINGERPRINT::JA4H::LOG,
    [$columns=FINGERPRINT::JA4H::Info, $ev=log_fingerprint_ja4h, $path="fingerprint_ja4h", $policy=log_policy]
  );
}

event http_header (c: connection, is_orig: bool, original_name: string, name: string, value: string)
{
    if (!c?$fp) { c$fp = FINGERPRINT::Info(); }
    if (is_orig) {
        c$fp$http_client$header_names_o += original_name;
        if (name == "COOKIE") {
            c$fp$http_client$cookie = value;
            local cookies = split_string(value, /;/);
            for (idx in cookies) {
                local cookie = strip(cookies[idx]);
                c$fp$http_client$cookie_values += cookie;
                c$fp$http_client$cookie_names += split_string1(cookie, /=/)[0];
            }
        } else if (name == "REFERER") {
            c$fp$http_client$referer = value;
        } else {
            c$fp$http_client$header_names += original_name;
        }
        
        if (name == "ACCEPT-LANGUAGE") {
            local prim_lang = to_lower(split_string(value, /,/)[0]);  # find primary language
            local lang = gsub(prim_lang, /\-/, ""); #strip hyphens 

            local i = 0;
            c$fp$http_client$language = "";
            while ( i < 4) {
                if (i >= |lang|) {
                    c$fp$http_client$language += "0";
                }
                    c$fp$http_client$language += lang[i];
                ++i;
            }
        }
    }
}

global HTTP_METHOD_MAP: table[string] of string = {
    ["GET"]  = "ge",
    ["HEAD"]   = "he",
    ["OPTIONS"]  = "op",
    ["TRACE"] = "tr",
    ["DELETE"]  = "de",
    ["PUT"]  = "pu",
    ["POST"]  = "po",
    ["PATCH"]  = "pa",
    ["CONNECT"] = "co"
};

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
{
    if (!c?$fp) { c$fp = FINGERPRINT::Info(); }

    # clear the last request if there was one
    c$fp$http_client = [];

    if (method in HTTP_METHOD_MAP) {
        c$fp$http_client$method = HTTP_METHOD_MAP[method];
    }

    if (version == "1.0") {
        c$fp$http_client$version = "10";
    } else if (version == "1.1") {
        c$fp$http_client$version = "11";
    } else if (version == "2.0") {
        c$fp$http_client$version = "20";
    } else if (version == "3.0") {
        c$fp$http_client$version = "30";
    }
}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
{
    if (!is_orig || !c?$fp || !c$fp?$http_client || !FINGERPRINT::JA4H_enabled) { return; }

    c$fp$ja4h = JA4::calculate_ja4h(c, FINGERPRINT::delimiter);
    c$fp$ja4h$uid = c$uid;

    c$http$ja4h = c$fp$ja4h$ja4h;
    @if(FINGERPRINT::JA4H_raw)
    c$http$ja4h_r = c$fp$ja4h$ja4h_r;
    c$http$ja4h_ro = c$fp$ja4h$ja4h_ro;
    @endif
}
