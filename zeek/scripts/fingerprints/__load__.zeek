@load base/protocols/conn
@load base/protocols/ssl
@load base/protocols/http/main
@load base/protocols/quic

module FINGERPRINT;

export { type Info: record {}; }
redef record connection += { fp: FINGERPRINT::Info &optional; };

@load ./config
@load ./utils/common
@load ./utils/ssl-consts

@load ./ja4
@load ./ja4s
@load ./ja4x
@load ./ja4h
@load ./ja4ssh
@load ./ja4t
@load ./ja4l
@load ./ja4d
