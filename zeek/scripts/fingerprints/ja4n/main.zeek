@load ../config

module FINGERPRINT::JA4N;

# JA4N is part of JA4+ and is licensed under the FoxIO License 1.1.
#
# This follows the JA4N reference implementation in arkime/ja4 (ja4plus.c):
#
#  * A UDP connection with port 123 on either side is fingerprinted once the
#    first non-empty payload of either direction passes JA4::ja4n_classify().
#    Only the first payload of each direction is classified.
#  * From then on every payload of at least 48 bytes, in both directions, is
#    fingerprinted, including the one that passed classification.
#  * Each distinct fingerprint is reported once per connection.
#
# A direction is a sending endpoint, not Zeek's originator flag. Zeek's NTP
# analyzer can swap a connection's roles. In Zeek 7.0 and 8.0 the UDP analyzer
# computes is_orig and queues udp_contents before handing the packet to
# protocol analyzers, so a swap made for a packet appears in u$id for that
# packet's udp_contents (records are updated before handlers run) while its
# connection_flipped event is queued after it. Hence:
#
#  * for every packet after the first, is_orig is relative to the roles as
#    u$id showed them at the previous packet's udp_contents, and
#  * the first packet's sender is settled by the connection_flipped events
#    that arrive before the second packet.

export {
  ## One record per distinct JA4N fingerprint seen in a connection.
  type Info: record {
    ## Time of the first message that produced this fingerprint.
    ts: time &log;
    ## The connection's unique id.
    uid: string &log;
    ## The connection's 4-tuple of endpoint addresses/ports.
    id: conn_id &log;
    ## The JA4N fingerprint.
    ja4n: string &log;
  };

  ## Per-connection JA4N state; not logged.
  type State: record {
    ## Originator as u$id showed it at the last udp_contents. The responder
    ## is the other endpoint.
    last_orig_h: addr &optional;
    last_orig_p: port &optional;
    ## The first packet's is_orig, and the parity of role swaps made while
    ## processing it. Together with last_orig_* from that packet they give
    ## its sender once the next packet arrives.
    first_is_orig: bool &default=F;
    first_flips: bool &default=F;
    ## Whether the first packet's sender is known, and whether it is the
    ## endpoint that was the originator at the last udp_contents.
    first_sender_known: bool &default=F;
    first_sender_was_orig: bool &default=F;
    ## The first non-empty payload of each direction has been classified.
    first_dir_classified: bool &default=F;
    second_dir_classified: bool &default=F;
    ## A classified payload qualified the connection for fingerprinting.
    fingerprinting: bool &default=F;
    ## Fingerprints already logged for this connection.
    seen: set[string] &default=set();
  };

  ## Upper bound on distinct fingerprints logged per connection, so a
  ## long-lived or hostile flow cannot grow per-connection state and log
  ## volume without limit. Ordinary NTP exchanges produce one or two.
  option max_fingerprints_per_conn: count = 100;

  redef enum Log::ID += { LOG };
  global log_fingerprint_ja4n: event(rec: Info);
  global log_policy: Log::PolicyHook;
}

redef record FINGERPRINT::Info += {
  ja4n: FINGERPRINT::JA4N::State &optional;
};

# Deliver NTP payloads in both directions via udp_contents, whether port 123
# is the source or the destination, and only for that port.
redef udp_content_ports += { 123/udp };

event zeek_init() &priority=5 {
  Log::create_stream(FINGERPRINT::JA4N::LOG,
    [$columns=FINGERPRINT::JA4N::Info, $ev=log_fingerprint_ja4n, $path="ja4n", $policy=log_policy]
  );
}

# Role swaps while the first packet is processed are queued after its
# udp_contents and before the next packet's. Swaps made when the connection
# was created come before the first udp_contents and are already reflected in
# its is_orig, so they are not counted.
event connection_flipped(c: connection) {
  if ( ! c?$fp || ! c$fp?$ja4n ) {
    return;
  }
  local st = c$fp$ja4n;
  if ( st?$last_orig_h && ! st$first_sender_known ) {
    st$first_flips = ! st$first_flips;
  }
}

# Returns whether the packet behind this udp_contents was sent by the sender
# of the connection's first udp_contents, and records the roles as u$id shows
# them now for the next call. See the comment at the top of this file.
function from_first_sender(u: connection, is_orig: bool, st: State, first_packet: bool): bool {
  local result = T;

  if ( first_packet ) {
    st$first_is_orig = is_orig;
  }
  else {
    if ( ! st$first_sender_known ) {
      # The first sender relative to the roles at the first udp_contents,
      # swapped once more if an odd number of flips happened while the first
      # packet was processed.
      st$first_sender_was_orig = st$first_is_orig != st$first_flips;
      st$first_sender_known = T;
    }

    # is_orig and first_sender_was_orig are both relative to the roles at the
    # previous udp_contents.
    result = is_orig == st$first_sender_was_orig;

    # Re-express the first sender relative to the roles as they are now.
    if ( u$id$orig_h != st$last_orig_h || u$id$orig_p != st$last_orig_p ) {
      st$first_sender_was_orig = ! st$first_sender_was_orig;
    }
  }

  st$last_orig_h = u$id$orig_h;
  st$last_orig_p = u$id$orig_p;
  return result;
}

event udp_contents(u: connection, is_orig: bool, contents: string) {
  if ( ! FINGERPRINT::JA4N_enabled ) {
    return;
  }

  # Other scripts may enable udp_contents for other ports.
  if ( u$id$orig_p != 123/udp && u$id$resp_p != 123/udp ) {
    return;
  }

  if ( ! u?$fp ) { u$fp = FINGERPRINT::Info(); }
  local first_packet = ! u$fp?$ja4n;
  if ( first_packet ) { u$fp$ja4n = State(); }
  local st = u$fp$ja4n;

  # Directions only matter until the first non-empty payload of each one has
  # been classified. After that a connection either never qualifies or only
  # needs fingerprinting, so the bookkeeping stops.
  if ( ! st$first_dir_classified || ! st$second_dir_classified ) {
    local first_dir = from_first_sender(u, is_orig, st, first_packet);

    # Empty payloads neither count as a direction's first payload nor
    # produce a fingerprint.
    if ( |contents| == 0 ) {
      return;
    }

    local first_in_direction = F;
    if ( first_dir && ! st$first_dir_classified ) {
      st$first_dir_classified = T;
      first_in_direction = T;
    }
    else if ( ! first_dir && ! st$second_dir_classified ) {
      st$second_dir_classified = T;
      first_in_direction = T;
    }

    if ( first_in_direction && ! st$fingerprinting && JA4::ja4n_classify(contents) ) {
      st$fingerprinting = T;
    }
  }

  # Shorter payloads have no NTP header to fingerprint.
  if ( ! st$fingerprinting || |contents| < 48 || |st$seen| >= max_fingerprints_per_conn ) {
    return;
  }

  local fp = JA4::calculate_ja4n(contents, is_v6_addr(u$id$orig_h), u$start_time);
  if ( fp in st$seen ) {
    return;
  }
  add st$seen[fp];

  Log::write(FINGERPRINT::JA4N::LOG, Info($ts=network_time(), $uid=u$uid, $id=u$id, $ja4n=fp));
}
