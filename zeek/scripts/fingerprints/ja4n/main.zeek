@load base/protocols/ntp
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
#
# Each fingerprint is written to the ja4n field of the record Zeek's NTP
# analyzer logs for the same message: NTP::Info (ntp.log), and on Zeek
# versions that have them NTP::ControlInfo (ntp_control.log) and
# NTP::PrivateInfo (ntp_private.log). A message the NTP analyzer does not log,
# such as mode 0 or a payload it fails to parse, has no record to carry its
# fingerprint and it is dropped. Zeek removes an analyzer after a protocol
# violation, so once the NTP analyzer rejects a payload, every later message
# on that connection is dropped the same way.
#
# The payload comes from udp_contents and the log record from ntp_message.
# In Zeek 7.0 and 8.0 the UDP analyzer computes is_orig and queues
# udp_contents before handing the packet to protocol analyzers, so for each
# packet udp_contents runs first and leaves the fingerprint in State$pending.
# ntp_message for the same packet then copies it into the record between
# base/protocols/ntp's handlers at priority 5 (which builds the record) and
# -5 (which writes it). udp_contents clears pending at the start of every
# packet, so a payload the NTP analyzer rejects cannot leak its fingerprint
# into the next message's record.
#
# A direction is a sending endpoint, not Zeek's originator flag. Zeek's NTP
# analyzer can swap a connection's roles. Because of the ordering above, a
# swap made for a packet appears in u$id for that packet's udp_contents
# (records are updated before handlers run) while its connection_flipped
# event is queued after it. Hence:
#
#  * for every packet after the first, is_orig is relative to the roles as
#    u$id showed them at the previous packet's udp_contents, and
#  * the first packet's sender is settled by the connection_flipped events
#    that arrive before the second packet.

export {
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
    ## Fingerprint of the payload seen by the latest udp_contents, waiting
    ## for that packet's ntp_message to put it into the log record.
    pending: string &optional;
  };
}

redef record FINGERPRINT::Info += {
  ja4n: FINGERPRINT::JA4N::State &optional;
};

redef record NTP::Info += {
  ## The JA4N fingerprint of this message, or empty if the message produced
  ## none.
  ja4n: string &log &default="";
};

@ifdef ( NTP::CONTROL_LOG )
redef record NTP::ControlInfo += {
  ## The JA4N fingerprint of this message, or empty if the message produced
  ## none.
  ja4n: string &log &default="";
};
@endif

@ifdef ( NTP::PRIVATE_LOG )
redef record NTP::PrivateInfo += {
  ## The JA4N fingerprint of this message, or empty if the message produced
  ## none.
  ja4n: string &log &default="";
};
@endif

# Deliver NTP payloads in both directions via udp_contents, whether port 123
# is the source or the destination, and only for that port.
redef udp_content_ports += { 123/udp };

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

  # Whatever the previous packet left behind belongs to that packet.
  delete st$pending;

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
  if ( ! st$fingerprinting || |contents| < 48 ) {
    return;
  }

  st$pending = JA4::calculate_ja4n(contents, is_v6_addr(u$id$orig_h), u$start_time);
}

# These run between base/protocols/ntp's ntp_message handlers at priority 5,
# which builds the message's record, and -5, which logs it. Each one always
# assigns the field, to the empty string when there is no fingerprint, so a
# record reused across messages never shows an older message's fingerprint. pending is left alone here; the next udp_contents
# clears it.
event ntp_message(c: connection, is_orig: bool, msg: NTP::Message) &priority=3 {
  if ( ! FINGERPRINT::JA4N_enabled || ! msg?$std_msg || ! c?$ntp || ! c?$fp || ! c$fp?$ja4n ) {
    return;
  }
  if ( c$fp$ja4n?$pending ) { c$ntp$ja4n = c$fp$ja4n$pending; }
  else { c$ntp$ja4n = ""; }
}

@ifdef ( NTP::CONTROL_LOG )
event ntp_message(c: connection, is_orig: bool, msg: NTP::Message) &priority=3 {
  if ( ! FINGERPRINT::JA4N_enabled || ! msg?$control_msg || ! c?$ntp_control || ! c?$fp || ! c$fp?$ja4n ) {
    return;
  }
  if ( c$fp$ja4n?$pending ) { c$ntp_control$ja4n = c$fp$ja4n$pending; }
  else { c$ntp_control$ja4n = ""; }
}
@endif

@ifdef ( NTP::PRIVATE_LOG )
event ntp_message(c: connection, is_orig: bool, msg: NTP::Message) &priority=3 {
  if ( ! FINGERPRINT::JA4N_enabled || ! msg?$mode7_msg || ! c?$ntp_private || ! c?$fp || ! c$fp?$ja4n ) {
    return;
  }
  if ( c$fp$ja4n?$pending ) { c$ntp_private$ja4n = c$fp$ja4n$pending; }
  else { c$ntp_private$ja4n = ""; }
}
@endif
