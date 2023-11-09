// Copyright (c) 2023, FoxIO, LLC.
// All rights reserved.
// Patent Pending
// JA4 is Open-Source, Licensed under BSD 3-Clause
// JA4+ (JA4S, JA4H, JA4L, JA4X, JA4SSH) are licenced under the FoxIO License 1.1.
// For full license text, see the repo root.

use indexmap::IndexMap;
use serde::Serialize;

use crate::{
    conf::Conf,
    http, ssh,
    time::{self, TcpTimestamps, Timestamps, UdpTimestamps},
    tls, FormatFlags, Packet, Proto, Result,
};

/// User-facing record containing data obtained from a TCP or UDP stream.
#[derive(Debug, Serialize)]
pub(crate) struct OutRec {
    stream: StreamId,
    transport: Transport,
    #[serde(flatten)]
    sockets: SocketPair,
    #[serde(flatten)]
    payload: OutStream,
}

#[derive(Debug, Serialize)]
struct OutStream {
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    tls: Option<tls::OutStream>,
    /// Light distance (latency) fingerprints.
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    ja4l: Option<time::Fingerprints>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    http: Option<http::OutStream>,
    /// SSH fingerprints.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ja4ssh: Vec<ssh::Fingerprint>,
    /// Additional information from SSH packets.
    #[serde(skip_serializing_if = "Option::is_none")]
    ssh_extras: Option<ssh::Extras>,
}

#[derive(Debug, Default)]
struct Stream<T> {
    tls: Option<tls::Stream>,
    timestamps: Option<T>,
    http: http::Stream,
    ssh: ssh::Stream,
}

impl<T: Timestamps> Stream<T> {
    fn into_out(self, flags: FormatFlags) -> Option<OutStream> {
        let Self {
            tls,
            timestamps,
            http,
            ssh,
        } = self;

        let tls = tls.and_then(|stats| stats.into_out(flags));
        let ja4l = timestamps.and_then(|ts| ts.finish());
        let http = http.into_out(flags);
        let (ja4ssh, ssh_extras) = ssh.finish();

        if tls.is_none() && ja4l.is_none() && http.is_none() && ja4ssh.is_empty() {
            return None;
        }

        Some(OutStream {
            tls,
            ja4l,
            http,
            ja4ssh,
            ssh_extras,
        })
    }
}

#[derive(Debug)]
struct AddressedStream<T> {
    sockets: SocketPair,
    stream: Stream<T>,
}

impl<T: Timestamps> AddressedStream<T> {
    fn new(sockets: SocketPair) -> Self {
        Self {
            sockets,
            stream: Stream::default(),
        }
    }

    fn update(&mut self, pkt: &Packet, conf: &Conf, store_pkt_num: bool) {
        if conf.tls.enabled {
            if let Err(error) = self
                .stream
                .tls
                .get_or_insert_with(Default::default)
                .update(pkt, store_pkt_num)
            {
                tracing::debug!(%pkt.num, %error, "failed to fingerprint TLS");
            }
        }
        if conf.http.enabled {
            if let Err(error) = self.stream.http.update(pkt, store_pkt_num) {
                tracing::debug!(%pkt.num, %error, "failed to fingerprint HTTP");
            }
        }
        if conf.time.enabled {
            match self
                .stream
                .timestamps
                .take()
                .unwrap_or_default()
                .update(pkt)
            {
                Ok(ts) => self.stream.timestamps = Some(ts),
                Err(error) => tracing::debug!(%pkt.num, %error, "failed to store timestamp"),
            }
        }
        if conf.ssh.enabled {
            if let Err(error) = self.process_ssh(pkt, conf.ssh.sample_size) {
                tracing::debug!(%pkt.num, %error, "failed to handle SSH packet");
            }
        }
    }

    fn process_ssh(&mut self, pkt: &Packet, sample_size: u32) -> Result<()> {
        if pkt.find_proto("tcp").is_none() {
            return Ok(());
        }
        let sender_is_client = match self.sockets.ip_ver {
            IpVersion::Ipv4 => {
                // SAFETY: We've established in `SocketPair::new` that "ip" layer is
                // present.
                let ip = pkt.find_proto("ip").unwrap();
                self.sockets.src == ip.first("ip.src")?
            }
            IpVersion::Ipv6 => {
                // SAFETY: We've established in `SocketPair::new` that "ipv6" layer is
                // present.
                let ipv6 = pkt.find_proto("ipv6").unwrap();
                self.sockets.src == ipv6.first("ipv6.src")?
            }
        };
        let sender = if sender_is_client {
            crate::Sender::Client
        } else {
            crate::Sender::Server
        };
        self.stream.ssh.update(pkt, sender, sample_size)
    }
}

/// Information collected from the capture file.
#[derive(Debug, Default)]
pub(crate) struct Streams {
    tcp: IndexMap<StreamId, AddressedStream<TcpTimestamps>>,
    udp: IndexMap<StreamId, AddressedStream<UdpTimestamps>>,
}

impl Streams {
    pub(crate) fn update(&mut self, pkt: &Packet, conf: &Conf, store_pkt_num: bool) -> Result<()> {
        use indexmap::map::Entry;

        let Some(sid2) = StreamId2::new(pkt)? else {
            return Ok(());
        };
        match sid2.proto.name() {
            "tcp" => {
                let stream = match self.tcp.entry(sid2.stream_id) {
                    Entry::Occupied(x) => {
                        x.get().sockets.check(pkt, &sid2.proto);
                        x.into_mut()
                    }
                    Entry::Vacant(x) => {
                        let Some(sockets) = SocketPair::new(pkt, &sid2.proto)? else {
                            return Ok(());
                        };
                        x.insert(AddressedStream::new(sockets))
                    }
                };
                stream.update(pkt, conf, store_pkt_num);
            }
            "udp" => {
                let stream = match self.udp.entry(sid2.stream_id) {
                    Entry::Occupied(x) => {
                        x.get().sockets.check(pkt, &sid2.proto);
                        x.into_mut()
                    }
                    Entry::Vacant(x) => {
                        let Some(sockets) = SocketPair::new(pkt, &sid2.proto)? else {
                            return Ok(());
                        };
                        x.insert(AddressedStream::new(sockets))
                    }
                };
                stream.update(pkt, conf, store_pkt_num);
            }
            // SAFETY: `StreamId2::new` only returns `Some` for "tcp" or "udp".
            proto_name => unreachable!("proto={proto_name:?}"),
        }
        Ok(())
    }

    pub(crate) fn into_out(self, flags: FormatFlags) -> impl Iterator<Item = OutRec> {
        let Self { tcp, udp } = self;
        let tcp = tcp.into_iter().filter_map(move |(sid, addressed)| {
            let AddressedStream { sockets, stream } = addressed;
            Some(OutRec {
                stream: sid,
                transport: Transport::Tcp,
                sockets,
                payload: stream.into_out(flags)?,
            })
        });
        let udp = udp.into_iter().filter_map(move |(sid, addressed)| {
            let AddressedStream { sockets, stream } = addressed;
            Some(OutRec {
                stream: sid,
                transport: Transport::Udp,
                sockets,
                payload: stream.into_out(flags)?,
            })
        });
        tcp.chain(udp)
    }
}

// -----------------------------------------------------------------------------
// Auxiliary definitions

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
enum Transport {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpVersion {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
struct SocketPair {
    #[serde(skip)]
    ip_ver: IpVersion,
    src: String,
    dst: String,
    src_port: u32,
    dst_port: u32,
}

impl SocketPair {
    fn new(pkt: &Packet, transport: &Proto) -> Result<Option<Self>> {
        debug_assert!(pkt.find_proto("icmp").is_none());

        let (ip_ver, src, dst) = if let Some(ip) = pkt.find_proto("ip") {
            (
                IpVersion::Ipv4,
                ip.first("ip.src")?.to_owned(),
                ip.first("ip.dst")?.to_owned(),
            )
        } else if let Some(ipv6) = pkt.find_proto("ipv6") {
            (
                IpVersion::Ipv6,
                ipv6.first("ipv6.src")?.to_owned(),
                ipv6.first("ipv6.dst")?.to_owned(),
            )
        } else {
            return Ok(None);
        };

        let tname = transport.name();
        assert!(["tcp", "udp"].contains(&tname));

        Ok(Some(Self {
            ip_ver,
            src,
            dst,
            src_port: transport.first(&format!("{tname}.srcport"))?.parse()?,
            dst_port: transport.first(&format!("{tname}.dstport"))?.parse()?,
        }))
    }

    #[cfg(debug_assertions)]
    fn opposite(self) -> Self {
        Self {
            ip_ver: self.ip_ver,
            src: self.dst,
            dst: self.src,
            src_port: self.dst_port,
            dst_port: self.src_port,
        }
    }

    #[cfg(debug_assertions)]
    fn check(&self, pkt: &Packet, transport: &Proto) {
        if let Ok(Some(sockets)) = Self::new(pkt, transport) {
            assert!(sockets == *self || sockets == self.clone().opposite());
        }
    }

    #[cfg(not(debug_assertions))]
    fn check(&self, _pkt: &Packet, _transport: &Proto) {}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
struct StreamId(u32);

struct StreamId2<'a> {
    proto: Proto<'a>,
    stream_id: StreamId,
}

impl StreamId2<'_> {
    fn new<'a>(pkt: &'a Packet<'a>) -> Result<Option<StreamId2<'a>>> {
        if pkt.find_proto("icmp").is_some() {
            // `tshark` may return a hierarchy of `<proto>`, but `rtshark` flattens them
            // into s vector of `rtshark::Layer`s.
            //
            // E.g., `rtshark` hides the distinction between an outer `<proto name="tcp">`
            //
            // ```xml
            //    <proto name="tcp" showname="Transmission Control Protocol, Src Port: 57361, Dst Port: 5000, Seq: 0, Len: 0" size="32" pos="34">
            //      <field name="tcp.srcport" showname="Source Port: 57361" size="2" pos="34" show="57361" value="e011"/>
            //      <field name="tcp.dstport" showname="Destination Port: 5000" size="2" pos="36" show="5000" value="1388"/>
            // ```
            //
            // and the one nested inside `<proto name="icmp">`.
            //
            // ```xml
            //    <proto name="icmp" showname="Internet Control Message Protocol" size="60" pos="34">
            //      <field name="icmp.type" showname="Type: 3 (Destination unreachable)" size="1" pos="34" show="3" value="03"/>
            //      <field name="icmp.code" showname="Code: 13 (Communication administratively filtered)" size="1" pos="35" show="13" value="0d"/>
            //      <field name="icmp.checksum" showname="Checksum: 0xbc7d [correct]" size="2" pos="36" show="0xbc7d" value="bc7d"/>
            //      <field name="icmp.checksum.status" showname="Checksum Status: Good" size="0" pos="36" show="1"/>
            //      <field name="icmp.unused" showname="Unused: 00000000" size="4" pos="38" show="00:00:00:00" value="00000000"/>
            //      <proto name="ip" showname="Internet Protocol Version 4, Src: 172.16.225.48, Dst: 10.244.39.47" size="20" pos="42">
            //        <field name="ip.version" showname="0100 .... = Version: 4" size="1" pos="42" show="4" value="45"/>
            //        <field name="ip.hdr_len" showname=".... 0101 = Header Length: 20 bytes (5)" size="1" pos="42" show="20" value="45"/>
            //        [...]
            //      </proto>
            //      <proto name="tcp" showname="Transmission Control Protocol, Src Port: 57361, Dst Port: 5000, Seq: 1687692832" size="32" pos="62">
            //        <field name="tcp.srcport" showname="Source Port: 57361" size="2" pos="62" show="57361" value="e011"/>
            //        <field name="tcp.dstport" showname="Destination Port: 5000" size="2" pos="64" show="5000" value="1388"/>
            //        [...]
            // ```
            //
            // HACK: As a workaround, we ignore ICMP packets.
            return Ok(None);
        }

        if let Some(tcp) = pkt.find_proto("tcp") {
            debug_assert_eq!(tcp.name(), "tcp");
            let sid = tcp.first("tcp.stream")?.parse()?;
            Ok(Some(StreamId2 {
                proto: tcp,
                stream_id: StreamId(sid),
            }))
        } else if let Some(udp) = pkt.find_proto("udp") {
            debug_assert_eq!(udp.name(), "udp");
            let sid = udp.first("udp.stream")?.parse()?;
            Ok(Some(StreamId2 {
                proto: udp,
                stream_id: StreamId(sid),
            }))
        } else {
            Ok(None)
        }
    }
}
