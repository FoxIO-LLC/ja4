// Copyright (c) 2023, FoxIO, LLC.
// All rights reserved.
// Patent Pending
// JA4 is Open-Source, Licensed under BSD 3-Clause
// JA4+ (JA4S, JA4H, JA4L, JA4X, JA4SSH) are licenced under the FoxIO License 1.1.
// For full license text, see the repo root.

//! JA4T (TCP client) fingerprinting

use serde::Serialize;

use crate::{FormatFlags, Packet, PacketNum, Result};

/// JA4T stream state.
#[derive(Debug, Default)]
pub(crate) struct Stream {
    client: Option<ClientStats>,
}

/// Final output for TCP fingerprints.
#[derive(Debug, Serialize)]
pub(crate) struct OutStream {
    /// JA4T fingerprint
    ja4t: String,

    /// Packet number where the fingerprint was observed
    #[serde(skip_serializing_if = "Option::is_none")]
    pkt_ja4t: Option<PacketNum>,
}

/// Internal representation of a TCP client SYN.
#[derive(Debug)]
struct ClientStats {
    pkt_num: Option<PacketNum>,
    window_size: u16,
    options: Vec<u8>, // TCP option kinds, in order
    mss: Option<u16>,
    window_scale: Option<u8>,
}

impl Stream {
    /// Update stream state from a packet.
    ///
    /// Only the first SYN without ACK is processed.
    pub(crate) fn update(&mut self, pkt: &Packet, store_pkt_num: bool) -> Result<()> {
        // Already fingerprinted → nothing to do
        if self.client.is_some() {
            return Ok(());
        }

        // Find TCP protocol
        let Some(tcp) = pkt.find_proto("tcp") else {
            return Ok(());
        };

        // Check SYN and not ACK
        /*
        const FIN: u16 = 0x01;
        const SYN: u16 = 0x02;
        const RST: u16 = 0x04;
        const PSH: u16 = 0x08;
        const ACK: u16 = 0x10;
        const URG: u16 = 0x20;
         */
        const SYN: u16 = 0x02;

        let raw = tcp.first("tcp.flags")?;
        let flags = u16::from_str_radix(raw.trim_start_matches("0x"), 16)?;
        if flags != SYN {
            return Ok(());
        }

        // Extract window size (raw, before scaling)
        let window_size: u16 = tcp.first("tcp.window_size_value")?.parse()?;

        // Parse TCP options
        let mut options = Vec::new();
        for opt in tcp.fields("tcp.option_kind") {
            let kind: u8 = opt.value().parse()?;

            options.push(kind);
        }

        let mss = tcp
            .fields("tcp.options.mss_val")
            .next()
            .map(|md| md.value().parse::<u16>())
            .transpose()?;
        let window_scale = tcp
            .fields("tcp.options.wscale.shift")
            .next()
            .map(|md| md.value().parse::<u8>())
            .transpose()?;

        tracing::debug!(
            pkt = %pkt.num,
            window_size,
            ?options,
            mss = ?mss,
            window_scale = ?window_scale,
            "JA4T client SYN fingerprinted"
        );

        self.client = Some(ClientStats {
            pkt_num: store_pkt_num.then_some(pkt.num),
            window_size,
            options,
            mss,
            window_scale,
        });

        Ok(())
    }

    /// Convert internal state into output.
    pub(crate) fn into_out(self, flags: FormatFlags) -> Option<OutStream> {
        let client = self.client?;

        let raw = client.to_ja4t();
        let ja4t = if flags.with_raw { raw.clone() } else { raw };

        Some(OutStream {
            ja4t,
            pkt_ja4t: client.pkt_num,
        })
    }
}

impl ClientStats {
    /// Format:
    ///   <window size>_<options>_<mss>_<window scale>
    ///
    /// Example:
    ///   64240_2-1-3-1-1-4_1460_8
    fn to_ja4t(&self) -> String {
        let opts = self
            .options
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join("-");

        format!(
            "{}_{}_{}_{}",
            self.window_size,
            opts,
            self.mss.unwrap_or(0),
            self.window_scale.unwrap_or(0),
        )
    }
}
