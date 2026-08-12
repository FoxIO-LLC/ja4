// Copyright (c) 2023, FoxIO, LLC.
// All rights reserved.
// Patent Pending
// JA4 is Open-Source, Licensed under BSD 3-Clause
// JA4+ (JA4S, JA4H, JA4L, JA4X, JA4SSH) are licenced under the FoxIO License 1.1.
// For full license text, see the repo root.

//! JA4T (TCP client) fingerprinting

use serde::Serialize;

use crate::{FormatFlags, Packet, PacketNum, Result};

const TCP_FLAG_SYN: u16 = 0x02;
const TCP_FLAG_ACK: u16 = 0x10;

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

        let raw = tcp.first("tcp.flags")?;
        let flags = u16::from_str_radix(raw.trim_start_matches("0x"), 16)?;
        if !is_initial_syn(flags) {
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
            .last()
            .map(|md| md.value().parse::<u16>())
            .transpose()?;
        let window_scale = tcp
            .fields("tcp.options.wscale.shift")
            .last()
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
    pub(crate) fn into_out(self, _flags: FormatFlags) -> Option<OutStream> {
        let client = self.client?;

        let ja4t = client.to_ja4t();

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
        use std::fmt::Write;
        let mut opts = String::with_capacity(self.options.len() * 3);
        for (i, v) in self.options.iter().enumerate() {
            if i > 0 {
                opts.push('-');
            }
            let _ = write!(opts, "{}", v);
        }
        if opts.is_empty() {
            opts.push_str("00");
        }

        let mss = self.mss.unwrap_or(0);
        let window_scale = self.window_scale.unwrap_or(0);

        if window_scale == 0 {
            format!("{}_{opts}_{mss:02}_{window_scale:02}", self.window_size)
        } else {
            format!("{}_{opts}_{mss:02}_{window_scale}", self.window_size)
        }
    }
}

fn is_initial_syn(flags: u16) -> bool {
    (flags & TCP_FLAG_SYN) != 0 && (flags & TCP_FLAG_ACK) == 0
}

#[test]
fn test_is_initial_syn() {
    // Plain SYN
    assert!(is_initial_syn(0x02));
    // SYN + ECN (ECE + CWR)
    assert!(is_initial_syn(0xC2));

    // SYN-ACK must be ignored
    assert!(!is_initial_syn(0x12));
    // ACK without SYN
    assert!(!is_initial_syn(0x10));
}

#[test]
fn test_ja4t_format_defaults() {
    let client = ClientStats {
        pkt_num: None,
        window_size: 8192,
        options: Vec::new(),
        mss: None,
        window_scale: None,
    };

    assert_eq!(client.to_ja4t(), "8192_00_00_00");
}

#[test]
fn test_ja4t_format_zero_window_scale() {
    let client = ClientStats {
        pkt_num: None,
        window_size: 5744,
        options: vec![2, 4, 8, 1, 3],
        mss: Some(1436),
        window_scale: Some(0),
    };

    assert_eq!(client.to_ja4t(), "5744_2-4-8-1-3_1436_00");
}

#[test]
fn test_ja4t_format_present_single_digit_mss() {
    let client = ClientStats {
        pkt_num: None,
        window_size: 8192,
        options: vec![2],
        mss: Some(9),
        window_scale: None,
    };

    assert_eq!(client.to_ja4t(), "8192_2_09_00");
}
