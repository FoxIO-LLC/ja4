use std::{
    io::{self, Write as _},
    path::PathBuf,
};

use clap::Parser;
use color_eyre::eyre;
use fs_err as fs;
use serde::Serialize;
use tracing_subscriber::filter::EnvFilter;
use x509_parser::{certificate::X509Certificate, pem, prelude::FromDer as _};

/// Print JA4X fingerprints of X.509 certificates
#[derive(Debug, Parser)]
#[command(version = env!("CARGO_PKG_VERSION"))]
struct Cli {
    /// JSON output (default is YAML)
    #[arg(short, long)]
    json: bool,
    /// Include raw (unhashed) fingerprints in the output
    #[arg(short = 'r', long)]
    with_raw: bool,
    /// X.509 certificate(s)
    certs: Vec<PathBuf>,
}

fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_file(true)
        .with_line_number(true)
        .init();
    color_eyre::install()?;

    let cli = Cli::parse();
    for path in cli.certs {
        let buf = fs::read(&path)?;

        let rec = if buf.starts_with(b"-----BEGIN CERTIFICATE-----") {
            tracing::debug!(?path, format = "PEM");
            let (rem, pem) = pem::parse_x509_pem(&buf)?;
            debug_assert!(rem.is_empty());
            pem.parse_x509()?.into()
        } else {
            tracing::debug!(?path, format = "DER");
            let (rem, x509) = X509Certificate::from_der(&buf)?;
            debug_assert!(rem.is_empty());
            ja4x::X509Rec::from(x509)
        };

        let rec = OutRec {
            path,
            x509: rec.into_out(cli.with_raw),
        };
        let Err(err) = write_rec(&rec, cli.json) else {
            continue;
        };
        // I wish Rust handled BrokenPipe errors gracefully.
        return match err.root_cause().downcast_ref::<io::Error>() {
            Some(io_err) if matches!(io_err.kind(), io::ErrorKind::BrokenPipe) => Ok(()),
            _ => Err(err),
        };
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct OutRec {
    path: PathBuf,
    #[serde(flatten)]
    x509: ja4x::OutX509Rec,
}

fn write_rec(rec: &OutRec, json_p: bool) -> eyre::Result<()> {
    if json_p {
        serde_json::to_writer(io::stdout(), rec)?;
    } else {
        serde_yaml::to_writer(io::stdout(), rec)?;
    }
    Ok(writeln!(io::stdout())?)
}
