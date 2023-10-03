use std::io;

use clap::Parser as _;
use color_eyre::eyre;
use tracing_subscriber::filter::EnvFilter;

fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_file(true)
        .with_line_number(true)
        .init();
    color_eyre::install()?;

    match ja4::Cli::parse().run() {
        Err(ja4::Error::Io(e)) if matches!(e.kind(), io::ErrorKind::BrokenPipe) => Ok(()),
        Err(e) => Err(e.into()),
        Ok(()) => Ok(()),
    }
}
