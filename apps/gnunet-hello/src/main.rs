//! Actual installed official public-peer utility, without private key access.
#![forbid(unsafe_code)]
use std::{
    io::{self, Write},
    process::ExitCode,
};
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _diagnostic = writeln!(io::stderr().lock(), "gnunet-hello: {error}");
            ExitCode::FAILURE
        }
    }
}
#[cfg(unix)]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    gnunet_peer_tools_host::run(gnunet_peer_tools_host::Tool::Hello)
}
#[cfg(not(unix))]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    Err("public PILS/PEERSTORE native PROGRAM requires Unix".into())
}
