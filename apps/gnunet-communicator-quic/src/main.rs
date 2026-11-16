//! Native GNUnet communicator PROGRAM with original startup ownership.
#![deny(unsafe_code)]
mod statistics;
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
#[expect(
    unsafe_code,
    reason = "First fresh-process capture before competing native owners"
)]
fn main() -> ExitCode {
    // SAFETY: first and only inheritance capture in this fresh single-threaded process.
    let result = unsafe { gnunet_service_startup::ClientStartup::capture() }
        .map_err(|error| Box::new(error) as Box<dyn Error>)
        .and_then(|startup| {
            gnunet_quic_communicator_host::program::run_with_statistics::<statistics::Factory>(
                gnunet_quic_communicator_host::tls::Profile::Raw,
                startup,
            )
        });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if error.is::<gnunet_quic_communicator_host::program::ReportedFailure>() {
                return ExitCode::FAILURE;
            }
            let _diagnostic = writeln!(io::stderr().lock(), "gnunet-communicator-quic: {error}");
            ExitCode::FAILURE
        }
    }
}
