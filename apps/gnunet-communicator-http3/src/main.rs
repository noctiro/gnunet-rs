//! Standard GNUnet communicator PROGRAM. No private command-line protocol.
#![deny(unsafe_code)]
#[cfg(unix)]
mod statistics;
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => match writeln!(io::stderr().lock(), "gnunet-communicator-http3: {error}") {
            Ok(()) | Err(_) => ExitCode::FAILURE,
        },
    }
}
#[cfg(not(unix))]
fn run() -> Result<(), Box<dyn Error>> {
    Err("native communicator requires Unix".into())
}
#[cfg(unix)]
#[expect(
    unsafe_code,
    reason = "Sole single-threaded initial transfer of parent-declared descriptors before logging/configuration/runtime/native resource creation"
)]
fn run() -> Result<(), Box<dyn Error>> {
    use gnunet_service_startup::{InheritedMode, InheritedResources};
    // SAFETY: first operation of the fresh process, with no concurrent close,
    // descriptor reuse, environment mutation, second capture or unrelated owner.
    let captured = unsafe {
        gnunet_service_startup::capture_from_environment(InheritedMode::CloseAfterConfiguredBind)?
    };
    if let Some(notice) = captured.control_notice {
        writeln!(
            io::stderr().lock(),
            "gnunet-communicator-http3 parent-control declaration: {notice:?}"
        )?
    }
    match captured.inherited {
        InheritedResources::CloseAfterBind(hold) => {
            let nonempty = !hold.is_empty();
            let report = hold.abort();
            if nonempty {
                return Err(format!("communicator has no SERVICE listener; inherited descriptors refused: {report:?}").into());
            }
        }
        InheritedResources::Listeners(_) => {
            return Err("unexpected communicator descriptor mode".into());
        }
    }
    gnunet_quic_communicator_host::program::run_with_statistics::<statistics::Factory>(
        gnunet_quic_communicator_host::tls::Profile::Http3,
        captured.parent_control,
    )
}
