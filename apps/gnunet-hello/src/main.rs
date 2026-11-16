//! Public GNUnet peer utility over original native client ownership.
#![deny(unsafe_code)]
use std::{
    io::{self, Write},
    process::ExitCode,
};
#[expect(
    unsafe_code,
    reason = "Fresh process captures client inheritance before competing native resources"
)]
fn main() -> ExitCode {
    // SAFETY: first and only initialization in this fresh single-threaded process.
    let result = unsafe { gnunet_service_startup::ClientStartup::capture() }
        .map_err(|error| Box::new(error) as Box<dyn std::error::Error>)
        .and_then(|startup| {
            gnunet_peer_tools_host::run(gnunet_peer_tools_host::Tool::Hello, startup)
        });
    match result {
        Ok(code) => code,
        Err(error) => {
            let _diagnostic = writeln!(io::stderr().lock(), "gnunet-hello: {error}");
            ExitCode::FAILURE
        }
    }
}
