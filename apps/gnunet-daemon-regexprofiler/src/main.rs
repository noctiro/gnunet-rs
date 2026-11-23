//! Installed GNUnet REGEX policy profiler.
use std::{
    io::{self, Write},
    process::ExitCode,
};

#[expect(
    unsafe_code,
    reason = "Fresh executable entry adopts native inherited resources once"
)]
fn main() -> ExitCode {
    // SAFETY: no other owner has adopted resources or created a runtime.
    match unsafe { gnunet_regex_program_host::run_profiler() } {
        Ok(code) => code,
        Err(error) => {
            let _report = writeln!(io::stderr().lock(), "gnunet-daemon-regexprofiler: {error}");
            ExitCode::FAILURE
        }
    }
}
