//! Standard installed REGEX SERVICE using the actual native DHT Factory.
use std::{
    io::{self, Write},
    process::ExitCode,
};
#[cfg(unix)]
#[expect(
    unsafe_code,
    reason = "Once-only fresh-exec SERVICE entry adopts inherited descriptors before runtime or threads"
)]
fn main() -> ExitCode {
    // SAFETY: this is the fresh single-threaded exec entry. No task, runtime,
    // provider, global application lock or independently adopted FD exists.
    let result =
        unsafe { gnunet_regex_program_host::run::<gnunet_regex_program_host::NativeFactory>() };
    match result {
        Ok(code) => code,
        Err(error) => {
            let _written = writeln!(
                io::stderr().lock(),
                "REGEX original startup failure: {error}"
            );
            ExitCode::FAILURE
        }
    }
}
#[cfg(not(unix))]
fn main() -> ExitCode {
    let _written = writeln!(
        io::stderr().lock(),
        "REGEX SERVICE requires the supported Unix native profile"
    );
    ExitCode::FAILURE
}
