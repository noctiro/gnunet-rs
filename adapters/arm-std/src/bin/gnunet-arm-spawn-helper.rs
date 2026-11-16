//! Fresh exec helper for the checked ARM launcher native boundary.
#![deny(unsafe_code)]
#[cfg(unix)]
fn main() -> std::process::ExitCode {
    #[expect(
        unsafe_code,
        reason = "This dedicated binary is a fresh exec helper before any file/runtime/thread creation; foreign stdio has no Rust OwnedFd owner"
    )]
    // SAFETY: this binary performs no work before the unique helper entrypoint.
    unsafe {
        gnunet_arm_host::process::helper_main(std::env::args_os().skip(1))
    }
}
#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    // Windows ARM launches through the native process producer, never this helper.
    std::process::ExitCode::FAILURE
}
