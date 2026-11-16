//! Native process-local startup probe with platform-specific ownership.
#[cfg(unix)]
#[path = "primitive/unix.rs"]
mod native;
#[cfg(windows)]
#[path = "primitive/windows.rs"]
mod native;
fn main() -> std::process::ExitCode {
    native::main()
}
