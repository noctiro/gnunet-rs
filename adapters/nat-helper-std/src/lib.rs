//! Actual Linux, Darwin and modern FreeBSD NAT helpers. Packet algorithms belong to gnunet-nat; privileged
//! syscalls are confined to the existing gnunet-native platform boundary.
#![forbid(unsafe_code)]
use std::{fmt, io};
/// Exact original helper cause, plus independent stdout/signal cleanup failures.
#[derive(Debug)]
pub struct Failure {
    /// Original official-compatible nonzero exit category.
    pub code: u8,
    /// Independent second actual client packet failure, if both variants failed.
    pub secondary: Option<Box<Cause>>,
    /// Exact original cause.
    pub cause: Cause,
    /// Actual original output flag-restoration errno.
    pub output_cleanup: Option<io::Error>,
    /// Actual original signal-restoration errno.
    pub signal_cleanup: Option<io::Error>,
}
/// Original failure; a short datagram is never retried as a stream suffix.
#[derive(Debug)]
pub enum Cause {
    /// Original OS cause and action.
    Io(&'static str, io::Error),
    /// Original packet builder/parser resource failure.
    Packet(gnunet_types::Error),
    /// Invalid explicit CLI input.
    Usage(&'static str),
    /// Actual positive short/zero raw datagram outcome is uncertain.
    ShortPacket {
        /// Full original datagram length.
        expected: usize,
        /// Actual prefix accepted by the original raw socket.
        actual: usize,
    },
    /// Original native I/O deadline.
    Deadline(&'static str),
    /// Current target has no qualified raw-kernel ABI.
    Unsupported,
    /// Actual original stop was received before a complete request.
    Stopped,
    /// Primary operation completed but actual cleanup failed.
    Cleanup,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NAT helper code{}: {:?}; output cleanup={:?}; signal cleanup={:?}; second packet={:?}",
            self.code, self.cause, self.output_cleanup, self.signal_cleanup, self.secondary
        )
    }
}
impl std::error::Error for Failure {}
fn failure(code: u8, cause: Cause) -> Failure {
    Failure {
        code,
        cause,
        secondary: None,
        output_cleanup: None,
        signal_cleanup: None,
    }
}
#[cfg(target_os = "linux")]
#[path = "linux.rs"]
mod platform;
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
#[path = "bsd.rs"]
mod platform;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
mod runner;
/// Actual client entry. Raw capture and permanent credential drop precede CLI
/// parsing. Returns success only after both complete original local packet writes.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
pub fn client() -> Result<(), Failure> {
    runner::client()
}
/// Actual server entry. Stdin carries no commands. Stdout is only official lines;
/// original parent/stop, raw IO and bounded line deadlines own its lifetime.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
pub fn server() -> Result<(), Failure> {
    runner::server()
}
/// Unsupported targets perform no capability/socket/credential operation.
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
pub fn client() -> Result<(), Failure> {
    Err(failure(1, Cause::Unsupported))
}
/// Unsupported targets perform no capability/socket/credential operation.
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
pub fn server() -> Result<(), Failure> {
    Err(failure(1, Cause::Unsupported))
}
/// One bounded best-effort stderr diagnostic. It never writes a protocol line.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
pub fn diagnostic(error: &Failure) {
    use std::fmt::Write;
    let mut line = runner::Text::<512>::new();
    let _formatted = writeln!(&mut line, "{error}");
    if let Ok(mut out) = gnunet_native::nat_helper::Output::stderr() {
        let _written = out.write(line.bytes());
        let _restored = out.restore();
    }
}
/// Unsupported-target diagnostic has no native boundary or privileged execution.
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
pub fn diagnostic(error: &Failure) {
    use std::io::Write;
    let _report = writeln!(std::io::stderr().lock(), "{error}");
}
