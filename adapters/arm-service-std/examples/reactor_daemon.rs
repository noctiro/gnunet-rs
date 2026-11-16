//! Unix native descriptor/process fixture entry.
#[cfg(unix)]
#[path = "reactor_daemon/unix.rs"]
mod unix;
#[cfg(unix)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    unix::run()
}
#[cfg(not(unix))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "this descriptor/process fixture requires the Unix ARM native port",
    )
    .into())
}
