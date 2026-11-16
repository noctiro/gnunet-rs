//! Unix native descriptor/process fixture entry.
#[cfg(unix)]
#[path = "listener_child/unix.rs"]
mod unix;
#[cfg(unix)]
fn main() -> std::io::Result<()> {
    unix::run()
}
#[cfg(not(unix))]
fn main() -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "this descriptor/process fixture requires the Unix ARM native port",
    ))
}
