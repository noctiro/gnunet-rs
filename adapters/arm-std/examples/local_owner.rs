//! Unix native process/descriptor integration fixture.
#[cfg(unix)]
#[path = "local_owner/unix.rs"]
mod unix;
#[cfg(unix)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    unix::main_entry()
}
#[cfg(not(unix))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "this C/Unix integration fixture requires Unix",
    )
    .into())
}
