//! Explicit owned-Unix observation adapter for the ARM core.
#[cfg(unix)]
#[path = "public_owner/unix.rs"]
mod unix;

#[cfg(unix)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    unix::main()
}

#[cfg(not(unix))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    Err("public_owner requires Unix sockets".into())
}
