//! Real Windows local ARM launch, native arguments and cancellation ownership.
#[cfg(windows)]
#[path = "windows_client/native.rs"]
mod native;
#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    native::run()
}
#[cfg(not(windows))]
fn main() {}
