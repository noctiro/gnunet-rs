//! Scalar observations from the operating system's protocol and service databases.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
pub use unix::Database;
#[cfg(windows)]
pub use windows::Database;

#[cfg(not(any(
    windows,
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd"
)))]
pub use unavailable::Database;

#[cfg(not(any(
    windows,
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd"
)))]
mod unavailable {
    use std::{ffi::CStr, io};

    /// The platform has no supported native registry ABI.
    pub struct Database {
        _unavailable: (),
    }

    impl Database {
        /// Report the unavailable native registry.
        pub fn open() -> io::Result<Self> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }

        /// Report the unavailable native protocol lookup.
        pub fn protocol(&mut self, _name: &CStr) -> io::Result<Option<u16>> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }

        /// Report the unavailable native service lookup.
        pub fn service(&mut self, _name: &CStr, _protocol: &CStr) -> io::Result<Option<u16>> {
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }
}
