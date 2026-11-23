//! Bounded complete-member compression primitives shared by protocol owners.
//! The caller owns all message storage. There is no native I/O or worker.
#![no_std]
#![forbid(unsafe_code)]
#[cfg(feature = "fixed-zlib")]
mod fixed_zlib;
#[cfg(feature = "fixed-zlib")]
pub use fixed_zlib::FixedZlib;
#[cfg(any(feature = "alloc", feature = "fixed-zlib"))]
mod inflate;
#[cfg(any(feature = "alloc", feature = "fixed-zlib"))]
pub use inflate::INFLATE_WINDOW_BYTES;
#[cfg(feature = "alloc")]
mod zlib;
#[cfg(feature = "alloc")]
pub use zlib::Zlib;
