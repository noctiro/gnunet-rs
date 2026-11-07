//! Bounded complete-member compression primitives shared by protocol owners.
//! No algorithm, native IO, clock or background worker is supplied here.
#![no_std]
#![forbid(unsafe_code)]
#[cfg(feature = "alloc")]
mod zlib;
#[cfg(feature = "alloc")]
pub use zlib::Zlib;
