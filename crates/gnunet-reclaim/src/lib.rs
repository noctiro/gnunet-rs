//! Checked RECLAIM objects and active v0.29.1 local IPC, without allocation by default.
//!
//! Default codecs do not sign/verify credentials, generate identifiers or contact
//! a resolver. The explicit alloc business module plans real ticket operations
//! through caller-driven provider effects; local writes are never service results.
//! Borrowed sensitive fields must live in caller-owned storage erased by that caller.
#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
pub mod business;
pub mod ipc;
pub mod objects;
#[cfg(feature = "alloc")]
pub mod owned;
pub mod sequence;

pub use objects::{
    Attribute, AttributeType, Credential, CredentialType, Identifier, Name, Presentation,
    Sensitive, Ticket, Uri,
};
pub use sequence::{AttributeList, CredentialList, List, ListLimits, PresentationList};

/// Exact public upstream source revision used for these encodings.
pub const UPSTREAM_REVISION: &str = "346358e26d4dcc2dc4f51bef5d52dca29c7d8165";

pub(crate) fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}
pub(crate) fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}
pub(crate) fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_be_bytes());
}
pub(crate) fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_be_bytes());
}
