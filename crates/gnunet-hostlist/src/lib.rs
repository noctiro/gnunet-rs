//! Official HOSTLIST framing and bounded caller-driven bootstrap/publication state.
//! No HTTP, DNS, socket, scheduler, storage, or implicit peer authority lives here.
#![no_std]
#![forbid(unsafe_code)]
#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
mod state;
pub use gnunet_types::Error;
use gnunet_wire::official::message_type::HOSTLIST_ADVERTISEMENT;
#[cfg(feature = "alloc")]
pub use state::*;
#[cfg(all(test, feature = "alloc"))]
mod model;

/// Official default URL byte bound, excluding final C NUL.
pub const URL_BYTES: usize = 1000;
/// Official hostlist binary body cap.
pub const BODY_BYTES: usize = 500_000;
/// Official connection threshold above which bootstrap rounds are unnecessary.
pub const MIN_CONNECTIONS: usize = 4;

/// Borrowed actual advertisement. Active C emits header4 + URL + NUL, without
/// the reserved field declared in its unused struct. Accepted ignored-tail bytes
/// are preserved, while `uri` follows the consumer's first-NUL semantics.
#[derive(Clone, Copy)]
pub struct Advertisement<'a> {
    uri: &'a [u8],
    tail: &'a [u8],
}
impl core::fmt::Debug for Advertisement<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Advertisement")
            .field("uri", &"[redacted]")
            .field("bytes", &self.tail.len())
            .finish()
    }
}
impl<'a> Advertisement<'a> {
    /// Canonical new producer, without an embedded or terminal NUL.
    pub fn new(uri: &'a [u8]) -> Result<Self, Error> {
        if uri.is_empty() || uri.len() > URL_BYTES || uri.contains(&0) {
            return Err(Error::InvalidInput);
        }
        Ok(Self { uri, tail: uri })
    }
    /// Decode one exact official CORE payload; only final NUL is mandatory in C.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        if input.len() < 5
            || input.len() != usize::from(u16::from_be_bytes([input[0], input[1]]))
            || u16::from_be_bytes([input[2], input[3]]) != HOSTLIST_ADVERTISEMENT.value()
            || input.last() != Some(&0)
        {
            return Err(Error::Malformed);
        }
        let tail = &input[4..input.len() - 1];
        let first = tail.iter().position(|b| *b == 0).unwrap_or(tail.len());
        if first == 0 || first > URL_BYTES {
            return Err(Error::Capacity);
        }
        Ok(Self {
            uri: &tail[..first],
            tail,
        })
    }
    /// Exact consumer-visible URI; it is opaque potentially sensitive data.
    pub const fn uri(self) -> &'a [u8] {
        self.uri
    }
    /// Preserve accepted ignored-tail bytes, excluding final NUL.
    pub const fn wire_uri(self) -> &'a [u8] {
        self.tail
    }
    /// Required full frame size.
    pub fn encoded_len(self) -> Result<usize, Error> {
        self.tail
            .len()
            .checked_add(5)
            .filter(|n| *n <= u16::MAX as usize)
            .ok_or(Error::TooLarge)
    }
    /// Encode a complete official message atomically into caller capacity.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len()?;
        if out.len() < n {
            return Err(Error::Capacity);
        }
        out[..2].copy_from_slice(&(n as u16).to_be_bytes());
        out[2..4].copy_from_slice(&HOSTLIST_ADVERTISEMENT.value().to_be_bytes());
        out[4..n - 1].copy_from_slice(self.tail);
        out[n - 1] = 0;
        Ok(n)
    }
}

/// Noalloc iterator over one complete HTTP binary body. Every element is one
/// exact bounded GNUnet frame; HELLO type/signature/expiry checking is separate.
pub struct Frames<'a> {
    input: &'a [u8],
    failed: bool,
}
impl<'a> Frames<'a> {
    /// Reject an oversized body before any iteration.
    pub fn new(input: &'a [u8], limit: usize) -> Result<Self, Error> {
        if input.len() > limit {
            return Err(Error::Capacity);
        }
        Ok(Self {
            input,
            failed: false,
        })
    }
}
impl<'a> Iterator for Frames<'a> {
    type Item = Result<&'a [u8], Error>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.input.is_empty() {
            return None;
        }
        if self.input.len() < 4 {
            self.failed = true;
            return Some(Err(Error::Truncated));
        }
        let n = usize::from(u16::from_be_bytes([self.input[0], self.input[1]]));
        if n < 4 {
            self.failed = true;
            return Some(Err(Error::Malformed));
        }
        if n > self.input.len() {
            self.failed = true;
            return Some(Err(Error::Truncated));
        }
        let (frame, rest) = self.input.split_at(n);
        self.input = rest;
        Some(Ok(frame))
    }
}
