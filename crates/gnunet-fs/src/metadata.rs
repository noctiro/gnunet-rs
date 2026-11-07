//! Official v2 metadata with caller buffers and explicit codec capabilities.
//!
//! Raw records, C-compatible container transformations and partial selection are
//! separate. Recovered prefixes are reported explicitly and are never complete
//! containers. This module owns no allocation, file, network or codec backend.
mod decode;
mod records;
mod semantics;
mod serialize;

pub use decode::{
    Decoded, Metadata, Mode, Recovery, decode, decode_length_prefixed, decode_uncompressed,
};
pub use records::{Format, Item, Items, c_prefix};
pub use semantics::{Insert, Set, normalize_filename};
pub use serialize::{
    Compression, Inclusion, Options, Plan, Report, plan, plan_uncompressed, write_absent,
};

/// Serialized v2 envelope bytes, excluding its body.
pub const HEADER_BYTES: usize = 12;
/// Serialized descriptor bytes per metadata item.
pub const ENTRY_BYTES: usize = 20;
/// Compression flag in the big-endian version word.
pub const COMPRESSED: u32 = 0x8000_0000;

/// Caller resource policy, distinct from any embedding's wire budget.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Complete coded artifact bytes, including the header.
    pub max_coded_bytes: usize,
    /// Decompressed descriptor array and variable payload bytes.
    pub max_plain_bytes: usize,
    /// Declared or source item count.
    pub max_entries: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_coded_bytes: 1024 * 1024,
            max_plain_bytes: 8 * 1024 * 1024,
            max_entries: 4096,
        }
    }
}

/// Why an entry cannot be interpreted as the declared value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryIssue {
    /// Unknown value format; metadata types themselves remain open u32 values.
    Format,
    /// A declared field exceeds the remaining variable payload.
    Length,
    /// A required final zero byte is absent, or string data has length zero.
    Terminator,
}

/// Codec failure without a partially validated metadata result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodecError {
    /// The caller did not select this codec capability.
    Unavailable,
    /// The supplied output buffer cannot hold the complete coded/plain body.
    Capacity,
    /// Invalid stream, header, dictionary requirement or checksum.
    Invalid,
    /// Incomplete input or an unfinished stream with no further progress.
    Truncated,
    /// Produced output differs from the declared body length.
    Length,
    /// Bytes remain after the complete zlib member.
    Trailing,
}

/// Metadata parsing/planning failure. Final serializer output is untouched.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Fewer than twelve envelope bytes are available.
    Truncated,
    /// An unsupported low version value, distinct from the recognized v1 null.
    Version(u32),
    /// Input, body or item count exceeds explicit caller limits.
    Limit,
    /// A checked length calculation is not representable.
    Overflow,
    /// Caller workspace or final output is too short.
    Capacity,
    /// Body framing or an explicit constructor input is invalid.
    Invalid,
    /// A declared entry is invalid; the index is its wire descriptor index.
    Entry {
        /// Zero-based descriptor index.
        index: u32,
        /// Exact field failure category.
        issue: EntryIssue,
    },
    /// Complete entry processing left unreferenced payload bytes.
    Trailing(usize),
    /// A real codec operation failed or violated its byte-count contract.
    Codec(CodecError),
    /// The bounded number of candidate plans was exhausted.
    Work,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "metadata {self:?}")
    }
}
impl core::error::Error for Error {}

/// Successful complete zlib operation counters, checked again by the core.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Progress {
    /// Complete coded/source input consumed.
    pub consumed: usize,
    /// Complete produced output prefix.
    pub produced: usize,
}

/// Complete zlib inflation into a caller-owned non-wrapping body buffer.
/// Success must validate stream termination and Adler32. Each operation resets
/// its independent stream state; no dictionary or C/FFI fallback is implicit.
pub trait Inflater {
    /// Decode one member. Output may be scratch-written on failure.
    fn inflate(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, CodecError>;
}
/// Complete zlib compression with explicit, reusable caller-owned codec state.
/// This trait does not promise that constructing its implementation is noalloc.
pub trait Deflater {
    /// Encode one complete member, resetting any previous stream state first.
    fn deflate(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, CodecError>;
}
/// Explicit absence of a compression/decompression capability.
#[derive(Default)]
pub struct NoCodec;
impl Inflater for NoCodec {
    fn inflate(&mut self, _: &[u8], _: &mut [u8]) -> Result<Progress, CodecError> {
        Err(CodecError::Unavailable)
    }
}
impl Deflater for NoCodec {
    fn deflate(&mut self, _: &[u8], _: &mut [u8]) -> Result<Progress, CodecError> {
        Err(CodecError::Unavailable)
    }
}

fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}
