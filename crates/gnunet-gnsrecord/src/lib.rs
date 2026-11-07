//! Official GNUnet GNS record serialization and typed zone identifiers.
//!
//! The wire contract follows GNUnet v0.29.1, commit
//! `346358e26d4dcc2dc4f51bef5d52dca29c7d8165`. The record header contains
//! expiration microseconds, a 16-bit data length, 16-bit flags, and a 32-bit
//! GANA record type. No native magic, network scope, or millisecond conversion
//! is inserted. See the crate's `UPSTREAM.md` for exact reference paths.
//!
//! These codecs do not implement zone signing, record encryption, resolver
//! policy, DNS value interpretation, or authority validation. Unknown record
//! types and flag bits are preserved for the owning protocol to interpret.
//! The separate authoritative-set policy helper checks combinations of types
//! and flags only; it does not establish an owner's authority or record trust.
#![no_std]
#![forbid(unsafe_code)]

mod base32;
mod policy;
pub use policy::{is_gns2dns_security_type, validate_authoritative_records};
mod records;
mod registry;
mod zone;

pub use base32::{base32_encoded_len, decode_base32, encode_base32};
pub use records::{
    MAX_BLOCK_SIZE, RECORD_HEADER_LEN, RecordData, RecordIter, RecordSet, serialize,
    serialize_to_size, serialized_len,
};
pub use registry::{RecordFlags, RecordType};
pub use zone::{ZONE_KEY_LEN, ZONE_TEXT_LEN, ZONE_WIRE_LEN, ZoneKey, ZoneKeyType};
