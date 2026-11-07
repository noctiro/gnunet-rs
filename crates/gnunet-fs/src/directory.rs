//! Official directory artifacts over caller-owned storage. Parsing syntax does
//! not authenticate a directory source, inline file, path or durable output.
mod build;
mod inline;
mod parse;
mod source;
pub mod walk;
use crate::metadata;
pub use build::{
    BuildOptions, BuildPlan, BuildReport, Inclusion, Placement, PreparedEntry, PreparedMetadata,
    plan,
};
pub use inline::{
    InlineBuffers, InlineHint, VerifiedInline, automatic_inline_fits, hints, verify_inline,
};
pub use parse::{
    Entry, Event, Failure, Parser, Policy, Progress, RangeRef, Segment, Stage, Status, Summary,
};
pub use source::{SourceError, SourceParser, SourceProgress, VerifiedDirectory, VerifiedEntry};

/// Official eight-byte directory prefix.
pub const MAGIC: &[u8; 8] = b"\x89GND\r\n\x1a\n";
/// Entry alignment and partial recovery boundary.
pub const BLOCK_BYTES: u64 = 32768;
/// Directory MIME claim; this does not authenticate content type.
pub const MIME: &[u8] = b"application/gnunet-directory";
/// Canonical metadata item callers may add before planning root metadata.
pub const MIME_ITEM: metadata::Item<'static> = metadata::Item {
    kind: 1,
    format: metadata::Format::Utf8,
    data: b"application/gnunet-directory\0",
    plugin: Some(b"<gnunet>\0"),
    mime: Some(b"text/plain\0"),
};
/// Explicit bounded parsing policy, without a global inline-hint wire cap.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum directory absolute end offset.
    pub max_extent: u64,
    /// Maximum committed entries.
    pub max_entries: usize,
    /// Maximum copied/skipped input plus URI and declared metadata work bytes.
    pub max_work: u64,
    /// Maximum record bytes, including URI/length or directory header.
    pub max_record_bytes: usize,
    /// URI parsing and signature work bounds.
    pub uri: crate::Limits,
    /// Metadata coded/plain/item bounds.
    pub metadata: metadata::Limits,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_extent: 64 * 1024 * 1024,
            max_entries: 4096,
            max_work: 256 * 1024 * 1024,
            max_record_bytes: 2 * 1024 * 1024,
            uri: crate::Limits::default(),
            metadata: metadata::Limits::default(),
        }
    }
}
/// Typed refusal shared by parser, builder and inline verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Checked arithmetic or representation failed.
    Overflow,
    /// A caller resource/work bound was exceeded.
    Limit,
    /// Caller storage is too small; no final builder output was changed.
    Capacity,
    /// Segment gap, overlap, inconsistent extent or invalid constructor input.
    Input,
    /// Initial magic differs from the official bytes.
    Magic,
    /// Known final extent ended inside a required field.
    Truncated,
    /// Metadata cannot be null/absent in this directory context.
    NullMetadata,
    /// KSK is not a directory entry.
    Keyword,
    /// URI parser rejected the textual representation.
    Uri(gnunet_types::Error),
    /// Raw metadata decoding/planning failed.
    Metadata(metadata::Error),
    /// Content encoding failed; scratch may have been used.
    Content(gnunet_types::Error),
    /// Unresolved namespace has no contextual CHK for verification.
    Unresolved,
    /// Hint length or actual encoded root key/query differs from contextual CHK.
    Authentication,
    /// Full metadata policy cannot accept a known partial selection.
    PartialMetadata,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "directory {self:?}")
    }
}
impl core::error::Error for Error {}

/// First textual original-filename projection from the supplied item order.
/// Use a semantic Set's order for C logical projection; raw wire order is distinct.
pub fn filename<'a>(items: impl IntoIterator<Item = metadata::Item<'a>>) -> Option<&'a [u8]> {
    items
        .into_iter()
        .find_map(|item| (item.kind == 180).then(|| item.text()).flatten())
}
/// First textual MIME claim, using bounded ASCII case folding only.
pub fn claims_directory<'a>(items: impl IntoIterator<Item = metadata::Item<'a>>) -> Option<bool> {
    items
        .into_iter()
        .find_map(|item| (item.kind == 1).then(|| item.text()).flatten())
        .map(|value| value.eq_ignore_ascii_case(MIME))
}
fn next_boundary(at: u64) -> Result<u64, Error> {
    (at / BLOCK_BYTES)
        .checked_add(1)
        .and_then(|n| n.checked_mul(BLOCK_BYTES))
        .ok_or(Error::Overflow)
}
fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}
