//! Source-pinned GNUnet BLOCK context and duplicate-group primitives.
//!
//! Caller buffers, time, entropy and plugin selection are explicit. No dynamic
//! C plugin loading, allocation, OS access or private wire format is introduced.
#![no_std]
#![forbid(unsafe_code)]
pub mod bloom;
pub mod callbacks;
pub mod plugins;
/// Shared GNUnet PoW primitive with caller-owned work memory.
pub use gnunet_crypto::pow;
pub mod regex;
pub mod revocation;
use gnunet_types::Error;
/// Explicit resource/malformed error shared by core and caller plugin implementations.
pub use gnunet_types::Error as ResourceError;
/// Official64-byte SHA-512 result.
pub type Hash = [u8; 64];
/// Official GANA block number, including unknown values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockType(pub u32);
impl BlockType {
    /// Sentinel/wildcard, not a plugin-dispatched concrete type.
    pub const ANY: Self = Self(0);
    /// FS leaf content.
    pub const FS_DBLOCK: Self = Self(1);
    /// FS tree node.
    pub const FS_IBLOCK: Self = Self(2);
    /// FS local on-demand metadata, not an installed block plugin type.
    pub const FS_ONDEMAND: Self = Self(6);
    /// Legacy HELLO, not an installed default plugin type.
    pub const LEGACY_HELLO: Self = Self(7);
    /// DHT testing value.
    pub const TEST: Self = Self(8);
    /// FS universal signed result.
    pub const FS_UBLOCK: Self = Self(9);
    /// DNS service advertisement.
    pub const DNS: Self = Self(10);
    /// GNS encrypted record block.
    pub const GNS_NAMERECORD: Self = Self(11);
    /// Key revocation proof.
    pub const REVOCATION: Self = Self(12);
    /// DHT HELLO block.
    pub const DHT_HELLO: Self = Self(13);
    /// Regex state block.
    pub const REGEX: Self = Self(22);
    /// Signed regex accepting state.
    pub const REGEX_ACCEPT: Self = Self(23);
    /// Installed active contrib generic SET test plugin type.
    pub const SET_TEST: Self = Self(24);
    /// Installed active contrib CONSENSUS wrapper plugin type.
    pub const CONSENSUS_ELEMENT: Self = Self(25);
    /// Set intersection test.
    pub const SETI_TEST: Self = Self(26);
    /// Set union test.
    pub const SETU_TEST: Self = Self(27);
}
/// Exact `GNUNET_GenericReturnValue`, retaining NO versus SYSERR.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum ReturnValue {
    /// Unsupported operation or plugin-specific error.
    SysErr = -1,
    /// Negative result, distinct from unsupported.
    No = 0,
    /// OK and YES have the same official value.
    Yes = 1,
}
/// Official reply classification; block/signature checks are separate operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum ReplyEvaluation {
    /// No plugin owns the concrete block type.
    Unsupported = -1,
    /// Likely duplicate in the original group.
    Duplicate = 0,
    /// Valid but irrelevant to this query.
    Irrelevant = 1,
    /// Relevant; additional results may follow.
    More = 2,
    /// Last possible result.
    Last = 3,
}
/// Presence of the optional void mark-seen callback. The public C wrapper can
/// return only YES (callback ran) or SYSERR (callback absent) for a real group.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MarkSeen {
    /// No mark-seen callback is installed.
    Unsupported,
    /// Callback completed; it has no independent C return code.
    Marked,
}
/// Rust replacement for a group's nullable callback vtable.
/// One concrete G fixes the merge callback family at compile time. Returning
/// false for has_merge preserves the source exception which retains bg2.
pub trait GroupState {
    /// Original block type metadata; Bloom merge does not require matching types.
    fn block_type(&self) -> BlockType;
    /// Whether serialization is implemented by this group.
    fn serialize_into(&self, output: &mut [u8]) -> Result<Option<usize>, Error>;
    /// Optional void mark-seen callback, with explicit absence.
    fn mark_seen(&mut self, hashes: &[Hash]) -> MarkSeen;
    /// Whether a merge callback is installed.
    fn has_merge(&self) -> bool;
    /// Merge with another group from the same callback family.
    fn merge_from(&mut self, other: &Self) -> Result<ReturnValue, Error>;
}
/// Explicit ownership outcome for merge's documented-but-exceptional bg2 lifetime.
#[derive(Debug)]
pub enum MergeOutcome<G> {
    /// bg2 was absent, or consumed even when merge returned NO.
    Consumed(ReturnValue),
    /// The left group had no callback: SYSERR and bg2 remains caller-owned.
    Unsupported(G),
}
/// Mirror block.c nullable merge and second-owner consumption rules.
pub fn group_merge<G: GroupState>(
    left: Option<&mut G>,
    right: Option<G>,
) -> Result<MergeOutcome<G>, Error> {
    let Some(right) = right else {
        return Ok(MergeOutcome::Consumed(ReturnValue::Yes));
    };
    let Some(left) = left else {
        drop(right);
        return Ok(MergeOutcome::Consumed(ReturnValue::Yes));
    };
    if !left.has_merge() {
        return Ok(MergeOutcome::Unsupported(right));
    }
    let result = left.merge_from(&right);
    drop(right);
    result.map(MergeOutcome::Consumed)
}
/// Serialization of a NULL group is NO and does not write caller output.
pub fn group_serialize<G: GroupState>(
    group: Option<&G>,
    output: &mut [u8],
) -> Result<Option<usize>, Error> {
    group.map_or(Ok(None), |g| g.serialize_into(output))
}
/// Marking a NULL group succeeds; absent mark callback on a real group is SYSERR.
pub fn group_set_seen<G: GroupState>(group: Option<&mut G>, hashes: &[Hash]) -> ReturnValue {
    group.map_or(ReturnValue::Yes, |g| match g.mark_seen(hashes) {
        MarkSeen::Unsupported => ReturnValue::SysErr,
        MarkSeen::Marked => ReturnValue::Yes,
    })
}

/// Release an optional caller-owned group; Rust Drop replaces its destroy callback.
pub fn group_destroy<G: GroupState>(group: Option<G>) {
    drop(group);
}
