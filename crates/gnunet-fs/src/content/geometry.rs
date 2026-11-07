//! Canonical file geometry over the complete u64 byte-length domain.
use super::{BLOCK_BYTES, CHK_BYTES, MAX_CHILDREN, TAG_BYTES};
use core::ops::Range;
use gnunet_types::Error;

/// Maximum tree levels, including level0 data and level7 index root.
pub const MAX_TREE_LEVELS: u8 = 8;
/// Maximum caller key slots across every internal level for any u64 file.
pub const MAX_FRONTIER_KEYS: usize = 6 * MAX_CHILDREN + 2;

pub(super) fn span(level: u8) -> u128 {
    (BLOCK_BYTES as u128) << (u32::from(level) * 8)
}

/// Canonical geometry. A zero-byte file has one empty data leaf. Every index
/// level multiplies its theoretical covered span by256; spans use u128 so the
/// highest level's2^71 bytes never wrap at u64.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layout {
    size: u64,
    root_level: u8,
}
impl Layout {
    /// Describe any representable file byte length, including zero and u64::MAX.
    #[must_use]
    pub fn new(size: u64) -> Self {
        let mut root_level = 0;
        while span(root_level) < u128::from(size) {
            root_level += 1;
        }
        Self { size, root_level }
    }
    /// Original file length in bytes.
    #[must_use]
    pub const fn size(self) -> u64 {
        self.size
    }
    /// Data is level0; the highest possible root is level7.
    #[must_use]
    pub const fn root_level(self) -> u8 {
        self.root_level
    }
    /// Total levels, counting both data and index layers.
    #[must_use]
    pub const fn levels(self) -> u8 {
        self.root_level + 1
    }
    /// Number of data leaves, with one empty leaf for an empty file.
    #[must_use]
    pub fn leaf_count(self) -> u64 {
        self.count(0)
    }
    pub(super) fn count(self, level: u8) -> u64 {
        u128::from(self.size).div_ceil(span(level)).max(1) as u64
    }
    /// Number of nodes in one present level. Check before multiplying any
    /// caller-supplied ordinal by its theoretical span.
    pub fn node_count(self, level: u8) -> Result<u64, Error> {
        if level > self.root_level {
            return Err(Error::InvalidInput);
        }
        Ok(self.count(level))
    }
    /// Root descriptor; no key or content authentication is implied.
    #[must_use]
    pub const fn root(self) -> Node {
        Node {
            layout: self,
            level: self.root_level,
            ordinal: 0,
        }
    }
    /// Checked canonical node descriptor. Global ordinals are u64 even on
    ///32-bit targets; an invalid ordinal is rejected before wide multiplication.
    pub fn node(self, level: u8, ordinal: u64) -> Result<Node, Error> {
        if level > self.root_level || ordinal >= self.count(level) {
            return Err(Error::InvalidInput);
        }
        Ok(self.node_at(level, ordinal))
    }
    pub(super) const fn node_at(self, level: u8, ordinal: u64) -> Node {
        Node {
            layout: self,
            level,
            ordinal,
        }
    }
    /// Checked data-leaf descriptor in canonical file order.
    pub fn leaf(self, ordinal: u64) -> Result<Node, Error> {
        self.node(0, ordinal)
    }
    /// Reference slots reserved by the frontier's per-level buckets or the
    /// range walker's parent frames. At most1538slots for any file length.
    #[must_use]
    pub fn required_keys(self) -> usize {
        (1..=self.root_level)
            .map(|level| self.level_keys(level))
            .sum()
    }
    fn level_keys(self, level: u8) -> usize {
        self.count(level - 1).min(MAX_CHILDREN as u64) as usize
    }
    pub(super) fn slots(self, level: u8) -> Range<usize> {
        let start: usize = (1..level).map(|lower| self.level_keys(lower)).sum();
        start..start + self.level_keys(level)
    }
    /// Theoretical total ciphertext bytes over every node, including tags.
    /// This may exceed u64 and is not a processed-byte or verification counter.
    #[must_use]
    pub fn encoded_tree_bytes(self) -> u128 {
        let mut total = u128::from(self.size) + u128::from(self.leaf_count()) * TAG_BYTES as u128;
        for level in 1..=self.root_level {
            total += u128::from(self.count(level - 1)) * CHK_BYTES as u128
                + u128::from(self.count(level)) * TAG_BYTES as u128;
        }
        total
    }
}

/// A checked node position and size context. Theoretical spans and endpoint
/// sums remain wide until clipping to the file's representable endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Node {
    layout: Layout,
    level: u8,
    ordinal: u64,
}
impl Node {
    /// Complete size context retained by the descriptor.
    #[must_use]
    pub const fn layout(self) -> Layout {
        self.layout
    }
    /// Level0 data, or index levels1..7.
    #[must_use]
    pub const fn level(self) -> u8 {
        self.level
    }
    /// Global ordinal within this level.
    #[must_use]
    pub const fn ordinal(self) -> u64 {
        self.ordinal
    }
    /// Theoretical covered byte span, possibly greater than u64::MAX.
    #[must_use]
    pub fn span(self) -> u128 {
        span(self.level)
    }
    /// Exact half-open file range, clipped before conversion to u64.
    #[must_use]
    pub fn range(self) -> Range<u64> {
        let start = u128::from(self.ordinal) * self.span();
        start as u64..(start + self.span()).min(u128::from(self.layout.size)) as u64
    }
    /// First data-leaf ordinal represented by this node.
    #[must_use]
    pub fn first_leaf(self) -> u64 {
        self.range().start / BLOCK_BYTES as u64
    }
    /// Number of data leaves represented, including the one virtual empty leaf.
    #[must_use]
    pub fn leaf_count(self) -> u64 {
        let range = self.range();
        (range.end - range.start)
            .div_ceil(BLOCK_BYTES as u64)
            .max(1)
    }
    /// Zero for a DBLOCK; exact1..256 children for an IBLOCK, retaining required
    /// single-child tail index nodes rather than collapsing their levels.
    #[must_use]
    pub fn child_count(self) -> usize {
        if self.level == 0 {
            return 0;
        }
        let range = self.range();
        u128::from(range.end - range.start).div_ceil(span(self.level - 1)) as usize
    }
    /// Exact plaintext length, at most32768bytes, before the detached tag.
    #[must_use]
    pub fn plaintext_bytes(self) -> usize {
        if self.level == 0 {
            let range = self.range();
            (range.end - range.start) as usize
        } else {
            self.child_count() * CHK_BYTES
        }
    }
    /// Parent in this file tree; the canonical root has no parent.
    #[must_use]
    pub fn parent(self) -> Option<Self> {
        if self.level == self.layout.root_level {
            return None;
        }
        Some(
            self.layout
                .node_at(self.level + 1, self.ordinal / MAX_CHILDREN as u64),
        )
    }
    /// Checked child descriptor. Child ordinals remain global within their level.
    pub fn child(self, index: usize) -> Result<Self, Error> {
        if index >= self.child_count() {
            return Err(Error::InvalidInput);
        }
        Ok(self.child_at(index))
    }
    pub(super) fn child_at(self, index: usize) -> Self {
        self.layout.node_at(
            self.level - 1,
            self.ordinal * MAX_CHILDREN as u64 + index as u64,
        )
    }
    /// Whether a nonempty half-open byte range overlaps this node.
    #[must_use]
    pub fn intersects(self, query: &Range<u64>) -> bool {
        let range = self.range();
        query.start < query.end && range.start < query.end && query.start < range.end
    }
}
