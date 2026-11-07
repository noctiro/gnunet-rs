//! Authenticated nodes and caller-driven bounded depth-first range traversal.
use super::{
    BlockKey, CHK_BYTES, Content, Layout, MAX_TREE_LEVELS, Node, TAG_BYTES, open_data, read_key,
};
use core::ops::Range;
use gnunet_types::Error;

/// A position-bound lookup reference. Constructing it does not authenticate the
/// target or prove availability; open must verify its bytes before traversal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeRef {
    node: Node,
    key: BlockKey,
}
impl NodeRef {
    /// Pair a checked position with an untrusted key/query lookup reference.
    #[must_use]
    pub const fn new(node: Node, key: BlockKey) -> Self {
        Self { node, key }
    }
    /// Form the canonical root lookup from a public CHK URI's fixed fields.
    #[must_use]
    pub fn root(content: Content) -> Self {
        Self {
            node: Layout::new(content.size).root(),
            key: BlockKey {
                key: content.key,
                query: content.query,
            },
        }
    }
    /// Canonical file position and size context.
    #[must_use]
    pub const fn node(self) -> Node {
        self.node
    }
    /// Expected plaintext key and ciphertext query.
    #[must_use]
    pub const fn key(self) -> BlockKey {
        self.key
    }
    /// Verify exact size-derived shape, query, tag and plaintext key. Failure
    /// follows open_data's capacity/framing preservation and authentication wipe.
    /// A successful parent authenticates child references, not child contents.
    pub fn open<'a>(
        self,
        ciphertext: &[u8],
        output: &'a mut [u8],
    ) -> Result<OpenedNode<'a>, Error> {
        if ciphertext.len() != self.node.plaintext_bytes() + TAG_BYTES {
            return Err(Error::Malformed);
        }
        let plaintext = open_data(self.key, ciphertext, output)?;
        Ok(OpenedNode {
            reference: self,
            plaintext,
        })
    }
}

/// An authenticated node borrowing caller plaintext storage. Level context is
/// external geometry, not a private wire type tag or AAD domain.
#[derive(Clone, Copy, Debug)]
pub struct OpenedNode<'a> {
    reference: NodeRef,
    plaintext: &'a [u8],
}
impl<'a> OpenedNode<'a> {
    /// Exact position/key whose bytes were authenticated.
    #[must_use]
    pub const fn reference(self) -> NodeRef {
        self.reference
    }
    /// Plain file bytes for a data leaf, including an empty file's empty leaf.
    #[must_use]
    pub fn data(self) -> Option<&'a [u8]> {
        (self.reference.node.level() == 0).then_some(self.plaintext)
    }
    /// Obtain one authenticated child lookup reference. Its target still needs
    /// its own open, and single-child tail indexes retain their actual level.
    pub fn child(self, index: usize) -> Result<NodeRef, Error> {
        let node = self.reference.node.child(index)?;
        Ok(NodeRef::new(
            node,
            read_key(&self.plaintext.as_chunks::<CHK_BYTES>().0[index]),
        ))
    }
    /// Iterate exact child lookups; data nodes have no children, even when their
    /// bytes happen to look like a128-byte key/query pair.
    pub fn children(self) -> impl ExactSizeIterator<Item = NodeRef> + 'a {
        let node = self.reference.node;
        self.plaintext
            .as_chunks::<CHK_BYTES>()
            .0
            .iter()
            .take(node.child_count())
            .enumerate()
            .map(move |(index, bytes)| NodeRef::new(node.child_at(index), read_key(bytes)))
    }
}

/// Selected plaintext with its original half-open file coordinates.
#[derive(Clone, Debug)]
pub struct DataSlice<'a> {
    /// Exact selected byte range, after clipping the authenticated leaf.
    pub range: Range<u64>,
    /// Caller-owned plaintext for that range.
    pub bytes: &'a [u8],
}

#[derive(Clone, Copy)]
struct Frame {
    node: Node,
    next_child: u16,
}

/// Bounded depth-first traversal of a nonempty selected range. It exposes the
/// same pending lookup until a matching authenticated node is accepted. It owns
/// no I/O, plaintext buffers or allocator. An empty range requests no nodes and
/// authenticates nothing; use NodeRef::root(...).open for an empty-file proof.
pub struct RangeTraversal<'a> {
    layout: Layout,
    range: Range<u64>,
    keys: &'a mut [BlockKey],
    frames: [Option<Frame>; MAX_TREE_LEVELS as usize - 1],
    pending: Option<NodeRef>,
}
impl<'a> RangeTraversal<'a> {
    /// Validate range and storage before changing any caller slots. Nonempty
    /// ranges require Layout::required_keys slots; empty ranges need no slots.
    pub fn new(
        content: Content,
        range: Range<u64>,
        keys: &'a mut [BlockKey],
    ) -> Result<Self, Error> {
        if range.start > range.end || range.end > content.size {
            return Err(Error::InvalidInput);
        }
        let layout = Layout::new(content.size);
        let empty = range.start == range.end;
        if !empty && keys.len() < layout.required_keys() {
            return Err(Error::Capacity);
        }
        Ok(Self {
            layout,
            range,
            keys,
            frames: [None; MAX_TREE_LEVELS as usize - 1],
            pending: (!empty).then(|| NodeRef::root(content)),
        })
    }
    /// Exact next lookup. A framing, capacity or crypto error in NodeRef::open
    /// leaves this pending lookup unchanged and can be retried by the caller.
    #[must_use]
    pub const fn next(&self) -> Option<NodeRef> {
        self.pending
    }
    fn next_from_frames(&mut self) -> Option<NodeRef> {
        for level in 1..=self.layout.root_level() {
            let group = usize::from(level - 1);
            if let Some(mut frame) = self.frames[group] {
                while usize::from(frame.next_child) < frame.node.child_count() {
                    let index = usize::from(frame.next_child);
                    frame.next_child += 1;
                    self.frames[group] = Some(frame);
                    let child = frame.node.child_at(index);
                    if child.intersects(&self.range) {
                        let slots = self.layout.slots(level);
                        return Some(NodeRef::new(child, self.keys[slots.start + index]));
                    }
                }
                self.frames[group] = None;
            }
        }
        None
    }
    /// Advance only after the exact pending node was authenticated. Parent keys
    /// are copied into bounded caller storage; leaf data is returned borrowed.
    /// An unrelated/stale authenticated node changes no traversal state.
    pub fn accept<'b>(&mut self, opened: OpenedNode<'b>) -> Result<Option<DataSlice<'b>>, Error> {
        let expected = self.pending.ok_or(Error::Closed)?;
        if opened.reference != expected {
            return Err(Error::InvalidInput);
        }
        let node = expected.node;
        let selected = if let Some(data) = opened.data() {
            let full = node.range();
            let start = full.start.max(self.range.start);
            let end = full.end.min(self.range.end);
            let offset = (start - full.start) as usize;
            let length = (end - start) as usize;
            Some(DataSlice {
                range: start..end,
                bytes: &data[offset..offset + length],
            })
        } else {
            let slots = self.layout.slots(node.level());
            for (index, child) in opened.children().enumerate() {
                self.keys[slots.start + index] = child.key;
            }
            self.frames[usize::from(node.level() - 1)] = Some(Frame {
                node,
                next_child: 0,
            });
            None
        };
        self.pending = self.next_from_frames();
        Ok(selected)
    }
}
