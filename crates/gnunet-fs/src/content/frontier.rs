//! Bounded prefix assembly over references, without hashing or authentication.
use super::{BlockKey, Content, Layout, MAX_CHILDREN, MAX_TREE_LEVELS, Node};
use gnunet_types::Error;

/// Pending index inputs borrowed from the caller's reference storage.
#[derive(Clone, Copy, Debug)]
pub struct IndexInput<'a> {
    /// Canonical index node being materialized.
    pub node: Node,
    /// Exact ordered child references, including duplicates.
    pub children: &'a [BlockKey],
}

enum Placement {
    Root,
    Child {
        parent: Node,
        group: usize,
        slot: usize,
        count: u16,
        full: bool,
    },
}

/// Geometry-only assembly of a canonical prefix. Supplied references are not
/// authenticated and do not prove that the underlying file bytes exist. This
/// layer can accept aligned precomputed subtrees; FileEncoder privately restricts
/// its own frontier to keys actually produced by block encoding.
pub struct ReferenceFrontier<'a> {
    layout: Layout,
    keys: &'a mut [BlockKey],
    counts: [u16; MAX_TREE_LEVELS as usize - 1],
    parents: [u64; MAX_TREE_LEVELS as usize - 1],
    next_leaf: u64,
    pending: Option<Node>,
    root: Option<BlockKey>,
}
impl<'a> ReferenceFrontier<'a> {
    /// Borrow caller storage. Capacity refusal leaves all slots unchanged.
    pub fn new(size: u64, keys: &'a mut [BlockKey]) -> Result<Self, Error> {
        let layout = Layout::new(size);
        if keys.len() < layout.required_keys() {
            return Err(Error::Capacity);
        }
        Ok(Self {
            layout,
            keys,
            counts: [0; MAX_TREE_LEVELS as usize - 1],
            parents: [0; MAX_TREE_LEVELS as usize - 1],
            next_leaf: 0,
            pending: None,
            root: None,
        })
    }
    /// Complete canonical geometry.
    #[must_use]
    pub const fn layout(&self) -> Layout {
        self.layout
    }
    /// Data-leaf ordinal after the accepted reference prefix. It is not an
    /// authenticated or processed-file-byte counter.
    #[must_use]
    pub const fn next_leaf(&self) -> u64 {
        self.next_leaf
    }
    /// Next node to materialize when supplying ordinary data leaves. A pending
    /// index must be recorded before another external reference can be accepted.
    #[must_use]
    pub fn next(&self) -> Option<Node> {
        if self.root.is_some() {
            return None;
        }
        self.pending.or_else(|| {
            (self.next_leaf < self.layout.leaf_count())
                .then(|| self.layout.node_at(0, self.next_leaf))
        })
    }
    /// Current pending index and its exact child list.
    #[must_use]
    pub fn pending_index(&self) -> Option<IndexInput<'_>> {
        let node = self.pending?;
        let slots = self.layout.slots(node.level());
        let count = usize::from(self.counts[usize::from(node.level() - 1)]);
        Some(IndexInput {
            node,
            children: &self.keys[slots.start..slots.start + count],
        })
    }
    /// Root reference after the complete canonical structure has been recorded.
    /// Only the plaintext FileEncoder grants hashing/encoding meaning to this value.
    #[must_use]
    pub fn content(&self) -> Option<Content> {
        self.root.map(|key| key.content(self.layout.size()))
    }
    fn placement(&self, node: Node) -> Result<Placement, Error> {
        let Some(parent) = node.parent() else {
            return Ok(Placement::Root);
        };
        let group = usize::from(parent.level() - 1);
        let count = usize::from(self.counts[group]);
        if count != (node.ordinal() % MAX_CHILDREN as u64) as usize
            || count >= parent.child_count()
            || (count > 0 && self.parents[group] != parent.ordinal())
        {
            return Err(Error::InvalidInput);
        }
        let slots = self.layout.slots(parent.level());
        Ok(Placement::Child {
            parent,
            group,
            slot: slots.start + count,
            count: (count + 1) as u16,
            full: count + 1 == parent.child_count(),
        })
    }
    fn place(&mut self, placement: Placement, key: BlockKey) {
        match placement {
            Placement::Root => {
                self.root = Some(key);
                self.pending = None;
            }
            Placement::Child {
                parent,
                group,
                slot,
                count,
                full,
            } => {
                self.keys[slot] = key;
                self.counts[group] = count;
                self.parents[group] = parent.ordinal();
                self.pending = full.then_some(parent);
            }
        }
    }
    /// Record an unverified reference covering exactly the next aligned prefix.
    /// A precomputed higher node may skip data leaves only when lower groups are
    /// empty. Invalid/stale positions and pending-index refusal change no state.
    pub fn accept_reference(&mut self, node: Node, key: BlockKey) -> Result<(), Error> {
        if self.root.is_some() {
            return Err(Error::Closed);
        }
        if self.pending.is_some() {
            return Err(Error::WouldBlock);
        }
        if node.layout() != self.layout
            || node.first_leaf() != self.next_leaf
            || self.counts[..usize::from(node.level())]
                .iter()
                .any(|count| *count != 0)
        {
            return Err(Error::InvalidInput);
        }
        let end = self
            .next_leaf
            .checked_add(node.leaf_count())
            .ok_or(Error::Overflow)?;
        if end > self.layout.leaf_count() {
            return Err(Error::InvalidInput);
        }
        let placement = self.placement(node)?;
        self.place(placement, key);
        self.next_leaf = end;
        Ok(())
    }
    /// Record the pending index key and promote it without advancing the data
    /// cursor twice. This performs geometry only; callers must actually encode
    /// the exact child list if they need a valid content artifact.
    pub fn record_index(&mut self, key: BlockKey) -> Result<(), Error> {
        if self.root.is_some() {
            return Err(Error::Closed);
        }
        let node = self.pending.ok_or(Error::WouldBlock)?;
        let group = usize::from(node.level() - 1);
        if self.counts[group] as usize != node.child_count()
            || self.parents[group] != node.ordinal()
            || self.counts[..group].iter().any(|count| *count != 0)
            || node.first_leaf() + node.leaf_count() != self.next_leaf
        {
            return Err(Error::InvalidInput);
        }
        let placement = self.placement(node)?;
        self.counts[group] = 0;
        self.pending = None;
        self.place(placement, key);
        Ok(())
    }
}
