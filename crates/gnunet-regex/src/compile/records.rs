//! Packed proof text, labels and record metadata shared by both profiles.

use super::{BuildError, Limit, storage::Buffer};
use crate::{BlockEdge, EdgeSource, Hash, encode_state, state_block_len};

#[derive(Clone, Copy)]
pub(super) struct Span {
    pub(super) start: usize,
    pub(super) end: usize,
}

impl Span {
    pub(super) const EMPTY: Self = Self { start: 0, end: 0 };

    pub(super) fn slice<T>(self, data: &[T]) -> &[T] {
        &data[self.start..self.end]
    }
}

#[derive(Clone, Copy)]
pub(super) struct EdgeSlot {
    pub(super) target: usize,
    pub(super) label: Span,
}

impl EdgeSlot {
    pub(super) const EMPTY: Self = Self {
        target: 0,
        label: Span::EMPTY,
    };
}

#[derive(Clone, Copy)]
pub(super) struct RecordSlot {
    pub(super) key: Hash,
    pub(super) proof: Span,
    pub(super) accepting: bool,
    pub(super) edges: Span,
    pub(super) pending: Option<usize>,
}

impl RecordSlot {
    pub(super) const EMPTY: Self = Self {
        key: [0; 64],
        proof: Span::EMPTY,
        accepting: false,
        edges: Span::EMPTY,
        pending: None,
    };
}

#[derive(Clone, Copy)]
pub(super) struct Layout {
    pub(super) states: usize,
    pub(super) records: usize,
    pub(super) edges: usize,
    pub(super) bytes: usize,
    pub(super) language: Span,
    pub(super) work: u64,
}

pub(super) struct Table<'a> {
    pub(super) records: Buffer<'a, RecordSlot>,
    pub(super) edges: Buffer<'a, EdgeSlot>,
    pub(super) bytes: Buffer<'a, u8>,
}

impl Table<'_> {
    pub(super) fn text(&mut self, bytes: &[u8], kind: Limit) -> Result<Span, BuildError> {
        let start = self.bytes.len();
        self.bytes.extend_from_slice(bytes, usize::MAX, kind)?;
        Ok(Span {
            start,
            end: self.bytes.len(),
        })
    }

    pub(super) fn view(&self, layout: Layout) -> AutomatonView<'_> {
        AutomatonView {
            records: &self.records,
            edges: &self.edges,
            bytes: &self.bytes,
            layout,
        }
    }
}

#[cfg(feature = "alloc")]
impl Table<'static> {
    pub(super) fn heap() -> Self {
        Self {
            records: Buffer::heap(),
            edges: Buffer::heap(),
            bytes: Buffer::heap(),
        }
    }
}

/// Caller-owned space for the records, edges and text retained after compiling.
pub struct RecordMemory<const RECORDS: usize, const EDGES: usize, const TEXT: usize> {
    records: [RecordSlot; RECORDS],
    edges: [EdgeSlot; EDGES],
    bytes: [u8; TEXT],
    pub(super) layout: Option<Layout>,
}

impl<const RECORDS: usize, const EDGES: usize, const TEXT: usize>
    RecordMemory<RECORDS, EDGES, TEXT>
{
    /// Empty record storage, suitable for constant initialization.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            records: [RecordSlot::EMPTY; RECORDS],
            edges: [EdgeSlot::EMPTY; EDGES],
            bytes: [0; TEXT],
            layout: None,
        }
    }

    pub(super) fn table(&mut self) -> Table<'_> {
        self.layout = None;
        Table {
            records: Buffer::fixed(&mut self.records),
            edges: Buffer::fixed(&mut self.edges),
            bytes: Buffer::fixed(&mut self.bytes),
        }
    }

    /// Access the last complete compilation, if any.
    #[must_use]
    pub fn view(&self) -> Option<AutomatonView<'_>> {
        let layout = self.layout?;
        Some(AutomatonView {
            records: &self.records[..layout.records],
            edges: &self.edges[..layout.edges],
            bytes: &self.bytes[..layout.bytes],
            layout,
        })
    }

    /// Retire the current compilation so its storage can be reused.
    pub fn clear(&mut self) {
        self.layout = None;
    }
}

impl<const RECORDS: usize, const EDGES: usize, const TEXT: usize> Default
    for RecordMemory<RECORDS, EDGES, TEXT>
{
    fn default() -> Self {
        Self::new()
    }
}

/// Borrowed exact literal transition and its destination.
#[derive(Clone, Copy, Debug)]
pub struct Edge<'a> {
    label: &'a [u8],
    destination: &'a Hash,
}

impl<'a> Edge<'a> {
    /// Nonempty literal edge bytes.
    #[must_use]
    pub const fn label(self) -> &'a [u8] {
        self.label
    }

    /// Exact SHA-512 key of the destination state.
    #[must_use]
    pub const fn destination(self) -> Hash {
        *self.destination
    }
}

/// Borrowed ordered outgoing transition table.
#[derive(Clone, Copy)]
pub struct Edges<'a> {
    view: AutomatonView<'a>,
    slots: &'a [EdgeSlot],
}

impl<'a> Edges<'a> {
    /// Count of outgoing edges.
    #[must_use]
    pub const fn len(self) -> usize {
        self.slots.len()
    }

    /// Whether the state has no outgoing edge.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.slots.is_empty()
    }

    /// Iterate in official block order.
    pub fn iter(self) -> impl ExactSizeIterator<Item = Edge<'a>> {
        self.into_iter()
    }

    fn edge_at(self, slot: &EdgeSlot) -> Edge<'a> {
        Edge {
            label: slot.label.slice(self.view.bytes),
            destination: &self.view.records[slot.target].key,
        }
    }
}

impl core::fmt::Debug for Edges<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

/// Iterates a borrowed record's outgoing transitions.
pub struct EdgeIter<'a> {
    edges: Edges<'a>,
    slots: core::slice::Iter<'a, EdgeSlot>,
}

impl<'a> Iterator for EdgeIter<'a> {
    type Item = Edge<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.slots.next().map(|slot| self.edges.edge_at(slot))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.slots.size_hint()
    }
}

impl ExactSizeIterator for EdgeIter<'_> {}

impl<'a> IntoIterator for Edges<'a> {
    type Item = Edge<'a>;
    type IntoIter = EdgeIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        EdgeIter {
            edges: self,
            slots: self.slots.iter(),
        }
    }
}

impl EdgeSource for Edges<'_> {
    fn len(&self) -> usize {
        (*self).len()
    }

    fn edge(&self, index: usize) -> Option<BlockEdge<'_>> {
        let edge = self.edge_at(self.slots.get(index)?);
        Some(BlockEdge {
            destination: edge.destination(),
            label: edge.label(),
        })
    }
}

/// A complete pure state block view, without any network effects.
#[derive(Clone, Copy, Debug)]
pub struct Record<'a> {
    /// Exact proof bytes, without NUL.
    pub proof: &'a [u8],
    /// SHA-512 key of exactly the proof bytes.
    pub key: Hash,
    /// Whether full consumption at this state accepts.
    pub accepting: bool,
    /// Ordered literal edges and their destination proof keys.
    pub edges: Edges<'a>,
}

impl Record<'_> {
    /// Checked official block byte size.
    pub fn encoded_len(self) -> Result<usize, gnunet_types::Error> {
        state_block_len(self.proof, &self.edges)
    }

    /// Encode the official block into caller storage.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, gnunet_types::Error> {
        encode_state(self.proof, self.accepting, &self.edges, output)
    }
}

/// One minimized state in a completed automaton.
#[derive(Clone, Copy, Debug)]
pub struct State<'a>(Record<'a>);

impl<'a> State<'a> {
    /// Borrow the official record for this state.
    #[must_use]
    pub const fn record(self) -> Record<'a> {
        self.0
    }
}

/// Borrowed sequence of minimized states in compiler order.
#[derive(Clone, Copy)]
pub struct States<'a>(AutomatonView<'a>);

impl<'a> States<'a> {
    /// Number of minimized states, excluding synthetic start records.
    pub const fn len(self) -> usize {
        self.0.layout.states
    }

    /// Whether there is no state.
    pub const fn is_empty(self) -> bool {
        self.len() == 0
    }

    /// Borrow a state by its compiler index.
    pub fn get(self, index: usize) -> Option<State<'a>> {
        (index < self.len()).then(|| State(self.0.record(index)))
    }

    /// Borrow the start state.
    pub fn first(self) -> Option<State<'a>> {
        self.get(0)
    }

    /// Iterate without allocating.
    pub fn iter(self) -> impl ExactSizeIterator<Item = State<'a>> {
        self.into_iter()
    }
}

/// Iterates all minimized states.
pub struct StateIter<'a> {
    view: AutomatonView<'a>,
    indices: core::ops::Range<usize>,
}

impl<'a> Iterator for StateIter<'a> {
    type Item = State<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.indices
            .next()
            .map(|index| State(self.view.record(index)))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.indices.size_hint()
    }
}

impl ExactSizeIterator for StateIter<'_> {}

impl<'a> IntoIterator for States<'a> {
    type Item = State<'a>;
    type IntoIter = StateIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        StateIter {
            view: self.0,
            indices: 0..self.len(),
        }
    }
}

/// A sealed automaton, independent of the temporary compiler workspace.
#[derive(Clone, Copy)]
pub struct AutomatonView<'a> {
    records: &'a [RecordSlot],
    edges: &'a [EdgeSlot],
    bytes: &'a [u8],
    layout: Layout,
}

impl<'a> AutomatonView<'a> {
    pub(super) fn record(self, index: usize) -> Record<'a> {
        let row = &self.records[index];
        Record {
            proof: row.proof.slice(self.bytes),
            key: row.key,
            accepting: row.accepting,
            edges: Edges {
                view: self,
                slots: row.edges.slice(self.edges),
            },
        }
    }

    /// All minimized states with their original proofs.
    #[must_use]
    pub const fn states(self) -> States<'a> {
        States(self)
    }

    /// Number of retained synthetic entry records.
    #[must_use]
    pub const fn initial_count(self) -> usize {
        self.layout.records - self.layout.states
    }

    /// A synthetic entry, indexed independently of minimized states.
    #[must_use]
    pub fn initial(self, index: usize) -> Option<Record<'a>> {
        (index < self.initial_count()).then(|| self.record(self.layout.states + index))
    }

    /// Language-equivalent expression.
    #[must_use]
    pub fn language_expression(self) -> &'a [u8] {
        self.layout.language.slice(self.bytes)
    }

    /// Actual charged compiler work.
    #[must_use]
    pub const fn work_used(self) -> u64 {
        self.layout.work
    }

    /// Match the full input against the retained graph.
    pub fn is_match(self, input: &[u8]) -> Result<bool, gnunet_types::Error> {
        if input.contains(&0) {
            return Err(gnunet_types::Error::InvalidInput);
        }
        let mut row = &self.records[0];
        let mut rest = input;
        while !rest.is_empty() {
            let Some(edge) = row
                .edges
                .slice(self.edges)
                .iter()
                .filter(|edge| rest.starts_with(edge.label.slice(self.bytes)))
                .max_by_key(|edge| edge.label.end - edge.label.start)
            else {
                return Ok(false);
            };
            rest = &rest[edge.label.end - edge.label.start..];
            row = &self.records[edge.target];
        }
        Ok(row.accepting)
    }
}
