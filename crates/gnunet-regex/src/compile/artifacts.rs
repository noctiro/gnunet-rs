//! Compress transitions and construct official synthetic prefixes.

use super::automaton::Graph;
use super::proof::Proofs;
use super::records::{EdgeSlot, Layout, RecordSlot, Span, Table};
use super::storage::Buffer;
use super::{Budget, BuildError, Limit};
use crate::{INITIAL_BYTES, proof_key};

#[derive(Clone, Copy)]
struct Frame {
    node: usize,
    next: usize,
    base: usize,
    entered: bool,
    expanded: bool,
}

impl Frame {
    const fn new(node: usize, base: usize) -> Self {
        Self {
            node,
            next: 0,
            base,
            entered: false,
            expanded: false,
        }
    }
}

#[derive(Clone, Copy)]
struct Pending {
    edge: EdgeSlot,
    next: Option<usize>,
}

impl Pending {
    const EMPTY: Self = Self {
        edge: EdgeSlot::EMPTY,
        next: None,
    };
}

/// Caller-owned scratch for compression and construction of synthetic entries.
/// This storage is reusable as soon as compilation returns.
pub struct ArtifactMemory<
    const STATES: usize,
    const STACK: usize,
    const PATH: usize,
    const INITIAL_EDGES: usize,
> {
    incoming: [usize; STATES],
    active: [bool; STATES],
    stack: [Frame; STACK],
    path: [u8; PATH],
    pending: [Pending; INITIAL_EDGES],
}

impl<const STATES: usize, const STACK: usize, const PATH: usize, const INITIAL_EDGES: usize>
    ArtifactMemory<STATES, STACK, PATH, INITIAL_EDGES>
{
    /// Empty scratch, suitable for constant initialization.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            incoming: [0; STATES],
            active: [false; STATES],
            stack: [Frame::new(0, 0); STACK],
            path: [0; PATH],
            pending: [Pending::EMPTY; INITIAL_EDGES],
        }
    }

    /// Exclusively borrow this scratch for artifact construction.
    pub fn workspace(&mut self) -> ArtifactWorkspace<'_> {
        ArtifactWorkspace {
            incoming: Buffer::fixed(&mut self.incoming),
            active: Buffer::fixed(&mut self.active),
            stack: Buffer::fixed(&mut self.stack),
            path: Buffer::fixed(&mut self.path),
            pending: Buffer::fixed(&mut self.pending),
        }
    }
}

impl<const STATES: usize, const STACK: usize, const PATH: usize, const INITIAL_EDGES: usize> Default
    for ArtifactMemory<STATES, STACK, PATH, INITIAL_EDGES>
{
    fn default() -> Self {
        Self::new()
    }
}

/// Exclusive artifact workspace borrowed from [`ArtifactMemory`].
pub struct ArtifactWorkspace<'a> {
    incoming: Buffer<'a, usize>,
    active: Buffer<'a, bool>,
    stack: Buffer<'a, Frame>,
    path: Buffer<'a, u8>,
    pending: Buffer<'a, Pending>,
}

#[cfg(feature = "alloc")]
impl ArtifactWorkspace<'static> {
    pub(super) fn heap() -> Self {
        Self {
            incoming: Buffer::heap(),
            active: Buffer::heap(),
            stack: Buffer::heap(),
            path: Buffer::heap(),
            pending: Buffer::heap(),
        }
    }
}

impl ArtifactWorkspace<'_> {
    fn backtrack(&mut self) {
        if let Some(frame) = self.stack.pop() {
            if frame.expanded {
                self.active[frame.node] = false;
            }
            self.path.truncate(frame.base);
        }
    }

    fn descend(&mut self, node: usize, base: usize, b: &Budget) -> Result<(), BuildError> {
        self.stack
            .push(Frame::new(node, base), b.limits.stack, Limit::ParserStack)
    }

    fn compress(
        &mut self,
        dfa: &Graph<'_>,
        table: &mut Table<'_>,
        compression: u16,
        b: &mut Budget,
    ) -> Result<(), BuildError> {
        self.incoming.clear();
        self.active.clear();
        self.path.clear();
        self.stack.clear();
        let n = dfa.len();
        self.incoming
            .resize(n, 0, b.limits.dfa_states, Limit::DfaStates)?;
        self.active
            .resize(n, false, b.limits.dfa_states, Limit::DfaStates)?;
        for row in dfa.rows() {
            for edge in row.edges {
                b.step()?;
                let incoming = &mut self.incoming[edge.to];
                *incoming = incoming.checked_add(1).ok_or(BuildError::Overflow)?;
            }
        }
        let mut labels = 0usize;
        for start in 0..n {
            let cap = match compression {
                1 => 1,
                _ if start == 0 => INITIAL_BYTES,
                0 => usize::MAX,
                n => usize::from(n),
            };
            let edge_start = table.edges.len();
            self.descend(start, 0, b)?;
            while let Some(mut frame) = self.stack.last().copied() {
                b.step()?;
                let row = dfa.row(frame.node);
                if !frame.entered {
                    frame.entered = true;
                    if !self.path.is_empty()
                        && (row.accept
                            || self.incoming[frame.node] > 1
                            || self.active[frame.node]
                            || self.path.len() >= cap)
                    {
                        account(
                            &mut labels,
                            self.path.len(),
                            b.limits.label_bytes,
                            Limit::LabelBytes,
                        )?;
                        let label = table.text(&self.path, Limit::LabelBytes)?;
                        table.edges.push(
                            EdgeSlot {
                                label,
                                target: frame.node,
                            },
                            b.limits.transitions,
                            Limit::Transitions,
                        )?;
                        self.backtrack();
                        continue;
                    }
                    self.active[frame.node] = true;
                    frame.expanded = true;
                    if let Some(top) = self.stack.last_mut() {
                        *top = frame;
                    }
                }
                let Some(edge) = row.edges.get(frame.next) else {
                    self.backtrack();
                    continue;
                };
                if let Some(top) = self.stack.last_mut() {
                    top.next += 1;
                }
                let base = self.path.len();
                self.path
                    .push(edge.byte, b.limits.label_bytes, Limit::LabelBytes)?;
                self.descend(edge.to, base, b)?;
            }
            table.records[start].edges = Span {
                start: edge_start,
                end: table.edges.len(),
            };
        }
        Ok(())
    }
}

fn account(used: &mut usize, bytes: usize, max: usize, kind: Limit) -> Result<(), BuildError> {
    *used = used.checked_add(bytes).ok_or(BuildError::Overflow)?;
    if *used > max {
        return Err(BuildError::Limit(kind));
    }
    Ok(())
}

pub(super) fn create(
    dfa: &Graph<'_>,
    proofs: &Proofs<'_>,
    scratch: &mut ArtifactWorkspace<'_>,
    table: &mut Table<'_>,
    compression: u16,
    b: &mut Budget,
) -> Result<Layout, BuildError> {
    for (row, proof) in dfa.rows().zip(proofs.states()) {
        let key = proof_key(proof);
        for previous in table.records.iter() {
            b.step()?;
            if previous.key == key {
                return Err(BuildError::Conflict);
            }
        }
        let proof = table.text(proof, Limit::TotalProofBytes)?;
        table.records.push(
            RecordSlot {
                key,
                proof,
                accepting: row.accept,
                edges: Span::EMPTY,
                pending: None,
            },
            b.limits.dfa_states,
            Limit::DfaStates,
        )?;
    }
    let language = table.text(proofs.language(), Limit::TotalProofBytes)?;
    scratch.compress(dfa, table, compression, b)?;
    initial::create(table, scratch, b)?;
    let mut layout = Layout {
        states: dfa.len(),
        records: table.records.len(),
        edges: table.edges.len(),
        bytes: table.bytes.len(),
        language,
        work: b.steps,
    };
    let view = table.view(layout);
    for index in 0..layout.records {
        let record = view.record(index);
        let n = record.edges.len() as u64;
        let cost = n
            .checked_add(1)
            .and_then(|next| n.checked_mul(next))
            .ok_or(BuildError::Overflow)?
            / 2;
        b.charge(cost)?;
        record
            .encoded_len()
            .map_err(|_| BuildError::Limit(Limit::BlockBytes))?;
    }
    layout.work = b.steps;
    Ok(layout)
}

mod initial;
