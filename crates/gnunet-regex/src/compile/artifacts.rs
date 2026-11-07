//! Iterative compressed path and synthetic24-byte entry construction.
use super::dfa::Dfa;
use super::{Budget, BuildError, Edge, Initial, Limit, State, bytes, filled, push};
use crate::{INITIAL_BYTES, proof_key};
use alloc::vec::Vec;
#[derive(Clone, Copy)]
struct Frame {
    node: usize,
    next: usize,
    base: usize,
    entered: bool,
    expanded: bool,
}
fn leave(stack: &mut Vec<Frame>, path: &mut Vec<u8>, active: &mut [bool]) {
    if let Some(frame) = stack.pop() {
        if frame.expanded {
            active[frame.node] = false;
        }
        path.truncate(frame.base);
    }
}
pub(super) fn compress(
    dfa: &Dfa,
    proofs: Vec<Vec<u8>>,
    compression: u16,
    b: &mut Budget,
) -> Result<Vec<State>, BuildError> {
    let n = dfa.rows.len();
    let mut incoming = filled(n, 0usize)?;
    for row in &dfa.rows {
        for edge in &row.edges {
            b.step()?;
            incoming[edge.to] = incoming[edge.to]
                .checked_add(1)
                .ok_or(BuildError::Overflow)?;
        }
    }
    let mut states: Vec<State> = Vec::new();
    for (i, proof) in proofs.into_iter().enumerate() {
        let key = proof_key(&proof);
        for previous in &states {
            b.step()?;
            if previous.key == key {
                return Err(BuildError::Conflict);
            }
        }
        push(
            &mut states,
            State {
                key,
                proof,
                accepting: dfa.rows[i].accept,
                edges: Vec::new(),
            },
            b.limits.dfa_states,
            Limit::DfaStates,
        )?;
    }
    let mut active = filled(n, false)?;
    let mut path = Vec::new();
    let mut stack = Vec::new();
    let mut edges = 0usize;
    let mut labels = 0usize;
    for start in 0..n {
        let cap = if compression == 1 {
            1
        } else if start == 0 {
            INITIAL_BYTES
        } else if compression == 0 {
            usize::MAX
        } else {
            usize::from(compression)
        };
        push(
            &mut stack,
            Frame {
                node: start,
                next: 0,
                base: 0,
                entered: false,
                expanded: false,
            },
            b.limits.stack,
            Limit::ParserStack,
        )?;
        while let Some(mut frame) = stack.last().copied() {
            b.step()?;
            if !frame.entered {
                frame.entered = true;
                if !path.is_empty()
                    && (dfa.rows[frame.node].accept
                        || incoming[frame.node] > 1
                        || active[frame.node]
                        || path.len() >= cap)
                {
                    edges = edges.checked_add(1).ok_or(BuildError::Overflow)?;
                    labels = labels.checked_add(path.len()).ok_or(BuildError::Overflow)?;
                    if edges > b.limits.transitions {
                        return Err(BuildError::Limit(Limit::Transitions));
                    }
                    if labels > b.limits.label_bytes {
                        return Err(BuildError::Limit(Limit::LabelBytes));
                    }
                    let edge = Edge {
                        label: bytes(&path)?,
                        destination: states[frame.node].key,
                        target: frame.node,
                    };
                    push(
                        &mut states[start].edges,
                        edge,
                        b.limits.transitions,
                        Limit::Transitions,
                    )?;
                    leave(&mut stack, &mut path, &mut active);
                    continue;
                }
                active[frame.node] = true;
                frame.expanded = true;
                if let Some(top) = stack.last_mut() {
                    *top = frame;
                }
            }
            let Some(edge) = dfa.rows[frame.node].edges.get(frame.next) else {
                leave(&mut stack, &mut path, &mut active);
                continue;
            };
            if let Some(top) = stack.last_mut() {
                top.next += 1;
            }
            let base = path.len();
            push(
                &mut path,
                edge.byte,
                b.limits.label_bytes,
                Limit::LabelBytes,
            )?;
            push(
                &mut stack,
                Frame {
                    node: edge.to,
                    next: 0,
                    base,
                    entered: false,
                    expanded: false,
                },
                b.limits.stack,
                Limit::ParserStack,
            )?;
        }
    }
    Ok(states)
}
struct Entries {
    entries: Vec<Initial>,
    buckets: Vec<usize>,
    bytes: usize,
    edges: usize,
}
impl Entries {
    // This public-prefix index is not a protocol hash. Exact proof bytes still
    // resolve collisions, every probe is charged, and records use SHA-512 keys.
    fn bucket(prefix: &[u8], size: usize) -> usize {
        let hash = prefix.iter().fold(0xcbf29ce484222325u64, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
        });
        (hash as usize) & (size - 1)
    }
    fn find(&self, prefix: &[u8], b: &mut Budget) -> Result<Option<usize>, BuildError> {
        if self.buckets.is_empty() {
            return Ok(None);
        }
        let mut at = Self::bucket(prefix, self.buckets.len());
        for _ in 0..self.buckets.len() {
            b.step()?;
            let index = self.buckets[at];
            if index == usize::MAX {
                return Ok(None);
            }
            if self.entries[index].proof == prefix {
                return Ok(Some(index));
            }
            at = (at + 1) & (self.buckets.len() - 1);
        }
        Err(BuildError::Conflict)
    }
    fn insert_index(
        entries: &[Initial],
        buckets: &mut [usize],
        index: usize,
        b: &mut Budget,
    ) -> Result<(), BuildError> {
        let mut at = Self::bucket(&entries[index].proof, buckets.len());
        for _ in 0..buckets.len() {
            b.step()?;
            if buckets[at] == usize::MAX {
                buckets[at] = index;
                return Ok(());
            }
            at = (at + 1) & (buckets.len() - 1);
        }
        Err(BuildError::Conflict)
    }
    fn reserve_index(&mut self, b: &mut Budget) -> Result<(), BuildError> {
        if self.entries.len() >= b.limits.initial_records {
            return Err(BuildError::Limit(Limit::InitialRecords));
        }
        let needed = self
            .entries
            .len()
            .checked_add(1)
            .ok_or(BuildError::Overflow)?;
        if needed.checked_mul(2).ok_or(BuildError::Overflow)? <= self.buckets.len() {
            return Ok(());
        }
        // Grow only with admitted entries, at load <=1/2. No maximum-capacity
        // table is allocated for the common single-namespace lookup case.
        let size = self
            .buckets
            .len()
            .max(8)
            .checked_mul(2)
            .ok_or(BuildError::Overflow)?;
        let mut buckets = filled(size, usize::MAX)?;
        for index in 0..self.entries.len() {
            Self::insert_index(&self.entries, &mut buckets, index, b)?;
        }
        self.buckets = buckets;
        Ok(())
    }
    fn charge(&mut self, len: usize, b: &Budget) -> Result<(), BuildError> {
        self.bytes = self.bytes.checked_add(len).ok_or(BuildError::Overflow)?;
        if self.bytes > b.limits.initial_bytes {
            return Err(BuildError::Limit(Limit::InitialBytes));
        }
        Ok(())
    }
    fn add(
        &mut self,
        states: &[State],
        prefix: &[u8],
        accept: bool,
        edges: &[Edge],
        b: &mut Budget,
    ) -> Result<(), BuildError> {
        // A regular state with exactly this literal proof already supplies the
        // lookup block; never publish conflicting duplicate descriptions for it.
        for state in states {
            b.step()?;
            if state.proof == prefix {
                return Ok(());
            }
        }
        let i = match self.find(prefix, b)? {
            Some(i) => i,
            None => {
                self.reserve_index(b)?;
                self.charge(prefix.len(), b)?;
                let i = self.entries.len();
                push(
                    &mut self.entries,
                    Initial {
                        proof: bytes(prefix)?,
                        accepting: accept,
                        edges: Vec::new(),
                    },
                    b.limits.initial_records,
                    Limit::InitialRecords,
                )?;
                Self::insert_index(&self.entries, &mut self.buckets, i, b)?;
                i
            }
        };
        self.entries[i].accepting |= accept;
        for edge in edges {
            let mut duplicate = false;
            for old in &self.entries[i].edges {
                b.step()?;
                if old.label == edge.label {
                    if old.target != edge.target || old.destination != edge.destination {
                        return Err(BuildError::Conflict);
                    }
                    duplicate = true;
                    break;
                }
            }
            if duplicate {
                continue;
            }
            self.edges = self.edges.checked_add(1).ok_or(BuildError::Overflow)?;
            if self.edges > b.limits.transitions {
                return Err(BuildError::Limit(Limit::Transitions));
            }
            self.charge(
                edge.label
                    .len()
                    .checked_add(core::mem::size_of::<Edge>())
                    .ok_or(BuildError::Overflow)?,
                b,
            )?;
            let copy = Edge {
                label: bytes(&edge.label)?,
                destination: edge.destination,
                target: edge.target,
            };
            push(
                &mut self.entries[i].edges,
                copy,
                b.limits.transitions,
                Limit::Transitions,
            )?;
        }
        Ok(())
    }
}
pub(super) fn initial(states: &[State], b: &mut Budget) -> Result<Vec<Initial>, BuildError> {
    let mut entries = Entries {
        entries: Vec::new(),
        buckets: Vec::new(),
        bytes: 0,
        edges: 0,
    };
    let mut path = Vec::new();
    let mut stack = Vec::new();
    push(
        &mut stack,
        Frame {
            node: 0,
            next: 0,
            base: 0,
            entered: false,
            expanded: false,
        },
        b.limits.stack,
        Limit::ParserStack,
    )?;
    while let Some(mut frame) = stack.last().copied() {
        b.step()?;
        let state = &states[frame.node];
        if !frame.entered {
            frame.entered = true;
            if path.len() >= INITIAL_BYTES || state.accepting {
                if path.len() <= INITIAL_BYTES {
                    entries.add(states, &path, state.accepting, &state.edges, b)?;
                    if state.accepting
                        && path.len() > 1
                        && state.edges.is_empty()
                        && path.len() < INITIAL_BYTES
                    {
                        let bridge = Edge {
                            label: bytes(&path[path.len() - 1..])?,
                            destination: state.key,
                            target: frame.node,
                        };
                        entries.add(
                            states,
                            &path[..path.len() - 1],
                            false,
                            core::slice::from_ref(&bridge),
                            b,
                        )?;
                    }
                } else {
                    let bridge = Edge {
                        label: bytes(&path[INITIAL_BYTES..])?,
                        destination: state.key,
                        target: frame.node,
                    };
                    entries.add(
                        states,
                        &path[..INITIAL_BYTES],
                        false,
                        core::slice::from_ref(&bridge),
                        b,
                    )?;
                }
            }
            if let Some(top) = stack.last_mut() {
                *top = frame;
            }
        }
        if path.len() >= INITIAL_BYTES {
            if let Some(done) = stack.pop() {
                path.truncate(done.base);
            }
            continue;
        }
        let Some(edge) = state.edges.get(frame.next) else {
            if let Some(done) = stack.pop() {
                path.truncate(done.base);
            }
            continue;
        };
        if let Some(top) = stack.last_mut() {
            top.next += 1;
        }
        let base = path.len();
        let len = base
            .checked_add(edge.label.len())
            .ok_or(BuildError::Overflow)?;
        if len > b.limits.initial_bytes {
            return Err(BuildError::Limit(Limit::InitialBytes));
        }
        path.try_reserve(edge.label.len())
            .map_err(|_| BuildError::Allocation)?;
        path.extend_from_slice(&edge.label);
        push(
            &mut stack,
            Frame {
                node: edge.target,
                next: 0,
                base,
                entered: false,
                expanded: false,
            },
            b.limits.stack,
            Limit::ParserStack,
        )?;
    }
    // SHA collisions between distinct raw prefixes or a normal proof are never
    // silently taken as identity. Prefix duplicate rows were coalesced above.
    for (i, entry) in entries.entries.iter().enumerate() {
        let key = proof_key(&entry.proof);
        for old in &entries.entries[..i] {
            b.step()?;
            if proof_key(&old.proof) == key {
                return Err(BuildError::Conflict);
            }
        }
        for state in states {
            b.step()?;
            if state.key == key {
                return Err(BuildError::Conflict);
            }
        }
    }
    Ok(entries.entries)
}
