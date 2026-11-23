//! Build lookup entries from raw prefixes consumed by the one official first GET.

use super::{ArtifactWorkspace, Pending, account};
use crate::compile::records::{EdgeSlot, RecordSlot, Span, Table};
use crate::compile::{Budget, BuildError, Limit, storage::Buffer};
use crate::{INITIAL_BYTES, proof_key};

struct Entries<'a, 'slots> {
    states: usize,
    bytes: usize,
    pending: &'a mut Buffer<'slots, Pending>,
}

impl Entries<'_, '_> {
    fn entry(
        &mut self,
        table: &mut Table<'_>,
        prefix: &[u8],
        accept: bool,
        b: &mut Budget,
    ) -> Result<Option<usize>, BuildError> {
        let key = proof_key(prefix);
        for (index, row) in table.records.iter_mut().enumerate() {
            b.step()?;
            if row.key != key {
                continue;
            }
            if row.proof.slice(&table.bytes) != prefix {
                return Err(BuildError::Conflict);
            }
            if index < self.states {
                // This exact proof already supplies the normal lookup block.
                return Ok(None);
            }
            row.accepting |= accept;
            return Ok(Some(index));
        }
        account(
            &mut self.bytes,
            prefix.len(),
            b.limits.initial_bytes,
            Limit::InitialBytes,
        )?;
        let index = table.records.len();
        let max = self
            .states
            .checked_add(b.limits.initial_records)
            .ok_or(BuildError::Overflow)?;
        let proof = table.text(prefix, Limit::InitialBytes)?;
        table.records.push(
            RecordSlot {
                key,
                proof,
                accepting: accept,
                edges: Span::EMPTY,
                pending: None,
            },
            max,
            Limit::InitialRecords,
        )?;
        Ok(Some(index))
    }

    fn put(
        &mut self,
        table: &mut Table<'_>,
        index: usize,
        edge: EdgeSlot,
        b: &mut Budget,
    ) -> Result<(), BuildError> {
        if self.existing(table, index, edge.target, edge.label.slice(&table.bytes), b)? {
            return Ok(());
        }
        self.link(table, index, edge, b)
    }

    fn existing(
        &self,
        table: &Table<'_>,
        index: usize,
        target: usize,
        label: &[u8],
        b: &mut Budget,
    ) -> Result<bool, BuildError> {
        let mut next = table.records[index].pending;
        while let Some(i) = next {
            b.step()?;
            let item = self.pending[i];
            if item.edge.label.slice(&table.bytes) == label {
                if target != item.edge.target {
                    return Err(BuildError::Conflict);
                }
                return Ok(true);
            }
            next = item.next;
        }
        Ok(false)
    }

    fn link(
        &mut self,
        table: &mut Table<'_>,
        index: usize,
        edge: EdgeSlot,
        b: &Budget,
    ) -> Result<(), BuildError> {
        let cost = (edge.label.end - edge.label.start)
            .checked_add(core::mem::size_of::<EdgeSlot>())
            .ok_or(BuildError::Overflow)?;
        account(
            &mut self.bytes,
            cost,
            b.limits.initial_bytes,
            Limit::InitialBytes,
        )?;
        let slot = self.pending.len();
        self.pending.push(
            Pending {
                edge,
                next: table.records[index].pending,
            },
            b.limits.transitions,
            Limit::Transitions,
        )?;
        table.records[index].pending = Some(slot);
        Ok(())
    }

    fn bridge(
        &mut self,
        table: &mut Table<'_>,
        prefix: &[u8],
        label: &[u8],
        target: usize,
        b: &mut Budget,
    ) -> Result<(), BuildError> {
        if let Some(index) = self.entry(table, prefix, false, b)?
            && !self.existing(table, index, target, label, b)?
        {
            let label = table.text(label, Limit::InitialBytes)?;
            self.link(table, index, EdgeSlot { target, label }, b)?;
        }
        Ok(())
    }

    fn finish(self, table: &mut Table<'_>, b: &mut Budget) -> Result<(), BuildError> {
        let max = table
            .edges
            .len()
            .checked_add(b.limits.transitions)
            .ok_or(BuildError::Overflow)?;
        for row in &mut table.records[self.states..] {
            let start = table.edges.len();
            let mut next = row.pending.take();
            while let Some(index) = next {
                b.step()?;
                let item = self.pending[index];
                table.edges.push(item.edge, max, Limit::Transitions)?;
                next = item.next;
            }
            table.edges[start..].reverse();
            row.edges = Span {
                start,
                end: table.edges.len(),
            };
        }
        Ok(())
    }
}

pub(super) fn create(
    table: &mut Table<'_>,
    scratch: &mut ArtifactWorkspace<'_>,
    b: &mut Budget,
) -> Result<(), BuildError> {
    let ArtifactWorkspace {
        stack,
        path,
        pending,
        ..
    } = scratch;
    pending.clear();
    let mut entries = Entries {
        states: table.records.len(),
        bytes: 0,
        pending,
    };
    stack.push(super::Frame::new(0, 0), b.limits.stack, Limit::ParserStack)?;
    while let Some(mut frame) = stack.last().copied() {
        b.step()?;
        let node = table.records[frame.node];
        if !frame.entered {
            frame.entered = true;
            if path.len() > INITIAL_BYTES {
                entries.bridge(
                    table,
                    &path[..INITIAL_BYTES],
                    &path[INITIAL_BYTES..],
                    frame.node,
                    b,
                )?;
            } else if path.len() == INITIAL_BYTES || node.accepting {
                if let Some(entry) = entries.entry(table, path, node.accepting, b)? {
                    for i in node.edges.start..node.edges.end {
                        entries.put(table, entry, table.edges[i], b)?;
                    }
                }
                if node.accepting
                    && node.edges.start == node.edges.end
                    && path.len() > 1
                    && path.len() < INITIAL_BYTES
                {
                    let (prefix, label) = path.split_at(path.len() - 1);
                    entries.bridge(table, prefix, label, frame.node, b)?;
                }
            }
            if let Some(top) = stack.last_mut() {
                *top = frame;
            }
        }
        let edge = (path.len() < INITIAL_BYTES && frame.next < node.edges.end - node.edges.start)
            .then(|| table.edges[node.edges.start + frame.next]);
        let Some(edge) = edge else {
            stack.pop();
            path.truncate(frame.base);
            continue;
        };
        if let Some(top) = stack.last_mut() {
            top.next += 1;
        }
        let base = path.len();
        path.extend_from_slice(
            edge.label.slice(&table.bytes),
            b.limits.initial_bytes,
            Limit::InitialBytes,
        )?;
        stack.push(
            super::Frame::new(edge.target, base),
            b.limits.stack,
            Limit::ParserStack,
        )?;
    }
    entries.finish(table, b)
}
