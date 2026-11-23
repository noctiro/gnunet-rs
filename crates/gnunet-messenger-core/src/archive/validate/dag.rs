//! Reusable workspace for acceptance order and the two-parent archive graphs.

use crate::{Error, Limits, storage::Backing};
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::num::NonZeroUsize;
use gnunet_types::Error as Fault;

/// One caller-owned workspace cell for validating the archive message order and graphs.
#[derive(Clone, Copy, Debug)]
pub struct ArchiveGraphCell(Cell);

impl ArchiveGraphCell {
    /// An unused vertex cell.
    pub const fn empty() -> Self {
        Self(Cell::Vertex(Vertex {
            children: None,
            sibling_edges: [None; 2],
            next_ready: None,
            parents_left: None,
        }))
    }

    /// Cells needed to validate the acceptance order and graphs of any one room.
    pub const fn required_cells(limits: Limits) -> usize {
        if limits.messages_per_room > limits.epochs_per_room {
            limits.messages_per_room
        } else {
            limits.epochs_per_room
        }
    }

    /// Cells needed when one room can also have `detached_rows` on the
    /// selected committed pages. Return `None` if the sum does not fit.
    pub const fn required_cells_with_detached(
        limits: Limits,
        detached_rows: usize,
    ) -> Option<usize> {
        let Some(messages) = limits.messages_per_room.checked_add(detached_rows) else {
            return None;
        };
        if messages > limits.epochs_per_room {
            Some(messages)
        } else {
            Some(limits.epochs_per_room)
        }
    }

    const fn sequence(&self) -> Option<u64> {
        match self.0 {
            Cell::Sequence(sequence) => Some(sequence),
            Cell::Vertex(_) => None,
        }
    }

    fn vertex(&self) -> Result<&Vertex, Fault> {
        match &self.0 {
            Cell::Vertex(vertex) => Ok(vertex),
            Cell::Sequence(_) => Err(Fault::Malformed),
        }
    }

    fn vertex_mut(&mut self) -> Result<&mut Vertex, Fault> {
        match &mut self.0 {
            Cell::Vertex(vertex) => Ok(vertex),
            Cell::Sequence(_) => Err(Fault::Malformed),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Cell {
    Sequence(u64),
    Vertex(Vertex),
}

#[derive(Clone, Copy, Debug)]
struct Vertex {
    children: Option<EdgeIndex>,
    sibling_edges: [Option<EdgeIndex>; 2],
    next_ready: Option<VertexIndex>,
    parents_left: Option<u8>,
}

#[derive(Clone, Copy, Debug)]
struct VertexIndex(NonZeroUsize);

impl VertexIndex {
    fn at(index: usize) -> Self {
        Self(NonZeroUsize::MIN.saturating_add(index))
    }

    const fn get(self) -> usize {
        self.0.get() - 1
    }
}

#[derive(Clone, Copy, Debug)]
struct EdgeIndex(NonZeroUsize);

impl EdgeIndex {
    fn at(child: usize, side: usize) -> Self {
        // The child indexes a slice of multi-byte cells, so twice the index fits.
        Self(NonZeroUsize::MIN.saturating_add(child * 2 + side))
    }

    const fn location(self) -> (usize, usize) {
        let index = self.0.get() - 1;
        (index / 2, index % 2)
    }
}

pub(in crate::archive) struct DagWorkspace<'graph> {
    cells: Backing<ArchiveGraphCell, &'graph mut [ArchiveGraphCell]>,
    #[cfg(feature = "alloc")]
    width: usize,
}

#[cfg(feature = "alloc")]
impl DagWorkspace<'static> {
    pub(in crate::archive) fn owned(limits: Limits) -> Self {
        Self {
            cells: Backing::Owned(Vec::new()),
            width: ArchiveGraphCell::required_cells(limits),
        }
    }
}

impl<'graph> DagWorkspace<'graph> {
    pub(in crate::archive) fn with_cells(
        cells: &'graph mut [ArchiveGraphCell],
        limits: Limits,
    ) -> Result<Self, Error> {
        let width = ArchiveGraphCell::required_cells(limits);
        if cells.len() < width {
            return Err(Fault::Capacity.into());
        }
        Ok(Self {
            cells: Backing::fixed(cells),
            #[cfg(feature = "alloc")]
            width,
        })
    }

    pub(super) fn check(
        &mut self,
        limit: usize,
        rows: impl Iterator<Item = Result<(usize, [Option<usize>; 2]), Error>>,
    ) -> Result<(), Error> {
        let mut rows = rows.peekable();
        if rows.peek().is_none() {
            return Ok(());
        }
        let cells = self
            .ensure_cells()?
            .get_mut(..limit)
            .ok_or(Fault::Capacity)?;
        cells.fill(ArchiveGraphCell::empty());
        check_dag(cells, rows)
    }

    pub(super) fn check_unique_sequences(
        &mut self,
        sequences: impl Iterator<Item = Result<u64, Error>>,
    ) -> Result<(), Error> {
        let mut sequences = sequences.peekable();
        if sequences.peek().is_none() {
            return Ok(());
        }
        let cells = self.ensure_cells()?;
        let count = sequences.try_fold(0, |index, sequence| {
            *cells.get_mut(index).ok_or(Fault::Capacity)? =
                ArchiveGraphCell(Cell::Sequence(sequence?));
            Ok::<_, Error>(index + 1)
        })?;
        let keys = &mut cells[..count];
        keys.sort_unstable_by_key(ArchiveGraphCell::sequence);
        if keys
            .windows(2)
            .any(|pair| pair[0].sequence() == pair[1].sequence())
        {
            return Err(Fault::Conflict.into());
        }
        Ok(())
    }

    fn ensure_cells(&mut self) -> Result<&mut [ArchiveGraphCell], Error> {
        #[cfg(feature = "alloc")]
        if let Backing::Owned(cells) = &mut self.cells
            && cells.is_empty()
        {
            cells
                .try_reserve_exact(self.width)
                .map_err(|_| Fault::Capacity)?;
            cells.resize(self.width, ArchiveGraphCell::empty());
        }
        Ok(self.cells.as_mut())
    }
}

fn check_dag(
    cells: &mut [ArchiveGraphCell],
    rows: impl Iterator<Item = Result<(usize, [Option<usize>; 2]), Error>>,
) -> Result<(), Error> {
    let limit = cells.len();
    let mut ready = None;
    let mut count = 0;
    for row in rows {
        let (child, parents) = row?;
        if child >= limit || cells[child].vertex()?.parents_left.is_some() {
            return Err(Fault::Malformed.into());
        }
        count += 1;
        let mut parents_left = 0;
        for (side, parent) in parents.into_iter().enumerate() {
            let Some(parent) = parent else { continue };
            if parent >= limit {
                return Err(Fault::Malformed.into());
            }
            // Each child owns at most two edges. The edge identifies its child
            // and links to the next child of the same parent.
            parents_left += 1;
            let next = cells[parent].vertex()?.children;
            cells[child].vertex_mut()?.sibling_edges[side] = next;
            cells[parent].vertex_mut()?.children = Some(EdgeIndex::at(child, side));
        }
        let child_vertex = cells[child].vertex_mut()?;
        child_vertex.parents_left = Some(parents_left);
        if parents_left == 0 {
            child_vertex.next_ready = ready;
            ready = Some(VertexIndex::at(child));
        }
    }

    let mut visited = 0;
    while let Some(parent) = ready {
        let parent = cells[parent.get()].vertex()?;
        ready = parent.next_ready;
        let mut cursor = parent.children;
        visited += 1;
        while let Some(edge) = cursor {
            let (index, side) = edge.location();
            let child = cells[index].vertex_mut()?;
            cursor = child.sibling_edges[side];
            let parents_left = child.parents_left.as_mut().ok_or(Fault::Malformed)?;
            *parents_left = parents_left.checked_sub(1).ok_or(Fault::Malformed)?;
            if *parents_left == 0 {
                child.next_ready = ready;
                ready = Some(VertexIndex::at(index));
            }
        }
    }
    if visited != count {
        return Err(Fault::Malformed.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Check duplicate acceptance orders and reuse on a later graph"
    )]
    fn fixed_workspace_checks_full_width_sequences() -> Result<(), Error> {
        let limits = Limits {
            messages_per_room: 3,
            epochs_per_room: 2,
            ..Limits::default()
        };
        let mut cells = [ArchiveGraphCell::empty(); 3];
        let mut workspace = DagWorkspace::with_cells(&mut cells, limits)?;
        let high = (1 << 32) | 1;
        workspace.check_unique_sequences([high, 1, u64::MAX].into_iter().map(Ok))?;
        assert!(matches!(
            workspace.check_unique_sequences([high, 1, high].into_iter().map(Ok)),
            Err(Error::Protocol(Fault::Conflict))
        ));
        workspace.check(
            3,
            [(2, [Some(0), None]), (0, [None, None])]
                .into_iter()
                .map(Ok),
        )?;
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Check cyclic input refusal and workspace reuse"
    )]
    fn fixed_workspace_rejects_cycles_and_accepts_a_later_graph() -> Result<(), Error> {
        let limits = Limits {
            messages_per_room: 5,
            epochs_per_room: 3,
            ..Limits::default()
        };
        let mut cells = [ArchiveGraphCell::empty(); 5];
        let mut workspace = DagWorkspace::with_cells(&mut cells, limits)?;
        assert!(matches!(
            workspace.check(
                5,
                [(1, [Some(4), None]), (4, [Some(1), None])]
                    .into_iter()
                    .map(Ok),
            ),
            Err(Error::Protocol(Fault::Malformed))
        ));
        workspace.check(
            5,
            [
                (1, [Some(3), Some(3)]),
                (3, [None, None]),
                (4, [Some(1), Some(3)]),
            ]
            .into_iter()
            .map(Ok),
        )?;
        workspace.check(3, [(2, [None, None])].into_iter().map(Ok))?;
        Ok(())
    }
}
