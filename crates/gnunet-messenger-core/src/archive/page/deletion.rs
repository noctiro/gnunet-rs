//! A bounded replacement of one exact, previously committed page.

use super::*;
use crate::graph::owns_author;

/// One native page replacement derived from an authenticated DELETE or its
/// already committed timer. The storage owner must commit it together with
/// the matching working checkpoint and the new page directory.
pub struct DetachedDeletion {
    page: GraphPageIdentity,
    target: Hash,
    sequence: NonZeroU64,
    deadline: u64,
    cause: Hash,
    erase: bool,
}

impl DetachedDeletion {
    /// The original committed page identity. The caller also checks the exact
    /// storage receipt selecting this page before publication.
    #[must_use]
    pub const fn page(&self) -> GraphPageIdentity {
        self.page
    }

    /// The original room message being scheduled or erased.
    #[must_use]
    pub const fn target(&self) -> &Hash {
        &self.target
    }

    /// Whether this replacement omits the original bytes and retains the
    /// authenticated graph facts as a tombstone.
    #[must_use]
    pub const fn erases_original(&self) -> bool {
        self.erase
    }

    /// Prepare a different immutable page carrying the same accepted graph.
    /// The destination must have a later emission in the same namespace, peer
    /// and room. Publication still belongs to the original storage owner.
    ///
    /// # Errors
    /// Refuses a different source page or acceptance sequence, a foreign or
    /// stale destination, invalid row encodings and insufficient output.
    pub fn prepare_into<'output>(
        &self,
        source: &CommittedGraphPage<'_, '_>,
        destination: GraphPageIdentity,
        output: &'output mut [u8],
    ) -> Result<PreparedGraphPageRef<'output>, Error> {
        if source.identity != self.page
            || destination.emission <= self.page.emission
            || destination.room != self.page.room
            || destination.peer != self.page.peer
            || destination.namespace != self.page.namespace
        {
            return Err(Fault::StaleGeneration.into());
        }
        u32::try_from(output.len()).map_err(|_| Fault::Capacity)?;
        let position = source
            .position(&self.target)
            .ok_or(Fault::StaleGeneration)?;
        let start = source.index[position].row as usize;
        let (row, offsets) = MessageRecord::read_with_offsets(
            &mut Decoder::at(source.bytes, start),
            source.limits,
            source.accepted_through,
        )?;
        if row.hash != self.target
            || row.sequence != self.sequence.get()
            || row.phase != MessagePhase::Applied
        {
            return Err(Fault::StaleGeneration.into());
        }

        let mut writer = Encoder::new(SliceSink::new(output));
        destination.write(&mut writer)?;
        writer.slot(source.room)?;
        writer.u64(source.accepted_through)?;
        writer.u8(u8::try_from(source.len()).map_err(|_| Fault::Capacity)?)?;
        let first = source.index.first().ok_or(Fault::Malformed)?.row as usize;
        writer.raw(&source.bytes[first..start])?;
        if self.erase {
            writer.raw(&source.bytes[start..offsets.phase])?;
            writer.u8(phase(MessagePhase::Deleted))?;
            writer.original(self.page.room(), &self.target, None)?;
            writer.raw(&source.bytes[offsets.after_frame..offsets.delete])?;
        } else {
            writer.raw(&source.bytes[start..offsets.delete])?;
        }
        writer.opt_u64(Some(self.deadline))?;
        writer.opt_array(Some(&self.cause))?;
        writer.raw(&source.bytes[offsets.after_delete..])?;
        Ok(PreparedGraphPageRef {
            body: writer.finish(),
        })
    }
}

impl CommittedGraphPage<'_, '_> {
    pub(in crate::archive) fn plan_deletion(
        &self,
        index: usize,
        session: &SessionRow,
        deadline: u64,
        cause: Hash,
        now: u64,
    ) -> Result<Option<DetachedDeletion>, Error> {
        let row = self.record(index)?;
        if !DetachedKind::of(row.kind).is_some_and(DetachedKind::is_deletable)
            || !owns_author(session, row.owner)
        {
            return Err(Error::Permission);
        }
        if row.phase == MessagePhase::Deleted {
            return Ok(None);
        }
        let deadline = row.delete_at.map_or(deadline, |old| old.min(deadline));
        Ok(Some(DetachedDeletion {
            page: self.identity,
            target: row.hash,
            sequence: NonZeroU64::new(row.sequence).ok_or(Fault::Malformed)?,
            deadline,
            cause,
            erase: deadline <= now,
        }))
    }

    pub(in crate::archive) fn next_deletion(&self) -> Option<u64> {
        self.next_deletion.map(|(deadline, _)| deadline)
    }

    pub(in crate::archive) fn expire_deletion(
        &self,
        now: u64,
    ) -> Result<Option<DetachedDeletion>, Error> {
        let Some((deadline, index)) = self.next_deletion.filter(|(deadline, _)| *deadline <= now)
        else {
            return Ok(None);
        };
        let row = self.record(index)?;
        Ok(Some(DetachedDeletion {
            page: self.identity,
            target: row.hash,
            sequence: NonZeroU64::new(row.sequence).ok_or(Fault::Malformed)?,
            deadline,
            cause: row.deleted_by.ok_or(Fault::Malformed)?,
            erase: true,
        }))
    }
}
