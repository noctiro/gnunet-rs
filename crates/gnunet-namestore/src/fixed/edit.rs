//! Advisory editor-hint changes on the original authority inventory.

use super::{AfterImage, CommitError, Hint, MAX_HINT_BYTES, Owner, ReadScratch, checked_time};
use crate::{Code, SecretKeyView, policy::RecordView};
use gnunet_types::Error;
use gnunet_wire::official::namestore::Records;

/// Original filtered records and optional prior hint in the caller's scratch.
pub struct EditReply<'a> {
    /// Actual edit outcome.
    pub code: Code,
    /// Previous advisory hint, if there was a changed value.
    pub hint: Option<&'a [u8]>,
    /// Selected original records.
    pub records: Records<'a>,
}

impl<const R: usize, const D: usize> Owner<'_, R, D> {
    /// Return the existing record set and durably replace its advisory hint.
    /// No row is created for a missing label, and no new serial is allocated.
    ///
    /// # Errors
    /// Refuses invalid names, hints, time or media. An uncertain publication
    /// fences the original inventory until recovery.
    pub fn edit_begin<'scratch, const OUTPUT: usize, const N: usize>(
        &mut self,
        zone: SecretKeyView<'_>,
        name: &[u8],
        hint: &[u8],
        now: u64,
        scratch: &'scratch mut ReadScratch<OUTPUT, N>,
        publish: impl FnOnce(AfterImage<'_, R, D>) -> Result<(), CommitError>,
    ) -> Result<EditReply<'scratch>, Error> {
        self.live()?;
        checked_time(now)?;
        validate(hint)?;
        scratch.previous_hint = None;
        let label = scratch.labels.normalize(name)?;
        let slot = self
            .inventory
            .locate(self.inventory.zone_index(zone), label.bytes());
        let row = slot.and_then(|index| self.inventory.rows[index].as_ref());
        let _rendered = self.render(zone, label, RecordView::Edit, now, row, scratch)?;
        let code = if let Some(index) = slot {
            let old = self.inventory.rows[index]
                .as_ref()
                .and_then(|row| row.hint.as_ref());
            if old.map_or(&[][..], Hint::bytes) != hint {
                scratch.previous_hint = self.replace_hint(index, proposed(hint)?, publish)?;
            }
            Code::NONE
        } else {
            Code::NO_RESULTS
        };
        Ok(EditReply {
            code,
            hint: scratch.previous_hint.as_ref().map(Hint::bytes),
            records: scratch.output.view()?,
        })
    }

    /// Replace a matching advisory hint. Missing and mismatching hints are
    /// successful no-ops. This does not cancel any original operation.
    ///
    /// # Errors
    /// Refuses invalid names or hints and fences after uncertain publication.
    pub fn edit_cancel<const OUTPUT: usize, const N: usize>(
        &mut self,
        zone: SecretKeyView<'_>,
        name: &[u8],
        expected: &[u8],
        replacement: &[u8],
        scratch: &mut ReadScratch<OUTPUT, N>,
        publish: impl FnOnce(AfterImage<'_, R, D>) -> Result<(), CommitError>,
    ) -> Result<Code, Error> {
        self.live()?;
        validate(expected)?;
        validate(replacement)?;
        let label = scratch.labels.normalize(name)?;
        let Some(index) = self
            .inventory
            .locate(self.inventory.zone_index(zone), label.bytes())
        else {
            return Ok(Code::NONE);
        };
        let old = self.inventory.rows[index]
            .as_ref()
            .and_then(|row| row.hint.as_ref());
        if old.map_or(&[][..], Hint::bytes) == expected && expected != replacement {
            drop(self.replace_hint(index, proposed(replacement)?, publish)?);
        }
        Ok(Code::NONE)
    }

    fn replace_hint(
        &mut self,
        slot: usize,
        next: Option<Hint>,
        publish: impl FnOnce(AfterImage<'_, R, D>) -> Result<(), CommitError>,
    ) -> Result<Option<Hint>, Error> {
        let image = AfterImage::hint(self.inventory, slot, next.as_ref());
        match publish(image) {
            Ok(()) => (),
            Err(CommitError::OutcomeUnknown | CommitError::Failed(Error::OutcomeUnknown)) => {
                self.inventory.needs_recovery = true;
                return Err(Error::OutcomeUnknown);
            }
            Err(CommitError::Failed(error)) => return Err(error),
        }
        if let Some(row) = self.inventory.rows[slot].as_mut() {
            return Ok(core::mem::replace(&mut row.hint, next));
        }
        self.inventory.needs_recovery = true;
        Err(Error::OutcomeUnknown)
    }
}

fn validate(hint: &[u8]) -> Result<(), Error> {
    if hint.len() > MAX_HINT_BYTES {
        return Err(Error::TooLarge);
    }
    if hint.contains(&0) {
        return Err(Error::InvalidInput);
    }
    Ok(())
}

fn proposed(hint: &[u8]) -> Result<Option<Hint>, Error> {
    (!hint.is_empty()).then(|| Hint::copy(hint)).transpose()
}
