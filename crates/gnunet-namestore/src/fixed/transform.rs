//! Scoped transformations of one zone's exact authority rows.

use super::{
    AfterImage, Body, CommitError, Committed, Inventory, Label, LabelScratch, Owner, Row, RowRef,
    StoreScratch, checked_time, query, store,
};
use crate::{Code, RecordData, RecordFlags, RecordType, SecretKeyView, policy};
use gnunet_gnsrecord::RECORD_HEADER_LEN;
use gnunet_types::Error;
use gnunet_wire::official::namestore::Records;
use zeroize::Zeroize;

/// Whether the stored record is ordinary and visible at the given source time.
/// Relative durations stay visible until their original row is rewritten.
#[must_use]
pub fn record_is_ordinary_at(record: RecordData<'_>, now: u64) -> bool {
    record.record_type != RecordType::TOMBSTONE
        && !record.flags.contains(RecordFlags::MAINTENANCE)
        && policy::visible(record, now)
}

impl<'a> RowRef<'a> {
    /// Iterate active ordinary records, including private data, without adding
    /// nicknames or normalizing the stored flags and durations.
    pub fn ordinary_records_at(
        self,
        now: u64,
    ) -> impl Iterator<Item = Result<RecordData<'a>, Error>> {
        self.records
            .records()
            .iter()
            .filter(move |item| match item {
                Ok(record) => record_is_ordinary_at(*record, now),
                Err(_) => true,
            })
    }

    /// Apply the STORE deletion existence test to this physical row. Expired
    /// data and non-tombstone maintenance count; a tombstone-only row does not.
    pub fn has_ordinary_records(self) -> Result<bool, Error> {
        store::has_ordinary_records(self.records)
    }
}

/// One exclusive transform turn before an immutable after-image is published.
pub struct ZoneTransform<'a, const R: usize, const D: usize, const N: usize> {
    inventory: &'a Inventory<R, D>,
    stage: &'a mut StoreScratch<R, D, N>,
    next: &'a mut u64,
    zone: Option<usize>,
    now: u64,
}

impl<const R: usize, const D: usize, const N: usize> ZoneTransform<'_, R, D, N> {
    /// Inspect exact originals (including expired, private, and maintenance
    /// records) in increasing revision order before any row is transformed.
    pub fn rows(&self) -> impl Iterator<Item = Result<RowRef<'_>, Error>> {
        let inventory = self.inventory;
        zone_rows(inventory, self.zone).map(move |(_, row)| inventory.view(row))
    }

    /// Visit each original row once in increasing revision order. A row is
    /// unchanged unless its visitor elects to replace, move or remove records.
    /// Refusal by the visitor aborts the entire turn before publication.
    pub fn visit(
        self,
        mut visit: impl FnMut(RowRef<'_>, &mut RowChange<'_, D>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        for (slot, row) in zone_rows(self.inventory, self.zone) {
            let original = self.inventory.view(row)?;
            let (previous, available) = self.stage.delta.split_at_mut(self.stage.len);
            let delta = available.first_mut().ok_or(Error::Capacity)?;
            // Include this slot in cleanup even if the visitor fails after writing it.
            self.stage.len += 1;
            let (action, destination) = {
                let mut change = RowChange {
                    original: original.records,
                    body: &mut delta.records,
                    labels: &mut self.stage.labels,
                    action: Action::Keep,
                    destination: None,
                };
                visit(original, &mut change)?;
                (change.action, change.destination)
            };
            if let Some(destination) = destination {
                if self
                    .inventory
                    .locate(self.zone, destination.bytes())
                    .is_some()
                    || previous
                        .iter()
                        .any(|delta| delta.label.bytes() == destination.bytes())
                {
                    return Err(Error::Conflict);
                }
                query::validate_recovered(destination.bytes(), delta.records.view()?)?;
                let floor = query::public_expiry(
                    original.label,
                    original.records,
                    self.now,
                    &mut self.stage.indices,
                )?;
                let retirement = take_serial(self.next)?;
                let mut retired = store::Retired {
                    label: row.label,
                    serial: (floor != 0).then_some(retirement),
                    floor: [0; RECORD_HEADER_LEN],
                };
                if floor != 0 {
                    policy::tombstone(floor).encode_header(&mut retired.floor)?;
                }
                delta.original = Some(slot);
                delta.label = destination;
                delta.serial = Some(take_serial(self.next)?);
                delta.retired = Some(retired);
                continue;
            }
            if action == Action::Keep || same(original.records, delta.records.view()?) {
                delta.clear();
                self.stage.len -= 1;
                continue;
            }
            if action == Action::Replace {
                query::validate_recovered(original.label, delta.records.view()?)?;
            }
            preserve_expiration(
                original,
                &mut delta.records,
                self.now,
                &mut self.stage.indices,
            )?;
            if same(original.records, delta.records.view()?) {
                delta.clear();
                self.stage.len -= 1;
                continue;
            }
            let serial = take_serial(self.next)?;
            delta.original = Some(slot);
            delta.label = row.label;
            delta.serial = (delta.records.count != 0).then_some(serial);
        }
        Ok(())
    }
}

fn take_serial(next: &mut u64) -> Result<u64, Error> {
    let serial = *next;
    *next = serial.checked_add(1).ok_or(Error::Overflow)?;
    Ok(serial)
}

fn zone_rows<const R: usize, const D: usize>(
    inventory: &Inventory<R, D>,
    zone: Option<usize>,
) -> impl Iterator<Item = (usize, &Row<D>)> {
    let mut after = 0;
    core::iter::from_fn(move || {
        let zone = zone?;
        let (slot, row) = inventory
            .rows
            .iter()
            .enumerate()
            .filter_map(|(slot, row)| row.as_ref().map(|row| (slot, row)))
            .filter(|(_, row)| row.zone == zone && row.serial > after)
            .min_by_key(|(_, row)| row.serial)?;
        after = row.serial;
        Some((slot, row))
    })
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Action {
    Keep,
    Retain,
    Replace,
}

/// Change proposal for just one original row, backed by bounded caller scratch.
/// Each decision starts from the exact original, independent of prior choices.
pub struct RowChange<'a, const D: usize> {
    original: Records<'a>,
    body: &'a mut Body<D>,
    labels: &'a mut LabelScratch,
    action: Action,
    destination: Option<Label>,
}

impl<const D: usize> RowChange<'_, D> {
    /// Replace the exact stored representation. The owner validates its
    /// authority policy and carries forward any still-live publication floor.
    pub fn replace(&mut self, records: Records<'_>) -> Result<(), Error> {
        self.destination = None;
        if records.count() == 0 {
            self.delete();
            return Ok(());
        }
        self.body.copy(records)?;
        self.action = Action::Replace;
        Ok(())
    }

    /// Encode a complete replacement from borrowed record data.
    pub fn replace_records(&mut self, records: &[RecordData<'_>]) -> Result<(), Error> {
        self.destination = None;
        self.body.encode(records)?;
        self.action = Action::Replace;
        Ok(())
    }

    /// Remove the row's application records, retaining a tombstone if required
    /// to protect its previous public expiration.
    pub fn delete(&mut self) {
        self.body.clear();
        self.action = Action::Retain;
        self.destination = None;
    }

    /// Move this row to an unused label in the same private zone atomically.
    /// The old label retains its publication floor and an advisory hint only if
    /// a tombstone is needed. The new label has no hint. The caller supplies the
    /// final nonempty destination records and must not copy old tombstones there.
    pub fn move_to(&mut self, label: &[u8], records: Records<'_>) -> Result<(), Error> {
        if records.count() == 0 {
            return Err(Error::InvalidInput);
        }
        for record in records.records().iter() {
            if record?.record_type == RecordType::TOMBSTONE {
                return Err(Error::InvalidInput);
            }
        }
        let label = self.labels.normalize(label)?;
        self.replace(records)?;
        self.destination = Some(label);
        Ok(())
    }

    /// Filter the original row while preserving the exact record bytes and
    /// relative order of all survivors. The predicate can refuse the turn.
    pub fn retain_records(
        &mut self,
        mut keep: impl FnMut(RecordData<'_>) -> Result<bool, Error>,
    ) -> Result<(), Error> {
        self.body.clear();
        self.action = Action::Keep;
        self.destination = None;
        let bytes = self.original.records().record_bytes();
        let mut remaining = bytes;
        let mut before_removal = 0;
        let mut removed = false;
        while !remaining.is_empty() {
            let (record, tail) = RecordData::decode_prefix(remaining)?;
            if keep(record)? {
                if removed {
                    let prefix = &remaining[..remaining.len() - tail.len()];
                    let end = self
                        .body
                        .used
                        .checked_add(prefix.len())
                        .ok_or(Error::Overflow)?;
                    self.body
                        .bytes
                        .get_mut(self.body.used..end)
                        .ok_or(Error::Capacity)?
                        .copy_from_slice(prefix);
                    self.body.used = end;
                    self.body.count += 1;
                } else {
                    before_removal += 1;
                }
            } else if !removed {
                let offset = bytes.len() - remaining.len();
                self.body
                    .bytes
                    .get_mut(..offset)
                    .ok_or(Error::Capacity)?
                    .copy_from_slice(&bytes[..offset]);
                self.body.used = offset;
                self.body.count = before_removal;
                removed = true;
            }
            remaining = tail;
        }
        if removed {
            let (used, count) = (self.body.used, self.body.count);
            finish_records(self.body, used, count)?;
            self.action = Action::Retain;
        }
        Ok(())
    }
}

impl<const R: usize, const D: usize> Owner<'_, R, D> {
    /// Inspect and atomically transform existing rows in one exact zone. A
    /// replacement keeps its advisory hint and uses a new revision. Moves
    /// touch both labels. Physical removals consume a revision too. If there
    /// are no changes, the publisher is not called and changes are empty.
    ///
    /// # Errors
    /// A visitor or definite publisher failure leaves all rows untouched.
    /// Uncertain publication fences the inventory until durable recovery.
    pub fn transform_zone<'request, 'scratch, const N: usize>(
        &mut self,
        zone: SecretKeyView<'request>,
        now: u64,
        stage: &'scratch mut StoreScratch<R, D, N>,
        transform: impl FnOnce(ZoneTransform<'_, R, D, N>) -> Result<(), Error>,
        publish: impl FnOnce(AfterImage<'_, R, D>) -> Result<(), CommitError>,
    ) -> Result<Committed<'request, 'scratch, R, D, N>, Error> {
        stage.clear();
        let result = (|| {
            self.live()?;
            checked_time(now)?;
            let known = self.inventory.zone_index(zone);
            let mut next = self.inventory.next_serial;
            transform(ZoneTransform {
                inventory: self.inventory,
                stage,
                next: &mut next,
                zone: known,
                now,
            })?;
            self.commit_records(zone, known, next, true, stage, publish)
        })();
        if let Err(error) = result {
            stage.clear();
            return Err(error);
        }
        Ok(Committed {
            code: Code::NONE,
            zone,
            stage,
        })
    }
}

fn same(left: Records<'_>, right: Records<'_>) -> bool {
    left.count() == right.count() && left.bytes() == right.bytes()
}

fn preserve_expiration<const D: usize>(
    original: RowRef<'_>,
    candidate: &mut Body<D>,
    now: u64,
    indices: &mut [usize],
) -> Result<(), Error> {
    let floor = query::public_expiry(original.label, original.records, now, indices)?;
    if floor == 0 || query::public_expiry(original.label, candidate.view()?, now, indices)? >= floor
    {
        return Ok(());
    }
    // Keep all exact ordinary/extension records. Replace only tombstones, so
    // a large survivor set does not pay for a second, now redundant floor.
    let mut written = 0;
    let mut read = 0;
    let mut count: u16 = 0;
    for _ in 0..candidate.count {
        let (record, tail) = RecordData::decode_prefix(&candidate.bytes[read..candidate.used])?;
        let end = candidate.used - tail.len();
        if record.record_type != RecordType::TOMBSTONE {
            candidate.bytes.copy_within(read..end, written);
            written += end - read;
            count += 1;
        }
        read = end;
    }
    written += policy::tombstone(floor).encode(&mut candidate.bytes[written..])?;
    finish_records(
        candidate,
        written,
        count.checked_add(1).ok_or(Error::Overflow)?,
    )
}

fn finish_records<const D: usize>(
    target: &mut Body<D>,
    unpadded: usize,
    count: u16,
) -> Result<(), Error> {
    let preferred = if count != 0
        && !RecordData::decode_prefix(&target.bytes[..unpadded])?
            .0
            .record_type
            .is_zone_delegation()
    {
        unpadded
            .checked_next_power_of_two()
            .ok_or(Error::Overflow)?
    } else {
        unpadded
    };
    // An explicitly sized record set may be unpadded when canonical padding
    // would exceed this caller's fixed capacity.
    let used = if preferred <= D { preferred } else { unpadded };
    target.bytes[unpadded..target.used.max(used)].zeroize();
    target.used = used;
    target.count = count;
    Ok(())
}
