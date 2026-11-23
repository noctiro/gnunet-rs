//! Scoped STORE preparation, durable after-image publication and settlement.

use super::{Body, Hint, Inventory, Label, LabelScratch, Owner, Row, RowRef, checked_time, query};
use crate::{Code, RecordType, SecretKey, SecretKeyView, policy};
use gnunet_gnsrecord::{RECORD_HEADER_LEN, validate_authoritative_iter};
use gnunet_types::Error;
use gnunet_wire::official::namestore::{RecordSets, Records, StoreSet};
use zeroize::Zeroize;

pub(super) struct Delta<const D: usize> {
    pub(super) label: Label,
    pub(super) original: Option<usize>,
    pub(super) serial: Option<u64>,
    pub(super) records: Body<D>,
    pub(super) retired: Option<Retired>,
}

/// Relocations need only the old label and its optional publication floor.
/// The new body's storage is the ordinary delta, even for a very large row.
pub(super) struct Retired {
    pub(super) label: Label,
    pub(super) serial: Option<u64>,
    pub(super) floor: [u8; RECORD_HEADER_LEN],
}

impl<const D: usize> Delta<D> {
    const EMPTY: Self = Self {
        label: Label::EMPTY,
        original: None,
        serial: None,
        records: Body::EMPTY,
        retired: None,
    };

    pub(super) fn clear(&mut self) {
        self.label.bytes.zeroize();
        self.label.len = 0;
        self.original = None;
        self.serial = None;
        self.records.clear();
        if let Some(retired) = &mut self.retired {
            retired.label.bytes.zeroize();
            retired.floor.zeroize();
        }
        self.retired = None;
    }

    fn effective(&self) -> bool {
        self.original.is_some() || self.serial.is_some()
    }
}

/// Caller-owned staging for up to `B` changed labels with `D` bytes each.
/// `N` is the number of sortable public-record offsets available per label.
pub struct StoreScratch<const B: usize, const D: usize, const N: usize> {
    pub(super) labels: LabelScratch,
    pub(super) indices: [usize; N],
    pub(super) delta: [Delta<D>; B],
    pub(super) len: usize,
}

impl<const B: usize, const D: usize, const N: usize> StoreScratch<B, D, N> {
    /// Empty staging storage for a native arena.
    pub const EMPTY: Self = Self {
        labels: LabelScratch::EMPTY,
        indices: [0; N],
        delta: [const { Delta::EMPTY }; B],
        len: 0,
    };

    /// Erase all retained mutation bytes and temporary names.
    pub fn clear(&mut self) {
        for delta in &mut self.delta[..self.len] {
            delta.clear();
        }
        self.len = 0;
        self.labels.clear();
        self.indices.zeroize();
    }

    fn proposals(&self) -> &[Delta<D>] {
        &self.delta[..self.len]
    }
}

/// Disposition of a failed request to durably publish the exact after-image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitError {
    /// The original publication is known to have been rejected.
    Failed(Error),
    /// The backend must recover the actual result before serving again.
    OutcomeUnknown,
}

/// Borrow of one qualified after-image. Unchanged record bodies remain in the
/// original inventory and changed bodies are borrowed from the staging arena.
pub struct AfterImage<'a, const R: usize, const D: usize> {
    previous: &'a Inventory<R, D>,
    change: ImageChange<'a, D>,
    next_serial: u64,
}

#[derive(Clone, Copy)]
enum ImageChange<'a, const D: usize> {
    Records {
        deltas: &'a [Delta<D>],
        zone: SecretKeyView<'a>,
        preserve_hints: bool,
    },
    Hint {
        slot: usize,
        hint: Option<&'a Hint>,
    },
}

impl<const R: usize, const D: usize> AfterImage<'_, R, D> {
    /// Persist this original next unused serial along with all rows.
    pub const fn next_serial(&self) -> u64 {
        self.next_serial
    }

    /// Borrow the complete resulting authority in increasing serial order.
    pub fn rows(&self) -> impl Iterator<Item = Result<RowRef<'_>, Error>> {
        let mut after = 0;
        core::iter::from_fn(move || {
            let records = match self.change {
                ImageChange::Records {
                    deltas,
                    zone,
                    preserve_hints,
                } => Some((deltas, zone, preserve_hints)),
                ImageChange::Hint { .. } => None,
            };
            let existing = self
                .previous
                .rows
                .iter()
                .enumerate()
                .filter(|(i, _)| {
                    records.is_none_or(|(deltas, _, _)| {
                        !deltas.iter().any(|delta| delta.original == Some(*i))
                    })
                })
                .filter_map(|(index, row)| row.as_ref().map(|row| (index, row)))
                .filter(|(_, row)| row.serial > after)
                .min_by_key(|(_, row)| row.serial);
            if let Some((index, row)) = existing {
                after = row.serial;
                return Some(self.previous.view(row).map(|mut view| {
                    if let ImageChange::Hint { slot, hint } = self.change
                        && slot == index
                    {
                        view.hint = hint.map(Hint::bytes);
                    }
                    view
                }));
            }
            let (deltas, zone, preserve_hints) = records?;
            let (serial, replacement, retired) = deltas
                .iter()
                .flat_map(|delta| {
                    [
                        delta.serial.map(|serial| (serial, delta, None)),
                        delta
                            .retired
                            .as_ref()
                            .and_then(|old| old.serial.map(|serial| (serial, delta, Some(old)))),
                    ]
                    .into_iter()
                    .flatten()
                })
                .filter(|(serial, _, _)| *serial > after)
                .min_by_key(|(serial, _, _)| *serial)?;
            after = serial;
            let hint = || {
                replacement
                    .original
                    .filter(|_| preserve_hints)
                    .and_then(|slot| {
                        self.previous.rows[slot]
                            .as_ref()?
                            .hint
                            .as_ref()
                            .map(Hint::bytes)
                    })
            };
            if let Some(old) = retired {
                return Some(Records::new(&old.floor, 1).map(|records| RowRef {
                    zone,
                    label: old.label.bytes(),
                    records,
                    serial,
                    hint: hint(),
                }));
            }
            Some(replacement.records.view().map(|records| RowRef {
                zone,
                label: replacement.label.bytes(),
                records,
                serial,
                hint: replacement.retired.is_none().then(hint).flatten(),
            }))
        })
    }
}

impl<'a, const R: usize, const D: usize> AfterImage<'a, R, D> {
    pub(super) const fn hint(
        previous: &'a Inventory<R, D>,
        slot: usize,
        hint: Option<&'a Hint>,
    ) -> Self {
        Self {
            previous,
            change: ImageChange::Hint { slot, hint },
            next_serial: previous.next_serial,
        }
    }
}

/// One label affected by the confirmed batch, including an actual deletion.
pub struct Changed<'a> {
    /// Exact private zone from the original STORE.
    pub zone: SecretKeyView<'a>,
    /// Canonical label suitable for filtered monitor lookup.
    pub label: &'a [u8],
    /// New committed row revision, or `None` for a physical deletion.
    pub serial: Option<u64>,
}

/// Store result and its exact labels for synchronous monitor publication.
pub struct Committed<'request, 'scratch, const B: usize, const D: usize, const N: usize> {
    /// Actual business result. Non-atomic frames can commit a valid prefix.
    pub code: Code,
    pub(super) zone: SecretKeyView<'request>,
    pub(super) stage: &'scratch mut StoreScratch<B, D, N>,
}

impl<const B: usize, const D: usize, const N: usize> Committed<'_, '_, B, D, N> {
    /// Borrow the final touched labels, in original first-touch ordering.
    pub fn changes(&self) -> impl Iterator<Item = Changed<'_>> {
        self.stage
            .proposals()
            .iter()
            .filter(|delta| delta.effective())
            .flat_map(|delta| {
                [
                    delta.retired.as_ref().map(|old| Changed {
                        zone: self.zone,
                        label: old.label.bytes(),
                        serial: old.serial,
                    }),
                    Some(Changed {
                        zone: self.zone,
                        label: delta.label.bytes(),
                        serial: delta.serial,
                    }),
                ]
                .into_iter()
                .flatten()
            })
    }
}

impl<const B: usize, const D: usize, const N: usize> Drop for Committed<'_, '_, B, D, N> {
    fn drop(&mut self) {
        self.stage.clear();
    }
}

struct Revision {
    next: u64,
    rows: usize,
}

impl<const R: usize, const D: usize> Owner<'_, R, D> {
    /// Prepare a complete STORE batch and publish it only on durable success.
    /// A non-atomic validation refusal can publish only the valid prefix.
    ///
    /// # Errors
    /// Resource failures preserve the original committed image. Uncertain
    /// publication fences live reads and requires explicit durable recovery.
    pub fn store<'request, 'scratch, const B: usize, const N: usize>(
        &mut self,
        zone: SecretKeyView<'request>,
        sets: RecordSets<'_>,
        single_tx: bool,
        now: u64,
        stage: &'scratch mut StoreScratch<B, D, N>,
        publish: impl FnOnce(AfterImage<'_, R, D>) -> Result<(), CommitError>,
    ) -> Result<Committed<'request, 'scratch, B, D, N>, Error> {
        self.store_sets(zone, sets.iter(), single_tx, now, stage, publish)
    }

    /// Replace one complete row of the original zone through the same atomic
    /// store path as an IPC Store batch.
    pub fn store_one<'request, 'scratch, const B: usize, const N: usize>(
        &mut self,
        zone: SecretKeyView<'request>,
        set: StoreSet<'_>,
        now: u64,
        stage: &'scratch mut StoreScratch<B, D, N>,
        publish: impl FnOnce(AfterImage<'_, R, D>) -> Result<(), CommitError>,
    ) -> Result<Committed<'request, 'scratch, B, D, N>, Error> {
        self.store_sets(zone, core::iter::once(Ok(set)), true, now, stage, publish)
    }

    fn store_sets<'request, 'scratch, 'set, const B: usize, const N: usize>(
        &mut self,
        zone: SecretKeyView<'request>,
        mut sets: impl ExactSizeIterator<Item = Result<StoreSet<'set>, Error>>,
        single_tx: bool,
        now: u64,
        stage: &'scratch mut StoreScratch<B, D, N>,
        publish: impl FnOnce(AfterImage<'_, R, D>) -> Result<(), CommitError>,
    ) -> Result<Committed<'request, 'scratch, B, D, N>, Error> {
        stage.clear();
        match self.store_original(zone, &mut sets, single_tx, now, stage, publish) {
            Ok(code) => Ok(Committed { code, zone, stage }),
            Err(error) => {
                stage.clear();
                Err(error)
            }
        }
    }

    fn store_original<'set, const B: usize, const N: usize>(
        &mut self,
        zone: SecretKeyView<'_>,
        sets: &mut dyn ExactSizeIterator<Item = Result<StoreSet<'set>, Error>>,
        single_tx: bool,
        now: u64,
        stage: &mut StoreScratch<B, D, N>,
        publish: impl FnOnce(AfterImage<'_, R, D>) -> Result<(), CommitError>,
    ) -> Result<Code, Error> {
        self.live()?;
        checked_time(now)?;
        if sets.len() > B {
            return Err(Error::Capacity);
        }
        let known = self.inventory.zone_index(zone);
        let mut revision = Revision {
            next: self.inventory.next_serial,
            rows: self.inventory.rows.iter().flatten().count(),
        };
        let mut code = Code::NONE;
        for set in sets {
            if let Some(refused) = self.stage_record(known, set?, now, stage, &mut revision)? {
                code = refused;
                break;
            }
        }
        if code != Code::NONE && (single_tx || stage.len == 0) {
            stage.clear();
            return Ok(code);
        }
        self.commit_records(zone, known, revision.next, false, stage, publish)?;
        Ok(code)
    }

    pub(super) fn commit_records<const B: usize, const N: usize>(
        &mut self,
        zone: SecretKeyView<'_>,
        known: Option<usize>,
        next: u64,
        preserve_hints: bool,
        stage: &mut StoreScratch<B, D, N>,
        publish: impl FnOnce(AfterImage<'_, R, D>) -> Result<(), CommitError>,
    ) -> Result<(), Error> {
        if stage.len == 0 {
            return Ok(());
        }
        let assignments = self.reserve_rows(stage)?;
        let new_rows = assignments.iter().any(Option::is_some);
        let (zone_index, imported) = if new_rows {
            match known {
                Some(index) => (Some(index), None),
                None => {
                    let index = self
                        .inventory
                        .zones
                        .iter()
                        .position(Option::is_none)
                        .ok_or(Error::Capacity)?;
                    (
                        Some(index),
                        Some(SecretKey::from_serialized(zone.expose_serialized())?),
                    )
                }
            }
        } else {
            (known, None)
        };
        let image = AfterImage {
            previous: self.inventory,
            change: ImageChange::Records {
                deltas: stage.proposals(),
                zone,
                preserve_hints,
            },
            next_serial: next,
        };
        match publish(image) {
            Ok(()) => (),
            Err(CommitError::OutcomeUnknown | CommitError::Failed(Error::OutcomeUnknown)) => {
                self.inventory.needs_recovery = true;
                return Err(Error::OutcomeUnknown);
            }
            Err(CommitError::Failed(error)) => return Err(error),
        }
        self.apply(
            stage,
            assignments,
            zone_index,
            imported,
            next,
            preserve_hints,
        );
        Ok(())
    }

    fn stage_record<const B: usize, const N: usize>(
        &self,
        zone: Option<usize>,
        set: StoreSet<'_>,
        now: u64,
        stage: &mut StoreScratch<B, D, N>,
        revision: &mut Revision,
    ) -> Result<Option<Code>, Error> {
        let label = match stage.labels.normalize(set.label.bytes()) {
            Ok(label) => label,
            Err(Error::InvalidInput | Error::TooLarge) => return Ok(Some(Code::LABEL_INVALID)),
            Err(error) => return Err(error),
        };
        let draft = stage
            .proposals()
            .iter()
            .position(|draft| draft.label.bytes() == label.bytes());
        let original = draft.map_or_else(
            || self.inventory.locate(zone, label.bytes()),
            |index| stage.delta[index].original,
        );
        let previous = match draft {
            Some(index) => {
                let row = &stage.delta[index];
                row.serial.map(|_| row.records.view()).transpose()?
            }
            None => original
                .and_then(|index| self.inventory.rows[index].as_ref())
                .map(|row| row.records.view())
                .transpose()?,
        };
        if set.records.count() == 0 && !previous.map_or(Ok(false), has_ordinary_records)? {
            return Ok(Some(Code::RECORD_NOT_FOUND));
        }
        let expiry = previous.map_or(Ok(0), |records| {
            query::public_expiry(label.bytes(), records, now, &mut stage.indices)
        })?;

        let existed = previous.is_some();
        let index = draft.unwrap_or(stage.len);
        let delta = stage.delta.get_mut(index).ok_or(Error::Capacity)?;
        match prepare_body(
            label.bytes(),
            set.records,
            expiry,
            now,
            &mut delta.records,
            &mut stage.indices,
            self.critical,
        ) {
            Ok(()) => (),
            Err(Error::InvalidInput) => return Ok(Some(Code::RECORD_DATA_INVALID)),
            Err(error) => return Err(error),
        }
        let exists = delta.records.count != 0;
        stage.len = stage.len.max(index + 1);
        let rows = revision.rows + usize::from(exists) - usize::from(existed);
        if rows > R {
            return Err(Error::Capacity);
        }
        // An admitted physical deletion advances the same durable floor as a
        // replacement. No present row may reuse the deleted revision.
        let serial = revision.next;
        revision.next = revision.next.checked_add(1).ok_or(Error::Overflow)?;
        delta.label = label;
        delta.original = original;
        delta.serial = exists.then_some(serial);
        revision.rows = rows;
        Ok(None)
    }

    fn reserve_rows<const B: usize, const N: usize>(
        &self,
        stage: &StoreScratch<B, D, N>,
    ) -> Result<[Option<usize>; B], Error> {
        let mut used = self.inventory.rows.each_ref().map(Option::is_some);
        let mut assignments = [None; B];
        for (target, delta) in assignments.iter_mut().zip(stage.proposals()) {
            if let Some(original) = delta.original {
                if delta
                    .retired
                    .as_ref()
                    .is_some_and(|old| old.serial.is_some())
                {
                    // The old slot keeps its tombstone; assign the destination below.
                    continue;
                }
                if delta.serial.is_some() {
                    *target = Some(original);
                } else {
                    used[original] = false;
                }
            }
        }
        for (target, delta) in assignments.iter_mut().zip(stage.proposals()) {
            if delta.serial.is_some() && target.is_none() {
                let empty = used
                    .iter_mut()
                    .position(|occupied| !core::mem::replace(occupied, true))
                    .ok_or(Error::Capacity)?;
                *target = Some(empty);
            }
        }
        Ok(assignments)
    }

    fn apply<const B: usize, const N: usize>(
        &mut self,
        stage: &mut StoreScratch<B, D, N>,
        assignments: [Option<usize>; B],
        zone: Option<usize>,
        imported: Option<SecretKey>,
        next: u64,
        preserve_hints: bool,
    ) {
        for delta in stage.proposals() {
            if let Some(slot) = delta.original {
                if delta.serial.is_none() {
                    self.inventory.rows[slot] = None;
                }
                if let Some(old) = &delta.retired
                    && let Some(serial) = old.serial
                    && let Some(row) = &mut self.inventory.rows[slot]
                {
                    row.records.clear();
                    row.records.bytes[..RECORD_HEADER_LEN].copy_from_slice(&old.floor);
                    row.records.used = RECORD_HEADER_LEN;
                    row.records.count = 1;
                    row.serial = serial;
                }
            }
        }
        if let Some(zone) = zone {
            if let Some(imported) = imported {
                self.inventory.zones[zone] = Some(imported);
            }
            for (delta, target) in stage.delta[..stage.len].iter_mut().zip(assignments) {
                if let Some((serial, slot)) = delta.serial.zip(target) {
                    let records = core::mem::replace(&mut delta.records, Body::EMPTY);
                    let hint = if preserve_hints && delta.retired.is_none() {
                        self.inventory.rows[slot]
                            .as_mut()
                            .and_then(|row| row.hint.take())
                    } else {
                        None
                    };
                    self.inventory.rows[slot] = Some(Row {
                        zone,
                        records,
                        label: delta.label,
                        serial,
                        hint,
                    });
                }
            }
            if !self
                .inventory
                .rows
                .iter()
                .flatten()
                .any(|row| row.zone == zone)
            {
                self.inventory.zones[zone] = None;
            }
        }
        self.inventory.next_serial = next;
    }
}

pub(super) fn has_ordinary_records(records: Records<'_>) -> Result<bool, Error> {
    for item in records.records().iter() {
        if item?.record_type != RecordType::TOMBSTONE {
            return Ok(true);
        }
    }
    Ok(false)
}

fn prepare_body<const D: usize>(
    label: &[u8],
    records: Records<'_>,
    previous_expiry: u64,
    now: u64,
    body: &mut Body<D>,
    indices: &mut [usize],
    mut critical: fn(RecordType) -> bool,
) -> Result<(), Error> {
    let records = records.records();
    validate_authoritative_iter(label, records.iter(), |record| {
        policy::retain_for_store(label, *record, now)
    })?;
    let mut floor = if previous_expiry >= now {
        previous_expiry
    } else {
        0
    };
    let mut writer = body.writer();
    let mut used = 0;
    for record in records.iter() {
        let record = record?;
        floor = policy::tombstone_floor(record, now, floor);
        if let Some(record) = policy::select_for_store(label, record, now, &mut critical) {
            let offset = writer.push(record)?;
            if policy::contributes_public_expiry(label, record) {
                *indices.get_mut(used).ok_or(Error::Capacity)? = offset;
                used += 1;
            }
        }
    }
    let expires = query::expiration_at_offsets(writer.records(), &mut indices[..used], now)?;
    if floor > expires && floor >= now {
        writer.push(policy::tombstone(floor))?;
    }
    writer.finish()
}
