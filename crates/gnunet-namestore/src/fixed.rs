//! Fixed rows and zeroizing private zone keys for a native NAMESTORE owner.

mod edit;
mod query;
mod store;
mod transform;

pub use edit::EditReply;
pub use query::{Query, ReadScratch};
pub use store::{AfterImage, Changed, CommitError, Committed, StoreScratch};
pub use transform::{RowChange, ZoneTransform, record_is_ordinary_at};

#[cfg(test)]
mod tests;

use crate::{
    MAX_LABEL_BYTES, MAX_RECORDS, RecordData, RecordType, SecretKey, SecretKeyView, normalize_label,
};
use gnunet_gnsrecord::RECORD_HEADER_LEN;
use gnunet_types::Error;
use gnunet_wire::official::{MAX_MESSAGE_SIZE, namestore::Records};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Maximum advisory hint bytes retained by the fixed inventory.
pub const MAX_HINT_BYTES: usize = 512;
/// Maximum decomposed label wire bytes accepted by this fixed profile.
pub const MAX_LABEL_INPUT_BYTES: usize = 4 * MAX_LABEL_BYTES;

#[derive(Clone, Copy)]
struct Label {
    bytes: [u8; MAX_LABEL_BYTES],
    len: u8,
}

impl Label {
    const EMPTY: Self = Self {
        bytes: [0; MAX_LABEL_BYTES],
        len: 0,
    };

    fn bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

struct LabelScratch {
    scalars: [u32; MAX_LABEL_INPUT_BYTES],
    normalized: [u32; MAX_LABEL_INPUT_BYTES],
    ordering: [u32; MAX_LABEL_INPUT_BYTES],
}

impl LabelScratch {
    const EMPTY: Self = Self {
        scalars: [0; MAX_LABEL_INPUT_BYTES],
        normalized: [0; MAX_LABEL_INPUT_BYTES],
        ordering: [0; MAX_LABEL_INPUT_BYTES],
    };

    fn normalize(&mut self, name: &[u8]) -> Result<Label, Error> {
        if name.len() > MAX_LABEL_INPUT_BYTES {
            return Err(Error::TooLarge);
        }
        let mut result = Label::EMPTY;
        let len = normalize_label(
            name,
            &mut result.bytes,
            &mut self.scalars,
            &mut self.normalized,
            &mut self.ordering,
            MAX_LABEL_BYTES,
        )
        .map_err(|error| {
            if error == Error::Capacity {
                Error::TooLarge
            } else {
                error
            }
        })?;
        result.len = u8::try_from(len).map_err(|_| Error::TooLarge)?;
        Ok(result)
    }

    fn clear(&mut self) {
        self.scalars.zeroize();
        self.normalized.zeroize();
        self.ordering.zeroize();
    }
}

struct Body<const D: usize> {
    bytes: [u8; D],
    used: usize,
    count: u16,
}

impl<const D: usize> Body<D> {
    const EMPTY: Self = Self {
        bytes: [0; D],
        used: 0,
        count: 0,
    };

    fn clear(&mut self) {
        self.bytes[..self.used].zeroize();
        self.used = 0;
        self.count = 0;
    }

    fn copy(&mut self, records: Records<'_>) -> Result<(), Error> {
        let used = records.bytes().len();
        if used > D || usize::from(records.count()) > D / RECORD_HEADER_LEN {
            return Err(Error::Capacity);
        }
        self.clear();
        self.bytes[..used].copy_from_slice(records.bytes());
        self.used = used;
        self.count = records.count();
        Ok(())
    }

    fn encode(&mut self, records: &[RecordData<'_>]) -> Result<(), Error> {
        let count = u16::try_from(records.len()).map_err(|_| Error::Capacity)?;
        let used =
            gnunet_gnsrecord::serialize(records, &mut self.bytes[..D.min(MAX_MESSAGE_SIZE)])?;
        if used < self.used {
            self.bytes[used..self.used].zeroize();
        }
        self.used = used;
        self.count = count;
        Ok(())
    }

    fn view(&self) -> Result<Records<'_>, Error> {
        Records::new(&self.bytes[..self.used], self.count)
    }

    fn writer(&mut self) -> BodyWriter<'_, D> {
        self.clear();
        BodyWriter {
            body: self,
            padded: false,
            finished: false,
        }
    }
}

impl<const D: usize> Drop for Body<D> {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Serialize selected borrowed records directly into their caller-owned body.
/// Failed writes erase the incomplete body, including bytes from earlier rows.
struct BodyWriter<'body, const D: usize> {
    body: &'body mut Body<D>,
    padded: bool,
    finished: bool,
}

impl<const D: usize> BodyWriter<'_, D> {
    fn push(&mut self, record: RecordData<'_>) -> Result<usize, Error> {
        let body = &mut *self.body;
        if usize::from(body.count) >= MAX_RECORDS {
            return Err(Error::Capacity);
        }
        let start = body.used;
        let capacity = D.min(MAX_MESSAGE_SIZE);
        body.used += record.encode(&mut body.bytes[start..capacity])?;
        if body.count == 0 {
            self.padded = !record.record_type.is_zone_delegation();
        }
        body.count += 1;
        Ok(start)
    }

    fn records(&self) -> &[u8] {
        &self.body.bytes[..self.body.used]
    }

    fn finish(mut self) -> Result<(), Error> {
        let body = &mut *self.body;
        if self.padded {
            let used = body.used.next_power_of_two();
            if used > D || used > MAX_MESSAGE_SIZE {
                return Err(Error::Capacity);
            }
            body.bytes[body.used..used].fill(0);
            body.used = used;
        }
        self.finished = true;
        Ok(())
    }
}

impl<const D: usize> Drop for BodyWriter<'_, D> {
    fn drop(&mut self) {
        if !self.finished {
            self.body.clear();
        }
    }
}

struct Hint {
    bytes: [u8; MAX_HINT_BYTES],
    len: usize,
}

impl Hint {
    fn copy(hint: &[u8]) -> Result<Self, Error> {
        if hint.len() > MAX_HINT_BYTES || hint.contains(&0) {
            return Err(Error::InvalidInput);
        }
        let mut value = Self {
            bytes: [0; MAX_HINT_BYTES],
            len: hint.len(),
        };
        value.bytes[..hint.len()].copy_from_slice(hint);
        Ok(value)
    }

    fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl Drop for Hint {
    fn drop(&mut self) {
        self.bytes[..self.len].zeroize();
    }
}

struct Row<const D: usize> {
    zone: usize,
    label: Label,
    records: Body<D>,
    hint: Option<Hint>,
    serial: u64,
}

/// Exact borrowed authoritative row for recovery, raw lookup and persistence.
#[derive(Clone, Copy)]
pub struct RowRef<'a> {
    /// Original private zone authority.
    pub zone: SecretKeyView<'a>,
    /// Canonical case-preserving NFC label.
    pub label: &'a [u8],
    /// Sensitive serialized GNS records, including maintenance.
    pub records: Records<'a>,
    /// Stable database row serial.
    pub serial: u64,
    /// Original advisory hint without NUL, if present.
    pub hint: Option<&'a [u8]>,
}

/// Exclusive caller-owned inventory and its qualified durable serial floor.
pub struct Inventory<const R: usize, const D: usize> {
    rows: [Option<Row<D>>; R],
    zones: [Option<SecretKey>; R],
    next_serial: u64,
    needs_recovery: bool,
}

impl<const R: usize, const D: usize> Inventory<R, D> {
    /// Empty inventory for startup recovery.
    pub const EMPTY: Self = Self {
        rows: [const { None }; R],
        zones: [const { None }; R],
        next_serial: 1,
        needs_recovery: false,
    };

    /// Erase the original authority before loading a complete durable image.
    pub fn clear(&mut self) {
        self.erase_rows();
        self.next_serial = 1;
        self.needs_recovery = false;
    }

    fn erase_rows(&mut self) {
        self.rows.fill_with(|| None);
        self.zones.fill_with(|| None);
    }

    /// Load one canonical original row while no live service owns the inventory.
    ///
    /// # Errors
    /// Refuses invalid/duplicate authority rows and unqualified storage.
    pub fn restore<const OUTPUT: usize, const N: usize>(
        &mut self,
        row: RowRef<'_>,
        scratch: &mut ReadScratch<OUTPUT, N>,
    ) -> Result<(), Error> {
        self.live()?;
        dimensions::<R, D>()?;
        let label = scratch.labels.normalize(row.label)?;
        if label.bytes() != row.label || row.serial == 0 || row.records.count() == 0 {
            return Err(Error::InvalidInput);
        }
        query::validate_recovered(row.label, row.records)?;
        let next = row.serial.checked_add(1).ok_or(Error::Overflow)?;
        let known = self.zone_index(row.zone);
        if self.rows.iter().flatten().any(|existing| {
            existing.serial == row.serial
                || (Some(existing.zone) == known && existing.label.bytes() == row.label)
        }) {
            return Err(Error::Conflict);
        }
        let index = self
            .rows
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let hint = row.hint.map(Hint::copy).transpose()?;
        let mut records = Body::EMPTY;
        records.copy(row.records)?;
        let zone = match known {
            Some(index) => index,
            None => {
                let slot = self
                    .zones
                    .iter()
                    .position(Option::is_none)
                    .ok_or(Error::Capacity)?;
                self.zones[slot] = Some(SecretKey::from_serialized(row.zone.expose_serialized())?);
                slot
            }
        };
        self.rows[index] = Some(Row {
            zone,
            label,
            records,
            hint,
            serial: row.serial,
        });
        self.next_serial = self.next_serial.max(next);
        Ok(())
    }

    /// Qualify the persisted next unused serial, including removed rows.
    pub fn finish_restore(&mut self, next_serial: u64) -> Result<(), Error> {
        self.live()?;
        if next_serial < self.next_serial {
            return Err(Error::Replay);
        }
        self.next_serial = next_serial;
        Ok(())
    }

    fn live(&self) -> Result<(), Error> {
        if self.needs_recovery {
            Err(Error::OutcomeUnknown)
        } else {
            Ok(())
        }
    }

    fn zone_index(&self, key: SecretKeyView<'_>) -> Option<usize> {
        self.zones.iter().position(|original| {
            original.as_ref().is_some_and(|original| {
                bool::from(original.expose_serialized().ct_eq(key.expose_serialized()))
            })
        })
    }

    fn zone(&self, index: usize) -> Result<SecretKeyView<'_>, Error> {
        self.zones
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(Error::Conflict)?
            .view()
    }

    fn locate(&self, zone: Option<usize>, name: &[u8]) -> Option<usize> {
        let zone = zone?;
        self.rows.iter().position(|row| {
            row.as_ref()
                .is_some_and(|row| row.zone == zone && row.label.bytes() == name)
        })
    }

    fn view<'a>(&'a self, row: &'a Row<D>) -> Result<RowRef<'a>, Error> {
        Ok(RowRef {
            zone: self.zone(row.zone)?,
            label: row.label.bytes(),
            records: row.records.view()?,
            serial: row.serial,
            hint: row.hint.as_ref().map(Hint::bytes),
        })
    }
}

fn dimensions<const R: usize, const D: usize>() -> Result<(), Error> {
    if R == 0 || !(RECORD_HEADER_LEN..=MAX_MESSAGE_SIZE).contains(&D) {
        Err(Error::InvalidInput)
    } else {
        Ok(())
    }
}

fn checked_time(now: u64) -> Result<(), Error> {
    if now == u64::MAX {
        Err(Error::TimeUncertain)
    } else {
        Ok(())
    }
}

/// The original live fixed authority, exclusively borrowing its recovered rows.
pub struct Owner<'memory, const R: usize, const D: usize> {
    inventory: &'memory mut Inventory<R, D>,
    critical: fn(RecordType) -> bool,
    closed: bool,
}

impl<'memory, const R: usize, const D: usize> Owner<'memory, R, D> {
    /// Start after complete recovery with the actual critical-type registry.
    pub fn new(
        inventory: &'memory mut Inventory<R, D>,
        critical: fn(RecordType) -> bool,
    ) -> Result<Self, Error> {
        dimensions::<R, D>()?;
        inventory.live()?;
        Ok(Self {
            inventory,
            critical,
            closed: false,
        })
    }

    /// Erase retained keys and permanently retire this owner.
    pub fn clear(&mut self) {
        self.inventory.erase_rows();
        self.closed = true;
    }

    fn live(&self) -> Result<(), Error> {
        self.inventory.live()?;
        if self.closed {
            Err(Error::Closed)
        } else {
            Ok(())
        }
    }

    /// Original next unused record serial and committed record revision floor.
    /// Physical removal may consume a serial without creating a current row.
    /// Edits to advisory hints preserve this floor.
    pub fn next_serial(&self) -> Result<u64, Error> {
        self.live()?;
        Ok(self.inventory.next_serial)
    }
}
