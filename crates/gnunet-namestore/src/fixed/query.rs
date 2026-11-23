//! Borrowed authority lookup and bounded serialization of selected records.

use super::{Body, Hint, Label, LabelScratch, Owner, Row, RowRef, checked_time};
use crate::{
    APEX, Filter, RecordData, RecordType, SecretKeyView, ZoneKey,
    policy::{
        RecordView, absolute_expiry, contributes_public_expiry, supplemental_nickname_for_expiry,
        tombstone_floor, visible,
    },
};
use gnunet_gnsrecord::{RECORD_HEADER_LEN, validate_authoritative_iter};
use gnunet_types::Error;
use gnunet_wire::official::namestore::Records;
use zeroize::Zeroize;

/// Caller-owned rendering scratch with `D` output bytes and `N` sortable record offsets.
pub struct ReadScratch<const D: usize, const N: usize> {
    pub(super) labels: LabelScratch,
    pub(super) indices: [usize; N],
    label: Label,
    pub(super) output: Body<D>,
    pub(super) previous_hint: Option<Hint>,
}

impl<const D: usize, const N: usize> ReadScratch<D, N> {
    /// Empty storage for a product arena.
    pub const EMPTY: Self = Self {
        labels: LabelScratch::EMPTY,
        indices: [0; N],
        label: Label::EMPTY,
        output: Body::EMPTY,
        previous_hint: None,
    };

    /// Erase rendered record bytes and temporary label data.
    pub fn clear(&mut self) {
        self.labels.clear();
        self.indices.zeroize();
        self.label.bytes.zeroize();
        self.label.len = 0;
        self.output.clear();
        self.previous_hint = None;
    }
}

/// One rendered query borrowing original authority and caller response storage.
pub struct Query<'a> {
    /// Exact original private zone.
    pub zone: SecretKeyView<'a>,
    /// Canonical case-preserving label, including on a miss.
    pub label: &'a [u8],
    /// Official result record serialization.
    pub records: Records<'a>,
    /// Actual row existence before payload filtering.
    pub found: bool,
    /// Filtered expiration including a retained tombstone floor.
    pub expires: u64,
    /// Original advisory hint, if present.
    pub hint: Option<&'a [u8]>,
}

impl<const R: usize, const D: usize> Owner<'_, R, D> {
    /// Read a normalized label using the official lookup filter and nickname.
    pub fn lookup<'a, const OUTPUT: usize, const N: usize>(
        &'a self,
        zone: SecretKeyView<'a>,
        label: &[u8],
        filter: Filter,
        now: u64,
        scratch: &'a mut ReadScratch<OUTPUT, N>,
    ) -> Result<Query<'a>, Error> {
        self.read_label(zone, label, RecordView::Lookup(filter), now, scratch)
    }

    /// Read a normalized label for a monitor. A removed row has no records.
    pub fn stream_lookup<'a, const OUTPUT: usize, const N: usize>(
        &'a self,
        zone: SecretKeyView<'a>,
        label: &[u8],
        filter: Filter,
        now: u64,
        scratch: &'a mut ReadScratch<OUTPUT, N>,
    ) -> Result<Query<'a>, Error> {
        self.read_label(zone, label, RecordView::Standard(filter), now, scratch)
    }

    fn read_label<'a, const OUTPUT: usize, const N: usize>(
        &'a self,
        zone: SecretKeyView<'a>,
        label: &[u8],
        view: RecordView,
        now: u64,
        scratch: &'a mut ReadScratch<OUTPUT, N>,
    ) -> Result<Query<'a>, Error> {
        self.live()?;
        checked_time(now)?;
        let name = scratch.labels.normalize(label)?;
        let row = self
            .inventory
            .locate(self.inventory.zone_index(zone), name.bytes())
            .and_then(|index| self.inventory.rows[index].as_ref());
        self.render(zone, name, view, now, row, scratch)
    }

    /// Return the first original stored typed delegation in this private zone.
    pub fn zone_to_name(
        &self,
        key: SecretKeyView<'_>,
        target: ZoneKey,
    ) -> Result<Option<RowRef<'_>>, Error> {
        self.live()?;
        let Some(zone) = self.inventory.zone_index(key) else {
            return Ok(None);
        };
        let mut found = None;
        for row in self
            .inventory
            .rows
            .iter()
            .flatten()
            .filter(|row| row.zone == zone)
        {
            if found.is_some_and(|previous: &Row<D>| previous.serial <= row.serial) {
                continue;
            }
            for record in row.records.view()?.records().iter() {
                if ZoneKey::from_record(&record?).is_ok_and(|value| value == target) {
                    found = Some(row);
                    break;
                }
            }
        }
        found.map(|row| self.inventory.view(row)).transpose()
    }

    /// Borrow the next current original by serial, optionally inside one zone.
    pub fn next_row(
        &self,
        key: Option<SecretKeyView<'_>>,
        after: u64,
    ) -> Result<Option<RowRef<'_>>, Error> {
        self.live()?;
        let zone = if let Some(key) = key {
            let Some(zone) = self.inventory.zone_index(key) else {
                return Ok(None);
            };
            Some(zone)
        } else {
            None
        };
        self.inventory
            .rows
            .iter()
            .flatten()
            .filter(|row| row.serial > after && zone.is_none_or(|zone| row.zone == zone))
            .min_by_key(|row| row.serial)
            .map(|row| self.inventory.view(row))
            .transpose()
    }

    /// Render the exact retained row selected by a stable serial cursor.
    pub fn stream_row<'a, const OUTPUT: usize, const N: usize>(
        &'a self,
        serial: u64,
        filter: Filter,
        now: u64,
        scratch: &'a mut ReadScratch<OUTPUT, N>,
    ) -> Result<Option<Query<'a>>, Error> {
        self.live()?;
        checked_time(now)?;
        let Some(row) = self.row_by_serial(serial) else {
            return Ok(None);
        };
        self.render(
            self.inventory.zone(row.zone)?,
            row.label,
            RecordView::Standard(filter),
            now,
            Some(row),
            scratch,
        )
        .map(Some)
    }

    /// Borrow a current authoritative row by its exact original serial.
    /// A removed or replaced serial returns no row.
    pub fn row(&self, serial: u64) -> Result<Option<RowRef<'_>>, Error> {
        self.live()?;
        self.row_by_serial(serial)
            .map(|row| self.inventory.view(row))
            .transpose()
    }

    fn row_by_serial(&self, serial: u64) -> Option<&Row<D>> {
        self.inventory
            .rows
            .iter()
            .flatten()
            .find(|row| row.serial == serial)
    }

    pub(super) fn render<'a, const OUTPUT: usize, const N: usize>(
        &'a self,
        zone: SecretKeyView<'a>,
        label: Label,
        view: RecordView,
        now: u64,
        row: Option<&'a Row<D>>,
        scratch: &'a mut ReadScratch<OUTPUT, N>,
    ) -> Result<Query<'a>, Error> {
        scratch.label = label;
        let (expires, hint) = if let Some(row) = row {
            let nickname = self.nickname(row.zone, label.bytes())?;
            let expires = render_records(
                label.bytes(),
                row.records.view()?,
                view,
                now,
                self.critical,
                nickname,
                &mut scratch.output,
                &mut scratch.indices,
            )?;
            (expires, row.hint.as_ref().map(Hint::bytes))
        } else {
            scratch.output.clear();
            (0, None)
        };
        Ok(Query {
            zone,
            label: scratch.label.bytes(),
            records: scratch.output.view()?,
            found: row.is_some(),
            expires,
            hint,
        })
    }

    fn nickname(&self, zone: usize, label: &[u8]) -> Result<Option<RecordData<'_>>, Error> {
        if label == APEX {
            return Ok(None);
        }
        let Some(apex) = self
            .inventory
            .locate(Some(zone), APEX)
            .and_then(|index| self.inventory.rows[index].as_ref())
        else {
            return Ok(None);
        };
        for record in apex.records.view()?.records().iter() {
            let record = record?;
            if record.record_type == RecordType::NICK {
                return Ok(Some(record));
            }
        }
        Ok(None)
    }
}

pub(super) fn validate_recovered(label: &[u8], records: Records<'_>) -> Result<(), Error> {
    validate_authoritative_iter(label, records.records().iter(), |_| true)
}

pub(super) fn public_expiry(
    label: &[u8],
    records: Records<'_>,
    now: u64,
    indices: &mut [usize],
) -> Result<u64, Error> {
    // Only the existing publication lifetime is needed. Sort offsets into
    // the trusted stored body rather than materializing normalized records.
    let bytes = records.records().record_bytes();
    let mut tail = bytes;
    let mut used = 0;
    let mut floor = 0;
    while !tail.is_empty() {
        let offset = bytes.len() - tail.len();
        let (record, remaining) = RecordData::decode_prefix(tail)?;
        tail = remaining;
        if !visible(record, now) {
            continue;
        }
        floor = tombstone_floor(record, now, floor);
        if contributes_public_expiry(label, record) {
            *indices.get_mut(used).ok_or(Error::Capacity)? = offset;
            used += 1;
        }
    }
    Ok(expiration_at_offsets(bytes, &mut indices[..used], now)?.max(floor))
}

pub(super) fn expiration_at_offsets(
    bytes: &[u8],
    offsets: &mut [usize],
    now: u64,
) -> Result<u64, Error> {
    if offsets.is_empty() {
        return Ok(0);
    }
    offsets.sort_unstable_by(|&left, &right| {
        record_type_key(bytes, left).cmp(record_type_key(bytes, right))
    });
    let mut smallest = u64::MAX;
    let mut current = None;
    let mut greatest = 0;
    for &offset in offsets.iter() {
        let (record, _) = RecordData::decode_prefix(&bytes[offset..])?;
        if let Some(kind) = current
            && kind != record.record_type
        {
            smallest = smallest.min(greatest);
            greatest = 0;
        }
        current = Some(record.record_type);
        greatest = greatest.max(absolute_expiry(record, now));
    }
    Ok(smallest.min(greatest))
}

fn record_type_key(bytes: &[u8], offset: usize) -> &[u8] {
    let header_end = offset + RECORD_HEADER_LEN;
    // The original network-order 32-bit record type terminates the header.
    &bytes[header_end - size_of::<u32>()..header_end]
}

#[expect(
    clippy::too_many_arguments,
    reason = "bind original row, view, time, nickname and disjoint scratch"
)]
fn render_records<'a, const D: usize>(
    label: &[u8],
    records: Records<'a>,
    view: RecordView,
    now: u64,
    critical: fn(RecordType) -> bool,
    nickname: Option<RecordData<'a>>,
    output: &mut Body<D>,
    indices: &mut [usize],
) -> Result<u64, Error> {
    let records = records.records();
    validate_authoritative_iter(label, records.iter(), |record| visible(*record, now))?;
    let mut writer = output.writer();
    let mut critical = critical;
    let mut floor = 0;
    let mut latest = None;
    let mut used = 0;
    for record in records.iter() {
        let record = record?;
        floor = tombstone_floor(record, now, floor);
        if let Some(selected) = view.select(label, record, now, &mut critical) {
            let offset = writer.push(selected)?;
            if view.contributes_expiry(label, selected) {
                *indices.get_mut(used).ok_or(Error::Capacity)? = offset;
                used += 1;
            }
            latest = Some(latest.unwrap_or(0).max(absolute_expiry(selected, now)));
        }
    }
    let expires = expiration_at_offsets(writer.records(), &mut indices[..used], now)?.max(floor);
    if let Some(nick) = supplemental_nickname_for_expiry(label, nickname, now, latest) {
        writer.push(nick)?;
    }
    writer.finish()?;
    Ok(expires)
}
