//! Original ticket authority, bounded object rotations and dependent rewrites.

use super::{IDENTIFIER_LABEL_BYTES, identifier_label, records::StoredRecord};
use crate::{Attribute, Credential, Identifier, Presentation, Ticket, ipc::Request};
use core::num::NonZeroUsize;
use gnunet_gnsrecord::{RECORD_HEADER_LEN, RecordData, RecordFlags, RecordType, ZoneKey};
use gnunet_types::Error;
use gnunet_wire::official::{identity::SecretKeyView, namestore::Records};
use zeroize::Zeroizing;

/// Original ticket revoke request; its capability and private key stay borrowed.
#[derive(Clone, Copy)]
pub struct Revoke<'a> {
    rid: u32,
    key: SecretKeyView<'a>,
    ticket: Ticket<'a>,
}

impl<'a> Revoke<'a> {
    /// Select the original private authority and ticket.
    #[must_use]
    pub const fn from_request(request: Request<'a>) -> Option<Self> {
        match request {
            Request::RevokeTicket { rid, key, ticket } => Some(Self { rid, key, ticket }),
            _ => None,
        }
    }

    /// Original opaque request ID.
    #[must_use]
    pub const fn rid(self) -> u32 {
        self.rid
    }

    /// Original private zone whose public key the caller must derive.
    #[must_use]
    pub const fn key(self) -> SecretKeyView<'a> {
        self.key
    }

    /// Require the capability to name the original request's derived issuer.
    pub fn bind(self, issuer: ZoneKey) -> Result<BoundRevoke<'a>, Error> {
        let (label, owner) = self.ticket.capability()?;
        if owner != issuer {
            return Err(Error::Authentication);
        }
        Ok(BoundRevoke { label, issuer })
    }
}

/// A ticket scoped to its derived original issuer.
pub struct BoundRevoke<'a> {
    label: &'a [u8],
    issuer: ZoneKey,
}

impl<'a> BoundRevoke<'a> {
    /// Exact original label in the issuer's private authority.
    #[must_use]
    pub const fn label(&self) -> &'a [u8] {
        self.label
    }

    /// Authenticate the active original row before making any change. Pass the
    /// same active target records when checking its selected attribute IDs.
    pub fn scan<'row, const R: usize>(
        &self,
        serial: u64,
        label: &[u8],
        records: impl IntoIterator<Item = Result<RecordData<'row>, Error>>,
    ) -> Result<RevocationScan<R>, Error> {
        if !(1..=u64::BITS as usize).contains(&R) {
            return Err(Error::Capacity);
        }
        if serial == 0 || label != self.label {
            return Err(Error::Authentication);
        }
        let mut descriptor = false;
        for record in records {
            let record = record?;
            match record.record_type {
                RecordType::RECLAIM_TICKET => {
                    if descriptor
                        || !record.flags.contains(RecordFlags::PRIVATE)
                        || Ticket::decode(record.data)?.capability()? != (self.label, self.issuer)
                    {
                        return Err(Error::Authentication);
                    }
                    descriptor = true;
                }
                RecordType::RECLAIM_ATTRIBUTE_REF => {
                    if Identifier::decode(record.data)?.is_zero() {
                        return Err(Error::Malformed);
                    }
                }
                _ => {}
            }
        }
        if !descriptor {
            return Err(Error::NotFound);
        }
        Ok(RevocationScan {
            target: serial,
            rows: core::array::from_fn(|_| Group::empty()),
            len: 0,
            visited: 0,
        })
    }

    /// Check whether the already authenticated target references this object ID.
    pub fn references<'row>(
        &self,
        id: Identifier,
        records: impl IntoIterator<Item = Result<RecordData<'row>, Error>>,
    ) -> Result<bool, Error> {
        for record in records {
            let record = record?;
            if record.record_type == RecordType::RECLAIM_ATTRIBUTE_REF
                && Identifier::decode(record.data)? == id
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

const ATTRIBUTE: u8 = 1;
const CREDENTIAL: u8 = 2;
const ANY_OBJECT: u8 = ATTRIBUTE | CREDENTIAL;

struct Group {
    serial: u64,
    id: Zeroizing<[u8; 32]>,
    fresh: Zeroizing<[u8; 32]>,
    kinds: u8,
    selected: bool,
    dependencies: u64,
}

impl Group {
    fn empty() -> Self {
        Self {
            serial: 0,
            id: Zeroizing::new([0; 32]),
            fresh: Zeroizing::new([0; 32]),
            kinds: 0,
            selected: false,
            dependencies: 0,
        }
    }

    fn record(&mut self, id: Identifier, kind: u8) -> Result<(), Error> {
        if self.kinds != 0 && self.id.as_ref() != id.bytes() {
            return Err(Error::Malformed);
        }
        self.id.copy_from_slice(id.bytes());
        self.kinds |= kind;
        Ok(())
    }

    fn rotated(&self) -> Option<Identifier> {
        self.selected.then(|| Identifier::new(*self.fresh))
    }
}

/// Two bounded passes over a single immutable private zone: discover live
/// object labels and then their dependencies. No record payloads are retained.
pub struct RevocationScan<const R: usize> {
    target: u64,
    rows: [Group; R],
    len: usize,
    visited: usize,
}

impl<const R: usize> RevocationScan<R> {
    /// Visit every original row by serial, passing only its active records.
    /// The selector queries the same authenticated target's attribute refs.
    pub fn visit<'row>(
        &mut self,
        serial: u64,
        label: &[u8],
        records: impl IntoIterator<Item = Result<RecordData<'row>, Error>>,
        selected: impl FnOnce(Identifier) -> Result<bool, Error>,
    ) -> Result<(), Error> {
        if self.visited != 0
            || serial == 0
            || self.rows[..self.len]
                .last()
                .is_some_and(|row| row.serial >= serial)
        {
            return Err(Error::Stale);
        }
        let slot = self.rows.get_mut(self.len).ok_or(Error::Capacity)?;
        let mut row = Group::empty();
        for record in records {
            let parsed = StoredRecord::decode(record?)?;
            parsed.check_label(label)?;
            match parsed {
                StoredRecord::Attribute(attribute) => row.record(attribute.id, ATTRIBUTE)?,
                StoredRecord::Credential(credential) => row.record(credential.id, CREDENTIAL)?,
                _ => {}
            }
        }
        row.serial = serial;
        row.selected =
            serial != self.target && row.kinds != 0 && selected(Identifier::new(*row.id))?;
        *slot = row;
        self.len += 1;
        Ok(())
    }

    /// Second pass, with exactly the same original rows and serial order.
    pub fn dependencies<'row>(
        &mut self,
        serial: u64,
        records: impl IntoIterator<Item = Result<RecordData<'row>, Error>>,
    ) -> Result<(), Error> {
        let index = self.visited;
        let rows = &mut self.rows[..self.len];
        if rows.get(index).is_none_or(|row| row.serial != serial) {
            return Err(Error::Stale);
        }
        if rows[index].kinds & ATTRIBUTE != 0 {
            let mut dependencies = 0;
            for record in records {
                let record = record?;
                if record.record_type == RecordType::RECLAIM_ATTRIBUTE {
                    let credential = Attribute::decode(record.data)?.credential;
                    if let Some(target) = find(rows, credential, CREDENTIAL) {
                        dependencies |= bit(target);
                    }
                }
            }
            rows[index].dependencies = dependencies;
        }
        self.visited += 1;
        Ok(())
    }

    /// Assign collision-free fresh IDs to surviving selected objects. The
    /// original physical inventory must remain pinned through the final commit.
    pub fn finish(
        mut self,
        attempts: NonZeroUsize,
        mut generate: impl FnMut() -> Result<Identifier, Error>,
        mut unused_label: impl FnMut(&[u8]) -> Result<bool, Error>,
    ) -> Result<Revocation<R>, Error> {
        if self.visited != self.len {
            return Err(Error::NotReady);
        }
        let rows = &mut self.rows[..self.len];
        let target = rows
            .binary_search_by_key(&self.target, |row| row.serial)
            .map_err(|_| Error::NotFound)?;
        let mut removed = bit(target);
        loop {
            let before = removed;
            for (index, row) in rows.iter().enumerate() {
                if row.dependencies & removed != 0 {
                    removed |= bit(index);
                }
            }
            if before == removed {
                break;
            }
        }
        let mut label = Zeroizing::new([0; IDENTIFIER_LABEL_BYTES]);
        for index in 0..rows.len() {
            if !rows[index].selected || removed & bit(index) != 0 {
                rows[index].selected = false;
                continue;
            }
            let mut generated = None;
            for _ in 0..attempts.get() {
                let candidate = generate()?;
                if candidate.is_zero()
                    || rows[..index]
                        .iter()
                        .any(|row| row.rotated() == Some(candidate))
                {
                    continue;
                }
                identifier_label(candidate, label.as_mut())?;
                if unused_label(label.as_ref())? {
                    generated = Some(candidate);
                    break;
                }
            }
            let generated = generated.ok_or(Error::Entropy)?;
            rows[index].fresh.copy_from_slice(generated.bytes());
        }
        Ok(Revocation {
            rows: self.rows,
            len: self.len,
            removed,
        })
    }
}

fn bit(index: usize) -> u64 {
    1 << index
}

fn find(rows: &[Group], id: Identifier, kinds: u8) -> Option<usize> {
    rows.iter()
        .position(|row| row.kinds & kinds != 0 && row.id.as_ref() == id.bytes())
}

/// Complete proposed revocation of a single immutable private zone snapshot.
pub struct Revocation<const R: usize> {
    rows: [Group; R],
    len: usize,
    removed: u64,
}

/// Exact proposed action on one original NAMESTORE row.
pub enum RevokeChange<'a> {
    /// This row is unrelated and remains unchanged.
    Keep,
    /// Discard this row's original application records.
    Delete,
    /// Retain this label and replace its records with the final representation.
    Replace(Records<'a>),
    /// Retire the old label and atomically place the final records at a fresh one.
    Move {
        /// New object identifier and therefore its canonical label.
        to: Identifier,
        /// Complete destination records, excluding old-label tombstones.
        records: Records<'a>,
    },
}

impl<const R: usize> Revocation<R> {
    /// Rewrite one exact original row. The supplied predicate identifies active
    /// records at the pinned observation time; unrelated and expired bytes are
    /// preserved. Scratch is owned and erased by the caller.
    pub fn rewrite<'out>(
        &self,
        serial: u64,
        records: Records<'_>,
        mut active: impl FnMut(RecordData<'_>) -> bool,
        output: &'out mut [u8],
    ) -> Result<RevokeChange<'out>, Error> {
        let rows = &self.rows[..self.len];
        let index = rows
            .binary_search_by_key(&serial, |row| row.serial)
            .map_err(|_| Error::Stale)?;
        if self.removed & bit(index) != 0 {
            return Ok(RevokeChange::Delete);
        }
        let moved = rows[index].rotated();
        let original = records.records().record_bytes();
        let mut tail = original;
        let mut written = moved.map(|_| 0usize);
        let mut count = records.count();
        while !tail.is_empty() {
            let (record, rest) = RecordData::decode_prefix(tail)?;
            let patch = if moved.is_some() && record.record_type == RecordType::TOMBSTONE {
                Patch::Delete
            } else if active(record) {
                self.patch(record, moved)?
            } else {
                Patch::Keep
            };
            if written.is_none() && !matches!(patch, Patch::Keep) {
                let offset = original.len() - tail.len();
                output
                    .get_mut(..offset)
                    .ok_or(Error::Capacity)?
                    .copy_from_slice(&original[..offset]);
                written = Some(offset);
            }
            if let Some(position) = &mut written {
                if matches!(patch, Patch::Delete) {
                    count = count.checked_sub(1).ok_or(Error::Malformed)?;
                } else {
                    *position += patch
                        .encode(record, output.get_mut(*position..).ok_or(Error::Capacity)?)?;
                }
            }
            tail = rest;
        }
        let Some(len) = written else {
            return Ok(RevokeChange::Keep);
        };
        let new = Records::new(&output[..len], count)?;
        Ok(match moved {
            Some(to) => RevokeChange::Move { to, records: new },
            None => RevokeChange::Replace(new),
        })
    }

    fn object(&self, id: Identifier, kinds: u8) -> Option<(bool, Option<Identifier>)> {
        let rows = &self.rows[..self.len];
        let index = find(rows, id, kinds)?;
        Some((self.removed & bit(index) != 0, rows[index].rotated()))
    }

    fn patch<'row>(
        &self,
        record: RecordData<'row>,
        moved: Option<Identifier>,
    ) -> Result<Patch<'row>, Error> {
        Ok(match record.record_type {
            RecordType::RECLAIM_ATTRIBUTE => {
                let mut attribute = Attribute::decode(record.data)?;
                let credential = self
                    .object(attribute.credential, CREDENTIAL)
                    .and_then(|(_, next)| next);
                if moved.is_some() || credential.is_some() {
                    attribute.id = moved.unwrap_or(attribute.id);
                    attribute.credential = credential.unwrap_or(attribute.credential);
                    Patch::Attribute(attribute)
                } else {
                    Patch::Keep
                }
            }
            RecordType::RECLAIM_CREDENTIAL if moved.is_some() => {
                let mut credential = Credential::decode(record.data)?;
                credential.id = moved.ok_or(Error::Conflict)?;
                Patch::Credential(credential)
            }
            RecordType::RECLAIM_ATTRIBUTE_REF => {
                let original = Identifier::decode(record.data)?;
                match self.object(original, ANY_OBJECT) {
                    Some((true, _)) => Patch::Delete,
                    Some((false, Some(id))) => Patch::Reference(id),
                    _ => Patch::Keep,
                }
            }
            RecordType::RECLAIM_PRESENTATION => {
                let mut presentation = Presentation::decode(record.data)?;
                match self.object(presentation.credential, CREDENTIAL) {
                    Some((true, _)) => Patch::Delete,
                    Some((false, Some(id))) => {
                        presentation.credential = id;
                        Patch::Presentation(presentation)
                    }
                    _ => Patch::Keep,
                }
            }
            _ => Patch::Keep,
        })
    }
}

enum Patch<'a> {
    Keep,
    Delete,
    Reference(Identifier),
    Attribute(Attribute<'a>),
    Credential(Credential<'a>),
    Presentation(Presentation<'a>),
}

impl Patch<'_> {
    fn encode(self, record: RecordData<'_>, output: &mut [u8]) -> Result<usize, Error> {
        if matches!(self, Self::Keep) {
            return record.encode(output);
        }
        let (header, value) = output
            .split_at_mut_checked(RECORD_HEADER_LEN)
            .ok_or(Error::Capacity)?;
        let written = match self {
            Self::Reference(id) => id.encode(value)?,
            Self::Attribute(attribute) => attribute.encode(value)?,
            Self::Credential(credential) => credential.encode(value)?,
            Self::Presentation(presentation) => presentation.encode(value)?,
            Self::Keep | Self::Delete => return Err(Error::Conflict),
        };
        RecordData {
            data: &value[..written],
            ..record
        }
        .encode_header(header)?;
        Ok(RECORD_HEADER_LEN + written)
    }
}
