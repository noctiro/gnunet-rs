//! Dependency planning for one private NAMESTORE zone.

use super::{IDENTIFIER_LABEL_BYTES, identifier_label, records::StoredRecord};
use crate::{Attribute, Identifier, ipc::Request};
use gnunet_gnsrecord::{RecordData, RecordType};
use gnunet_types::Error;
use gnunet_wire::official::identity::SecretKeyView;
use zeroize::Zeroizing;

/// Original attribute or credential DELETE. Both request types remove the
/// complete canonical NAMESTORE label, regardless of colocated record types.
#[derive(Clone, Copy, Debug)]
pub struct Delete<'a> {
    rid: u32,
    key: SecretKeyView<'a>,
    id: Identifier,
}

impl<'a> Delete<'a> {
    /// Borrow the original authority and select the identifier from either
    /// official DELETE opcode. No payload is retained.
    #[must_use]
    pub const fn from_request(request: Request<'a>) -> Option<Self> {
        match request {
            Request::DeleteAttribute {
                rid,
                key,
                attribute,
            } => Some(Self {
                rid,
                key,
                id: attribute.id,
            }),
            Request::DeleteCredential {
                rid,
                key,
                credential,
            } => Some(Self {
                rid,
                key,
                id: credential.id,
            }),
            _ => None,
        }
    }

    /// Original opaque request ID.
    #[must_use]
    pub const fn rid(&self) -> u32 {
        self.rid
    }

    /// Original private authority for all reads and the entire mutation.
    #[must_use]
    pub const fn key(&self) -> SecretKeyView<'a> {
        self.key
    }

    /// Write the canonical target label. A zero identifier is invalid for DELETE.
    pub fn label(&self, out: &mut [u8]) -> Result<usize, Error> {
        if self.id.is_zero() {
            return Err(Error::InvalidInput);
        }
        identifier_label(self.id, out)
    }

    /// Begin an allocation-free scan of at most `R` original rows. The fixed
    /// dependency representation supports capacities from 1 through 64.
    pub fn scan<const R: usize>(self) -> Result<DeleteScan<R>, Error> {
        if !(1..=u64::BITS as usize).contains(&R) {
            return Err(Error::Capacity);
        }
        let mut label = Zeroizing::new([0; IDENTIFIER_LABEL_BYTES]);
        self.label(label.as_mut())?;
        Ok(DeleteScan {
            label,
            zone: Zone::empty(),
            target: None,
        })
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Attribute = 1,
    Credential = 2,
}

struct Group {
    id: Zeroizing<[u8; 32]>,
    kinds: u8,
}

impl Group {
    fn observe(&mut self, id: Identifier, kind: Kind) -> Result<(), Error> {
        if self.kinds == 0 {
            self.id.copy_from_slice(id.bytes());
        } else if self.id.as_ref() != id.bytes() {
            return Err(Error::Malformed);
        }
        self.kinds |= kind as u8;
        Ok(())
    }

    fn matches(&self, id: Identifier, kind: Kind) -> bool {
        self.kinds & kind as u8 != 0 && self.id.as_ref() == id.bytes()
    }
}

struct Row {
    serial: u64,
    group: Group,
}

impl Row {
    fn empty() -> Self {
        Self {
            serial: 0,
            group: Group {
                id: Zeroizing::new([0; 32]),
                kinds: 0,
            },
        }
    }
}

struct Zone<const R: usize> {
    rows: [Row; R],
    len: usize,
}

impl<const R: usize> Zone<R> {
    fn empty() -> Self {
        Self {
            rows: core::array::from_fn(|_| Row::empty()),
            len: 0,
        }
    }

    fn rows(&self) -> &[Row] {
        &self.rows[..self.len]
    }

    fn find(&self, id: Identifier, kind: Kind) -> Option<usize> {
        self.rows()
            .iter()
            .position(|row| row.group.matches(id, kind))
    }
}

/// First scan of one exact private zone. Only row serials and object identities
/// are retained; the caller owns and pins the original rows until commit.
pub struct DeleteScan<const R: usize> {
    label: Zeroizing<[u8; IDENTIFIER_LABEL_BYTES]>,
    zone: Zone<R>,
    target: Option<(usize, RowPresence)>,
}

/// Whether an original label has anything other than retained tombstones.
/// Expired primary data is absent from the active view but still deletable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RowPresence {
    /// The original contains at least one non-tombstone record.
    Records,
    /// The original contains no non-tombstone records.
    TombstonesOnly,
}

impl<const R: usize> DeleteScan<R> {
    /// Inspect a current authority row in increasing serial order. Pass the
    /// authoritative active private/public projection of every original row,
    /// including rows with an empty active projection. Determine presence
    /// independently from the original, before projecting the active records.
    pub fn visit<'a>(
        &mut self,
        serial: u64,
        label: &[u8],
        presence: RowPresence,
        records: impl IntoIterator<Item = Result<RecordData<'a>, Error>>,
    ) -> Result<(), Error> {
        let index = self.zone.len;
        if serial == 0
            || self
                .zone
                .rows()
                .last()
                .is_some_and(|row| row.serial >= serial)
        {
            return Err(Error::Stale);
        }
        if index == R {
            return Err(Error::Capacity);
        }
        let is_target = self.label.as_ref() == label;
        if is_target && self.target.is_some() {
            return Err(Error::Conflict);
        }
        let mut row = Row::empty();
        row.serial = serial;
        for record in records {
            let record = StoredRecord::decode(record?)?;
            record.check_label(label)?;
            match record {
                StoredRecord::Attribute(attribute) => {
                    row.group.observe(attribute.id, Kind::Attribute)?
                }
                StoredRecord::Credential(credential) => {
                    row.group.observe(credential.id, Kind::Credential)?
                }
                _ => (),
            }
        }
        if is_target {
            self.target = Some((index, presence));
        }
        self.zone.rows[index] = row;
        self.zone.len += 1;
        Ok(())
    }

    /// Start dependency collection only after finding the target label.
    /// A nonexistent target is a rejection and cannot repair unrelated rows.
    pub fn dependencies(self) -> Result<DeleteDependencies<R>, Error> {
        let Some((target, RowPresence::Records)) = self.target else {
            return Err(Error::NotFound);
        };
        Ok(DeleteDependencies {
            zone: self.zone,
            edges: [0; R],
            removed: bit(target),
            visited: 0,
        })
    }
}

/// Second scan maps credential dependencies to snapshot-local row positions.
/// A mixed row may have any number of attributes, but at most one edge to
/// each other row. The planner retains no attribute or credential payloads.
pub struct DeleteDependencies<const R: usize> {
    zone: Zone<R>,
    edges: [u64; R],
    removed: u64,
    visited: usize,
}

impl<const R: usize> DeleteDependencies<R> {
    /// Supply the same active rows in the same order as the first scan. A
    /// missing, different, duplicated or reordered serial cannot finish.
    pub fn visit<'a>(
        &mut self,
        serial: u64,
        records: impl IntoIterator<Item = Result<RecordData<'a>, Error>>,
    ) -> Result<(), Error> {
        let row = self.visited;
        if self
            .zone
            .rows()
            .get(row)
            .is_none_or(|item| item.serial != serial)
        {
            return Err(Error::Stale);
        }
        let mut edges = 0;
        let mut orphan = false;
        for record in records {
            let record = record?;
            if record.record_type != RecordType::RECLAIM_ATTRIBUTE {
                continue;
            }
            let credential = Attribute::decode(record.data)?.credential;
            if !credential.is_zero() {
                if let Some(index) = self.zone.find(credential, Kind::Credential) {
                    edges |= bit(index);
                } else {
                    orphan = true;
                }
            }
        }
        self.edges[row] = edges;
        if orphan {
            self.removed |= bit(row);
        }
        self.visited += 1;
        Ok(())
    }

    /// Close transitive credential dependencies before any write can run.
    /// A cycle is retained unless its own row or one of its dependencies is
    /// removed. An incomplete scan cannot produce a plan.
    pub fn finish(mut self) -> Result<DeletePlan<R>, Error> {
        if self.visited != self.zone.len {
            return Err(Error::NotReady);
        }
        loop {
            let before = self.removed;
            for (index, dependencies) in self.edges[..self.visited].iter().enumerate() {
                if dependencies & self.removed != 0 {
                    self.removed |= bit(index);
                }
            }
            if before == self.removed {
                return Ok(DeletePlan {
                    zone: self.zone,
                    removed: self.removed,
                });
            }
        }
    }
}

/// Final deletion decisions for one original zone snapshot. Apply whole-label
/// removals first in the decision process, then filter the remaining rows. The
/// owner publishes all resulting changes together; a plan is not a receipt.
pub struct DeletePlan<const R: usize> {
    zone: Zone<R>,
    removed: u64,
}

impl<const R: usize> DeletePlan<R> {
    /// Whether this exact original row must be removed in full. An unknown
    /// serial is stale and cannot be used as a change target.
    pub fn removes_row(&self, serial: u64) -> Result<bool, Error> {
        let index = self
            .zone
            .rows()
            .binary_search_by_key(&serial, |row| row.serial)
            .map_err(|_| Error::Stale)?;
        Ok(self.removed & bit(index) != 0)
    }

    /// For a surviving original row, retain exactly those references whose
    /// live object survives. Preserve all other records verbatim in original
    /// order, including ticket authority, flags, expirations and extensions.
    pub fn retains_record(&self, record: RecordData<'_>) -> Result<bool, Error> {
        if !matches!(
            record.record_type,
            RecordType::RECLAIM_ATTRIBUTE_REF | RecordType::RECLAIM_PRESENTATION
        ) {
            return Ok(true);
        }
        let (id, kind) = match StoredRecord::decode(record)? {
            StoredRecord::AttributeReference(id) => (id, Kind::Attribute),
            StoredRecord::Presentation(presentation) => (presentation.credential, Kind::Credential),
            _ => return Err(Error::Conflict),
        };
        Ok(self
            .zone
            .find(id, kind)
            .is_some_and(|index| self.removed & bit(index) == 0))
    }
}

const fn bit(index: usize) -> u64 {
    1 << index
}
