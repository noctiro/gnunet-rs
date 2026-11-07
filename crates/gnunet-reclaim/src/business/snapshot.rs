//! Mutation-only metadata over the one original NAMESTORE snapshot.
use super::{
    engine::{OwnedId, consume_work},
    memory::{Quota, Table},
    records::Row,
};
use crate::{Attribute, Credential, Identifier};
use alloc::rc::Rc;
use core::cell::Cell;
use gnunet_gnsrecord::RecordType;
use gnunet_types::Error;

pub(super) const ATTRIBUTE: u8 = 1;
pub(super) const CREDENTIAL: u8 = 2;
pub(super) struct Object {
    id: OwnedId,
    pub row: usize,
    pub kinds: u8,
    pub dependents: Option<usize>,
    pub removed: bool,
    pub rotation: Option<usize>,
}
impl Object {
    pub fn id(&self) -> Identifier {
        self.id.value()
    }
}
#[derive(Clone, Copy)]
pub(super) struct Edge {
    pub row: usize,
    pub next: Option<usize>,
}
pub(super) struct RowIndex {
    pub object: Option<usize>,
    pub orphan: bool,
}
pub(super) struct Snapshot {
    pub objects: Table<Option<Object>>,
    pub rows: Table<RowIndex>,
    pub edges: Table<Edge>,
    pub missing_removed: Option<OwnedId>,
}
impl Snapshot {
    pub fn build(quota: &Rc<Quota>, rows: &[Row], work: &Cell<usize>) -> Result<Self, Error> {
        let slots = rows
            .len()
            .checked_mul(2)
            .and_then(|n| n.checked_add(1))
            .ok_or(Error::Overflow)?;
        let mut records = 0usize;
        for row in rows {
            consume_work(work, 1)?;
            records = records
                .checked_add(usize::from(row.count))
                .ok_or(Error::Overflow)?;
        }
        let mut snapshot = Self {
            objects: Table::new(quota, slots)?,
            rows: Table::new(quota, rows.len())?,
            edges: Table::new(quota, records)?,
            missing_removed: None,
        };
        for _ in 0..slots {
            consume_work(work, 1)?;
            snapshot.objects.push(None)?;
        }
        for (index, row) in rows.iter().enumerate() {
            consume_work(work, usize::from(row.count))?;
            let mut object = None;
            let mut kinds = 0;
            for record in row.view()?.records().iter() {
                consume_work(work, 1)?;
                let record = record?;
                let parsed = match record.record_type {
                    RecordType::RECLAIM_ATTRIBUTE => {
                        Some((Attribute::decode(record.data)?.id, ATTRIBUTE))
                    }
                    RecordType::RECLAIM_CREDENTIAL => {
                        Some((Credential::decode(record.data)?.id, CREDENTIAL))
                    }
                    _ => None,
                };
                if let Some((id, kind)) = parsed {
                    if object.is_some_and(|previous| previous != id) {
                        return Err(Error::Malformed);
                    }
                    object = Some(id);
                    kinds |= kind;
                }
            }
            let slot = if let Some(id) = object {
                let slot = snapshot.locate(id, work)?;
                if snapshot.objects[slot].is_some() {
                    return Err(Error::Conflict);
                }
                snapshot.objects[slot] = Some(Object {
                    id: OwnedId::new(id),
                    row: index,
                    kinds,
                    dependents: None,
                    removed: false,
                    rotation: None,
                });
                Some(slot)
            } else {
                None
            };
            snapshot.rows.push(RowIndex {
                object: slot,
                orphan: false,
            })?;
        }
        // A second linear decode avoids retaining a second copy of credential
        // IDs per attribute. Reverse edges contain only stable row/edge indices.
        // Prepending in reverse row order preserves original row traversal when
        // a credential's dependent groups are later queued for removal.
        for (index, row) in rows.iter().enumerate().rev() {
            consume_work(work, usize::from(row.count))?;
            for record in row.view()?.records().iter() {
                consume_work(work, 1)?;
                let record = record?;
                if record.record_type != RecordType::RECLAIM_ATTRIBUTE {
                    continue;
                }
                let credential = Attribute::decode(record.data)?.credential;
                if credential.is_zero() {
                    continue;
                }
                let target = snapshot.find(credential, work)?;
                if let Some(slot) = target.filter(|slot| {
                    snapshot.objects[*slot]
                        .as_ref()
                        .is_some_and(|object| object.kinds & CREDENTIAL != 0)
                }) {
                    let object = snapshot.objects[slot].as_mut().ok_or(Error::Stale)?;
                    let edge = snapshot.edges.len();
                    snapshot.edges.push(Edge {
                        row: index,
                        next: object.dependents,
                    })?;
                    object.dependents = Some(edge);
                } else {
                    snapshot.rows[index].orphan = true;
                }
            }
        }
        Ok(snapshot)
    }
    fn locate(&self, id: Identifier, work: &Cell<usize>) -> Result<usize, Error> {
        // This is an internal table coordinate, never an authentication hash.
        // Every bounded collision probe is charged, including adversarial IDs.
        let mut hash = 0xcbf2_9ce4_8422_2325u64;
        for byte in id.bytes() {
            hash = (hash ^ u64::from(*byte)).wrapping_mul(0x100_0000_01b3);
        }
        consume_work(work, 1)?;
        let mut slot = (hash % self.objects.len() as u64) as usize;
        for _ in 0..self.objects.len() {
            consume_work(work, 1)?;
            match &self.objects[slot] {
                None => return Ok(slot),
                Some(object) if object.id.value() == id => return Ok(slot),
                Some(_) => {}
            }
            slot = if slot + 1 == self.objects.len() {
                0
            } else {
                slot + 1
            };
        }
        Err(Error::Capacity)
    }
    pub fn find(&self, id: Identifier, work: &Cell<usize>) -> Result<Option<usize>, Error> {
        let slot = self.locate(id, work)?;
        Ok(self.objects[slot].as_ref().map(|_| slot))
    }
    pub fn object(&self, slot: usize) -> Result<&Object, Error> {
        self.objects
            .get(slot)
            .and_then(Option::as_ref)
            .ok_or(Error::Stale)
    }
    pub fn object_mut(&mut self, slot: usize) -> Result<&mut Object, Error> {
        self.objects
            .get_mut(slot)
            .and_then(Option::as_mut)
            .ok_or(Error::Stale)
    }
}
