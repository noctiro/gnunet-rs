use super::{
    Blob,
    memory::{Quota, Table},
};
use crate::{Attribute, Credential, Identifier, Presentation, Ticket};
use alloc::rc::Rc;
use gnunet_gnsrecord::{RecordData, RecordFlags, RecordType, ZoneKey};
use gnunet_types::Error;
use gnunet_wire::official::namestore::Records;
/// Exact Crockford text length for a256bit official RECLAIM identifier.
pub const IDENTIFIER_LABEL_BYTES: usize = 52;
/// Encode the actual GNUnet data-to-string label, without NUL or private prefix.
pub fn identifier_label(id: Identifier, out: &mut [u8]) -> Result<usize, Error> {
    let out = out
        .get_mut(..IDENTIFIER_LABEL_BYTES)
        .ok_or(Error::Capacity)?;
    const A: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let (mut bits, mut used, mut at) = (0u16, 0u32, 0usize);
    for byte in id.bytes() {
        bits = ((bits & ((1 << used) - 1)) << 8) | u16::from(*byte);
        used += 8;
        while used >= 5 {
            used -= 5;
            out[at] = A[usize::from((bits >> used) & 31)];
            at += 1;
        }
    }
    if used > 0 {
        out[at] = A[usize::from((bits << (5 - used)) & 31)];
        at += 1;
    }
    Ok(at)
}
/// Parse a current mutable GNS-name capability and its typed issuer.
/// This validates format only; lookup authenticity belongs to the GNS provider.
pub fn capability<'a>(ticket: Ticket<'a>) -> Result<(&'a [u8], ZoneKey), Error> {
    ticket.capability()
}
pub(super) fn new_ticket(quota: &Rc<Quota>, id: Identifier, zone: ZoneKey) -> Result<Blob, Error> {
    let mut label = [0; IDENTIFIER_LABEL_BYTES];
    identifier_label(id, &mut label)?;
    let mut ztld = [0; gnunet_gnsrecord::ZONE_TEXT_LEN];
    let zone = zone.write_ztld(&mut ztld)?;
    let len = label.len() + 1 + zone.len();
    Blob::encode(quota, len + 1, |out| {
        out[..label.len()].copy_from_slice(&label);
        out[label.len()] = b'.';
        out[label.len() + 1..len].copy_from_slice(zone.as_bytes());
        out[len] = 0;
        Ticket::decode(out)?;
        Ok(out.len())
    })
}
pub(super) struct Row {
    pub label: Blob,
    pub data: Blob,
    pub count: u16,
}
impl Row {
    pub fn copy(quota: &Rc<Quota>, label: &[u8], records: Records<'_>) -> Result<Self, Error> {
        if label.len() > 255
            || label.contains(&0)
            || usize::from(records.count()) > quota.limits.records
        {
            return Err(Error::TooLarge);
        }
        for record in records.records().iter() {
            let r = record?;
            let object = match r.record_type {
                RecordType::RECLAIM_ATTRIBUTE => Some(Attribute::decode(r.data)?.id),
                RecordType::RECLAIM_CREDENTIAL => Some(Credential::decode(r.data)?.id),
                RecordType::RECLAIM_PRESENTATION => {
                    Presentation::decode(r.data)?;
                    None
                }
                RecordType::RECLAIM_ATTRIBUTE_REF => {
                    Identifier::decode(r.data)?;
                    None
                }
                RecordType::RECLAIM_TICKET => {
                    Ticket::decode(r.data)?;
                    None
                }
                _ => None,
            };
            if let Some(id) = object {
                // A mixed/duplicate object set is legal when every object is
                // bound to this same canonical identifier label. No second
                // record is silently discarded or given a different owner.
                let mut expected = [0; IDENTIFIER_LABEL_BYTES];
                identifier_label(id, &mut expected)?;
                if id.is_zero() || label != expected {
                    return Err(Error::Malformed);
                }
            }
        }
        Ok(Self {
            label: Blob::copy(quota, label)?,
            data: Blob::copy(quota, records.bytes())?,
            count: records.count(),
        })
    }
    pub fn build(
        quota: &Rc<Quota>,
        label: &[u8],
        records: &[RecordData<'_>],
    ) -> Result<Self, Error> {
        if records.len() > quota.limits.records {
            return Err(Error::Capacity);
        }
        let n = gnunet_gnsrecord::serialized_len(records)?;
        let frame = gnunet_wire::official::namestore::STORE_PREFIX
            .checked_add(gnunet_wire::official::identity::KEY_LEN)
            .and_then(|n| n.checked_add(gnunet_wire::official::namestore::SET_PREFIX))
            .and_then(|n| n.checked_add(label.len() + 1))
            .and_then(|x| x.checked_add(n))
            .ok_or(Error::Overflow)?;
        if frame > quota.limits.frame_bytes {
            return Err(Error::TooLarge);
        }
        let data = Blob::encode(quota, n, |out| gnunet_gnsrecord::serialize(records, out))?;
        Ok(Self {
            label: Blob::copy(quota, label)?,
            data,
            count: u16::try_from(records.len()).map_err(|_| Error::TooLarge)?,
        })
    }
    pub fn view(&self) -> Result<Records<'_>, Error> {
        Records::new(self.data.expose(), self.count)
    }

    pub fn credential(&self) -> Result<Option<Credential<'_>>, Error> {
        for r in self.view()?.records().iter() {
            let r = r?;
            if r.record_type == RecordType::RECLAIM_CREDENTIAL {
                return Credential::decode(r.data).map(Some);
            }
        }
        Ok(None)
    }
}
pub(super) fn object_record<'a>(
    kind: RecordType,
    expiration: u64,
    data: &'a [u8],
) -> RecordData<'a> {
    RecordData {
        record_type: kind,
        expiration_time: expiration,
        flags: RecordFlags::RELATIVE_EXPIRATION,
        data,
    }
}
pub(super) fn attribute_blob(quota: &Rc<Quota>, attribute: Attribute<'_>) -> Result<Blob, Error> {
    Blob::encode(quota, attribute.encoded_len()?, |o| attribute.encode(o))
}
pub(super) fn credential_blob(
    quota: &Rc<Quota>,
    credential: Credential<'_>,
) -> Result<Blob, Error> {
    Blob::encode(quota, credential.encoded_len()?, |o| credential.encode(o))
}
pub(super) fn presentation_blob(
    quota: &Rc<Quota>,
    presentation: Presentation<'_>,
) -> Result<Blob, Error> {
    Blob::encode(quota, presentation.encoded_len()?, |o| {
        presentation.encode(o)
    })
}
pub(super) fn serialized_list(quota: &Rc<Quota>, items: &Table<Blob>) -> Result<Blob, Error> {
    let mut len = 0usize;
    for i in items.iter() {
        len = len.checked_add(i.len()).ok_or(Error::Overflow)?;
    }
    Blob::encode(quota, len, |out| {
        let mut at = 0;
        for i in items.iter() {
            out[at..at + i.len()].copy_from_slice(i.expose());
            at += i.len();
        }
        Ok(at)
    })
}
