use crate::{
    Attribute, Credential, Identifier, Presentation, PresentationList, Ticket, Uri,
    ipc::{Iteration, Response},
};
use gnunet_gnsrecord::{RecordData, RecordFlags, RecordType, ZoneKey, encode_base32};
use gnunet_types::Error;
use gnunet_wire::official::namestore::Records;

/// Unpadded Base32GNS length of a 256-bit RECLAIM identifier.
pub const IDENTIFIER_LABEL_BYTES: usize = 52;

/// Write the official identifier label without a terminator or private prefix.
pub fn identifier_label(id: Identifier, out: &mut [u8]) -> Result<usize, Error> {
    encode_base32(id.bytes(), out)
}

fn check_identifier_label(id: Identifier, label: &[u8]) -> Result<(), Error> {
    let mut expected = [0; IDENTIFIER_LABEL_BYTES];
    identifier_label(id, &mut expected)?;
    if id.is_zero() || label != expected {
        return Err(Error::Malformed);
    }
    Ok(())
}

/// A structurally checked RECLAIM record from a NAMESTORE row.
pub(crate) enum StoredRecord<'a> {
    Attribute(Attribute<'a>),
    Credential(Credential<'a>),
    AttributeReference(Identifier),
    Presentation(Presentation<'a>),
    Ticket,
    Other,
}

impl<'a> StoredRecord<'a> {
    pub(crate) fn decode(record: RecordData<'a>) -> Result<Self, Error> {
        Ok(match record.record_type {
            RecordType::RECLAIM_ATTRIBUTE => Self::Attribute(Attribute::decode(record.data)?),
            RecordType::RECLAIM_CREDENTIAL => Self::Credential(Credential::decode(record.data)?),
            RecordType::RECLAIM_ATTRIBUTE_REF => {
                Self::AttributeReference(Identifier::decode(record.data)?)
            }
            RecordType::RECLAIM_PRESENTATION => {
                Self::Presentation(Presentation::decode(record.data)?)
            }
            RecordType::RECLAIM_TICKET => {
                Ticket::decode(record.data)?;
                Self::Ticket
            }
            _ => Self::Other,
        })
    }

    pub(crate) fn check_label(&self, label: &[u8]) -> Result<(), Error> {
        match self {
            Self::Attribute(attribute) => check_identifier_label(attribute.id, label),
            Self::Credential(credential) => check_identifier_label(credential.id, label),
            _ => Ok(()),
        }
    }
}

/// Select one official result from a normalized NAMESTORE row. The caller
/// supplies only rows read from the original private zone, retaining private
/// records and excluding expired records. This checks structure and storage
/// bindings only; it does not verify credential or presentation payloads.
/// Attribute and credential iteration counts the entire normalized set,
/// including any supplemental nickname, when deciding whether it is a singleton.
pub fn iteration_row<'a>(
    kind: Iteration,
    rid: u32,
    issuer: ZoneKey,
    label: &[u8],
    records: Records<'a>,
) -> Result<Option<Response<'a>>, Error> {
    if kind == Iteration::Tickets {
        return issued_ticket(rid, issuer, label, records);
    }
    if records.count() != 1 {
        return Ok(None);
    }
    let record = records.records().iter().next().ok_or(Error::Malformed)??;
    let response = match (kind, record.record_type) {
        (Iteration::Attributes, RecordType::RECLAIM_ATTRIBUTE) => {
            let attribute = Attribute::decode(record.data)?;
            check_identifier_label(attribute.id, label)?;
            Response::Attribute {
                rid,
                reserved: 0,
                credential_len: 0,
                identity: Some(issuer),
                attribute: Some(attribute),
            }
        }
        (Iteration::Credentials, RecordType::RECLAIM_CREDENTIAL) => {
            let credential = Credential::decode(record.data)?;
            check_identifier_label(credential.id, label)?;
            Response::Credential {
                rid,
                identity: Some(issuer),
                credential: Some(credential),
            }
        }
        _ => return Ok(None),
    };
    Ok(Some(response))
}

fn issued_ticket<'a>(
    rid: u32,
    issuer: ZoneKey,
    label: &[u8],
    records: Records<'a>,
) -> Result<Option<Response<'a>>, Error> {
    let (mut ticket, mut uri, mut multiple_uris) = (None, None, false);
    for record in records.records().iter() {
        let record = record?;
        match record.record_type {
            RecordType::RECLAIM_TICKET if record.flags.contains(RecordFlags::PRIVATE) => {
                if ticket.replace(Ticket::decode(record.data)?).is_some() {
                    return Err(Error::Malformed);
                }
            }
            RecordType::TXT => multiple_uris |= uri.replace(record.data).is_some(),
            _ => {}
        }
    }
    let Some(ticket) = ticket else {
        return Ok(None);
    };
    let (stored_label, stored_issuer) = ticket.capability()?;
    if stored_issuer != issuer || stored_label != label {
        return Err(Error::Authentication);
    }
    if multiple_uris {
        return Err(Error::Malformed);
    }
    let Some(uri) = uri else {
        // The TXT may have expired independently of the private ticket.
        return Ok(None);
    };
    Ok(Some(Response::Ticket {
        rid,
        ticket: Some(ticket),
        // NAMESTORE stores the length-delimited TXT without a NUL. IPC adds it.
        uri: Some(Uri::new(uri)?),
        presentations: PresentationList::empty(),
    }))
}
