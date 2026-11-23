//! Borrowed issuance against one original NAMESTORE zone.

use super::{IDENTIFIER_LABEL_BYTES, identifier_label};
use crate::{
    AttributeList, CredentialType, Identifier, Presentation, Ticket, Uri,
    ipc::{Request, encode_issued_ticket},
    objects::PRESENTATION_PREFIX,
};
use gnunet_gnsrecord::{
    RECORD_HEADER_LEN, RecordData, RecordFlags, RecordType, ZONE_TEXT_LEN, ZoneKey,
};
use gnunet_types::{Error, RelativeTime};
use gnunet_wire::official::{identity::SecretKeyView, namestore::Records};
use zeroize::Zeroizing;

const TICKET_BYTES: usize = IDENTIFIER_LABEL_BYTES + 1 + ZONE_TEXT_LEN + 1;
const REFERENCE_BYTES: usize = RECORD_HEADER_LEN + 32;
const MIN_PRESENTATION_BYTES: usize = RECORD_HEADER_LEN + PRESENTATION_PREFIX;
// These non-delegation rows are padded to a power of two. NAMESTORE's BE16
// data length can represent at most the largest power below 65536.
const MAX_PADDED_ROW: usize = 1 << (u16::BITS - 1);
const PUBLIC: RecordFlags = RecordFlags::RELATIVE_EXPIRATION;
const PRIVATE: RecordFlags = PUBLIC.union(RecordFlags::PRIVATE);

/// Original issue request, retaining its typed private authority and opaque RID.
#[derive(Clone, Copy)]
pub struct Issue<'a> {
    rid: u32,
    key: SecretKeyView<'a>,
    uri: Uri<'a>,
    attributes: AttributeList<'a>,
}

impl<'a> Issue<'a> {
    /// Select an issue request without copying its sensitive bytes.
    #[must_use]
    pub const fn from_request(request: Request<'a>) -> Option<Self> {
        match request {
            Request::IssueTicket {
                rid,
                key,
                uri,
                attributes,
                ..
            } => Some(Self {
                rid,
                key,
                uri,
                attributes,
            }),
            _ => None,
        }
    }

    /// Original opaque request ID.
    #[must_use]
    pub const fn rid(self) -> u32 {
        self.rid
    }

    /// Original typed secret key; its storage remains owned by the caller.
    #[must_use]
    pub const fn key(self) -> SecretKeyView<'a> {
        self.key
    }

    /// Bound work before checking exact, nonzero attribute references.
    /// The record limit includes the descriptor, TXT and distinct presentations.
    /// The byte limit is the lane's capacity for the padded NAMESTORE row.
    pub fn validate(
        self,
        max_records: usize,
        row_bytes: usize,
    ) -> Result<ValidatedIssue<'a>, Error> {
        let limit = packed_limit(row_bytes);
        let mut count = self.attributes.len() + 2;
        let mut minimum_bytes = self.attributes.len() * REFERENCE_BYTES
            + 2 * RECORD_HEADER_LEN
            + TICKET_BYTES
            + self.uri.expose().len();
        if count > max_records || minimum_bytes > limit {
            return Err(Error::TooLarge);
        }
        let mut presentations = 0;
        for (index, attribute) in self.attributes.iter().enumerate() {
            if attribute.id.is_zero() {
                return Err(Error::InvalidInput);
            }
            let mut first_credential = !attribute.credential.is_zero();
            for earlier in self.attributes.iter().take(index) {
                if earlier.id == attribute.id {
                    return Err(Error::Conflict);
                }
                first_credential &= earlier.credential != attribute.credential;
            }
            if first_credential {
                presentations += 1;
                count += 1;
                minimum_bytes += MIN_PRESENTATION_BYTES;
                if count > max_records || minimum_bytes > limit {
                    return Err(Error::TooLarge);
                }
            }
        }
        Ok(ValidatedIssue {
            original: self,
            count: u16::try_from(count).map_err(|_| Error::TooLarge)?,
            presentations,
            minimum_bytes,
            limit,
        })
    }
}

/// A bounded, exact attribute selection ready for ticket reuse or preparation.
#[derive(Clone, Copy)]
pub struct ValidatedIssue<'a> {
    original: Issue<'a>,
    count: u16,
    presentations: usize,
    minimum_bytes: usize,
    limit: usize,
}

impl<'a> ValidatedIssue<'a> {
    /// Original opaque request ID.
    #[must_use]
    pub const fn rid(self) -> u32 {
        self.original.rid()
    }

    /// Original authority. The caller derives the typed public issuer from it.
    #[must_use]
    pub const fn key(self) -> SecretKeyView<'a> {
        self.original.key()
    }

    /// Reuse one active row from the original private zone only if its
    /// descriptor binds the supplied issuer and label and the entire selection
    /// and RP match exactly. The caller supplies normalized, unexpired records.
    pub fn matching_ticket<'row>(
        self,
        issuer: ZoneKey,
        label: &[u8],
        records: Records<'row>,
    ) -> Result<Option<TicketRow<'row>>, Error> {
        let mut descriptor = None;
        let mut uri = None;
        let mut references = 0;
        let mut presentations = 0;
        let mut presentation_bytes = 0;
        for record in records.records().iter() {
            let record = record?;
            let private = record.flags.contains(RecordFlags::PRIVATE);
            match record.record_type {
                RecordType::RECLAIM_TICKET => {
                    if !private || descriptor.replace(record.data).is_some() {
                        return Ok(None);
                    }
                }
                RecordType::TXT => {
                    if private || uri.replace(record.data).is_some() {
                        return Ok(None);
                    }
                }
                RecordType::RECLAIM_ATTRIBUTE_REF => {
                    references += 1;
                    if private || references > self.original.attributes.len() {
                        return Ok(None);
                    }
                }
                RecordType::RECLAIM_PRESENTATION => {
                    presentations += 1;
                    if private || presentations > self.presentations {
                        return Ok(None);
                    }
                    presentation_bytes += record.data.len();
                }
                _ => {}
            }
        }
        let (Some(descriptor), Some(uri)) = (descriptor, uri) else {
            return Ok(None);
        };
        if uri != self.original.uri.expose()
            || references != self.original.attributes.len()
            || presentations != self.presentations
        {
            return Ok(None);
        }
        let ticket = Ticket::decode(descriptor)?;
        if ticket.capability()? != (label, issuer) {
            return Ok(None);
        }
        // With exact counts, presence of each requested ID proves equality of
        // the sets and rules out duplicate as well as unexpected entries.
        for attribute in self.original.attributes.iter() {
            let mut referenced = false;
            let mut presented = attribute.credential.is_zero();
            for record in records.records().iter() {
                let record = record?;
                match record.record_type {
                    RecordType::RECLAIM_ATTRIBUTE_REF => {
                        referenced |= Identifier::decode(record.data)? == attribute.id;
                    }
                    RecordType::RECLAIM_PRESENTATION => {
                        presented |=
                            Presentation::decode(record.data)?.credential == attribute.credential;
                    }
                    _ => {}
                }
            }
            if !referenced || !presented {
                return Ok(None);
            }
        }
        Ok(Some(TicketRow {
            ticket,
            uri: Uri::new(uri)?,
            records,
            presentation_bytes,
        }))
    }

    /// Prepare official relative-expiry records in caller storage without
    /// publishing them. The caller supplies the derived issuer and a fresh
    /// nonzero ID whose label is free in the original authority.
    ///
    /// The provider writes a complete presentation for each distinct selected
    /// credential and returns the original credential type and written length.
    /// This verifies the serialized ID and type binding, not the proof itself.
    /// Errors may leave sensitive bytes in scratch; the caller owns erasure.
    pub fn build<'out>(
        self,
        issuer: ZoneKey,
        generated: Identifier,
        refresh: RelativeTime,
        output: &'out mut [u8],
        mut present: impl FnMut(
            Identifier,
            AttributeList<'a>,
            &mut [u8],
        ) -> Result<(CredentialType, usize), Error>,
    ) -> Result<IssuedTicket<'out>, Error> {
        if generated.is_zero() {
            return Err(Error::InvalidInput);
        }
        // Only give the provider bytes the padded row can actually use.
        let limit = self.limit.min(packed_limit(output.len()));
        if self.minimum_bytes > limit {
            return Err(Error::Capacity);
        }
        let mut descriptor = Zeroizing::new([0; TICKET_BYTES]);
        identifier_label(generated, &mut descriptor[..IDENTIFIER_LABEL_BYTES])?;
        descriptor[IDENTIFIER_LABEL_BYTES] = b'.';
        issuer.write_ztld(&mut descriptor[IDENTIFIER_LABEL_BYTES + 1..TICKET_BYTES - 1])?;

        let attributes = self.original.attributes;
        let mut remaining = self.minimum_bytes;
        let mut presentation_bytes = 0;
        let mut writer = RowWriter {
            output: &mut output[..limit],
            position: 0,
            refresh,
        };
        for (index, attribute) in attributes.iter().enumerate() {
            writer.push(
                RecordType::RECLAIM_ATTRIBUTE_REF,
                PUBLIC,
                attribute.id.bytes(),
            )?;
            remaining -= REFERENCE_BYTES;
            let id = attribute.credential;
            if id.is_zero()
                || attributes
                    .iter()
                    .take(index)
                    .any(|earlier| earlier.credential == id)
            {
                continue;
            }
            remaining -= MIN_PRESENTATION_BYTES;
            presentation_bytes +=
                writer.presentation(remaining, id, |out| present(id, attributes, out))?;
        }
        let ticket_start = writer.push(RecordType::RECLAIM_TICKET, PRIVATE, descriptor.as_ref())?;
        let uri = self.original.uri.expose();
        let uri_start = writer.push(RecordType::TXT, PUBLIC, uri)?;
        let len = writer.position.next_power_of_two();
        writer.output[writer.position..len].fill(0);
        let bytes = &output[..len];
        let ticket = Ticket::decode(&bytes[ticket_start..ticket_start + TICKET_BYTES])?;
        let uri = Uri::new(&bytes[uri_start..uri_start + uri.len()])?;
        Ok(IssuedTicket(TicketRow {
            ticket,
            uri,
            records: Records::new(bytes, self.count)?,
            presentation_bytes,
        }))
    }
}

fn packed_limit(capacity: usize) -> usize {
    capacity
        .min(MAX_PADDED_ROW)
        .checked_ilog2()
        .map_or(0, |exponent| 1 << exponent)
}

struct RowWriter<'a> {
    output: &'a mut [u8],
    position: usize,
    refresh: RelativeTime,
}

impl RowWriter<'_> {
    fn push(
        &mut self,
        record_type: RecordType,
        flags: RecordFlags,
        data: &[u8],
    ) -> Result<usize, Error> {
        let start = self.position + RECORD_HEADER_LEN;
        self.position += RecordData {
            expiration_time: self.refresh.as_micros(),
            record_type,
            flags,
            data,
        }
        .encode(&mut self.output[self.position..])?;
        Ok(start)
    }

    fn presentation(
        &mut self,
        remaining: usize,
        id: Identifier,
        present: impl FnOnce(&mut [u8]) -> Result<(CredentialType, usize), Error>,
    ) -> Result<usize, Error> {
        let end = self.output.len() - remaining;
        let (header, value) = self.output[self.position..end].split_at_mut(RECORD_HEADER_LEN);
        let (kind, written) = present(value)?;
        let bytes = value.get(..written).ok_or(Error::Capacity)?;
        let presentation = Presentation::decode(bytes)?;
        if presentation.credential != id || presentation.kind != kind {
            return Err(Error::Authentication);
        }
        // The provider encoded directly after the NetworkRecord header.
        RecordData {
            expiration_time: self.refresh.as_micros(),
            record_type: RecordType::RECLAIM_PRESENTATION,
            flags: PUBLIC,
            data: bytes,
        }
        .encode_header(header)?;
        self.position += RECORD_HEADER_LEN + written;
        Ok(written)
    }
}

/// One prepared NAMESTORE write and its matching issuance result.
pub struct IssuedTicket<'a>(TicketRow<'a>);

impl<'a> IssuedTicket<'a> {
    /// Canonical NAMESTORE label without the terminator.
    #[must_use]
    pub fn label(&self) -> &'a [u8] {
        &self.0.ticket.expose()[..IDENTIFIER_LABEL_BYTES]
    }

    /// Complete replacement set for the original private zone.
    #[must_use]
    pub const fn records(&self) -> Records<'a> {
        self.0.records
    }

    /// Prepared response data. Send success only after the authoritative write.
    #[must_use]
    pub const fn result(&self) -> TicketRow<'a> {
        self.0
    }
}

/// A checked ticket and the presentations borrowed from its stored records.
#[derive(Clone, Copy)]
pub struct TicketRow<'a> {
    ticket: Ticket<'a>,
    uri: Uri<'a>,
    records: Records<'a>,
    presentation_bytes: usize,
}

impl<'a> TicketRow<'a> {
    /// Original public capability name.
    #[must_use]
    pub const fn ticket(self) -> Ticket<'a> {
        self.ticket
    }

    /// Exact relying-party URI stored with the descriptor.
    #[must_use]
    pub const fn uri(self) -> Uri<'a> {
        self.uri
    }

    /// Borrow the original presentations in record order.
    pub fn presentations(self) -> impl Iterator<Item = Result<Presentation<'a>, Error>> {
        self.records
            .records()
            .iter()
            .filter_map(|record| match record {
                Ok(record) if record.record_type == RecordType::RECLAIM_PRESENTATION => {
                    Some(Presentation::decode(record.data))
                }
                Ok(_) => None,
                Err(error) => Some(Err(error)),
            })
    }

    /// Encode the official issue reply directly from the checked records. As
    /// with the C issue result, the stored RP URI is not included in this frame.
    pub fn encode_response(self, rid: u32, out: &mut [u8]) -> Result<usize, Error> {
        encode_issued_ticket(rid, self.ticket, self.records, self.presentation_bytes, out)
    }
}
