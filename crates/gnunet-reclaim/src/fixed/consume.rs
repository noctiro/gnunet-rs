//! Checked RECLAIM ticket consumption values, independent of the GNS driver.

use super::{IDENTIFIER_LABEL_BYTES, identifier_label};
use crate::{
    Attribute, AttributeList, Identifier, Presentation, PresentationList, Uri,
    ipc::{Request, Response},
};
use core::fmt;
use gnunet_gnsrecord::{RecordFlags, RecordSet, RecordType, ZoneKey};
use gnunet_types::Error;

/// Accepted bounds for one authoritative ticket row. The provider separately
/// enforces the actual response byte limit and active record projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsumeLimits {
    /// Maximum items in the complete GNS answer, including unknown records.
    pub records: usize,
    /// Maximum distinct requested attributes.
    pub references: usize,
    /// Maximum distinct credential presentations.
    pub presentations: usize,
}

/// Original consume request, with its typed issuer and exact RP URI.
/// This is syntactic capability decoding; no GNS response is trusted here.
#[derive(Clone, Copy)]
pub struct Consume<'a> {
    rid: u32,
    issuer: ZoneKey,
    label: &'a [u8],
    uri: Uri<'a>,
}

impl<'a> Consume<'a> {
    /// Decode the issuer and lookup label only for a ConsumeTicket request.
    pub fn from_request(request: Request<'a>) -> Result<Option<Self>, Error> {
        let Request::ConsumeTicket { rid, ticket, uri } = request else {
            return Ok(None);
        };
        let (label, issuer) = ticket.capability()?;
        Ok(Some(Self {
            rid,
            issuer,
            label,
            uri,
        }))
    }

    /// Original opaque request identifier.
    #[must_use]
    pub const fn rid(self) -> u32 {
        self.rid
    }

    /// Exact typed issuer from the original capability.
    #[must_use]
    pub const fn issuer(self) -> ZoneKey {
        self.issuer
    }

    /// Original capability label, excluding the final issuer component.
    #[must_use]
    pub const fn label(self) -> &'a [u8] {
        self.label
    }

    /// Qualify one complete answer before exposing any of its grant values.
    /// The caller must correlate the answer with the original authenticated
    /// GNS query and pass that query's issuer and label, not values inferred
    /// from untrusted record contents. Exactly one public TXT must match the
    /// RP URI. Private records in a local GNS answer cannot grant disclosure.
    pub fn authorize<'records>(
        self,
        answer_issuer: ZoneKey,
        answer_label: &[u8],
        records: RecordSet<'records>,
        limits: ConsumeLimits,
    ) -> Result<Authorization<'records>, Error> {
        check_scope(self.issuer, self.label, answer_issuer, answer_label)?;
        if records.len() > limits.records {
            return Err(Error::Capacity);
        }
        let mut uri = payloads(records, RecordType::TXT);
        let value = uri.next().transpose()?;
        if uri.next().transpose()?.is_some() {
            return Err(Error::Malformed);
        }
        if value != Some(self.uri.expose()) {
            return Err(Error::Authentication);
        }
        let references = validate_unique(
            records,
            RecordType::RECLAIM_ATTRIBUTE_REF,
            limits.references,
            Identifier::decode,
        )?;
        let presentations = validate_unique(
            records,
            RecordType::RECLAIM_PRESENTATION,
            limits.presentations,
            |data| Ok(Presentation::decode(data)?.credential),
        )?;
        Ok(Authorization {
            issuer: self.issuer,
            records,
            references,
            presentations,
        })
    }

    /// Encode the canonical success fields after all original GNS answers
    /// have settled. The caller owns the completed borrowed lists.
    #[must_use]
    pub const fn success<'reply>(
        self,
        attributes: AttributeList<'reply>,
        presentations: PresentationList<'reply>,
    ) -> Response<'reply> {
        Response::Consumed {
            rid: self.rid,
            result: 1,
            reserved: 0,
            identity: Some(self.issuer),
            attributes,
            presentations,
        }
    }

    /// Report a business failure without any partial attributes or presentations.
    #[must_use]
    pub const fn failure(self, cause: Error) -> Response<'static> {
        consume_failure(self.rid, Some(self.issuer), cause)
    }
}

impl fmt::Debug for Consume<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Consume")
            .field("rid", &self.rid)
            .finish_non_exhaustive()
    }
}

/// Report a consume failure even when the capability has no decodable issuer.
/// Authentication refusal is zero; any other failure is the canonical SYSERR.
#[must_use]
pub const fn consume_failure(rid: u32, issuer: Option<ZoneKey>, cause: Error) -> Response<'static> {
    Response::Consumed {
        rid,
        result: if matches!(cause, Error::Authentication) {
            0
        } else {
            u32::MAX
        },
        reserved: 0,
        identity: issuer,
        attributes: AttributeList::empty(),
        presentations: PresentationList::empty(),
    }
}

/// Exact, wholly validated grant from an original issuer query. The provider
/// still owns these borrowed bytes; the caller must retain any future work.
pub struct Authorization<'a> {
    issuer: ZoneKey,
    records: RecordSet<'a>,
    references: usize,
    presentations: usize,
}

impl<'a> Authorization<'a> {
    /// Number of distinct, nonzero attribute references.
    #[must_use]
    pub const fn reference_count(&self) -> usize {
        self.references
    }

    /// Number of original credential presentations.
    #[must_use]
    pub const fn presentation_count(&self) -> usize {
        self.presentations
    }

    /// One original issuer-scoped lookup per reference, in record order.
    pub fn references(&self) -> impl Iterator<Item = Result<AttributeLookup, Error>> + '_ {
        let issuer = self.issuer;
        payloads(self.records, RecordType::RECLAIM_ATTRIBUTE_REF)
            .map(move |data| Ok(AttributeReference(Identifier::decode(data?)?).in_zone(issuer)))
    }

    /// Original credential presentations in record order. Their proof content
    /// remains opaque and is not verified by a GNS binding or by this API.
    pub fn presentations(&self) -> impl Iterator<Item = Result<Presentation<'a>, Error>> + '_ {
        payloads(self.records, RecordType::RECLAIM_PRESENTATION)
            .map(|data| Presentation::decode(data?))
    }
}

/// One nonzero reference from an already checked authorization row. Callers
/// retaining several references from the same grant can store the issuer once.
#[repr(transparent)]
#[derive(Clone, Copy, Debug)]
pub struct AttributeReference(Identifier);

impl AttributeReference {
    /// Restore the scoped lookup with the issuer retained from the original
    /// grant. This does not authenticate a new issuer or authorize reassignment.
    #[must_use]
    pub const fn in_zone(self, issuer: ZoneKey) -> AttributeLookup {
        AttributeLookup {
            reference: self,
            issuer,
        }
    }
}

/// An original nonzero reference and its inherited issuer.
#[derive(Clone, Copy, Debug)]
pub struct AttributeLookup {
    reference: AttributeReference,
    issuer: ZoneKey,
}

impl AttributeLookup {
    /// Exact attribute identifier from the authorization row.
    #[must_use]
    pub const fn id(self) -> Identifier {
        self.reference.0
    }

    /// The original reference, for storage alongside the grant's shared issuer.
    #[must_use]
    pub const fn reference(self) -> AttributeReference {
        self.reference
    }

    /// Typed issuer inherited from the original capability.
    #[must_use]
    pub const fn issuer(self) -> ZoneKey {
        self.issuer
    }

    /// Write the exact canonical RECLAIM attribute label.
    pub fn label(self, out: &mut [u8]) -> Result<usize, Error> {
        identifier_label(self.id(), out)
    }

    /// Wholly validate one correlated attribute answer. Every returned
    /// public attribute must bind to this original ID. An otherwise valid
    /// empty answer contributes no attribute.
    pub fn attributes<'records>(
        self,
        answer_issuer: ZoneKey,
        answer_label: &[u8],
        records: RecordSet<'records>,
        record_limit: usize,
    ) -> Result<AttributeAnswer<'records>, Error> {
        let mut label = [0; IDENTIFIER_LABEL_BYTES];
        let length = self.label(&mut label)?;
        check_scope(self.issuer, &label[..length], answer_issuer, answer_label)?;
        if records.len() > record_limit {
            return Err(Error::Capacity);
        }
        for bytes in payloads(records, RecordType::RECLAIM_ATTRIBUTE) {
            if Attribute::decode(bytes?)?.id != self.id() {
                return Err(Error::Malformed);
            }
        }
        Ok(AttributeAnswer { records })
    }
}

/// An original GNS result validated for exactly one attribute reference.
pub struct AttributeAnswer<'a> {
    records: RecordSet<'a>,
}

impl<'a> AttributeAnswer<'a> {
    /// View each original matching attribute, in record order.
    pub fn attributes(&self) -> impl Iterator<Item = Result<Attribute<'a>, Error>> + '_ {
        payloads(self.records, RecordType::RECLAIM_ATTRIBUTE).map(|data| Attribute::decode(data?))
    }
}

fn check_scope(
    zone: ZoneKey,
    label: &[u8],
    answer_zone: ZoneKey,
    answer_label: &[u8],
) -> Result<(), Error> {
    if zone == answer_zone && label == answer_label {
        Ok(())
    } else {
        Err(Error::Authentication)
    }
}

fn payloads(
    records: RecordSet<'_>,
    kind: RecordType,
) -> impl Iterator<Item = Result<&[u8], Error>> {
    records.iter().filter_map(move |item| match item {
        Ok(record) => (record.record_type == kind && !record.flags.contains(RecordFlags::PRIVATE))
            .then_some(Ok(record.data)),
        Err(error) => Some(Err(error)),
    })
}

fn validate_unique<'a>(
    records: RecordSet<'a>,
    kind: RecordType,
    limit: usize,
    id: impl Fn(&'a [u8]) -> Result<Identifier, Error>,
) -> Result<usize, Error> {
    let mut count = 0;
    for data in payloads(records, kind) {
        let next = id(data?)?;
        if next.is_zero() {
            return Err(Error::Malformed);
        }
        if count == limit {
            return Err(Error::Capacity);
        }
        for previous in payloads(records, kind).take(count) {
            if id(previous?)? == next {
                return Err(Error::Malformed);
            }
        }
        count += 1;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AttributeType, CredentialType, Name, Sensitive, Ticket, objects::TICKET_NAME_BYTES,
    };
    use gnunet_gnsrecord::{RecordData, ZoneKeyType};

    const ISSUER: ZoneKey = ZoneKey::new(ZoneKeyType::Edkey, [7; 32]);
    const FOREIGN: ZoneKey = ZoneKey::new(ZoneKeyType::Edkey, [8; 32]);
    const ID: Identifier = Identifier::new([8; 32]);
    const OTHER_ID: Identifier = Identifier::new([9; 32]);
    const LABEL: &[u8] = b"capability";
    const RP: &[u8] = b"https://rp.example";
    const LIMITS: ConsumeLimits = ConsumeLimits {
        records: 8,
        references: 4,
        presentations: 4,
    };

    fn request(out: &mut [u8; TICKET_NAME_BYTES]) -> Result<Consume<'_>, Error> {
        out[..LABEL.len()].copy_from_slice(LABEL);
        out[LABEL.len()] = b'.';
        let start = LABEL.len() + 1;
        let end = start + ISSUER.write_ztld(&mut out[start..])?.len();
        Consume::from_request(Request::ConsumeTicket {
            rid: u32::MAX,
            ticket: Ticket::new(&out[..end])?,
            uri: Uri::new(RP)?,
        })?
        .ok_or(Error::NotFound)
    }

    fn record(kind: RecordType, data: &[u8]) -> RecordData<'_> {
        RecordData {
            record_type: kind,
            expiration_time: 1,
            flags: RecordFlags::NONE,
            data,
        }
    }

    fn records<'a>(items: &[RecordData<'_>], out: &'a mut [u8]) -> Result<RecordSet<'a>, Error> {
        let len = gnunet_gnsrecord::serialize(items, out)?;
        RecordSet::parse(&out[..len], items.len(), LIMITS.records)
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "asserts authorization rejection paths"
    )]
    fn authority_and_exact_rp_are_checked_before_exposing_grant() -> Result<(), Error> {
        let mut ticket = [0; TICKET_NAME_BYTES];
        let op = request(&mut ticket)?;
        let mut bytes = [0; 256];
        let bad_ref = record(RecordType::RECLAIM_ATTRIBUTE_REF, b"invalid");
        let good_rp = record(RecordType::TXT, RP);
        let private_rp = RecordData {
            flags: RecordFlags::PRIVATE,
            ..good_rp
        };
        let row = records(&[private_rp, bad_ref], &mut bytes)?;
        assert!(matches!(
            op.authorize(ISSUER, LABEL, row, LIMITS),
            Err(Error::Authentication)
        ));
        for uri in [
            &b"https://rp.exampl"[..],
            &b"https://rp.example/more"[..],
            &b"https://rp.example\0"[..],
        ] {
            let row = records(&[record(RecordType::TXT, uri), bad_ref], &mut bytes)?;
            assert!(matches!(
                op.authorize(ISSUER, LABEL, row, LIMITS),
                Err(Error::Authentication),
            ));
        }
        let row = records(&[good_rp, good_rp], &mut bytes)?;
        assert!(matches!(
            op.authorize(ISSUER, LABEL, row, LIMITS),
            Err(Error::Malformed)
        ));
        let row = records(&[good_rp], &mut bytes)?;
        assert!(matches!(
            op.authorize(FOREIGN, LABEL, row, LIMITS),
            Err(Error::Authentication)
        ));
        assert!(matches!(
            op.authorize(ISSUER, b"other", row, LIMITS),
            Err(Error::Authentication)
        ));
        assert_eq!(
            op.authorize(ISSUER, LABEL, row, LIMITS)?.reference_count(),
            0
        );
        assert!(matches!(
            op.failure(Error::Authentication),
            Response::Consumed { rid: u32::MAX, result: 0, identity: Some(ISSUER), attributes, presentations, .. }
                if attributes.is_empty() && presentations.is_empty()
        ));
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "asserts unique ticket and original result ID"
    )]
    fn references_and_attribute_answers_are_bound_to_the_original_scope() -> Result<(), Error> {
        let mut ticket = [0; TICKET_NAME_BYTES];
        let op = request(&mut ticket)?;
        let mut row_bytes = [0; 256];
        let rp = record(RecordType::TXT, RP);
        let reference = record(RecordType::RECLAIM_ATTRIBUTE_REF, ID.bytes());
        let zero = record(RecordType::RECLAIM_ATTRIBUTE_REF, Identifier::ZERO.bytes());
        let mut presentation_bytes = [0; 100];
        let presentation_len =
            Presentation::new(OTHER_ID, CredentialType::JWT, Sensitive::new(b"opaque"))
                .encode(&mut presentation_bytes)?;
        let presentation = record(
            RecordType::RECLAIM_PRESENTATION,
            &presentation_bytes[..presentation_len],
        );
        for items in [
            &[rp, reference, reference][..],
            &[rp, zero][..],
            &[rp, reference, presentation, presentation][..],
        ] {
            let row = records(items, &mut row_bytes)?;
            assert!(matches!(
                op.authorize(ISSUER, LABEL, row, LIMITS),
                Err(Error::Malformed)
            ));
        }
        let row = records(&[rp, reference, presentation], &mut row_bytes)?;
        assert!(matches!(
            op.authorize(
                ISSUER,
                LABEL,
                row,
                ConsumeLimits {
                    references: 0,
                    ..LIMITS
                }
            ),
            Err(Error::Capacity)
        ));
        let authorization = op.authorize(ISSUER, LABEL, row, LIMITS)?;
        let reference = authorization.references().next().ok_or(Error::NotFound)??;
        assert_eq!(reference.id(), ID);
        assert_eq!(reference.issuer(), ISSUER);
        assert_eq!(authorization.presentation_count(), 1);
        assert_eq!(
            authorization
                .presentations()
                .next()
                .ok_or(Error::NotFound)??
                .credential,
            OTHER_ID,
        );
        let mut attr_label = [0; IDENTIFIER_LABEL_BYTES];
        reference.label(&mut attr_label)?;
        let mut attr_bytes = [0; 128];
        let mut answer_bytes = [0; 256];
        for id in [OTHER_ID, ID] {
            let len = Attribute::new(
                id,
                Identifier::ZERO,
                AttributeType::STRING,
                Name::new(b"attribute")?,
                Sensitive::new(b"value"),
            )
            .encode(&mut attr_bytes)?;
            let items = [record(RecordType::RECLAIM_ATTRIBUTE, &attr_bytes[..len])];
            let answer = records(&items, &mut answer_bytes)?;
            assert!(matches!(
                reference.attributes(FOREIGN, &attr_label, answer, 8),
                Err(Error::Authentication)
            ));
            assert!(matches!(
                reference.attributes(ISSUER, LABEL, answer, 8),
                Err(Error::Authentication)
            ));
            let result = reference.attributes(ISSUER, &attr_label, answer, 8);
            if id == ID {
                let returned = result?.attributes().next().ok_or(Error::NotFound)??;
                assert_eq!(returned.id, ID);
            } else {
                assert!(matches!(result, Err(Error::Malformed)));
            }
        }
        let (_, len) = Attribute::decode_prefix(&attr_bytes)?;
        let row = records(
            &[RecordData {
                flags: RecordFlags::PRIVATE,
                ..record(RecordType::RECLAIM_ATTRIBUTE, &attr_bytes[..len])
            }],
            &mut answer_bytes,
        )?;
        let answer = reference.attributes(ISSUER, &attr_label, row, 8)?;
        assert!(answer.attributes().next().is_none());
        Ok(())
    }
}
