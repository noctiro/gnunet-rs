//! All active RECLAIM messages from the pinned service handler table. No native
//! MQ, retry, key derivation, operation cancellation record, or service is hidden here.
use crate::{
    Attribute, AttributeList, Credential, ListLimits, PresentationList, Ticket, Uri, be16, be32,
    put16, put32,
};
use core::fmt;
use gnunet_gnsrecord::ZoneKey;
use gnunet_types::Error;
use gnunet_wire::official::{
    Frame, MessageHeader, MessageType, RelativeTime, identity::SecretKeyView, message_type as mt,
};

/// Complete fixed store prefix, followed by private key and one serialized object.
pub const STORE_PREFIX: usize = 20;
/// Complete fixed delete prefix, followed by private key and one serialized object.
pub const DELETE_PREFIX: usize = 12;
/// Complete iteration-start prefix, followed by its original private key.
pub const ITERATION_PREFIX: usize = 12;
/// NEXT/STOP include only the common header and original request ID.
pub const ITERATION_CONTROL_LEN: usize = 8;
/// Complete ticket-issue prefix.
pub const ISSUE_PREFIX: usize = 16;
/// Complete ticket-consume/revoke prefix.
pub const TICKET_REQUEST_PREFIX: usize = 12;
/// Complete attribute result prefix.
pub const ATTRIBUTE_RESULT_PREFIX: usize = 16;
/// Complete credential result prefix.
pub const CREDENTIAL_RESULT_PREFIX: usize = 12;
/// Complete ticket result prefix (packed fields, with no host padding).
pub const TICKET_RESULT_PREFIX: usize = 14;
/// Complete consumed result prefix.
pub const CONSUMED_PREFIX: usize = 20;
/// Complete SUCCESS_RESPONSE and REVOKE_TICKET_RESULT size.
pub const STATUS_LEN: usize = 12;

/// Which independent official iterator protocol owns a request ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Iteration {
    /// Stored attributes, with ATTRIBUTE_RESULT and empty-key termination.
    Attributes,
    /// Stored credentials, with CREDENTIAL_RESULT and empty-key termination.
    Credentials,
    /// Issued tickets, with TICKET_RESULT and missing-ticket termination.
    Tickets,
}
impl Iteration {
    fn start(self) -> MessageType {
        match self {
            Self::Attributes => mt::RECLAIM_ATTRIBUTE_ITERATION_START,
            Self::Credentials => mt::RECLAIM_CREDENTIAL_ITERATION_START,
            Self::Tickets => mt::RECLAIM_TICKET_ITERATION_START,
        }
    }
    fn next(self) -> MessageType {
        match self {
            Self::Attributes => mt::RECLAIM_ATTRIBUTE_ITERATION_NEXT,
            Self::Credentials => mt::RECLAIM_CREDENTIAL_ITERATION_NEXT,
            Self::Tickets => mt::RECLAIM_TICKET_ITERATION_NEXT,
        }
    }
    fn stop(self) -> MessageType {
        match self {
            Self::Attributes => mt::RECLAIM_ATTRIBUTE_ITERATION_STOP,
            Self::Credentials => mt::RECLAIM_CREDENTIAL_ITERATION_STOP,
            Self::Tickets => mt::RECLAIM_TICKET_ITERATION_STOP,
        }
    }
}

/// Original caller request. Encoding does not assign/reuse IDs or transfer
/// private-key ownership; the caller must erase the whole original TX buffer.
#[derive(Clone, Copy, Debug)]
pub enum Request<'a> {
    /// Store one attribute with an original relative expiration interval.
    StoreAttribute {
        /// Original opaque RID, including zero if assigned by the caller.
        rid: u32,
        /// Relative expiration in microseconds, including the forever sentinel.
        expiration: RelativeTime,
        /// Borrowed serialized identity private key, redacted in diagnostics.
        key: SecretKeyView<'a>,
        /// Complete attribute, not a list.
        attribute: Attribute<'a>,
    },
    /// Store one credential without authenticating its format here.
    StoreCredential {
        /// Original RID.
        rid: u32,
        /// Original expiration interval.
        expiration: RelativeTime,
        /// Original private identity key.
        key: SecretKeyView<'a>,
        /// Complete credential bytes.
        credential: Credential<'a>,
    },
    /// Delete an attribute; the protocol carries its complete serialized object.
    DeleteAttribute {
        /// Original RID.
        rid: u32,
        /// Original private key.
        key: SecretKeyView<'a>,
        /// Original serialized attribute.
        attribute: Attribute<'a>,
    },
    /// Delete a credential, also carrying the complete object.
    DeleteCredential {
        /// Original RID.
        rid: u32,
        /// Original private key.
        key: SecretKeyView<'a>,
        /// Original credential.
        credential: Credential<'a>,
    },
    /// Start one iterator. The C service starts the first result automatically.
    IterateStart {
        /// Exact iterator family.
        kind: Iteration,
        /// Original iterator RID, retained by NEXT and STOP.
        rid: u32,
        /// Original private identity key.
        key: SecretKeyView<'a>,
        /// Ignored official reserved word, canonically zero.
        reserved: u16,
    },
    /// Request one further item. There is no count/credit field in this message.
    IterateNext {
        /// Exact iterator family.
        kind: Iteration,
        /// Original iterator RID.
        rid: u32,
    },
    /// Stop an iterator. There is no STOP acknowledgement or remote rollback.
    IterateStop {
        /// Exact iterator family.
        kind: Iteration,
        /// Original iterator RID.
        rid: u32,
    },
    /// Request a ticket for selected attributes and its RP URI.
    IssueTicket {
        /// Original RID.
        rid: u32,
        /// Original private issuer key.
        key: SecretKeyView<'a>,
        /// Sensitive relying-party URI, not a fixed audience public key.
        uri: Uri<'a>,
        /// Checked complete attribute list, possibly empty.
        attributes: AttributeList<'a>,
        /// Ignored alignment word, canonically zero.
        reserved: u16,
    },
    /// Revoke a capability. Actual result is REVOKE_TICKET_RESULT.
    RevokeTicket {
        /// Original RID.
        rid: u32,
        /// Original issuer private key.
        key: SecretKeyView<'a>,
        /// Variable-length capability name.
        ticket: Ticket<'a>,
    },
    /// Consume a ticket using its RP URI. No private key is included.
    ConsumeTicket {
        /// Original RID.
        rid: u32,
        /// Capability name, excluding its final wire NUL.
        ticket: Ticket<'a>,
        /// Original RP URI, excluding its final wire NUL.
        uri: Uri<'a>,
    },
}
impl<'a> Request<'a> {
    /// Original request/iterator identifier without normalizing or reallocating it.
    pub const fn request_id(self) -> u32 {
        match self {
            Self::StoreAttribute { rid, .. }
            | Self::StoreCredential { rid, .. }
            | Self::DeleteAttribute { rid, .. }
            | Self::DeleteCredential { rid, .. }
            | Self::IterateStart { rid, .. }
            | Self::IterateNext { rid, .. }
            | Self::IterateStop { rid, .. }
            | Self::IssueTicket { rid, .. }
            | Self::RevokeTicket { rid, .. }
            | Self::ConsumeTicket { rid, .. } => rid,
        }
    }
    /// Exact complete frame size, after checking every field and BE16 size bound.
    pub fn encoded_len(self) -> Result<usize, Error> {
        self.plan()?.encoded_len()
    }
    /// Encode after complete preflight. Failure leaves all output bytes unchanged.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        self.plan()?.encode(out)
    }
    /// Decode exactly one active request, validating all nested objects and lengths.
    /// The codec deliberately rejects trailing garbage accepted by some weak C
    /// checkers; no official producer emits those ignored suffixes.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let frame = Frame::decode(input)?;
        let code = frame.header().message_type();
        let store = code == mt::RECLAIM_ATTRIBUTE_STORE || code == mt::RECLAIM_CREDENTIAL_STORE;
        let delete = code == mt::RECLAIM_ATTRIBUTE_DELETE || code == mt::RECLAIM_CREDENTIAL_DELETE;
        if store || delete {
            let prefix = if store { STORE_PREFIX } else { DELETE_PREFIX };
            let h = input.get(..prefix).ok_or(Error::Truncated)?;
            let (rid, al, kl) = if store {
                (be32(h, 12), be16(h, 16), be16(h, 18))
            } else {
                (be32(h, 4), be16(h, 8), be16(h, 10))
            };
            let p = split(input, prefix, [usize::from(kl), usize::from(al), 0, 0])?;
            let key = SecretKeyView::new(p[0])?;
            if store {
                let expiration = RelativeTime::decode(&h[4..12])?;
                return if code == mt::RECLAIM_ATTRIBUTE_STORE {
                    Ok(Self::StoreAttribute {
                        rid,
                        expiration,
                        key,
                        attribute: Attribute::decode(p[1])?,
                    })
                } else {
                    Ok(Self::StoreCredential {
                        rid,
                        expiration,
                        key,
                        credential: Credential::decode(p[1])?,
                    })
                };
            }
            return if code == mt::RECLAIM_ATTRIBUTE_DELETE {
                Ok(Self::DeleteAttribute {
                    rid,
                    key,
                    attribute: Attribute::decode(p[1])?,
                })
            } else {
                Ok(Self::DeleteCredential {
                    rid,
                    key,
                    credential: Credential::decode(p[1])?,
                })
            };
        }
        for kind in [
            Iteration::Attributes,
            Iteration::Credentials,
            Iteration::Tickets,
        ] {
            if code == kind.start() {
                let h = input.get(..ITERATION_PREFIX).ok_or(Error::Truncated)?;
                let p = split(input, ITERATION_PREFIX, [usize::from(be16(h, 10)), 0, 0, 0])?;
                return Ok(Self::IterateStart {
                    kind,
                    rid: be32(h, 4),
                    reserved: be16(h, 8),
                    key: SecretKeyView::new(p[0])?,
                });
            }
            if code == kind.next() || code == kind.stop() {
                if input.len() != ITERATION_CONTROL_LEN {
                    return Err(Error::Malformed);
                }
                let rid = be32(input, 4);
                return if code == kind.next() {
                    Ok(Self::IterateNext { kind, rid })
                } else {
                    Ok(Self::IterateStop { kind, rid })
                };
            }
        }
        if code == mt::RECLAIM_ISSUE_TICKET {
            let h = input.get(..ISSUE_PREFIX).ok_or(Error::Truncated)?;
            let p = split(
                input,
                ISSUE_PREFIX,
                [
                    usize::from(be16(h, 12)),
                    usize::from(be16(h, 14)),
                    usize::from(be16(h, 10)),
                    0,
                ],
            )?;
            return Ok(Self::IssueTicket {
                rid: be32(h, 4),
                reserved: be16(h, 8),
                key: SecretKeyView::new(p[0])?,
                uri: Uri::decode(p[1])?,
                attributes: AttributeList::new(p[2], ListLimits::IPC)?,
            });
        }
        if code == mt::RECLAIM_REVOKE_TICKET {
            let h = input.get(..TICKET_REQUEST_PREFIX).ok_or(Error::Truncated)?;
            // Actual producer/consumer order is key then ticket; the old struct
            // comment claims the reverse and is not the active wire behavior.
            let p = split(
                input,
                TICKET_REQUEST_PREFIX,
                [usize::from(be16(h, 8)), usize::from(be16(h, 10)), 0, 0],
            )?;
            return Ok(Self::RevokeTicket {
                rid: be32(h, 4),
                key: SecretKeyView::new(p[0])?,
                ticket: Ticket::decode(p[1])?,
            });
        }
        if code == mt::RECLAIM_CONSUME_TICKET {
            let h = input.get(..TICKET_REQUEST_PREFIX).ok_or(Error::Truncated)?;
            let p = split(
                input,
                TICKET_REQUEST_PREFIX,
                [usize::from(be16(h, 8)), usize::from(be16(h, 10)), 0, 0],
            )?;
            return Ok(Self::ConsumeTicket {
                rid: be32(h, 4),
                ticket: Ticket::decode(p[0])?,
                uri: Uri::decode(p[1])?,
            });
        }
        Err(Error::Unsupported)
    }
    fn plan(self) -> Result<Plan<'a>, Error> {
        let rid = self.request_id();
        match self {
            Self::StoreAttribute {
                expiration,
                key,
                attribute,
                ..
            } => store_plan(
                mt::RECLAIM_ATTRIBUTE_STORE,
                rid,
                Some(expiration),
                key,
                Part::Attribute(attribute),
            ),
            Self::StoreCredential {
                expiration,
                key,
                credential,
                ..
            } => store_plan(
                mt::RECLAIM_CREDENTIAL_STORE,
                rid,
                Some(expiration),
                key,
                Part::Credential(credential),
            ),
            Self::DeleteAttribute { key, attribute, .. } => store_plan(
                mt::RECLAIM_ATTRIBUTE_DELETE,
                rid,
                None,
                key,
                Part::Attribute(attribute),
            ),
            Self::DeleteCredential {
                key, credential, ..
            } => store_plan(
                mt::RECLAIM_CREDENTIAL_DELETE,
                rid,
                None,
                key,
                Part::Credential(credential),
            ),
            Self::IterateStart {
                kind,
                key,
                reserved,
                ..
            } => {
                let mut p = Plan::new(kind.start(), ITERATION_PREFIX, rid);
                put16(&mut p.fixed, 8, reserved);
                put16(&mut p.fixed, 10, 36);
                p.parts[0] = Part::Secret(key);
                Ok(p)
            }
            Self::IterateNext { kind, .. } => {
                Ok(Plan::new(kind.next(), ITERATION_CONTROL_LEN, rid))
            }
            Self::IterateStop { kind, .. } => {
                Ok(Plan::new(kind.stop(), ITERATION_CONTROL_LEN, rid))
            }
            Self::IssueTicket {
                key,
                uri,
                attributes,
                reserved,
                ..
            } => {
                let mut p = Plan::new(mt::RECLAIM_ISSUE_TICKET, ISSUE_PREFIX, rid);
                put16(&mut p.fixed, 8, reserved);
                put16(&mut p.fixed, 10, len16(attributes.encoded_len())?);
                put16(&mut p.fixed, 12, 36);
                put16(&mut p.fixed, 14, len16(uri.encoded_len())?);
                p.parts = [
                    Part::Secret(key),
                    Part::Uri(uri),
                    Part::Attributes(attributes),
                    Part::Empty,
                ];
                Ok(p)
            }
            Self::RevokeTicket { key, ticket, .. } => {
                let mut p = Plan::new(mt::RECLAIM_REVOKE_TICKET, TICKET_REQUEST_PREFIX, rid);
                put16(&mut p.fixed, 8, 36);
                put16(&mut p.fixed, 10, len16(ticket.encoded_len())?);
                p.parts[0] = Part::Secret(key);
                p.parts[1] = Part::Ticket(ticket);
                Ok(p)
            }
            Self::ConsumeTicket { ticket, uri, .. } => {
                let mut p = Plan::new(mt::RECLAIM_CONSUME_TICKET, TICKET_REQUEST_PREFIX, rid);
                put16(&mut p.fixed, 8, len16(ticket.encoded_len())?);
                put16(&mut p.fixed, 10, len16(uri.encoded_len())?);
                p.parts[0] = Part::Ticket(ticket);
                p.parts[1] = Part::Uri(uri);
                Ok(p)
            }
        }
    }
}

/// Actual service responses. Missing tickets have contextual meaning (issue
/// failure versus iterator exhaustion); neither a local write nor a STOP is DONE.
#[derive(Clone, Copy, Debug)]
pub enum Response<'a> {
    /// Store/delete status. Official GNUNET_OK is 1; SYSERR is -1.
    Success {
        /// Original RID.
        rid: u32,
        /// Raw signed BE32 status, with unknown values preserved.
        result: i32,
    },
    /// Attribute item, or iteration termination when identity/attribute are None.
    Attribute {
        /// Original RID.
        rid: u32,
        /// Original ignored reserved word.
        reserved: u16,
        /// Legacy unused credential-length field; no credential payload follows.
        credential_len: u16,
        /// Original public identity key, None only for termination.
        identity: Option<ZoneKey>,
        /// Complete attribute, None only for termination.
        attribute: Option<Attribute<'a>>,
    },
    /// Credential item, or empty-key iterator termination.
    Credential {
        /// Original RID.
        rid: u32,
        /// Public identity, None only for termination.
        identity: Option<ZoneKey>,
        /// Credential, None only for termination.
        credential: Option<Credential<'a>>,
    },
    /// Ticket issuance/iteration result. The protocol has NO success field.
    Ticket {
        /// Original RID.
        rid: u32,
        /// Original capability, if one was produced.
        ticket: Option<Ticket<'a>>,
        /// RP URI for iterator items; issuance normally omits it.
        uri: Option<Uri<'a>>,
        /// Newly created opaque presentations, possibly empty.
        presentations: PresentationList<'a>,
    },
    /// Ticket revocation completion, whose BE32 status is preserved.
    Revoked {
        /// Original RID.
        rid: u32,
        /// Raw service status (not an inferred durability or remote ACK).
        result: u32,
    },
    /// Consumed identity/attributes/presentations. `result` is the actual decoded
    /// BE32 word. Pinned C producer mistakenly assigns htons(success) to uint32;
    /// the codec NEVER silently maps its native-endian defect to success.
    Consumed {
        /// Original RID.
        rid: u32,
        /// Raw BE32 word exactly as received or requested for encoding.
        result: u32,
        /// Original reserved word.
        reserved: u16,
        /// Returned public identity; absent bytes remain None, never fabricated.
        identity: Option<ZoneKey>,
        /// Original attributes, possibly empty.
        attributes: AttributeList<'a>,
        /// Original presentations, linked by credential identifier.
        presentations: PresentationList<'a>,
    },
}
impl<'a> Response<'a> {
    /// Original request ID; never a new operation or iterator generation.
    pub const fn request_id(self) -> u32 {
        match self {
            Self::Success { rid, .. }
            | Self::Attribute { rid, .. }
            | Self::Credential { rid, .. }
            | Self::Ticket { rid, .. }
            | Self::Revoked { rid, .. }
            | Self::Consumed { rid, .. } => rid,
        }
    }
    /// Required complete frame size after all field validation.
    pub fn encoded_len(self) -> Result<usize, Error> {
        self.plan()?.encoded_len()
    }
    /// Encode after complete preflight; failure changes no output bytes.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        self.plan()?.encode(out)
    }
    /// Decode one complete active response, including every nested list/object.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let f = Frame::decode(input)?;
        let code = f.header().message_type();
        if code == mt::RECLAIM_SUCCESS_RESPONSE || code == mt::RECLAIM_REVOKE_TICKET_RESULT {
            if input.len() != STATUS_LEN {
                return Err(Error::Malformed);
            }
            let rid = be32(input, 4);
            let result = be32(input, 8);
            return if code == mt::RECLAIM_SUCCESS_RESPONSE {
                Ok(Self::Success {
                    rid,
                    result: i32::from_be_bytes(result.to_be_bytes()),
                })
            } else {
                Ok(Self::Revoked { rid, result })
            };
        }
        if code == mt::RECLAIM_ATTRIBUTE_RESULT {
            let h = input
                .get(..ATTRIBUTE_RESULT_PREFIX)
                .ok_or(Error::Truncated)?;
            let p = split(
                input,
                ATTRIBUTE_RESULT_PREFIX,
                [usize::from(be16(h, 14)), usize::from(be16(h, 10)), 0, 0],
            )?;
            let identity = public_key(p[0])?;
            let attribute = if p[1].is_empty() {
                None
            } else {
                Some(Attribute::decode(p[1])?)
            };
            if identity.is_some() != attribute.is_some() {
                return Err(Error::Malformed);
            }
            return Ok(Self::Attribute {
                rid: be32(h, 4),
                reserved: be16(h, 8),
                credential_len: be16(h, 12),
                identity,
                attribute,
            });
        }
        if code == mt::RECLAIM_CREDENTIAL_RESULT {
            let h = input
                .get(..CREDENTIAL_RESULT_PREFIX)
                .ok_or(Error::Truncated)?;
            let p = split(
                input,
                CREDENTIAL_RESULT_PREFIX,
                [usize::from(be16(h, 10)), usize::from(be16(h, 8)), 0, 0],
            )?;
            let identity = public_key(p[0])?;
            let credential = if p[1].is_empty() {
                None
            } else {
                Some(Credential::decode(p[1])?)
            };
            if identity.is_some() != credential.is_some() {
                return Err(Error::Malformed);
            }
            return Ok(Self::Credential {
                rid: be32(h, 4),
                identity,
                credential,
            });
        }
        if code == mt::RECLAIM_TICKET_RESULT {
            let h = input.get(..TICKET_RESULT_PREFIX).ok_or(Error::Truncated)?;
            let p = split(
                input,
                TICKET_RESULT_PREFIX,
                [
                    usize::from(be16(h, 8)),
                    usize::from(be16(h, 10)),
                    usize::from(be16(h, 12)),
                    0,
                ],
            )?;
            return Ok(Self::Ticket {
                rid: be32(h, 4),
                ticket: if p[0].is_empty() {
                    None
                } else {
                    Some(Ticket::decode(p[0])?)
                },
                uri: if p[1].is_empty() {
                    None
                } else {
                    Some(Uri::decode(p[1])?)
                },
                presentations: PresentationList::new(p[2], ListLimits::IPC)?,
            });
        }
        if code == mt::RECLAIM_CONSUME_TICKET_RESULT {
            let h = input.get(..CONSUMED_PREFIX).ok_or(Error::Truncated)?;
            let p = split(
                input,
                CONSUMED_PREFIX,
                [
                    usize::from(be16(h, 18)),
                    usize::from(be16(h, 14)),
                    usize::from(be16(h, 16)),
                    0,
                ],
            )?;
            return Ok(Self::Consumed {
                rid: be32(h, 4),
                result: be32(h, 8),
                reserved: be16(h, 12),
                identity: public_key(p[0])?,
                attributes: AttributeList::new(p[1], ListLimits::IPC)?,
                presentations: PresentationList::new(p[2], ListLimits::IPC)?,
            });
        }
        Err(Error::Unsupported)
    }
    fn plan(self) -> Result<Plan<'a>, Error> {
        let rid = self.request_id();
        match self {
            Self::Success { result, .. } => {
                let mut p = Plan::new(mt::RECLAIM_SUCCESS_RESPONSE, STATUS_LEN, rid);
                p.fixed[8..12].copy_from_slice(&result.to_be_bytes());
                Ok(p)
            }
            Self::Revoked { result, .. } => {
                let mut p = Plan::new(mt::RECLAIM_REVOKE_TICKET_RESULT, STATUS_LEN, rid);
                put32(&mut p.fixed, 8, result);
                Ok(p)
            }
            Self::Attribute {
                identity,
                attribute,
                reserved,
                credential_len,
                ..
            } => {
                if identity.is_some() != attribute.is_some() {
                    return Err(Error::InvalidInput);
                }
                let mut p = Plan::new(mt::RECLAIM_ATTRIBUTE_RESULT, ATTRIBUTE_RESULT_PREFIX, rid);
                put16(&mut p.fixed, 8, reserved);
                put16(&mut p.fixed, 12, credential_len);
                put16(&mut p.fixed, 14, if identity.is_some() { 36 } else { 0 });
                if let Some(v) = identity {
                    p.parts[0] = Part::Public(v)
                }
                if let Some(v) = attribute {
                    put16(&mut p.fixed, 10, len16(v.encoded_len()?)?);
                    p.parts[1] = Part::Attribute(v)
                }
                Ok(p)
            }
            Self::Credential {
                identity,
                credential,
                ..
            } => {
                if identity.is_some() != credential.is_some() {
                    return Err(Error::InvalidInput);
                }
                let mut p = Plan::new(mt::RECLAIM_CREDENTIAL_RESULT, CREDENTIAL_RESULT_PREFIX, rid);
                put16(&mut p.fixed, 10, if identity.is_some() { 36 } else { 0 });
                if let Some(v) = identity {
                    p.parts[0] = Part::Public(v)
                }
                if let Some(v) = credential {
                    put16(&mut p.fixed, 8, len16(v.encoded_len()?)?);
                    p.parts[1] = Part::Credential(v)
                }
                Ok(p)
            }
            Self::Ticket {
                ticket,
                uri,
                presentations,
                ..
            } => {
                let mut p = Plan::new(mt::RECLAIM_TICKET_RESULT, TICKET_RESULT_PREFIX, rid);
                if let Some(v) = ticket {
                    put16(&mut p.fixed, 8, len16(v.encoded_len())?);
                    p.parts[0] = Part::Ticket(v)
                }
                if let Some(v) = uri {
                    put16(&mut p.fixed, 10, len16(v.encoded_len())?);
                    p.parts[1] = Part::Uri(v)
                }
                put16(&mut p.fixed, 12, len16(presentations.encoded_len())?);
                p.parts[2] = Part::Presentations(presentations);
                Ok(p)
            }
            Self::Consumed {
                identity,
                result,
                reserved,
                attributes,
                presentations,
                ..
            } => {
                let mut p = Plan::new(mt::RECLAIM_CONSUME_TICKET_RESULT, CONSUMED_PREFIX, rid);
                put32(&mut p.fixed, 8, result);
                put16(&mut p.fixed, 12, reserved);
                put16(&mut p.fixed, 14, len16(attributes.encoded_len())?);
                put16(&mut p.fixed, 16, len16(presentations.encoded_len())?);
                put16(&mut p.fixed, 18, if identity.is_some() { 36 } else { 0 });
                if let Some(v) = identity {
                    p.parts[0] = Part::Public(v)
                }
                p.parts[1] = Part::Attributes(attributes);
                p.parts[2] = Part::Presentations(presentations);
                Ok(p)
            }
        }
    }
}

fn len16(n: usize) -> Result<u16, Error> {
    u16::try_from(n).map_err(|_| Error::TooLarge)
}
fn public_key(bytes: &[u8]) -> Result<Option<ZoneKey>, Error> {
    if bytes.is_empty() {
        Ok(None)
    } else {
        ZoneKey::from_wire(bytes).map(Some)
    }
}
fn split(input: &[u8], prefix: usize, lengths: [usize; 4]) -> Result<[&[u8]; 4], Error> {
    let mut at = prefix;
    let mut parts = [&[][..]; 4];
    for (part, len) in parts.iter_mut().zip(lengths) {
        let end = at.checked_add(len).ok_or(Error::Overflow)?;
        *part = input.get(at..end).ok_or(Error::Malformed)?;
        at = end;
    }
    if at != input.len() {
        return Err(Error::Malformed);
    }
    Ok(parts)
}
#[derive(Clone, Copy)]
enum Part<'a> {
    Empty,
    Secret(SecretKeyView<'a>),
    Public(ZoneKey),
    Attribute(Attribute<'a>),
    Credential(Credential<'a>),
    Attributes(AttributeList<'a>),
    Presentations(PresentationList<'a>),
    Ticket(Ticket<'a>),
    Uri(Uri<'a>),
}
impl Part<'_> {
    fn len(self) -> Result<usize, Error> {
        match self {
            Self::Empty => Ok(0),
            Self::Secret(_) | Self::Public(_) => Ok(36),
            Self::Attribute(a) => a.encoded_len(),
            Self::Credential(c) => c.encoded_len(),
            Self::Attributes(a) => Ok(a.encoded_len()),
            Self::Presentations(p) => Ok(p.encoded_len()),
            Self::Ticket(t) => Ok(t.encoded_len()),
            Self::Uri(u) => Ok(u.encoded_len()),
        }
    }
    fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        match self {
            Self::Empty => Ok(0),
            Self::Secret(k) => {
                let d = out.get_mut(..36).ok_or(Error::Capacity)?;
                d.copy_from_slice(k.expose_serialized());
                Ok(36)
            }
            Self::Public(k) => {
                let d = out.get_mut(..36).ok_or(Error::Capacity)?;
                d.copy_from_slice(&k.to_wire());
                Ok(36)
            }
            Self::Attribute(a) => a.encode(out),
            Self::Credential(c) => c.encode(out),
            Self::Attributes(a) => a.encode(out),
            Self::Presentations(p) => p.encode(out),
            Self::Ticket(t) => t.encode(out),
            Self::Uri(u) => u.encode(out),
        }
    }
}
struct Plan<'a> {
    kind: MessageType,
    fixed: [u8; CONSUMED_PREFIX],
    prefix: usize,
    parts: [Part<'a>; 4],
}
impl<'a> Plan<'a> {
    fn new(kind: MessageType, prefix: usize, rid: u32) -> Self {
        let mut fixed = [0; CONSUMED_PREFIX];
        put32(&mut fixed, 4, rid);
        Self {
            kind,
            fixed,
            prefix,
            parts: [Part::Empty; 4],
        }
    }
    fn encoded_len(&self) -> Result<usize, Error> {
        let mut n = self.prefix;
        for part in self.parts {
            n = n.checked_add(part.len()?).ok_or(Error::Overflow)?;
        }
        MessageHeader::from_total_size(self.kind, n)?;
        Ok(n)
    }
    fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len()?;
        let h = MessageHeader::from_total_size(self.kind, n)?;
        let out = out.get_mut(..n).ok_or(Error::Capacity)?;
        out[..self.prefix].copy_from_slice(&self.fixed[..self.prefix]);
        h.encode(out)?;
        let mut at = self.prefix;
        for part in self.parts {
            at += part.encode(&mut out[at..])?;
        }
        Ok(n)
    }
}
fn store_plan<'a>(
    kind: MessageType,
    rid: u32,
    expiration: Option<RelativeTime>,
    key: SecretKeyView<'a>,
    object: Part<'a>,
) -> Result<Plan<'a>, Error> {
    let prefix = if expiration.is_some() {
        STORE_PREFIX
    } else {
        DELETE_PREFIX
    };
    let mut p = Plan::new(kind, prefix, rid);
    if let Some(exp) = expiration {
        p.fixed[4..12].copy_from_slice(&exp.to_be_bytes());
        put32(&mut p.fixed, 12, rid);
        put16(&mut p.fixed, 16, len16(object.len()?)?);
        put16(&mut p.fixed, 18, 36);
    } else {
        put16(&mut p.fixed, 8, len16(object.len()?)?);
        put16(&mut p.fixed, 10, 36);
    }
    p.parts[0] = Part::Secret(key);
    p.parts[1] = object;
    Ok(p)
}

/// A local operation callback fence, with no invented CANCEL wire command.
/// Cancel suppresses delivery but cannot undo bytes already sent or service work.
pub struct Callback {
    rid: u32,
    canceled: bool,
}
impl Callback {
    /// Bind a callback to the owner's original RID; no RID allocation occurs.
    pub const fn new(rid: u32) -> Self {
        Self {
            rid,
            canceled: false,
        }
    }
    /// Original RID, including after cancellation.
    pub const fn request_id(&self) -> u32 {
        self.rid
    }
    /// Suppress this callback locally, returning whether this was the first cancel.
    pub fn cancel(&mut self) -> bool {
        let first = !self.canceled;
        self.canceled = true;
        first
    }
    /// Whether this still-live local callback may receive an original-ID response.
    /// An actual MQ owner must additionally enforce its own original source epoch.
    pub const fn accepts(&self, rid: u32) -> bool {
        !self.canceled && self.rid == rid
    }
}
impl fmt::Debug for Callback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Callback")
            .field("rid", &self.rid)
            .field("canceled", &self.canceled)
            .finish()
    }
}
