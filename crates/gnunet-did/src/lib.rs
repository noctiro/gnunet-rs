//! Official `did:gns:` identifiers, Ed25519-2020 document template and bound
//! DID_DOCUMENT/current-C TXT selection. No allocation, crypto, service or IO.
#![no_std]
#![forbid(unsafe_code)]
use base64ct::{Base64UrlUnpadded, Encoding};
use gnunet_gnsrecord::{RecordData, RecordSet, RecordType, ZONE_TEXT_LEN, ZoneKey, ZoneKeyType};
use gnunet_json::{ValueKind, Workspace};
use gnunet_types::Error;
/// Exact active GNUnet DID method prefix.
pub const METHOD_PREFIX: &[u8] = b"did:gns:";
/// Active library lookup/store label; never the unrelated root label `@`.
pub const DOCUMENT_LABEL: &[u8] = b"didd";
/// Complete DID bytes, excluding a NUL terminator.
pub const DID_BYTES: usize = 8 + ZONE_TEXT_LEN;
/// Actual `did_core.h` default365days, in relative microseconds.
pub const DEFAULT_EXPIRATION_MICROS: u64 = 365 * 24 * 60 * 60 * 1_000_000;
/// Public Ed25519 multicodec+multibase base64url representation bytes.
pub const MULTIBASE_BYTES: usize = 47;
/// An exact typed public GNUnet zone identifier, not private material or an
/// assertion that the public point/JSON/controller is cryptographically verified.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Did(ZoneKey);
impl Did {
    /// Bind an already typed public zone without deriving a secret/public key.
    #[must_use]
    pub const fn from_public(zone: ZoneKey) -> Self {
        Self(zone)
    }
    /// Decode exactly one complete `did:gns:` typed36-byte public identifier.
    /// Trailing paths/fragments/whitespace are refused; C's scanf truncation is
    /// not a second DID method. Base32 aliases/case follow the official decoder.
    pub fn parse(input: &str) -> Result<Self, Error> {
        if input.len() != DID_BYTES || !input.as_bytes().starts_with(METHOD_PREFIX) {
            return Err(Error::Malformed);
        }
        Ok(Self(ZoneKey::from_ztld(
            input.get(METHOD_PREFIX.len()..).ok_or(Error::Malformed)?,
        )?))
    }
    /// Original public zone for the explicit GNS query port.
    #[must_use]
    pub const fn zone(self) -> ZoneKey {
        self.0
    }
    /// Canonical uppercase method-specific identifier; no key derivation occurs.
    pub fn write(self, out: &mut [u8]) -> Result<&str, Error> {
        if out.len() < DID_BYTES {
            return Err(Error::Capacity);
        }
        let mut key = [0; ZONE_TEXT_LEN];
        self.0.write_ztld(&mut key)?;
        out[..8].copy_from_slice(METHOD_PREFIX);
        out[8..DID_BYTES].copy_from_slice(&key);
        core::str::from_utf8(&out[..DID_BYTES]).map_err(|_| Error::Malformed)
    }
}
/// Encode the actual pinned default-template multibase value. Only EdDSA is
/// meaningful for this Ed25519VerificationKey2020 template. No crypto executes.
pub fn multibase(zone: ZoneKey, out: &mut [u8]) -> Result<&str, Error> {
    if zone.kind() != ZoneKeyType::Edkey {
        return Err(Error::Unsupported);
    }
    if out.len() < MULTIBASE_BYTES {
        return Err(Error::Capacity);
    }
    let mut raw = [0; 34];
    raw[..2].copy_from_slice(&[0xed, 0x01]);
    raw[2..].copy_from_slice(zone.key());
    let mut encoded = [0; 46];
    let text = Base64UrlUnpadded::encode(&raw, &mut encoded).map_err(|_| Error::Capacity)?;
    if text.len() != 46 {
        return Err(Error::Malformed);
    }
    out[0] = b'u';
    out[1..MULTIBASE_BYTES].copy_from_slice(text.as_bytes());
    core::str::from_utf8(&out[..MULTIBASE_BYTES]).map_err(|_| Error::Malformed)
}
/// Default-template JSON size. Call with an EdDSA zone through `template` to
/// check its role; formatting whitespace is not a wire/verification requirement.
pub const TEMPLATE_BYTES: usize = A.len()
    + DID_BYTES
    + B.len()
    + DID_BYTES
    + C.len()
    + DID_BYTES
    + D.len()
    + MULTIBASE_BYTES
    + E.len();
const A:&[u8]=b"{\"@context\":[\"https://www.w3.org/ns/did/v1\",\"https://w3id.org/security/suites/ed25519-2020/v1\"],\"id\":\"";
const B: &[u8] = b"\",\"verificationMethod\":[{\"id\":\"";
const C: &[u8] = b"#key-1\",\"type\":\"Ed25519VerificationKey2020\",\"controller\":\"";
const D: &[u8] = b"\",\"publicKeyMultibase\":\"";
const E: &[u8] = b"\"}],\"authentication\":[\"#key-1\"],\"assertionMethod\":[\"#key-1\"]}";
/// Write the exact default-template fields built by pinned did_helper.c, using
/// the existing base64 codec. Output is JSON only, with no C terminator. Failure
/// leaves output untouched and never creates keys or signatures.
pub fn template(did: Did, out: &mut [u8]) -> Result<usize, Error> {
    let mut id = [0; DID_BYTES];
    did.write(&mut id)?;
    let mut key = [0; MULTIBASE_BYTES];
    multibase(did.zone(), &mut key)?;
    if out.len() < TEMPLATE_BYTES {
        return Err(Error::Capacity);
    }
    let mut at = 0;
    for part in [A, &id, B, &id, C, &id, D, &key, E] {
        out[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
    Ok(at)
}
/// Strip at most one actual C terminator while rejecting ignored embedded tails.
/// Authoritative document producers may also supply exact unterminated JSON.
pub fn record_json(bytes: &[u8]) -> Result<&[u8], Error> {
    let body = bytes.strip_suffix(&[0]).unwrap_or(bytes);
    if body.contains(&0) {
        return Err(Error::Malformed);
    }
    Ok(body)
}
/// Validate complete JSON object and a method-specific `id` bound to exactly the
/// requested public zone. This is format/source binding, NOT proof/signature or
/// W3C schema/controller authentication. Shared JSON limits/workspace apply.
pub fn check_document(
    did: Did,
    input: &[u8],
    workspace: &mut Workspace<'_>,
    limits: gnunet_json::Limits,
) -> Result<(), Error> {
    let document = workspace.parse(input, limits)?;
    let root = document.root();
    if root.kind() != ValueKind::Object {
        return Err(Error::Malformed);
    }
    let id = root.get(b"id").ok_or(Error::Authentication)?.string()?;
    if id.decoded_len()? != DID_BYTES {
        return Err(Error::Authentication);
    }
    let mut value = [0; DID_BYTES];
    id.decode(&mut value)?;
    let actual = Did::parse(core::str::from_utf8(&value).map_err(|_| Error::Malformed)?)?;
    if actual != did {
        return Err(Error::Authentication);
    }
    Ok(())
}
/// Actual original record form; no arbitrary TXT is interpreted as a document.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordForm {
    /// Official registered DID_DOCUMENT65561.
    Authoritative,
    /// Current pinned DID_create incorrectly emits TXT16 at the same label.
    /// Accepted only after the same full JSON+exact-DID admission check.
    CurrentProducerTxt,
}
/// Borrowed actual matching original record data. Safe Debug reveals no body.
#[derive(Clone, Copy)]
pub struct Document<'a> {
    did: Did,
    body: &'a [u8],
    form: RecordForm,
}
impl<'a> Document<'a> {
    /// Expected method-specific public source identity.
    #[must_use]
    pub const fn did(self) -> Did {
        self.did
    }
    /// Complete validated original JSON bytes, excluding a possible C terminator.
    #[must_use]
    pub const fn json(self) -> &'a [u8] {
        self.body
    }
    /// Actual selected record form.
    #[must_use]
    pub const fn form(self) -> RecordForm {
        self.form
    }
}
impl core::fmt::Debug for Document<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DidDocument")
            .field("did", &self.did)
            .field("bytes", &self.body.len())
            .field("form", &self.form)
            .finish()
    }
}
/// Check whether this is an actual managed canonical-label document record.
/// Malformed/mismatched authoritative records fail closed. Unrelated TXT is
/// preserved; resource/work refusals are never guessed to mean unrelated TXT.
pub fn managed<'a>(
    record: RecordData<'a>,
    did: Did,
    workspace: &mut Workspace<'_>,
    limits: gnunet_json::Limits,
) -> Result<Option<Document<'a>>, Error> {
    if record.record_type != RecordType::DID_DOCUMENT && record.record_type != RecordType::TXT {
        return Ok(None);
    }
    let checked = record_json(record.data).and_then(|body| {
        check_document(did, body, workspace, limits)?;
        Ok(body)
    });
    match checked {
        Ok(body) => Ok(Some(Document {
            did,
            body,
            form: if record.record_type == RecordType::DID_DOCUMENT {
                RecordForm::Authoritative
            } else {
                RecordForm::CurrentProducerTxt
            },
        })),
        Err(
            Error::Malformed
            | Error::Authentication
            | Error::InvalidInput
            | Error::Unsupported
            | Error::Truncated,
        ) if record.record_type == RecordType::TXT => Ok(None),
        Err(error) => Err(error),
    }
}
/// Choose one bound actual document from one original ANY lookup. Authoritative
/// records take precedence; conflicting authoritative or matching TXT documents
/// are refused rather than picking an arbitrary result. No second lookup occurs.
pub fn select<'a>(
    records: RecordSet<'a>,
    did: Did,
    workspace: &mut Workspace<'_>,
    limits: gnunet_json::Limits,
) -> Result<Option<Document<'a>>, Error> {
    for form in [RecordForm::Authoritative, RecordForm::CurrentProducerTxt] {
        let mut selected: Option<Document<'a>> = None;
        for record in records.iter() {
            let record = record?;
            let wanted = if form == RecordForm::Authoritative {
                RecordType::DID_DOCUMENT
            } else {
                RecordType::TXT
            };
            if record.record_type != wanted {
                continue;
            }
            let Some(document) = managed(record, did, workspace, limits)? else {
                continue;
            };
            if let Some(old) = selected {
                if old.json() != document.json() {
                    return Err(Error::Conflict);
                }
            } else {
                selected = Some(document);
            }
        }
        if selected.is_some() {
            return Ok(selected);
        }
    }
    Ok(None)
}
