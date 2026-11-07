//! Actual pinned RECLAIM STRING/JWT credential helpers, with bounded caller
//! storage and explicitly UNVERIFIED claims. No key, crypto, trust store, I/O or
//! C plugin ABI is invoked. PABC is not built by the pinned Meson plugin file.
#![no_std]
#![forbid(unsafe_code)]
use core::fmt;
use gnunet_reclaim::{
    AttributeList, AttributeType, Credential, CredentialType, Presentation, Sensitive,
};
use gnunet_types::Error as Fault;
use gnunet_wire::official::AbsoluteTime;
#[cfg(feature = "attributes")]
mod attributes;
mod json;
mod value;
#[cfg(feature = "attributes")]
pub use attributes::NameScratch;
pub use json::{JsonString, Nest, Token};
pub use value::{Claim, ClaimIter, JsonValue, ValueKind};

/// Actual provider availability in src/plugin/reclaim/meson.build at the pin.
pub const JWT_ACTIVE: bool = true;
/// PABC source is present but has no actual Meson build target/dependency.
pub const PABC_ACTIVE: bool = false;
/// This path parses/copies credentials; it does not grant issuer authenticity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Assurance {
    /// No signature/proof, issuer trust, audience or clock policy was verified.
    Unverified,
}
/// Original type namespace for a conversion failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Family {
    /// Public attribute format namespace.
    Attribute,
    /// Public credential/presentation format namespace.
    Credential,
}
/// Precise bounded helper stage, with no private diagnostic strings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    /// Pure text/value conversion.
    Conversion,
    /// Encoded JWT payload selection/base64url decoding.
    Decode,
    /// JSON validation/token workspace admission.
    Json,
    /// Claim/issuer/expiration extraction.
    Claims,
    /// Presentation creation or original binding check.
    Presentation,
    /// Exact Unicode lowercase/NFD name conversion.
    Name,
    /// JSON-derived attribute text formatting.
    Format,
}
/// Raw plugin type and original classified failure; never a false empty success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Failure {
    /// Exact original type namespace.
    pub family: Family,
    /// Exact original numeric plugin type, including unknown extensions.
    pub kind: u32,
    /// Stage that actually failed.
    pub stage: Stage,
    /// Original finite-capacity, malformed, unsupported or unavailable cause.
    pub cause: Fault,
}
impl Failure {
    pub(crate) const fn credential(kind: CredentialType, stage: Stage, cause: Fault) -> Self {
        Self {
            family: Family::Credential,
            kind: kind.value(),
            stage,
            cause,
        }
    }
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} type {} {:?}: {}",
            self.family, self.kind, self.stage, self.cause
        )
    }
}
impl core::error::Error for Failure {}

/// Explicit input/metadata/nesting/work limits; buffers can impose smaller bounds.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum original credential/presentation bytes, including ignored C tail.
    pub input_bytes: usize,
    /// Maximum decoded payload bytes.
    pub payload_bytes: usize,
    /// Maximum JSON value/key metadata tokens.
    pub nodes: usize,
    /// Maximum JSON container nesting, at most64 (also bounds formatting stack).
    pub depth: usize,
    /// Maximum extracted attributes, including flattened address children.
    pub attributes: usize,
    /// Maximum parsing/duplicate-check work steps, including compared key scalars.
    pub work: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            input_bytes: 65535,
            payload_bytes: 49152,
            nodes: 4096,
            depth: 64,
            attributes: 1024,
            work: 4_000_000,
        }
    }
}
impl Limits {
    fn validate(self) -> Result<(), Fault> {
        if self.input_bytes == 0
            || self.payload_bytes == 0
            || self.nodes == 0
            || self.depth == 0
            || self.depth > 64
            || self.attributes == 0
            || self.work == 0
        {
            return Err(Fault::InvalidInput);
        }
        Ok(())
    }
}
/// Borrowed caller workspace. Drop and every parse failure erase ALL supplied
/// decoded payload/token/nesting storage. A live Claims borrow prevents reuse.
/// No allocation or recursively allocated generic JSON tree is used.
pub struct Workspace<'a> {
    inner: gnunet_json::Workspace<'a>,
}
impl<'a> Workspace<'a> {
    /// Bind caller buffers. Their previous contents are erased immediately.
    pub fn new(payload: &'a mut [u8], tokens: &'a mut [Token], stack: &'a mut [Nest]) -> Self {
        Self {
            inner: gnunet_json::Workspace::new(payload, tokens, stack),
        }
    }
    /// Parse a JWT credential with the source plugin's second-nonempty-dot
    /// segment selection. Header/signature are neither required nor verified.
    pub fn credential(
        &mut self,
        credential: Credential<'_>,
        limits: Limits,
    ) -> Result<Claims<'_>, Failure> {
        self.parse(credential.kind, credential.value, limits)
    }
    /// Parse a presentation without inferring signature/proof/source authority.
    pub fn presentation(
        &mut self,
        presentation: Presentation<'_>,
        limits: Limits,
    ) -> Result<Claims<'_>, Failure> {
        self.parse(presentation.kind, presentation.value, limits)
    }
    /// Parse raw typed payload using the shared bounded/zeroizing JSON owner.
    pub fn parse(
        &mut self,
        kind: CredentialType,
        input: Sensitive<'_>,
        limits: Limits,
    ) -> Result<Claims<'_>, Failure> {
        self.clear();
        limits
            .validate()
            .map_err(|e| Failure::credential(kind, Stage::Decode, e))?;
        if kind != CredentialType::JWT {
            return Err(Failure::credential(
                kind,
                Stage::Decode,
                if kind == CredentialType::PABC {
                    Fault::Unavailable
                } else {
                    Fault::Unsupported
                },
            ));
        }
        if input.len() > limits.input_bytes {
            return Err(Failure::credential(kind, Stage::Decode, Fault::Capacity));
        }
        let text = gnunet_reclaim::objects::string_bytes(input);
        let body = text
            .split(|b| *b == b'.')
            .filter(|s| !s.is_empty())
            .nth(1)
            .ok_or(Failure::credential(kind, Stage::Decode, Fault::Malformed))?;
        let stage = core::cell::Cell::new(Stage::Decode);
        let document = self
            .inner
            .parse_with_check(
                |out| {
                    let n = decode_url(body, out)?;
                    stage.set(Stage::Json);
                    Ok(n)
                },
                gnunet_json::Limits {
                    bytes: limits.payload_bytes,
                    nodes: limits.nodes,
                    depth: limits.depth,
                    work: limits.work,
                },
                |doc| {
                    if doc.root().kind() != ValueKind::Object {
                        return Err(Fault::Malformed);
                    }
                    stage.set(Stage::Claims);
                    if (Claims { document: doc })
                        .attributes()
                        .take(limits.attributes.saturating_add(1))
                        .count()
                        > limits.attributes
                    {
                        return Err(Fault::Capacity);
                    }
                    Ok(())
                },
            )
            .map_err(|e| Failure::credential(kind, stage.get(), e))?;
        Ok(Claims { document })
    }
    /// Erase full original scratch. Live claims prevent safe reuse/drop.
    pub fn clear(&mut self) {
        self.inner.clear();
    }
}
impl fmt::Debug for Workspace<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Workspace([REDACTED])")
    }
}

/// Immutable borrowed JWT payload/claims, tied to its zeroizing Workspace.
/// Arbitrary JSON grammar is checked, with explicit depth/node/work capacities.
pub struct Claims<'a> {
    document: gnunet_json::Document<'a>,
}
impl<'a> Claims<'a> {
    /// Explicit assurance: successful extraction is never signature validation.
    pub const fn assurance(&self) -> Assurance {
        Assurance::Unverified
    }
    /// Borrow the decoded JSON bytes explicitly while the original workspace lives.
    pub fn expose_payload(&self) -> Sensitive<'a> {
        Sensitive::new(self.document.expose_json())
    }
    /// Actual public plugin attribute selection: skip iss/jti/exp/iat/nbf/aud,
    /// flatten an object-valued address, and skip a nonobject address.
    pub fn attributes(&self) -> ClaimIter<'a> {
        ClaimIter::new(self.document.root())
    }
    /// Decoded issuer string; missing/wrong-type is an actual classified failure.
    pub fn issuer(&self) -> Result<JsonString<'a>, Failure> {
        self.lookup(b"iss")
            .ok_or(Failure::credential(
                CredentialType::JWT,
                Stage::Claims,
                Fault::NotFound,
            ))?
            .string()
            .map_err(|e| Failure::credential(CredentialType::JWT, Stage::Claims, e))
    }
    /// Integer NumericDate seconds converted to microseconds with checked
    /// nonnegative multiplication. Negative/overflow values never become far-
    /// future validity by unsigned wrapping, unlike the C arithmetic defect.
    pub fn expiration(&self) -> Result<AbsoluteTime, Failure> {
        let value = self.lookup(b"exp").ok_or(Failure::credential(
            CredentialType::JWT,
            Stage::Claims,
            Fault::NotFound,
        ))?;
        let seconds = value
            .integer()
            .map_err(|e| Failure::credential(CredentialType::JWT, Stage::Claims, e))?;
        let micros = u64::try_from(seconds)
            .map_err(|_| {
                Failure::credential(CredentialType::JWT, Stage::Claims, Fault::InvalidInput)
            })?
            .checked_mul(1_000_000)
            .ok_or(Failure::credential(
                CredentialType::JWT,
                Stage::Claims,
                Fault::Overflow,
            ))?;
        Ok(AbsoluteTime::from_micros(micros))
    }
    /// Lookup one decoded top-level key without allocation or Unicode conversion.
    pub fn lookup(&self, key: &[u8]) -> Option<JsonValue<'a>> {
        self.document
            .root()
            .get(key)
            .map(|inner| JsonValue { inner })
    }
}
impl fmt::Debug for Claims<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Claims([REDACTED, UNVERIFIED])")
    }
}

/// Actual JWT plugin presentation: complete original bytes, without selective
/// disclosure, parsing or verification. The library wrapper binds credential ID.
/// This borrowed output can be copied once by the caller's bounded owned Pool.
pub fn presentation<'a>(
    credential: Credential<'a>,
    _selected: AttributeList<'_>,
) -> Result<Presentation<'a>, Failure> {
    if credential.kind != CredentialType::JWT {
        return Err(Failure::credential(
            credential.kind,
            Stage::Presentation,
            if credential.kind == CredentialType::PABC {
                Fault::Unavailable
            } else {
                Fault::Unsupported
            },
        ));
    }
    let presentation = Presentation::new(credential.id, credential.kind, credential.value);
    presentation
        .encoded_len()
        .map_err(|e| Failure::credential(credential.kind, Stage::Presentation, e))?;
    Ok(presentation)
}
/// Check the actual full-payload JWT presentation binding to an original local
/// credential. This compares ID/type/bytes; even a match is explicitly unverified
/// with respect to any issuer, JWT signature, claim truth, audience or time policy.
pub fn check_binding(
    presentation: Presentation<'_>,
    credential: Credential<'_>,
) -> Result<Assurance, Failure> {
    if credential.kind != CredentialType::JWT {
        return Err(Failure::credential(
            credential.kind,
            Stage::Presentation,
            if credential.kind == CredentialType::PABC {
                Fault::Unavailable
            } else {
                Fault::Unsupported
            },
        ));
    }
    if presentation.kind != credential.kind
        || presentation.credential != credential.id
        || presentation.value.expose() != credential.value.expose()
    {
        return Err(Failure::credential(
            presentation.kind,
            Stage::Presentation,
            Fault::Authentication,
        ));
    }
    Ok(Assurance::Unverified)
}
/// BASIC STRING conversion, matching the plugin's strlen+1 data convention.
pub fn attribute_from_string(
    kind: AttributeType,
    input: &[u8],
    out: &mut [u8],
) -> Result<usize, Failure> {
    if kind != AttributeType::STRING {
        return Err(Failure {
            family: Family::Attribute,
            kind: kind.value(),
            stage: Stage::Conversion,
            cause: Fault::Unsupported,
        });
    }
    gnunet_reclaim::objects::string_value(input, out).map_err(|cause| Failure {
        family: Family::Attribute,
        kind: kind.value(),
        stage: Stage::Conversion,
        cause,
    })
}
/// Actual JWT/PABC source text conversion (copy plus NUL), NOT credential/proof
/// creation. PABC remains inactive for semantic inspection/presentation methods.
pub fn credential_from_string(
    kind: CredentialType,
    input: &[u8],
    out: &mut [u8],
) -> Result<usize, Failure> {
    if kind != CredentialType::JWT && kind != CredentialType::PABC {
        return Err(Failure::credential(
            kind,
            Stage::Conversion,
            Fault::Unsupported,
        ));
    }
    gnunet_reclaim::objects::string_value(input, out)
        .map_err(|e| Failure::credential(kind, Stage::Conversion, e))
}
/// Exact bounded text view used by all three source conversion plugins.
pub fn value_string(value: Sensitive<'_>) -> Sensitive<'_> {
    Sensitive::new(gnunet_reclaim::objects::string_bytes(value))
}
fn decode_url(input: &[u8], out: &mut [u8]) -> Result<usize, Fault> {
    let padding = input.iter().rev().take_while(|b| **b == b'=').count();
    if padding > 2 {
        return Err(Fault::Malformed);
    }
    let data = &input[..input.len() - padding];
    let remainder = data.len() % 4;
    if remainder == 1
        || data.is_empty()
        || (padding != 0 && (!input.len().is_multiple_of(4) || padding != 4 - remainder))
    {
        return Err(Fault::Malformed);
    }
    let n = data.len().checked_mul(6).ok_or(Fault::Overflow)? / 8;
    if n > out.len() {
        return Err(Fault::Capacity);
    }
    let decode = |b: u8| -> Result<u8, Fault> {
        match b {
            b'A'..=b'Z' => Ok(b - b'A'),
            b'a'..=b'z' => Ok(b - b'a' + 26),
            b'0'..=b'9' => Ok(b - b'0' + 52),
            b'-' => Ok(62),
            b'_' => Ok(63),
            _ => Err(Fault::Malformed),
        }
    };
    for b in data {
        decode(*b)?;
    }
    let last = decode(*data.last().ok_or(Fault::Malformed)?)?;
    if (remainder == 2 && last & 15 != 0) || (remainder == 3 && last & 3 != 0) {
        return Err(Fault::Malformed);
    }
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    let mut at = 0;
    for b in data {
        accumulator = (accumulator << 6) | u32::from(decode(*b)?);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out[at] = ((accumulator >> bits) & 255) as u8;
            at += 1;
        }
        accumulator &= (1 << bits) - 1;
    }
    Ok(n)
}

/// Public BASIC format name. Unknown plugin types are not registered here.
pub const fn attribute_type_name(kind: AttributeType) -> Option<&'static str> {
    if kind.value() == 1 {
        Some("STRING")
    } else {
        None
    }
}
/// Known source credential format names; PABC's known name does NOT claim its
/// inactive cryptographic plugin is available in the pinned build.
pub const fn credential_type_name(kind: CredentialType) -> Option<&'static str> {
    match kind.value() {
        1 => Some("JWT"),
        2 => Some("PABC"),
        _ => None,
    }
}
/// Case-insensitive public ASCII BASIC type-name conversion.
pub fn attribute_type(name: &[u8]) -> Option<AttributeType> {
    if name.eq_ignore_ascii_case(b"STRING") {
        Some(AttributeType::STRING)
    } else {
        None
    }
}
/// Case-insensitive source type-name conversion, retaining PABC as a known
/// opaque format independently of actual provider availability.
pub fn credential_type(name: &[u8]) -> Option<CredentialType> {
    if name.eq_ignore_ascii_case(b"JWT") {
        Some(CredentialType::JWT)
    } else if name.eq_ignore_ascii_case(b"PABC") {
        Some(CredentialType::PABC)
    } else {
        None
    }
}
/// Type-checked BASIC value-to-string conversion, borrowing the C-visible prefix.
pub fn attribute_value_string(
    kind: AttributeType,
    value: Sensitive<'_>,
) -> Result<Sensitive<'_>, Failure> {
    if kind != AttributeType::STRING {
        return Err(Failure {
            family: Family::Attribute,
            kind: kind.value(),
            stage: Stage::Conversion,
            cause: Fault::Unsupported,
        });
    }
    Ok(value_string(value))
}
/// Type-checked opaque JWT/PABC source value-to-string conversion. This performs
/// no credential parsing, proof generation or signature verification.
pub fn credential_value_string(
    kind: CredentialType,
    value: Sensitive<'_>,
) -> Result<Sensitive<'_>, Failure> {
    if kind != CredentialType::JWT && kind != CredentialType::PABC {
        return Err(Failure::credential(
            kind,
            Stage::Conversion,
            Fault::Unsupported,
        ));
    }
    Ok(value_string(value))
}
