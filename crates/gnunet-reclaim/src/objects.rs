//! Public object encodings from reclaim_attribute/credential.c; no C layout casts.
use crate::{be16, be32, put16, put32};
use core::fmt;
use gnunet_gnsrecord::ZoneKey;
use gnunet_types::Error;

/// Exact serialized attribute prefix, excluding name/value payloads.
pub const ATTRIBUTE_PREFIX: usize = 80;
/// Exact serialized credential prefix, excluding name/value payloads.
pub const CREDENTIAL_PREFIX: usize = 48;
/// Exact serialized presentation prefix; its legacy name length is ignored.
pub const PRESENTATION_PREFIX: usize = 48;
/// Maximum bytes INCLUDING the terminator in the public ticket name array.
pub const TICKET_NAME_BYTES: usize = 128;
/// The public RP URI buffer limit INCLUDING its final NUL.
pub const RP_URI_BYTES: usize = 256;

/// Opaque 256-bit attribute/credential identifier, never generated here.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Identifier([u8; 32]);
impl Identifier {
    /// The self-asserted/no-credential sentinel.
    pub const ZERO: Self = Self([0; 32]);
    /// Preserve an exact caller-supplied identifier.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    /// Decode the exact 32-byte public serialized identifier/reference.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self(bytes.try_into().map_err(|_| Error::Malformed)?))
    }
    /// Encode the identifier/reference in caller storage. Failure changes nothing.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let out = out.get_mut(..32).ok_or(Error::Capacity)?;
        out.copy_from_slice(&self.0);
        Ok(32)
    }
    /// Borrow its exact identifier bytes explicitly.
    pub const fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
    /// Test the all-zero sentinel; this does not establish identity validity.
    pub fn is_zero(self) -> bool {
        self.0.iter().fold(0, |a, b| a | b) == 0
    }
}
impl fmt::Debug for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Identifier([REDACTED])")
    }
}

/// Sensitive borrowed bytes. No ownership, allocation, verification or erasure.
#[derive(Clone, Copy)]
pub struct Sensitive<'a>(&'a [u8]);
impl<'a> Sensitive<'a> {
    /// Wrap bytes without claiming their contents are trustworthy.
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }
    /// Explicitly expose the bytes while retaining the original owner's lifetime.
    pub const fn expose(self) -> &'a [u8] {
        self.0
    }
    /// Byte length without exposing data in diagnostics.
    pub const fn len(self) -> usize {
        self.0.len()
    }
    /// Whether the byte string is empty.
    pub const fn is_empty(self) -> bool {
        self.0.is_empty()
    }
}
impl fmt::Debug for Sensitive<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sensitive([REDACTED])")
    }
}

/// Length-delimited object name. Serialized names have NO terminating NUL.
/// Decoder retains embedded NUL tails, which the C deserializer stores but its
/// later C-string consumers ignore. New names are canonical and contain no NUL.
#[derive(Clone, Copy)]
pub struct Name<'a>(&'a [u8]);
impl<'a> Name<'a> {
    /// Construct a canonical exact name, without case/Unicode conversion.
    /// C convenience constructors lowercase names; the serializer does not.
    pub fn new(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.contains(&0) {
            return Err(Error::InvalidInput);
        }
        u16::try_from(bytes.len()).map_err(|_| Error::TooLarge)?;
        Ok(Self(bytes))
    }
    pub(crate) fn decode(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }
    /// Original length-delimited bytes, including any decoded ignored tail.
    pub const fn wire_bytes(self) -> &'a [u8] {
        self.0
    }
    /// Bytes observed by an official C-string consumer after deserialization.
    pub fn bytes(self) -> &'a [u8] {
        &self.0[..self.0.iter().position(|b| *b == 0).unwrap_or(self.0.len())]
    }
    /// Whether later serialization through C would preserve the whole name.
    pub fn is_canonical(self) -> bool {
        !self.0.contains(&0)
    }
}
impl fmt::Debug for Name<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Name([REDACTED])")
    }
}

macro_rules! value_type {
    ($name:ident, $doc:literal) => {
        #[doc=$doc]
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub struct $name(u32);
        impl $name {
            /// Preserve the full public/plugin numeric type namespace.
            pub const fn new(value: u32) -> Self {
                Self(value)
            }
            /// Exact host-order numeric value, serialized as BE32.
            pub const fn value(self) -> u32 {
                self.0
            }
        }
    };
}
value_type!(
    AttributeType,
    "An attribute type; unknown plugin values remain opaque."
);
impl AttributeType {
    /// Unspecified attribute type.
    pub const NONE: Self = Self(0);
    /// Official basic STRING plugin value (its C-string conversion includes NUL).
    pub const STRING: Self = Self(1);
}
value_type!(
    CredentialType,
    "A credential/presentation format; decoding is not verification."
);
impl CredentialType {
    /// Unspecified credential format.
    pub const NONE: Self = Self(0);
    /// JWT payload bytes, opaque to this codec.
    pub const JWT: Self = Self(1);
    /// PABC payload bytes, opaque to this codec.
    pub const PABC: Self = Self(2);
}

/// One attribute with original IDs, flags and a borrowed sensitive payload.
#[derive(Clone, Copy, Debug)]
pub struct Attribute<'a> {
    /// Exact numeric attribute format.
    pub kind: AttributeType,
    /// Raw official flags; no undefined bits are discarded.
    pub flags: u32,
    /// Attribute identifier; zero is allowed before service assignment.
    pub id: Identifier,
    /// Referenced credential, or zero for self-asserted data.
    pub credential: Identifier,
    /// Length-delimited name, without normalization by the codec.
    pub name: Name<'a>,
    /// Original two ignored alignment words; canonical producers use zero.
    pub reserved: [u16; 2],
    /// Value bytes, not interpreted or authenticated.
    pub value: Sensitive<'a>,
}
impl<'a> Attribute<'a> {
    /// Canonical object with zero flags/reserved words.
    pub const fn new(
        id: Identifier,
        credential: Identifier,
        kind: AttributeType,
        name: Name<'a>,
        value: Sensitive<'a>,
    ) -> Self {
        Self {
            kind,
            flags: 0,
            id,
            credential,
            name,
            reserved: [0; 2],
            value,
        }
    }
    /// Complete serialized length; each variable field must fit BE16.
    pub fn encoded_len(self) -> Result<usize, Error> {
        length(ATTRIBUTE_PREFIX, self.name.0.len(), self.value.len())
    }
    /// Encode into caller storage; a validation/capacity failure changes nothing.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len()?;
        let out = out.get_mut(..n).ok_or(Error::Capacity)?;
        put32(out, 0, self.kind.value());
        put32(out, 4, self.flags);
        out[8..40].copy_from_slice(self.id.bytes());
        out[40..72].copy_from_slice(self.credential.bytes());
        put16(out, 72, self.reserved[0]);
        put16(out, 74, self.name.0.len() as u16);
        put16(out, 76, self.reserved[1]);
        put16(out, 78, self.value.len() as u16);
        let split = ATTRIBUTE_PREFIX + self.name.0.len();
        out[ATTRIBUTE_PREFIX..split].copy_from_slice(self.name.0);
        out[split..].copy_from_slice(self.value.expose());
        Ok(n)
    }
    /// Decode exactly one object, refusing silent trailing bytes.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        let (v, n) = Self::decode_prefix(bytes)?;
        if n != bytes.len() {
            return Err(Error::Malformed);
        }
        Ok(v)
    }
    /// Decode one object and report the exact consumed bytes for list traversal.
    pub fn decode_prefix(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        let h = bytes.get(..ATTRIBUTE_PREFIX).ok_or(Error::Truncated)?;
        let nl = usize::from(be16(h, 74));
        let dl = usize::from(be16(h, 78));
        let n = length(ATTRIBUTE_PREFIX, nl, dl)?;
        let b = bytes.get(..n).ok_or(Error::Truncated)?;
        let id = Identifier(b[8..40].try_into().map_err(|_| Error::Malformed)?);
        let credential = Identifier(b[40..72].try_into().map_err(|_| Error::Malformed)?);
        Ok((
            Self {
                kind: AttributeType::new(be32(h, 0)),
                flags: be32(h, 4),
                id,
                credential,
                name: Name::decode(&b[ATTRIBUTE_PREFIX..ATTRIBUTE_PREFIX + nl]),
                reserved: [be16(h, 72), be16(h, 76)],
                value: Sensitive::new(&b[ATTRIBUTE_PREFIX + nl..]),
            },
            n,
        ))
    }
}

/// One opaque credential; parsing its wire fields does not validate JWT/PABC.
#[derive(Clone, Copy, Debug)]
pub struct Credential<'a> {
    /// Exact format including unknown extension values.
    pub kind: CredentialType,
    /// Raw credential flags.
    pub flags: u32,
    /// Original credential identifier.
    pub id: Identifier,
    /// Length-delimited name.
    pub name: Name<'a>,
    /// Original ignored alignment words, zero in canonical new objects.
    pub reserved: [u16; 2],
    /// Original credential bytes, potentially containing secrets.
    pub value: Sensitive<'a>,
}
impl<'a> Credential<'a> {
    /// Construct an opaque credential without verification or name conversion.
    pub const fn new(
        id: Identifier,
        kind: CredentialType,
        name: Name<'a>,
        value: Sensitive<'a>,
    ) -> Self {
        Self {
            kind,
            flags: 0,
            id,
            name,
            reserved: [0; 2],
            value,
        }
    }
    /// Exact required serialized bytes.
    pub fn encoded_len(self) -> Result<usize, Error> {
        length(CREDENTIAL_PREFIX, self.name.0.len(), self.value.len())
    }
    /// Encode after complete preflight; failure leaves output unchanged.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len()?;
        let out = out.get_mut(..n).ok_or(Error::Capacity)?;
        put32(out, 0, self.kind.value());
        put32(out, 4, self.flags);
        out[8..40].copy_from_slice(self.id.bytes());
        put16(out, 40, self.reserved[0]);
        put16(out, 42, self.name.0.len() as u16);
        put16(out, 44, self.reserved[1]);
        put16(out, 46, self.value.len() as u16);
        let split = CREDENTIAL_PREFIX + self.name.0.len();
        out[CREDENTIAL_PREFIX..split].copy_from_slice(self.name.0);
        out[split..].copy_from_slice(self.value.expose());
        Ok(n)
    }
    /// Decode exactly one credential.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        let (v, n) = Self::decode_prefix(bytes)?;
        if n != bytes.len() {
            return Err(Error::Malformed);
        }
        Ok(v)
    }
    /// Decode one credential at the start of a list.
    pub fn decode_prefix(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        let h = bytes.get(..CREDENTIAL_PREFIX).ok_or(Error::Truncated)?;
        let nl = usize::from(be16(h, 42));
        let dl = usize::from(be16(h, 46));
        let n = length(CREDENTIAL_PREFIX, nl, dl)?;
        let b = bytes.get(..n).ok_or(Error::Truncated)?;
        Ok((
            Self {
                kind: CredentialType::new(be32(h, 0)),
                flags: be32(h, 4),
                id: Identifier(b[8..40].try_into().map_err(|_| Error::Malformed)?),
                reserved: [be16(h, 40), be16(h, 44)],
                name: Name::decode(&b[CREDENTIAL_PREFIX..CREDENTIAL_PREFIX + nl]),
                value: Sensitive::new(&b[CREDENTIAL_PREFIX + nl..]),
            },
            n,
        ))
    }
}

/// One credential presentation. Legacy flag/name/alignment fields are ignored by
/// C consumers but preserved here, with NO name payload appended.
#[derive(Clone, Copy, Debug)]
pub struct Presentation<'a> {
    /// Presentation format, in the credential/plugin namespace.
    pub kind: CredentialType,
    /// Parent credential identifier.
    pub credential: Identifier,
    /// Ignored legacy flags, retained byte-for-byte.
    pub ignored_flags: u32,
    /// Ignored legacy reserved/name-length/reserved words.
    pub ignored_words: [u16; 3],
    /// Opaque presentation bytes; no proof has been checked.
    pub value: Sensitive<'a>,
}
impl<'a> Presentation<'a> {
    /// Canonical presentation with all ignored words initialized to zero.
    pub const fn new(credential: Identifier, kind: CredentialType, value: Sensitive<'a>) -> Self {
        Self {
            kind,
            credential,
            ignored_flags: 0,
            ignored_words: [0; 3],
            value,
        }
    }
    /// Required serialized size.
    pub fn encoded_len(self) -> Result<usize, Error> {
        length(PRESENTATION_PREFIX, 0, self.value.len())
    }
    /// Encode after full preflight, with no mutation on failure.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len()?;
        let out = out.get_mut(..n).ok_or(Error::Capacity)?;
        put32(out, 0, self.kind.value());
        put32(out, 4, self.ignored_flags);
        out[8..40].copy_from_slice(self.credential.bytes());
        put16(out, 40, self.ignored_words[0]);
        put16(out, 42, self.ignored_words[1]);
        put16(out, 44, self.ignored_words[2]);
        put16(out, 46, self.value.len() as u16);
        out[PRESENTATION_PREFIX..].copy_from_slice(self.value.expose());
        Ok(n)
    }
    /// Decode a complete presentation.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        let (v, n) = Self::decode_prefix(bytes)?;
        if n != bytes.len() {
            return Err(Error::Malformed);
        }
        Ok(v)
    }
    /// Decode a presentation prefix; ignored name_len does not consume data.
    pub fn decode_prefix(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
        let h = bytes.get(..PRESENTATION_PREFIX).ok_or(Error::Truncated)?;
        let n = length(PRESENTATION_PREFIX, 0, usize::from(be16(h, 46)))?;
        let b = bytes.get(..n).ok_or(Error::Truncated)?;
        Ok((
            Self {
                kind: CredentialType::new(be32(h, 0)),
                credential: Identifier(b[8..40].try_into().map_err(|_| Error::Malformed)?),
                ignored_flags: be32(h, 4),
                ignored_words: [be16(h, 40), be16(h, 42), be16(h, 44)],
                value: Sensitive::new(&b[PRESENTATION_PREFIX..]),
            },
            n,
        ))
    }
}

fn length(prefix: usize, name: usize, data: usize) -> Result<usize, Error> {
    u16::try_from(name).map_err(|_| Error::TooLarge)?;
    u16::try_from(data).map_err(|_| Error::TooLarge)?;
    prefix
        .checked_add(name)
        .and_then(|n| n.checked_add(data))
        .ok_or(Error::Overflow)
}

macro_rules! cstring {
    ($name:ident,$max:ident,$doc:literal) => {
        #[doc=$doc]
        #[derive(Clone, Copy)]
        pub struct $name<'a>(&'a [u8]);
        impl<'a> $name<'a> {
            /// Construct canonical bytes without their final NUL. No URI/DNS
            /// authenticity or syntax beyond safe length/termination is implied.
            pub fn new(bytes: &'a [u8]) -> Result<Self, Error> {
                if bytes.contains(&0) {
                    return Err(Error::InvalidInput);
                }
                if bytes.len().checked_add(1).ok_or(Error::Overflow)? > $max {
                    return Err(Error::TooLarge);
                }
                Ok(Self(bytes))
            }
            /// Decode exactly one terminated public field, rejecting ignored tails.
            pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
                if bytes.last() != Some(&0) {
                    return Err(Error::Malformed);
                }
                Self::new(&bytes[..bytes.len() - 1]).map_err(|_| Error::Malformed)
            }
            /// Explicit sensitive borrow excluding the final NUL.
            pub const fn expose(self) -> &'a [u8] {
                self.0
            }
            /// Encoded size including the final NUL.
            pub const fn encoded_len(self) -> usize {
                self.0.len() + 1
            }
            /// Encode in caller-owned storage, unchanged on insufficient capacity.
            pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
                let n = self.encoded_len();
                let out = out.get_mut(..n).ok_or(Error::Capacity)?;
                out[..self.0.len()].copy_from_slice(self.0);
                out[self.0.len()] = 0;
                Ok(n)
            }
        }
        impl fmt::Debug for $name<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    };
}
cstring!(
    Ticket,
    TICKET_NAME_BYTES,
    "A current public RECLAIM ticket capability: a variable-length NUL-terminated GNS name, not a fixed key/rnd struct."
);
impl<'a> Ticket<'a> {
    /// Borrow the original capability label and decode its final typed issuer
    /// zone, without allocation or normalization. The label may contain dots;
    /// only the last dot separates it from the zone. Ticket's own array bound
    /// already limits the label below the GNS255-byte ceiling. This validates
    /// format only: issuer authenticity belongs to the actual GNS provider.
    pub fn capability(self) -> Result<(&'a [u8], ZoneKey), Error> {
        let name = self.expose();
        let at = name
            .iter()
            .rposition(|b| *b == b'.')
            .ok_or(Error::Malformed)?;
        let label = &name[..at];
        if label.is_empty() {
            return Err(Error::Malformed);
        }
        let zone = ZoneKey::from_ztld(
            core::str::from_utf8(&name[at + 1..]).map_err(|_| Error::Malformed)?,
        )?;
        Ok((label, zone))
    }
}
cstring!(
    Uri,
    RP_URI_BYTES,
    "A sensitive RP URI associated with a ticket; not a serialized public key."
);

/// Convert a basic STRING/JWT/PABC C-string payload into caller storage. This
/// only performs the public plugin's byte conversion; it does not verify JWT/PABC.
pub fn string_value(input: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    if input.contains(&0) {
        return Err(Error::InvalidInput);
    }
    let n = input.len().checked_add(1).ok_or(Error::Overflow)?;
    u16::try_from(n).map_err(|_| Error::TooLarge)?;
    let out = out.get_mut(..n).ok_or(Error::Capacity)?;
    out[..input.len()].copy_from_slice(input);
    out[input.len()] = 0;
    Ok(n)
}

/// Borrow the bytes that an official plugin's strndup(value, data_size) would
/// expose, stopping at the first NUL without allocating or interpreting UTF-8.
/// This is textual conversion only and confers no JWT/PABC authenticity.
pub fn string_bytes(value: Sensitive<'_>) -> &[u8] {
    let bytes = value.expose();
    &bytes[..bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len())]
}
