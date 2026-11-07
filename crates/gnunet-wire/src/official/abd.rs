//! Active v0.29.1 ABD IPC and GNS DEL/ATTR formats.
//!
//! The normal C service emits VERIFY_RESULT for both VERIFY and COLLECT. Its
//! public API also accepts COLLECT_RESULT. IPC's plural delegate serializer is
//! distinct from the signed singular GNS record: normal request attributes omit
//! their NUL although the original signature covers it. [`Delegate::encode_record`](crate::official::abd::Delegate::encode_record)
//! reconstructs the canonical signed representation; decoding alone verifies no
//! signature, authorization, GNS source, expiration or proof.
//!
//! The reference plural serializer cannot transport a delegate's subject role.
//! This codec rejects that unsupported representation rather than discarding a
//! restriction. GNS DEL records retain the complete signed subject role.

use super::{Frame, MessageHeader, MessageType, message_type as mt};
use gnunet_types::Error;

/// Blindable public/private key extent, including its BE32 type.
pub const KEY_BYTES: usize = 36;
/// Blindable signature extent, including its BE32 type.
pub const SIGNATURE_BYTES: usize = 68;
/// Official ECDSA PKEY assignment.
pub const PKEY: u32 = 65_536;
/// Official EdDSA EDKEY assignment.
pub const EDKEY: u32 = 65_556;
/// Official DELEGATE signature purpose.
pub const DELEGATE_PURPOSE: u32 = 28;
/// Singular DEL/plural IPC delegate prefix.
pub const DELEGATE_PREFIX: usize = 164;
/// Signed fixed bytes after the signature.
pub const SIGNED_PREFIX: usize = DELEGATE_PREFIX - SIGNATURE_BYTES;
/// Serialized delegation-chain entry prefix.
pub const CHAIN_PREFIX: usize = 80;
/// Serialized ATTR conjunction term prefix.
pub const TERM_PREFIX: usize = 40;
/// Official forward resolution bit.
pub const FORWARD: u16 = 1;
/// Official backward resolution bit.
pub const BACKWARD: u16 = 2;
/// Official combined resolution bits.
pub const BOTH: u16 = FORWARD | BACKWARD;

fn be16(input: &[u8], at: usize) -> Result<u16, Error> {
    let v = input.get(at..at + 2).ok_or(Error::Truncated)?;
    Ok(u16::from_be_bytes([v[0], v[1]]))
}
fn be32(input: &[u8], at: usize) -> Result<u32, Error> {
    let v = input.get(at..at + 4).ok_or(Error::Truncated)?;
    Ok(u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
}
fn be64(input: &[u8], at: usize) -> Result<u64, Error> {
    let v: [u8; 8] = input
        .get(at..at + 8)
        .ok_or(Error::Truncated)?
        .try_into()
        .map_err(|_| Error::Truncated)?;
    Ok(u64::from_be_bytes(v))
}
fn count(value: u32) -> Result<usize, Error> {
    usize::try_from(value).map_err(|_| Error::TooLarge)
}
fn add(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_add(b).ok_or(Error::Overflow)
}
fn cstr(input: &[u8]) -> Result<&[u8], Error> {
    let body = input.strip_suffix(&[0]).ok_or(Error::Malformed)?;
    if body.contains(&0) {
        return Err(Error::Malformed);
    }
    Ok(body)
}
fn canonical(input: &[u8]) -> Result<(), Error> {
    if input.contains(&0) {
        return Err(Error::InvalidInput);
    }
    Ok(())
}
fn key_kind(input: &[u8]) -> Result<(), Error> {
    match be32(input, 0)? {
        PKEY | EDKEY => Ok(()),
        _ => Err(Error::Unsupported),
    }
}
fn begin(out: &mut [u8], kind: MessageType, n: usize) -> Result<(), Error> {
    let header = MessageHeader::from_total_size(kind, n)?;
    if out.len() < n {
        return Err(Error::Capacity);
    }
    header.encode(out)?;
    Ok(())
}

/// Borrowed typed public key. The key's curve membership is a crypto concern.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Key<'a>(&'a [u8; KEY_BYTES]);
impl<'a> Key<'a> {
    /// Borrow an exact public key with a supported official type.
    pub fn new(input: &'a [u8]) -> Result<Self, Error> {
        let bytes = input.try_into().map_err(|_| Error::Malformed)?;
        key_kind(input)?;
        Ok(Self(bytes))
    }
    /// Original bytes, including the official BE32 type.
    #[must_use]
    pub const fn bytes(self) -> &'a [u8; KEY_BYTES] {
        self.0
    }
    /// Host-order official type.
    #[must_use]
    pub fn kind(self) -> u32 {
        u32::from_be_bytes([self.0[0], self.0[1], self.0[2], self.0[3]])
    }
    /// Original 32-byte public material.
    #[must_use]
    pub fn material(self) -> &'a [u8] {
        &self.0[4..]
    }
}

/// Borrowed collect-only private key. It deliberately has no Debug or Clone.
pub struct PrivateKey<'a>(&'a [u8; KEY_BYTES]);
impl<'a> PrivateKey<'a> {
    /// Borrow one exact typed private-key representation; no key is derived.
    pub fn new(input: &'a [u8]) -> Result<Self, Error> {
        let bytes = input.try_into().map_err(|_| Error::Malformed)?;
        key_kind(input)?;
        Ok(Self(bytes))
    }
    /// Borrow the original secret IPC bytes. Owners must erase their storage.
    #[must_use]
    pub const fn bytes(&self) -> &'a [u8; KEY_BYTES] {
        self.0
    }
}

/// Complete semantic fields of a signed delegate, with attributes excluding NUL.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Delegate<'a> {
    /// Original signature: BE32 type and 64 signature bytes.
    pub signature: &'a [u8; SIGNATURE_BYTES],
    /// Issuer whose public key authenticates the canonical signed payload.
    pub issuer: Key<'a>,
    /// Subject principal, whose optional role is retained below.
    pub subject: Key<'a>,
    /// Absolute expiration in official microseconds.
    pub expiration_us: u64,
    /// Issuer role bytes excluding its canonical terminating NUL.
    pub issuer_attribute: &'a [u8],
    /// Optional subject role bytes, excluding its terminating NUL.
    pub subject_attribute: Option<&'a [u8]>,
}
impl Delegate<'_> {
    fn validate(self) -> Result<(), Error> {
        if be32(self.signature, 0)? != self.issuer.kind() {
            return Err(Error::InvalidInput);
        }
        canonical(self.issuer_attribute)?;
        if let Some(attr) = self.subject_attribute {
            canonical(attr)?;
        }
        Ok(())
    }
    /// Canonical singular GNS DEL size, including every signed terminator.
    pub fn record_len(self) -> Result<usize, Error> {
        self.validate()?;
        let n = add(DELEGATE_PREFIX, add(self.issuer_attribute.len(), 1)?)?;
        let n = if let Some(attr) = self.subject_attribute {
            add(n, add(attr.len(), 1)?)?
        } else {
            n
        };
        u32::try_from(n - SIGNATURE_BYTES).map_err(|_| Error::TooLarge)?;
        Ok(n)
    }
    /// Encode canonical singular DEL bytes. The signature itself is not produced
    /// or verified here. All errors precede any modification of caller storage.
    pub fn encode_record(self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.record_len()?;
        if out.len() < n {
            return Err(Error::Capacity);
        }
        self.fixed(
            out,
            self.issuer_attribute.len() + 1,
            self.subject_attribute.map_or(0, |a| a.len() + 1),
            n - SIGNATURE_BYTES,
        );
        let end = DELEGATE_PREFIX + self.issuer_attribute.len();
        out[DELEGATE_PREFIX..end].copy_from_slice(self.issuer_attribute);
        out[end] = 0;
        if let Some(attr) = self.subject_attribute {
            out[end + 1..n - 1].copy_from_slice(attr);
            out[n - 1] = 0;
        }
        Ok(n)
    }
    fn fixed(self, out: &mut [u8], issuer_len: usize, subject_len: usize, purpose_size: usize) {
        out[..68].copy_from_slice(self.signature);
        out[68..72].copy_from_slice(&(purpose_size as u32).to_be_bytes());
        out[72..76].copy_from_slice(&DELEGATE_PURPOSE.to_be_bytes());
        out[76..112].copy_from_slice(self.issuer.bytes());
        out[112..148].copy_from_slice(self.subject.bytes());
        out[148..156].copy_from_slice(&self.expiration_us.to_be_bytes());
        out[156..160].copy_from_slice(&(issuer_len as u32).to_be_bytes());
        out[160..164].copy_from_slice(&(subject_len as u32).to_be_bytes());
    }
    /// C plural IPC leaf size. A subject role cannot be transported by that C
    /// serializer and is rejected instead of being silently removed.
    pub fn ipc_len(self, terminating_nul: bool) -> Result<usize, Error> {
        self.validate()?;
        if self.subject_attribute.is_some() {
            return Err(Error::Unsupported);
        }
        let n = add(
            DELEGATE_PREFIX,
            add(self.issuer_attribute.len(), usize::from(terminating_nul))?,
        )?;
        u32::try_from(n - SIGNATURE_BYTES).map_err(|_| Error::TooLarge)?;
        Ok(n)
    }
    /// Encode the actual C plural leaf representation. The normal C request
    /// uses terminating_nul=false; service result producers use true. A verifier
    /// must reconstruct canonical DEL bytes before checking the signature.
    pub fn encode_ipc(self, out: &mut [u8], terminating_nul: bool) -> Result<usize, Error> {
        let n = self.ipc_len(terminating_nul)?;
        if out.len() < n {
            return Err(Error::Capacity);
        }
        self.fixed(out, n - DELEGATE_PREFIX, 0, n - SIGNATURE_BYTES);
        let end = DELEGATE_PREFIX + self.issuer_attribute.len();
        out[DELEGATE_PREFIX..end].copy_from_slice(self.issuer_attribute);
        if terminating_nul {
            out[end] = 0;
        }
        Ok(n)
    }
}

fn delegate_prefix(input: &[u8]) -> Result<(usize, usize), Error> {
    input.get(..DELEGATE_PREFIX).ok_or(Error::Truncated)?;
    if be32(input, 72)? != DELEGATE_PURPOSE {
        return Err(Error::Malformed);
    }
    let issuer = count(be32(input, 156)?)?;
    let subject = count(be32(input, 160)?)?;
    let n = add(DELEGATE_PREFIX, add(issuer, subject)?)?;
    input.get(..n).ok_or(Error::Truncated)?;
    Key::new(&input[76..112])?;
    Key::new(&input[112..148])?;
    if be32(input, 0)? != be32(input, 76)? {
        return Err(Error::Malformed);
    }
    Ok((issuer, subject))
}
fn fields<'a>(
    input: &'a [u8],
    issuer: &'a [u8],
    subject: Option<&'a [u8]>,
) -> Result<Delegate<'a>, Error> {
    Ok(Delegate {
        signature: input[..68].try_into().map_err(|_| Error::Truncated)?,
        issuer: Key::new(&input[76..112])?,
        subject: Key::new(&input[112..148])?,
        expiration_us: be64(input, 148)?,
        issuer_attribute: issuer,
        subject_attribute: subject,
    })
}

/// Borrowed canonical singular GNS DEL record, including its original signed bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignedDelegate<'a> {
    raw: &'a [u8],
    delegate: Delegate<'a>,
}
impl<'a> SignedDelegate<'a> {
    /// Decode the complete signed format. No cryptographic authentication occurs.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let (a, b) = delegate_prefix(input)?;
        let n = add(DELEGATE_PREFIX, add(a, b)?)?;
        if input.len() != n || count(be32(input, 68)?)? != n - SIGNATURE_BYTES {
            return Err(Error::Malformed);
        }
        let issuer = cstr(&input[DELEGATE_PREFIX..DELEGATE_PREFIX + a])?;
        let subject = if b == 0 {
            None
        } else {
            Some(cstr(&input[DELEGATE_PREFIX + a..])?)
        };
        Ok(Self {
            raw: input,
            delegate: fields(input, issuer, subject)?,
        })
    }
    /// Complete authenticated semantic fields, after a caller verifies the signature.
    #[must_use]
    pub const fn delegate(self) -> Delegate<'a> {
        self.delegate
    }
    /// Original purpose header and complete canonical signed payload.
    #[must_use]
    pub fn signed_bytes(self) -> &'a [u8] {
        &self.raw[SIGNATURE_BYTES..]
    }
    /// Exact complete GNS record bytes.
    #[must_use]
    pub const fn bytes(self) -> &'a [u8] {
        self.raw
    }
}

fn ipc_delegate(input: &[u8]) -> Result<(Delegate<'_>, usize), Error> {
    let (a, b) = delegate_prefix(input)?;
    if b != 0 {
        return Err(Error::Unsupported);
    }
    let n = add(DELEGATE_PREFIX, a)?;
    if count(be32(input, 68)?)? != n - SIGNATURE_BYTES {
        return Err(Error::Malformed);
    }
    let attr = &input[DELEGATE_PREFIX..n];
    let attr = if attr.last() == Some(&0) {
        cstr(attr)?
    } else {
        canonical(attr).map_err(|_| Error::Malformed)?;
        attr
    };
    Ok((fields(input, attr, None)?, n))
}

/// Exact borrowed sequence of C plural IPC leaf delegates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Delegates<'a> {
    bytes: &'a [u8],
    count: u32,
}
impl<'a> Delegates<'a> {
    /// Validate all counts/extents before constructing a zero-allocation iterator.
    pub fn new(bytes: &'a [u8], count: u32) -> Result<Self, Error> {
        let (used, rest) = split_delegates(bytes, count)?;
        if !rest.is_empty() {
            return Err(Error::Malformed);
        }
        Ok(Self { bytes: used, count })
    }
    /// Exact original bytes, retaining each original NUL convention.
    #[must_use]
    pub const fn bytes(self) -> &'a [u8] {
        self.bytes
    }
    /// Original declared count, validated against every element.
    #[must_use]
    pub const fn count(self) -> u32 {
        self.count
    }
    /// Validated semantic fields; signatures still require canonical verification.
    #[must_use]
    pub fn iter(self) -> DelegateIter<'a> {
        DelegateIter {
            rest: self.bytes,
            left: self.count,
        }
    }
}
fn split_delegates(mut input: &[u8], count: u32) -> Result<(&[u8], &[u8]), Error> {
    if usize::try_from(count).map_err(|_| Error::TooLarge)? > input.len() / DELEGATE_PREFIX {
        return Err(Error::Truncated);
    }
    let original = input;
    for _ in 0..count {
        let (_, n) = ipc_delegate(input)?;
        input = &input[n..];
    }
    Ok((&original[..original.len() - input.len()], input))
}
/// No-allocation iterator over a previously validated delegate sequence.
pub struct DelegateIter<'a> {
    rest: &'a [u8],
    left: u32,
}
impl<'a> Iterator for DelegateIter<'a> {
    type Item = Delegate<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.left == 0 {
            return None;
        }
        let (item, n) = ipc_delegate(self.rest).ok()?;
        self.rest = &self.rest[n..];
        self.left -= 1;
        Some(item)
    }
}

/// One unsigned chain edge reported by a service, not an independent credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Chain<'a> {
    /// Issuer authority.
    pub issuer: Key<'a>,
    /// Subject principal.
    pub subject: Key<'a>,
    /// Issuer role, excluding NUL.
    pub issuer_attribute: &'a [u8],
    /// Optional subject role, excluding NUL.
    pub subject_attribute: Option<&'a [u8]>,
}
impl Chain<'_> {
    /// Complete serialized chain-entry size.
    pub fn encoded_len(self) -> Result<usize, Error> {
        canonical(self.issuer_attribute)?;
        let mut n = add(CHAIN_PREFIX, add(self.issuer_attribute.len(), 1)?)?;
        if let Some(attr) = self.subject_attribute {
            canonical(attr)?;
            n = add(n, add(attr.len(), 1)?)?;
        }
        u32::try_from(n).map_err(|_| Error::TooLarge)?;
        Ok(n)
    }
    /// Encode one chain edge. It carries no signature or source authentication.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len()?;
        if out.len() < n {
            return Err(Error::Capacity);
        }
        out[..36].copy_from_slice(self.issuer.bytes());
        out[36..72].copy_from_slice(self.subject.bytes());
        out[72..76].copy_from_slice(&((self.issuer_attribute.len() + 1) as u32).to_be_bytes());
        out[76..80].copy_from_slice(
            &(self.subject_attribute.map_or(0, |a| a.len() + 1) as u32).to_be_bytes(),
        );
        let end = CHAIN_PREFIX + self.issuer_attribute.len();
        out[CHAIN_PREFIX..end].copy_from_slice(self.issuer_attribute);
        out[end] = 0;
        if let Some(attr) = self.subject_attribute {
            out[end + 1..n - 1].copy_from_slice(attr);
            out[n - 1] = 0;
        }
        Ok(n)
    }
}
fn chain(input: &[u8]) -> Result<(Chain<'_>, usize), Error> {
    input.get(..CHAIN_PREFIX).ok_or(Error::Truncated)?;
    let a = count(be32(input, 72)?)?;
    let b = count(be32(input, 76)?)?;
    let end = add(CHAIN_PREFIX, a)?;
    let n = add(end, b)?;
    input.get(..n).ok_or(Error::Truncated)?;
    Ok((
        Chain {
            issuer: Key::new(&input[..36])?,
            subject: Key::new(&input[36..72])?,
            issuer_attribute: cstr(&input[CHAIN_PREFIX..end])?,
            subject_attribute: if b == 0 {
                None
            } else {
                Some(cstr(&input[end..n])?)
            },
        },
        n,
    ))
}
/// Exact borrowed sequence of serialized chain entries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Chains<'a> {
    bytes: &'a [u8],
    count: u32,
}
impl<'a> Chains<'a> {
    /// Validate a complete chain sequence and its count.
    pub fn new(bytes: &'a [u8], count: u32) -> Result<Self, Error> {
        let (used, rest) = split_chains(bytes, count)?;
        if !rest.is_empty() {
            return Err(Error::Malformed);
        }
        Ok(Self { bytes: used, count })
    }
    /// Exact original serialized bytes.
    #[must_use]
    pub const fn bytes(self) -> &'a [u8] {
        self.bytes
    }
    /// Validated original count.
    #[must_use]
    pub const fn count(self) -> u32 {
        self.count
    }
    /// Iterate original edges in wire order.
    #[must_use]
    pub fn iter(self) -> ChainIter<'a> {
        ChainIter {
            rest: self.bytes,
            left: self.count,
        }
    }
}
fn split_chains(mut input: &[u8], count: u32) -> Result<(&[u8], &[u8]), Error> {
    if usize::try_from(count).map_err(|_| Error::TooLarge)? > input.len() / CHAIN_PREFIX {
        return Err(Error::Truncated);
    }
    let original = input;
    for _ in 0..count {
        let (_, n) = chain(input)?;
        input = &input[n..];
    }
    Ok((&original[..original.len() - input.len()], input))
}
/// No-allocation iterator over validated chain entries.
pub struct ChainIter<'a> {
    rest: &'a [u8],
    left: u32,
}
impl<'a> Iterator for ChainIter<'a> {
    type Item = Chain<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.left == 0 {
            return None;
        }
        let (item, n) = chain(self.rest).ok()?;
        self.rest = &self.rest[n..];
        self.left -= 1;
        Some(item)
    }
}

/// Official requests on the original ABD service MQ. There is no cancel frame.
pub enum Request<'a> {
    /// Collect private DEL records from the subject's own namestore zone.
    Collect {
        /// Original local request identifier, encoded BE32.
        id: u32,
        /// Subject's typed private key; the native owner must erase input buffers.
        subject: PrivateKey<'a>,
        /// Public trust anchor.
        issuer: Key<'a>,
        /// Issuer attribute, excluding the final request NUL.
        attribute: &'a [u8],
        /// Original direction bits; resolution policy checks their validity.
        resolution: u16,
    },
    /// Verify supplied leaf delegates against GNS delegation policies.
    Verify {
        /// Original local request identifier, encoded BE32.
        id: u32,
        /// Required subject, not inferred solely from a credential's issuer.
        subject: Key<'a>,
        /// Public trust anchor.
        issuer: Key<'a>,
        /// Issuer attribute, excluding the final request NUL.
        attribute: &'a [u8],
        /// Original direction bits.
        resolution: u16,
        /// Exact C plural delegates; canonical signature verification is separate.
        delegates: Delegates<'a>,
    },
}
impl<'a> Request<'a> {
    /// Decode one complete request, including all nested delegates and terminators.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let frame = Frame::decode(input)?;
        match frame.header().message_type() {
            mt::ABD_COLLECT => {
                input.get(..84).ok_or(Error::Truncated)?;
                let end = add(84, add(usize::from(be16(input, 76)?), 1)?)?;
                if end != input.len() {
                    return Err(Error::Malformed);
                }
                Ok(Self::Collect {
                    id: be32(input, 80)?,
                    subject: PrivateKey::new(&input[4..40])?,
                    issuer: Key::new(&input[40..76])?,
                    attribute: cstr(&input[84..end])?,
                    resolution: be16(input, 78)?,
                })
            }
            mt::ABD_VERIFY => {
                input.get(..88).ok_or(Error::Truncated)?;
                let end = add(88, add(usize::from(be16(input, 80)?), 1)?)?;
                let attr = input.get(88..end).ok_or(Error::Truncated)?;
                Ok(Self::Verify {
                    id: be32(input, 84)?,
                    subject: Key::new(&input[4..40])?,
                    issuer: Key::new(&input[40..76])?,
                    attribute: cstr(attr)?,
                    resolution: be16(input, 82)?,
                    delegates: Delegates::new(&input[end..], be32(input, 76)?)?,
                })
            }
            _ => Err(Error::Unsupported),
        }
    }
    /// Exact registered message number.
    #[must_use]
    pub const fn message_type(&self) -> MessageType {
        match self {
            Self::Collect { .. } => mt::ABD_COLLECT,
            Self::Verify { .. } => mt::ABD_VERIFY,
        }
    }
    /// Complete bounded request size.
    pub fn encoded_len(&self) -> Result<usize, Error> {
        let (prefix, attr, tail) = match self {
            Self::Collect { attribute, .. } => (84, *attribute, 0),
            Self::Verify {
                attribute,
                delegates,
                ..
            } => (88, *attribute, delegates.bytes.len()),
        };
        canonical(attr)?;
        u16::try_from(attr.len()).map_err(|_| Error::TooLarge)?;
        let n = add(add(prefix, add(attr.len(), 1)?)?, tail)?;
        MessageHeader::from_total_size(self.message_type(), n)?;
        Ok(n)
    }
    /// Encode one original request. No acknowledgement, result or cancellation is implied.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len()?;
        begin(out, self.message_type(), n)?;
        let (prefix, attr) = match self {
            Self::Collect {
                id,
                subject,
                issuer,
                attribute,
                resolution,
            } => {
                out[4..40].copy_from_slice(subject.bytes());
                out[40..76].copy_from_slice(issuer.bytes());
                out[76..78].copy_from_slice(&(attribute.len() as u16).to_be_bytes());
                out[78..80].copy_from_slice(&resolution.to_be_bytes());
                out[80..84].copy_from_slice(&id.to_be_bytes());
                (84, *attribute)
            }
            Self::Verify {
                id,
                subject,
                issuer,
                attribute,
                resolution,
                delegates,
            } => {
                out[4..40].copy_from_slice(subject.bytes());
                out[40..76].copy_from_slice(issuer.bytes());
                out[76..80].copy_from_slice(&delegates.count.to_be_bytes());
                out[80..82].copy_from_slice(&(attribute.len() as u16).to_be_bytes());
                out[82..84].copy_from_slice(&resolution.to_be_bytes());
                out[84..88].copy_from_slice(&id.to_be_bytes());
                out[n - delegates.bytes.len()..n].copy_from_slice(delegates.bytes);
                (88, *attribute)
            }
        };
        out[prefix..prefix + attr.len()].copy_from_slice(attr);
        out[prefix + attr.len()] = 0;
        Ok(n)
    }
}

/// Official terminal and intermediate responses; these carry service claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Response<'a> {
    /// The pinned C service uses kind992 for both request types. Kind994 remains
    /// accepted by the official API and is retained explicitly.
    Result {
        /// Original type992 or994.
        kind: MessageType,
        /// Original request identifier.
        id: u32,
        /// Raw original del_found word; no any-nonzero authorization is inferred.
        found: u32,
        /// Reported chain edges, not independently signed credentials.
        chain: Chains<'a>,
        /// Reported used leaf credentials.
        delegates: Delegates<'a>,
    },
    /// One nonterminal source-reported edge. It does not complete a request.
    Intermediate {
        /// Original request identifier.
        id: u32,
        /// Raw original BE16 direction flag.
        backward: u16,
        /// Exactly one chain entry.
        edge: Chain<'a>,
    },
}
impl<'a> Response<'a> {
    /// Decode one complete response with exact nested extents.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let kind = Frame::decode(input)?.header().message_type();
        match kind {
            mt::ABD_VERIFY_RESULT | mt::ABD_COLLECT_RESULT => {
                input.get(..20).ok_or(Error::Truncated)?;
                let (edges, tail) = split_chains(&input[20..], be32(input, 12)?)?;
                Ok(Self::Result {
                    kind,
                    id: be32(input, 4)?,
                    found: be32(input, 8)?,
                    chain: Chains::new(edges, be32(input, 12)?)?,
                    delegates: Delegates::new(tail, be32(input, 16)?)?,
                })
            }
            mt::ABD_INTERMEDIATE_RESULT => {
                input.get(..14).ok_or(Error::Truncated)?;
                if count(be32(input, 10)?)? != input.len() - 14 {
                    return Err(Error::Malformed);
                }
                let (edge, n) = chain(&input[14..])?;
                if n != input.len() - 14 {
                    return Err(Error::Malformed);
                }
                Ok(Self::Intermediate {
                    id: be32(input, 4)?,
                    backward: be16(input, 8)?,
                    edge,
                })
            }
            _ => Err(Error::Unsupported),
        }
    }
    /// Complete frame size, rejecting unsupported result kinds before writing.
    pub fn encoded_len(self) -> Result<usize, Error> {
        let (kind, n) = match self {
            Self::Result {
                kind,
                chain,
                delegates,
                ..
            } => {
                if kind != mt::ABD_VERIFY_RESULT && kind != mt::ABD_COLLECT_RESULT {
                    return Err(Error::InvalidInput);
                }
                (
                    kind,
                    add(20, add(chain.bytes.len(), delegates.bytes.len())?)?,
                )
            }
            Self::Intermediate { edge, .. } => {
                (mt::ABD_INTERMEDIATE_RESULT, add(14, edge.encoded_len()?)?)
            }
        };
        MessageHeader::from_total_size(kind, n)?;
        Ok(n)
    }
    /// Encode the exact response. It provides no local signature or proof verification.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len()?;
        let kind = match self {
            Self::Result { kind, .. } => kind,
            Self::Intermediate { .. } => mt::ABD_INTERMEDIATE_RESULT,
        };
        begin(out, kind, n)?;
        match self {
            Self::Result {
                id,
                found,
                chain,
                delegates,
                ..
            } => {
                out[4..8].copy_from_slice(&id.to_be_bytes());
                out[8..12].copy_from_slice(&found.to_be_bytes());
                out[12..16].copy_from_slice(&chain.count.to_be_bytes());
                out[16..20].copy_from_slice(&delegates.count.to_be_bytes());
                out[20..20 + chain.bytes.len()].copy_from_slice(chain.bytes);
                out[20 + chain.bytes.len()..n].copy_from_slice(delegates.bytes);
            }
            Self::Intermediate { id, backward, edge } => {
                out[4..8].copy_from_slice(&id.to_be_bytes());
                out[8..10].copy_from_slice(&backward.to_be_bytes());
                out[10..14].copy_from_slice(&((n - 14) as u32).to_be_bytes());
                edge.encode(&mut out[14..n])?;
            }
        }
        Ok(n)
    }
}

/// C ABI for ATTR's unpacked u64 data_size member. Its values remain BE64.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordLayout {
    /// Actual target C alignment of uint64_t, either4 or8.
    pub align64: u8,
}
impl RecordLayout {
    /// Explicit local C-target default; no remote profile is detected from bytes.
    #[must_use]
    pub const fn native() -> Self {
        Self {
            align64: core::mem::align_of::<u64>() as u8,
        }
    }
    /// Validate the only layouts used by the pinned public record struct.
    pub fn validate(self) -> Result<(), Error> {
        if self.align64 == 4 || self.align64 == 8 {
            Ok(())
        } else {
            Err(Error::InvalidInput)
        }
    }
    fn prefix(self) -> Result<usize, Error> {
        self.validate()?;
        Ok(if self.align64 == 8 { 16 } else { 12 })
    }
}

/// One term in an ATTR record's conjunction. None denotes the direct principal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Term<'a> {
    /// Original subject authority.
    pub subject: Key<'a>,
    /// Optional linked subject role, without NUL.
    pub attribute: Option<&'a [u8]>,
}
impl Term<'_> {
    /// Exact term size including a nonempty role's required terminating NUL.
    pub fn encoded_len(self) -> Result<usize, Error> {
        let n = if let Some(attr) = self.attribute {
            canonical(attr)?;
            add(TERM_PREFIX, add(attr.len(), 1)?)?
        } else {
            TERM_PREFIX
        };
        u32::try_from(n).map_err(|_| Error::TooLarge)?;
        Ok(n)
    }
    /// Encode one term; it must be bound to the original authenticated GNS lookup.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len()?;
        if out.len() < n {
            return Err(Error::Capacity);
        }
        out[..36].copy_from_slice(self.subject.bytes());
        out[36..40].copy_from_slice(&((n - TERM_PREFIX) as u32).to_be_bytes());
        if let Some(attr) = self.attribute {
            out[TERM_PREFIX..n - 1].copy_from_slice(attr);
            out[n - 1] = 0;
        }
        Ok(n)
    }
}
fn term(input: &[u8]) -> Result<(Term<'_>, usize), Error> {
    input.get(..TERM_PREFIX).ok_or(Error::Truncated)?;
    let len = count(be32(input, 36)?)?;
    let n = add(TERM_PREFIX, len)?;
    input.get(..n).ok_or(Error::Truncated)?;
    Ok((
        Term {
            subject: Key::new(&input[..36])?,
            attribute: if len == 0 {
                None
            } else {
                Some(cstr(&input[TERM_PREFIX..n])?)
            },
        },
        n,
    ))
}
/// Borrowed ATTR conjunction. Separate GNS records are alternative rules (OR),
/// whereas every term within this record must hold for the same subject (AND).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Policy<'a> {
    terms: &'a [u8],
    count: u32,
}
impl<'a> Policy<'a> {
    /// Validate a conjunction payload before encoding a record header around it.
    pub fn from_terms(bytes: &'a [u8], count: u32) -> Result<Self, Error> {
        if usize::try_from(count).map_err(|_| Error::TooLarge)? > bytes.len() / TERM_PREFIX {
            return Err(Error::Truncated);
        }
        let mut rest = bytes;
        for _ in 0..count {
            let (_, n) = term(rest)?;
            rest = &rest[n..];
        }
        if !rest.is_empty() {
            return Err(Error::Malformed);
        }
        Ok(Self {
            terms: bytes,
            count,
        })
    }
    /// Decode the exact C-layout ATTR record without interpreting its authority.
    pub fn decode(input: &'a [u8], layout: RecordLayout) -> Result<Self, Error> {
        let prefix = layout.prefix()?;
        input.get(..prefix).ok_or(Error::Truncated)?;
        let declared = usize::try_from(be64(input, prefix - 8)?).map_err(|_| Error::TooLarge)?;
        if declared != input.len() - prefix {
            return Err(Error::Malformed);
        }
        Self::from_terms(&input[prefix..], be32(input, 0)?)
    }
    /// Number of conjunctive terms, not the number of alternative records.
    #[must_use]
    pub const fn count(self) -> u32 {
        self.count
    }
    /// Original term bytes without the ABI-dependent header.
    #[must_use]
    pub const fn bytes(self) -> &'a [u8] {
        self.terms
    }
    /// Iterate terms with no allocation or alignment assumptions.
    #[must_use]
    pub fn iter(self) -> TermIter<'a> {
        TermIter {
            rest: self.terms,
            left: self.count,
        }
    }
    /// Complete record size in the explicitly selected target C layout.
    pub fn encoded_len(self, layout: RecordLayout) -> Result<usize, Error> {
        add(layout.prefix()?, self.terms.len())
    }
    /// Encode a record. Unused C padding is set to zero and is not a new field.
    pub fn encode(self, out: &mut [u8], layout: RecordLayout) -> Result<usize, Error> {
        let n = self.encoded_len(layout)?;
        if out.len() < n {
            return Err(Error::Capacity);
        }
        let prefix = layout.prefix()?;
        out[..prefix].fill(0);
        out[..4].copy_from_slice(&self.count.to_be_bytes());
        out[prefix - 8..prefix].copy_from_slice(&(self.terms.len() as u64).to_be_bytes());
        out[prefix..n].copy_from_slice(self.terms);
        Ok(n)
    }
}
/// No-allocation iterator over validated conjunction terms.
pub struct TermIter<'a> {
    rest: &'a [u8],
    left: u32,
}
impl<'a> Iterator for TermIter<'a> {
    type Item = Term<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.left == 0 {
            return None;
        }
        let (value, n) = term(self.rest).ok()?;
        self.rest = &self.rest[n..];
        self.left -= 1;
        Some(value)
    }
}
