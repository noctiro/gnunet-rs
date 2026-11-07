//! DNSSEC canonical RRsets, DS trust anchoring and actual RRSIG verification.
//! No heap, clock, entropy, network or implicit trust anchor is used here.
//! Callers supply bounded scratch and a real cryptographic verifier. A validated
//! RRset proves its signature under the supplied chain; wildcard/denial proofs
//! are additional obligations, never inferred from AD or an empty answer.
pub mod denial;
use crate::{Error, Name};
use core::cmp::Ordering;
/// One canonical, fully expanded RRset. Individual records contain only RDATA.
#[derive(Clone, Copy)]
pub struct Rrset<'a> {
    /// Complete owner name.
    pub owner: Name<'a>,
    /// Original DNS type.
    pub kind: u16,
    /// Original DNS class.
    pub class: u16,
    /// Original remaining TTL, in seconds.
    pub ttl: u32,
    /// Canonical, fully expanded RDATA; duplicate records are ignored for signing.
    pub records: &'a [&'a [u8]],
}
/// Caller-owned bounded temporary storage. Contents may change on failure;
/// no authenticated result is published until the actual verifier succeeds.
pub struct Scratch<'a> {
    /// Complete canonical signed message storage.
    pub message: &'a mut [u8],
    /// One complete canonical RDATA, used to check canonical input.
    pub record: &'a mut [u8],
    /// Record indices, at least the RRset record count.
    pub order: &'a mut [usize],
}
/// Actual crypto operations, inverted to keep this wire/chain core no_std.
pub trait Crypto {
    /// Verify the real signature under the DNSKEY public-key field.
    fn verify(
        &self,
        algorithm: u8,
        key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Error>;
    /// DS digest over exact canonical owner and DNSKEY RDATA parts. Return the
    /// actual digest extent; unknown digests must return Unsupported.
    fn digest(&self, algorithm: u8, parts: &[&[u8]], output: &mut [u8]) -> Result<usize, Error>;
}
/// DNSKEY RRset authenticated through at least one original DS trust anchor
/// and a real self-signature. There is no public unchecked constructor.
#[derive(Clone, Copy)]
pub struct TrustedKeys<'a> {
    zone: Name<'a>,
    set: Rrset<'a>,
    verified_at: u32,
    ttl: u32,
}
impl<'a> TrustedKeys<'a> {
    /// Authenticated zone apex.
    pub fn zone(self) -> Name<'a> {
        self.zone
    }
    /// Complete authenticated DNSKEY RRset, including rollover keys.
    pub fn set(self) -> Rrset<'a> {
        self.set
    }
    /// Original DNSKEY chain lifetime, in seconds from this validation.
    pub fn ttl(self) -> u32 {
        self.ttl
    }
    fn remaining(self, now: u32) -> Result<u32, Error> {
        let elapsed = now.wrapping_sub(self.verified_at);
        if elapsed > self.ttl || elapsed >= 0x8000_0000 {
            return Err(Error::Deadline);
        }
        Ok(self.ttl - elapsed)
    }
}
/// Actual verified RRSIG result under an original trusted zone. Wildcard
/// expansion remains a separate proof obligation for the resolver.
#[derive(Clone, Copy)]
pub struct Validated<'a> {
    set: Rrset<'a>,
    signer: Name<'a>,
    labels: u8,
    ttl: u32,
    wildcard: bool,
}
impl<'a> Validated<'a> {
    /// The exact RRset whose real signature was verified.
    pub fn set(self) -> Rrset<'a> {
        self.set
    }
    /// Actual authenticated RRSIG signer.
    pub fn signer(self) -> Name<'a> {
        self.signer
    }
    /// Original RRSIG label count, excluding an original wildcard label.
    pub fn labels(self) -> u8 {
        self.labels
    }
    /// Remaining cache lifetime, bounded by signature and original/current TTLs.
    pub fn ttl(self) -> u32 {
        self.ttl
    }
    /// Whether the answer owner was expanded from a different wildcard name.
    pub fn wildcard(self) -> bool {
        self.wildcard
    }
}
/// Parsed public DNSKEY, without trust authority.
#[derive(Clone, Copy)]
pub struct Dnskey<'a> {
    /// Exact original flags, including zone/revocation bits.
    pub flags: u16,
    /// Original algorithm number.
    pub algorithm: u8,
    /// Complete public-key field.
    pub key: &'a [u8],
    rdata: &'a [u8],
}
impl<'a> Dnskey<'a> {
    /// Parse a complete original DNSKEY. Protocol must be3; key must be nonempty.
    pub fn parse(rdata: &'a [u8]) -> Result<Self, Error> {
        if rdata.len() < 5 {
            return Err(Error::Truncated);
        }
        if rdata.len() > 65535 {
            return Err(Error::TooLarge);
        }
        if rdata[2] != 3 {
            return Err(Error::Malformed);
        }
        Ok(Self {
            flags: u16::from_be_bytes([rdata[0], rdata[1]]),
            algorithm: rdata[3],
            key: &rdata[4..],
            rdata,
        })
    }
    /// RFC4034 key tag. Deprecated RSA/MD5 is not supported for validation.
    pub fn tag(self) -> u16 {
        let mut sum = 0u32;
        for (i, b) in self.rdata.iter().enumerate() {
            sum += if i % 2 == 0 {
                u32::from(*b) << 8
            } else {
                u32::from(*b)
            };
        }
        sum += (sum >> 16) & 0xffff;
        (sum & 0xffff) as u16
    }
    fn usable(self) -> bool {
        self.flags & 0x100 != 0
            && self.flags & 0x80 == 0
            && !matches!(self.algorithm, 0 | 1 | 2 | 3 | 6 | 12)
    }
}
/// Parsed uncompressed public RRSIG data, without signature/trust authority.
#[derive(Clone, Copy)]
pub struct Rrsig<'a> {
    /// Type covered.
    pub kind: u16,
    /// Real signing algorithm.
    pub algorithm: u8,
    /// Original label count, excluding a wildcard.
    pub labels: u8,
    /// Signed original TTL.
    pub original_ttl: u32,
    /// Serial32 expiration.
    pub expiration: u32,
    /// Serial32 inception.
    pub inception: u32,
    /// DNSKEY selector; collisions still require real verification.
    pub key_tag: u16,
    /// Fully expanded, original signer name.
    pub signer: Name<'a>,
    /// Actual signature bytes.
    pub signature: &'a [u8],
    prefix: &'a [u8],
}
impl<'a> Rrsig<'a> {
    /// Parse complete RRSIG RDATA. Its signer name cannot use compression.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        let fixed = data.get(..18).ok_or(Error::Truncated)?;
        let end = name_end(data, 18)?;
        let signer = Name::from_wire(&data[18..end])?;
        let signature = data
            .get(end..)
            .filter(|s| !s.is_empty())
            .ok_or(Error::Truncated)?;
        Ok(Self {
            kind: u16::from_be_bytes([fixed[0], fixed[1]]),
            algorithm: fixed[2],
            labels: fixed[3],
            original_ttl: word(&fixed[4..8])?,
            expiration: word(&fixed[8..12])?,
            inception: word(&fixed[12..16])?,
            key_tag: u16::from_be_bytes([fixed[16], fixed[17]]),
            signer,
            signature,
            prefix: &data[..end],
        })
    }
    fn remaining(self, now: u32) -> Result<u32, Error> {
        let span = self.expiration.wrapping_sub(self.inception);
        let elapsed = now.wrapping_sub(self.inception);
        if span >= 0x8000_0000 || elapsed > span {
            return Err(Error::Deadline);
        }
        Ok(span - elapsed)
    }
}
fn word(bytes: &[u8]) -> Result<u32, Error> {
    Ok(u32::from_be_bytes(
        bytes.try_into().map_err(|_| Error::Truncated)?,
    ))
}
/// Case-insensitive DNS semantic equality, independent of parser provenance.
pub fn name_eq(a: Name<'_>, b: Name<'_>) -> bool {
    a.wire().eq_ignore_ascii_case(b.wire())
}
/// Label-boundary suffix relationship, including the root and equal names.
pub fn within(name: Name<'_>, zone: Name<'_>) -> bool {
    let mut n = name.wire();
    loop {
        if n.eq_ignore_ascii_case(zone.wire()) {
            return true;
        }
        let len = usize::from(n[0]);
        if len == 0 {
            return false;
        }
        n = &n[len + 1..];
    }
}
/// RFC4034 rightmost-label-first canonical order, independent of case.
pub fn name_cmp(a: Name<'_>, b: Name<'_>) -> Ordering {
    let mut aa = [0u8; 127];
    let mut bb = [0u8; 127];
    let mut an = 0;
    let mut bn = 0;
    let mut at = 0;
    while a.wire()[at] != 0 {
        aa[an] = at as u8;
        an += 1;
        at += usize::from(a.wire()[at]) + 1;
    }
    at = 0;
    while b.wire()[at] != 0 {
        bb[bn] = at as u8;
        bn += 1;
        at += usize::from(b.wire()[at]) + 1;
    }
    for i in 0..an.min(bn) {
        let ai = usize::from(aa[an - i - 1]);
        let bi = usize::from(bb[bn - i - 1]);
        let x = &a.wire()[ai + 1..ai + 1 + usize::from(a.wire()[ai])];
        let y = &b.wire()[bi + 1..bi + 1 + usize::from(b.wire()[bi])];
        let order = x
            .iter()
            .map(u8::to_ascii_lowercase)
            .cmp(y.iter().map(u8::to_ascii_lowercase));
        if order != Ordering::Equal {
            return order;
        }
    }
    an.cmp(&bn)
}

fn name_end(input: &[u8], mut at: usize) -> Result<usize, Error> {
    let start = at;
    loop {
        let n = usize::from(*input.get(at).ok_or(Error::Truncated)?);
        at += 1;
        if n > 63 {
            return Err(Error::Malformed);
        }
        if n == 0 {
            break;
        }
        at = at.checked_add(n).ok_or(Error::Overflow)?;
        if at > input.len() {
            return Err(Error::Truncated);
        }
        if at - start >= 255 {
            return Err(Error::TooLarge);
        }
    }
    Name::from_wire(input.get(start..at).ok_or(Error::Truncated)?)?;
    Ok(at)
}
fn lower_name(input: &mut [u8], at: usize) -> Result<usize, Error> {
    let end = name_end(input, at)?;
    input[at..end].make_ascii_lowercase();
    Ok(end)
}
/// Canonicalize fully expanded RDATA into bounded caller storage. DNS packet
/// decompression must precede this call; compressed names are refused.
/// Unknown types retain RFC3597 opaque bytes. Scratch may change on failure.
pub fn canonical_rdata(kind: u16, input: &[u8], output: &mut [u8]) -> Result<usize, Error> {
    if input.len() > u16::MAX as usize || output.len() < input.len() {
        return Err(Error::Capacity);
    }
    output[..input.len()].copy_from_slice(input);
    let data = &mut output[..input.len()];
    let names = match kind {
        2 | 3 | 4 | 5 | 7 | 8 | 9 | 12 | 30 | 39 => Some((0, 1)),
        6 | 14 | 17 => Some((0, 2)),
        15 | 18 | 21 | 36 => Some((2, 1)),
        26 => Some((2, 2)),
        33 => Some((6, 1)),
        24 | 46 => Some((18, 1)),
        35 => {
            let mut at = 4;
            for _ in 0..3 {
                let n = usize::from(*data.get(at).ok_or(Error::Truncated)?);
                at = at.checked_add(1 + n).ok_or(Error::Overflow)?;
                if at > data.len() {
                    return Err(Error::Truncated);
                }
            }
            Some((at, 1))
        }
        38 => {
            let prefix = usize::from(*data.first().ok_or(Error::Truncated)?);
            if prefix > 128 {
                return Err(Error::Malformed);
            }
            let at = 1 + (128 - prefix).div_ceil(8);
            if prefix == 0 {
                if data.len() != 17 {
                    return Err(Error::Malformed);
                }
                None
            } else {
                Some((at, 1))
            }
        }
        // RFC6840 corrects RFC4034: NSEC Next Domain Name retains its case.
        47 => {
            name_end(data, 0)?;
            None
        }
        _ => None,
    };
    if let Some((mut at, count)) = names {
        for _ in 0..count {
            at = lower_name(data, at)?;
        }
        match kind {
            6 if at.checked_add(20) != Some(data.len()) => return Err(Error::Malformed),
            2 | 3 | 4 | 5 | 7 | 8 | 9 | 12 | 14 | 15 | 17 | 18 | 21 | 26 | 33 | 35 | 36 | 39
                if at != data.len() =>
            {
                return Err(Error::Malformed);
            }
            _ => {}
        }
    }
    Ok(data.len())
}
fn owner_for<'a>(
    owner: Name<'_>,
    labels: u8,
    out: &'a mut [u8; 255],
) -> Result<(Name<'a>, bool), Error> {
    let count = owner.labels().count();
    let labels = usize::from(labels);
    if labels > count {
        return Err(Error::Authentication);
    }
    let wire = owner.wire();
    let mut at = 0;
    for _ in 0..count - labels {
        at += usize::from(wire[at]) + 1;
    }
    let expanded = labels < count;
    let used = if expanded {
        let suffix = &wire[at..];
        out[0] = 1;
        out[1] = b'*';
        out[2..2 + suffix.len()].copy_from_slice(suffix);
        2 + suffix.len()
    } else {
        out[..wire.len()].copy_from_slice(wire);
        wire.len()
    };
    out[..used].make_ascii_lowercase();
    let name = Name::from_wire(&out[..used])?;
    let changed = !name_eq(name, owner);
    Ok((name, changed))
}
fn message(
    set: Rrset<'_>,
    sig: Rrsig<'_>,
    scratch: &mut Scratch<'_>,
) -> Result<(usize, bool), Error> {
    if set.records.is_empty() || scratch.order.len() < set.records.len() {
        return Err(Error::Capacity);
    }
    for (i, data) in set.records.iter().enumerate() {
        let n = canonical_rdata(set.kind, data, scratch.record)?;
        if &scratch.record[..n] != *data {
            return Err(Error::InvalidInput);
        }
        scratch.order[i] = i;
    }
    let order = &mut scratch.order[..set.records.len()];
    order.sort_unstable_by(|a, b| set.records[*a].cmp(set.records[*b]));
    let mut owner_storage = [0; 255];
    let (owner, wildcard) = owner_for(set.owner, sig.labels, &mut owner_storage)?;
    let mut size = sig.prefix.len();
    let mut previous = None;
    for &i in order.iter() {
        let data = set.records[i];
        if previous == Some(data) {
            continue;
        }
        previous = Some(data);
        size = size
            .checked_add(owner.wire_len() + 10)
            .and_then(|n| n.checked_add(data.len()))
            .ok_or(Error::Overflow)?;
    }
    if scratch.message.len() < size {
        return Err(Error::Capacity);
    }
    scratch.message[..sig.prefix.len()].copy_from_slice(sig.prefix);
    scratch.message[18..sig.prefix.len()].make_ascii_lowercase();
    let mut at = sig.prefix.len();
    previous = None;
    for &i in order.iter() {
        let data = set.records[i];
        if previous == Some(data) {
            continue;
        }
        previous = Some(data);
        let n = owner.wire_len();
        scratch.message[at..at + n].copy_from_slice(owner.wire());
        at += n;
        scratch.message[at..at + 2].copy_from_slice(&set.kind.to_be_bytes());
        scratch.message[at + 2..at + 4].copy_from_slice(&set.class.to_be_bytes());
        scratch.message[at + 4..at + 8].copy_from_slice(&sig.original_ttl.to_be_bytes());
        scratch.message[at + 8..at + 10].copy_from_slice(&(data.len() as u16).to_be_bytes());
        at += 10;
        scratch.message[at..at + data.len()].copy_from_slice(data);
        at += data.len();
    }
    Ok((size, wildcard))
}
fn verify_key<'a>(
    zone: Name<'a>,
    key: Dnskey<'_>,
    set: Rrset<'a>,
    signatures: Rrset<'a>,
    now: u32,
    crypto: &impl Crypto,
    scratch: &mut Scratch<'_>,
) -> Result<Validated<'a>, Error> {
    if !key.usable()
        || signatures.kind != 46
        || set.class != signatures.class
        || !name_eq(set.owner, signatures.owner)
        || !within(set.owner, zone)
    {
        return Err(Error::Authentication);
    }
    let mut last = Error::Authentication;
    for data in signatures.records {
        let sig = match Rrsig::parse(data) {
            Ok(sig) => sig,
            Err(error) => {
                last = error;
                continue;
            }
        };
        if usize::from(sig.labels) > set.owner.labels().count()
            || usize::from(sig.labels) < zone.labels().count()
            || sig.kind != set.kind
            || sig.algorithm != key.algorithm
            || sig.key_tag != key.tag()
            || !name_eq(sig.signer, zone)
        {
            continue;
        }
        let ttl = match sig.remaining(now) {
            Ok(ttl) => ttl,
            Err(error) => {
                last = error;
                continue;
            }
        };
        let (n, wildcard) = message(set, sig, scratch)?;
        match crypto.verify(sig.algorithm, key.key, &scratch.message[..n], sig.signature) {
            Ok(()) => {
                return Ok(Validated {
                    set,
                    signer: zone,
                    labels: sig.labels,
                    ttl: ttl.min(sig.original_ttl).min(set.ttl).min(signatures.ttl),
                    wildcard,
                });
            }
            Err(error) => last = error,
        }
    }
    Err(last)
}
/// Authenticate a DNSKEY RRset from the exact original DS trust anchors. A
/// digest match alone is insufficient: a matching key must sign the whole set.
pub fn trust_dnskeys<'a>(
    zone: Name<'a>,
    ds: &[&[u8]],
    keys: Rrset<'a>,
    signatures: Rrset<'a>,
    now: u32,
    crypto: &impl Crypto,
    scratch: &mut Scratch<'_>,
) -> Result<TrustedKeys<'a>, Error> {
    if keys.kind != 48 || !name_eq(keys.owner, zone) || ds.is_empty() {
        return Err(Error::Authentication);
    }
    let mut name = [0; 255];
    name[..zone.wire_len()].copy_from_slice(zone.wire());
    name[..zone.wire_len()].make_ascii_lowercase();
    let strong = ds.iter().any(|d| d.len() >= 4 && matches!(d[3], 2 | 4));
    let mut last = Error::Authentication;
    for raw in keys.records {
        let key = match Dnskey::parse(raw) {
            Ok(key) if key.usable() => key,
            _ => continue,
        };
        for anchor in ds {
            if anchor.len() < 4 {
                last = Error::Truncated;
                continue;
            }
            if key.tag() != u16::from_be_bytes([anchor[0], anchor[1]])
                || key.algorithm != anchor[2]
                || (strong && anchor[3] == 1)
            {
                continue;
            }
            let mut hash = [0; 48];
            let n = match crypto.digest(anchor[3], &[&name[..zone.wire_len()], raw], &mut hash) {
                Ok(n) if n <= hash.len() => n,
                Ok(_) => return Err(Error::Malformed),
                Err(error) => {
                    last = error;
                    continue;
                }
            };
            if hash[..n] != anchor[4..] {
                continue;
            }
            match verify_key(zone, key, keys, signatures, now, crypto, scratch) {
                Ok(validated) => {
                    return Ok(TrustedKeys {
                        zone,
                        set: keys,
                        verified_at: now,
                        ttl: validated.ttl(),
                    });
                }
                Err(error) => last = error,
            }
        }
    }
    Err(last)
}
/// Verify a complete real RRset under an already authenticated DNSKEY set.
/// Any expanded wildcard still requires a separate positive-wildcard proof.
pub fn verify_rrset<'a>(
    keys: TrustedKeys<'a>,
    set: Rrset<'a>,
    signatures: Rrset<'a>,
    now: u32,
    crypto: &impl Crypto,
    scratch: &mut Scratch<'_>,
) -> Result<Validated<'a>, Error> {
    if set.class != keys.set.class {
        return Err(Error::Authentication);
    }
    let chain_ttl = keys.remaining(now)?;
    let mut last = Error::Authentication;
    for raw in keys.set.records {
        let key = match Dnskey::parse(raw) {
            Ok(key) => key,
            Err(error) => {
                last = error;
                continue;
            }
        };
        match verify_key(keys.zone, key, set, signatures, now, crypto, scratch) {
            Ok(mut validated) => {
                validated.ttl = validated.ttl.min(chain_ttl);
                return Ok(validated);
            }
            Err(error) => last = error,
        }
    }
    Err(last)
}
