//! Fixed-size DNS address transformation without recompressing unknown RDATA.
use gnunet_dns::{AbsoluteTime, Arena, Header, RData, Reader, Type};
use gnunet_types::Error;
/// One literal IP address, in its original network representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Address {
    /// IPv4 network bytes.
    V4([u8; 4]),
    /// IPv6 network bytes.
    V6([u8; 16]),
}
impl Address {
    /// Exact address bytes, without family/padding or a port.
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::V4(a) => a,
            Self::V6(a) => a,
        }
    }
    /// Official DNS resource record type.
    pub const fn kind(self) -> Type {
        match self {
            Self::V4(_) => Type::A,
            Self::V6(_) => Type::AAAA,
        }
    }
}
/// Enabled address families; disabled records are preserved byte for byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Families {
    /// Transform A records.
    pub ipv4: bool,
    /// Transform AAAA records.
    pub ipv6: bool,
}
/// Fully checked source record, with offsets sealed against caller mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AddressRecord {
    address: Address,
    data: usize,
    ttl: usize,
    seconds: u32,
}
impl AddressRecord {
    /// An empty caller slot, overwritten only by scan's returned prefix.
    pub const EMPTY: Self = Self {
        address: Address::V4([0; 4]),
        data: 0,
        ttl: 0,
        seconds: 0,
    };
    /// Original destination for the VPN allocation.
    pub const fn address(self) -> Address {
        self.address
    }
    /// Original relative TTL in seconds.
    pub const fn ttl_seconds(self) -> u32 {
        self.seconds
    }
}
/// One actual same-family VPN allocation, with its original absolute expiry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Replacement {
    /// Address actually returned by the VPN service.
    pub address: Address,
    /// Original requested VPN allocation expiration, microseconds.
    pub lease_until: u64,
}
fn reader(input: &[u8], limits: gnunet_dns::Limits) -> Result<Reader<'_>, Error> {
    let h = Header::decode(input)?;
    let count = usize::from(h.counts.answers)
        + usize::from(h.counts.authority)
        + usize::from(h.counts.additional);
    if usize::from(h.counts.queries) > limits.maximum_queries || count > limits.maximum_records {
        return Err(Error::Capacity);
    }
    Reader::at(input, 12, input.len(), limits)
}
fn selected(kind: Type, f: Families) -> bool {
    (kind == Type::A && f.ipv4) || (kind == Type::AAAA && f.ipv6)
}
/// Validate all counted sections and collect every enabled A/AAAA record in wire
/// order. Scratch is reused for each query/record, not retained per record. The
/// caller supplies enough scratch for one expanded record (packet bytes+510 is
/// sufficient). Trailing bytes and malformed address lengths are rejected.
pub fn scan(
    input: &[u8],
    families: Families,
    out: &mut [AddressRecord],
    scratch: &mut [u8],
    limits: gnunet_dns::Limits,
) -> Result<usize, Error> {
    let h = Header::decode(input)?;
    let mut r = reader(input, limits)?;
    for _ in 0..h.counts.queries {
        r.query(&mut Arena::new(scratch))?;
    }
    let mut used = 0;
    for count in [h.counts.answers, h.counts.authority, h.counts.additional] {
        for _ in 0..count {
            let rec = r.record(AbsoluteTime::from_micros(0), &mut Arena::new(scratch))?;
            if rec.kind == Type::A || rec.kind == Type::AAAA {
                let RData::Raw(raw) = rec.data else {
                    return Err(Error::Malformed);
                };
                let address = if rec.kind == Type::A {
                    Address::V4(raw.try_into().map_err(|_| Error::Malformed)?)
                } else {
                    Address::V6(raw.try_into().map_err(|_| Error::Malformed)?)
                };
                if selected(rec.kind, families) {
                    let data = r
                        .position()
                        .checked_sub(raw.len())
                        .ok_or(Error::Malformed)?;
                    let ttl = data.checked_sub(6).ok_or(Error::Malformed)?;
                    let seconds = u32::from_be_bytes(
                        input
                            .get(ttl..ttl + 4)
                            .ok_or(Error::Truncated)?
                            .try_into()
                            .map_err(|_| Error::Truncated)?,
                    );
                    *out.get_mut(used).ok_or(Error::Capacity)? = AddressRecord {
                        address,
                        data,
                        ttl,
                        seconds,
                    };
                    used += 1;
                }
            }
        }
    }
    if r.position() != input.len() {
        return Err(Error::Malformed);
    }
    Ok(used)
}
/// Validate a complete packet, including address widths, without retaining it.
pub fn validate(input: &[u8], scratch: &mut [u8], limits: gnunet_dns::Limits) -> Result<(), Error> {
    let h = Header::decode(input)?;
    let mut r = reader(input, limits)?;
    for _ in 0..h.counts.queries {
        r.query(&mut Arena::new(scratch))?;
    }
    for n in [h.counts.answers, h.counts.authority, h.counts.additional] {
        for _ in 0..n {
            let v = r.record(AbsoluteTime::from_micros(0), &mut Arena::new(scratch))?;
            if let RData::Raw(raw) = v.data
                && ((v.kind == Type::A && raw.len() != 4)
                    || (v.kind == Type::AAAA && raw.len() != 16))
            {
                return Err(Error::Malformed);
            }
        }
    }
    if r.position() != input.len() {
        return Err(Error::Malformed);
    }
    Ok(())
}
/// Compare complete questions semantically, accepting ASCII case differences in
/// DNS labels. This is correlation with the original query, not DNSSEC proof.
pub fn same_questions(
    query: &[u8],
    response: &[u8],
    a: &mut [u8],
    b: &mut [u8],
    limits: gnunet_dns::Limits,
) -> Result<bool, Error> {
    let qh = Header::decode(query)?;
    let rh = Header::decode(response)?;
    if qh.counts.queries != rh.counts.queries
        || qh.flags.opcode() != rh.flags.opcode()
        || !rh.flags.query_or_response()
    {
        return Ok(false);
    }
    let mut q = reader(query, limits)?;
    let mut r = reader(response, limits)?;
    for _ in 0..qh.counts.queries {
        let left = q.query(&mut Arena::new(a))?;
        let right = r.query(&mut Arena::new(b))?;
        if left.kind != right.kind
            || left.class != right.class
            || !left.name.wire().eq_ignore_ascii_case(right.name.wire())
        {
            return Ok(false);
        }
    }
    Ok(true)
}
/// Caller-owned output and reusable parsing scratch for one transformation.
pub struct RewriteBuffers<'a> {
    /// Separate packet output, published only after successful validation.
    pub output: &'a mut [u8],
    /// Scratch for parsing the original packet.
    pub original: &'a mut [u8],
    /// Independent scratch for parsing the transformed packet.
    pub transformed: &'a mut [u8],
}
/// Write replacements into a separate output and validate that compression has
/// not changed any owner, question or non-address RDATA through an alias into a
/// modified field. On failure output is unspecified and must not be published.
/// Original input is never mutated. TTL is bounded by both its original value
/// and every corresponding allocation's actual remaining lease; AD is cleared.
pub fn rewrite(
    input: &[u8],
    records: &[AddressRecord],
    replacements: &[Replacement],
    now: u64,
    buffers: RewriteBuffers<'_>,
    limits: gnunet_dns::Limits,
) -> Result<usize, Error> {
    rewrite_with_ttl(input, records, replacements, now, buffers, limits, false)
}
/// Prepare a PT reply for immutable native queuing. Only transformed A/AAAA
/// TTLs become zero, avoiding adding queue/partial-write time to finite VPN
/// leases. The same complete compression-alias/invariance validation runs after
/// TTL0 is written; original input, other records and actual leases are intact.
pub fn rewrite_uncached(
    input: &[u8],
    records: &[AddressRecord],
    replacements: &[Replacement],
    now: u64,
    buffers: RewriteBuffers<'_>,
    limits: gnunet_dns::Limits,
) -> Result<usize, Error> {
    rewrite_with_ttl(input, records, replacements, now, buffers, limits, true)
}
fn rewrite_with_ttl(
    input: &[u8],
    records: &[AddressRecord],
    replacements: &[Replacement],
    now: u64,
    buffers: RewriteBuffers<'_>,
    limits: gnunet_dns::Limits,
    uncached: bool,
) -> Result<usize, Error> {
    let RewriteBuffers {
        output: out,
        original: scratch_a,
        transformed: scratch_b,
    } = buffers;
    if records.len() != replacements.len() || out.len() < input.len() {
        return Err(Error::Capacity);
    }
    out[..input.len()].copy_from_slice(input);
    let out = &mut out[..input.len()];
    for (record, replacement) in records.iter().zip(replacements) {
        if record.address.kind() != replacement.address.kind() || replacement.lease_until <= now {
            return Err(Error::Deadline);
        }
        let n = record.address.bytes().len();
        if input.get(record.data..record.data + n) != Some(record.address.bytes())
            || input.get(record.ttl..record.ttl + 4)
                != Some(record.seconds.to_be_bytes().as_slice())
        {
            return Err(Error::Stale);
        }
        let seconds = u32::try_from((replacement.lease_until - now) / 1_000_000)
            .unwrap_or(u32::MAX)
            .min(record.seconds);
        let seconds = if uncached { 0 } else { seconds };
        out.get_mut(record.data..record.data + n)
            .ok_or(Error::Malformed)?
            .copy_from_slice(replacement.address.bytes());
        out.get_mut(record.ttl..record.ttl + 4)
            .ok_or(Error::Malformed)?
            .copy_from_slice(&seconds.to_be_bytes());
    }
    if !records.is_empty() {
        out[3] &= !0x20;
    }
    let h = Header::decode(input)?;
    let mut l = reader(input, limits)?;
    let mut r = reader(out, limits)?;
    for _ in 0..h.counts.queries {
        let a = l.query(&mut Arena::new(scratch_a))?;
        let b = r.query(&mut Arena::new(scratch_b))?;
        if a != b {
            return Err(Error::Malformed);
        }
    }
    let mut applied = 0;
    for count in [h.counts.answers, h.counts.authority, h.counts.additional] {
        for _ in 0..count {
            let left = l.record(AbsoluteTime::from_micros(0), &mut Arena::new(scratch_a))?;
            let right = r.record(AbsoluteTime::from_micros(0), &mut Arena::new(scratch_b))?;
            if left.name != right.name
                || left.kind != right.kind
                || left.class != right.class
                || l.position() != r.position()
            {
                return Err(Error::Malformed);
            }
            let target = records
                .get(applied)
                .filter(|rec| rec.data + rec.address.bytes().len() == l.position());
            if let Some(target) = target {
                if target.address.kind() != left.kind {
                    return Err(Error::Malformed);
                }
                let RData::Raw(raw) = right.data else {
                    return Err(Error::Malformed);
                };
                if raw != replacements[applied].address.bytes() {
                    return Err(Error::Malformed);
                }
                applied += 1;
            } else if left.data != right.data || left.expiration != right.expiration {
                return Err(Error::Malformed);
            }
        }
    }
    if applied != records.len() || l.position() != input.len() || r.position() != out.len() {
        return Err(Error::Malformed);
    }
    Ok(out.len())
}
