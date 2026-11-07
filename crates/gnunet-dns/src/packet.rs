use crate::record::Write;
use crate::{
    AbsoluteTime, Arena, Cert, Error, HEADER_LEN, Limits, MAX_WIRE_NAME_LENGTH, Mx, Name, RData,
    Record, Soa, Srv, Type, Uri, ttl_expiration,
};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// DNS query name, type and class.
pub struct Query<'a> {
    /// Record owner or query name, retaining original wire label octets.
    pub name: Name<'a>,
    /// Lossless DNS type number.
    pub kind: Type,
    /// Lossless DNS class number.
    pub class: u16,
}
impl<'a> Query<'a> {
    /// Empty placeholder for caller-owned object slots.
    pub const EMPTY: Self = Self {
        name: Name::ROOT,
        kind: Type(0),
        class: 0,
    };
    /// Compute checked encoded byte length before any output mutation.
    pub const fn encoded_len(self) -> usize {
        self.name.wire_len() + 4
    }
    /// Preflight and encode the complete value; errors preserve the complete output slice.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len();
        if out.len() < n {
            return Err(Error::Capacity);
        }
        let mut w = Write::new(out);
        self.write(&mut w);
        Ok(n)
    }
    /// Append atomically; errors preserve the complete destination and cursor.
    pub fn encode_at(self, out: &mut [u8], offset: &mut usize) -> Result<usize, Error> {
        let n = self.encoded_len();
        let end = offset.checked_add(n).ok_or(Error::Overflow)?;
        if end > out.len() {
            return Err(Error::Capacity);
        }
        self.encode(&mut out[*offset..end])?;
        *offset = end;
        Ok(n)
    }
    /// Deep-copy every borrowed name/payload into independent caller arena storage.
    pub fn duplicate_into<'t, 'b: 't>(self, a: &mut Arena<'b>) -> Result<Query<'b>, Error> {
        Ok(Query {
            name: self.name.duplicate_into(a)?,
            kind: self.kind,
            class: self.class,
        })
    }
    fn write(self, w: &mut Write<'_>) {
        w.bytes(self.name.wire());
        w.u16(self.kind.0);
        w.u16(self.class);
    }
}
/// Bounded low-level parser. Typed reads commit the cursor only on success;
/// errors may spend work and consume arena storage. Input remains caller-owned.
/// Bounded transactional wire reader with explicit packet context.
pub struct Reader<'i> {
    input: &'i [u8],
    pos: usize,
    end: usize,
    work: usize,
    limits: Limits,
}
impl<'i> Reader<'i> {
    /// Construct the explicit caller-owned view/state without allocating.
    pub fn new(input: &'i [u8], limits: Limits) -> Result<Self, Error> {
        Self::at(input, 0, input.len(), limits)
    }
    /// Create a bounded Reader with an explicit initial position and logical RDATA end.
    pub fn at(input: &'i [u8], offset: usize, end: usize, limits: Limits) -> Result<Self, Error> {
        if input.len() > limits.maximum_packet_bytes {
            return Err(Error::Capacity);
        }
        if offset > end || end > input.len() {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            input,
            pos: offset,
            end,
            work: limits.maximum_work,
            limits,
        })
    }
    /// Current committed input position.
    pub const fn position(&self) -> usize {
        self.pos
    }
    /// Remaining byte/label/pointer budget.
    pub const fn remaining_work(&self) -> usize {
        self.work
    }
    fn spend(&mut self, n: usize) -> Result<(), Error> {
        self.work = self.work.checked_sub(n).ok_or(Error::Capacity)?;
        Ok(())
    }
    fn take(&mut self, n: usize) -> Result<&'i [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::Overflow)?;
        if end > self.end {
            return Err(Error::Truncated);
        }
        self.spend(n)?;
        let result = &self.input[self.pos..end];
        self.pos = end;
        Ok(result)
    }
    fn u16(&mut self) -> Result<u16, Error> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32, Error> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    /// Expand one bounded name, including native backward/forward compression.
    /// Errors retain the cursor; no out-of-bounds pointer byte is inspected.
    pub fn name<'a>(&mut self, a: &mut Arena<'a>) -> Result<Name<'a>, Error> {
        let mut pos = self.pos;
        let mut consumed = None;
        let mut hops = 0;
        let mut last_pointer_used = None;
        let mut wire = [0; MAX_WIRE_NAME_LENGTH];
        let mut used: usize = 0;
        loop {
            let bound = if consumed.is_some() {
                self.input.len()
            } else {
                self.end
            };
            if pos >= bound {
                return Err(Error::Truncated);
            }
            self.spend(1)?;
            let tag = self.input[pos];
            if tag == 0 {
                if used >= wire.len() {
                    return Err(Error::TooLarge);
                }
                wire[used] = 0;
                let name = Name::from_wire(a.copy(&wire[..used + 1])?)?.with_native_parse_hints(
                    last_pointer_used.is_some_and(|n| n == used && used > 0),
                    last_pointer_used.map(|_| self.input.len() - 1),
                );
                self.pos = consumed.unwrap_or(pos + 1);
                return Ok(name);
            }
            if tag & 0xc0 == 0xc0 {
                let second = pos.checked_add(1).ok_or(Error::Overflow)?;
                if second >= bound {
                    return Err(Error::Truncated);
                }
                self.spend(1)?;
                if hops
                    >= self
                        .limits
                        .maximum_compression_hops
                        .min(crate::MAX_COMPRESSION_HOPS)
                {
                    return Err(Error::Malformed);
                }
                hops += 1;
                let target = ((usize::from(tag & 0x3f)) << 8) | usize::from(self.input[second]);
                if target >= self.input.len() {
                    return Err(Error::Malformed);
                }
                if consumed.is_none() {
                    consumed = Some(second + 1);
                }
                last_pointer_used = Some(used);
                pos = target;
                continue;
            }
            if tag & 0xc0 != 0 {
                return Err(Error::Malformed);
            }
            let length = usize::from(tag);
            let end = pos.checked_add(1 + length).ok_or(Error::Overflow)?;
            if end > bound {
                return Err(Error::Truncated);
            }
            let next = used.checked_add(1 + length).ok_or(Error::Overflow)?;
            if next >= wire.len() {
                return Err(Error::TooLarge);
            }
            self.spend(length)?;
            wire[used] = tag;
            wire[used + 1..next].copy_from_slice(&self.input[pos + 1..end]);
            used = next;
            pos = end;
        }
    }
    /// Read a complete query; errors restore the cursor but may consume arena/work.
    pub fn query<'a>(&mut self, a: &mut Arena<'a>) -> Result<Query<'a>, Error> {
        let start = self.pos;
        let result = (|| {
            Ok(Query {
                name: self.name(a)?,
                kind: Type(self.u16()?),
                class: self.u16()?,
            })
        })();
        if result.is_err() {
            self.pos = start;
        }
        result
    }
    /// Read one typed RDATA prefix within the explicit Reader end. Low-level
    /// hostname/MX/SOA/SRV reads may leave bytes; record() enforces exact RDLEN.
    /// Compression references retain the whole-packet context.
    pub fn data<'a>(&mut self, kind: Type, a: &mut Arena<'a>) -> Result<RData<'a>, Error> {
        let start = self.pos;
        let result = self.data_inner(kind, a);
        if result.is_err() {
            self.pos = start;
        }
        result
    }
    fn data_inner<'a>(&mut self, kind: Type, a: &mut Arena<'a>) -> Result<RData<'a>, Error> {
        Ok(if kind.is_hostname() {
            RData::Hostname(self.name(a)?)
        } else {
            match kind {
                Type::MX => RData::Mx(Mx {
                    preference: self.u16()?,
                    host: self.name(a)?,
                }),
                Type::SRV => RData::Srv(Srv {
                    priority: self.u16()?,
                    weight: self.u16()?,
                    port: self.u16()?,
                    target: self.name(a)?,
                }),
                Type::SOA => RData::Soa(Soa {
                    mname: self.name(a)?,
                    rname: self.name(a)?,
                    serial: self.u32()?,
                    refresh: self.u32()?,
                    retry: self.u32()?,
                    expire: self.u32()?,
                    minimum_ttl: self.u32()?,
                }),
                Type::CERT => {
                    let cert_type = self.u16()?;
                    let key_tag = self.u16()?;
                    let algorithm = self.take(1)?[0];
                    let data = a.copy(self.take(self.end - self.pos)?)?;
                    RData::Cert(Cert {
                        cert_type,
                        key_tag,
                        algorithm,
                        data,
                    })
                }
                Type::URI => {
                    let priority = self.u16()?;
                    let weight = self.u16()?;
                    let target = a.copy(self.take(self.end - self.pos)?)?;
                    if target.is_empty() {
                        return Err(Error::Malformed);
                    }
                    RData::Uri(Uri {
                        priority,
                        weight,
                        target,
                    })
                }
                _ => RData::Raw(a.copy(self.take(self.end - self.pos)?)?),
            }
        })
    }
    /// Read MX preference and name from the bounded RDATA region.
    pub fn mx<'a>(&mut self, arena: &mut Arena<'a>) -> Result<Mx<'a>, Error> {
        match self.data(Type::MX, arena)? {
            RData::Mx(value) => Ok(value),
            _ => Err(Error::Malformed),
        }
    }
    /// Read two SOA names and all five32-bit values.
    pub fn soa<'a>(&mut self, arena: &mut Arena<'a>) -> Result<Soa<'a>, Error> {
        match self.data(Type::SOA, arena)? {
            RData::Soa(value) => Ok(value),
            _ => Err(Error::Malformed),
        }
    }
    /// Read SRV priority, weight, port and target name.
    pub fn srv<'a>(&mut self, arena: &mut Arena<'a>) -> Result<Srv<'a>, Error> {
        match self.data(Type::SRV, arena)? {
            RData::Srv(value) => Ok(value),
            _ => Err(Error::Malformed),
        }
    }
    /// Read an RFC4398 five-octet CERT prefix and complete bounded certificate tail.
    pub fn cert<'a>(&mut self, arena: &mut Arena<'a>) -> Result<Cert<'a>, Error> {
        match self.data(Type::CERT, arena)? {
            RData::Cert(value) => Ok(value),
            _ => Err(Error::Malformed),
        }
    }
    /// Read both URI scalars and the complete nonempty RFC7553 target tail.
    pub fn uri<'a>(&mut self, arena: &mut Arena<'a>) -> Result<Uri<'a>, Error> {
        match self.data(Type::URI, arena)? {
            RData::Uri(value) => Ok(value),
            _ => Err(Error::Malformed),
        }
    }
    /// Read a complete resource record with explicit UTC and exact RDLEN checks.
    pub fn record<'a>(
        &mut self,
        now: AbsoluteTime,
        a: &mut Arena<'a>,
    ) -> Result<Record<'a>, Error> {
        let start = self.pos;
        let result = (|| {
            let name = self.name(a)?;
            let kind = Type(self.u16()?);
            let class = self.u16()?;
            let expiration = ttl_expiration(self.u32()?, now);
            let length = usize::from(self.u16()?);
            let data_end = self.pos.checked_add(length).ok_or(Error::Overflow)?;
            if data_end > self.end {
                return Err(Error::Truncated);
            }
            let old_end = self.end;
            self.end = data_end;
            let data = self.data_inner(kind, a);
            self.end = old_end;
            let data = data?;
            if self.pos != data_end {
                return Err(Error::Malformed);
            }
            Ok(Record {
                name,
                kind,
                class,
                expiration,
                data,
            })
        })();
        if result.is_err() {
            self.pos = start;
        }
        result
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Four16-bit DNS section counts.
pub struct Counts {
    /// Counted query entries.
    pub queries: u16,
    /// Counted answer entries.
    pub answers: u16,
    /// Counted authority records.
    pub authority: u16,
    /// Counted additional records.
    pub additional: u16,
}
impl Counts {
    /// No emitted objects in any section.
    pub const ZERO: Self = Self {
        queries: 0,
        answers: 0,
        authority: 0,
        additional: 0,
    };
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Committed packet length, actual counts and truncation outcome.
pub struct PackReport {
    /// Number of packet bytes committed.
    pub written: usize,
    /// Uncompressed byte length required for all supplied objects.
    pub full_size: usize,
    /// Whether any supplied section prefix did not fit.
    pub truncated: bool,
    /// Actual fully emitted section counts.
    pub counts: Counts,
}
/// ID and flags are lossless wire values. Parsing retains any trailing bytes;
/// packing serializes only the counted objects, never an untrusted hidden tail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Borrowed caller-slot packet view with independent data-storage lifetime.
pub struct Packet<'s, 'a> {
    /// Opaque two-octet wire transaction identifier.
    pub id: [u8; 2],
    /// Lossless native DNS/CAA flag bits.
    pub flags: u16,
    /// Counted query entries.
    pub queries: &'s [Query<'a>],
    /// Counted answer entries.
    pub answers: &'s [Record<'a>],
    /// Counted authority records.
    pub authority: &'s [Record<'a>],
    /// Counted additional records.
    pub additional: &'s [Record<'a>],
    /// Copied uncounted trailing input bytes; encoding omits them.
    pub trailing: &'a [u8],
    /// Input position immediately after the final counted object.
    pub consumed: usize,
}
impl<'s, 'a: 's> Packet<'s, 'a> {
    /// Construct the explicit caller-owned view/state without allocating.
    pub const fn new(
        id: [u8; 2],
        flags: u16,
        queries: &'s [Query<'a>],
        answers: &'s [Record<'a>],
        authority: &'s [Record<'a>],
        additional: &'s [Record<'a>],
    ) -> Self {
        Self {
            id,
            flags,
            queries,
            answers,
            authority,
            additional,
            trailing: &[],
            consumed: 0,
        }
    }
    /// Parse a bounded input into caller-owned storage; return no partial typed result.
    pub fn parse(
        input: &[u8],
        now: AbsoluteTime,
        a: &mut Arena<'a>,
        queries: &'s mut [Query<'a>],
        records: &'s mut [Record<'a>],
        limits: Limits,
    ) -> Result<Self, Error> {
        let mut rd = Reader::new(input, limits)?;
        let h = rd.take(HEADER_LEN)?;
        let id = [h[0], h[1]];
        let flags = u16::from_be_bytes([h[2], h[3]]);
        let count = |i| usize::from(u16::from_be_bytes([h[i], h[i + 1]]));
        let q = count(4);
        let an = count(6);
        let au = count(8);
        let ad = count(10);
        let total = an
            .checked_add(au)
            .and_then(|v| v.checked_add(ad))
            .ok_or(Error::Overflow)?;
        if q > limits.maximum_queries
            || total > limits.maximum_records
            || q > queries.len()
            || total > records.len()
        {
            return Err(Error::Capacity);
        }
        // Even a root name needs one octet. Reject impossible counts before
        // touching caller slots or spending work on a large error cleanup.
        let minimum = q
            .checked_mul(5)
            .and_then(|n| total.checked_mul(11).and_then(|r| n.checked_add(r)))
            .and_then(|n| n.checked_add(HEADER_LEN))
            .ok_or(Error::Overflow)?;
        if minimum > input.len() {
            return Err(Error::Truncated);
        }
        let mut queries_written = 0;
        let mut records_written = 0;
        let result = (|| {
            for slot in &mut queries[..q] {
                *slot = rd.query(a)?;
                queries_written += 1;
            }
            for slot in &mut records[..total] {
                *slot = rd.record(now, a)?;
                records_written += 1;
            }
            a.copy(&input[rd.pos..])
        })();
        let trailing = match result {
            Ok(value) => value,
            Err(e) => {
                queries[..queries_written].fill(Query::EMPTY);
                records[..records_written].fill(Record::EMPTY);
                return Err(e);
            }
        };
        let (answers, tail) = records[..total].split_at(an);
        let (authority, additional) = tail.split_at(au);
        Ok(Self {
            id,
            flags,
            queries: &queries[..q],
            answers,
            authority,
            additional,
            trailing,
            consumed: rd.pos,
        })
    }
    /// Check that every section count fits16 bits.
    pub fn counts(self) -> Result<Counts, Error> {
        Ok(Counts {
            queries: u16::try_from(self.queries.len()).map_err(|_| Error::TooLarge)?,
            answers: u16::try_from(self.answers.len()).map_err(|_| Error::TooLarge)?,
            authority: u16::try_from(self.authority.len()).map_err(|_| Error::TooLarge)?,
            additional: u16::try_from(self.additional.len()).map_err(|_| Error::TooLarge)?,
        })
    }
    /// Compute checked encoded byte length before any output mutation.
    pub fn encoded_len(self) -> Result<usize, Error> {
        self.counts()?;
        let mut size = HEADER_LEN;
        for q in self.queries {
            size = size.checked_add(q.encoded_len()).ok_or(Error::Overflow)?;
        }
        for section in [self.answers, self.authority, self.additional] {
            for r in section {
                size = size.checked_add(r.encoded_len()?).ok_or(Error::Overflow)?;
            }
        }
        Ok(size)
    }
    /// Full atomic output. Truncation is available only through explicit pack().
    /// Preflight and encode the complete value; errors preserve the complete output slice.
    pub fn encode(self, now: AbsoluteTime, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len()?;
        if n > u16::MAX as usize {
            return Err(Error::TooLarge);
        }
        if n > out.len() {
            return Err(Error::Capacity);
        }
        Ok(self.pack(now, out, n as u16)?.written)
    }
    /// Native section-prefix packing with corrected actual counts and TC. All
    /// object validation occurs before output changes, even for truncated objects.
    /// Validate all objects, then encode section prefixes with actual counts and explicit truncation status.
    pub fn pack(
        self,
        now: AbsoluteTime,
        out: &mut [u8],
        maximum: u16,
    ) -> Result<PackReport, Error> {
        let full_size = self.encoded_len()?;
        let cap = out.len().min(usize::from(maximum));
        if cap < HEADER_LEN {
            return Err(Error::Capacity);
        }
        let mut size = HEADER_LEN;
        let mut counts = Counts::ZERO;
        let mut truncated = false;
        for q in self.queries {
            let next = size.checked_add(q.encoded_len()).ok_or(Error::Overflow)?;
            if next > cap {
                truncated = true;
                break;
            }
            size = next;
            counts.queries += 1;
        }
        for (section, count) in [
            (self.answers, &mut counts.answers),
            (self.authority, &mut counts.authority),
            (self.additional, &mut counts.additional),
        ] {
            for r in section {
                let next = size.checked_add(r.encoded_len()?).ok_or(Error::Overflow)?;
                if next > cap {
                    truncated = true;
                    break;
                }
                size = next;
                *count += 1;
            }
        }
        let mut w = Write::new(out);
        w.bytes(&self.id);
        w.u16(self.flags | if truncated { 0x0200 } else { 0 });
        for n in [
            counts.queries,
            counts.answers,
            counts.authority,
            counts.additional,
        ] {
            w.u16(n);
        }
        for q in &self.queries[..usize::from(counts.queries)] {
            q.write(&mut w);
        }
        for (section, count) in [
            (self.answers, counts.answers),
            (self.authority, counts.authority),
            (self.additional, counts.additional),
        ] {
            for r in &section[..usize::from(count)] {
                r.write(now, &mut w)?;
            }
        }
        Ok(PackReport {
            written: w.pos,
            full_size,
            truncated,
            counts,
        })
    }
    /// Deep-copy every borrowed name/payload into independent caller arena storage.
    pub fn duplicate_into<'t, 'b: 't>(
        self,
        a: &mut Arena<'b>,
        queries: &'t mut [Query<'b>],
        records: &'t mut [Record<'b>],
    ) -> Result<Packet<'t, 'b>, Error> {
        let total = self
            .answers
            .len()
            .checked_add(self.authority.len())
            .and_then(|n| n.checked_add(self.additional.len()))
            .ok_or(Error::Overflow)?;
        if queries.len() < self.queries.len() || records.len() < total {
            return Err(Error::Capacity);
        }
        self.encoded_len()?;
        let mut needed = self.trailing.len();
        for q in self.queries {
            needed = needed
                .checked_add(q.name.wire_len())
                .ok_or(Error::Overflow)?;
        }
        for section in [self.answers, self.authority, self.additional] {
            for r in section {
                needed = needed
                    .checked_add(r.name.wire_len())
                    .and_then(|n| n.checked_add(r.data.copied_bytes().ok()?))
                    .ok_or(Error::Overflow)?;
            }
        }
        if needed > a.remaining() {
            return Err(Error::Capacity);
        }
        for (slot, q) in queries.iter_mut().zip(self.queries) {
            *slot = q.duplicate_into(a)?;
        }
        let mut pos = 0;
        for section in [self.answers, self.authority, self.additional] {
            for r in section {
                records[pos] = r.duplicate_into(a)?;
                pos += 1;
            }
        }
        let trailing = a.copy(self.trailing)?;
        let (answers, tail) = records[..total].split_at(self.answers.len());
        let (authority, additional) = tail.split_at(self.authority.len());
        Ok(Packet {
            id: self.id,
            flags: self.flags,
            queries: &queries[..self.queries.len()],
            answers,
            authority,
            additional,
            trailing,
            consumed: self.consumed,
        })
    }
}
