//! Native C text-to-wire staging, separate from lossless wire encoders.
use crate::{
    AbsoluteTime, Arena, Cert, Counts, Error, HEADER_LEN, Idna, Limits, MAX_WIRE_NAME_LENGTH, Mx,
    Name, Packet, Query, RData, Record, Soa, Srv, Uri,
};

/// Explicit reusable native text work/output slices and caller text limits.
/// Neither slice is retained in any returned name, record or packet.
pub struct NativeScratch<'a> {
    work: &'a mut [u8],
    text: &'a mut [u8],
    limits: Limits,
}
impl<'a> NativeScratch<'a> {
    /// Bind two disjoint caller slices; neither is allocated by this library.
    pub const fn new(work: &'a mut [u8], text: &'a mut [u8], limits: Limits) -> Self {
        Self { work, text, limits }
    }
    fn project(&mut self, name: Name<'_>, idna: &impl Idna) -> Result<usize, Error> {
        let n = name.write_native_text(idna, self.work, self.text)?;
        if n > self.limits.maximum_text_input_bytes {
            return Err(Error::Capacity);
        }
        Ok(n)
    }
    fn lookup_with_requirement<'b>(
        &mut self,
        name: Name<'_>,
        idna: &impl Idna,
        arena: &mut Arena<'b>,
    ) -> Result<(Name<'b>, usize), Failure> {
        let n = self.project(name, idna).map_err(Failure::Fault)?;
        let ascii_len = idna
            .to_ascii(&self.text[..n], self.work)
            .map_err(|e| match e {
                Error::Malformed | Error::InvalidInput => Failure::Semantic,
                _ => Failure::Fault(e),
            })?;
        let ascii = self
            .work
            .get(..ascii_len)
            .ok_or(Failure::Fault(Error::Malformed))?;
        if !ascii.is_ascii() || ascii.contains(&0) {
            return Err(Failure::Fault(Error::Malformed));
        }
        let name = Name::from_dotted_impl(ascii, arena, true).map_err(Failure::Fault)?;
        let required = ascii_len
            .checked_add(2)
            .ok_or(Failure::Fault(Error::Overflow))?;
        Ok((name, required))
    }
    fn lookup<'b>(
        &mut self,
        name: Name<'_>,
        idna: &impl Idna,
        arena: &mut Arena<'b>,
    ) -> Result<Name<'b>, Failure> {
        self.lookup_with_requirement(name, idna, arena).map(|v| v.0)
    }
    fn name_metric(&mut self, name: Name<'_>, idna: &impl Idna) -> Result<Metric, Failure> {
        let mut bytes = [0; MAX_WIRE_NAME_LENGTH];
        let mut arena = Arena::new(&mut bytes);
        let (name, required) = self.lookup_with_requirement(name, idna, &mut arena)?;
        Ok(Metric {
            wire: name.wire_len(),
            arena: name.wire_len(),
            required,
        })
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Native prefix-pack result. A rejected native lookup makes full size unknown.
pub struct NativePackReport {
    /// Committed wire bytes, including the12-byte DNS header.
    pub written: usize,
    /// Complete canonical native wire size, or None after any lookup rejection.
    /// Native conservative name prechecks can require more capacity than this size.
    pub native_size: Option<usize>,
    /// A capacity or native lookup refusal stopped at least one section prefix.
    pub truncated: bool,
    /// Actual emitted counts, correcting the native C counter underflow.
    pub counts: Counts,
}
#[derive(Clone, Copy)]
struct Metric {
    wire: usize,
    arena: usize,
    required: usize,
}
impl Metric {
    fn plus(self, other: Self) -> Result<Self, Failure> {
        Ok(Self {
            wire: self
                .wire
                .checked_add(other.wire)
                .ok_or(Failure::Fault(Error::Overflow))?,
            arena: self
                .arena
                .checked_add(other.arena)
                .ok_or(Failure::Fault(Error::Overflow))?,
            required: self.required.max(
                self.wire
                    .checked_add(other.required)
                    .ok_or(Failure::Fault(Error::Overflow))?,
            ),
        })
    }
    fn reserve(self, n: usize) -> Result<Self, Failure> {
        Ok(Self {
            wire: self
                .wire
                .checked_add(n)
                .ok_or(Failure::Fault(Error::Overflow))?,
            arena: self.arena,
            required: self
                .required
                .checked_add(n)
                .ok_or(Failure::Fault(Error::Overflow))?,
        })
    }
    const fn fixed(wire: usize, arena: usize) -> Self {
        Self {
            wire,
            arena,
            required: wire,
        }
    }
}

enum Failure {
    Semantic,
    Fault(Error),
}
impl Failure {
    fn error(self) -> Error {
        match self {
            Self::Semantic => Error::Malformed,
            Self::Fault(e) => e,
        }
    }
}
fn semantic_result<T>(v: Result<T, Failure>) -> Result<T, Error> {
    v.map_err(Failure::error)
}
fn validate_record_text(
    r: Record<'_>,
    idna: &impl Idna,
    s: &mut NativeScratch<'_>,
) -> Result<(), Error> {
    s.project(r.name, idna)?;
    // A native URI target is a C-string value. Keep the raw URI codec lossless,
    // but do not manufacture a native parsed record from bytes beyond a NUL.
    if let RData::Uri(uri) = r.data
        && uri.target.contains(&0)
    {
        return Err(Error::InvalidInput);
    }
    match r.data {
        RData::Hostname(n) => {
            s.project(n, idna)?;
        }
        RData::Mx(v) => {
            s.project(v.host, idna)?;
        }
        RData::Srv(v) => {
            s.project(v.target, idna)?;
        }
        RData::Soa(v) => {
            s.project(v.mname, idna)?;
            s.project(v.rname, idna)?;
        }
        _ => {}
    }
    Ok(())
}
fn record_metric(
    r: Record<'_>,
    idna: &impl Idna,
    s: &mut NativeScratch<'_>,
) -> Result<Metric, Failure> {
    r.data_len().map_err(Failure::Fault)?;
    let data = match r.data {
        RData::Hostname(n) => s.name_metric(n, idna)?,
        RData::Mx(v) => Metric::fixed(2, 0).plus(s.name_metric(v.host, idna)?)?,
        RData::Srv(v) => Metric::fixed(6, 0).plus(s.name_metric(v.target, idna)?)?,
        RData::Soa(v) => s
            .name_metric(v.mname, idna)?
            .plus(s.name_metric(v.rname, idna)?)?
            .plus(Metric::fixed(20, 0))?,
        RData::Cert(v) => Metric::fixed(5 + v.data.len(), v.data.len()),
        RData::Uri(v) => Metric::fixed(4 + v.target.len(), v.target.len()),
        RData::Raw(v) => Metric::fixed(v.len(), v.len()),
    };
    s.name_metric(r.name, idna)?.reserve(10)?.plus(data)
}
fn copy_record<'b>(
    r: Record<'_>,
    idna: &impl Idna,
    s: &mut NativeScratch<'_>,
    a: &mut Arena<'b>,
) -> Result<Record<'b>, Error> {
    let name = semantic_result(s.lookup(r.name, idna, a))?;
    let data = match r.data {
        RData::Hostname(n) => RData::Hostname(semantic_result(s.lookup(n, idna, a))?),
        RData::Mx(v) => RData::Mx(Mx {
            preference: v.preference,
            host: semantic_result(s.lookup(v.host, idna, a))?,
        }),
        RData::Srv(v) => RData::Srv(Srv {
            priority: v.priority,
            weight: v.weight,
            port: v.port,
            target: semantic_result(s.lookup(v.target, idna, a))?,
        }),
        RData::Soa(v) => RData::Soa(Soa {
            mname: semantic_result(s.lookup(v.mname, idna, a))?,
            rname: semantic_result(s.lookup(v.rname, idna, a))?,
            serial: v.serial,
            refresh: v.refresh,
            retry: v.retry,
            expire: v.expire,
            minimum_ttl: v.minimum_ttl,
        }),
        RData::Cert(v) => RData::Cert(Cert {
            cert_type: v.cert_type,
            key_tag: v.key_tag,
            algorithm: v.algorithm,
            data: a.copy(v.data)?,
        }),
        RData::Uri(v) => RData::Uri(Uri {
            priority: v.priority,
            weight: v.weight,
            target: a.copy(v.target)?,
        }),
        RData::Raw(v) => RData::Raw(a.copy(v)?),
    };
    Ok(Record {
        name,
        kind: r.kind,
        class: r.class,
        expiration: r.expiration,
        data,
    })
}
impl Name<'_> {
    /// Replay native Unicode/raw text then native ToASCII lookup into independent
    /// arena storage. This is distinct from preserving the original wire bytes.
    pub fn native_builder_form<'b>(
        self,
        idna: &impl Idna,
        s: &mut NativeScratch<'_>,
        a: &mut Arena<'b>,
    ) -> Result<Name<'b>, Error> {
        semantic_result(s.lookup(self, idna, a))
    }
}
impl Record<'_> {
    /// Canonical native builder form with independent names and payload storage.
    /// A refusal publishes no record; scratch may change and arena may be spent
    /// if a non-deterministic backend changes after successful preflight.
    pub fn native_builder_form<'b>(
        self,
        idna: &impl Idna,
        s: &mut NativeScratch<'_>,
        a: &mut Arena<'b>,
    ) -> Result<Record<'b>, Error> {
        validate_record_text(self, idna, s)?;
        let m = semantic_result(record_metric(self, idna, s))?;
        if m.arena > a.remaining() {
            return Err(Error::Capacity);
        }
        copy_record(self, idna, s, a)
    }
}
struct Plan {
    counts: Counts,
    selected_size: usize,
    arena: usize,
    native_size: Option<usize>,
    truncated: bool,
}
impl Plan {
    const fn new() -> Self {
        Self {
            counts: Counts::ZERO,
            selected_size: HEADER_LEN,
            arena: 0,
            native_size: Some(HEADER_LEN),
            truncated: false,
        }
    }
    fn consider(
        &mut self,
        m: Result<Metric, Failure>,
        stopped: &mut bool,
        count: &mut u16,
        cap: usize,
    ) -> Result<(), Error> {
        let m = match m {
            Ok(m) => m,
            Err(Failure::Semantic) => {
                self.native_size = None;
                *stopped = true;
                self.truncated = true;
                return Ok(());
            }
            Err(Failure::Fault(e)) => return Err(e),
        };
        if let Some(size) = self.native_size {
            self.native_size = Some(size.checked_add(m.wire).ok_or(Error::Overflow)?);
        }
        if !*stopped {
            let next = self
                .selected_size
                .checked_add(m.wire)
                .ok_or(Error::Overflow)?;
            let needed = self
                .selected_size
                .checked_add(m.required)
                .ok_or(Error::Overflow)?;
            if needed > cap {
                *stopped = true;
                self.truncated = true;
            } else {
                self.selected_size = next;
                self.arena = self.arena.checked_add(m.arena).ok_or(Error::Overflow)?;
                *count += 1;
            }
        }
        Ok(())
    }
}
impl<'s, 'a: 's> Packet<'s, 'a> {
    fn validate_native_source(
        self,
        idna: &impl Idna,
        s: &mut NativeScratch<'_>,
    ) -> Result<(), Error> {
        self.encoded_len()?;
        for q in self.queries {
            s.project(q.name, idna)?;
        }
        for section in [self.answers, self.authority, self.additional] {
            for r in section {
                validate_record_text(*r, idna, s)?;
            }
        }
        Ok(())
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "All destination slots, text scratch and arena ownership remain explicit in this internal staging boundary."
    )]
    fn selected_copy<'t, 'b: 't>(
        self,
        counts: Counts,
        idna: &impl Idna,
        s: &mut NativeScratch<'_>,
        a: &mut Arena<'b>,
        queries: &'t mut [Query<'b>],
        records: &'t mut [Record<'b>],
        copy_trailing: bool,
    ) -> Result<Packet<'t, 'b>, Error> {
        let mut qw = 0;
        let mut rw = 0;
        let result = (|| {
            for (slot, q) in queries
                .iter_mut()
                .zip(&self.queries[..usize::from(counts.queries)])
            {
                *slot = Query {
                    name: semantic_result(s.lookup(q.name, idna, a))?,
                    kind: q.kind,
                    class: q.class,
                };
                qw += 1;
            }
            for (section, count) in [
                (self.answers, counts.answers),
                (self.authority, counts.authority),
                (self.additional, counts.additional),
            ] {
                for r in &section[..usize::from(count)] {
                    records[rw] = copy_record(*r, idna, s, a)?;
                    rw += 1;
                }
            }
            if copy_trailing {
                a.copy(self.trailing)
            } else {
                Ok(&[][..])
            }
        })();
        let trailing = match result {
            Ok(v) => v,
            Err(e) => {
                queries[..qw].fill(Query::EMPTY);
                records[..rw].fill(Record::EMPTY);
                return Err(e);
            }
        };
        let (answers, tail) = records[..rw].split_at(usize::from(counts.answers));
        let (authority, additional) = tail.split_at(usize::from(counts.authority));
        Ok(Packet {
            id: self.id,
            flags: self.flags,
            queries: &queries[..qw],
            answers,
            authority,
            additional,
            trailing,
            consumed: self.consumed,
        })
    }
    /// Build a complete independent native canonical graph. All name projection,
    /// lookup, shape and destination capacities are preflighted before slots or
    /// arena are touched. The supplied backend must provide deterministic native
    /// conversions; errors publish no packet. Scratch contents are unspecified.
    pub fn native_builder_form<'t, 'b: 't>(
        self,
        idna: &impl Idna,
        s: &mut NativeScratch<'_>,
        a: &mut Arena<'b>,
        queries: &'t mut [Query<'b>],
        records: &'t mut [Record<'b>],
    ) -> Result<Packet<'t, 'b>, Error> {
        self.validate_native_source(idna, s)?;
        let counts = self.counts()?;
        let total = self
            .answers
            .len()
            .checked_add(self.authority.len())
            .and_then(|n| n.checked_add(self.additional.len()))
            .ok_or(Error::Overflow)?;
        if queries.len() < self.queries.len() || records.len() < total {
            return Err(Error::Capacity);
        }
        let mut needed = self.trailing.len();
        for q in self.queries {
            needed = needed
                .checked_add(semantic_result(s.name_metric(q.name, idna))?.arena)
                .ok_or(Error::Overflow)?;
        }
        for section in [self.answers, self.authority, self.additional] {
            for r in section {
                needed = needed
                    .checked_add(semantic_result(record_metric(*r, idna, s))?.arena)
                    .ok_or(Error::Overflow)?;
            }
        }
        if needed > a.remaining() {
            return Err(Error::Capacity);
        }
        self.selected_copy(counts, idna, s, a, queries, records, true)
    }
    /// Native C-style prefix packing: a semantic ToASCII refusal ends that
    /// section, sets TC and permits later sections. Source native-text failure
    /// (including compression guards), resources and unavailable backends return
    /// Err; they are never disguised as TC. Every Err preserves the wire output.
    /// Actual counts replace C's underflow. The original wire pack is unchanged.
    /// URI targets are opaque nonempty bytes, without a UTF8 or IDNA requirement;
    /// an interior NUL is refused here because native CString values cannot hold
    /// it. Raw URI encoding still preserves every target byte.
    #[expect(
        clippy::too_many_arguments,
        reason = "The codec keeps time, conversion capability, caller scratch, arena, object slots and wire capacity explicit without allocation."
    )]
    pub fn pack_native<'t, 'b: 't>(
        self,
        now: AbsoluteTime,
        idna: &impl Idna,
        s: &mut NativeScratch<'_>,
        a: &mut Arena<'b>,
        queries: &'t mut [Query<'b>],
        records: &'t mut [Record<'b>],
        out: &mut [u8],
        maximum: u16,
    ) -> Result<NativePackReport, Error> {
        self.validate_native_source(idna, s)?;
        let cap = out.len().min(usize::from(maximum));
        if cap < HEADER_LEN {
            return Err(Error::Capacity);
        }
        let mut plan = Plan::new();
        let mut stopped = false;
        let mut qcount = 0;
        for q in self.queries {
            let metric = s.name_metric(q.name, idna).and_then(|m| m.reserve(4));
            plan.consider(metric, &mut stopped, &mut qcount, cap)?;
        }
        plan.counts.queries = qcount;
        for (section, kind) in [(self.answers, 0), (self.authority, 1), (self.additional, 2)] {
            let mut stopped = false;
            let mut count = 0;
            for r in section {
                plan.consider(record_metric(*r, idna, s), &mut stopped, &mut count, cap)?;
            }
            match kind {
                0 => plan.counts.answers = count,
                1 => plan.counts.authority = count,
                _ => plan.counts.additional = count,
            }
        }
        let total = usize::from(plan.counts.answers)
            + usize::from(plan.counts.authority)
            + usize::from(plan.counts.additional);
        if queries.len() < usize::from(plan.counts.queries)
            || records.len() < total
            || a.remaining() < plan.arena
        {
            return Err(Error::Capacity);
        }
        let mut canonical = self.selected_copy(plan.counts, idna, s, a, queries, records, false)?;
        if canonical.encoded_len()? != plan.selected_size {
            return Err(Error::InvalidInput);
        }
        if plan.truncated {
            canonical.flags |= 0x0200;
        }
        let written = canonical.encode(now, out)?;
        Ok(NativePackReport {
            written,
            native_size: plan.native_size,
            truncated: plan.truncated,
            counts: plan.counts,
        })
    }
}
