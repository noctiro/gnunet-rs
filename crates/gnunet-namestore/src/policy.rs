//! Allocation-free caller-scratch NFC and authoritative record policy.
use gnunet_gnsrecord::{RecordData, RecordFlags as Flags, RecordType as Type};
use gnunet_idna::{NativeProfile, normalize_nfc_scalars};
use gnunet_types::Error;
/// Official NAMESTORE client label limit, excluding its final NUL.
pub const MAX_LABEL_BYTES: usize = 255;
/// Maximum record headers fitting in one official 16-bit serialized field.
pub const MAX_RECORDS: usize = 65535 / 16;
/// Official apex label. It is not an empty C string.
pub const APEX: &[u8] = b"@";
/// Record query flags; unknown extension bits survive rather than being guessed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Filter(u16);
impl Filter {
    /// Return ordinary private/public records, without maintenance payloads.
    pub const NONE: Self = Self(0);
    /// Include retained maintenance payloads.
    pub const INCLUDE_MAINTENANCE: Self = Self(1);
    /// Omit private record payloads.
    pub const OMIT_PRIVATE: Self = Self(2);
    /// Keep original caller extension bits.
    #[must_use]
    pub const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }
    /// Original bits for wire serialization.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }
}
/// Normalize a case-preserving Unicode NFC label, without IDNA or identity
/// lowercase conversion. Caller supplies all scalar/order/output storage. Input
/// may be a longer decomposed lookup string if caller storage permits it; the
/// canonical result must fit maximum and contain no dot/NUL. Capacity failure
/// does not publish a successful partial label; scalar buffers remain scratch.
pub fn normalize_label(
    input: &[u8],
    out: &mut [u8],
    scalars: &mut [u32],
    normalized: &mut [u32],
    ordering: &mut [u32],
    maximum: usize,
) -> Result<usize, Error> {
    if input.len() > 65530 {
        return Err(Error::TooLarge);
    }
    if maximum > MAX_LABEL_BYTES || input.contains(&0) || input.contains(&b'.') {
        return Err(Error::InvalidInput);
    }
    let text = core::str::from_utf8(input).map_err(|_| Error::InvalidInput)?;
    let mut count = 0;
    for c in text.chars() {
        *scalars.get_mut(count).ok_or(Error::Capacity)? = u32::from(c);
        count += 1;
    }
    let n = normalize_nfc_scalars(
        &scalars[..count],
        normalized,
        ordering,
        NativeProfile::Libunistring1_5Unicode18_0,
    )
    .map_err(|_| Error::Capacity)?;
    let mut bytes = 0usize;
    for cp in &normalized[..n] {
        bytes = bytes
            .checked_add(char::from_u32(*cp).ok_or(Error::InvalidInput)?.len_utf8())
            .ok_or(Error::Overflow)?;
    }
    if bytes > maximum {
        return Err(Error::TooLarge);
    }
    if out.len() < bytes {
        return Err(Error::Capacity);
    }
    let mut at = 0;
    for cp in &normalized[..n] {
        let c = char::from_u32(*cp).ok_or(Error::InvalidInput)?;
        let mut b = [0; 4];
        let b = c.encode_utf8(&mut b).as_bytes();
        out[at..at + b.len()].copy_from_slice(b);
        at += b.len();
    }
    Ok(bytes)
}
/// Convert one relative duration to this explicit absolute source time. Forever
/// and overflow saturate as official GNUnet time arithmetic does.
#[must_use]
pub fn absolute_expiry(record: RecordData<'_>, now: u64) -> u64 {
    if record.flags.contains(Flags::RELATIVE_EXPIRATION) {
        now.saturating_add(record.expiration_time)
    } else {
        record.expiration_time
    }
}
/// Record-derived RRBLOCK lifetime from LSD0001/RFC9498 section6.3: maximum
/// expiration per type (including shadows), then minimum across those types,
/// and the caller's explicit floor. Sorting caller indices is O(n log n) and
/// never reorders payloads. A publishing authority must separately reserve a
/// value greater than every earlier block expiration for the same storage key.
pub fn expiration_time(
    records: &[RecordData<'_>],
    now: u64,
    minimum: u64,
    indices: &mut [usize],
) -> Result<u64, Error> {
    expiration_selected(records, now, minimum, indices, |_| true)
}
fn expiration_selected(
    records: &[RecordData<'_>],
    now: u64,
    minimum: u64,
    indices: &mut [usize],
    mut include: impl FnMut(RecordData<'_>) -> bool,
) -> Result<u64, Error> {
    if records.len() > MAX_RECORDS || indices.len() < records.len() {
        return Err(Error::Capacity);
    }
    let mut count = 0;
    for (i, r) in records.iter().enumerate() {
        if include(*r) {
            indices[count] = i;
            count += 1;
        }
    }
    if count == 0 {
        return Ok(minimum);
    }
    let indices = &mut indices[..count];
    indices.sort_unstable_by_key(|i| records[*i].record_type.value());
    let mut expiry = u64::MAX;
    let mut at = 0;
    while at < indices.len() {
        let kind = records[indices[at]].record_type;
        let mut end = at;
        let mut greatest = 0;
        while end < indices.len() && records[indices[end]].record_type == kind {
            let r = records[indices[end]];
            let exp = absolute_expiry(r, now);
            greatest = greatest.max(exp);
            end += 1;
        }
        expiry = expiry.min(greatest);
        at = end;
    }
    Ok(expiry.max(minimum))
}

fn visible(record: RecordData<'_>, now: u64) -> bool {
    record.flags.contains(Flags::RELATIVE_EXPIRATION) || record.expiration_time >= now
}
fn consistency(
    label: &[u8],
    records: &[RecordData<'_>],
    now: u64,
    mut include: impl FnMut(RecordData<'_>) -> bool,
) -> Result<(), Error> {
    gnunet_gnsrecord::validate_authoritative_records(label, records, |r| {
        include(*r) && visible(*r, now)
    })
}
/// Checked normalized view. It borrows explicit caller output and never formats
/// record payloads. Expiry includes unexpired tombstones even if filtered out.
pub struct Normalized<'out, 'data> {
    records: &'out [RecordData<'data>],
    expires: u64,
}
impl<'out, 'data> Normalized<'out, 'data> {
    /// Explicit sensitive record borrow, preserving original payload order.
    #[must_use]
    pub const fn records(&self) -> &'out [RecordData<'data>] {
        self.records
    }
    /// Actual explicit-time record-set expiration after same-type shadows/floor.
    #[must_use]
    pub const fn expires(&self) -> u64 {
        self.expires
    }
}
impl core::fmt::Debug for Normalized<'_, '_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Normalized")
            .field("count", &self.records.len())
            .field("expires", &self.expires)
            .finish_non_exhaustive()
    }
}
/// Normalize/filter an authoritative set using explicit source time and caller
/// scratch. The critical-type callback is the caller's actual registry policy,
/// corresponding to C's loaded plugin registry; no unknown type is guessed.
/// Validation precedes private payload filtering to enforce local consistency.
/// Apex NICK is retained in storage separately and omitted from this public view.
pub fn normalize_records<'out, 'data>(
    label: &[u8],
    records: &[RecordData<'data>],
    now: u64,
    filter: Filter,
    out: &'out mut [RecordData<'data>],
    indices: &mut [usize],
    mut critical: impl FnMut(Type) -> bool,
) -> Result<Normalized<'out, 'data>, Error> {
    if records.len() > MAX_RECORDS || out.len() < records.len() || indices.len() < records.len() {
        return Err(Error::Capacity);
    }
    consistency(label, records, now, |_| true)?;
    let mut count = 0;
    let mut minimum = 0;
    for record in records {
        let mut r = *record;
        if !visible(r, now) {
            continue;
        }
        if r.record_type == Type::TOMBSTONE {
            minimum = minimum.max(absolute_expiry(r, now));
        }
        if filter.0 & 2 != 0 && r.flags.contains(Flags::PRIVATE) {
            continue;
        }
        if r.flags.contains(Flags::MAINTENANCE) {
            if filter.0 & 1 != 0 {
                out[count] = r;
                count += 1;
            }
            continue;
        }
        if label == APEX && r.record_type == Type::NICK {
            continue;
        }
        if critical(r.record_type) {
            r.flags = Flags::from_bits_preserve(r.flags.bits() | Flags::CRITICAL.bits());
        }
        out[count] = r;
        count += 1;
    }
    let expires = expiration_time(&out[..count], now, minimum, indices)?;
    Ok(Normalized {
        records: &out[..count],
        expires,
    })
}
/// Append a live apex nickname to a non-apex normalized view. The synthetic
/// supplemental nickname uses an absolute latest payload expiry, clears PRIVATE
/// and RELATIVE, and never extends payload expiration or exposes its original
/// private flag. Caller retains the actual stored nickname separately.
pub fn append_nickname<'out, 'data>(
    label: &[u8],
    records: &[RecordData<'data>],
    nickname: Option<RecordData<'data>>,
    now: u64,
    out: &'out mut [RecordData<'data>],
) -> Result<&'out [RecordData<'data>], Error> {
    let nick = nickname.filter(|n| {
        label != APEX && n.record_type == Type::NICK && visible(*n, now) && !records.is_empty()
    });
    let required = records
        .len()
        .checked_add(usize::from(nick.is_some()))
        .ok_or(Error::Overflow)?;
    if required > MAX_RECORDS || out.len() < required {
        return Err(Error::Capacity);
    }
    out[..records.len()].copy_from_slice(records);
    if let Some(mut nick) = nick {
        nick.flags = Flags::from_bits_preserve(
            (nick.flags.bits() & !Flags::PRIVATE.bits() & !Flags::RELATIVE_EXPIRATION.bits())
                | Flags::SUPPLEMENTAL.bits(),
        );
        nick.expiration_time = records
            .iter()
            .map(|r| absolute_expiry(*r, now))
            .max()
            .unwrap_or(0);
        out[records.len()] = nick;
    }
    Ok(&out[..required])
}
/// Prepare durable authoritative replacement records. Private/maintenance input
/// is preserved, non-apex NICK is removed, apex NICK persists as source
/// metadata, and a previous public expiry is protected by a private tombstone.
/// Caller output needs input.len()+1 slots and bounded sort scratch. A missing
/// label's empty deletion/not-found status is decided by the inventory engine.
pub fn prepare_store<'out, 'data>(
    label: &[u8],
    input: &[RecordData<'data>],
    previous_public_expiry: u64,
    now: u64,
    out: &'out mut [RecordData<'data>],
    indices: &mut [usize],
    mut critical: impl FnMut(Type) -> bool,
) -> Result<Normalized<'out, 'data>, Error> {
    if input.len() >= MAX_RECORDS || out.len() <= input.len() || indices.len() < input.len() {
        return Err(Error::Capacity);
    }
    // Non-apex NICK is discarded by store preparation, so it cannot make the
    // retained delegation/redirect set inconsistent. Ordinary normalization
    // still validates every record that its caller actually retains.
    consistency(label, input, now, |r| {
        label == APEX || r.record_type != Type::NICK
    })?;
    let mut count = 0;
    let mut minimum = if previous_public_expiry >= now {
        previous_public_expiry
    } else {
        0
    };
    for record in input {
        let mut r = *record;
        if !visible(r, now) {
            continue;
        }
        if r.record_type == Type::NICK && label != APEX {
            continue;
        }
        if r.record_type == Type::TOMBSTONE {
            minimum = minimum.max(absolute_expiry(r, now));
            continue;
        }
        if critical(r.record_type) {
            r.flags = Flags::from_bits_preserve(r.flags.bits() | Flags::CRITICAL.bits());
        }
        out[count] = r;
        count += 1;
    }
    let expires = expiration_selected(&out[..count], now, 0, indices, |r| {
        !r.flags.contains(Flags::PRIVATE)
            && !r.flags.contains(Flags::MAINTENANCE)
            && !(label == APEX && r.record_type == Type::NICK)
    })?;
    if minimum > expires && minimum >= now {
        out[count] = RecordData {
            expiration_time: minimum,
            record_type: Type::TOMBSTONE,
            flags: Flags::from_bits_preserve(Flags::PRIVATE.bits() | Flags::MAINTENANCE.bits()),
            data: &[],
        };
        count += 1;
    }
    Ok(Normalized {
        records: &out[..count],
        expires: expires.max(minimum),
    })
}
