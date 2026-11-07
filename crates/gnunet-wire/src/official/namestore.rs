//! Active GNUnet v0.29.1 NAMESTORE local IPC. Private zone fields and possibly
//! private record values are borrowed sensitive material, never diagnostic IDs.
//! The pinned TX_CONTROL structs have no active message assignment/handler.
use super::{
    AbsoluteTime, Frame, MessageHeader, MessageType, identity::SecretKeyView, message_type as mt,
};
use core::fmt;
use gnunet_gnsrecord::{RecordSet, ZoneKey};
use gnunet_types::Error;
/// Generic request header: GNUnet header and opaque BE32 request ID.
pub const HEADER: usize = 8;
/// Store fixed prefix.
pub const STORE_PREFIX: usize = 16;
/// Per-label store header, excluding its label and record serialization.
pub const SET_PREFIX: usize = 8;
/// Lookup fixed prefix.
pub const LOOKUP_PREFIX: usize = 16;
/// Zone-to-name request fixed prefix.
pub const ZONE_PREFIX: usize = 12;
/// Iteration start fixed prefix.
pub const ITERATE_PREFIX: usize = 12;
/// Iteration NEXT fixed frame size.
pub const NEXT_LEN: usize = 16;
/// Iteration STOP/result end fixed frame size.
pub const END_LEN: usize = 8;
/// Monitor START fixed prefix.
pub const MONITOR_PREFIX: usize = 12;
/// Monitor NEXT fixed frame size.
pub const MONITOR_NEXT_LEN: usize = 16;
/// Advisory edit begin/cancel fixed prefix.
pub const EDIT_PREFIX: usize = 16;
/// Generic response fixed frame size.
pub const GENERIC_LEN: usize = 12;
/// Lookup response fixed prefix.
pub const LOOKUP_RESPONSE_PREFIX: usize = 20;
/// Zone-to-name response fixed prefix.
pub const ZONE_RESPONSE_PREFIX: usize = 20;
/// Iteration/monitor record response fixed prefix.
pub const RECORD_PREFIX: usize = 24;
/// Advisory edit response fixed prefix.
pub const EDIT_RESPONSE_PREFIX: usize = 16;
/// Monitor SYNC fixed frame size. It has no request ID or credit debit.
pub const SYNC_LEN: usize = 4;
/// Borrowed C string excluding the final NUL. A decoder preserves an accepted
/// embedded-NUL suffix, while `.bytes()` exposes the actual first C word.
#[derive(Clone, Copy)]
pub struct CString<'a> {
    wire: &'a [u8],
}
impl<'a> CString<'a> {
    /// Canonical newly submitted string: no embedded NUL and representable length.
    pub fn new(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.contains(&0) {
            return Err(Error::InvalidInput);
        }
        u16::try_from(bytes.len().checked_add(1).ok_or(Error::Overflow)?)
            .map_err(|_| Error::TooLarge)?;
        Ok(Self { wire: bytes })
    }
    fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.last() != Some(&0) {
            return Err(Error::Malformed);
        }
        Ok(Self {
            wire: &bytes[..bytes.len() - 1],
        })
    }
    /// Actual string as read by C, excluding NUL and any ignored suffix.
    #[must_use]
    pub fn bytes(self) -> &'a [u8] {
        let end = self
            .wire
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(self.wire.len());
        &self.wire[..end]
    }
    /// All original bytes before the final wire NUL, including an ignored suffix.
    #[must_use]
    pub const fn wire_bytes(self) -> &'a [u8] {
        self.wire
    }
    /// Whether this is a canonical new string.
    #[must_use]
    pub fn is_canonical(self) -> bool {
        !self.wire.contains(&0)
    }
    /// Original encoded length including final NUL.
    #[must_use]
    pub fn encoded_len(self) -> usize {
        self.wire.len() + 1
    }
    fn put(self, out: &mut [u8]) {
        out[..self.wire.len()].copy_from_slice(self.wire);
        out[self.wire.len()] = 0;
    }
}
impl fmt::Debug for CString<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CString")
            .field("bytes", &self.wire.len())
            .finish_non_exhaustive()
    }
}
/// Checked sensitive record serialization. Unknown record flags/types survive;
/// framing and zero padding are checked using the shared GNS record codec.
#[derive(Clone, Copy)]
pub struct Records<'a> {
    bytes: &'a [u8],
    parsed: RecordSet<'a>,
}
impl<'a> Records<'a> {
    /// Validate a complete explicit-count serialization without allocation.
    pub fn new(bytes: &'a [u8], count: u16) -> Result<Self, Error> {
        u16::try_from(bytes.len()).map_err(|_| Error::TooLarge)?;
        Ok(Self {
            bytes,
            parsed: RecordSet::parse(bytes, usize::from(count), usize::from(u16::MAX))?,
        })
    }
    /// Empty record list, including deletion requests.
    pub fn empty() -> Result<Self, Error> {
        Self::new(&[], 0)
    }
    /// Exact original serialization including checked zero padding.
    #[must_use]
    pub const fn bytes(self) -> &'a [u8] {
        self.bytes
    }
    /// Validated explicit record count.
    #[must_use]
    pub fn count(self) -> u16 {
        self.parsed.len() as u16
    }
    /// Explicit borrowed record interpretation; this can expose private values.
    #[must_use]
    pub const fn records(self) -> RecordSet<'a> {
        self.parsed
    }
}
impl fmt::Debug for Records<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Records")
            .field("count", &self.count())
            .field("bytes", &self.bytes.len())
            .finish_non_exhaustive()
    }
}
/// One original label replacement in a Store batch. Formatting redacts data.
#[derive(Clone, Copy, Debug)]
pub struct StoreSet<'a> {
    /// Label, excluding its final NUL.
    pub label: CString<'a>,
    /// Records to replace the label with; empty means removal.
    pub records: Records<'a>,
    /// Original uninterpreted reserved bits; new producers normally use zero.
    pub reserved: u16,
}
impl StoreSet<'_> {
    /// Complete per-label encoded byte count.
    pub fn encoded_len(self) -> Result<usize, Error> {
        SET_PREFIX
            .checked_add(self.label.encoded_len())
            .and_then(|n| n.checked_add(self.records.bytes.len()))
            .ok_or(Error::Overflow)
    }
    /// Encode exactly one complete set. Refusal preserves caller output.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len()?;
        if out.len() < n {
            return Err(Error::Capacity);
        }
        p16(out, 0, self.label.encoded_len() as u16);
        p16(out, 2, self.records.bytes.len() as u16);
        p16(out, 4, self.records.count());
        p16(out, 6, self.reserved);
        let end = SET_PREFIX + self.label.encoded_len();
        self.label.put(&mut out[SET_PREFIX..end]);
        out[end..n].copy_from_slice(self.records.bytes);
        Ok(n)
    }
}
fn set_prefix(bytes: &[u8]) -> Result<(StoreSet<'_>, &[u8]), Error> {
    let h = bytes.get(..SET_PREFIX).ok_or(Error::Truncated)?;
    let name = usize::from(b16(h, 0));
    let size = usize::from(b16(h, 2));
    let end = SET_PREFIX
        .checked_add(name)
        .and_then(|n| n.checked_add(size))
        .ok_or(Error::Overflow)?;
    let whole = bytes.get(..end).ok_or(Error::Truncated)?;
    Ok((
        StoreSet {
            label: CString::decode(&whole[SET_PREFIX..SET_PREFIX + name])?,
            records: Records::new(&whole[SET_PREFIX + name..], b16(h, 4))?,
            reserved: b16(h, 6),
        },
        &bytes[end..],
    ))
}
/// Entire validated original Store batch, without copying its sensitive body.
#[derive(Clone, Copy)]
pub struct RecordSets<'a> {
    bytes: &'a [u8],
    count: u16,
}
impl<'a> RecordSets<'a> {
    /// Validate exactly the declared sets and all lengths before any iteration.
    pub fn new(bytes: &'a [u8], count: u16) -> Result<Self, Error> {
        let mut tail = bytes;
        for _ in 0..count {
            tail = set_prefix(tail)?.1;
        }
        if !tail.is_empty() {
            return Err(Error::Malformed);
        }
        Ok(Self { bytes, count })
    }
    /// Original sensitive batch serialization.
    #[must_use]
    pub const fn bytes(self) -> &'a [u8] {
        self.bytes
    }
    /// Number of validated whole sets.
    #[must_use]
    pub const fn count(self) -> u16 {
        self.count
    }
    /// Borrow each original set in wire order, without allocating a table.
    #[must_use]
    pub const fn iter(self) -> Sets<'a> {
        Sets {
            bytes: self.bytes,
            left: self.count,
        }
    }
}
impl fmt::Debug for RecordSets<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordSets")
            .field("count", &self.count)
            .field("bytes", &self.bytes.len())
            .finish_non_exhaustive()
    }
}
/// Bounded iterator over already checked Store set boundaries.
pub struct Sets<'a> {
    bytes: &'a [u8],
    left: u16,
}
impl<'a> Iterator for Sets<'a> {
    type Item = Result<StoreSet<'a>, Error>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.left == 0 {
            return None;
        }
        self.left -= 1;
        match set_prefix(self.bytes) {
            Ok((s, tail)) => {
                self.bytes = tail;
                Some(Ok(s))
            }
            Err(e) => {
                self.left = 0;
                Some(Err(e))
            }
        }
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = usize::from(self.left);
        (n, Some(n))
    }
}
impl ExactSizeIterator for Sets<'_> {}
impl core::iter::FusedIterator for Sets<'_> {}
/// Total bytes for caller-owned batch storage. No partial set is admitted.
pub fn encoded_sets_len(sets: &[StoreSet<'_>]) -> Result<usize, Error> {
    u16::try_from(sets.len()).map_err(|_| Error::TooLarge)?;
    sets.iter().try_fold(0usize, |n, s| {
        n.checked_add(s.encoded_len()?).ok_or(Error::Overflow)
    })
}
/// Encode whole sets into caller-owned sensitive storage. Errors before writing
/// preserve all output; the caller remains responsible for erasing that storage.
pub fn encode_sets(sets: &[StoreSet<'_>], out: &mut [u8]) -> Result<usize, Error> {
    let n = encoded_sets_len(sets)?;
    if out.len() < n {
        return Err(Error::Capacity);
    }
    let mut at = 0;
    for s in sets {
        at += s.encode(&mut out[at..])?;
    }
    Ok(n)
}
fn b16(b: &[u8], a: usize) -> u16 {
    u16::from_be_bytes([b[a], b[a + 1]])
}
fn b32(b: &[u8], a: usize) -> u32 {
    u32::from_be_bytes([b[a], b[a + 1], b[a + 2], b[a + 3]])
}
fn b64(b: &[u8], a: usize) -> u64 {
    u64::from_be_bytes([
        b[a],
        b[a + 1],
        b[a + 2],
        b[a + 3],
        b[a + 4],
        b[a + 5],
        b[a + 6],
        b[a + 7],
    ])
}
fn p16(b: &mut [u8], a: usize, n: u16) {
    b[a..a + 2].copy_from_slice(&n.to_be_bytes());
}
fn p32(b: &mut [u8], a: usize, n: u32) {
    b[a..a + 4].copy_from_slice(&n.to_be_bytes());
}
fn p64(b: &mut [u8], a: usize, n: u64) {
    b[a..a + 8].copy_from_slice(&n.to_be_bytes());
}
fn size(kind: MessageType, prefix: usize, parts: &[usize]) -> Result<usize, Error> {
    let n = parts
        .iter()
        .try_fold(prefix, |n, p| n.checked_add(*p).ok_or(Error::Overflow))?;
    MessageHeader::from_total_size(kind, n)?;
    Ok(n)
}
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8], prefix: usize) -> Result<Self, Error> {
        bytes.get(..prefix).ok_or(Error::Truncated)?;
        Ok(Self { bytes, at: prefix })
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(n).ok_or(Error::Overflow)?;
        let b = self.bytes.get(self.at..end).ok_or(Error::Truncated)?;
        self.at = end;
        Ok(b)
    }
    fn key(&mut self, n: u16) -> Result<SecretKeyView<'a>, Error> {
        SecretKeyView::new(self.take(usize::from(n))?)
    }
    fn opt_key(&mut self, n: u16) -> Result<Option<SecretKeyView<'a>>, Error> {
        if n == 0 {
            Ok(None)
        } else {
            self.key(n).map(Some)
        }
    }
    fn string(&mut self, n: u16) -> Result<CString<'a>, Error> {
        CString::decode(self.take(usize::from(n))?)
    }
    fn opt_string(&mut self, n: u16) -> Result<Option<CString<'a>>, Error> {
        if n == 0 {
            Ok(None)
        } else {
            self.string(n).map(Some)
        }
    }
    fn records(&mut self, n: u16, count: u16) -> Result<Records<'a>, Error> {
        Records::new(self.take(usize::from(n))?, count)
    }
    fn finish(self) -> Result<(), Error> {
        if self.at == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::Malformed)
        }
    }
}
/// One active official request. No RPC cancellation exists; EditCancel modifies
/// an advisory editor hint and IterateStop is the actual iterator stop command.
#[derive(Clone, Copy, Debug)]
pub enum Request<'a> {
    /// Replace complete label sets; single_tx=1 requests atomicity of this frame.
    Store {
        /// Original BE32 request ID.
        rid: u32,
        /// Original private zone serialization.
        zone: SecretKeyView<'a>,
        /// Original flag; only value1 requests a transaction in C.
        single_tx: u16,
        /// Preserved reserved bits.
        reserved: u16,
        /// Whole original batch.
        sets: RecordSets<'a>,
    },
    /// Read one normalized label.
    Lookup {
        /// Original request ID.
        rid: u32,
        /// Original private zone.
        zone: SecretKeyView<'a>,
        /// Original label.
        label: CString<'a>,
        /// INCLUDE_MAINTENANCE1/OMIT_PRIVATE2, retaining extensions.
        filter: u16,
        /// Preserved unused bits.
        unused: u16,
    },
    /// Find a delegation label pointing to a typed public zone.
    ZoneToName {
        /// Original request ID.
        rid: u32,
        /// Original authority private zone.
        zone: SecretKeyView<'a>,
        /// Target public typed key.
        target: ZoneKey,
    },
    /// Start finite credited enumeration, initially one result permitted.
    IterateStart {
        /// Original iterator request ID.
        rid: u32,
        /// None means all zones.
        zone: Option<SecretKeyView<'a>>,
        /// Original record filter.
        filter: u16,
    },
    /// Permit another finite iteration batch.
    IterateNext {
        /// Original iterator request ID.
        rid: u32,
        /// Actual additional requested results.
        limit: u64,
    },
    /// Stop the original iterator; the service sends no stop acknowledgement.
    IterateStop {
        /// Original iterator request ID.
        rid: u32,
    },
    /// Start the source's monitor, with initial result credit1.
    MonitorStart {
        /// None means all zones.
        zone: Option<SecretKeyView<'a>>,
        /// Exactly1 means initial iteration in C.
        iterate_first: u32,
        /// Original record filter.
        filter: u16,
    },
    /// Grant the source's monitor additional result credits.
    MonitorNext {
        /// Checked BE64 additional credit.
        limit: u64,
        /// Original reserved bits.
        reserved: u32,
    },
    /// Read records and replace their advisory editor hint.
    EditBegin {
        /// Original request ID.
        rid: u32,
        /// Private zone.
        zone: SecretKeyView<'a>,
        /// Original label.
        label: CString<'a>,
        /// New advisory hint; empty is an explicit empty C string.
        hint: CString<'a>,
        /// Original reserved bits.
        reserved: u16,
    },
    /// Conditionally replace the matching editor hint, not cancel an RPC.
    EditCancel {
        /// Original request ID.
        rid: u32,
        /// Private zone.
        zone: SecretKeyView<'a>,
        /// Original label.
        label: CString<'a>,
        /// Expected hint.
        hint: CString<'a>,
        /// Replacement hint; empty means clear in backend semantics.
        replacement: CString<'a>,
    },
}
impl<'a> Request<'a> {
    /// Original wire request ID, absent for source-bound monitoring messages.
    #[must_use]
    pub const fn request_id(self) -> Option<u32> {
        match self {
            Self::Store { rid, .. }
            | Self::Lookup { rid, .. }
            | Self::ZoneToName { rid, .. }
            | Self::IterateStart { rid, .. }
            | Self::IterateNext { rid, .. }
            | Self::IterateStop { rid }
            | Self::EditBegin { rid, .. }
            | Self::EditCancel { rid, .. } => Some(rid),
            _ => None,
        }
    }
    /// Decode one exact bounded frame and all nested lengths. Secret bytes stay
    /// borrowed from the original caller's zeroizing RX, never copied here.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let frame = Frame::decode(input)?;
        let kind = frame.header().message_type();
        let value = match kind {
            mt::NAMESTORE_RECORD_STORE => {
                let mut c = Cursor::new(input, STORE_PREFIX)?;
                let zone = c.key(b16(input, 14))?;
                let sets = RecordSets::new(&input[c.at..], b16(input, 12))?;
                Self::Store {
                    rid: b32(input, 4),
                    zone,
                    single_tx: b16(input, 10),
                    reserved: b16(input, 8),
                    sets,
                }
            }
            mt::NAMESTORE_RECORD_LOOKUP => {
                let mut c = Cursor::new(input, LOOKUP_PREFIX)?;
                let zone = c.key(b16(input, 14))?;
                let label = c.string(b16(input, 8))?;
                c.finish()?;
                Self::Lookup {
                    rid: b32(input, 4),
                    zone,
                    label,
                    filter: b16(input, 12),
                    unused: b16(input, 10),
                }
            }
            mt::NAMESTORE_ZONE_TO_NAME => {
                let mut c = Cursor::new(input, ZONE_PREFIX)?;
                let zone = c.key(b16(input, 8))?;
                let target = ZoneKey::from_wire(c.take(usize::from(b16(input, 10)))?)?;
                c.finish()?;
                Self::ZoneToName {
                    rid: b32(input, 4),
                    zone,
                    target,
                }
            }
            mt::NAMESTORE_ZONE_ITERATION_START => {
                let mut c = Cursor::new(input, ITERATE_PREFIX)?;
                let zone = c.opt_key(b16(input, 10))?;
                c.finish()?;
                Self::IterateStart {
                    rid: b32(input, 4),
                    zone,
                    filter: b16(input, 8),
                }
            }
            mt::NAMESTORE_ZONE_ITERATION_NEXT => {
                Cursor::new(input, NEXT_LEN)?.finish()?;
                Self::IterateNext {
                    rid: b32(input, 4),
                    limit: b64(input, 8),
                }
            }
            mt::NAMESTORE_ZONE_ITERATION_STOP => {
                Cursor::new(input, END_LEN)?.finish()?;
                Self::IterateStop { rid: b32(input, 4) }
            }
            mt::NAMESTORE_MONITOR_START => {
                let mut c = Cursor::new(input, MONITOR_PREFIX)?;
                let zone = c.opt_key(b16(input, 10))?;
                c.finish()?;
                Self::MonitorStart {
                    zone,
                    iterate_first: b32(input, 4),
                    filter: b16(input, 8),
                }
            }
            mt::NAMESTORE_MONITOR_NEXT => {
                Cursor::new(input, MONITOR_NEXT_LEN)?.finish()?;
                Self::MonitorNext {
                    reserved: b32(input, 4),
                    limit: b64(input, 8),
                }
            }
            mt::NAMESTORE_RECORD_SET_EDIT => {
                let mut c = Cursor::new(input, EDIT_PREFIX)?;
                let zone = c.key(b16(input, 14))?;
                let label = c.string(b16(input, 8))?;
                let hint = c.string(b16(input, 10))?;
                c.finish()?;
                Self::EditBegin {
                    rid: b32(input, 4),
                    zone,
                    label,
                    hint,
                    reserved: b16(input, 12),
                }
            }
            mt::NAMESTORE_RECORD_SET_EDIT_CANCEL => {
                let mut c = Cursor::new(input, EDIT_PREFIX)?;
                let zone = c.key(b16(input, 14))?;
                let label = c.string(b16(input, 8))?;
                let hint = c.string(b16(input, 10))?;
                let replacement = c.string(b16(input, 12))?;
                c.finish()?;
                Self::EditCancel {
                    rid: b32(input, 4),
                    zone,
                    label,
                    hint,
                    replacement,
                }
            }
            _ => return Err(Error::Unsupported),
        };
        Ok(value)
    }
    fn layout(self) -> Result<(MessageType, usize), Error> {
        let (k, p, a, b, c) = match self {
            Self::Store { sets, .. } => (
                mt::NAMESTORE_RECORD_STORE,
                STORE_PREFIX,
                36,
                sets.bytes.len(),
                0,
            ),
            Self::Lookup { label, .. } => (
                mt::NAMESTORE_RECORD_LOOKUP,
                LOOKUP_PREFIX,
                36,
                label.encoded_len(),
                0,
            ),
            Self::ZoneToName { .. } => (mt::NAMESTORE_ZONE_TO_NAME, ZONE_PREFIX, 36, 36, 0),
            Self::IterateStart { zone, .. } => (
                mt::NAMESTORE_ZONE_ITERATION_START,
                ITERATE_PREFIX,
                zone.map_or(0, |_| 36),
                0,
                0,
            ),
            Self::IterateNext { .. } => (mt::NAMESTORE_ZONE_ITERATION_NEXT, NEXT_LEN, 0, 0, 0),
            Self::IterateStop { .. } => (mt::NAMESTORE_ZONE_ITERATION_STOP, END_LEN, 0, 0, 0),
            Self::MonitorStart { zone, .. } => (
                mt::NAMESTORE_MONITOR_START,
                MONITOR_PREFIX,
                zone.map_or(0, |_| 36),
                0,
                0,
            ),
            Self::MonitorNext { .. } => (mt::NAMESTORE_MONITOR_NEXT, MONITOR_NEXT_LEN, 0, 0, 0),
            Self::EditBegin { label, hint, .. } => (
                mt::NAMESTORE_RECORD_SET_EDIT,
                EDIT_PREFIX,
                36,
                label.encoded_len(),
                hint.encoded_len(),
            ),
            Self::EditCancel {
                label,
                hint,
                replacement,
                ..
            } => (
                mt::NAMESTORE_RECORD_SET_EDIT_CANCEL,
                EDIT_PREFIX,
                36,
                label.encoded_len(),
                hint.encoded_len()
                    .checked_add(replacement.encoded_len())
                    .ok_or(Error::Overflow)?,
            ),
        };
        Ok((k, size(k, p, &[a, b, c])?))
    }
    /// Complete frame size, refusing an unrepresentable whole frame.
    pub fn encoded_len(self) -> Result<usize, Error> {
        self.layout().map(|(_, n)| n)
    }
    /// Encode an actual official request. Refusal preserves output; callers must
    /// use sensitive erased storage for private keys and record contents.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let (kind, n) = self.layout()?;
        if out.len() < n {
            return Err(Error::Capacity);
        }
        out[..n].fill(0);
        MessageHeader::from_total_size(kind, n)?.encode(out)?;
        if let Some(rid) = self.request_id() {
            p32(out, 4, rid);
        }
        match self {
            Self::Store {
                zone,
                single_tx,
                reserved,
                sets,
                ..
            } => {
                p16(out, 8, reserved);
                p16(out, 10, single_tx);
                p16(out, 12, sets.count);
                p16(out, 14, 36);
                out[16..52].copy_from_slice(zone.expose_serialized());
                out[52..n].copy_from_slice(sets.bytes);
            }
            Self::Lookup {
                zone,
                label,
                filter,
                unused,
                ..
            } => {
                p16(out, 8, label.encoded_len() as u16);
                p16(out, 10, unused);
                p16(out, 12, filter);
                p16(out, 14, 36);
                out[16..52].copy_from_slice(zone.expose_serialized());
                label.put(&mut out[52..n]);
            }
            Self::ZoneToName { zone, target, .. } => {
                p16(out, 8, 36);
                p16(out, 10, 36);
                out[12..48].copy_from_slice(zone.expose_serialized());
                out[48..84].copy_from_slice(&target.to_wire());
            }
            Self::IterateStart { zone, filter, .. } | Self::MonitorStart { zone, filter, .. } => {
                p16(out, 8, filter);
                p16(out, 10, zone.map_or(0, |_| 36));
                if let Some(zone) = zone {
                    out[12..48].copy_from_slice(zone.expose_serialized());
                }
                if let Self::MonitorStart { iterate_first, .. } = self {
                    p32(out, 4, iterate_first);
                }
            }
            Self::IterateNext { limit, .. } | Self::MonitorNext { limit, .. } => {
                if let Self::MonitorNext { reserved, .. } = self {
                    p32(out, 4, reserved);
                }
                p64(out, 8, limit);
            }
            Self::IterateStop { .. } => {}
            Self::EditBegin {
                zone,
                label,
                hint,
                reserved,
                ..
            } => {
                p16(out, 8, label.encoded_len() as u16);
                p16(out, 10, hint.encoded_len() as u16);
                p16(out, 12, reserved);
                p16(out, 14, 36);
                out[16..52].copy_from_slice(zone.expose_serialized());
                let end = 52 + label.encoded_len();
                label.put(&mut out[52..end]);
                hint.put(&mut out[end..n]);
            }
            Self::EditCancel {
                zone,
                label,
                hint,
                replacement,
                ..
            } => {
                p16(out, 8, label.encoded_len() as u16);
                p16(out, 10, hint.encoded_len() as u16);
                p16(out, 12, replacement.encoded_len() as u16);
                p16(out, 14, 36);
                out[16..52].copy_from_slice(zone.expose_serialized());
                let end = 52 + label.encoded_len();
                label.put(&mut out[52..end]);
                let end2 = end + hint.encoded_len();
                hint.put(&mut out[end..end2]);
                replacement.put(&mut out[end2..n]);
            }
        }
        Ok(n)
    }
}
/// One checked official reply. Every field with private material is redacted by
/// Debug. Numeric codes are retained exactly; no kernel/durability ACK is inferred.
#[derive(Clone, Copy, Debug)]
pub enum Response<'a> {
    /// Store or advisory cancel result.
    Generic {
        /// Original request ID.
        rid: u32,
        /// Original BE32 code, including unknown/malformed C producer values.
        code: u32,
    },
    /// Lookup hit/miss/backend error (found1/0/-1); the normalized label is echoed.
    Lookup {
        /// Original request ID.
        rid: u32,
        /// Original private authority.
        zone: SecretKeyView<'a>,
        /// Canonical returned label.
        label: CString<'a>,
        /// Signed original found value.
        found: i16,
        /// Original reserved bits.
        reserved: u16,
        /// Returned records.
        records: Records<'a>,
    },
    /// Delegation lookup response; the pinned service emits a keyless empty
    /// response for a miss, despite an incorrect assertion in its C consumer.
    ZoneToName {
        /// Original request ID.
        rid: u32,
        /// Actual original code.
        code: u32,
        /// Absent in a real empty response.
        zone: Option<SecretKeyView<'a>>,
        /// Absent in a real empty response.
        label: Option<CString<'a>>,
        /// Returned records.
        records: Records<'a>,
    },
    /// Iterator or monitor result; monitor convention uses RID0.
    Records {
        /// Original request ID.
        rid: u32,
        /// Private authority.
        zone: SecretKeyView<'a>,
        /// Returned label.
        label: CString<'a>,
        /// Actual block expiration microseconds.
        expires: AbsoluteTime,
        /// Records including selected filter/nick effects.
        records: Records<'a>,
    },
    /// Original iterator naturally ended, distinct from STOP write completion.
    End {
        /// Original iterator request ID.
        rid: u32,
    },
    /// Monitor initial enumeration synced; no result credit is consumed.
    MonitorSync,
    /// Advisory begin result. An absent previous hint is represented faithfully,
    /// even though the pinned C consumer incorrectly rejects that service reply.
    Edit {
        /// Original request ID.
        rid: u32,
        /// Original BE16 error code.
        code: u16,
        /// Previous hint; None differs from an explicit empty string.
        hint: Option<CString<'a>>,
        /// Returned original records.
        records: Records<'a>,
    },
}
impl<'a> Response<'a> {
    /// Original wire ID, absent only for monitor SYNC.
    #[must_use]
    pub const fn request_id(self) -> Option<u32> {
        match self {
            Self::Generic { rid, .. }
            | Self::Lookup { rid, .. }
            | Self::ZoneToName { rid, .. }
            | Self::Records { rid, .. }
            | Self::End { rid }
            | Self::Edit { rid, .. } => Some(rid),
            Self::MonitorSync => None,
        }
    }
    /// Decode exact checked fields without copying or logging private data.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let f = Frame::decode(input)?;
        match f.header().message_type() {
            mt::NAMESTORE_GENERIC_RESPONSE => {
                Cursor::new(input, GENERIC_LEN)?.finish()?;
                Ok(Self::Generic {
                    rid: b32(input, 4),
                    code: b32(input, 8),
                })
            }
            mt::NAMESTORE_RECORD_LOOKUP_RESPONSE => {
                let mut c = Cursor::new(input, LOOKUP_RESPONSE_PREFIX)?;
                let zone = c.key(b16(input, 18))?;
                let label = c.string(b16(input, 8))?;
                let records = c.records(b16(input, 10), b16(input, 12))?;
                c.finish()?;
                Ok(Self::Lookup {
                    rid: b32(input, 4),
                    zone,
                    label,
                    found: b16(input, 14) as i16,
                    reserved: b16(input, 16),
                    records,
                })
            }
            mt::NAMESTORE_ZONE_TO_NAME_RESPONSE => {
                let mut c = Cursor::new(input, ZONE_RESPONSE_PREFIX)?;
                let zone = c.opt_key(b16(input, 18))?;
                let label = c.opt_string(b16(input, 12))?;
                let records = c.records(b16(input, 14), b16(input, 16))?;
                c.finish()?;
                Ok(Self::ZoneToName {
                    rid: b32(input, 4),
                    code: b32(input, 8),
                    zone,
                    label,
                    records,
                })
            }
            mt::NAMESTORE_RECORD_RESULT => {
                let mut c = Cursor::new(input, RECORD_PREFIX)?;
                let zone = c.key(b16(input, 22))?;
                let label = c.string(b16(input, 16))?;
                let records = c.records(b16(input, 18), b16(input, 20))?;
                c.finish()?;
                Ok(Self::Records {
                    rid: b32(input, 4),
                    zone,
                    label,
                    expires: AbsoluteTime::from_micros(b64(input, 8)),
                    records,
                })
            }
            mt::NAMESTORE_RECORD_RESULT_END => {
                Cursor::new(input, END_LEN)?.finish()?;
                Ok(Self::End { rid: b32(input, 4) })
            }
            mt::NAMESTORE_MONITOR_SYNC => {
                Cursor::new(input, SYNC_LEN)?.finish()?;
                Ok(Self::MonitorSync)
            }
            mt::NAMESTORE_RECORD_SET_EDIT_RESPONSE => {
                let mut c = Cursor::new(input, EDIT_RESPONSE_PREFIX)?;
                let hint = c.opt_string(b16(input, 8))?;
                let records = c.records(b16(input, 12), b16(input, 14))?;
                c.finish()?;
                Ok(Self::Edit {
                    rid: b32(input, 4),
                    code: b16(input, 10),
                    hint,
                    records,
                })
            }
            _ => Err(Error::Unsupported),
        }
    }
    fn layout(self) -> Result<(MessageType, usize), Error> {
        let (k, p, a, b, c) = match self {
            Self::Generic { .. } => (mt::NAMESTORE_GENERIC_RESPONSE, GENERIC_LEN, 0, 0, 0),
            Self::Lookup { label, records, .. } => (
                mt::NAMESTORE_RECORD_LOOKUP_RESPONSE,
                LOOKUP_RESPONSE_PREFIX,
                36,
                label.encoded_len(),
                records.bytes.len(),
            ),
            Self::ZoneToName {
                zone,
                label,
                records,
                ..
            } => (
                mt::NAMESTORE_ZONE_TO_NAME_RESPONSE,
                ZONE_RESPONSE_PREFIX,
                zone.map_or(0, |_| 36),
                label.map_or(0, CString::encoded_len),
                records.bytes.len(),
            ),
            Self::Records { label, records, .. } => (
                mt::NAMESTORE_RECORD_RESULT,
                RECORD_PREFIX,
                36,
                label.encoded_len(),
                records.bytes.len(),
            ),
            Self::End { .. } => (mt::NAMESTORE_RECORD_RESULT_END, END_LEN, 0, 0, 0),
            Self::MonitorSync => (mt::NAMESTORE_MONITOR_SYNC, SYNC_LEN, 0, 0, 0),
            Self::Edit { hint, records, .. } => (
                mt::NAMESTORE_RECORD_SET_EDIT_RESPONSE,
                EDIT_RESPONSE_PREFIX,
                hint.map_or(0, CString::encoded_len),
                records.bytes.len(),
                0,
            ),
        };
        Ok((k, size(k, p, &[a, b, c])?))
    }
    /// Exact total frame length.
    pub fn encoded_len(self) -> Result<usize, Error> {
        self.layout().map(|(_, n)| n)
    }
    /// Encode the documented official network-order fields. Refusal preserves
    /// output. Broken C editor-cancel htons-to-u32 output is never fabricated.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let (k, n) = self.layout()?;
        if out.len() < n {
            return Err(Error::Capacity);
        }
        out[..n].fill(0);
        MessageHeader::from_total_size(k, n)?.encode(out)?;
        if let Some(rid) = self.request_id() {
            p32(out, 4, rid);
        }
        match self {
            Self::Generic { code, .. } => p32(out, 8, code),
            Self::Lookup {
                zone,
                label,
                found,
                reserved,
                records,
                ..
            } => {
                p16(out, 8, label.encoded_len() as u16);
                p16(out, 10, records.bytes.len() as u16);
                p16(out, 12, records.count());
                p16(out, 14, found as u16);
                p16(out, 16, reserved);
                p16(out, 18, 36);
                out[20..56].copy_from_slice(zone.expose_serialized());
                let end = 56 + label.encoded_len();
                label.put(&mut out[56..end]);
                out[end..n].copy_from_slice(records.bytes);
            }
            Self::ZoneToName {
                code,
                zone,
                label,
                records,
                ..
            } => {
                p32(out, 8, code);
                p16(out, 12, label.map_or(0, CString::encoded_len) as u16);
                p16(out, 14, records.bytes.len() as u16);
                p16(out, 16, records.count());
                p16(out, 18, zone.map_or(0, |_| 36));
                let mut at = 20;
                if let Some(zone) = zone {
                    out[at..at + 36].copy_from_slice(zone.expose_serialized());
                    at += 36;
                }
                if let Some(label) = label {
                    let end = at + label.encoded_len();
                    label.put(&mut out[at..end]);
                    at = end;
                }
                out[at..n].copy_from_slice(records.bytes);
            }
            Self::Records {
                zone,
                label,
                expires,
                records,
                ..
            } => {
                p64(out, 8, expires.as_micros());
                p16(out, 16, label.encoded_len() as u16);
                p16(out, 18, records.bytes.len() as u16);
                p16(out, 20, records.count());
                p16(out, 22, 36);
                out[24..60].copy_from_slice(zone.expose_serialized());
                let end = 60 + label.encoded_len();
                label.put(&mut out[60..end]);
                out[end..n].copy_from_slice(records.bytes);
            }
            Self::Edit {
                code,
                hint,
                records,
                ..
            } => {
                p16(out, 8, hint.map_or(0, CString::encoded_len) as u16);
                p16(out, 10, code);
                p16(out, 12, records.bytes.len() as u16);
                p16(out, 14, records.count());
                let mut at = 16;
                if let Some(hint) = hint {
                    let end = at + hint.encoded_len();
                    hint.put(&mut out[at..end]);
                    at = end;
                }
                out[at..n].copy_from_slice(records.bytes);
            }
            Self::End { .. } | Self::MonitorSync => {}
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "The pure model asserts active message-family layouts with public non-secret mocks"
    )]
    fn active_families_exact_roundtrip_and_empty_replies() -> Result<(), Error> {
        // Published structural mock only; no entropy, derivation or secret file.
        let mut mock = [0x42; 36];
        mock[..4].copy_from_slice(&super::super::identity::KeyType::Eddsa.value().to_be_bytes());
        let zone = SecretKeyView::new(&mock)?;
        let mut rd = [0; 32];
        rd[..8].copy_from_slice(&u64::MAX.to_be_bytes());
        rd[8..10].copy_from_slice(&4u16.to_be_bytes());
        rd[12..16].copy_from_slice(&1u32.to_be_bytes());
        rd[16..20].copy_from_slice(&[192, 0, 2, 1]);
        let records = Records::new(&rd, 1)?;
        let label = CString::new(b"MiXeD")?;
        let hint = CString::new(b"editor")?;
        let empty_hint = CString::new(b"")?;
        let mut body = [0; 64];
        let n = encode_sets(
            &[StoreSet {
                label,
                records,
                reserved: 7,
            }],
            &mut body,
        )?;
        let sets = RecordSets::new(&body[..n], 1)?;
        let public = ZoneKey::from_wire(&mock)?;
        let requests = [
            Request::Store {
                rid: 0x01020304,
                zone,
                single_tx: 1,
                reserved: 9,
                sets,
            },
            Request::Lookup {
                rid: 2,
                zone,
                label,
                filter: 3,
                unused: 8,
            },
            Request::ZoneToName {
                rid: 3,
                zone,
                target: public,
            },
            Request::IterateStart {
                rid: 4,
                zone: None,
                filter: 1,
            },
            Request::IterateNext {
                rid: 4,
                limit: 0x0102030405060708,
            },
            Request::IterateStop { rid: 4 },
            Request::MonitorStart {
                zone: Some(zone),
                iterate_first: 1,
                filter: 2,
            },
            Request::MonitorNext {
                limit: 11,
                reserved: 0,
            },
            Request::EditBegin {
                rid: 5,
                zone,
                label,
                hint,
                reserved: 2,
            },
            Request::EditCancel {
                rid: 6,
                zone,
                label,
                hint,
                replacement: empty_hint,
            },
        ];
        let mut bytes = [0; 256];
        let mut round = [0; 256];
        for request in requests {
            let n = request.encode(&mut bytes)?;
            assert_eq!(request.encoded_len()?, n);
            assert_eq!(Request::decode(&bytes[..n])?.encode(&mut round)?, n);
            assert_eq!(&bytes[..n], &round[..n]);
        }
        let responses = [
            Response::Generic { rid: 1, code: 5013 },
            Response::Lookup {
                rid: 2,
                zone,
                label,
                found: -1,
                reserved: 6,
                records,
            },
            Response::ZoneToName {
                rid: 3,
                code: 5002,
                zone: None,
                label: None,
                records: Records::empty()?,
            },
            Response::ZoneToName {
                rid: 3,
                code: 5002,
                zone: Some(zone),
                label: None,
                records: Records::empty()?,
            },
            Response::Records {
                rid: 4,
                zone,
                label,
                expires: AbsoluteTime::from_micros(123456),
                records,
            },
            Response::End { rid: 4 },
            Response::MonitorSync,
            Response::Edit {
                rid: 5,
                code: 5010,
                hint: None,
                records: Records::empty()?,
            },
        ];
        for response in responses {
            let n = response.encode(&mut bytes)?;
            assert_eq!(response.encoded_len()?, n);
            assert_eq!(Response::decode(&bytes[..n])?.encode(&mut round)?, n);
            assert_eq!(&bytes[..n], &round[..n]);
        }
        let missing = Response::ZoneToName {
            rid: 3,
            code: 5002,
            zone: None,
            label: None,
            records: Records::empty()?,
        };
        assert_eq!(missing.encode(&mut bytes)?, 20);
        assert_eq!(&bytes[..12], &[0, 20, 1, 184, 0, 0, 0, 3, 0, 0, 19, 138]);
        let embedded = CString::decode(b"first\0ignored\0")?;
        assert_eq!(embedded.bytes(), b"first");
        assert!(!embedded.is_canonical());
        assert!(CString::new(b"first\0ignored").is_err());
        assert!(Request::decode(&[0, 8, 1, 191, 0, 0, 0, 4]).is_err());
        Ok(())
    }
}
