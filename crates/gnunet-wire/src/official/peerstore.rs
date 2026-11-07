//! Official GNUnet v0.29.1 PEERSTORE IPC. All scalars use network byte order.
//! The request id is the actual official per-MQ u32; no additional RID is used.
//! C string decoding follows the service's first-NUL semantics; encoding emits
//! canonical strings with one terminal NUL. Records never prove peer authority.
use super::{Frame, MessageHeader, MessageType, message_type as mt};
use gnunet_types::Error;
/// Complete record prefix, before subsystem, key and arbitrary value bytes.
pub const RECORD_PREFIX: usize = 60;
/// Start-query prefix, before its two optional C strings.
pub const START_PREFIX: usize = 48;
/// Official maximum requested records per iteration/monitor credit increment.
pub const MAX_ROUND: u64 = 256;
/// Borrowed opaque cache record; HELLO is ordinary record data here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Record<'a> {
    /// Claimed record key identity; not authenticated by this IPC struct.
    pub peer: [u8; 32],
    /// Absolute Unix microseconds; u64::MAX represents forever.
    pub expiry: u64,
    /// Responsible subsystem, without the terminal NUL; None means absent.
    pub subsystem: Option<&'a [u8]>,
    /// Record key, without the terminal NUL; None means absent.
    pub key: Option<&'a [u8]>,
    /// Uninterpreted record value, including zero bytes.
    pub value: &'a [u8],
}
/// Optional exact cache selectors. Empty string and absent selector differ.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Filter<'a> {
    /// Optional exact claimed peer identity.
    pub peer: Option<[u8; 32]>,
    /// Optional exact subsystem bytes.
    pub subsystem: Option<&'a [u8]>,
    /// Optional exact key bytes.
    pub key: Option<&'a [u8]>,
}
impl Filter<'_> {
    /// Whether this opaque record matches every specified selector.
    #[must_use]
    pub fn matches(self, record: Record<'_>) -> bool {
        self.peer.is_none_or(|p| p == record.peer)
            && self.subsystem.is_none_or(|s| Some(s) == record.subsystem)
            && self.key.is_none_or(|k| Some(k) == record.key)
    }
}
/// Actual record envelope shared by STORE and RECORD.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Envelope<'a> {
    /// Official request id; monitor notifications use zero.
    pub rid: u32,
    /// STORE option 1 replaces, all other raw values mean multiple in C.
    pub options: u32,
    /// Alignment field retained by the codec, ignored by C.
    pub reserved: u16,
    /// Original borrowed data.
    pub record: Record<'a>,
}
/// Iterator creation; its implicit first round has one record of credit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Iteration<'a> {
    /// Original official request id.
    pub rid: u32,
    /// Exact optional selectors.
    pub filter: Filter<'a>,
    /// Alignment field, ignored by C.
    pub reserved: u16,
}
/// A monitor uses its own actual MQ; MONITOR_NEXT has no request id.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Monitor<'a> {
    /// Original diagnostic field; C notification records use zero regardless.
    pub rid: u32,
    /// Exact optional selectors.
    pub filter: Filter<'a>,
    /// Iterate existing records before actual MONITOR_SYNC.
    pub iterate_first: bool,
}
/// Every command registered by the pinned active service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Request<'a> {
    /// Store one record; result is emitted only from actual storage outcome.
    Store(Envelope<'a>),
    /// Start an official request-id iterator.
    IterateStart(Iteration<'a>),
    /// Grant another bounded round to that actual iterator.
    IterateNext {
        /// Original request id.
        rid: u32,
        /// Requested count; zero is invalid in the service.
        limit: u64,
    },
    /// Cancel matching iterator locally; unknown/finished ids are harmless.
    IterateStop {
        /// Original request id.
        rid: u32,
    },
    /// Start the one monitor allowed on this MQ.
    MonitorStart(Monitor<'a>),
    /// Add monitor credit; values above MAX_ROUND are clamped by the service.
    MonitorNext {
        /// Additional record credit.
        limit: u64,
    },
}
/// Actual service responses. GNUNET_OK is signed one, SYSERR is signed -1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Response<'a> {
    /// A complete opaque cache record.
    Record(Envelope<'a>),
    /// Original actual STORE result.
    StoreResult {
        /// Original request id.
        rid: u32,
        /// Actual signed GNUnet result.
        result: i32,
    },
    /// End of this actual iterator, not a live-monitor termination.
    IterateEnd {
        /// Original request id.
        rid: u32,
        /// Actual signed GNUnet result.
        result: i32,
    },
    /// Initial monitor enumeration really reached the end.
    MonitorSync,
}
fn number<const N: usize>(b: &[u8], at: usize) -> Result<[u8; N], Error> {
    b.get(at..at.checked_add(N).ok_or(Error::Overflow)?)
        .ok_or(Error::Truncated)?
        .try_into()
        .map_err(|_| Error::Truncated)
}
fn short(b: &[u8], at: usize) -> Result<usize, Error> {
    Ok(usize::from(u16::from_be_bytes(number(b, at)?)))
}
fn word(b: &[u8], at: usize) -> Result<u32, Error> {
    Ok(u32::from_be_bytes(number(b, at)?))
}
fn long(b: &[u8], at: usize) -> Result<u64, Error> {
    Ok(u64::from_be_bytes(number(b, at)?))
}
fn text(b: &[u8], at: usize, length: usize) -> Result<Option<&[u8]>, Error> {
    if length == 0 {
        return Ok(None);
    }
    let raw = b
        .get(at..at.checked_add(length).ok_or(Error::Overflow)?)
        .ok_or(Error::Truncated)?;
    if raw.last() != Some(&0) {
        return Err(Error::Malformed);
    }
    let end = raw.iter().position(|v| *v == 0).ok_or(Error::Malformed)?;
    Ok(Some(&raw[..end]))
}
fn string_len(s: Option<&[u8]>) -> Result<usize, Error> {
    match s {
        None => Ok(0),
        Some(s) => {
            if s.contains(&0) {
                return Err(Error::InvalidInput);
            }
            let n = s.len().checked_add(1).ok_or(Error::Overflow)?;
            u16::try_from(n).map_err(|_| Error::TooLarge)?;
            Ok(n)
        }
    }
}
fn strings_len(
    prefix: usize,
    s: Option<&[u8]>,
    k: Option<&[u8]>,
    v: usize,
) -> Result<usize, Error> {
    let ss = string_len(s)?;
    let ks = string_len(k)?;
    let n = prefix
        .checked_add(ss)
        .and_then(|n| n.checked_add(ks))
        .and_then(|n| n.checked_add(v))
        .ok_or(Error::TooLarge)?;
    MessageHeader::from_total_size(MessageType::new(0), n)?;
    Ok(n)
}
fn envelope(b: &[u8]) -> Result<Envelope<'_>, Error> {
    if b.len() < RECORD_PREFIX {
        return Err(Error::Truncated);
    }
    let ss = short(b, 56)?;
    let ks = short(b, 52)?;
    let vs = short(b, 54)?;
    if RECORD_PREFIX + ss + ks + vs != b.len() {
        return Err(Error::Malformed);
    }
    Ok(Envelope {
        rid: word(b, 44)?,
        options: word(b, 48)?,
        reserved: u16::from_be_bytes(number(b, 58)?),
        record: Record {
            peer: number(b, 4)?,
            expiry: long(b, 36)?,
            subsystem: text(b, 60, ss)?,
            key: text(b, 60 + ss, ks)?,
            value: &b[60 + ss + ks..],
        },
    })
}
fn filter(b: &[u8], ss: usize, ks: usize, set: usize) -> Result<Filter<'_>, Error> {
    if START_PREFIX + ss + ks > b.len() {
        return Err(Error::Truncated);
    }
    Ok(Filter {
        peer: if set != 0 { Some(number(b, 4)?) } else { None },
        subsystem: text(b, 48, ss)?,
        key: text(b, 48 + ss, ks)?,
    })
}
fn write_string(b: &mut [u8], at: usize, s: Option<&[u8]>) -> usize {
    match s {
        None => at,
        Some(s) => {
            b[at..at + s.len()].copy_from_slice(s);
            b[at + s.len()] = 0;
            at + s.len() + 1
        }
    }
}
fn write_envelope(e: Envelope<'_>, b: &mut [u8]) -> Result<(), Error> {
    b[4..36].copy_from_slice(&e.record.peer);
    b[36..44].copy_from_slice(&e.record.expiry.to_be_bytes());
    b[44..48].copy_from_slice(&e.rid.to_be_bytes());
    b[48..52].copy_from_slice(&e.options.to_be_bytes());
    b[52..54].copy_from_slice(&(string_len(e.record.key)? as u16).to_be_bytes());
    b[54..56].copy_from_slice(&(e.record.value.len() as u16).to_be_bytes());
    b[56..58].copy_from_slice(&(string_len(e.record.subsystem)? as u16).to_be_bytes());
    b[58..60].copy_from_slice(&e.reserved.to_be_bytes());
    let at = write_string(b, 60, e.record.subsystem);
    let at = write_string(b, at, e.record.key);
    b[at..].copy_from_slice(e.record.value);
    Ok(())
}
impl<'a> Request<'a> {
    /// Decode one complete active official command without allocation.
    pub fn decode(b: &'a [u8]) -> Result<Self, Error> {
        let frame = Frame::decode(b)?;
        let ty = frame.header().message_type();
        Ok(match ty {
            mt::PEERSTORE_STORE => Self::Store(envelope(b)?),
            mt::PEERSTORE_ITERATE_START => {
                if b.len() < 48 {
                    return Err(Error::Truncated);
                }
                Self::IterateStart(Iteration {
                    rid: word(b, 36)?,
                    reserved: u16::from_be_bytes(number(b, 44)?),
                    filter: filter(b, short(b, 42)?, short(b, 46)?, short(b, 40)?)?,
                })
            }
            mt::PEERSTORE_MONITOR_START => {
                if b.len() < 48 {
                    return Err(Error::Truncated);
                }
                Self::MonitorStart(Monitor {
                    rid: word(b, 36)?,
                    iterate_first: short(b, 46)? == 1,
                    filter: filter(b, short(b, 44)?, short(b, 40)?, short(b, 42)?)?,
                })
            }
            mt::PEERSTORE_ITERATE_NEXT if b.len() == 16 => Self::IterateNext {
                limit: long(b, 4)?,
                rid: word(b, 12)?,
            },
            mt::PEERSTORE_ITERATE_STOP if b.len() == 8 => Self::IterateStop { rid: word(b, 4)? },
            mt::PEERSTORE_MONITOR_NEXT if b.len() == 12 => Self::MonitorNext { limit: long(b, 4)? },
            mt::PEERSTORE_ITERATE_NEXT
            | mt::PEERSTORE_ITERATE_STOP
            | mt::PEERSTORE_MONITOR_NEXT => return Err(Error::Malformed),
            _ => return Err(Error::Unsupported),
        })
    }
    /// Exact canonical frame size; refusal occurs before output mutation.
    pub fn encoded_len(self) -> Result<usize, Error> {
        Ok(match self {
            Self::Store(e) => {
                strings_len(60, e.record.subsystem, e.record.key, e.record.value.len())?
            }
            Self::IterateStart(i) => strings_len(48, i.filter.subsystem, i.filter.key, 0)?,
            Self::MonitorStart(m) => strings_len(48, m.filter.subsystem, m.filter.key, 0)?,
            Self::IterateNext { .. } => 16,
            Self::IterateStop { .. } => 8,
            Self::MonitorNext { .. } => 12,
        })
    }
    /// Encode canonical official bytes; capacity/validation errors are atomic.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len()?;
        let b = out.get_mut(..n).ok_or(Error::Capacity)?;
        b.fill(0);
        let ty = match self {
            Self::Store(_) => mt::PEERSTORE_STORE,
            Self::IterateStart(_) => mt::PEERSTORE_ITERATE_START,
            Self::MonitorStart(_) => mt::PEERSTORE_MONITOR_START,
            Self::IterateNext { .. } => mt::PEERSTORE_ITERATE_NEXT,
            Self::IterateStop { .. } => mt::PEERSTORE_ITERATE_STOP,
            Self::MonitorNext { .. } => mt::PEERSTORE_MONITOR_NEXT,
        };
        MessageHeader::from_total_size(ty, n)?.encode(b)?;
        match self {
            Self::Store(e) => write_envelope(e, b)?,
            Self::IterateStart(i) => {
                if let Some(p) = i.filter.peer {
                    b[4..36].copy_from_slice(&p);
                    b[40..42].copy_from_slice(&1u16.to_be_bytes())
                }
                b[36..40].copy_from_slice(&i.rid.to_be_bytes());
                b[42..44].copy_from_slice(&(string_len(i.filter.subsystem)? as u16).to_be_bytes());
                b[44..46].copy_from_slice(&i.reserved.to_be_bytes());
                b[46..48].copy_from_slice(&(string_len(i.filter.key)? as u16).to_be_bytes());
                let at = write_string(b, 48, i.filter.subsystem);
                write_string(b, at, i.filter.key);
            }
            Self::MonitorStart(m) => {
                if let Some(p) = m.filter.peer {
                    b[4..36].copy_from_slice(&p);
                    b[42..44].copy_from_slice(&1u16.to_be_bytes())
                }
                b[36..40].copy_from_slice(&m.rid.to_be_bytes());
                b[40..42].copy_from_slice(&(string_len(m.filter.key)? as u16).to_be_bytes());
                b[44..46].copy_from_slice(&(string_len(m.filter.subsystem)? as u16).to_be_bytes());
                let first = if m.iterate_first { 1_u16 } else { 0_u16 };
                b[46..48].copy_from_slice(&first.to_be_bytes());
                let at = write_string(b, 48, m.filter.subsystem);
                write_string(b, at, m.filter.key);
            }
            Self::IterateNext { rid, limit } => {
                b[4..12].copy_from_slice(&limit.to_be_bytes());
                b[12..16].copy_from_slice(&rid.to_be_bytes());
            }
            Self::IterateStop { rid } => b[4..8].copy_from_slice(&rid.to_be_bytes()),
            Self::MonitorNext { limit } => b[4..12].copy_from_slice(&limit.to_be_bytes()),
        }
        Ok(n)
    }
}
impl<'a> Response<'a> {
    /// Decode one complete official response, preserving signed results.
    pub fn decode(b: &'a [u8]) -> Result<Self, Error> {
        let ty = Frame::decode(b)?.header().message_type();
        Ok(match ty {
            mt::PEERSTORE_RECORD => Self::Record(envelope(b)?),
            mt::PEERSTORE_STORE_RESULT if b.len() == 12 => Self::StoreResult {
                rid: word(b, 4)?,
                result: word(b, 8)? as i32,
            },
            mt::PEERSTORE_ITERATE_END if b.len() == 12 => Self::IterateEnd {
                rid: word(b, 4)?,
                result: word(b, 8)? as i32,
            },
            mt::PEERSTORE_MONITOR_SYNC if b.len() == 4 => Self::MonitorSync,
            mt::PEERSTORE_STORE_RESULT | mt::PEERSTORE_ITERATE_END | mt::PEERSTORE_MONITOR_SYNC => {
                return Err(Error::Malformed);
            }
            _ => return Err(Error::Unsupported),
        })
    }
    /// Exact complete canonical frame size.
    pub fn encoded_len(self) -> Result<usize, Error> {
        match self {
            Self::Record(e) => {
                strings_len(60, e.record.subsystem, e.record.key, e.record.value.len())
            }
            Self::StoreResult { .. } | Self::IterateEnd { .. } => Ok(12),
            Self::MonitorSync => Ok(4),
        }
    }
    /// Encode exact official output, after complete size validation.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len()?;
        let b = out.get_mut(..n).ok_or(Error::Capacity)?;
        b.fill(0);
        let ty = match self {
            Self::Record(_) => mt::PEERSTORE_RECORD,
            Self::StoreResult { .. } => mt::PEERSTORE_STORE_RESULT,
            Self::IterateEnd { .. } => mt::PEERSTORE_ITERATE_END,
            Self::MonitorSync => mt::PEERSTORE_MONITOR_SYNC,
        };
        MessageHeader::from_total_size(ty, n)?.encode(b)?;
        match self {
            Self::Record(e) => write_envelope(e, b)?,
            Self::StoreResult { rid, result } | Self::IterateEnd { rid, result } => {
                b[4..8].copy_from_slice(&rid.to_be_bytes());
                b[8..12].copy_from_slice(&result.to_be_bytes());
            }
            Self::MonitorSync => {}
        }
        Ok(n)
    }
}
