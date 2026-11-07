//! Official active v0.29.1 SETU IPC and union P2P frames.
//! The reference includes native-order/alignment fields. Abi is an explicit
//! source ABI selector, never a new field or a fallback negotiation on the wire.
use super::{Frame, MessageHeader, MessageType, message_type as mt};
use gnunet_types::Error;
/// Maximum official nested application context frame.
pub const CONTEXT_MAX: usize = 64512;
/// Serialized IBF bucket stride, including native reference padding.
pub const IBF_BUCKET_BYTES: usize = 20;
/// Explicit order for active reference native fields and element fingerprints.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Order {
    /// Little-endian C platform.
    Little,
    /// Big-endian C platform.
    Big,
}
impl Order {
    /// Encode an actual native16 scalar.
    #[must_use]
    pub const fn u16(self, n: u16) -> [u8; 2] {
        match self {
            Self::Little => n.to_le_bytes(),
            Self::Big => n.to_be_bytes(),
        }
    }
    /// Encode an actual native32 scalar.
    #[must_use]
    pub const fn u32(self, n: u32) -> [u8; 4] {
        match self {
            Self::Little => n.to_le_bytes(),
            Self::Big => n.to_be_bytes(),
        }
    }
    /// Encode an actual native64 scalar.
    #[must_use]
    pub const fn u64(self, n: u64) -> [u8; 8] {
        match self {
            Self::Little => n.to_le_bytes(),
            Self::Big => n.to_be_bytes(),
        }
    }
    /// Decode an actual native16 scalar.
    #[must_use]
    pub const fn read16(self, b: [u8; 2]) -> u16 {
        match self {
            Self::Little => u16::from_le_bytes(b),
            Self::Big => u16::from_be_bytes(b),
        }
    }
    /// Decode an actual native32 scalar.
    #[must_use]
    pub const fn read32(self, b: [u8; 4]) -> u32 {
        match self {
            Self::Little => u32::from_le_bytes(b),
            Self::Big => u32::from_be_bytes(b),
        }
    }
    /// Decode an actual native64 scalar.
    #[must_use]
    pub const fn read64(self, b: [u8; 8]) -> u64 {
        match self {
            Self::Little => u64::from_le_bytes(b),
            Self::Big => u64::from_be_bytes(b),
        }
    }
}
/// Current source's unpacked uint64 alignment used by ACCEPT and RESULT.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Abi {
    /// Actual C native byte order.
    pub order: Order,
    /// uint64 alignment4 or8, selected explicitly.
    pub align64: u8,
}
impl Abi {
    /// Native compiler ABI selector for this Rust target; no peer probing/fallback.
    #[must_use]
    pub const fn native() -> Self {
        Self {
            order: if cfg!(target_endian = "little") {
                Order::Little
            } else {
                Order::Big
            },
            align64: core::mem::align_of::<u64>() as u8,
        }
    }
    /// Validate the active source ABI profile.
    pub fn validate(self) -> Result<(), Error> {
        if matches!(self.align64, 4 | 8) {
            Ok(())
        } else {
            Err(Error::Unsupported)
        }
    }
    /// Complete fixed ACCEPT bytes.
    #[must_use]
    pub const fn accept_len(self) -> usize {
        if self.align64 == 8 { 56 } else { 52 }
    }
    /// Complete fixed RESULT bytes.
    #[must_use]
    pub const fn result_len(self) -> usize {
        if self.align64 == 8 { 24 } else { 20 }
    }
    /// Active C assigns htonl(salt) into a uint16. Preserve the resulting native
    /// field; callers must use effective_salt when building the actual IBF.
    #[must_use]
    pub const fn salt_field(self, salt: u32) -> u16 {
        match self.order {
            Order::Little => salt.swap_bytes() as u16,
            Order::Big => salt as u16,
        }
    }
    /// Active C promotes the native16 field then applies ntohl, not ntohs.
    #[must_use]
    pub const fn effective_salt(self, field: u16) -> u32 {
        match self.order {
            Order::Little => (field as u32).swap_bytes(),
            Order::Big => field as u32,
        }
    }
}
/// Exact operation options; the four byte flags retain their original raw value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Options {
    /// Force delta (active C also retains this option even where its chooser ignores it).
    pub force_delta: u8,
    /// Force full mode.
    pub force_full: u8,
    /// Enable Byzantine bounds.
    pub byzantine: u8,
    /// Return ADD_REMOTE when the source can identify it.
    pub symmetric: u8,
    /// Network-order lower bound in the actual C frame.
    pub lower_bound: u32,
    /// Native-order upper bound read directly by C.
    pub upper_bound: u64,
    /// Native-order byte cost assigned to a round trip.
    pub bandwidth_latency_tradeoff: u64,
    /// Native-order bucket multiplier.
    pub bucket_factor: u64,
    /// Native-order hashes/buckets per element.
    pub hashes: u64,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            force_delta: 0,
            force_full: 0,
            byzantine: 0,
            symmetric: 0,
            lower_bound: 0,
            upper_bound: u64::MAX,
            bandwidth_latency_tradeoff: 0,
            bucket_factor: 2,
            hashes: 3,
        }
    }
}
/// Official result status values; a DONE frame is not native peer acceptance evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Status {
    /// New element belongs in local union result.
    AddLocal = 0,
    /// Actual remote missing element under symmetric reporting.
    AddRemote = 1,
    /// Operation refused/failed.
    Failure = 2,
    /// Operation protocol finished.
    Done = 3,
}
impl TryFrom<u16> for Status {
    type Error = Error;
    fn try_from(value: u16) -> Result<Self, Error> {
        match value {
            0 => Ok(Self::AddLocal),
            1 => Ok(Self::AddRemote),
            2 => Ok(Self::Failure),
            3 => Ok(Self::Done),
            _ => Err(Error::Unsupported),
        }
    }
}
/// Borrowed typed set element. Its wire wrapper is header/type/reserved plus data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Element<'a> {
    /// Application-specific element type.
    pub kind: u16,
    /// Opaque complete data, at most65527 bytes on element P2P frames.
    pub data: &'a [u8],
}
/// All active client-to-service SETU commands. Active source has no REMOVE IPC.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Request<'a> {
    /// Create this client's union set.
    Create,
    /// Add a deduplicated typed element.
    Add(Element<'a>),
    /// Listen on the actual application CADET port hash.
    Listen {
        /// Reserved source field, retained on decode.
        reserved: u32,
        /// Application/port hash.
        app: [u8; 64],
    },
    /// Initiate an original operation against this peer and application.
    Evaluate {
        /// Original client request id.
        request: u32,
        /// Target peer.
        peer: [u8; 32],
        /// Application port hash.
        app: [u8; 64],
        /// Explicit local operation options.
        options: Options,
        /// Optional exact nested application message.
        context: Option<&'a [u8]>,
    },
    /// Accept an original incoming suggestion with this client's set.
    Accept {
        /// Original incoming suggestion id.
        incoming: u32,
        /// New client result correlation id.
        request: u32,
        /// Local options.
        options: Options,
    },
    /// Reject one original incoming suggestion.
    Reject {
        /// Original suggestion id.
        incoming: u32,
    },
    /// Cancel the original local operation, without a server ACK.
    Cancel {
        /// Original operation's client request id.
        request: u32,
    },
}
/// Active service-to-client observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Response<'a> {
    /// Incoming request bound to its actual application listener/channel.
    Incoming {
        /// Original suggestion id.
        incoming: u32,
        /// Actual requesting peer from the external CADET boundary.
        peer: [u8; 32],
        /// Optional exact application context frame.
        context: Option<&'a [u8]>,
    },
    /// Original operation element/status result.
    Result {
        /// Original union size observation.
        current_size: u64,
        /// Original client request id.
        request: u32,
        /// Official status.
        status: Status,
        /// Typed element, absent only when status is terminal.
        element: Element<'a>,
    },
}
/// Every active union P2P frame. Hash/key arrays remain borrowed original bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Peer<'a> {
    /// Initial original operation request, followed by application context.
    Operation {
        /// Sender's initial cardinality, network u32.
        count: u32,
        /// Original application port hash.
        app: [u8; 64],
        /// Optional nested application message.
        context: Option<&'a [u8]>,
    },
    /// Strata estimate, optionally actual zlib compressed.
    Strata {
        /// Source SEC when true, source SE when false.
        compressed: bool,
        /// Valid source estimator count1/2/4/8.
        count: u8,
        /// Actual claimed initial set cardinality.
        set_size: u64,
        /// Original serialized estimator bytes.
        data: &'a [u8],
    },
    /// A contiguous slice of the original IBF, whose metadata contains native fields.
    Ibf {
        /// Native u32 whole bucket count.
        size: u32,
        /// Network u32 bucket offset.
        offset: u32,
        /// Native16 truncated htonl field; use Abi::effective_salt.
        salt_field: u16,
        /// Native16 counter bit width.
        counter_bits: u16,
        /// Exact20-byte-stride original bucket slice.
        data: &'a [u8],
    },
    /// Inquiry for original salted native64 IBF keys.
    Inquiry {
        /// Actual full network u32 salt.
        salt: u32,
        /// Native64 key array, exact multiple8.
        keys: &'a [u8],
    },
    /// Original SHA512 element hash array, exact multiple64.
    Offer(&'a [u8]),
    /// Demand original offered SHA512 hashes, exact multiple64.
    Demand(&'a [u8]),
    /// Actual demanded element; reserved alignment bytes decode without authority.
    Element(Element<'a>),
    /// Actual full-mode element.
    FullElement(Element<'a>),
    /// Negotiated full mode, carrying directional estimated differences.
    Full {
        /// Request remote sends first when true, announce local send otherwise.
        request: bool,
        /// Receiver-local difference relative to sender.
        remote_difference: u32,
        /// Sender's initial total set size.
        remote_size: u32,
        /// Sender-local difference relative to receiver.
        local_difference: u32,
        /// Source currently allocates an extra16 zero bytes; retained on decode.
        padding: &'a [u8],
    },
    /// Differential enumeration ended; demands may still be in flight.
    Done,
    /// Full-mode enumeration ended.
    FullDone,
    /// Final original protocol indication before channel retirement.
    Over,
}
fn fixed<const N: usize>(bytes: &[u8], at: usize) -> Result<[u8; N], Error> {
    bytes
        .get(at..at.checked_add(N).ok_or(Error::Overflow)?)
        .ok_or(Error::Truncated)?
        .try_into()
        .map_err(|_| Error::Truncated)
}
fn be16(b: &[u8], at: usize) -> Result<u16, Error> {
    Ok(u16::from_be_bytes(fixed(b, at)?))
}
fn be32(b: &[u8], at: usize) -> Result<u32, Error> {
    Ok(u32::from_be_bytes(fixed(b, at)?))
}
fn be64(b: &[u8], at: usize) -> Result<u64, Error> {
    Ok(u64::from_be_bytes(fixed(b, at)?))
}
fn exact(bytes: &[u8], len: usize) -> Result<(), Error> {
    if bytes.len() == len {
        Ok(())
    } else {
        Err(Error::Malformed)
    }
}
fn nested(bytes: &[u8], at: usize) -> Result<Option<&[u8]>, Error> {
    let tail = bytes.get(at..).ok_or(Error::Truncated)?;
    if tail.is_empty() {
        return Ok(None);
    }
    if tail.len() > CONTEXT_MAX {
        return Err(Error::TooLarge);
    }
    Frame::decode(tail)?;
    Ok(Some(tail))
}
fn context_len(context: Option<&[u8]>) -> Result<usize, Error> {
    if let Some(context) = context {
        Frame::decode(context)?;
        if context.len() > CONTEXT_MAX {
            return Err(Error::TooLarge);
        }
        Ok(context.len())
    } else {
        Ok(0)
    }
}
fn len(prefix: usize, tail: usize) -> Result<usize, Error> {
    let n = prefix.checked_add(tail).ok_or(Error::Overflow)?;
    MessageHeader::from_total_size(MessageType::new(0), n)?;
    Ok(n)
}
fn prepare(ty: MessageType, n: usize, out: &mut [u8]) -> Result<&mut [u8], Error> {
    let bytes = out.get_mut(..n).ok_or(Error::Capacity)?;
    bytes.fill(0);
    MessageHeader::from_total_size(ty, n)?.encode(bytes)?;
    Ok(bytes)
}
fn opts(b: &[u8], at: usize, long: usize, abi: Abi) -> Result<Options, Error> {
    Ok(Options {
        force_delta: *b.get(at).ok_or(Error::Truncated)?,
        force_full: *b.get(at + 1).ok_or(Error::Truncated)?,
        byzantine: *b.get(at + 2).ok_or(Error::Truncated)?,
        symmetric: *b.get(at + 3).ok_or(Error::Truncated)?,
        lower_bound: be32(b, at + 4)?,
        upper_bound: abi.order.read64(fixed(b, long)?),
        bandwidth_latency_tradeoff: abi.order.read64(fixed(b, long + 8)?),
        bucket_factor: abi.order.read64(fixed(b, long + 16)?),
        hashes: abi.order.read64(fixed(b, long + 24)?),
    })
}
fn put_opts(b: &mut [u8], at: usize, long: usize, o: Options, abi: Abi) {
    b[at..at + 4].copy_from_slice(&[o.force_delta, o.force_full, o.byzantine, o.symmetric]);
    b[at + 4..at + 8].copy_from_slice(&o.lower_bound.to_be_bytes());
    for (n, v) in [
        o.upper_bound,
        o.bandwidth_latency_tradeoff,
        o.bucket_factor,
        o.hashes,
    ]
    .iter()
    .enumerate()
    {
        b[long + n * 8..long + n * 8 + 8].copy_from_slice(&abi.order.u64(*v));
    }
}
fn element(b: &[u8]) -> Result<Element<'_>, Error> {
    Ok(Element {
        kind: be16(b, 4)?,
        data: b.get(8..).ok_or(Error::Truncated)?,
    })
}
impl<'a> Request<'a> {
    /// Decode one exact official request under the selected source ABI.
    pub fn decode(bytes: &'a [u8], abi: Abi) -> Result<Self, Error> {
        abi.validate()?;
        let ty = Frame::decode(bytes)?.header().message_type();
        Ok(match ty {
            mt::SETU_CREATE => {
                exact(bytes, 4)?;
                Self::Create
            }
            mt::SETU_ADD => Self::Add(element(bytes)?),
            mt::SETU_LISTEN => {
                exact(bytes, 72)?;
                Self::Listen {
                    reserved: be32(bytes, 4)?,
                    app: fixed(bytes, 8)?,
                }
            }
            mt::SETU_REJECT => {
                exact(bytes, 8)?;
                Self::Reject {
                    incoming: be32(bytes, 4)?,
                }
            }
            mt::SETU_CANCEL => {
                exact(bytes, 8)?;
                Self::Cancel {
                    request: be32(bytes, 4)?,
                }
            }
            mt::SETU_ACCEPT => {
                exact(bytes, abi.accept_len())?;
                Self::Accept {
                    incoming: be32(bytes, 4)?,
                    request: be32(bytes, 8)?,
                    options: opts(bytes, 12, if abi.align64 == 8 { 24 } else { 20 }, abi)?,
                }
            }
            mt::SETU_EVALUATE => Self::Evaluate {
                request: be32(bytes, 4)?,
                peer: fixed(bytes, 8)?,
                app: fixed(bytes, 40)?,
                options: opts(bytes, 104, 112, abi)?,
                context: nested(bytes, 144)?,
            },
            _ => return Err(Error::Unsupported),
        })
    }
    /// Exact complete request length after structural preflight.
    pub fn encoded_len(self, abi: Abi) -> Result<usize, Error> {
        abi.validate()?;
        match self {
            Self::Create => Ok(4),
            Self::Add(element) => len(8, element.data.len()),
            Self::Listen { .. } => Ok(72),
            Self::Accept { .. } => Ok(abi.accept_len()),
            Self::Reject { .. } | Self::Cancel { .. } => Ok(8),
            Self::Evaluate { context, .. } => len(144, context_len(context)?),
        }
    }
    /// Encode canonical source bytes, preserving active native field conventions.
    pub fn encode(self, abi: Abi, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len(abi)?;
        let ty = match self {
            Self::Create => mt::SETU_CREATE,
            Self::Add(_) => mt::SETU_ADD,
            Self::Listen { .. } => mt::SETU_LISTEN,
            Self::Evaluate { .. } => mt::SETU_EVALUATE,
            Self::Accept { .. } => mt::SETU_ACCEPT,
            Self::Reject { .. } => mt::SETU_REJECT,
            Self::Cancel { .. } => mt::SETU_CANCEL,
        };
        let b = prepare(ty, n, out)?;
        match self {
            Self::Create => {}
            Self::Add(e) => {
                b[4..6].copy_from_slice(&e.kind.to_be_bytes());
                b[8..].copy_from_slice(e.data)
            }
            Self::Listen { reserved, app } => {
                b[4..8].copy_from_slice(&reserved.to_be_bytes());
                b[8..72].copy_from_slice(&app)
            }
            Self::Reject { incoming } => b[4..8].copy_from_slice(&incoming.to_be_bytes()),
            Self::Cancel { request } => b[4..8].copy_from_slice(&request.to_be_bytes()),
            Self::Accept {
                incoming,
                request,
                options,
            } => {
                b[4..8].copy_from_slice(&incoming.to_be_bytes());
                b[8..12].copy_from_slice(&request.to_be_bytes());
                put_opts(b, 12, if abi.align64 == 8 { 24 } else { 20 }, options, abi)
            }
            Self::Evaluate {
                request,
                peer,
                app,
                options,
                context,
            } => {
                b[4..8].copy_from_slice(&request.to_be_bytes());
                b[8..40].copy_from_slice(&peer);
                b[40..104].copy_from_slice(&app);
                put_opts(b, 104, 112, options, abi);
                if let Some(context) = context {
                    b[144..].copy_from_slice(context)
                }
            }
        }
        Ok(n)
    }
}
impl<'a> Response<'a> {
    /// Decode one exact original source observation.
    pub fn decode(bytes: &'a [u8], abi: Abi) -> Result<Self, Error> {
        abi.validate()?;
        Ok(match Frame::decode(bytes)?.header().message_type() {
            mt::SETU_REQUEST => Self::Incoming {
                incoming: be32(bytes, 4)?,
                peer: fixed(bytes, 8)?,
                context: nested(bytes, 40)?,
            },
            mt::SETU_RESULT => {
                let at = if abi.align64 == 8 { 8 } else { 4 };
                let prefix = abi.result_len();
                let data = bytes.get(prefix..).ok_or(Error::Truncated)?;
                Self::Result {
                    current_size: be64(bytes, at)?,
                    request: be32(bytes, at + 8)?,
                    status: Status::try_from(be16(bytes, at + 12)?)?,
                    element: Element {
                        kind: be16(bytes, at + 14)?,
                        data,
                    },
                }
            }
            _ => return Err(Error::Unsupported),
        })
    }
    /// Exact original response size under the selected ABI.
    pub fn encoded_len(self, abi: Abi) -> Result<usize, Error> {
        abi.validate()?;
        match self {
            Self::Incoming { context, .. } => len(40, context_len(context)?),
            Self::Result { element, .. } => len(abi.result_len(), element.data.len()),
        }
    }
    /// Encode one complete official service observation; grants no native receipt.
    pub fn encode(self, abi: Abi, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len(abi)?;
        let ty = match self {
            Self::Incoming { .. } => mt::SETU_REQUEST,
            Self::Result { .. } => mt::SETU_RESULT,
        };
        let b = prepare(ty, n, out)?;
        match self {
            Self::Incoming {
                incoming,
                peer,
                context,
            } => {
                b[4..8].copy_from_slice(&incoming.to_be_bytes());
                b[8..40].copy_from_slice(&peer);
                if let Some(context) = context {
                    b[40..].copy_from_slice(context)
                }
            }
            Self::Result {
                current_size,
                request,
                status,
                element,
            } => {
                let at = if abi.align64 == 8 { 8 } else { 4 };
                b[at..at + 8].copy_from_slice(&current_size.to_be_bytes());
                b[at + 8..at + 12].copy_from_slice(&request.to_be_bytes());
                b[at + 12..at + 14].copy_from_slice(&(status as u16).to_be_bytes());
                b[at + 14..at + 16].copy_from_slice(&element.kind.to_be_bytes());
                b[abi.result_len()..].copy_from_slice(element.data)
            }
        }
        Ok(n)
    }
}
impl<'a> Peer<'a> {
    /// Decode an exact original union P2P frame. No ABI/profile fallback is tried.
    pub fn decode(bytes: &'a [u8], abi: Abi) -> Result<Self, Error> {
        abi.validate()?;
        let ty = Frame::decode(bytes)?.header().message_type();
        Ok(match ty {
            mt::SETU_P2P_OPERATION_REQUEST => Self::Operation {
                count: be32(bytes, 4)?,
                app: fixed(bytes, 8)?,
                context: nested(bytes, 72)?,
            },
            mt::SETU_P2P_SE | mt::SETU_P2P_SEC => {
                let count = *bytes.get(4).ok_or(Error::Truncated)?;
                if !matches!(count, 1 | 2 | 4 | 8) {
                    return Err(Error::Malformed);
                }
                Self::Strata {
                    compressed: ty == mt::SETU_P2P_SEC,
                    count,
                    set_size: be64(bytes, 5)?,
                    data: bytes.get(13..).ok_or(Error::Truncated)?,
                }
            }
            mt::SETU_P2P_IBF => {
                let data = bytes.get(16..).ok_or(Error::Truncated)?;
                if data.is_empty() || !data.len().is_multiple_of(IBF_BUCKET_BYTES) {
                    return Err(Error::Malformed);
                }
                Self::Ibf {
                    size: abi.order.read32(fixed(bytes, 4)?),
                    offset: be32(bytes, 8)?,
                    salt_field: abi.order.read16(fixed(bytes, 12)?),
                    counter_bits: abi.order.read16(fixed(bytes, 14)?),
                    data,
                }
            }
            mt::SETU_P2P_INQUIRY => {
                let keys = bytes.get(8..).ok_or(Error::Truncated)?;
                if !keys.len().is_multiple_of(8) {
                    return Err(Error::Malformed);
                }
                Self::Inquiry {
                    salt: be32(bytes, 4)?,
                    keys,
                }
            }
            mt::SETU_P2P_OFFER | mt::SETU_P2P_DEMAND => {
                let hashes = &bytes[4..];
                if !hashes.len().is_multiple_of(64) {
                    return Err(Error::Malformed);
                }
                if ty == mt::SETU_P2P_OFFER {
                    Self::Offer(hashes)
                } else {
                    Self::Demand(hashes)
                }
            }
            mt::SETU_P2P_ELEMENTS => Self::Element(element(bytes)?),
            mt::SETU_P2P_FULL_ELEMENT => Self::FullElement(element(bytes)?),
            mt::SETU_P2P_REQUEST_FULL | mt::SETU_P2P_SEND_FULL => Self::Full {
                request: ty == mt::SETU_P2P_REQUEST_FULL,
                remote_difference: be32(bytes, 4)?,
                remote_size: be32(bytes, 8)?,
                local_difference: be32(bytes, 12)?,
                padding: bytes.get(16..).ok_or(Error::Truncated)?,
            },
            mt::SETU_P2P_DONE => {
                exact(bytes, 4)?;
                Self::Done
            }
            mt::SETU_P2P_FULL_DONE => {
                exact(bytes, 4)?;
                Self::FullDone
            }
            mt::SETU_P2P_OVER => {
                exact(bytes, 4)?;
                Self::Over
            }
            _ => return Err(Error::Unsupported),
        })
    }
    /// Exact P2P wire bytes after structural preflight.
    pub fn encoded_len(self) -> Result<usize, Error> {
        match self {
            Self::Operation { context, .. } => len(72, context_len(context)?),
            Self::Strata { count, data, .. } => {
                if !matches!(count, 1 | 2 | 4 | 8) {
                    return Err(Error::InvalidInput);
                }
                len(13, data.len())
            }
            Self::Ibf { data, .. } => {
                if data.is_empty() || !data.len().is_multiple_of(20) {
                    return Err(Error::InvalidInput);
                }
                len(16, data.len())
            }
            Self::Inquiry { keys, .. } => {
                if !keys.len().is_multiple_of(8) {
                    return Err(Error::InvalidInput);
                }
                len(8, keys.len())
            }
            Self::Offer(h) | Self::Demand(h) => {
                if !h.len().is_multiple_of(64) {
                    return Err(Error::InvalidInput);
                }
                len(4, h.len())
            }
            Self::Element(e) | Self::FullElement(e) => len(8, e.data.len()),
            Self::Full { padding, .. } => len(16, padding.len()),
            Self::Done | Self::FullDone | Self::Over => Ok(4),
        }
    }
    /// Encode active source fields atomically after exact preflight.
    pub fn encode(self, abi: Abi, out: &mut [u8]) -> Result<usize, Error> {
        abi.validate()?;
        let n = self.encoded_len()?;
        let ty = match self {
            Self::Operation { .. } => mt::SETU_P2P_OPERATION_REQUEST,
            Self::Strata {
                compressed: true, ..
            } => mt::SETU_P2P_SEC,
            Self::Strata { .. } => mt::SETU_P2P_SE,
            Self::Ibf { .. } => mt::SETU_P2P_IBF,
            Self::Inquiry { .. } => mt::SETU_P2P_INQUIRY,
            Self::Offer(_) => mt::SETU_P2P_OFFER,
            Self::Demand(_) => mt::SETU_P2P_DEMAND,
            Self::Element(_) => mt::SETU_P2P_ELEMENTS,
            Self::FullElement(_) => mt::SETU_P2P_FULL_ELEMENT,
            Self::Full { request: true, .. } => mt::SETU_P2P_REQUEST_FULL,
            Self::Full { .. } => mt::SETU_P2P_SEND_FULL,
            Self::Done => mt::SETU_P2P_DONE,
            Self::FullDone => mt::SETU_P2P_FULL_DONE,
            Self::Over => mt::SETU_P2P_OVER,
        };
        let b = prepare(ty, n, out)?;
        match self {
            Self::Operation {
                count,
                app,
                context,
            } => {
                b[4..8].copy_from_slice(&count.to_be_bytes());
                b[8..72].copy_from_slice(&app);
                if let Some(context) = context {
                    b[72..].copy_from_slice(context)
                }
            }
            Self::Strata {
                count,
                set_size,
                data,
                ..
            } => {
                b[4] = count;
                b[5..13].copy_from_slice(&set_size.to_be_bytes());
                b[13..].copy_from_slice(data)
            }
            Self::Ibf {
                size,
                offset,
                salt_field,
                counter_bits,
                data,
            } => {
                b[4..8].copy_from_slice(&abi.order.u32(size));
                b[8..12].copy_from_slice(&offset.to_be_bytes());
                b[12..14].copy_from_slice(&abi.order.u16(salt_field));
                b[14..16].copy_from_slice(&abi.order.u16(counter_bits));
                b[16..].copy_from_slice(data)
            }
            Self::Inquiry { salt, keys } => {
                b[4..8].copy_from_slice(&salt.to_be_bytes());
                b[8..].copy_from_slice(keys)
            }
            Self::Offer(h) | Self::Demand(h) => b[4..].copy_from_slice(h),
            Self::Element(e) | Self::FullElement(e) => {
                b[4..6].copy_from_slice(&e.kind.to_be_bytes());
                b[8..].copy_from_slice(e.data)
            }
            Self::Full {
                remote_difference,
                remote_size,
                local_difference,
                padding,
                ..
            } => {
                b[4..8].copy_from_slice(&remote_difference.to_be_bytes());
                b[8..12].copy_from_slice(&remote_size.to_be_bytes());
                b[12..16].copy_from_slice(&local_difference.to_be_bytes());
                b[16..].copy_from_slice(padding)
            }
            Self::Done | Self::FullDone | Self::Over => {}
        }
        Ok(n)
    }
}
