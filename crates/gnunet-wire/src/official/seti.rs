//! Official GNUnet v0.29.1 SETI IPC and CADET plaintext protocol.
//! Active IPC has ADD, not a REMOVE/ITERATE command. Element hashing has a
//! separate explicit native-endian profile; it is not a new wire field.
use super::{Frame, MessageHeader, MessageType, message_type as mt};
use gnunet_types::Error;
/// Maximum complete application context message accepted by the official API.
pub const CONTEXT_MAX: usize = 65536 - 1024;
/// Actual pinned C RESULT layouts: the u64 was not marked GNUNET_PACKED and
/// GNUNET_NETWORK_STRUCT_BEGIN is empty. This is an IPC ABI, not a P2P choice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResultLayout {
    /// Four-byte-aligned/packed u64: current_size at4, data at20.
    Packed20,
    /// Eight-byte-aligned u64: pad4..8, current_size at8, data at24.
    Aligned24,
}
impl ResultLayout {
    /// Native C-compatible u64 alignment on the current supported Rust target.
    #[must_use]
    pub const fn native() -> Self {
        if core::mem::align_of::<u64>() >= 8 {
            Self::Aligned24
        } else {
            Self::Packed20
        }
    }
    /// Complete prefix, including the actual ABI padding.
    #[must_use]
    pub const fn prefix(self) -> usize {
        match self {
            Self::Packed20 => 20,
            Self::Aligned24 => 24,
        }
    }
    const fn current(self) -> usize {
        self.prefix() - 16
    }
}
/// Native RESULT prefix before element data (24 on the pinned64-bit profile).
pub const RESULT_PREFIX: usize = ResultLayout::native().prefix();
/// Complete Bloom chunk prefix before raw filter bytes.
pub const BLOOM_PREFIX: usize = 84;
/// Official sender's complete Bloom frame ceiling (fits public CADET messages).
pub const BLOOM_FRAME_MAX: usize = 60 * 1024;
/// Status: this element is part of the final intersection.
pub const ADD_LOCAL: u16 = 0;
/// Status: this element must be removed from the caller's original set.
pub const DEL_LOCAL: u16 = 1;
/// Status: peer refusal or actual protocol/resource failure.
pub const FAILURE: u16 = 2;
/// Status: protocol completed, not remote application consumption.
pub const DONE: u16 = 3;
/// All commands registered by the pinned SETI service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Request<'a> {
    /// Create this MQ's one set.
    Create,
    /// Add an opaque element; reserved is ignored by C.
    Add {
        /// Application element type, in network order on IPC.
        element_type: u16,
        /// Alignment field retained verbatim.
        reserved: u16,
        /// Entire element data.
        data: &'a [u8],
    },
    /// Initiate one operation on this MQ's existing set.
    Evaluate {
        /// Actual official request id.
        request_id: u32,
        /// Expected actual CADET endpoint.
        peer: [u8; 32],
        /// Actual CADET application port id.
        app_id: [u8; 64],
        /// Return intersection (1), otherwise removal delta (0).
        return_intersection: u32,
        /// Optional one complete nested GNUnet message.
        context: Option<&'a [u8]>,
    },
    /// Listen on an actual application port; C ignores operation.
    Listen {
        /// Original raw legacy field (public API emits zero).
        operation: u32,
        /// Actual CADET port, not an identity proof.
        app_id: [u8; 64],
    },
    /// Accept the original suggested operation using this MQ's set.
    Accept {
        /// Official suggested incoming id.
        accept_id: u32,
        /// Local request id for result correlation.
        request_id: u32,
        /// Return-intersection option, as a raw NBO integer.
        return_intersection: u32,
    },
    /// Reject the original pending incoming request.
    Reject {
        /// Official incoming suggestion id.
        accept_id: u32,
    },
    /// Cancel this MQ's original operation; unknown ids are harmless.
    Cancel {
        /// Original official request id.
        request_id: u32,
    },
}
/// Actual client notifications/results. No record is peer authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Response<'a> {
    /// Incoming request on the actual listener MQ.
    Request {
        /// Official suggestion correlation id.
        accept_id: u32,
        /// Actual endpoint must be supplied by the CADET port.
        peer: [u8; 32],
        /// Optional complete nested context.
        context: Option<&'a [u8]>,
    },
    /// One incremental result or terminal status.
    Result {
        /// Current operation cardinality; pinned C leaves this zero.
        current_size: u64,
        /// Original request id.
        request_id: u32,
        /// Raw status (0..3 are the active official values).
        status: u16,
        /// Raw network-field value. Pinned C omits htons on
        /// element results; decoding/encoding still preserves those raw bytes.
        element_type: u16,
        /// Opaque data, normally empty for terminal status.
        data: &'a [u8],
    },
}
/// SETI messages carried as complete CADET application messages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerMessage<'a> {
    /// First request; active C does not populate app_id and uses its port binding.
    OperationRequest {
        /// Original sender count.
        element_count: u32,
        /// Raw reserved app_idX, not routing authority.
        app_id: [u8; 64],
        /// Optional complete application context.
        context: Option<&'a [u8]>,
    },
    /// Larger acceptor asks the smaller initiator to send the first filter.
    ElementInfo {
        /// Original sender count.
        element_count: u32,
    },
    /// Complete filter or consecutive fragment. There is no private offset or RID.
    Bloom {
        /// Remaining sender count.
        element_count: u32,
        /// XOR of all remaining element hashes.
        element_xor: [u8; 64],
        /// Actual numeric mutator.
        mutator: u32,
        /// Total raw bytes across consecutive fragments.
        total_length: u32,
        /// Number of actual GNUnet container hash-bit rounds.
        bits_per_element: u32,
        /// Entire current raw fragment.
        data: &'a [u8],
    },
    /// Final agreement. Count and XOR must both match the actual local reduction.
    Done {
        /// Final sender cardinality.
        element_count: u32,
        /// XOR of remaining element hashes.
        element_xor: [u8; 64],
    },
}
fn array<const N: usize>(b: &[u8], at: usize) -> Result<[u8; N], Error> {
    b.get(at..at.checked_add(N).ok_or(Error::Overflow)?)
        .ok_or(Error::Truncated)?
        .try_into()
        .map_err(|_| Error::Truncated)
}
fn word(b: &[u8], at: usize) -> Result<u32, Error> {
    Ok(u32::from_be_bytes(array(b, at)?))
}
fn short(b: &[u8], at: usize) -> Result<u16, Error> {
    Ok(u16::from_be_bytes(array(b, at)?))
}
fn context(b: &[u8]) -> Result<Option<&[u8]>, Error> {
    if b.is_empty() {
        return Ok(None);
    }
    Frame::decode(b)?;
    if b.len() > CONTEXT_MAX {
        return Err(Error::TooLarge);
    }
    Ok(Some(b))
}
fn sized(prefix: usize, tail: usize) -> Result<usize, Error> {
    let n = prefix.checked_add(tail).ok_or(Error::Overflow)?;
    MessageHeader::from_total_size(MessageType::new(0), n)?;
    Ok(n)
}
fn nested(prefix: usize, c: Option<&[u8]>) -> Result<usize, Error> {
    let tail = match c {
        Some(c) => {
            context(c)?;
            c.len()
        }
        None => 0,
    };
    sized(prefix, tail)
}
fn output(out: &mut [u8], n: usize, kind: MessageType) -> Result<&mut [u8], Error> {
    let b = out.get_mut(..n).ok_or(Error::Capacity)?;
    b.fill(0);
    MessageHeader::from_total_size(kind, n)?.encode(b)?;
    Ok(b)
}
impl<'a> Request<'a> {
    /// Decode exactly one official request, with bounded nested-context validation.
    pub fn decode(b: &'a [u8]) -> Result<Self, Error> {
        let kind = Frame::decode(b)?.header().message_type();
        Ok(match kind {
            mt::SETI_CREATE if b.len() == 4 => Self::Create,
            mt::SETI_ADD if b.len() >= 8 => Self::Add {
                element_type: short(b, 4)?,
                reserved: short(b, 6)?,
                data: &b[8..],
            },
            mt::SETI_EVALUATE if b.len() >= 108 => Self::Evaluate {
                request_id: word(b, 4)?,
                peer: array(b, 8)?,
                app_id: array(b, 40)?,
                return_intersection: word(b, 104)?,
                context: context(&b[108..])?,
            },
            mt::SETI_LISTEN if b.len() == 72 => Self::Listen {
                operation: word(b, 4)?,
                app_id: array(b, 8)?,
            },
            mt::SETI_ACCEPT if b.len() == 16 => Self::Accept {
                accept_id: word(b, 4)?,
                request_id: word(b, 8)?,
                return_intersection: word(b, 12)?,
            },
            mt::SETI_REJECT if b.len() == 8 => Self::Reject {
                accept_id: word(b, 4)?,
            },
            mt::SETI_CANCEL if b.len() == 8 => Self::Cancel {
                request_id: word(b, 4)?,
            },
            mt::SETI_CREATE
            | mt::SETI_ADD
            | mt::SETI_EVALUATE
            | mt::SETI_LISTEN
            | mt::SETI_ACCEPT
            | mt::SETI_REJECT
            | mt::SETI_CANCEL => return Err(Error::Malformed),
            _ => return Err(Error::Unsupported),
        })
    }
    /// Exact size; all validation precedes any output mutation.
    pub fn encoded_len(self) -> Result<usize, Error> {
        match self {
            Self::Create => Ok(4),
            Self::Add { data, .. } => sized(8, data.len()),
            Self::Evaluate { context, .. } => nested(108, context),
            Self::Listen { .. } => Ok(72),
            Self::Accept { .. } => Ok(16),
            Self::Reject { .. } | Self::Cancel { .. } => Ok(8),
        }
    }
    /// Encode the exact active IPC layout, preserving raw options/reserved fields.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len()?;
        let kind = match self {
            Self::Create => mt::SETI_CREATE,
            Self::Add { .. } => mt::SETI_ADD,
            Self::Evaluate { .. } => mt::SETI_EVALUATE,
            Self::Listen { .. } => mt::SETI_LISTEN,
            Self::Accept { .. } => mt::SETI_ACCEPT,
            Self::Reject { .. } => mt::SETI_REJECT,
            Self::Cancel { .. } => mt::SETI_CANCEL,
        };
        let b = output(out, n, kind)?;
        match self {
            Self::Create => {}
            Self::Add {
                element_type,
                reserved,
                data,
            } => {
                b[4..6].copy_from_slice(&element_type.to_be_bytes());
                b[6..8].copy_from_slice(&reserved.to_be_bytes());
                b[8..].copy_from_slice(data)
            }
            Self::Evaluate {
                request_id,
                peer,
                app_id,
                return_intersection,
                context,
            } => {
                b[4..8].copy_from_slice(&request_id.to_be_bytes());
                b[8..40].copy_from_slice(&peer);
                b[40..104].copy_from_slice(&app_id);
                b[104..108].copy_from_slice(&return_intersection.to_be_bytes());
                if let Some(c) = context {
                    b[108..].copy_from_slice(c)
                }
            }
            Self::Listen { operation, app_id } => {
                b[4..8].copy_from_slice(&operation.to_be_bytes());
                b[8..72].copy_from_slice(&app_id)
            }
            Self::Accept {
                accept_id,
                request_id,
                return_intersection,
            } => {
                b[4..8].copy_from_slice(&accept_id.to_be_bytes());
                b[8..12].copy_from_slice(&request_id.to_be_bytes());
                b[12..16].copy_from_slice(&return_intersection.to_be_bytes())
            }
            Self::Reject { accept_id } => b[4..8].copy_from_slice(&accept_id.to_be_bytes()),
            Self::Cancel { request_id } => b[4..8].copy_from_slice(&request_id.to_be_bytes()),
        }
        Ok(n)
    }
}
impl<'a> Response<'a> {
    /// Decode one result/notification using the actual native C ABI profile.
    pub fn decode(b: &'a [u8]) -> Result<Self, Error> {
        Self::decode_with_layout(b, ResultLayout::native())
    }
    /// Decode the explicitly chosen original RESULT ABI; there is no heuristic
    /// fallback that could reassign an application RID or element boundary.
    pub fn decode_with_layout(b: &'a [u8], layout: ResultLayout) -> Result<Self, Error> {
        let kind = Frame::decode(b)?.header().message_type();
        let at = layout.current();
        Ok(match kind {
            mt::SETI_REQUEST if b.len() >= 40 => Self::Request {
                accept_id: word(b, 4)?,
                peer: array(b, 8)?,
                context: context(&b[40..])?,
            },
            mt::SETI_RESULT if b.len() >= layout.prefix() => Self::Result {
                current_size: u64::from_be_bytes(array(b, at)?),
                request_id: word(b, at + 8)?,
                status: short(b, at + 12)?,
                element_type: short(b, at + 14)?,
                data: &b[layout.prefix()..],
            },
            mt::SETI_REQUEST | mt::SETI_RESULT => return Err(Error::Malformed),
            _ => return Err(Error::Unsupported),
        })
    }
    /// Exact native C-layout size, without allocation or hidden framing.
    pub fn encoded_len(self) -> Result<usize, Error> {
        self.encoded_len_with_layout(ResultLayout::native())
    }
    /// Exact size for the explicitly selected original RESULT layout.
    pub fn encoded_len_with_layout(self, layout: ResultLayout) -> Result<usize, Error> {
        match self {
            Self::Request { context, .. } => nested(40, context),
            Self::Result { data, .. } => sized(layout.prefix(), data.len()),
        }
    }
    /// Encode the actual native C-layout prefix, canonical zero padding and
    /// network fields. The official public client calls ntohs on element_type.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        self.encode_with_layout(out, ResultLayout::native())
    }
    /// Encode one explicitly chosen RESULT ABI; no native memory is transmuted.
    pub fn encode_with_layout(self, out: &mut [u8], layout: ResultLayout) -> Result<usize, Error> {
        let n = self.encoded_len_with_layout(layout)?;
        let b = output(
            out,
            n,
            match self {
                Self::Request { .. } => mt::SETI_REQUEST,
                Self::Result { .. } => mt::SETI_RESULT,
            },
        )?;
        match self {
            Self::Request {
                accept_id,
                peer,
                context,
            } => {
                b[4..8].copy_from_slice(&accept_id.to_be_bytes());
                b[8..40].copy_from_slice(&peer);
                if let Some(c) = context {
                    b[40..].copy_from_slice(c)
                }
            }
            Self::Result {
                current_size,
                request_id,
                status,
                element_type,
                data,
            } => {
                let at = layout.current();
                b[at..at + 8].copy_from_slice(&current_size.to_be_bytes());
                b[at + 8..at + 12].copy_from_slice(&request_id.to_be_bytes());
                b[at + 12..at + 14].copy_from_slice(&status.to_be_bytes());
                b[at + 14..at + 16].copy_from_slice(&element_type.to_be_bytes());
                b[layout.prefix()..].copy_from_slice(data)
            }
        }
        Ok(n)
    }
}
impl<'a> PeerMessage<'a> {
    /// Decode an exact CADET plaintext frame. Stateful filter sizes/phase/source
    /// are checked by the operation owner, never inferred from an untrusted id.
    pub fn decode(b: &'a [u8]) -> Result<Self, Error> {
        let kind = Frame::decode(b)?.header().message_type();
        Ok(match kind {
            mt::SETI_P2P_OPERATION_REQUEST if b.len() >= 72 => Self::OperationRequest {
                element_count: word(b, 4)?,
                app_id: array(b, 8)?,
                context: context(&b[72..])?,
            },
            mt::SETI_P2P_ELEMENT_INFO if b.len() == 8 => Self::ElementInfo {
                element_count: word(b, 4)?,
            },
            mt::SETI_P2P_BF if b.len() >= 84 => Self::Bloom {
                element_count: word(b, 4)?,
                element_xor: array(b, 8)?,
                mutator: word(b, 72)?,
                total_length: word(b, 76)?,
                bits_per_element: word(b, 80)?,
                data: &b[84..],
            },
            mt::SETI_P2P_DONE if b.len() == 72 => Self::Done {
                element_count: word(b, 4)?,
                element_xor: array(b, 8)?,
            },
            mt::SETI_P2P_OPERATION_REQUEST
            | mt::SETI_P2P_ELEMENT_INFO
            | mt::SETI_P2P_BF
            | mt::SETI_P2P_DONE => return Err(Error::Malformed),
            _ => return Err(Error::Unsupported),
        })
    }
    /// Exact complete frame size; fragments may contain arbitrary raw filter bytes.
    pub fn encoded_len(self) -> Result<usize, Error> {
        match self {
            Self::OperationRequest { context, .. } => nested(72, context),
            Self::ElementInfo { .. } => Ok(8),
            Self::Bloom { data, .. } => sized(84, data.len()),
            Self::Done { .. } => Ok(72),
        }
    }
    /// Encode only official fields and the original raw fragment/context.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len()?;
        let kind = match self {
            Self::OperationRequest { .. } => mt::SETI_P2P_OPERATION_REQUEST,
            Self::ElementInfo { .. } => mt::SETI_P2P_ELEMENT_INFO,
            Self::Bloom { .. } => mt::SETI_P2P_BF,
            Self::Done { .. } => mt::SETI_P2P_DONE,
        };
        let b = output(out, n, kind)?;
        match self {
            Self::OperationRequest {
                element_count,
                app_id,
                context,
            } => {
                b[4..8].copy_from_slice(&element_count.to_be_bytes());
                b[8..72].copy_from_slice(&app_id);
                if let Some(c) = context {
                    b[72..].copy_from_slice(c)
                }
            }
            Self::ElementInfo { element_count } => {
                b[4..8].copy_from_slice(&element_count.to_be_bytes())
            }
            Self::Bloom {
                element_count,
                element_xor,
                mutator,
                total_length,
                bits_per_element,
                data,
            } => {
                b[4..8].copy_from_slice(&element_count.to_be_bytes());
                b[8..72].copy_from_slice(&element_xor);
                b[72..76].copy_from_slice(&mutator.to_be_bytes());
                b[76..80].copy_from_slice(&total_length.to_be_bytes());
                b[80..84].copy_from_slice(&bits_per_element.to_be_bytes());
                b[84..].copy_from_slice(data)
            }
            Self::Done {
                element_count,
                element_xor,
            } => {
                b[4..8].copy_from_slice(&element_count.to_be_bytes());
                b[8..72].copy_from_slice(&element_xor)
            }
        }
        Ok(n)
    }
}
