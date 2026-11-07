//! Exact public UDP communicator TRANSPORT IPC fields, without callback authority.
//! Numeric ids stay original wire bytes. Parsing/encoding alone admits no send,
//! native completion, replay commit, cryptographic ACK or current identity.
use gnunet_types::Error;
use gnunet_udp_communicator_core::{PeerId, wire::Ack};
use gnunet_wire::official::{Frame, message_type as mt};
use std::net::SocketAddr;
/// Fixed UDP communicator prefix; no private negotiation or URI envelope.
pub const PREFIX: &[u8] = b"udp";
fn kind(input: &[u8]) -> Result<u16, Error> {
    Ok(Frame::decode(input)?.header().message_type().value())
}
fn fixed<const N: usize>(input: &[u8], at: usize) -> Result<[u8; N], Error> {
    input
        .get(at..at.checked_add(N).ok_or(Error::Overflow)?)
        .ok_or(Error::Truncated)?
        .try_into()
        .map_err(|_| Error::Truncated)
}
fn string(input: &[u8]) -> Result<&[u8], Error> {
    if input.last() != Some(&0) || input[..input.len() - 1].contains(&0) {
        return Err(Error::Malformed);
    }
    core::str::from_utf8(&input[..input.len() - 1]).map_err(|_| Error::Malformed)?;
    Ok(&input[..input.len() - 1])
}
fn prepare(out: &mut [u8], size: usize, kind: u16) -> Result<&mut [u8], Error> {
    let size16 = u16::try_from(size).map_err(|_| Error::TooLarge)?;
    let b = out.get_mut(..size).ok_or(Error::Capacity)?;
    b.fill(0);
    b[..2].copy_from_slice(&size16.to_be_bytes());
    b[2..4].copy_from_slice(&kind.to_be_bytes());
    Ok(b)
}
/// Actual service-to-communicator input. Every field remains unauthenticated
/// local request data until matched to the original live MQ/queue owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event<'a> {
    /// Original queue creation request and exact numeric address string.
    Create {
        /// Original opaque four-byte request id.
        request: [u8; 4],
        /// Requested remote public peer.
        peer: PeerId,
        /// Complete NUL-free numeric address string.
        address: &'a [u8],
    },
    /// Original local send attempt; its MID is never native/delivery authority.
    Send {
        /// Original local queue id.
        qid: u32,
        /// Original opaque eight-byte send id.
        mid: [u8; 8],
        /// Actual request's destination identity.
        peer: PeerId,
        /// Exactly one complete ordinary GNUnet frame.
        message: &'a [u8],
    },
    /// Official callback message; UDP emits incoming without flow control.
    IncomingCompleted {
        /// Original opaque incoming flow token.
        flow: [u8; 8],
        /// Original incoming remote identity.
        peer: PeerId,
    },
    /// Complete official1220 envelope containing exact ACK72. The actual IPC
    /// owner must match the peer and original master CMAC before accepting credit.
    Backchannel {
        /// Authenticated transport-level peer named by this original MQ.
        peer: PeerId,
        /// Exact official ACK, before any original-owner key matching.
        ack: Ack,
    },
    /// Registered burst instruction. An implementation must advertise support
    /// explicitly before using this command as a native/NAT work request.
    Burst {
        /// Actual burst target identity.
        peer: PeerId,
        /// Requested RTT estimate in microseconds.
        rtt_us: u64,
        /// Complete NUL-free numeric address string.
        address: &'a [u8],
    },
    /// Well-framed unregistered MQ message, with no implicit success.
    Unknown(u16),
}
impl<'a> Event<'a> {
    /// Validate complete registered extents before borrowing any payload.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        match kind(input)? {
            1206 => {
                if input.len() < 41 {
                    return Err(Error::Truncated);
                }
                Ok(Self::Create {
                    request: fixed(input, 4)?,
                    peer: fixed(input, 8)?,
                    address: string(&input[40..])?,
                })
            }
            1209 => {
                if input.len() < 52 {
                    return Err(Error::Truncated);
                }
                Frame::decode(&input[48..])?;
                Ok(Self::Send {
                    qid: u32::from_be_bytes(fixed(input, 4)?),
                    mid: fixed(input, 8)?,
                    peer: fixed(input, 16)?,
                    message: &input[48..],
                })
            }
            1203 => {
                if input.len() != 48 {
                    return Err(Error::Malformed);
                }
                Ok(Self::IncomingCompleted {
                    flow: fixed(input, 8)?,
                    peer: fixed(input, 16)?,
                })
            }
            1220 => {
                if input.len() < 44 {
                    return Err(Error::Truncated);
                }
                if fixed::<4>(input, 4)? != [0; 4] {
                    return Err(Error::Malformed);
                }
                Ok(Self::Backchannel {
                    peer: fixed(input, 8)?,
                    ack: Ack::decode_backchannel(&input[40..])?,
                })
            }
            1253 => {
                if input.len() < 45 {
                    return Err(Error::Truncated);
                }
                Ok(Self::Burst {
                    peer: fixed(input, 4)?,
                    rtt_us: u64::from_be_bytes(fixed(input, 36)?),
                    address: string(&input[44..])?,
                })
            }
            other => Ok(Self::Unknown(other)),
        }
    }
}
/// Register actual Unreliable2 delivery and the explicit burst capability.
pub fn register(can_burst: bool, out: &mut [u8]) -> Result<usize, Error> {
    let b = prepare(out, 16, mt::TRANSPORT_NEW_COMMUNICATOR.value())?;
    b[4..8].copy_from_slice(&2u32.to_be_bytes());
    b[8..12].copy_from_slice(&u32::from(can_burst).to_be_bytes());
    b[12..].copy_from_slice(b"udp\0");
    Ok(16)
}
/// Actual completion of an admitted original burst scan. This four-byte local
/// callback has no request ID and conveys neither authentication nor delivery.
pub fn burst_finished(out: &mut [u8]) -> Result<usize, Error> {
    prepare(out, 4, 1254)?;
    Ok(4)
}
/// Public queue attributes. Length is initial SETUP credit or additive UPDATE
/// credit; native send completion never replenishes it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Queue {
    /// Original local qid, never reused within its physical MQ.
    pub id: u32,
    /// Remote destination key.
    pub peer: PeerId,
    /// Source network classifier's public enum value.
    pub network: u32,
    /// Actual per-message application MTU, excluding UDP crypto overhead.
    pub mtu: u32,
    /// Initial/additive packet credit; u64MAX is explicitly unlimited.
    pub length: u64,
    /// Relative queue scheduling priority.
    pub priority: u32,
}
impl Queue {
    fn fields(self, b: &mut [u8]) {
        b[4..8].copy_from_slice(&self.id.to_be_bytes());
        b[8..40].copy_from_slice(&self.peer);
        b[40..44].copy_from_slice(&self.network.to_be_bytes());
        b[44..48].copy_from_slice(&self.mtu.to_be_bytes());
        b[48..56].copy_from_slice(&self.length.to_be_bytes());
        b[56..60].copy_from_slice(&self.priority.to_be_bytes());
    }
    /// Advertise the exact original outbound queue/address and initial grant.
    pub fn setup(self, address: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        if address.contains(&0) || self.mtu < 4 {
            return Err(Error::InvalidInput);
        }
        core::str::from_utf8(address).map_err(|_| Error::InvalidInput)?;
        let n = 65usize.checked_add(address.len()).ok_or(Error::Overflow)?;
        let b = prepare(out, n, mt::TRANSPORT_QUEUE_SETUP.value())?;
        self.fields(b);
        b[64..n - 1].copy_from_slice(address);
        Ok(n)
    }
    /// Add only a matched peer/CMAC ACK's actual positive delta. This encoder
    /// grants no authority to erase or refund previously consumed sequences.
    pub fn update(self, out: &mut [u8]) -> Result<usize, Error> {
        if self.mtu < 4 {
            return Err(Error::InvalidInput);
        }
        let b = prepare(out, 64, mt::TRANSPORT_QUEUE_UPDATE.value())?;
        self.fields(b);
        Ok(64)
    }
    /// Teardown the original qid and peer on its original physical MQ.
    pub fn down(self, out: &mut [u8]) -> Result<usize, Error> {
        let b = prepare(out, 40, mt::TRANSPORT_QUEUE_TEARDOWN.value())?;
        b[4..8].copy_from_slice(&self.id.to_be_bytes());
        b[8..40].copy_from_slice(&self.peer);
        Ok(40)
    }
}
/// Reply to the actual CREATE request. Success means numeric/native admission,
/// never authentication, established delivery or a remote queue acknowledgement.
pub fn created(request: [u8; 4], accepted: bool, out: &mut [u8]) -> Result<usize, Error> {
    let b = prepare(out, 8, if accepted { 1207 } else { 1208 })?;
    b[4..8].copy_from_slice(&request);
    Ok(8)
}
/// Retire only the original local send attempt after its actual outcome. A
/// successful local atomic UDP syscall is not reliable remote delivery.
pub fn sent(
    qid: u32,
    mid: [u8; 8],
    peer: PeerId,
    success: bool,
    out: &mut [u8],
) -> Result<usize, Error> {
    let b = prepare(out, 52, mt::TRANSPORT_SEND_MSG_ACK.value())?;
    b[4..8].copy_from_slice(&(if success { 1i32 } else { -1i32 }).to_be_bytes());
    b[8..16].copy_from_slice(&mid);
    b[16..20].copy_from_slice(&qid.to_be_bytes());
    b[20..52].copy_from_slice(&peer);
    Ok(52)
}
/// Pass exactly one authenticated network frame without incoming flow-control
/// acknowledgement, matching UDP's actual no-backpressure service contract.
pub fn incoming(peer: PeerId, message: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    Frame::decode(message)?;
    let n = 88usize.checked_add(message.len()).ok_or(Error::Overflow)?;
    let b = prepare(out, n, mt::TRANSPORT_INCOMING_MSG.value())?;
    b[16..24].copy_from_slice(&3_600_000_000u64.to_be_bytes());
    b[24..56].copy_from_slice(&peer);
    b[88..].copy_from_slice(message);
    Ok(n)
}
/// Notify the actual transport1212 backchannel, with its reserved4 and peer32,
/// exact ACK72 then terminated UDP prefix. There is no direct clear UDP ACK.
pub fn notify(peer: PeerId, ack: Ack, out: &mut [u8]) -> Result<usize, Error> {
    let b = prepare(out, 116, mt::TRANSPORT_COMMUNICATOR_BACKCHANNEL.value())?;
    b[8..40].copy_from_slice(&peer);
    ack.encode(&mut b[40..112])?;
    b[112..].copy_from_slice(b"udp\0");
    Ok(116)
}
/// Publish a caller-owned actual NAT/interface address; no address validation or
/// NAT discovery is inferred by this encoder.
pub fn address_add(
    id: u32,
    address: &[u8],
    network: u32,
    validity: u64,
    out: &mut [u8],
) -> Result<usize, Error> {
    if address.contains(&0) {
        return Err(Error::InvalidInput);
    }
    core::str::from_utf8(address).map_err(|_| Error::InvalidInput)?;
    let n = 21usize.checked_add(address.len()).ok_or(Error::Overflow)?;
    let b = prepare(out, n, mt::TRANSPORT_ADD_ADDRESS.value())?;
    b[4..8].copy_from_slice(&id.to_be_bytes());
    b[8..16].copy_from_slice(&validity.to_be_bytes());
    b[16..20].copy_from_slice(&network.to_be_bytes());
    b[20..n - 1].copy_from_slice(address);
    Ok(n)
}
/// Withdraw only the original published local address identifier.
pub fn address_remove(id: u32, out: &mut [u8]) -> Result<usize, Error> {
    let b = prepare(out, 8, mt::TRANSPORT_DEL_ADDRESS.value())?;
    b[4..8].copy_from_slice(&id.to_be_bytes());
    Ok(8)
}
/// Format the official numeric UDP address prefix and native endpoint.
#[must_use]
pub fn address(endpoint: SocketAddr) -> String {
    format!("udp-{endpoint}")
}
/// Parse a complete official numeric IPv4/IPv6 endpoint. No DNS resolution,
/// private fallback, NAT reachability or peer identity is inferred.
pub fn parse_address(bytes: &[u8]) -> Result<SocketAddr, Error> {
    let text = core::str::from_utf8(bytes).map_err(|_| Error::InvalidInput)?;
    text.strip_prefix("udp-")
        .ok_or(Error::Unsupported)?
        .parse()
        .map_err(|_| Error::InvalidInput)
}
