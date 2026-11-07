//! Current standard communicator IPC, independent of any TCP/UDP session.
//! Parsing grants no authentication, queue lifetime, callback or source authority.
use super::{Frame, MessageType, message_type as mt};
use gnunet_types::Error;
/// Prefix before the complete inner message in SEND1209.
pub const SEND_PREFIX: usize = 48;
/// Prefix before the complete inner message in INCOMING1202.
pub const INCOMING_PREFIX: usize = 88;
/// Largest complete inner message fitting actual INCOMING IPC.
pub const MAX_INCOMING: usize = u16::MAX as usize - INCOMING_PREFIX;
/// Largest complete inner message fitting actual SEND IPC.
pub const MAX_SEND: usize = u16::MAX as usize - SEND_PREFIX;
fn arr<const N: usize>(b: &[u8], at: usize) -> Result<[u8; N], Error> {
    b.get(at..at.checked_add(N).ok_or(Error::Overflow)?)
        .ok_or(Error::Truncated)?
        .try_into()
        .map_err(|_| Error::Truncated)
}
fn u32at(b: &[u8], at: usize) -> Result<u32, Error> {
    Ok(u32::from_be_bytes(arr(b, at)?))
}
fn u64at(b: &[u8], at: usize) -> Result<u64, Error> {
    Ok(u64::from_be_bytes(arr(b, at)?))
}
fn fixed(b: &[u8], n: usize) -> Result<(), Error> {
    if b.len() == n {
        Ok(())
    } else {
        Err(Error::Malformed)
    }
}
fn string(b: &[u8]) -> Result<&[u8], Error> {
    if b.last() != Some(&0) {
        return Err(Error::Malformed);
    }
    let end = b.iter().position(|v| *v == 0).ok_or(Error::Malformed)?;
    Ok(&b[..end])
}
// GNUNET_MQ_check_zero_termination requires the first NUL at the very end.
// The backchannel checker has a different contract and keeps string() above.
fn terminated(b: &[u8]) -> Result<&[u8], Error> {
    let word = string(b)?;
    if word.len() + 1 != b.len() {
        return Err(Error::Malformed);
    }
    Ok(word)
}
fn size(b: &[u8]) -> Result<usize, Error> {
    if b.contains(&0) {
        return Err(Error::InvalidInput);
    }
    b.len().checked_add(1).ok_or(Error::Overflow)
}
fn total(base: usize, more: usize) -> Result<usize, Error> {
    base.checked_add(more)
        .filter(|n| *n <= u16::MAX as usize)
        .ok_or(Error::Overflow)
}
fn put(out: &mut [u8], n: usize, kind: MessageType) -> Result<&mut [u8], Error> {
    let b = out.get_mut(..n).ok_or(Error::Capacity)?;
    b.fill(0);
    b[..2].copy_from_slice(&(n as u16).to_be_bytes());
    b[2..4].copy_from_slice(&kind.value().to_be_bytes());
    Ok(b)
}
/// Official communicator reliability metadata, not a remote-delivery proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Characteristics {
    /// No known guarantee0.
    Unknown = 0,
    /// Official reliable metadata1; UNIX testing producer uses this value.
    Reliable = 1,
    /// Official unreliable metadata2.
    Unreliable = 2,
}
impl Characteristics {
    fn parse(n: u32) -> Result<Self, Error> {
        match n {
            0 => Ok(Self::Unknown),
            1 => Ok(Self::Reliable),
            2 => Ok(Self::Unreliable),
            _ => Err(Error::Malformed),
        }
    }
}
/// Exact standard queue attributes. Peer identity remains a public claimed value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Queue {
    /// Original communicator-local queue id.
    pub id: u32,
    /// Destination peer value, not independently authenticated by this codec.
    pub peer: [u8; 32],
    /// Official raw network category; loopback is1.
    pub network: u32,
    /// Maximum complete inner message size, including its header.
    pub mtu: u32,
    /// Initial or additional message credit; ACK does not replenish this value.
    pub length: u64,
    /// Relative priority.
    pub priority: u32,
    /// Outbound0 or inbound1.
    pub status: u32,
}
impl Queue {
    fn validate(self) -> Result<(), Error> {
        if self.mtu < 4 || self.status > 1 {
            Err(Error::InvalidInput)
        } else {
            Ok(())
        }
    }
    fn parse(b: &[u8]) -> Result<Self, Error> {
        let q = Self {
            id: u32at(b, 4)?,
            peer: arr(b, 8)?,
            network: u32at(b, 40)?,
            mtu: u32at(b, 44)?,
            length: u64at(b, 48)?,
            priority: u32at(b, 56)?,
            status: u32at(b, 60)?,
        };
        q.validate().map_err(|_| Error::Malformed)?;
        Ok(q)
    }
    fn encode(self, b: &mut [u8]) {
        b[4..8].copy_from_slice(&self.id.to_be_bytes());
        b[8..40].copy_from_slice(&self.peer);
        b[40..44].copy_from_slice(&self.network.to_be_bytes());
        b[44..48].copy_from_slice(&self.mtu.to_be_bytes());
        b[48..56].copy_from_slice(&self.length.to_be_bytes());
        b[56..60].copy_from_slice(&self.priority.to_be_bytes());
        b[60..64].copy_from_slice(&self.status.to_be_bytes());
    }
}
/// Actual communicator-to-TRANSPORT messages. Opaque callback ids stay literal.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Request<'a> {
    /// Register characteristics, burst capability and canonical nonempty byte prefix.
    Register {
        /// Actual metadata.
        characteristics: Characteristics,
        /// Actual optional burst handler.
        can_burst: bool,
        /// non-NUL prefix without final NUL.
        prefix: &'a [u8],
    },
    /// Add one original local address id and its relative validity/network.
    AddAddress {
        /// Original id.
        id: u32,
        /// Relative microseconds, FOREVER retained.
        validity: u64,
        /// Raw network category.
        network: u32,
        /// non-NUL address without NUL.
        address: &'a [u8],
    },
    /// Delete only the original local address id.
    DeleteAddress(u32),
    /// Advertise a real local queue. This does not prove a remote peer exists.
    QueueSetup(Queue, &'a [u8]),
    /// Update original queue attributes/credit, without rebinding its address.
    QueueUpdate(Queue),
    /// Retire the original queue id/peer.
    QueueDown(u32, [u8; 32]),
    /// Hand actual complete network input to TRANSPORT. This layer authenticates
    /// neither peer nor neighbour; each communicator must state its own coverage.
    Incoming {
        /// Request actual service flow-control callback.
        flow_control: bool,
        /// Opaque original callback id.
        flow_id: [u8; 8],
        /// Relative address validity.
        validity: u64,
        /// Claimed immediate sender.
        peer: [u8; 32],
        /// Separate claimed neighbour field.
        neighbour: [u8; 32],
        /// Exactly one complete inner message.
        message: &'a [u8],
    },
    /// Original local transmission result. Status1 is OK, -1 is SYSERR; neither
    /// is a remote processing acknowledgement.
    Sent {
        /// Original opaque message id.
        message_id: [u8; 8],
        /// Original numeric queue id.
        queue: u32,
        /// Original destination claim.
        peer: [u8; 32],
        /// Actual local result code.
        status: i32,
    },
    /// Original create request accepted/refused; never an authenticated connect.
    Created([u8; 4], bool),
    /// Optional standard backchannel request, with one complete inner message.
    Backchannel {
        /// Destination claim.
        peer: [u8; 32],
        /// Complete message.
        message: &'a [u8],
        /// Target communicator prefix without NUL.
        communicator: &'a [u8],
    },
    /// Optional actual burst handler completed; UNIX does not advertise it.
    BurstFinished,
}
impl<'a> Request<'a> {
    /// Validate every variable field before exposing output bytes.
    pub fn encoded_len(self) -> Result<usize, Error> {
        match self {
            Self::Register { prefix, .. } => {
                if prefix.is_empty() {
                    Ok(12)
                } else {
                    total(12, size(prefix)?)
                }
            }
            Self::AddAddress { address, .. } => total(20, size(address)?),
            Self::DeleteAddress(_) => Ok(8),
            Self::QueueSetup(q, a) => {
                q.validate()?;
                total(64, size(a)?)
            }
            Self::QueueUpdate(q) => {
                q.validate()?;
                Ok(64)
            }
            Self::QueueDown(..) => Ok(40),
            Self::Incoming { message, .. } => {
                Frame::decode(message)?;
                total(INCOMING_PREFIX, message.len())
            }
            Self::Sent { .. } => Ok(52),
            Self::Created(..) => Ok(8),
            Self::BurstFinished => Ok(4),
            Self::Backchannel {
                message,
                communicator,
                ..
            } => {
                Frame::decode(message)?;
                total(total(40, message.len())?, size(communicator)?)
            }
        }
    }
    /// Encode exact official bytes into caller storage, atomic on validation/capacity failure.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len()?;
        let kind = match self {
            Self::Register { .. } => mt::TRANSPORT_NEW_COMMUNICATOR,
            Self::AddAddress { .. } => mt::TRANSPORT_ADD_ADDRESS,
            Self::DeleteAddress(_) => mt::TRANSPORT_DEL_ADDRESS,
            Self::QueueSetup(..) => mt::TRANSPORT_QUEUE_SETUP,
            Self::QueueUpdate(_) => mt::TRANSPORT_QUEUE_UPDATE,
            Self::QueueDown(..) => mt::TRANSPORT_QUEUE_TEARDOWN,
            Self::Incoming { .. } => mt::TRANSPORT_INCOMING_MSG,
            Self::Sent { .. } => mt::TRANSPORT_SEND_MSG_ACK,
            Self::Created(_, true) => mt::TRANSPORT_QUEUE_CREATE_OK,
            Self::Created(_, false) => mt::TRANSPORT_QUEUE_CREATE_FAIL,
            Self::Backchannel { .. } => mt::TRANSPORT_COMMUNICATOR_BACKCHANNEL,
            Self::BurstFinished => mt::TRANSPORT_BURST_FINISHED,
        };
        let b = put(out, n, kind)?;
        match self {
            Self::Register {
                characteristics,
                can_burst,
                prefix,
            } => {
                b[4..8].copy_from_slice(&(characteristics as u32).to_be_bytes());
                b[8..12].copy_from_slice(&u32::from(can_burst).to_be_bytes());
                if !prefix.is_empty() {
                    b[12..n - 1].copy_from_slice(prefix)
                }
            }
            Self::AddAddress {
                id,
                validity,
                network,
                address,
            } => {
                b[4..8].copy_from_slice(&id.to_be_bytes());
                b[8..16].copy_from_slice(&validity.to_be_bytes());
                b[16..20].copy_from_slice(&network.to_be_bytes());
                b[20..n - 1].copy_from_slice(address)
            }
            Self::DeleteAddress(id) => b[4..8].copy_from_slice(&id.to_be_bytes()),
            Self::QueueSetup(q, a) => {
                q.encode(b);
                b[64..n - 1].copy_from_slice(a)
            }
            Self::QueueUpdate(q) => q.encode(b),
            Self::QueueDown(id, p) => {
                b[4..8].copy_from_slice(&id.to_be_bytes());
                b[8..40].copy_from_slice(&p)
            }
            Self::Incoming {
                flow_control,
                flow_id,
                validity,
                peer,
                neighbour,
                message,
            } => {
                b[4..8].copy_from_slice(&u32::from(flow_control).to_be_bytes());
                b[8..16].copy_from_slice(&flow_id);
                b[16..24].copy_from_slice(&validity.to_be_bytes());
                b[24..56].copy_from_slice(&peer);
                b[56..88].copy_from_slice(&neighbour);
                b[88..].copy_from_slice(message)
            }
            Self::Sent {
                message_id,
                queue,
                peer,
                status,
            } => {
                b[4..8].copy_from_slice(&status.to_be_bytes());
                b[8..16].copy_from_slice(&message_id);
                b[16..20].copy_from_slice(&queue.to_be_bytes());
                b[20..52].copy_from_slice(&peer)
            }
            Self::Created(id, _) => b[4..8].copy_from_slice(&id),
            Self::Backchannel {
                peer,
                message,
                communicator,
            } => {
                b[8..40].copy_from_slice(&peer);
                b[40..40 + message.len()].copy_from_slice(message);
                b[40 + message.len()..n - 1].copy_from_slice(communicator)
            }
            Self::BurstFinished => {}
        }
        Ok(n)
    }
    /// Decode actual standard requests, preserving opaque ids and raw result bits.
    pub fn decode(b: &'a [u8]) -> Result<Self, Error> {
        let kind = Frame::decode(b)?.header().message_type();
        if kind == mt::TRANSPORT_NEW_COMMUNICATOR {
            let burst = u32at(b, 8)?;
            let field = b.get(12..).ok_or(Error::Truncated)?;
            let prefix = if field.is_empty() {
                field
            } else {
                terminated(field)?
            };
            if burst > 1 {
                return Err(Error::Malformed);
            }
            return Ok(Self::Register {
                characteristics: Characteristics::parse(u32at(b, 4)?)?,
                can_burst: burst != 0,
                prefix,
            });
        }
        if kind == mt::TRANSPORT_ADD_ADDRESS {
            return Ok(Self::AddAddress {
                id: u32at(b, 4)?,
                validity: u64at(b, 8)?,
                network: u32at(b, 16)?,
                address: terminated(b.get(20..).ok_or(Error::Truncated)?)?,
            });
        }
        if kind == mt::TRANSPORT_DEL_ADDRESS {
            fixed(b, 8)?;
            return Ok(Self::DeleteAddress(u32at(b, 4)?));
        }
        if kind == mt::TRANSPORT_QUEUE_SETUP {
            return Ok(Self::QueueSetup(
                Queue::parse(b)?,
                terminated(b.get(64..).ok_or(Error::Truncated)?)?,
            ));
        }
        if kind == mt::TRANSPORT_QUEUE_UPDATE {
            fixed(b, 64)?;
            return Ok(Self::QueueUpdate(Queue::parse(b)?));
        }
        if kind == mt::TRANSPORT_QUEUE_TEARDOWN {
            fixed(b, 40)?;
            return Ok(Self::QueueDown(u32at(b, 4)?, arr(b, 8)?));
        }
        if kind == mt::TRANSPORT_INCOMING_MSG {
            let flag = u32at(b, 4)?;
            if flag > 1 {
                return Err(Error::Malformed);
            }
            let message = b.get(88..).ok_or(Error::Truncated)?;
            Frame::decode(message)?;
            return Ok(Self::Incoming {
                flow_control: flag != 0,
                flow_id: arr(b, 8)?,
                validity: u64at(b, 16)?,
                peer: arr(b, 24)?,
                neighbour: arr(b, 56)?,
                message,
            });
        }
        if kind == mt::TRANSPORT_SEND_MSG_ACK {
            fixed(b, 52)?;
            return Ok(Self::Sent {
                status: u32at(b, 4)? as i32,
                message_id: arr(b, 8)?,
                queue: u32at(b, 16)?,
                peer: arr(b, 20)?,
            });
        }
        if kind == mt::TRANSPORT_QUEUE_CREATE_OK || kind == mt::TRANSPORT_QUEUE_CREATE_FAIL {
            fixed(b, 8)?;
            return Ok(Self::Created(
                arr(b, 4)?,
                kind == mt::TRANSPORT_QUEUE_CREATE_OK,
            ));
        }
        if kind == mt::TRANSPORT_BURST_FINISHED {
            fixed(b, 4)?;
            return Ok(Self::BurstFinished);
        }
        if kind == mt::TRANSPORT_COMMUNICATOR_BACKCHANNEL {
            if u32at(b, 4)? != 0 {
                return Err(Error::Malformed);
            }
            let rest = b.get(40..).ok_or(Error::Truncated)?;
            let h = super::MessageHeader::decode(rest)?;
            let n = h.size();
            let message = rest.get(..n).ok_or(Error::Truncated)?;
            Frame::decode(message)?;
            return Ok(Self::Backchannel {
                peer: arr(b, 8)?,
                message,
                communicator: string(rest.get(n..).ok_or(Error::Truncated)?)?,
            });
        }
        Err(Error::Unsupported)
    }
}
/// Official START_BURST1253 command. The destination and address are claims,
/// not authenticated reachability or ownership of a communicator socket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartBurst<'a> {
    /// Target public peer bytes.
    pub peer: [u8; 32],
    /// Original synchronization RTT in network-order microseconds on wire.
    pub rtt_micros: u64,
    /// Portless target address without the terminating wire NUL.
    pub address: &'a [u8],
}
impl<'a> StartBurst<'a> {
    /// Validate the exact command and its single terminal-NUL address field.
    /// Byte parsing grants neither burst capability nor source association.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        if Frame::decode(input)?.header().message_type() != mt::TRANSPORT_START_BURST {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            peer: arr(input, 4)?,
            rtt_micros: u64at(input, 36)?,
            address: terminated(input.get(44..).ok_or(Error::Truncated)?)?,
        })
    }
    /// Complete bounded command length, including its final NUL. No caller
    /// output is changed when the address or complete frame cannot be encoded.
    pub fn encoded_len(self) -> Result<usize, Error> {
        total(44, size(self.address)?)
    }
    /// Encode the exact packed public command without a private request ID,
    /// acknowledgement, host-endian scalar or extra address prefix.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len()?;
        let out = put(output, n, mt::TRANSPORT_START_BURST)?;
        out[4..36].copy_from_slice(&self.peer);
        out[36..44].copy_from_slice(&self.rtt_micros.to_be_bytes());
        out[44..n - 1].copy_from_slice(self.address);
        Ok(n)
    }
}
/// Actual TRANSPORT callbacks/commands; no source epoch or private id is on wire.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Response<'a> {
    /// Opaque create request id, destination and non-NUL address.
    Create([u8; 4], [u8; 32], &'a [u8]),
    /// Original numeric queue id, opaque message id, destination, complete frame.
    Send(u32, [u8; 8], [u8; 32], &'a [u8]),
    /// Actual service incoming-message callback id and sender claim; not remote delivery.
    Received([u8; 8], [u8; 32]),
    /// Optional original backchannel sender claim and one complete message.
    Backchannel([u8; 32], &'a [u8]),
    /// Optional burst target, RTT microseconds and address. Capability must be advertised.
    Burst([u8; 32], u64, &'a [u8]),
    /// Well-framed unregistered type, like the public MQ handler dispatcher.
    Unknown(u16),
}
impl<'a> Response<'a> {
    /// Validate exact complete input and preserve all callback correlation bytes.
    pub fn decode(b: &'a [u8]) -> Result<Self, Error> {
        let k = Frame::decode(b)?.header().message_type();
        if k == mt::TRANSPORT_QUEUE_CREATE {
            return Ok(Self::Create(
                arr(b, 4)?,
                arr(b, 8)?,
                terminated(b.get(40..).ok_or(Error::Truncated)?)?,
            ));
        }
        if k == mt::TRANSPORT_SEND_MSG {
            let message = b.get(48..).ok_or(Error::Truncated)?;
            Frame::decode(message)?;
            return Ok(Self::Send(u32at(b, 4)?, arr(b, 8)?, arr(b, 16)?, message));
        }
        if k == mt::TRANSPORT_INCOMING_MSG_ACK {
            fixed(b, 48)?;
            return Ok(Self::Received(arr(b, 8)?, arr(b, 16)?));
        }
        if k == mt::TRANSPORT_COMMUNICATOR_BACKCHANNEL_INCOMING {
            let message = b.get(40..).ok_or(Error::Truncated)?;
            Frame::decode(message)?;
            return Ok(Self::Backchannel(arr(b, 8)?, message));
        }
        if k == mt::TRANSPORT_START_BURST {
            let command = StartBurst::decode(b)?;
            return Ok(Self::Burst(
                command.peer,
                command.rtt_micros,
                command.address,
            ));
        }
        Ok(Self::Unknown(k.value()))
    }
}

impl core::fmt::Debug for Request<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let (kind, payload) = match self {
            Self::Register { prefix, .. } => ("Register", prefix.len()),
            Self::AddAddress { address, .. } => ("AddAddress", address.len()),
            Self::DeleteAddress(_) => ("DeleteAddress", 0),
            Self::QueueSetup(_, address) => ("QueueSetup", address.len()),
            Self::QueueUpdate(_) => ("QueueUpdate", 0),
            Self::QueueDown(..) => ("QueueDown", 0),
            Self::Incoming { message, .. } => ("Incoming", message.len()),
            Self::Sent { .. } => ("Sent", 0),
            Self::Created(..) => ("Created", 0),
            Self::Backchannel { message, .. } => ("Backchannel", message.len()),
            Self::BurstFinished => ("BurstFinished", 0),
        };
        f.debug_struct("CommunicatorRequest")
            .field("kind", &kind)
            .field("payload_bytes", &payload)
            .finish()
    }
}
impl core::fmt::Debug for Response<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let (kind, payload) = match self {
            Self::Create(_, _, a) => ("Create", a.len()),
            Self::Send(_, _, _, m) => ("Send", m.len()),
            Self::Received(..) => ("Received", 0),
            Self::Backchannel(_, m) => ("Backchannel", m.len()),
            Self::Burst(_, _, a) => ("Burst", a.len()),
            Self::Unknown(_) => ("Unknown", 0),
        };
        f.debug_struct("CommunicatorResponse")
            .field("kind", &kind)
            .field("payload_bytes", &payload)
            .finish()
    }
}
