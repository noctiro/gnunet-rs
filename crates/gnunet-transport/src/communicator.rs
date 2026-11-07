//! Communicator-side official IPC server decoding, independent of TCP internals.
use crate::PeerId;
use gnunet_types::Error;
use gnunet_wire::official::communicator as wire;

/// Official communicator guarantees, with the shared codec's exact metadata.
pub use wire::Characteristics;

/// Bytes before the complete network frame in official communicator SEND1209.
pub const SEND_PREFIX_LEN: usize = wire::SEND_PREFIX;
/// Largest complete network frame fitting the outgoing SEND envelope.
pub const MAX_SEND_MESSAGE_LEN: usize = wire::MAX_SEND;
/// Bytes before a complete network frame in official incoming1202 IPC.
pub const INCOMING_PREFIX_LEN: usize = wire::INCOMING_PREFIX;
/// Largest complete network frame fitting that actual incoming IPC envelope.
pub const MAX_INCOMING_MESSAGE_LEN: usize = wire::MAX_INCOMING;

/// Public queue description, keyed by communicator connection, peer and qid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Queue {
    /// Process-local communicator queue id, opaque to remote peers.
    pub id: u32,
    /// Destination identity.
    pub peer: PeerId,
    /// Official network-type value.
    pub network: u32,
    /// Per-message MTU; UINT32_MAX denotes unlimited.
    pub mtu: u32,
    /// Packet grant: initial budget in SETUP, additive budget in UPDATE.
    /// SEND_ACK retires an attempt without returning this grant. UINT64_MAX
    /// explicitly selects unlimited transmission.
    pub length: u64,
    /// Relative queue priority.
    pub priority: u32,
    /// Official connection status: outbound0 or inbound1.
    pub status: u32,
}
impl From<wire::Queue> for Queue {
    fn from(queue: wire::Queue) -> Self {
        Self {
            id: queue.id,
            peer: PeerId(queue.peer),
            network: queue.network,
            mtu: queue.mtu,
            length: queue.length,
            priority: queue.priority,
            status: queue.status,
        }
    }
}
/// A complete communicator request. Opaque ids retain their original bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Request<'a> {
    /// Process registration, required exactly once before queue operations.
    Register {
        /// Exact official Unknown0, Reliable1 or Unreliable2 guarantee.
        characteristics: Characteristics,
        /// Whether this communicator supports burst requests.
        can_burst: bool,
        /// NUL-free address prefix; empty selects a receive-only communicator.
        prefix: &'a [u8],
    },
    /// Publish a local address.
    AddAddress {
        /// Communicator-owned address id.
        id: u32,
        /// Relative advertised lifetime.
        validity: u64,
        /// Network category.
        network: u32,
        /// NUL-free address, without its wire terminator.
        address: &'a [u8],
    },
    /// Withdraw the original address id.
    DeleteAddress(u32),
    /// Add a bidirectional peer queue.
    QueueSetup {
        /// Queue transport attributes.
        queue: Queue,
        /// Exact NUL-free remote address.
        address: &'a [u8],
    },
    /// Update an existing queue, without changing its address.
    QueueUpdate(Queue),
    /// Retire an existing peer/queue pair.
    QueueDown {
        /// Original peer identity.
        peer: PeerId,
        /// Original communicator qid.
        id: u32,
    },
    /// Receive a network frame through this communicator.
    Incoming {
        /// Whether an explicit per-message IPC acknowledgement is required.
        flow_control: bool,
        /// Opaque original acknowledgement token; never endian-converted.
        flow_id: [u8; 8],
        /// Relative lifetime expected for the inbound address.
        validity: u64,
        /// Immediate authenticated communicator sender.
        peer: PeerId,
        /// Claimed neighbour field, retained separately from origin identity.
        neighbour: PeerId,
        /// Exactly one complete nested network message.
        message: &'a [u8],
    },
    /// Finish a local transmission attempt, not remote delivery.
    Sent {
        /// Original request id, never endian-converted.
        message_id: [u8; 8],
        /// Queue originally chosen for the attempt.
        queue: u32,
        /// Original destination identity.
        peer: PeerId,
        /// Official GNUNET_GenericReturnValue; GNUNET_OK (1) denotes success.
        status: u32,
    },
    /// Result for a previously requested outbound queue creation.
    Created {
        /// Opaque original create request id.
        request_id: [u8; 4],
        /// Whether the communicator accepted the creation request.
        success: bool,
    },
    /// Request best-effort delivery to the target peer's named communicator.
    Backchannel {
        /// Remote destination, separate from the physical requesting owner.
        peer: PeerId,
        /// Complete nested communicator message.
        message: &'a [u8],
        /// Target prefix without NUL; it need not match the requesting prefix.
        communicator: &'a [u8],
    },
    /// A communicator burst completed.
    BurstFinished,
}
impl<'a> Request<'a> {
    /// Decode with the single official borrowed codec, then attach domain peer
    /// types without copying payloads or changing opaque callback/result bits.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        Ok(match wire::Request::decode(input)? {
            wire::Request::Register {
                characteristics,
                can_burst,
                prefix,
            } => Self::Register {
                characteristics,
                can_burst,
                prefix,
            },
            wire::Request::AddAddress {
                id,
                validity,
                network,
                address,
            } => Self::AddAddress {
                id,
                validity,
                network,
                address,
            },
            wire::Request::DeleteAddress(id) => Self::DeleteAddress(id),
            wire::Request::QueueSetup(queue, address) => Self::QueueSetup {
                queue: queue.into(),
                address,
            },
            wire::Request::QueueUpdate(queue) => Self::QueueUpdate(queue.into()),
            wire::Request::QueueDown(id, peer) => Self::QueueDown {
                id,
                peer: PeerId(peer),
            },
            wire::Request::Incoming {
                flow_control,
                flow_id,
                validity,
                peer,
                neighbour,
                message,
            } => Self::Incoming {
                flow_control,
                flow_id,
                validity,
                peer: PeerId(peer),
                neighbour: PeerId(neighbour),
                message,
            },
            wire::Request::Sent {
                message_id,
                queue,
                peer,
                status,
            } => Self::Sent {
                message_id,
                queue,
                peer: PeerId(peer),
                status: status as u32,
            },
            wire::Request::Created(request_id, success) => Self::Created {
                request_id,
                success,
            },
            wire::Request::Backchannel {
                peer,
                message,
                communicator,
            } => Self::Backchannel {
                peer: PeerId(peer),
                message,
                communicator,
            },
            wire::Request::BurstFinished => Self::BurstFinished,
        })
    }
}
