//! GNUnet v0.29.1 CADET application and monitoring IPC from `cadet.h`.
//!
//! Connecting to the service has no CONNECT/INIT record. This module models the
//! local IPC protocol, not CADET's encrypted peer protocol. Numeric fields are
//! network ordered except the explicitly opaque native-order test drop type.
//! Creation options and MQ preferences are preserved: current C accepts them
//! without a bit-mask check, and the public create API emits zero options.
use super::{Frame, MessageHeader, MessageType, message_type as mt};
use gnunet_types::Error;

/// First outgoing client-assigned channel number; incoming numbers are smaller.
pub const CLIENT_CHANNEL_BOUNDARY: u32 = 0x8000_0000;
/// Maximum complete application message, including its four-byte header.
pub const MAX_APPLICATION_MESSAGE_SIZE: usize = 63 * 1024 - 164;
/// Size of either port open or port close.
pub const PORT_LEN: usize = 68;
/// Size of either outgoing creation or incoming creation notification.
pub const CHANNEL_CREATE_LEN: usize = 108;
/// Size of either channel destroy or local ACK.
pub const CHANNEL_LEN: usize = 8;
/// Prefix of LOCAL_DATA, before complete application message bytes.
pub const DATA_PREFIX: usize = 12;
/// Prefix of a path reply, before its peer identities.
pub const PATH_INFO_PREFIX: usize = 8;
/// Size of a peer list entry.
pub const PEER_INFO_LEN: usize = 44;
/// Size of a tunnel list entry.
pub const TUNNEL_INFO_LEN: usize = 48;
/// Known prefix of the current channel information reply.
pub const CHANNEL_INFO_PREFIX: usize = 68;

#[derive(Clone, Copy, Debug)]
enum PeerStorage<'a> {
    Identities(&'a [[u8; 32]]),
    Network(&'a [u8]),
}

/// Borrowed path identities, with no unaligned native references or allocation.
#[derive(Clone, Copy, Debug)]
pub struct PeerIdentities<'a>(PeerStorage<'a>);
impl<'a> PeerIdentities<'a> {
    /// Borrow application-provided peer identities for a path reply.
    #[must_use]
    pub const fn new(identities: &'a [[u8; 32]]) -> Self {
        Self(PeerStorage::Identities(identities))
    }
    /// Borrow an exact sequence of 32-byte network identities.
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, Error> {
        if !bytes.len().is_multiple_of(32) {
            return Err(Error::Malformed);
        }
        Ok(Self(PeerStorage::Network(bytes)))
    }
    /// Number of peer identities in this path.
    #[must_use]
    pub const fn len(self) -> usize {
        match self.0 {
            PeerStorage::Identities(values) => values.len(),
            PeerStorage::Network(bytes) => bytes.len() / 32,
        }
    }
    /// Whether the reply contains no peer identities.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.len() == 0
    }
    /// Iterate identities by value while retaining the borrowed backing bytes.
    pub fn iter(self) -> impl Iterator<Item = [u8; 32]> + 'a {
        (0..self.len()).map(move |index| match self.0 {
            PeerStorage::Identities(values) => values[index],
            PeerStorage::Network(bytes) => {
                let mut identity = [0; 32];
                identity.copy_from_slice(&bytes[index * 32..(index + 1) * 32]);
                identity
            }
        })
    }
}
impl PartialEq for PeerIdentities<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.iter().eq(other.iter())
    }
}
impl Eq for PeerIdentities<'_> {}

/// One application or monitoring request on a physical CADET service connection.
///
/// Monitor operations have no correlation number; the C API uses a separate MQ
/// per operation. A decoded record grants no channel ownership or send credit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Request<'a> {
    /// Listen on a hashed application port.
    PortOpen {
        /// Official 512-bit application port hash.
        port: [u8; 64],
    },
    /// Stop listening on a previously opened port.
    PortClose {
        /// Official 512-bit application port hash.
        port: [u8; 64],
    },
    /// Create an outgoing channel using a client-assigned local number.
    ChannelCreate {
        /// Raw host-order channel number, at least CLIENT_CHANNEL_BOUNDARY.
        channel: u32,
        /// Remote peer identity.
        peer: [u8; 32],
        /// Remote application port hash.
        port: [u8; 64],
        /// Uninterpreted creation options; the current public C API emits zero.
        options: u32,
    },
    /// Destroy either an incoming or outgoing local channel.
    ChannelDestroy {
        /// Raw host-order local channel number.
        channel: u32,
    },
    /// Send application bytes after consuming one local send credit.
    Data {
        /// Raw host-order local channel number.
        channel: u32,
        /// Raw MQ priority/preferences, encoded as BE32.
        priority: u32,
        /// Complete application messages; current C also accepts an empty tail.
        messages: &'a [u8],
    },
    /// Signal receive_done for the prior incoming data on this channel.
    Ack {
        /// Raw host-order local channel number.
        channel: u32,
    },
    /// List known peers, terminated by the actual PeersEnd record.
    ListPeers,
    /// List current tunnels, terminated by the actual TunnelsEnd record.
    ListTunnels,
    /// Query paths to a peer; the reserved field is always zero.
    GetPath {
        /// Destination peer identity.
        peer: [u8; 32],
    },
    /// Existing C library layout; v0.29.1 service has no registered handler.
    GetChannel {
        /// Target peer identity.
        peer: [u8; 32],
    },
    /// Official test hook to drop one peer message, not a production handshake.
    DropMessage {
        /// Raw host-order local channel number.
        channel: u32,
        /// Two bytes of the C host-order uint16_t type, preserved without a cast.
        message_type_bytes: [u8; 2],
    },
}
impl<'a> Request<'a> {
    /// Decode exactly one known request, validating framing before field access.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        let frame = Frame::decode(bytes)?;
        let request = match frame.header().message_type() {
            mt::CADET_LOCAL_PORT_OPEN => {
                exact(bytes, PORT_LEN)?;
                Self::PortOpen {
                    port: array(bytes, 4)?,
                }
            }
            mt::CADET_LOCAL_PORT_CLOSE => {
                exact(bytes, PORT_LEN)?;
                Self::PortClose {
                    port: array(bytes, 4)?,
                }
            }
            mt::CADET_LOCAL_CHANNEL_CREATE => {
                exact(bytes, CHANNEL_CREATE_LEN)?;
                Self::ChannelCreate {
                    channel: number(bytes, 4)?,
                    peer: array(bytes, 8)?,
                    port: array(bytes, 40)?,
                    options: number(bytes, 104)?,
                }
            }
            mt::CADET_LOCAL_CHANNEL_DESTROY => {
                exact(bytes, CHANNEL_LEN)?;
                Self::ChannelDestroy {
                    channel: number(bytes, 4)?,
                }
            }
            mt::CADET_LOCAL_DATA => Self::Data {
                channel: number(bytes, 4)?,
                priority: number(bytes, 8)?,
                messages: bytes.get(DATA_PREFIX..).ok_or(Error::Truncated)?,
            },
            mt::CADET_LOCAL_ACK => {
                exact(bytes, CHANNEL_LEN)?;
                Self::Ack {
                    channel: number(bytes, 4)?,
                }
            }
            mt::CADET_LOCAL_REQUEST_INFO_PEERS => {
                exact(bytes, 4)?;
                Self::ListPeers
            }
            mt::CADET_LOCAL_REQUEST_INFO_TUNNELS => {
                exact(bytes, 4)?;
                Self::ListTunnels
            }
            mt::CADET_LOCAL_REQUEST_INFO_PATH => {
                exact(bytes, 40)?;
                if number(bytes, 4)? != 0 {
                    return Err(Error::Malformed);
                }
                Self::GetPath {
                    peer: array(bytes, 8)?,
                }
            }
            mt::CADET_LOCAL_REQUEST_INFO_CHANNEL => {
                exact(bytes, 36)?;
                Self::GetChannel {
                    peer: array(bytes, 4)?,
                }
            }
            mt::CADET_DROP_CADET_MESSAGE => {
                exact(bytes, 10)?;
                Self::DropMessage {
                    channel: number(bytes, 6)?,
                    message_type_bytes: array(bytes, 4)?,
                }
            }
            _ => return Err(Error::Unsupported),
        };
        request.shape()?;
        Ok(request)
    }
    /// Complete encoded size after semantic and variable-length preflight.
    pub fn encoded_len(self) -> Result<usize, Error> {
        let (kind, size) = self.shape()?;
        MessageHeader::from_total_size(kind, size)?;
        Ok(size)
    }
    /// Encode atomically; all validation and capacity failures leave output intact.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let (kind, size) = self.shape()?;
        let bytes = prepare(output, kind, size)?;
        match self {
            Self::PortOpen { port } | Self::PortClose { port } => {
                bytes[4..68].copy_from_slice(&port)
            }
            Self::ChannelCreate {
                channel,
                peer,
                port,
                options,
            } => creation(bytes, channel, peer, port, options),
            Self::ChannelDestroy { channel } | Self::Ack { channel } => put_channel(bytes, channel),
            Self::Data {
                channel,
                priority,
                messages,
            } => data(bytes, channel, priority, messages),
            Self::GetPath { peer } => {
                bytes[4..8].fill(0);
                bytes[8..40].copy_from_slice(&peer);
            }
            Self::GetChannel { peer } => bytes[4..36].copy_from_slice(&peer),
            Self::DropMessage {
                channel,
                message_type_bytes,
            } => {
                bytes[4..6].copy_from_slice(&message_type_bytes);
                bytes[6..10].copy_from_slice(&channel.to_be_bytes());
            }
            Self::ListPeers | Self::ListTunnels => {}
        }
        Ok(size)
    }
    fn shape(self) -> Result<(MessageType, usize), Error> {
        Ok(match self {
            Self::PortOpen { .. } => (mt::CADET_LOCAL_PORT_OPEN, PORT_LEN),
            Self::PortClose { .. } => (mt::CADET_LOCAL_PORT_CLOSE, PORT_LEN),
            Self::ChannelCreate { channel, .. } => {
                if channel < CLIENT_CHANNEL_BOUNDARY {
                    return Err(Error::Malformed);
                }
                (mt::CADET_LOCAL_CHANNEL_CREATE, CHANNEL_CREATE_LEN)
            }
            Self::ChannelDestroy { .. } => (mt::CADET_LOCAL_CHANNEL_DESTROY, CHANNEL_LEN),
            Self::Data { messages, .. } => {
                message_sequence(messages, true)?;
                (
                    mt::CADET_LOCAL_DATA,
                    DATA_PREFIX
                        .checked_add(messages.len())
                        .ok_or(Error::Overflow)?,
                )
            }
            Self::Ack { .. } => (mt::CADET_LOCAL_ACK, CHANNEL_LEN),
            Self::ListPeers => (mt::CADET_LOCAL_REQUEST_INFO_PEERS, 4),
            Self::ListTunnels => (mt::CADET_LOCAL_REQUEST_INFO_TUNNELS, 4),
            Self::GetPath { .. } => (mt::CADET_LOCAL_REQUEST_INFO_PATH, 40),
            Self::GetChannel { .. } => (mt::CADET_LOCAL_REQUEST_INFO_CHANNEL, 36),
            Self::DropMessage { .. } => (mt::CADET_DROP_CADET_MESSAGE, 10),
        })
    }
}

/// One CADET service notification or monitor response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Response<'a> {
    /// Incoming channel on an open port, assigned by the service.
    ChannelCreate {
        /// Raw host-order channel number below CLIENT_CHANNEL_BOUNDARY.
        channel: u32,
        /// Remote peer identity.
        peer: [u8; 32],
        /// Local application port hash.
        port: [u8; 64],
        /// Uninterpreted creation options; current C ignores them.
        options: u32,
    },
    /// A channel closed remotely or in the service.
    ChannelDestroy {
        /// Raw host-order local channel number.
        channel: u32,
    },
    /// Application messages received on a local channel.
    Data {
        /// Raw host-order local channel number.
        channel: u32,
        /// Raw priority field; current service emits zero here.
        priority: u32,
        /// Nonempty complete application message sequence, retained in full.
        messages: &'a [u8],
    },
    /// One local send credit, not proof of delivery to a remote application.
    Ack {
        /// Raw host-order local channel number.
        channel: u32,
    },
    /// One known peer from ListPeers.
    PeerInfo {
        /// Number of known paths, BE16 on the wire.
        paths: u16,
        /// Signed C informational field, retained without a boolean restriction.
        tunnel: i16,
        /// Shortest path length; the current service emits zero as a FIXME.
        best_path_length: u32,
        /// Peer identity.
        peer: [u8; 32],
    },
    /// Actual end of the current peer list.
    PeersEnd,
    /// One known path; offset may be outside a truncated identity sequence.
    PathInfo {
        /// Raw offset of the requested peer, BE32 on the wire.
        offset: u32,
        /// Whole identities actually present; no invented sentinel is removed.
        peers: PeerIdentities<'a>,
    },
    /// Actual end of the current path list.
    PathsEnd,
    /// One tunnel from ListTunnels.
    TunnelInfo {
        /// Number of local channels.
        channels: u32,
        /// Destination identity.
        peer: [u8; 32],
        /// Number of tunnel connections.
        connections: u32,
        /// Raw encryption-state enum, including unrecognized future values.
        encryption_state: u16,
        /// Raw connection-state enum; current service emits zero.
        connection_state: u16,
    },
    /// Actual end of the current tunnel list.
    TunnelsEnd,
    /// Existing library layout, although the current C service has no producer.
    ChannelInfo {
        /// Root of the channel.
        root: [u8; 32],
        /// Destination of the channel.
        destination: [u8; 32],
        /// Unspecified trailing bytes accepted by the current C variable handler.
        extra: &'a [u8],
    },
    /// Existing library channel-query end marker.
    ChannelsEnd,
}
impl<'a> Response<'a> {
    /// Decode exactly one known service record with its actual message type.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        let frame = Frame::decode(bytes)?;
        let response = match frame.header().message_type() {
            mt::CADET_LOCAL_CHANNEL_CREATE => {
                exact(bytes, CHANNEL_CREATE_LEN)?;
                Self::ChannelCreate {
                    channel: number(bytes, 4)?,
                    peer: array(bytes, 8)?,
                    port: array(bytes, 40)?,
                    options: number(bytes, 104)?,
                }
            }
            mt::CADET_LOCAL_CHANNEL_DESTROY => {
                exact(bytes, CHANNEL_LEN)?;
                Self::ChannelDestroy {
                    channel: number(bytes, 4)?,
                }
            }
            mt::CADET_LOCAL_DATA => Self::Data {
                channel: number(bytes, 4)?,
                priority: number(bytes, 8)?,
                messages: bytes.get(DATA_PREFIX..).ok_or(Error::Truncated)?,
            },
            mt::CADET_LOCAL_ACK => {
                exact(bytes, CHANNEL_LEN)?;
                Self::Ack {
                    channel: number(bytes, 4)?,
                }
            }
            mt::CADET_LOCAL_INFO_PEERS => {
                exact(bytes, PEER_INFO_LEN)?;
                Self::PeerInfo {
                    paths: short(bytes, 4)?,
                    tunnel: i16::from_be_bytes(array(bytes, 6)?),
                    best_path_length: number(bytes, 8)?,
                    peer: array(bytes, 12)?,
                }
            }
            mt::CADET_LOCAL_INFO_PEERS_END => {
                exact(bytes, 4)?;
                Self::PeersEnd
            }
            mt::CADET_LOCAL_INFO_PATH => Self::PathInfo {
                offset: number(bytes, 4)?,
                peers: PeerIdentities::from_bytes(
                    bytes.get(PATH_INFO_PREFIX..).ok_or(Error::Truncated)?,
                )?,
            },
            mt::CADET_LOCAL_INFO_PATH_END => {
                exact(bytes, 4)?;
                Self::PathsEnd
            }
            mt::CADET_LOCAL_INFO_TUNNELS => {
                exact(bytes, TUNNEL_INFO_LEN)?;
                Self::TunnelInfo {
                    channels: number(bytes, 4)?,
                    peer: array(bytes, 8)?,
                    connections: number(bytes, 40)?,
                    encryption_state: short(bytes, 44)?,
                    connection_state: short(bytes, 46)?,
                }
            }
            mt::CADET_LOCAL_INFO_TUNNELS_END => {
                exact(bytes, 4)?;
                Self::TunnelsEnd
            }
            mt::CADET_LOCAL_INFO_CHANNEL => Self::ChannelInfo {
                root: array(bytes, 4)?,
                destination: array(bytes, 36)?,
                extra: bytes.get(CHANNEL_INFO_PREFIX..).ok_or(Error::Truncated)?,
            },
            mt::CADET_LOCAL_INFO_CHANNEL_END => {
                exact(bytes, 4)?;
                Self::ChannelsEnd
            }
            _ => return Err(Error::Unsupported),
        };
        response.shape()?;
        Ok(response)
    }
    /// Complete encoded size after semantic and variable-length preflight.
    pub fn encoded_len(self) -> Result<usize, Error> {
        let (kind, size) = self.shape()?;
        MessageHeader::from_total_size(kind, size)?;
        Ok(size)
    }
    /// Encode atomically; all validation and capacity failures leave output intact.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let (kind, size) = self.shape()?;
        let bytes = prepare(output, kind, size)?;
        match self {
            Self::ChannelCreate {
                channel,
                peer,
                port,
                options,
            } => creation(bytes, channel, peer, port, options),
            Self::ChannelDestroy { channel } | Self::Ack { channel } => put_channel(bytes, channel),
            Self::Data {
                channel,
                priority,
                messages,
            } => data(bytes, channel, priority, messages),
            Self::PeerInfo {
                paths,
                tunnel,
                best_path_length,
                peer,
            } => {
                bytes[4..6].copy_from_slice(&paths.to_be_bytes());
                bytes[6..8].copy_from_slice(&tunnel.to_be_bytes());
                bytes[8..12].copy_from_slice(&best_path_length.to_be_bytes());
                bytes[12..44].copy_from_slice(&peer);
            }
            Self::PathInfo { offset, peers } => {
                bytes[4..8].copy_from_slice(&offset.to_be_bytes());
                for (index, peer) in peers.iter().enumerate() {
                    bytes[PATH_INFO_PREFIX + index * 32..PATH_INFO_PREFIX + (index + 1) * 32]
                        .copy_from_slice(&peer);
                }
            }
            Self::TunnelInfo {
                channels,
                peer,
                connections,
                encryption_state,
                connection_state,
            } => {
                bytes[4..8].copy_from_slice(&channels.to_be_bytes());
                bytes[8..40].copy_from_slice(&peer);
                bytes[40..44].copy_from_slice(&connections.to_be_bytes());
                bytes[44..46].copy_from_slice(&encryption_state.to_be_bytes());
                bytes[46..48].copy_from_slice(&connection_state.to_be_bytes());
            }
            Self::ChannelInfo {
                root,
                destination,
                extra,
            } => {
                bytes[4..36].copy_from_slice(&root);
                bytes[36..68].copy_from_slice(&destination);
                bytes[CHANNEL_INFO_PREFIX..].copy_from_slice(extra);
            }
            Self::PeersEnd | Self::PathsEnd | Self::TunnelsEnd | Self::ChannelsEnd => {}
        }
        Ok(size)
    }
    fn shape(self) -> Result<(MessageType, usize), Error> {
        Ok(match self {
            Self::ChannelCreate { channel, .. } => {
                if channel >= CLIENT_CHANNEL_BOUNDARY {
                    return Err(Error::Malformed);
                }
                (mt::CADET_LOCAL_CHANNEL_CREATE, CHANNEL_CREATE_LEN)
            }
            Self::ChannelDestroy { .. } => (mt::CADET_LOCAL_CHANNEL_DESTROY, CHANNEL_LEN),
            Self::Data { messages, .. } => {
                message_sequence(messages, false)?;
                (
                    mt::CADET_LOCAL_DATA,
                    DATA_PREFIX
                        .checked_add(messages.len())
                        .ok_or(Error::Overflow)?,
                )
            }
            Self::Ack { .. } => (mt::CADET_LOCAL_ACK, CHANNEL_LEN),
            Self::PeerInfo { .. } => (mt::CADET_LOCAL_INFO_PEERS, PEER_INFO_LEN),
            Self::PeersEnd => (mt::CADET_LOCAL_INFO_PEERS_END, 4),
            Self::PathInfo { peers, .. } => (
                mt::CADET_LOCAL_INFO_PATH,
                peers
                    .len()
                    .checked_mul(32)
                    .and_then(|n| n.checked_add(PATH_INFO_PREFIX))
                    .ok_or(Error::Overflow)?,
            ),
            Self::PathsEnd => (mt::CADET_LOCAL_INFO_PATH_END, 4),
            Self::TunnelInfo { .. } => (mt::CADET_LOCAL_INFO_TUNNELS, TUNNEL_INFO_LEN),
            Self::TunnelsEnd => (mt::CADET_LOCAL_INFO_TUNNELS_END, 4),
            Self::ChannelInfo { extra, .. } => (
                mt::CADET_LOCAL_INFO_CHANNEL,
                CHANNEL_INFO_PREFIX
                    .checked_add(extra.len())
                    .ok_or(Error::Overflow)?,
            ),
            Self::ChannelsEnd => (mt::CADET_LOCAL_INFO_CHANNEL_END, 4),
        })
    }
}

fn message_sequence(mut bytes: &[u8], empty_allowed: bool) -> Result<(), Error> {
    if !empty_allowed && bytes.is_empty() {
        return Err(Error::Malformed);
    }
    while !bytes.is_empty() {
        let (frame, rest) = Frame::decode_prefix(bytes)?;
        if frame.header().size() > MAX_APPLICATION_MESSAGE_SIZE {
            return Err(Error::TooLarge);
        }
        bytes = rest;
    }
    Ok(())
}
fn creation(bytes: &mut [u8], channel: u32, peer: [u8; 32], port: [u8; 64], options: u32) {
    put_channel(bytes, channel);
    bytes[8..40].copy_from_slice(&peer);
    bytes[40..104].copy_from_slice(&port);
    bytes[104..108].copy_from_slice(&options.to_be_bytes());
}
fn put_channel(bytes: &mut [u8], channel: u32) {
    bytes[4..8].copy_from_slice(&channel.to_be_bytes());
}
fn data(bytes: &mut [u8], channel: u32, priority: u32, messages: &[u8]) {
    put_channel(bytes, channel);
    bytes[8..12].copy_from_slice(&priority.to_be_bytes());
    bytes[DATA_PREFIX..].copy_from_slice(messages);
}
fn exact(bytes: &[u8], size: usize) -> Result<(), Error> {
    if bytes.len() == size {
        Ok(())
    } else {
        Err(Error::Malformed)
    }
}
fn array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], Error> {
    bytes
        .get(offset..offset + N)
        .ok_or(Error::Truncated)?
        .try_into()
        .map_err(|_| Error::Truncated)
}
fn number(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    Ok(u32::from_be_bytes(array(bytes, offset)?))
}
fn short(bytes: &[u8], offset: usize) -> Result<u16, Error> {
    Ok(u16::from_be_bytes(array(bytes, offset)?))
}
fn prepare(output: &mut [u8], kind: MessageType, size: usize) -> Result<&mut [u8], Error> {
    let header = MessageHeader::from_total_size(kind, size)?;
    let bytes = output.get_mut(..size).ok_or(Error::Capacity)?;
    header.encode(bytes)?;
    Ok(bytes)
}
