//! Current official CADET peer records, separate from local CLIENT IPC.
//!
//! `PeerMessage` travels through CORE; `ChannelMessage` is tunnel plaintext.
//! This module authenticates nothing and adds no fragments, IDs or handshake.
//! Source-native CREATE fields are opaque bytes: the pinned C writers assign
//! options=2 and has_monotime=1 without network conversion. Other numbers below
//! are explicitly network ordered. Deprecated registry-only records have no
//! invented current layout.
use super::{Frame, MessageHeader, MessageType, message_type as mt};
use gnunet_types::Error;

/// CONNECTION_CREATE prefix in the current C int32 ABI, before peer identities.
pub const CONNECTION_CREATE_PREFIX: usize = 116;
/// CONNECTION_CREATE_ACK and CONNECTION_DESTROY total size.
pub const CONNECTION_CONTROL_LEN: usize = 40;
/// CONNECTION_BROKEN total size.
pub const CONNECTION_BROKEN_LEN: usize = 104;
/// TUNNEL_KX total size with the pinned DEBUG_KX=0.
pub const KX_LEN: usize = 104;
/// TUNNEL_KX_AUTH total size with the pinned DEBUG_KX=0.
pub const KX_AUTH_LEN: usize = 168;
/// Plaintext or encrypted Axolotl header length.
pub const AX_HEADER_LEN: usize = 40;
/// TUNNEL_ENCRYPTED prefix, before body ciphertext and its detached tag.
pub const ENCRYPTED_PREFIX: usize = 96;
/// XChaCha20-Poly1305 detached authentication tag length.
pub const MAC_LEN: usize = 16;
/// Minimum encrypted body: one plaintext message header and its body tag.
pub const MIN_ENCRYPTED_BODY_LEN: usize = 4 + MAC_LEN;
/// Largest body representable inside a complete TUNNEL_ENCRYPTED frame.
pub const MAX_ENCRYPTED_BODY_LEN: usize = u16::MAX as usize - ENCRYPTED_PREFIX;
/// Maximum plaintext fitting that envelope; CORE may impose a smaller policy cap.
pub const MAX_TUNNEL_PLAINTEXT_LEN: usize = MAX_ENCRYPTED_BODY_LEN - MAC_LEN;
/// CHANNEL_OPEN and CHANNEL_OPEN_ACK total size.
pub const CHANNEL_OPEN_LEN: usize = 76;
/// CHANNEL_DESTROY total size.
pub const CHANNEL_DESTROY_LEN: usize = 12;
/// CHANNEL_APP_DATA prefix before raw application bytes.
pub const CHANNEL_DATA_PREFIX: usize = 12;
/// CHANNEL_APP_DATA_ACK total size.
pub const CHANNEL_DATA_ACK_LEN: usize = 20;
/// Current KX flag requesting an authentication response; other bits are retained.
pub const KX_FORCE_REPLY: u32 = 1;
/// Signature purpose for the exact signed connection initiator monotime region.
pub const CONNECTION_INITIATOR_PURPOSE: u32 = 38;
/// Complete signed monotime region, including its size/purpose header.
pub const CONNECTION_INITIATOR_PURPOSE_LEN: usize = 16;

#[derive(Clone, Copy, Debug)]
enum PathStorage<'a> {
    Identities(&'a [[u8; 32]]),
    Network(&'a [u8]),
}
/// Borrowed whole route identities, including origin and destination.
/// The session owner checks nonempty paths, loops, sender adjacency and destination.
#[derive(Clone, Copy, Debug)]
pub struct PathPeers<'a>(PathStorage<'a>);
impl<'a> PathPeers<'a> {
    /// Borrow caller-owned identities for encoding without allocation.
    #[must_use]
    pub const fn new(peers: &'a [[u8; 32]]) -> Self {
        Self(PathStorage::Identities(peers))
    }
    /// Borrow an exact sequence of 32-byte wire peer identities.
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, Error> {
        if !bytes.len().is_multiple_of(32) {
            return Err(Error::Malformed);
        }
        Ok(Self(PathStorage::Network(bytes)))
    }
    /// Number of route identities actually present.
    #[must_use]
    pub const fn len(self) -> usize {
        match self.0 {
            PathStorage::Identities(peers) => peers.len(),
            PathStorage::Network(bytes) => bytes.len() / 32,
        }
    }
    /// Whether the route has no identities; the C handler drops such a route.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.len() == 0
    }
    /// Iterate peer identities by value, without an unaligned reference.
    pub fn iter(self) -> impl Iterator<Item = [u8; 32]> + 'a {
        (0..self.len()).map(move |index| match self.0 {
            PathStorage::Identities(peers) => peers[index],
            PathStorage::Network(bytes) => {
                let mut peer = [0; 32];
                peer.copy_from_slice(&bytes[index * 32..(index + 1) * 32]);
                peer
            }
        })
    }
}
impl PartialEq for PathPeers<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.iter().eq(other.iter())
    }
}
impl Eq for PathPeers<'_> {}

/// Exact body bytes authenticated as the encrypted header's associated data.
/// Includes body ciphertext followed by its separate 16-byte body tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncryptedBody<'a>(&'a [u8]);
impl<'a> EncryptedBody<'a> {
    /// Borrow a bounded ciphertext/tag string, without claiming authentication.
    pub fn new(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() < MIN_ENCRYPTED_BODY_LEN {
            return Err(Error::Malformed);
        }
        if bytes.len() > MAX_ENCRYPTED_BODY_LEN {
            return Err(Error::TooLarge);
        }
        Ok(Self(bytes))
    }
    /// Exact contiguous header AAD bytes: body ciphertext and trailing body tag.
    #[must_use]
    pub const fn bytes(self) -> &'a [u8] {
        self.0
    }
    /// Body ciphertext only, excluding its detached authentication tag.
    #[must_use]
    pub fn ciphertext(self) -> &'a [u8] {
        &self.0[..self.0.len() - MAC_LEN]
    }
    /// Exact trailing detached body authentication tag.
    #[must_use]
    pub fn mac(self) -> &'a [u8] {
        &self.0[self.0.len() - MAC_LEN..]
    }
}

/// Unauthenticated structural decoding of an Axolotl plaintext header.
/// Use only after the session owner has authenticated/decrypted the header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AxHeader {
    /// Ns: messages sent using the current ratchet, BE32.
    pub sent: u32,
    /// PNs: messages sent using the previous ratchet, BE32.
    pub previous_sent: u32,
    /// DHRs: opaque 32-byte current public ratchet key.
    pub ratchet_key: [u8; 32],
}
impl AxHeader {
    /// Decode exactly 40 already-decrypted bytes; no cryptography is performed.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        exact(bytes, AX_HEADER_LEN)?;
        Ok(Self {
            sent: number(bytes, 0)?,
            previous_sent: number(bytes, 4)?,
            ratchet_key: array(bytes, 8)?,
        })
    }
    /// Encode plaintext header bytes, leaving insufficient output unchanged.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let bytes = output.get_mut(..AX_HEADER_LEN).ok_or(Error::Capacity)?;
        bytes[..4].copy_from_slice(&self.sent.to_be_bytes());
        bytes[4..8].copy_from_slice(&self.previous_sent.to_be_bytes());
        bytes[8..40].copy_from_slice(&self.ratchet_key);
        Ok(AX_HEADER_LEN)
    }
}

/// Exact purpose38 signed bytes for CONNECTION_CREATE's monotime signature.
/// It binds no connection ID, path, options or peer identity bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionInitiatorPurpose {
    /// Monotonic microseconds in the initiator's domain, not a shared wall clock.
    pub monotime: u64,
}
impl ConnectionInitiatorPurpose {
    /// Decode exactly the signed 16-byte size/purpose/monotime region.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        exact(bytes, CONNECTION_INITIATOR_PURPOSE_LEN)?;
        if number(bytes, 0)? != CONNECTION_INITIATOR_PURPOSE_LEN as u32 {
            return Err(Error::Malformed);
        }
        if number(bytes, 4)? != CONNECTION_INITIATOR_PURPOSE {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            monotime: long(bytes, 8)?,
        })
    }
    /// Encode the exact signed region atomically; no signature is computed.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let bytes = output
            .get_mut(..CONNECTION_INITIATOR_PURPOSE_LEN)
            .ok_or(Error::Capacity)?;
        bytes[..4].copy_from_slice(&(CONNECTION_INITIATOR_PURPOSE_LEN as u32).to_be_bytes());
        bytes[4..8].copy_from_slice(&CONNECTION_INITIATOR_PURPOSE.to_be_bytes());
        bytes[8..16].copy_from_slice(&self.monotime.to_be_bytes());
        Ok(CONNECTION_INITIATOR_PURPOSE_LEN)
    }
}

/// Current outer connection/KX/ciphertext records, carried over CORE.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerMessage<'a> {
    /// Create the whole route; intermediate peers forward the exact original.
    ConnectionCreate {
        /// Pinned C assigns native uint32_t(2); retain all four bytes verbatim.
        options_bytes: [u8; 4],
        /// Pinned C native int32 flag, not BE32 and not a Rust boolean.
        has_monotime_bytes: [u8; 4],
        /// Original monotime BE64, even when the native presence flag is unset.
        monotime: u64,
        /// Original Ed25519 signature over ConnectionInitiatorPurpose only.
        monotime_signature: [u8; 64],
        /// Opaque 256-bit tunnel connection identifier.
        connection: [u8; 32],
        /// Whole origin-to-destination route; context validity is owner policy.
        path: PathPeers<'a>,
    },
    /// Reverse-path confirmation of the connection.
    ConnectionCreateAck {
        /// Uninterpreted alignment field, normally zero; current C ignores it.
        reserved: u32,
        /// Opaque connection identifier.
        connection: [u8; 32],
    },
    /// Notify the route of a failed neighboring edge.
    ConnectionBroken {
        /// Uninterpreted alignment field, normally zero.
        reserved: u32,
        /// Opaque connection identifier.
        connection: [u8; 32],
        /// First failed-edge endpoint.
        peer1: [u8; 32],
        /// Second endpoint, including the official all-zero unknown value.
        peer2: [u8; 32],
    },
    /// Tear down a connection in either route direction.
    ConnectionDestroy {
        /// Uninterpreted alignment field, normally zero.
        reserved: u32,
        /// Opaque connection identifier.
        connection: [u8; 32],
    },
    /// Initial KX: only the role selected by peer ordering initiates it.
    KeyExchange {
        /// Raw BE32 KX flags; KX_FORCE_REPLY is the current defined bit.
        flags: u32,
        /// Opaque connection identifier.
        connection: [u8; 32],
        /// Original 32-byte ephemeral public key.
        ephemeral_key: [u8; 32],
        /// Original 32-byte public ratchet key.
        ratchet_key: [u8; 32],
    },
    /// Authenticated KX response/rekey record; decoding does not verify its proof.
    KeyExchangeAuth {
        /// Raw BE32 KX flags, preserving unknown bits.
        flags: u32,
        /// Opaque connection identifier.
        connection: [u8; 32],
        /// Original ephemeral public key.
        ephemeral_key: [u8; 32],
        /// Original public ratchet key.
        ratchet_key: [u8; 32],
        /// SHA-512(root key) proof bytes, retained without granting authority.
        auth: [u8; 64],
    },
    /// Encrypted tunnel packet; no encrypted field is interpreted as plaintext.
    Encrypted {
        /// Uninterpreted alignment field, normally zero.
        reserved: u32,
        /// Per-route connection identifier, assigned after encryption in C.
        connection: [u8; 32],
        /// Detached header authentication tag at wire offset40.
        header_mac: [u8; 16],
        /// Exactly 40 encrypted AxHeader bytes, not raw Ns/PNs authority.
        encrypted_header: [u8; AX_HEADER_LEN],
        /// Body ciphertext plus trailing body tag; exact header AAD bytes.
        body: EncryptedBody<'a>,
    },
}
impl<'a> PeerMessage<'a> {
    /// Decode one exact currently supported CORE-facing CADET record.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        let frame = Frame::decode(bytes)?;
        Ok(match frame.header().message_type() {
            mt::CADET_CONNECTION_CREATE => Self::ConnectionCreate {
                options_bytes: array(bytes, 4)?,
                has_monotime_bytes: array(bytes, 8)?,
                monotime: long(bytes, 12)?,
                monotime_signature: array(bytes, 20)?,
                connection: array(bytes, 84)?,
                path: PathPeers::from_bytes(
                    bytes
                        .get(CONNECTION_CREATE_PREFIX..)
                        .ok_or(Error::Truncated)?,
                )?,
            },
            mt::CADET_CONNECTION_CREATE_ACK => {
                exact(bytes, CONNECTION_CONTROL_LEN)?;
                Self::ConnectionCreateAck {
                    reserved: number(bytes, 4)?,
                    connection: array(bytes, 8)?,
                }
            }
            mt::CADET_CONNECTION_BROKEN => {
                exact(bytes, CONNECTION_BROKEN_LEN)?;
                Self::ConnectionBroken {
                    reserved: number(bytes, 4)?,
                    connection: array(bytes, 8)?,
                    peer1: array(bytes, 40)?,
                    peer2: array(bytes, 72)?,
                }
            }
            mt::CADET_CONNECTION_DESTROY => {
                exact(bytes, CONNECTION_CONTROL_LEN)?;
                Self::ConnectionDestroy {
                    reserved: number(bytes, 4)?,
                    connection: array(bytes, 8)?,
                }
            }
            mt::CADET_TUNNEL_KX => {
                exact(bytes, KX_LEN)?;
                Self::KeyExchange {
                    flags: number(bytes, 4)?,
                    connection: array(bytes, 8)?,
                    ephemeral_key: array(bytes, 40)?,
                    ratchet_key: array(bytes, 72)?,
                }
            }
            mt::CADET_TUNNEL_KX_AUTH => {
                exact(bytes, KX_AUTH_LEN)?;
                Self::KeyExchangeAuth {
                    flags: number(bytes, 4)?,
                    connection: array(bytes, 8)?,
                    ephemeral_key: array(bytes, 40)?,
                    ratchet_key: array(bytes, 72)?,
                    auth: array(bytes, 104)?,
                }
            }
            mt::CADET_TUNNEL_ENCRYPTED => Self::Encrypted {
                reserved: number(bytes, 4)?,
                connection: array(bytes, 8)?,
                header_mac: array(bytes, 40)?,
                encrypted_header: array(bytes, 56)?,
                body: EncryptedBody::new(bytes.get(ENCRYPTED_PREFIX..).ok_or(Error::Truncated)?)?,
            },
            _ => return Err(Error::Unsupported),
        })
    }
    /// Exact encoded size, checking path arithmetic and official BE16 framing.
    pub fn encoded_len(self) -> Result<usize, Error> {
        let (kind, size) = self.shape()?;
        MessageHeader::from_total_size(kind, size)?;
        Ok(size)
    }
    /// Encode original bytes atomically; all preflight refusals preserve output.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let (kind, size) = self.shape()?;
        let bytes = prepare(output, kind, size)?;
        match self {
            Self::ConnectionCreate {
                options_bytes,
                has_monotime_bytes,
                monotime,
                monotime_signature,
                connection,
                path,
            } => {
                bytes[4..8].copy_from_slice(&options_bytes);
                bytes[8..12].copy_from_slice(&has_monotime_bytes);
                bytes[12..20].copy_from_slice(&monotime.to_be_bytes());
                bytes[20..84].copy_from_slice(&monotime_signature);
                bytes[84..116].copy_from_slice(&connection);
                for (index, peer) in path.iter().enumerate() {
                    bytes[CONNECTION_CREATE_PREFIX + index * 32
                        ..CONNECTION_CREATE_PREFIX + (index + 1) * 32]
                        .copy_from_slice(&peer);
                }
            }
            Self::ConnectionCreateAck {
                reserved,
                connection,
            }
            | Self::ConnectionDestroy {
                reserved,
                connection,
            } => connection_prefix(bytes, reserved, connection),
            Self::ConnectionBroken {
                reserved,
                connection,
                peer1,
                peer2,
            } => {
                connection_prefix(bytes, reserved, connection);
                bytes[40..72].copy_from_slice(&peer1);
                bytes[72..104].copy_from_slice(&peer2);
            }
            Self::KeyExchange {
                flags,
                connection,
                ephemeral_key,
                ratchet_key,
            } => kx(bytes, flags, connection, ephemeral_key, ratchet_key),
            Self::KeyExchangeAuth {
                flags,
                connection,
                ephemeral_key,
                ratchet_key,
                auth,
            } => {
                kx(bytes, flags, connection, ephemeral_key, ratchet_key);
                bytes[104..168].copy_from_slice(&auth);
            }
            Self::Encrypted {
                reserved,
                connection,
                header_mac,
                encrypted_header,
                body,
            } => {
                connection_prefix(bytes, reserved, connection);
                bytes[40..56].copy_from_slice(&header_mac);
                bytes[56..96].copy_from_slice(&encrypted_header);
                bytes[ENCRYPTED_PREFIX..].copy_from_slice(body.bytes());
            }
        }
        Ok(size)
    }
    fn shape(self) -> Result<(MessageType, usize), Error> {
        Ok(match self {
            Self::ConnectionCreate { path, .. } => (
                mt::CADET_CONNECTION_CREATE,
                path.len()
                    .checked_mul(32)
                    .and_then(|n| n.checked_add(CONNECTION_CREATE_PREFIX))
                    .ok_or(Error::Overflow)?,
            ),
            Self::ConnectionCreateAck { .. } => {
                (mt::CADET_CONNECTION_CREATE_ACK, CONNECTION_CONTROL_LEN)
            }
            Self::ConnectionBroken { .. } => (mt::CADET_CONNECTION_BROKEN, CONNECTION_BROKEN_LEN),
            Self::ConnectionDestroy { .. } => {
                (mt::CADET_CONNECTION_DESTROY, CONNECTION_CONTROL_LEN)
            }
            Self::KeyExchange { .. } => (mt::CADET_TUNNEL_KX, KX_LEN),
            Self::KeyExchangeAuth { .. } => (mt::CADET_TUNNEL_KX_AUTH, KX_AUTH_LEN),
            Self::Encrypted { body, .. } => (
                mt::CADET_TUNNEL_ENCRYPTED,
                ENCRYPTED_PREFIX + body.bytes().len(),
            ),
        })
    }
}

/// Current tunnel plaintext records. Channel numbers/MIDs wrap as raw BE32;
/// ordering, window ownership and peer-direction checks belong to the owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelMessage<'a> {
    /// Open a channel toward a hidden destination-port challenge.
    Open {
        /// C emits native uint32_t(2), retained byte-for-byte across ABI profiles.
        options_bytes: [u8; 4],
        /// SHA-512(application port64 || listener peer32), not the port itself.
        h_port: [u8; 64],
        /// Raw tunnel channel number; not a local CLIENT channel identifier.
        channel: u32,
    },
    /// Reveal the original application port to acknowledge opening.
    OpenAck {
        /// Uninterpreted alignment field, normally zero.
        reserved: u32,
        /// Original tunnel channel number.
        channel: u32,
        /// Original application port64, whose challenge the owner verifies.
        port: [u8; 64],
    },
    /// Destroy the channel in either direction.
    Destroy {
        /// Uninterpreted alignment field, normally zero.
        reserved: u32,
        /// Original tunnel channel number.
        channel: u32,
    },
    /// Reliable packet; the wire defines no fragment header or correlation ID.
    Data {
        /// Original wrapping message identifier.
        mid: u32,
        /// Original tunnel channel number.
        channel: u32,
        /// Raw complete payload bytes; C's channel validator accepts any tail.
        payload: &'a [u8],
    },
    /// Acknowledge channel data with a cumulative base and 64 future bits.
    DataAck {
        /// Original tunnel channel number.
        channel: u32,
        /// BE64 bitmap; bit0 acknowledges mid+1, bit63 acknowledges mid+64.
        futures: u64,
        /// Next missing message ID; this base itself is not acknowledged.
        mid: u32,
    },
    /// Header-only keepalive, routed by the enclosing connection/tunnel.
    KeepAlive,
}
impl<'a> ChannelMessage<'a> {
    /// Decode one exact current plaintext record; payload bytes remain borrowed.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        let frame = Frame::decode(bytes)?;
        Ok(match frame.header().message_type() {
            mt::CADET_CHANNEL_OPEN => {
                exact(bytes, CHANNEL_OPEN_LEN)?;
                Self::Open {
                    options_bytes: array(bytes, 4)?,
                    h_port: array(bytes, 8)?,
                    channel: number(bytes, 72)?,
                }
            }
            mt::CADET_CHANNEL_OPEN_ACK => {
                exact(bytes, CHANNEL_OPEN_LEN)?;
                Self::OpenAck {
                    reserved: number(bytes, 4)?,
                    channel: number(bytes, 8)?,
                    port: array(bytes, 12)?,
                }
            }
            mt::CADET_CHANNEL_DESTROY => {
                exact(bytes, CHANNEL_DESTROY_LEN)?;
                Self::Destroy {
                    reserved: number(bytes, 4)?,
                    channel: number(bytes, 8)?,
                }
            }
            mt::CADET_CHANNEL_APP_DATA => Self::Data {
                mid: number(bytes, 4)?,
                channel: number(bytes, 8)?,
                payload: bytes.get(CHANNEL_DATA_PREFIX..).ok_or(Error::Truncated)?,
            },
            mt::CADET_CHANNEL_APP_DATA_ACK => {
                exact(bytes, CHANNEL_DATA_ACK_LEN)?;
                Self::DataAck {
                    channel: number(bytes, 4)?,
                    futures: long(bytes, 8)?,
                    mid: number(bytes, 16)?,
                }
            }
            mt::CADET_CHANNEL_KEEPALIVE => {
                exact(bytes, 4)?;
                Self::KeepAlive
            }
            _ => return Err(Error::Unsupported),
        })
    }
    /// Exact complete encoded length, checking the official BE16 width.
    pub fn encoded_len(self) -> Result<usize, Error> {
        let (kind, size) = self.shape()?;
        MessageHeader::from_total_size(kind, size)?;
        Ok(size)
    }
    /// Encode atomically without inventing fragmentation or interpreting payload.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let (kind, size) = self.shape()?;
        let bytes = prepare(output, kind, size)?;
        match self {
            Self::Open {
                options_bytes,
                h_port,
                channel,
            } => {
                bytes[4..8].copy_from_slice(&options_bytes);
                bytes[8..72].copy_from_slice(&h_port);
                bytes[72..76].copy_from_slice(&channel.to_be_bytes());
            }
            Self::OpenAck {
                reserved,
                channel,
                port,
            } => {
                channel_control(bytes, reserved, channel);
                bytes[12..76].copy_from_slice(&port);
            }
            Self::Destroy { reserved, channel } => channel_control(bytes, reserved, channel),
            Self::Data {
                mid,
                channel,
                payload,
            } => {
                bytes[4..8].copy_from_slice(&mid.to_be_bytes());
                bytes[8..12].copy_from_slice(&channel.to_be_bytes());
                bytes[CHANNEL_DATA_PREFIX..].copy_from_slice(payload);
            }
            Self::DataAck {
                channel,
                futures,
                mid,
            } => {
                bytes[4..8].copy_from_slice(&channel.to_be_bytes());
                bytes[8..16].copy_from_slice(&futures.to_be_bytes());
                bytes[16..20].copy_from_slice(&mid.to_be_bytes());
            }
            Self::KeepAlive => {}
        }
        Ok(size)
    }
    fn shape(self) -> Result<(MessageType, usize), Error> {
        Ok(match self {
            Self::Open { .. } => (mt::CADET_CHANNEL_OPEN, CHANNEL_OPEN_LEN),
            Self::OpenAck { .. } => (mt::CADET_CHANNEL_OPEN_ACK, CHANNEL_OPEN_LEN),
            Self::Destroy { .. } => (mt::CADET_CHANNEL_DESTROY, CHANNEL_DESTROY_LEN),
            Self::Data { payload, .. } => (
                mt::CADET_CHANNEL_APP_DATA,
                CHANNEL_DATA_PREFIX
                    .checked_add(payload.len())
                    .ok_or(Error::Overflow)?,
            ),
            Self::DataAck { .. } => (mt::CADET_CHANNEL_APP_DATA_ACK, CHANNEL_DATA_ACK_LEN),
            Self::KeepAlive => (mt::CADET_CHANNEL_KEEPALIVE, 4),
        })
    }
}

fn connection_prefix(bytes: &mut [u8], reserved: u32, connection: [u8; 32]) {
    bytes[4..8].copy_from_slice(&reserved.to_be_bytes());
    bytes[8..40].copy_from_slice(&connection);
}
fn kx(bytes: &mut [u8], flags: u32, connection: [u8; 32], ephemeral: [u8; 32], ratchet: [u8; 32]) {
    connection_prefix(bytes, flags, connection);
    bytes[40..72].copy_from_slice(&ephemeral);
    bytes[72..104].copy_from_slice(&ratchet);
}
fn channel_control(bytes: &mut [u8], reserved: u32, channel: u32) {
    bytes[4..8].copy_from_slice(&reserved.to_be_bytes());
    bytes[8..12].copy_from_slice(&channel.to_be_bytes());
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
fn long(bytes: &[u8], offset: usize) -> Result<u64, Error> {
    Ok(u64::from_be_bytes(array(bytes, offset)?))
}
fn prepare(output: &mut [u8], kind: MessageType, size: usize) -> Result<&mut [u8], Error> {
    let header = MessageHeader::from_total_size(kind, size)?;
    let bytes = output.get_mut(..size).ok_or(Error::Capacity)?;
    header.encode(bytes)?;
    Ok(bytes)
}
