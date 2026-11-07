//! Exact v0.29.1 local service framing used by the TCP communicator.
//! IDs described as opaque stay byte arrays; no network protocol is invented.
use crate::session::{ADDRESS_VALIDITY_US, ReplayKind, Role};
use gnunet_crypto::EddsaPublicKey;
use gnunet_types::Error;
use gnunet_wire::official::message_type as mt;
/// Source PEERSTORE subsystem, without its terminating NUL.
pub const SUBSYSTEM: &[u8] = b"transport_tcp_communicator";
fn frame(input: &[u8]) -> Result<u16, Error> {
    if input.len() < 4 {
        return Err(Error::Truncated);
    }
    if input.len() > u16::MAX as usize
        || u16::from_be_bytes([input[0], input[1]]) as usize != input.len()
    {
        return Err(Error::Malformed);
    }
    Ok(u16::from_be_bytes([input[2], input[3]]))
}
fn prepare(out: &mut [u8], size: usize, kind: u16) -> Result<&mut [u8], Error> {
    if size > u16::MAX as usize {
        return Err(Error::Overflow);
    }
    let b = out.get_mut(..size).ok_or(Error::Capacity)?;
    b.fill(0);
    b[..2].copy_from_slice(&(size as u16).to_be_bytes());
    b[2..4].copy_from_slice(&kind.to_be_bytes());
    Ok(b)
}
fn u16at(input: &[u8], i: usize) -> Result<usize, Error> {
    Ok(u16::from_be_bytes(
        input
            .get(i..i + 2)
            .ok_or(Error::Truncated)?
            .try_into()
            .map_err(|_| Error::Truncated)?,
    ) as usize)
}
fn u32at(input: &[u8], i: usize) -> Result<u32, Error> {
    Ok(u32::from_be_bytes(
        input
            .get(i..i + 4)
            .ok_or(Error::Truncated)?
            .try_into()
            .map_err(|_| Error::Truncated)?,
    ))
}
fn peer(input: &[u8], i: usize) -> Result<EddsaPublicKey, Error> {
    Ok(EddsaPublicKey::from_bytes(
        input
            .get(i..i + 32)
            .ok_or(Error::Truncated)?
            .try_into()
            .map_err(|_| Error::Truncated)?,
    ))
}
fn cstr(input: &[u8]) -> Result<&[u8], Error> {
    if input.last() != Some(&0) {
        return Err(Error::Malformed);
    }
    Ok(&input[..input.iter().position(|b| *b == 0).ok_or(Error::Malformed)?])
}
fn str_size(input: &[u8]) -> Result<usize, Error> {
    if input.contains(&0) {
        return Err(Error::InvalidInput);
    }
    input
        .len()
        .checked_add(1)
        .filter(|n| *n <= u16::MAX as usize)
        .ok_or(Error::Overflow)
}
/// Encode actual PEERSTORE iterator START with peer_set=YES and exact key.
pub fn replay_start(
    rid: u32,
    peer: EddsaPublicKey,
    kind: ReplayKind,
    out: &mut [u8],
) -> Result<usize, Error> {
    let ss = SUBSYSTEM.len() + 1;
    let ks = kind.key().len() + 1;
    let n = 48 + ss + ks;
    let b = prepare(out, n, mt::PEERSTORE_ITERATE_START.value())?;
    b[4..36].copy_from_slice(peer.as_bytes());
    b[36..40].copy_from_slice(&rid.to_be_bytes());
    b[40..42].copy_from_slice(&1u16.to_be_bytes());
    b[42..44].copy_from_slice(&(ss as u16).to_be_bytes());
    b[46..48].copy_from_slice(&(ks as u16).to_be_bytes());
    b[48..48 + ss - 1].copy_from_slice(SUBSYSTEM);
    b[48 + ss..n - 1].copy_from_slice(kind.key());
    Ok(n)
}
/// Encode the same actual iterator's NEXT(limit1), not a new query.
pub fn replay_next(rid: u32, out: &mut [u8]) -> Result<usize, Error> {
    let b = prepare(out, 16, mt::PEERSTORE_ITERATE_NEXT.value())?;
    b[4..12].copy_from_slice(&1u64.to_be_bytes());
    b[12..16].copy_from_slice(&rid.to_be_bytes());
    Ok(16)
}
/// Encode actual STOP; a terminal iterator must never receive this message.
pub fn replay_stop(rid: u32, out: &mut [u8]) -> Result<usize, Error> {
    let b = prepare(out, 8, mt::PEERSTORE_ITERATE_STOP.value())?;
    b[4..8].copy_from_slice(&rid.to_be_bytes());
    Ok(8)
}
/// Encode received monotime BE8, expiry FOREVER, STOREOPTION_REPLACE1.
pub fn replay_store(
    rid: u32,
    peer: EddsaPublicKey,
    kind: ReplayKind,
    value: [u8; 8],
    out: &mut [u8],
) -> Result<usize, Error> {
    let ss = SUBSYSTEM.len() + 1;
    let ks = kind.key().len() + 1;
    let n = 60 + ss + ks + 8;
    let b = prepare(out, n, mt::PEERSTORE_STORE.value())?;
    b[4..36].copy_from_slice(peer.as_bytes());
    b[36..44].copy_from_slice(&u64::MAX.to_be_bytes());
    b[44..48].copy_from_slice(&rid.to_be_bytes());
    b[48..52].copy_from_slice(&1u32.to_be_bytes());
    b[52..54].copy_from_slice(&(ks as u16).to_be_bytes());
    b[54..56].copy_from_slice(&8u16.to_be_bytes());
    b[56..58].copy_from_slice(&(ss as u16).to_be_bytes());
    b[60..60 + ss - 1].copy_from_slice(SUBSYSTEM);
    b[60 + ss..60 + ss + ks - 1].copy_from_slice(kind.key());
    b[n - 8..].copy_from_slice(&value);
    Ok(n)
}
/// Borrowed exact PEERSTORE result. Parsing grants no callback ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Peerstore<'a> {
    /// Record(rid, claimedpeer, subsystem, key, value).
    Record(u32, EddsaPublicKey, &'a [u8], &'a [u8], &'a [u8]),
    /// Terminal iteration(rid, original result); it invalidates the iterator.
    End(u32, i32),
    /// Store continuation(rid, original result).
    Stored(u32, i32),
    /// MQ has no registered handler for this type.
    Unknown(u16),
}
impl<'a> Peerstore<'a> {
    /// Validate complete registered layouts and string extents before borrowing.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let kind = frame(input)?;
        if kind == mt::PEERSTORE_ITERATE_END.value() || kind == mt::PEERSTORE_STORE_RESULT.value() {
            if input.len() != 12 {
                return Err(Error::Malformed);
            }
            let rid = u32at(input, 4)?;
            let status = u32at(input, 8)? as i32;
            return Ok(if kind == mt::PEERSTORE_ITERATE_END.value() {
                Self::End(rid, status)
            } else {
                Self::Stored(rid, status)
            });
        }
        if kind != mt::PEERSTORE_RECORD.value() {
            return Ok(Self::Unknown(kind));
        }
        if input.len() < 60 {
            return Err(Error::Truncated);
        }
        let ks = u16at(input, 52)?;
        let vs = u16at(input, 54)?;
        let ss = u16at(input, 56)?;
        if 60 + ss + ks + vs != input.len() {
            return Err(Error::Malformed);
        }
        let sub = if ss == 0 {
            &[][..]
        } else {
            cstr(&input[60..60 + ss])?
        };
        let key = if ks == 0 {
            &[][..]
        } else {
            cstr(&input[60 + ss..60 + ss + ks])?
        };
        Ok(Self::Record(
            u32at(input, 44)?,
            peer(input, 4)?,
            sub,
            key,
            &input[60 + ss + ks..],
        ))
    }
}
/// Actual reliable communicator announcement, can_burst=NO, prefix tcp.
pub fn communicator_available(out: &mut [u8]) -> Result<usize, Error> {
    let b = prepare(out, 16, mt::TRANSPORT_NEW_COMMUNICATOR.value())?;
    b[4..8].copy_from_slice(&1u32.to_be_bytes());
    b[12..].copy_from_slice(b"tcp\0");
    Ok(16)
}
/// Actual source queue description. Raw network type is the host classifier result.
pub struct Queue<'a> {
    peer: EddsaPublicKey,
    qid: u32,
    network: u32,
    role: Role,
    address: &'a [u8],
}
impl<'a> Queue<'a> {
    /// Bind one actual local queue handle to its peer, numeric address and role.
    #[must_use]
    pub const fn new(
        peer: EddsaPublicKey,
        qid: u32,
        network: u32,
        role: Role,
        address: &'a [u8],
    ) -> Self {
        Self {
            peer,
            qid,
            network,
            role,
            address,
        }
    }
    /// Advertise the caller's actual finite send capacity, MTU65535 and role.
    pub fn setup(&self, capacity: u64, out: &mut [u8]) -> Result<usize, Error> {
        if capacity == 0 || capacity == u64::MAX {
            return Err(Error::InvalidInput);
        }
        let n = 64 + str_size(self.address)?;
        let b = prepare(out, n, mt::TRANSPORT_QUEUE_SETUP.value())?;
        self.attributes(b, capacity);
        b[64..n - 1].copy_from_slice(self.address);
        Ok(n)
    }
    /// Return finite additive capacity on this exact queue after a local send
    /// continuation. This is neither a remote receipt nor a new queue binding.
    pub fn update(&self, increase: u64, out: &mut [u8]) -> Result<usize, Error> {
        if increase == 0 || increase == u64::MAX {
            return Err(Error::InvalidInput);
        }
        let b = prepare(out, 64, mt::TRANSPORT_QUEUE_UPDATE.value())?;
        self.attributes(b, increase);
        Ok(64)
    }
    fn attributes(&self, b: &mut [u8], capacity: u64) {
        b[4..8].copy_from_slice(&self.qid.to_be_bytes());
        b[8..40].copy_from_slice(self.peer.as_bytes());
        b[40..44].copy_from_slice(&self.network.to_be_bytes());
        b[44..48].copy_from_slice(&65535u32.to_be_bytes());
        b[48..56].copy_from_slice(&capacity.to_be_bytes());
        b[60..64].copy_from_slice(
            &(if self.role == Role::Outbound {
                0u32
            } else {
                1u32
            })
            .to_be_bytes(),
        );
    }
    /// Remove only this original actual queue/peer pair.
    pub fn teardown(&self, out: &mut [u8]) -> Result<usize, Error> {
        let b = prepare(out, 40, mt::TRANSPORT_QUEUE_TEARDOWN.value())?;
        b[4..8].copy_from_slice(&self.qid.to_be_bytes());
        b[8..40].copy_from_slice(self.peer.as_bytes());
        Ok(40)
    }
}
/// Encode source receive with callback, opaque original native-endian fcID,4h.
/// Fixed C leaves neighbour_sender zero. This profile retains that actual field.
pub fn incoming(
    peer: EddsaPublicKey,
    flow_id: [u8; 8],
    message: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    frame(message)?;
    let n = 88usize.checked_add(message.len()).ok_or(Error::Overflow)?;
    let b = prepare(out, n, mt::TRANSPORT_INCOMING_MSG.value())?;
    b[4..8].copy_from_slice(&1u32.to_be_bytes());
    b[8..16].copy_from_slice(&flow_id);
    b[16..24].copy_from_slice(&ADDRESS_VALIDITY_US.to_be_bytes());
    b[24..56].copy_from_slice(peer.as_bytes());
    b[88..].copy_from_slice(message);
    Ok(n)
}
/// Actual transport request/callback, with opaque wire IDs retained for replies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Transport<'a> {
    /// Peer asks to create an outbound queue (opaque requestID,peer,address).
    Create([u8; 4], EddsaPublicKey, &'a [u8]),
    /// Actual queued send(qid,opaque mid,peer,complete inner message).
    Send(u32, [u8; 8], EddsaPublicKey, &'a [u8]),
    /// Actual incoming-message completion(opaque fcID,peer).
    Received([u8; 8], EddsaPublicKey),
    /// Official backchannel envelope(peer,complete inner message).
    Backchannel(EddsaPublicKey, &'a [u8]),
    /// Registered burst command(peer,rtt microseconds,address); TCP has no handler.
    Burst(EddsaPublicKey, u64, &'a [u8]),
    /// Unregistered MQ type; silently ignored by fixed library dispatcher.
    Unknown(u16),
}
impl<'a> Transport<'a> {
    /// Validate exact registered fixed/boxed/string framing. No transport admission.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let k = frame(input)?;
        if k == mt::TRANSPORT_QUEUE_CREATE.value() {
            if input.len() < 41 {
                return Err(Error::Truncated);
            }
            return Ok(Self::Create(
                input[4..8].try_into().map_err(|_| Error::Truncated)?,
                peer(input, 8)?,
                cstr(&input[40..])?,
            ));
        }
        if k == mt::TRANSPORT_SEND_MSG.value() {
            if input.len() < 52 {
                return Err(Error::Truncated);
            }
            frame(&input[48..])?;
            return Ok(Self::Send(
                u32at(input, 4)?,
                input[8..16].try_into().map_err(|_| Error::Truncated)?,
                peer(input, 16)?,
                &input[48..],
            ));
        }
        if k == mt::TRANSPORT_INCOMING_MSG_ACK.value() {
            if input.len() != 48 {
                return Err(Error::Malformed);
            }
            return Ok(Self::Received(
                input[8..16].try_into().map_err(|_| Error::Malformed)?,
                peer(input, 16)?,
            ));
        }
        if k == mt::TRANSPORT_COMMUNICATOR_BACKCHANNEL_INCOMING.value() {
            if input.len() < 44 {
                return Err(Error::Truncated);
            }
            frame(&input[40..])?;
            return Ok(Self::Backchannel(peer(input, 8)?, &input[40..]));
        }
        if k == mt::TRANSPORT_START_BURST.value() {
            if input.len() < 45 {
                return Err(Error::Truncated);
            }
            return Ok(Self::Burst(
                peer(input, 4)?,
                u64::from_be_bytes(input[36..44].try_into().map_err(|_| Error::Truncated)?),
                cstr(&input[44..])?,
            ));
        }
        Ok(Self::Unknown(k))
    }
}
/// Reply to an original CREATE request. Accepted means real connect admission,
/// never authenticated readiness or successful connection establishment.
pub fn create_result(id: [u8; 4], accepted: bool, out: &mut [u8]) -> Result<usize, Error> {
    let b = prepare(
        out,
        8,
        if accepted {
            mt::TRANSPORT_QUEUE_CREATE_OK.value()
        } else {
            mt::TRANSPORT_QUEUE_CREATE_FAIL.value()
        },
    )?;
    b[4..8].copy_from_slice(&id);
    Ok(8)
}
/// Reply only after the actual MQ send continuation. qid/mid remain original bytes.
pub fn sent_result(
    qid: [u8; 4],
    mid: [u8; 8],
    peer: EddsaPublicKey,
    status: i32,
    out: &mut [u8],
) -> Result<usize, Error> {
    let b = prepare(out, 52, mt::TRANSPORT_SEND_MSG_ACK.value())?;
    b[4..8].copy_from_slice(&status.to_be_bytes());
    b[8..16].copy_from_slice(&mid);
    b[16..20].copy_from_slice(&qid);
    b[20..52].copy_from_slice(peer.as_bytes());
    Ok(52)
}
/// Source add-address message. C currently leaves transmitted aid zero even though
/// its local identifier increments; this precise discrepancy remains explicit.
pub fn address_add(
    address: &[u8],
    network: u32,
    lifetime: u64,
    out: &mut [u8],
) -> Result<usize, Error> {
    let n = 20 + str_size(address)?;
    let b = prepare(out, n, mt::TRANSPORT_ADD_ADDRESS.value())?;
    b[8..16].copy_from_slice(&lifetime.to_be_bytes());
    b[16..20].copy_from_slice(&network.to_be_bytes());
    b[20..n - 1].copy_from_slice(address);
    Ok(n)
}
/// Encode one caller-owned official address id. This uses the same public
/// layout while preserving that id for the original MQ's later withdrawal.
pub fn address_add_owned(
    id: u32,
    address: &[u8],
    network: u32,
    lifetime: u64,
    out: &mut [u8],
) -> Result<usize, Error> {
    let n = address_add(address, network, lifetime, out)?;
    out[4..8].copy_from_slice(&id.to_be_bytes());
    Ok(n)
}
/// Delete an actual address using its original local identifier.
pub fn address_remove(id: u32, out: &mut [u8]) -> Result<usize, Error> {
    let b = prepare(out, 8, mt::TRANSPORT_DEL_ADDRESS.value())?;
    b[4..8].copy_from_slice(&id.to_be_bytes());
    Ok(8)
}
/// Exact PILS peer update envelope. HELLO signature/identity still require checking.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pils<'a> {
    hash: [u8; 64],
    block: &'a [u8],
}
impl<'a> Pils<'a> {
    /// Parse the registered peer-id message; unrelated types return Unsupported.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        if frame(input)? != mt::PILS_PEER_ID.value() {
            return Err(Error::Unsupported);
        }
        if input.len() < 72 {
            return Err(Error::Truncated);
        }
        if u32at(input, 68)? as usize != input.len() - 72 {
            return Err(Error::Malformed);
        }
        Ok(Self {
            hash: input[4..68].try_into().map_err(|_| Error::Truncated)?,
            block: &input[72..],
        })
    }
    /// Actual announced address hash, used by the source's key derivation.
    #[must_use]
    pub const fn hash(self) -> [u8; 64] {
        self.hash
    }
    /// Borrow the exact HELLO block, not an invented standalone peer field.
    #[must_use]
    pub const fn block(self) -> &'a [u8] {
        self.block
    }
    /// Derive one complete source key ring; the caller verifies its public
    /// identity against the actual PILS HELLO before publishing it to sessions.
    pub fn key_ring(self, seed: &[u8; 32]) -> Result<crate::session::KeyRing, Error> {
        let prk = gnunet_session_crypto::hkdf_extract(&self.hash, &[seed]);
        let mut key = zeroize::Zeroizing::new([0; 32]);
        prk.expand(&[b"gnunet-pils-ephemeral-peer-key"], key.as_mut())?;
        Ok(crate::session::KeyRing::from_seed(*key))
    }
    /// Derive the active key from the actual stored32-byte IKM and announced hash.
    /// Caller must verify the HELLO signature and matching public key before use.
    pub fn derive(self, seed: &[u8; 32]) -> Result<gnunet_crypto::EddsaPrivateKey, Error> {
        let prk = gnunet_session_crypto::hkdf_extract(&self.hash, &[seed]);
        let mut key = zeroize::Zeroizing::new([0; 32]);
        prk.expand(&[b"gnunet-pils-ephemeral-peer-key"], key.as_mut())?;
        Ok(gnunet_crypto::EddsaPrivateKey::from_seed(*key))
    }
}
