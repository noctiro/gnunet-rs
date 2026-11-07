//! Exact active TNG network framing from v0.29.1 production TRANSPORT handlers.
use gnunet_crypto::{EddsaPublicKey, EddsaSignature};
use gnunet_types::Error;
use gnunet_wire::official::Frame;
use gnunet_wire::official::{MessageHeader, MessageType};

/// Validation signature purpose in the official GANA purpose registry.
pub const CHALLENGE_PURPOSE: u32 = 35;
/// Default per-peer flow-control window, in bytes.
pub const DEFAULT_WINDOW: u64 = 128 * 1024;
/// Maximum accepted address validity, matching the service's one-month bound.
pub const MAX_VALIDITY: u64 = 30 * 24 * 60 * 60 * 1_000_000;
/// Local validation lifetime cap before renewed reachability proof.
pub const VALIDATION_INTERVAL: u64 = 4 * 60 * 60 * 1_000_000;

pub(crate) fn bytes<const N: usize>(input: &[u8], offset: usize) -> Result<[u8; N], Error> {
    input
        .get(offset..offset.checked_add(N).ok_or(Error::Overflow)?)
        .ok_or(Error::Truncated)?
        .try_into()
        .map_err(|_| Error::Truncated)
}
pub(crate) fn u32_at(input: &[u8], offset: usize) -> Result<u32, Error> {
    Ok(u32::from_be_bytes(bytes(input, offset)?))
}
pub(crate) fn u64_at(input: &[u8], offset: usize) -> Result<u64, Error> {
    Ok(u64::from_be_bytes(bytes(input, offset)?))
}
pub(crate) fn header(out: &mut [u8], kind: u16, size: usize) -> Result<(), Error> {
    if out.len() < size {
        return Err(Error::Capacity);
    }
    MessageHeader::from_total_size(MessageType::new(kind), size)?.encode(out)?;
    Ok(())
}
fn exact(input: &[u8], kind: u16, size: usize) -> Result<(), Error> {
    let f = Frame::decode(input)?;
    if input.len() != size || f.header().message_type().value() != kind {
        return Err(Error::Malformed);
    }
    Ok(())
}

/// Current 48-byte unicast address challenge (1303), with no private fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Challenge {
    /// Fresh challenge value bound to the actual peer and reachable queue.
    pub nonce: [u8; 32],
    /// Originator's monotonic timestamp, echoed verbatim by the responder.
    pub origin: u64,
}
impl Challenge {
    /// Check the complete exact frame and reserved field.
    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        exact(input, 1303, 48)?;
        if u32_at(input, 4)? != 0 {
            return Err(Error::Malformed);
        }
        Ok(Self {
            nonce: bytes(input, 8)?,
            origin: u64_at(input, 40)?,
        })
    }
    /// Encode exactly the official network representation.
    pub fn encode(self) -> [u8; 48] {
        let mut out = [0; 48];
        out[..4].copy_from_slice(&[0, 48, 5, 23]);
        out[8..40].copy_from_slice(&self.nonce);
        out[40..48].copy_from_slice(&self.origin.to_be_bytes());
        out
    }
}
/// Address validation response (1304), authenticated by the challenged identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Validation {
    /// Signature of purpose35, validity and the challenge; origin is only echoed.
    pub signature: [u8; 64],
    /// Original challenge nonce.
    pub nonce: [u8; 32],
    /// Original timestamp, which must be in the pending challenge interval.
    pub origin: u64,
    /// Relative, bounded validity in microseconds.
    pub validity: u64,
}
impl Validation {
    /// Decode one exact response, rejecting a nonzero reserved field.
    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        exact(input, 1304, 120)?;
        if u32_at(input, 4)? != 0 {
            return Err(Error::Malformed);
        }
        Ok(Self {
            signature: bytes(input, 8)?,
            nonce: bytes(input, 72)?,
            origin: u64_at(input, 104)?,
            validity: u64_at(input, 112)?,
        })
    }
    /// Construct the exact 48-byte signed purpose region, not a hashed envelope.
    pub fn signed_region(nonce: &[u8; 32], validity: u64) -> [u8; 48] {
        let mut out = [0; 48];
        out[..4].copy_from_slice(&48u32.to_be_bytes());
        out[4..8].copy_from_slice(&CHALLENGE_PURPOSE.to_be_bytes());
        out[8..16].copy_from_slice(&validity.to_be_bytes());
        out[16..48].copy_from_slice(nonce);
        out
    }
    /// Verify only the signature; the engine checks peer/nonce/time/lifecycle.
    pub fn verify(self, peer: [u8; 32]) -> Result<(), Error> {
        EddsaPublicKey::from_bytes(peer).verify(
            CHALLENGE_PURPOSE,
            &Self::signed_region(&self.nonce, self.validity),
            &EddsaSignature::from_bytes(self.signature),
        )
    }
    /// Encode exactly the official response.
    pub fn encode(self) -> [u8; 120] {
        let mut out = [0; 120];
        out[..4].copy_from_slice(&[0, 120, 5, 24]);
        out[8..72].copy_from_slice(&self.signature);
        out[72..104].copy_from_slice(&self.nonce);
        out[104..112].copy_from_slice(&self.origin.to_be_bytes());
        out[112..120].copy_from_slice(&self.validity.to_be_bytes());
        out
    }
}
/// The fixed 60-byte flow-control prefix; address entries are separately checked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Flow {
    /// Counter that permits detecting a sender restart.
    pub sequence: u32,
    /// Absolute cumulative inbound byte window offered to this peer.
    pub inbound_window: u64,
    /// Cumulative bytes sent by this peer.
    pub outbound_sent: u64,
    /// Latest outbound window seen by this peer.
    pub outbound_window: u64,
    /// Strict sender-monotonic timestamp used for stale update rejection.
    pub sender_time: u64,
    /// Peer-estimated round-trip time in microseconds.
    pub rtt: u64,
    /// Whether the sender is ready for NAT burst synchronization.
    pub sync_ready: bool,
}
impl Flow {
    /// Parse fixed fields and every variable address entry before accepting any.
    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        let f = Frame::decode(input)?;
        if f.header().message_type().value() != 1221 || input.len() < 60 {
            return Err(Error::Malformed);
        }
        let count = u32_at(input, 52)?;
        let total = u32_at(input, 56)? as usize;
        let mut offset = 60usize;
        let mut actual = 0usize;
        for _ in 0..count {
            let length = u32_at(input, offset)? as usize;
            offset = offset
                .checked_add(4)
                .and_then(|v| v.checked_add(length))
                .ok_or(Error::Overflow)?;
            if offset > input.len() {
                return Err(Error::Truncated);
            }
            actual = actual.checked_add(length).ok_or(Error::Overflow)?;
        }
        if offset != input.len() || total != actual || u32_at(input, 48)? > 1 {
            return Err(Error::Malformed);
        }
        Ok(Self {
            sequence: u32_at(input, 4)?,
            inbound_window: u64_at(input, 8)?,
            outbound_sent: u64_at(input, 16)?,
            outbound_window: u64_at(input, 24)?,
            sender_time: u64_at(input, 32)?,
            rtt: u64_at(input, 40)?,
            sync_ready: u32_at(input, 48)? == 1,
        })
    }
    /// Encode a flow update without address advertisements.
    pub fn encode(self) -> [u8; 60] {
        let mut out = [0; 60];
        out[..4].copy_from_slice(&[0, 60, 4, 197]);
        out[4..8].copy_from_slice(&self.sequence.to_be_bytes());
        for (offset, value) in [
            (8, self.inbound_window),
            (16, self.outbound_sent),
            (24, self.outbound_window),
            (32, self.sender_time),
            (40, self.rtt),
        ] {
            out[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        }
        out[48..52].copy_from_slice(&u32::from(self.sync_ready).to_be_bytes());
        out
    }
}
/// One complete reliability envelope with the UUID of this transmission attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reliable<'a> {
    /// Maximum messages until immediate cumulative acknowledgement.
    pub countdown: u32,
    /// Opaque per-attempt acknowledgement UUID.
    pub uuid: [u8; 16],
    /// Exactly one nested official frame.
    pub message: &'a [u8],
}
impl<'a> Reliable<'a> {
    /// Encode the exact24-byte official wrapper around one complete frame.
    /// A zero countdown requests an immediate remote acknowledgement.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        Frame::decode(self.message)?;
        let size = 24usize
            .checked_add(self.message.len())
            .ok_or(Error::Overflow)?;
        if size > usize::from(u16::MAX) {
            return Err(Error::TooLarge);
        }
        if output.len() < size {
            return Err(Error::Capacity);
        }
        header(output, 1216, size)?;
        output[4..8].copy_from_slice(&self.countdown.to_be_bytes());
        output[8..24].copy_from_slice(&self.uuid);
        output[24..size].copy_from_slice(self.message);
        Ok(size)
    }
    /// Decode and validate the complete nested frame.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let f = Frame::decode(input)?;
        if f.header().message_type().value() != 1216 {
            return Err(Error::Malformed);
        }
        let message = input.get(24..).ok_or(Error::Truncated)?;
        Frame::decode(message)?;
        Ok(Self {
            countdown: u32_at(input, 4)?,
            uuid: bytes(input, 8)?,
            message,
        })
    }
}
/// One fragment; the reassembler must check overlap, capacity and replay state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fragment<'a> {
    /// Offset into the complete original frame.
    pub offset: u16,
    /// Complete original frame length, including its header.
    pub total: u16,
    /// Fresh transmission attempt identifier.
    pub ack: [u8; 16],
    /// Stable original-message identifier across all fragment attempts.
    pub message_id: [u8; 8],
    /// Fragment bytes, not necessarily a complete frame by themselves.
    pub body: &'a [u8],
}
impl<'a> Fragment<'a> {
    /// Encode one exact official fragment without allocating or changing IDs.
    /// The fragment body is a slice of the original frame, not a nested envelope.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let size = 32usize
            .checked_add(self.body.len())
            .ok_or(Error::Overflow)?;
        if self.total < 4
            || self.body.is_empty()
            || usize::from(self.offset)
                .checked_add(self.body.len())
                .ok_or(Error::Overflow)?
                > usize::from(self.total)
        {
            return Err(Error::Malformed);
        }
        if output.len() < size {
            return Err(Error::Capacity);
        }
        header(output, 1214, size)?;
        output[4..6].copy_from_slice(&self.offset.to_be_bytes());
        output[6..8].copy_from_slice(&self.total.to_be_bytes());
        output[8..24].copy_from_slice(&self.ack);
        output[24..32].copy_from_slice(&self.message_id);
        output[32..size].copy_from_slice(self.body);
        Ok(size)
    }
    /// Validate nonempty bounded fragment bytes before reassembly.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let f = Frame::decode(input)?;
        if f.header().message_type().value() != 1214 {
            return Err(Error::Malformed);
        }
        let offset = u16::from_be_bytes(bytes(input, 4)?);
        let total = u16::from_be_bytes(bytes(input, 6)?);
        let body = input.get(32..).ok_or(Error::Truncated)?;
        if total < 4
            || body.is_empty()
            || usize::from(offset)
                .checked_add(body.len())
                .ok_or(Error::Overflow)?
                > usize::from(total)
        {
            return Err(Error::Malformed);
        }
        Ok(Self {
            offset,
            total,
            ack: bytes(input, 8)?,
            message_id: bytes(input, 24)?,
            body,
        })
    }
}
/// Maximum nonempty24-byte ACK entries fitting an official u16-sized frame.
/// This is a wire extent, independent of the sender's smaller batching policy.
pub const MAX_ACKNOWLEDGEMENTS: usize = (u16::MAX as usize - 8) / 24;
/// Check every cumulative reliability acknowledgement and return its entries.
pub fn acknowledgements(input: &[u8]) -> Result<impl Iterator<Item = (u64, [u8; 16])> + '_, Error> {
    let f = Frame::decode(input)?;
    if f.header().message_type().value() != 1217
        || input.len() < 32
        || !(input.len() - 8).is_multiple_of(24)
        || (input.len() - 8) / 24 > MAX_ACKNOWLEDGEMENTS
    {
        return Err(Error::Malformed);
    }
    Ok(input[8..].as_chunks::<24>().0.iter().map(|entry| {
        let mut delay = [0; 8];
        delay.copy_from_slice(&entry[..8]);
        let mut uuid = [0; 16];
        uuid.copy_from_slice(&entry[8..24]);
        (u64::from_be_bytes(delay), uuid)
    }))
}

/// Encode a nonempty bounded official cumulative ACK with caller-owned IDs.
/// Acknowledgements signal receipt of transmission attempts, never CORE delivery.
pub fn encode_acknowledgements(
    counter: u32,
    entries: &[(u64, [u8; 16])],
    output: &mut [u8],
) -> Result<usize, Error> {
    if entries.is_empty() {
        return Err(Error::Malformed);
    }
    if entries.len() > MAX_ACKNOWLEDGEMENTS {
        return Err(Error::TooLarge);
    }
    let size = 8 + entries.len() * 24;
    if output.len() < size {
        return Err(Error::Capacity);
    }
    header(output, 1217, size)?;
    output[4..8].copy_from_slice(&counter.to_be_bytes());
    for (slot, (delay, id)) in output[8..size]
        .as_chunks_mut::<24>()
        .0
        .iter_mut()
        .zip(entries)
    {
        slot[..8].copy_from_slice(&delay.to_be_bytes());
        slot[8..].copy_from_slice(id);
    }
    Ok(size)
}

/// Official direct backchannel1213: message then a terminated communicator name.
/// The enclosing authenticated communicator supplies the sender identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Backchannel<'a> {
    /// Complete nested communicator message, not a Transport data payload.
    pub message: &'a [u8],
    /// First target byte string, without its NUL. Prefixes need not be UTF-8;
    /// encoding requires a canonical NUL-free slice.
    pub communicator: &'a [u8],
}
pub(crate) fn backchannel_fields(input: &[u8], offset: usize) -> Result<Backchannel<'_>, Error> {
    let rest = input.get(offset..).ok_or(Error::Truncated)?;
    let h = rest.get(..4).ok_or(Error::Truncated)?;
    let n = usize::from(u16::from_be_bytes([h[0], h[1]]));
    if n < 4 || n >= rest.len() {
        return Err(Error::Malformed);
    }
    Frame::decode(&rest[..n])?;
    let name = &rest[n..];
    // The reference check_backchannel_encapsulation requires a final NUL,
    // then its handler compares the first C byte string. Interior NUL suffixes
    // and non-UTF8 prefix bytes are not authentication or format failures.
    if name.last() != Some(&0) {
        return Err(Error::Malformed);
    }
    let end = name.iter().position(|b| *b == 0).ok_or(Error::Malformed)?;
    let communicator = &name[..end];
    Ok(Backchannel {
        message: &rest[..n],
        communicator,
    })
}
impl<'a> Backchannel<'a> {
    /// Decode one complete official network envelope, with no private fields.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        if Frame::decode(input)?.header().message_type().value() != 1213 {
            return Err(Error::Malformed);
        }
        backchannel_fields(input, 4)
    }
    /// Emit exactly header4, nested frame and terminated target prefix.
    /// All structure/length/capacity checks precede output mutation.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        Frame::decode(self.message)?;
        if self.communicator.contains(&0) {
            return Err(Error::Malformed);
        }
        let n = 4usize
            .checked_add(self.message.len())
            .and_then(|n| n.checked_add(self.communicator.len()))
            .and_then(|n| n.checked_add(1))
            .ok_or(Error::Overflow)?;
        if n > u16::MAX as usize {
            return Err(Error::TooLarge);
        }
        if out.len() < n {
            return Err(Error::Capacity);
        }
        header(out, 1213, n)?;
        let end = 4 + self.message.len();
        out[4..end].copy_from_slice(self.message);
        out[end..n - 1].copy_from_slice(self.communicator);
        out[n - 1] = 0;
        Ok(n)
    }
}
