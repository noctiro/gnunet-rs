//! Official distance-vector learning and box framing. Structural parsing never
//! authenticates a peer or ciphertext. Real signature checks are explicit.
use crate::{PeerId, p2p};
use gnunet_crypto::{EddsaPublicKey, EddsaSignature};
use gnunet_types::Error;
use gnunet_wire::official::Frame;

pub mod routes;
/// Official TRANSPORT_DV_LEARN message type.
pub const LEARN_TYPE: u16 = 1218;
/// Official TRANSPORT_DV_BOX message type.
pub const BOX_TYPE: u16 = 1219;
/// Maximum declared hops in either official DV envelope.
pub const MAX_HOPS: usize = 16;
/// Header, counters, delay, signed stamp, initiator signature/identity and nonce.
pub const LEARN_PREFIX: usize = 152;
/// One public identity and its EdDSA hop signature.
pub const HOP_BYTES: usize = 96;
/// Header/counters, encapsulation32, XChaCha nonce24, detached tag16 and orig_size.
pub const BOX_PREFIX: usize = 86;
/// Decrypted sender32, signature64 and source-monotonic stamp8, before the frame.
pub const PAYLOAD_PREFIX: usize = 104;
/// Purpose of the immutable initiator/challenge statement.
pub const INIT_PURPOSE: u32 = 37;
/// Purpose of one predecessor/successor/challenge statement.
pub const HOP_PURPOSE: u32 = 36;
/// Purpose binding a source, target and actual ephemeral encapsulation.
pub const EPHEMERAL_PURPOSE: u32 = 30;

fn u16_at(input: &[u8], at: usize) -> Result<u16, Error> {
    Ok(u16::from_be_bytes(p2p::bytes(input, at)?))
}
fn frame(input: &[u8], kind: u16, minimum: usize) -> Result<(), Error> {
    let parsed = Frame::decode(input)?;
    if parsed.header().message_type().value() != kind || input.len() < minimum {
        return Err(Error::Malformed);
    }
    Ok(())
}
fn purpose<const N: usize>(kind: u32) -> [u8; N] {
    let mut out = [0; N];
    out[..4].copy_from_slice(&(N as u32).to_be_bytes());
    out[4..8].copy_from_slice(&kind.to_be_bytes());
    out
}
/// Exact official48-byte statement signed by a learning initiator. The stamp
/// is a per-source monotonic value, never interpreted as recipient UTC expiry.
pub fn init_region(stamp: u64, challenge: &[u8; 32]) -> [u8; 48] {
    let mut out = purpose(INIT_PURPOSE);
    out[8..16].copy_from_slice(&stamp.to_be_bytes());
    out[16..48].copy_from_slice(challenge);
    out
}
/// Exact official104-byte statement for a single signed hop.
pub fn hop_region(previous: PeerId, next: PeerId, challenge: &[u8; 32]) -> [u8; 104] {
    let mut out = purpose(HOP_PURPOSE);
    out[8..40].copy_from_slice(&previous.0);
    out[40..72].copy_from_slice(&next.0);
    out[72..104].copy_from_slice(challenge);
    out
}
/// Exact official80-byte purpose30 statement. This is not the AEAD additional
/// data: DV ciphertext uses empty additional data in the pinned implementation.
pub fn ephemeral_region(target: PeerId, stamp: u64, encapsulation: &[u8; 32]) -> [u8; 80] {
    let mut out = purpose(EPHEMERAL_PURPOSE);
    out[8..16].copy_from_slice(&stamp.to_be_bytes());
    out[16..48].copy_from_slice(&target.0);
    out[48..80].copy_from_slice(encapsulation);
    out
}
/// One borrowed-layout public hop and its still-unverified signature.
#[derive(Clone, Copy)]
pub struct Hop {
    /// Claimed signing peer.
    pub peer: PeerId,
    /// Signature over the exact predecessor/successor/challenge statement.
    pub signature: [u8; 64],
}
/// One exact original DV learn frame. Hop records are borrowed, never allocated.
#[derive(Clone, Copy)]
pub struct Learn<'a> {
    raw: &'a [u8],
    count: u16,
}
impl core::fmt::Debug for Learn<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DvLearn")
            .field("hops", &self.count)
            .finish()
    }
}
impl<'a> Learn<'a> {
    /// Validate complete message size and the official sixteen-hop bound.
    pub fn decode(raw: &'a [u8]) -> Result<Self, Error> {
        frame(raw, LEARN_TYPE, LEARN_PREFIX)?;
        let count = u16_at(raw, 4)?;
        if usize::from(count) > MAX_HOPS
            || raw.len() != LEARN_PREFIX + usize::from(count) * HOP_BYTES
        {
            return Err(Error::Malformed);
        }
        Ok(Self { raw, count })
    }
    /// Exact original frame, including all original signatures.
    pub const fn bytes(self) -> &'a [u8] {
        self.raw
    }
    /// Number of signed hop entries, excluding the initiator and recipient.
    pub const fn hop_count(self) -> usize {
        self.count as usize
    }
    /// Raw source bidirectionality history; no flags are inferred by parsing.
    pub fn bidirectional(self) -> Result<u16, Error> {
        u16_at(self.raw, 6)
    }
    /// Accumulated non-network forwarding delay in microseconds.
    pub fn delay(self) -> Result<u64, Error> {
        p2p::u64_at(self.raw, 8)
    }
    /// Source-monotonic stamp, which is independent from local UTC.
    pub fn stamp(self) -> Result<u64, Error> {
        p2p::u64_at(self.raw, 16)
    }
    /// Claimed initiator; authenticate it with verify before route admission.
    pub fn initiator(self) -> Result<PeerId, Error> {
        Ok(PeerId(p2p::bytes(self.raw, 88)?))
    }
    /// Original public correlation nonce, not a cryptographic digest or identity.
    pub fn challenge(self) -> Result<[u8; 32], Error> {
        p2p::bytes(self.raw, 120)
    }
    /// One original fixed-width hop; index is checked before any offset use.
    pub fn hop(self, index: usize) -> Result<Hop, Error> {
        if index >= self.hop_count() {
            return Err(Error::NotFound);
        }
        let at = LEARN_PREFIX + index * HOP_BYTES;
        Ok(Hop {
            peer: PeerId(p2p::bytes(self.raw, at)?),
            signature: p2p::bytes(self.raw, at + 32)?,
        })
    }
    /// Validate recipient/sender and the original path ownership constraints.
    /// This does not grant cryptographic authentication.
    pub fn check_source(self, local: PeerId, predecessor: PeerId) -> Result<(), Error> {
        let initiator = self.initiator()?;
        if self.count == 0 {
            if predecessor != initiator || local == initiator {
                return Err(Error::Malformed);
            }
        } else if self.hop(self.hop_count() - 1)?.peer != predecessor {
            return Err(Error::Malformed);
        }
        for i in 0..self.hop_count() {
            let peer = self.hop(i)?.peer;
            if peer == initiator || peer == local {
                return Err(Error::Malformed);
            }
        }
        Ok(())
    }
    /// Verify the real initiator and every hop against the exact signed regions.
    /// This checks the initiator even when no neighbour cache entry exists.
    pub fn verify(self, local: PeerId, predecessor: PeerId) -> Result<VerifiedLearn<'a>, Error> {
        self.check_source(local, predecessor)?;
        let initiator = self.initiator()?;
        let challenge = self.challenge()?;
        EddsaPublicKey::from_bytes(initiator.0).verify(
            INIT_PURPOSE,
            &init_region(self.stamp()?, &challenge),
            &EddsaSignature::from_bytes(p2p::bytes(self.raw, 24)?),
        )?;
        for i in 0..self.hop_count() {
            let hop = self.hop(i)?;
            let previous = if i == 0 {
                initiator
            } else {
                self.hop(i - 1)?.peer
            };
            let next = if i + 1 == self.hop_count() {
                local
            } else {
                self.hop(i + 1)?.peer
            };
            EddsaPublicKey::from_bytes(hop.peer.0).verify(
                HOP_PURPOSE,
                &hop_region(previous, next, &challenge),
                &EddsaSignature::from_bytes(hop.signature),
            )?;
        }
        Ok(VerifiedLearn {
            packet: self,
            local,
            predecessor,
        })
    }
    /// Append one actual signed hop to an original packet. The caller obtains
    /// signature from its real purpose36 signer for hop_region(previous,next,...).
    /// Encoding alone is never claimed to prove that signing took place.
    pub fn forward(
        self,
        hop: Hop,
        reverse_link: bool,
        residence_micros: u64,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        if self.hop_count() >= MAX_HOPS {
            return Err(Error::TooLarge);
        }
        let size = self.raw.len() + HOP_BYTES;
        if out.len() < size {
            return Err(Error::Capacity);
        }
        p2p::header(out, LEARN_TYPE, size)?;
        out[4..6].copy_from_slice(&(self.count + 1).to_be_bytes());
        out[6..8].copy_from_slice(
            &((self.bidirectional()? << 1) | u16::from(reverse_link)).to_be_bytes(),
        );
        out[8..16].copy_from_slice(&self.delay()?.saturating_add(residence_micros).to_be_bytes());
        out[16..self.raw.len()].copy_from_slice(&self.raw[16..]);
        out[self.raw.len()..self.raw.len() + 32].copy_from_slice(&hop.peer.0);
        out[self.raw.len() + 32..size].copy_from_slice(&hop.signature);
        Ok(size)
    }
}
/// Real signature verification bound to the recipient and original predecessor.
/// Native provenance, challenge freshness and persistent replay checks are separate.
#[derive(Clone, Copy)]
pub struct VerifiedLearn<'a> {
    packet: Learn<'a>,
    local: PeerId,
    predecessor: PeerId,
}
impl<'a> VerifiedLearn<'a> {
    /// The exact authenticated original packet.
    pub const fn packet(self) -> Learn<'a> {
        self.packet
    }
    /// Recipient used as the last signature's successor.
    pub const fn local(self) -> PeerId {
        self.local
    }
    /// Original direct sender matched to the final hop.
    pub const fn predecessor(self) -> PeerId {
        self.predecessor
    }
}
/// Encode a canonical zero-hop packet using the actual caller's signature.
pub fn initiate(
    initiator: PeerId,
    stamp: u64,
    challenge: &[u8; 32],
    signature: &[u8; 64],
) -> [u8; LEARN_PREFIX] {
    let mut out = [0; LEARN_PREFIX];
    out[..2].copy_from_slice(&(LEARN_PREFIX as u16).to_be_bytes());
    out[2..4].copy_from_slice(&LEARN_TYPE.to_be_bytes());
    out[16..24].copy_from_slice(&stamp.to_be_bytes());
    out[24..88].copy_from_slice(signature);
    out[88..120].copy_from_slice(&initiator.0);
    out[120..152].copy_from_slice(challenge);
    out
}
/// Borrowed still-encrypted official DV box, with forwarding metadata separate
/// from immutable encapsulation, nonce, MAC and ciphertext.
#[derive(Clone, Copy)]
pub struct BoxPacket<'a> {
    raw: &'a [u8],
    count: u16,
    traversed: u16,
}
impl core::fmt::Debug for BoxPacket<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DvBox")
            .field("remaining_hops", &self.count)
            .field("traversed", &self.traversed)
            .finish()
    }
}
impl<'a> BoxPacket<'a> {
    /// Match current C structural bounds without using orig_size to locate the
    /// actual ciphertext. The recipient must additionally authenticate/decrypt.
    pub fn decode(raw: &'a [u8]) -> Result<Self, Error> {
        frame(raw, BOX_TYPE, BOX_PREFIX)?;
        let count = u16_at(raw, 10)?;
        let traversed = u16_at(raw, 8)?;
        let original = usize::from(u16_at(raw, 84)?);
        if usize::from(count) > MAX_HOPS
            || usize::from(traversed) > MAX_HOPS
            || raw.len() < BOX_PREFIX + usize::from(count) * 32 + 4
            || original < raw.len()
            || original < BOX_PREFIX + usize::from(traversed) * 32 + PAYLOAD_PREFIX + 4
        {
            return Err(Error::Malformed);
        }
        Ok(Self {
            raw,
            count,
            traversed,
        })
    }
    /// Complete original frame.
    pub const fn bytes(self) -> &'a [u8] {
        self.raw
    }
    /// Remaining path entries; zero means this peer is the ultimate recipient.
    pub const fn hop_count(self) -> usize {
        self.count as usize
    }
    /// Original traversal count, checked independently from remaining entries.
    pub const fn traversed(self) -> u16 {
        self.traversed
    }
    /// Preserve the C consumer's raw without-flow-control flag.
    pub fn without_fc(self) -> Result<u32, Error> {
        p2p::u32_at(self.raw, 4)
    }
    /// Immutable actual public encapsulation bytes; decoding does not validate it.
    pub fn encapsulation(self) -> Result<[u8; 32], Error> {
        p2p::bytes(self.raw, 12)
    }
    /// Immutable24-byte XChaCha20-Poly1305 nonce.
    pub fn nonce(self) -> Result<[u8; 24], Error> {
        p2p::bytes(self.raw, 44)
    }
    /// Immutable detached sixteen-byte AEAD tag.
    pub fn mac(self) -> Result<[u8; 16], Error> {
        p2p::bytes(self.raw, 68)
    }
    /// Original total frame size, never used as a ciphertext slice length.
    pub fn original_size(self) -> Result<u16, Error> {
        u16_at(self.raw, 84)
    }
    /// One original remaining peer entry.
    pub fn hop(self, index: usize) -> Result<PeerId, Error> {
        if index >= self.hop_count() {
            return Err(Error::NotFound);
        }
        Ok(PeerId(p2p::bytes(self.raw, BOX_PREFIX + index * 32)?))
    }
    /// Actual ciphertext bytes in this exact received frame.
    pub fn ciphertext(self) -> &'a [u8] {
        &self.raw[BOX_PREFIX + self.hop_count() * 32..]
    }
    /// Refuse loops before forwarding or choosing a next hop.
    pub fn check_recipient(self, local: PeerId) -> Result<(), Error> {
        for i in 0..self.hop_count() {
            if self.hop(i)? == local {
                return Err(Error::Malformed);
            }
        }
        if self.count == 0 && self.ciphertext().len() < PAYLOAD_PREFIX + 4 {
            return Err(Error::Truncated);
        }
        Ok(())
    }
    /// Find the farthest actual directly reachable next hop, without allocating a
    /// temporary path or trusting the box to authenticate that peer.
    pub fn shortcut(
        self,
        local: PeerId,
        mut reachable: impl FnMut(PeerId) -> bool,
    ) -> Result<Option<usize>, Error> {
        self.check_recipient(local)?;
        for i in (0..self.hop_count()).rev() {
            if reachable(self.hop(i)?) {
                return Ok(Some(i));
            }
        }
        Ok(None)
    }
    fn forward_layout(self, selected: usize) -> Result<(usize, u16, usize), Error> {
        if selected >= self.hop_count() {
            return Err(Error::NotFound);
        }
        let skipped = selected + 1;
        let traversed = usize::from(self.traversed)
            .checked_add(skipped)
            .ok_or(Error::Overflow)?;
        if traversed > MAX_HOPS {
            return Err(Error::TooLarge);
        }
        Ok((skipped, traversed as u16, self.raw.len() - skipped * 32))
    }
    /// Strip precisely the selected prefix and account every skipped path entry.
    /// Immutable ciphertext/encapsulation/nonce/MAC/orig_size are copied verbatim.
    pub fn forward(self, selected: usize, out: &mut [u8]) -> Result<usize, Error> {
        let (skipped, traversed, size) = self.forward_layout(selected)?;
        if out.len() < size {
            return Err(Error::Capacity);
        }
        out[..BOX_PREFIX].copy_from_slice(&self.raw[..BOX_PREFIX]);
        out[..2].copy_from_slice(&(size as u16).to_be_bytes());
        out[8..10].copy_from_slice(&traversed.to_be_bytes());
        out[10..12].copy_from_slice(&((self.hop_count() - skipped) as u16).to_be_bytes());
        out[BOX_PREFIX..size].copy_from_slice(&self.raw[BOX_PREFIX + skipped * 32..]);
        Ok(size)
    }
    /// Compact an owned received frame without a second ciphertext buffer.
    /// All structural and selected-hop checks precede the first mutation; a
    /// refusal preserves the complete input. On success only the returned prefix
    /// is the new frame, and the caller must truncate its original owned buffer.
    /// This transformation establishes no authentication or write outcome.
    pub fn forward_in_place(raw: &mut [u8], selected: usize) -> Result<usize, Error> {
        let (skipped, traversed, size, remaining) = {
            let packet = BoxPacket::decode(raw)?;
            let (skipped, traversed, size) = packet.forward_layout(selected)?;
            (skipped, traversed, size, packet.hop_count() - skipped)
        };
        raw.copy_within(BOX_PREFIX + skipped * 32.., BOX_PREFIX);
        raw[..2].copy_from_slice(&(size as u16).to_be_bytes());
        raw[8..10].copy_from_slice(&traversed.to_be_bytes());
        raw[10..12].copy_from_slice(&(remaining as u16).to_be_bytes());
        Ok(size)
    }
}
/// Exact box construction parameters. Key generation, KEM and AEAD are performed
/// by the real caller provider before serialization, never by a fake wire helper.
pub struct BoxHeader {
    /// Control messages may bypass the ordinary flow-control byte window.
    pub without_fc: bool,
    /// Actual public encapsulation from the original real KEM operation.
    pub encapsulation: [u8; 32],
    /// Actual unique XChaCha nonce chosen by the provider.
    pub nonce: [u8; 24],
    /// Actual detached AEAD tag for the ciphertext.
    pub mac: [u8; 16],
}
impl BoxHeader {
    /// Encode a canonical original box. Route excludes this source and the first
    /// direct receiver, and includes the ultimate target. Inputs are not authenticated.
    pub fn encode(
        &self,
        route: &[PeerId],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        if route.len() > MAX_HOPS || ciphertext.len() < PAYLOAD_PREFIX + 4 {
            return Err(Error::InvalidInput);
        }
        let size = BOX_PREFIX
            .checked_add(route.len() * 32)
            .and_then(|n| n.checked_add(ciphertext.len()))
            .ok_or(Error::Overflow)?;
        if size > u16::MAX as usize {
            return Err(Error::TooLarge);
        }
        if out.len() < size {
            return Err(Error::Capacity);
        }
        p2p::header(out, BOX_TYPE, size)?;
        out[4..8].copy_from_slice(&u32::from(self.without_fc).to_be_bytes());
        out[8..10].fill(0);
        out[10..12].copy_from_slice(&(route.len() as u16).to_be_bytes());
        out[12..44].copy_from_slice(&self.encapsulation);
        out[44..68].copy_from_slice(&self.nonce);
        out[68..84].copy_from_slice(&self.mac);
        out[84..86].copy_from_slice(&(size as u16).to_be_bytes());
        for (i, peer) in route.iter().enumerate() {
            out[BOX_PREFIX + i * 32..BOX_PREFIX + (i + 1) * 32].copy_from_slice(&peer.0);
        }
        out[BOX_PREFIX + route.len() * 32..size].copy_from_slice(ciphertext);
        Ok(size)
    }
}
/// Still-untrusted plaintext view after a caller decodes/decrypts a buffer. Only
/// the real AEAD provider can establish payload authenticity; signature verification
/// below separately binds source/target/encapsulation, not arbitrary plaintext.
#[derive(Clone, Copy)]
pub struct Plaintext<'a> {
    raw: &'a [u8],
}
impl<'a> Plaintext<'a> {
    /// Parse exact plaintext and refuse nested DV boxes/learn packets.
    pub fn decode(raw: &'a [u8]) -> Result<Self, Error> {
        if raw.len() < PAYLOAD_PREFIX + 4 {
            return Err(Error::Truncated);
        }
        let inner = Frame::decode(&raw[PAYLOAD_PREFIX..])?;
        if matches!(inner.header().message_type().value(), LEARN_TYPE | BOX_TYPE) {
            return Err(Error::Malformed);
        }
        Ok(Self { raw })
    }
    /// Claimed source, not yet authenticated by this structural operation.
    pub fn sender(self) -> Result<PeerId, Error> {
        Ok(PeerId(p2p::bytes(self.raw, 0)?))
    }
    /// Source-monotonic replay value, never local UTC.
    pub fn stamp(self) -> Result<u64, Error> {
        p2p::u64_at(self.raw, 96)
    }
    /// Exact original inner frame.
    pub fn message(self) -> &'a [u8] {
        &self.raw[PAYLOAD_PREFIX..]
    }
    /// Real purpose30 signature verification. AEAD must be independently successful
    /// before a caller attributes message() to this source.
    pub fn verify_signature(self, target: PeerId, encapsulation: &[u8; 32]) -> Result<(), Error> {
        EddsaPublicKey::from_bytes(self.sender()?.0).verify(
            EPHEMERAL_PURPOSE,
            &ephemeral_region(target, self.stamp()?, encapsulation),
            &EddsaSignature::from_bytes(p2p::bytes(self.raw, 32)?),
        )
    }
}
/// Serialize actual signed sender metadata with one original, non-nested frame.
/// This function provides no encryption or authentication receipt.
pub fn encode_plaintext(
    sender: PeerId,
    stamp: u64,
    signature: &[u8; 64],
    message: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    let inner = Frame::decode(message)?;
    if matches!(inner.header().message_type().value(), LEARN_TYPE | BOX_TYPE) {
        return Err(Error::Malformed);
    }
    let size = PAYLOAD_PREFIX
        .checked_add(message.len())
        .ok_or(Error::Overflow)?;
    if out.len() < size {
        return Err(Error::Capacity);
    }
    out[..32].copy_from_slice(&sender.0);
    out[32..96].copy_from_slice(signature);
    out[96..104].copy_from_slice(&stamp.to_be_bytes());
    out[104..size].copy_from_slice(message);
    Ok(size)
}

#[cfg(test)]
mod in_place_tests {
    use super::*;

    fn check(condition: bool) -> Result<(), Error> {
        if condition {
            Ok(())
        } else {
            Err(Error::Conflict)
        }
    }

    // Opaque standard wire fixtures exercise framing only. Encoding these
    // bytes supplies no KEM, AEAD, sender identity or authenticated delivery.
    fn received() -> Result<([u8; 1024], usize), Error> {
        let mut raw = [0; 1024];
        let route = [PeerId([2; 32]), PeerId([3; 32]), PeerId([4; 32])];
        let size = BoxHeader {
            without_fc: true,
            encapsulation: [0x31; 32],
            nonce: [0x42; 24],
            mac: [0x53; 16],
        }
        .encode(&route, &[0x64; 600], &mut raw)?;
        Ok((raw, size))
    }

    #[test]
    fn in_place_matches_copying_forward_and_preserves_opaque_fields() -> Result<(), Error> {
        let (original, len) = received()?;
        for selected in 0..3 {
            let mut expected = [0; 1024];
            let size = BoxPacket::decode(&original[..len])?.forward(selected, &mut expected)?;
            let mut owned = original;
            let address = owned.as_ptr();
            let compacted = BoxPacket::forward_in_place(&mut owned[..len], selected)?;
            check(compacted == size && owned.as_ptr() == address)?;
            check(owned[..size] == expected[..size])?;
            let packet = BoxPacket::decode(&owned[..size])?;
            check(
                packet.hop_count() == 2 - selected && packet.traversed() == (selected + 1) as u16,
            )?;
            check(packet.ciphertext() == [0x64; 600])?;
            check(owned[4..8] == original[4..8] && owned[12..86] == original[12..86])?;
        }
        Ok(())
    }

    #[test]
    fn in_place_refusal_keeps_the_complete_original_frame() -> Result<(), Error> {
        let (original, len) = received()?;
        let mut owned = original;
        check(BoxPacket::forward_in_place(&mut owned[..len], 3) == Err(Error::NotFound))?;
        check(owned == original)?;
        // This remains structurally decodable, but skipping two further hops
        // would exceed the official traversal limit. Nothing may be compacted.
        owned[8..10].copy_from_slice(&15u16.to_be_bytes());
        let overflowing = owned;
        BoxPacket::decode(&owned[..len])?;
        check(BoxPacket::forward_in_place(&mut owned[..len], 1) == Err(Error::TooLarge))?;
        check(owned == overflowing)?;
        owned[2..4].copy_from_slice(&0u16.to_be_bytes());
        let malformed = owned;
        check(BoxPacket::forward_in_place(&mut owned[..len], 0) == Err(Error::Malformed))?;
        check(owned == malformed)
    }
}
