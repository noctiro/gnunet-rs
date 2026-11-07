//! Official DNS advertisement and DNS-over-CADET application frames.
use gnunet_crypto::{EddsaPublicKey, EddsaSignature, hash512};
use gnunet_types::Error;
use gnunet_wire::official::{Frame, MessageHeader, message_type as mt};
/// Exact signed DNS advertisement length: signature64+purpose8+expiry8+peer32.
pub const ADVERTISEMENT_BYTES: usize = 112;
/// Public signed purpose GNUNET_SIGNATURE_PURPOSE_DNS_RECORD.
pub const PURPOSE: u32 = 11;
/// Official GNUNET_BLOCK_TYPE_DNS.
pub const BLOCK_TYPE: u32 = 10;
/// Well-known CADET logical port input, without a terminating NUL.
pub const PORT: &[u8] = b"exit-dns";
/// The complete checked public advertisement. No private key is carried.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Advertisement {
    peer: [u8; 32],
    expires: u64,
}
impl Advertisement {
    /// Exact public purpose region submitted to the real peer-identity signer.
    /// The caller must supply an independently checked, finite live expiration.
    pub fn signed_region(peer: [u8; 32], expires: u64) -> [u8; 48] {
        let mut region = [0; 48];
        region[..4].copy_from_slice(&48u32.to_be_bytes());
        region[4..8].copy_from_slice(&PURPOSE.to_be_bytes());
        region[8..16].copy_from_slice(&expires.to_be_bytes());
        region[16..].copy_from_slice(&peer);
        region
    }
    /// Assemble and independently verify the actual public signature over the
    /// original peer/expiration before allowing a DNS advertisement to escape.
    pub fn encode_signed(
        peer: [u8; 32],
        expires: u64,
        signature: &[u8; 64],
        now: u64,
    ) -> Result<[u8; ADVERTISEMENT_BYTES], Error> {
        if expires == u64::MAX || expires <= now {
            return Err(Error::Deadline);
        }
        let mut block = [0; ADVERTISEMENT_BYTES];
        block[..64].copy_from_slice(signature);
        block[64..].copy_from_slice(&Self::signed_region(peer, expires));
        Self::verify(&block, now)?;
        Ok(block)
    }
    /// Verify exact official purpose size/signature and live absolute expiration.
    /// This is public peer-service authentication, not an availability proof.
    pub fn verify(bytes: &[u8], now: u64) -> Result<Self, Error> {
        if bytes.len() != ADVERTISEMENT_BYTES {
            return Err(Error::Malformed);
        }
        let peer = bytes[80..112].try_into().map_err(|_| Error::Truncated)?;
        let expires = u64::from_be_bytes(bytes[72..80].try_into().map_err(|_| Error::Truncated)?);
        if expires <= now {
            return Err(Error::Deadline);
        }
        EddsaPublicKey::from_bytes(peer).verify(
            PURPOSE,
            &bytes[64..],
            &EddsaSignature::from_bytes(bytes[..64].try_into().map_err(|_| Error::Truncated)?),
        )?;
        Ok(Self { peer, expires })
    }
    /// Authenticated advertising peer, identical to CADET destination identity.
    pub const fn peer(self) -> [u8; 32] {
        self.peer
    }
    /// Exact signed absolute expiry in microseconds.
    pub const fn expires(self) -> u64 {
        self.expires
    }
}
/// Official DHT GET key SHA512("dns"), no NUL or private namespace.
pub fn discovery_key() -> [u8; 64] {
    hash512(b"dns")
}
/// Official CADET service-port hash SHA512("exit-dns"), no terminating NUL.
pub fn port_hash() -> [u8; 64] {
    hash512(PORT)
}
/// Encode one real DNS query as the official VPN_DNS_TO_INTERNET application
/// message. Size/type header is GNUnet BE16; the DNS body is unchanged.
pub fn encode_query(dns: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    if dns.len() < 12 {
        return Err(Error::Truncated);
    }
    let n = dns.len().checked_add(4).ok_or(Error::Overflow)?;
    let header = MessageHeader::from_total_size(mt::VPN_DNS_TO_INTERNET, n)?;
    if out.len() < n {
        return Err(Error::Capacity);
    }
    header.encode(out)?;
    out[4..n].copy_from_slice(dns);
    Ok(n)
}
/// Borrow an exact DNS reply from one application frame. Full DNS validation and
/// original-channel/ID/question correlation remain the room-independent PT core.
pub fn decode_response(input: &[u8]) -> Result<&[u8], Error> {
    let f = Frame::decode(input)?;
    if f.header().message_type() != mt::VPN_DNS_FROM_INTERNET {
        return Err(Error::Unsupported);
    }
    if input.len() < 16 {
        return Err(Error::Truncated);
    }
    Ok(&input[4..])
}
