//! Official HELLO URI, direct-DHT HELLO and raw HELLO block representations.
//!
//! Reference: GNUnet v0.29.1 `src/lib/hello/hello-uri.c`, especially the
//! `HelloUriMessage`, `DhtHelloMessage`, `BlockHeader` and `check_address`
//! definitions. These codecs only check framing/address syntax: their output
//! remains [`UnverifiedHello`], never an authenticated peer or usable contact.
use super::{AbsoluteTime, Frame, MessageHeader, SignaturePurpose, message_type};
use gnunet_types::Error;

/// A raw HELLO block contains peer32, signature64 and expiration microseconds64.
pub const BLOCK_HEADER_LEN: usize = 104;
/// HELLO_URI includes a common header, reserved16, count16 and the full block.
pub const MESSAGE_FIXED_LEN: usize = 112;
/// DHT_P2P_HELLO omits peer32, which is supplied by the adjacent protocol owner.
pub const DHT_MESSAGE_FIXED_LEN: usize = 80;
/// Official signature-purpose assignment (`gnunet_signatures.h:94`).
pub const SIGNATURE_PURPOSE: u32 = 7;
/// Signed purpose8, expiration8 and address hash64.
pub const SIGNED_PAYLOAD_LEN: usize = 80;

/// Caller-owned input/work ceilings, in addition to official wire-width limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HelloLimits {
    /// Maximum URI count; duplicate rejection costs at most this many squared comparisons.
    pub maximum_addresses: usize,
    /// Maximum complete message/block bytes the caller can inspect.
    pub maximum_bytes: usize,
}
impl HelloLimits {
    fn check_bytes(self, bytes: usize) -> Result<(), Error> {
        if bytes > self.maximum_bytes {
            return Err(Error::Capacity);
        }
        Ok(())
    }
}

/// A structurally checked HELLO with an **unverified** identity/signature/expiry.
///
/// The signature is not checked, expiration is not compared to a clock, and a
/// supported communicator is not inferred from an address's scheme. The direct
/// DHT form's supplied peer bytes are also a claim, not proof of authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnverifiedHello<'a> {
    peer: &'a [u8; 32],
    signature: &'a [u8; 64],
    expiration: AbsoluteTime,
    addresses: &'a [u8],
    count: u16,
}
impl<'a> UnverifiedHello<'a> {
    /// Borrow metadata and a NUL-delimited address region. This does not sign it.
    /// Address order is retained; the reference builder sorts before signing.
    pub fn new(
        peer: &'a [u8; 32],
        signature: &'a [u8; 64],
        expiration: AbsoluteTime,
        addresses: &'a [u8],
        limits: HelloLimits,
    ) -> Result<Self, Error> {
        limits.check_bytes(
            BLOCK_HEADER_LEN
                .checked_add(addresses.len())
                .ok_or(Error::Overflow)?,
        )?;
        Self::from_parts(peer, signature, expiration, addresses, None, limits)
    }

    /// Decode exactly one official HELLO_URI frame (type16), including peer32.
    /// Reserved bits, count mismatches, duplicate addresses and trailing bytes fail.
    pub fn decode_message(input: &'a [u8], limits: HelloLimits) -> Result<Self, Error> {
        limits.check_bytes(input.len())?;
        let frame = Frame::decode(input)?;
        if frame.header().message_type() != message_type::HELLO_URI {
            return Err(Error::Unsupported);
        }
        let body = frame.payload();
        if body.len() < MESSAGE_FIXED_LEN - 4 {
            return Err(Error::Truncated);
        }
        let count = read_metadata(body)?;
        let block = &body[4..];
        let hello = Self::decode_block(block, limits)?;
        if hello.count != count {
            return Err(Error::Malformed);
        }
        Ok(hello)
    }

    /// Decode direct DHT HELLO (type157) with an externally supplied claimed peer.
    pub fn decode_dht_message(
        input: &'a [u8],
        claimed_peer: &'a [u8; 32],
        limits: HelloLimits,
    ) -> Result<Self, Error> {
        limits.check_bytes(input.len())?;
        let frame = Frame::decode(input)?;
        if frame.header().message_type() != message_type::DHT_P2P_HELLO {
            return Err(Error::Unsupported);
        }
        let body = frame.payload();
        if body.len() < DHT_MESSAGE_FIXED_LEN - 4 {
            return Err(Error::Truncated);
        }
        let count = read_metadata(body)?;
        Self::from_parts(
            claimed_peer,
            body[4..68].try_into().map_err(|_| Error::Truncated)?,
            AbsoluteTime::decode(&body[68..76])?,
            &body[76..],
            Some(count),
            limits,
        )
    }

    /// Decode a raw DHT HELLO block, with no common header or address-count field.
    pub fn decode_block(input: &'a [u8], limits: HelloLimits) -> Result<Self, Error> {
        limits.check_bytes(input.len())?;
        if input.len() < BLOCK_HEADER_LEN {
            return Err(Error::Truncated);
        }
        Self::from_parts(
            input[..32].try_into().map_err(|_| Error::Truncated)?,
            input[32..96].try_into().map_err(|_| Error::Truncated)?,
            AbsoluteTime::decode(&input[96..104])?,
            &input[104..],
            None,
            limits,
        )
    }

    fn from_parts(
        peer: &'a [u8; 32],
        signature: &'a [u8; 64],
        expiration: AbsoluteTime,
        addresses: &'a [u8],
        expected_count: Option<u16>,
        limits: HelloLimits,
    ) -> Result<Self, Error> {
        let count = validate_addresses(addresses, limits.maximum_addresses)?;
        if expected_count.is_some_and(|expected| expected != count) {
            return Err(Error::Malformed);
        }
        Ok(Self {
            peer,
            signature,
            expiration,
            addresses,
            count,
        })
    }

    /// Encode an official HELLO_URI frame; no signature is generated or verified.
    pub fn encode_message(self, output: &mut [u8]) -> Result<usize, Error> {
        let size = MESSAGE_FIXED_LEN
            .checked_add(self.addresses.len())
            .ok_or(Error::Overflow)?;
        let header = MessageHeader::from_total_size(message_type::HELLO_URI, size)?;
        if output.len() < size {
            return Err(Error::Capacity);
        }
        header.encode(output)?;
        output[4..6].fill(0);
        output[6..8].copy_from_slice(&self.count.to_be_bytes());
        self.encode_block(&mut output[8..size])?;
        Ok(size)
    }

    /// Encode direct DHT HELLO, omitting claimed peer bytes from the message.
    pub fn encode_dht_message(self, output: &mut [u8]) -> Result<usize, Error> {
        let size = DHT_MESSAGE_FIXED_LEN
            .checked_add(self.addresses.len())
            .ok_or(Error::Overflow)?;
        let header = MessageHeader::from_total_size(message_type::DHT_P2P_HELLO, size)?;
        if output.len() < size {
            return Err(Error::Capacity);
        }
        header.encode(output)?;
        output[4..6].fill(0);
        output[6..8].copy_from_slice(&self.count.to_be_bytes());
        output[8..72].copy_from_slice(self.signature);
        output[72..80].copy_from_slice(&self.expiration.to_be_bytes());
        output[80..size].copy_from_slice(self.addresses);
        Ok(size)
    }

    /// Encode the raw block. A capacity error changes no output bytes.
    pub fn encode_block(self, output: &mut [u8]) -> Result<usize, Error> {
        let size = BLOCK_HEADER_LEN
            .checked_add(self.addresses.len())
            .ok_or(Error::Overflow)?;
        if output.len() < size {
            return Err(Error::Capacity);
        }
        output[..32].copy_from_slice(self.peer);
        output[32..96].copy_from_slice(self.signature);
        output[96..104].copy_from_slice(&self.expiration.to_be_bytes());
        output[104..size].copy_from_slice(self.addresses);
        Ok(size)
    }

    /// Claimed public identity bytes, without authentication authority.
    #[must_use]
    pub const fn claimed_peer(self) -> &'a [u8; 32] {
        self.peer
    }
    /// Unverified EdDSA signature bytes.
    #[must_use]
    pub const fn signature(self) -> &'a [u8; 64] {
        self.signature
    }
    /// Claimed expiration, in official absolute microseconds.
    #[must_use]
    pub const fn expiration(self) -> AbsoluteTime {
        self.expiration
    }
    /// Address count actually parsed, after checking any advertised counter.
    #[must_use]
    pub const fn address_count(self) -> u16 {
        self.count
    }
    /// Original NUL-delimited address bytes, retaining their wire order.
    #[must_use]
    pub const fn address_bytes(self) -> &'a [u8] {
        self.addresses
    }
    /// Borrowed URI iteration; no address is selected, authenticated or dialed.
    #[must_use]
    pub fn addresses(self) -> AddressIter<'a> {
        AddressIter {
            remaining: self.addresses,
            count: self.count,
        }
    }
}

/// One address's uninterpreted URI bytes, excluding its NUL terminator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HelloAddress<'a> {
    uri: &'a [u8],
    scheme_len: usize,
}
impl<'a> HelloAddress<'a> {
    /// URI bytes; opaque/non-UTF-8 paths are preserved as in the C format.
    #[must_use]
    pub const fn uri(self) -> &'a [u8] {
        self.uri
    }
    /// Communicator scheme bytes. Unknown schemes are not rejected by framing.
    #[must_use]
    pub fn scheme(self) -> &'a [u8] {
        &self.uri[..self.scheme_len]
    }
    /// Interpret URI bytes as UTF-8 only when the caller needs text.
    pub fn as_utf8(self) -> Result<&'a str, Error> {
        core::str::from_utf8(self.uri).map_err(|_| Error::Malformed)
    }
}

/// Iterator over a previously validated HELLO address region.
pub struct AddressIter<'a> {
    remaining: &'a [u8],
    count: u16,
}
impl<'a> Iterator for AddressIter<'a> {
    type Item = Result<HelloAddress<'a>, Error>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.count == 0 {
            return None;
        }
        self.count -= 1;
        let result = match self.remaining.iter().position(|byte| *byte == 0) {
            Some(end) => {
                let uri = &self.remaining[..end];
                self.remaining = &self.remaining[end + 1..];
                check_uri(uri).map(|scheme_len| HelloAddress { uri, scheme_len })
            }
            None => Err(Error::Truncated),
        };
        if result.is_err() {
            self.count = 0;
            self.remaining = &[];
        }
        Some(result)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (usize::from(self.count), Some(usize::from(self.count)))
    }
}
impl ExactSizeIterator for AddressIter<'_> {}
impl core::iter::FusedIterator for AddressIter<'_> {}

/// Serialize an address list into caller storage, preserving order. The caller
/// must supply sorted input when reproducing the reference builder's ordering.
/// Refusal leaves the destination untouched; NUL bytes inside a URI are invalid.
pub fn encode_addresses(
    uris: &[&[u8]],
    output: &mut [u8],
    limits: HelloLimits,
) -> Result<usize, Error> {
    if uris.len() > limits.maximum_addresses {
        return Err(Error::Capacity);
    }
    if uris.len() > usize::from(u16::MAX) {
        return Err(Error::TooLarge);
    }
    let mut size = 0_usize;
    for (index, uri) in uris.iter().enumerate() {
        check_uri(uri)?;
        if uri.contains(&0) || uris[..index].contains(uri) {
            return Err(Error::Malformed);
        }
        size = size
            .checked_add(uri.len())
            .and_then(|sum| sum.checked_add(1))
            .ok_or(Error::Overflow)?;
    }
    limits.check_bytes(size)?;
    if output.len() < size {
        return Err(Error::Capacity);
    }
    let mut offset = 0_usize;
    for uri in uris {
        output[offset..offset + uri.len()].copy_from_slice(uri);
        offset += uri.len();
        output[offset] = 0;
        offset += 1;
    }
    Ok(size)
}

/// Construct the exact signed-region representation for a caller-computed hash.
///
/// This does not compute/validate the hash or verify the signature. In the pinned
/// C implementation, address-hash input depends on the build's
/// `HELLO_DETERMINISTIC_PID_DERIVATION` configuration; no default is guessed here.
pub fn encode_signed_payload(
    expiration: AbsoluteTime,
    address_hash: &[u8; 64],
    output: &mut [u8],
) -> Result<usize, Error> {
    if output.len() < SIGNED_PAYLOAD_LEN {
        return Err(Error::Capacity);
    }
    SignaturePurpose::new(SIGNATURE_PURPOSE, SIGNED_PAYLOAD_LEN - 8)?.encode(output)?;
    output[8..16].copy_from_slice(&expiration.to_be_bytes());
    output[16..80].copy_from_slice(address_hash);
    Ok(SIGNED_PAYLOAD_LEN)
}

fn read_metadata(bytes: &[u8]) -> Result<u16, Error> {
    if bytes[..2] != [0, 0] {
        return Err(Error::Unsupported);
    }
    Ok(u16::from_be_bytes([bytes[2], bytes[3]]))
}
fn check_uri(uri: &[u8]) -> Result<usize, Error> {
    let scheme_len = uri
        .windows(3)
        .position(|part| part == b"://")
        .ok_or(Error::Malformed)?;
    if scheme_len == 0
        || uri[..scheme_len]
            .iter()
            .any(|byte| !byte.is_ascii_alphabetic() && *byte != b'+')
    {
        return Err(Error::Malformed);
    }
    Ok(scheme_len)
}
fn validate_addresses(bytes: &[u8], maximum_count: usize) -> Result<u16, Error> {
    let mut offset = 0_usize;
    let mut count = 0_usize;
    while offset < bytes.len() {
        if count == maximum_count {
            return Err(Error::Capacity);
        }
        let end = bytes[offset..]
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(Error::Truncated)?;
        let uri = &bytes[offset..offset + end];
        check_uri(uri)?;
        if bytes[..offset]
            .split(|byte| *byte == 0)
            .any(|previous| previous == uri)
        {
            return Err(Error::Malformed);
        }
        offset = offset
            .checked_add(end)
            .and_then(|n| n.checked_add(1))
            .ok_or(Error::Overflow)?;
        count = count.checked_add(1).ok_or(Error::Overflow)?;
    }
    u16::try_from(count).map_err(|_| Error::TooLarge)
}
