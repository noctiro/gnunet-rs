//! Official GNUnet v0.29.1 HELLO sets, binary messages, blocks and URLs.
//!
//! Parsing canonicalizes public addresses but grants no authority. The default
//! upstream compilation profile signs metadata with SHA512(empty), so even a
//! valid signature does **not** bind its address list. Select the signature
//! profile explicitly and inspect [`SignatureCoverage`] before using the result.
//! No communicator, peer admission, network connection or transport handshake is
//! implemented here. All storage, input limits and UTC times come from the caller.
//!
//! Values borrow address storage, never a private key or their original input.
//! A live address borrow prevents the builder from moving its bytes:
//!
//! ```compile_fail,E0502
//! use gnunet_hello::{HelloBuilder, Limits};
//! let mut bytes = [0; 64];
//! let limits = Limits { maximum_input_bytes: 1024, maximum_address_bytes: 64, maximum_addresses: 4 };
//! let mut builder = HelloBuilder::new(&mut bytes, limits);
//! builder.add_address(b"a://first").unwrap();
//! let address = builder.addresses().next().unwrap();
//! builder.add_address(b"z://second").unwrap();
//! assert_eq!(address.as_bytes(), b"a://first");
//! ```
//!
//! Ending the borrow permits the same storage to be changed and reused:
//!
//! ```
//! use gnunet_hello::{HelloBuilder, Limits};
//! let mut bytes = [0; 64];
//! let limits = Limits { maximum_input_bytes: 1024, maximum_address_bytes: 64, maximum_addresses: 4 };
//! {
//!     let mut builder = HelloBuilder::new(&mut bytes, limits);
//!     builder.add_address(b"a://first").unwrap();
//!     { let address = builder.addresses().next().unwrap(); assert_eq!(address.as_bytes(), b"a://first"); }
//!     builder.add_address(b"z://second").unwrap();
//! }
//! bytes.fill(0);
//! assert_eq!(HelloBuilder::new(&mut bytes, limits).address_count(), 0);
//! ```
//!
//! A parsed value likewise keeps its scratch storage borrowed:
//!
//! ```compile_fail,E0499
//! use gnunet_hello::{Hello, Limits};
//! let mut input = [0; 110];
//! input[104..].copy_from_slice(b"a://x\0");
//! let limits = Limits { maximum_input_bytes: 1024, maximum_address_bytes: 64, maximum_addresses: 4 };
//! let mut scratch = [0; 64];
//! let hello = Hello::parse_block(&input, &mut scratch, limits).unwrap();
//! scratch.fill(0);
//! assert_eq!(hello.address_bytes(), b"a://x\0");
//! ```
//!
//! Input metadata and addresses are copied, so the input may disappear before the
//! parsed value. Once that value's borrow ends, its scratch storage is reusable:
//!
//! ```
//! use gnunet_hello::{Hello, Limits};
//! let limits = Limits { maximum_input_bytes: 1024, maximum_address_bytes: 64, maximum_addresses: 4 };
//! let mut scratch = [0; 64];
//! {
//!     let hello = {
//!         let mut input = [0; 110];
//!         input[104..].copy_from_slice(b"a://x\0");
//!         Hello::parse_block(&input, &mut scratch, limits).unwrap()
//!     };
//!     assert_eq!(hello.address_bytes(), b"a://x\0");
//! }
//! scratch.fill(0);
//! assert!(scratch.iter().all(|byte| *byte == 0));
//! ```
//!
//! Verification authority cannot be manufactured from an unverified value:
//!
//! ```compile_fail,E0451
//! use gnunet_hello::{AbsoluteTime, Hello, Limits, SignatureCoverage, VerifiedHello};
//! let input = [0; 104];
//! let limits = Limits { maximum_input_bytes: 104, maximum_address_bytes: 0, maximum_addresses: 0 };
//! let mut scratch = [];
//! let hello = Hello::parse_block(&input, &mut scratch, limits).unwrap();
//! let forged = VerifiedHello { hello, coverage: SignatureCoverage::MetadataOnly, checked_at: AbsoluteTime::UNIX_EPOCH };
//! assert_eq!(forged.checked_at(), AbsoluteTime::UNIX_EPOCH);
//! ```
//!
//! Signing borrows only public address storage after the operation; the private
//! key can be dropped before the signature is checked:
//!
//! ```
//! use gnunet_crypto::EddsaPrivateKey;
//! use gnunet_hello::{AbsoluteTime, HelloBuilder, Limits, SignatureCoverage, SignatureProfile};
//! let mut bytes = [0; 64];
//! let limits = Limits { maximum_input_bytes: 1024, maximum_address_bytes: 64, maximum_addresses: 4 };
//! let mut builder = HelloBuilder::new(&mut bytes, limits);
//! builder.add_address(b"a://first").unwrap();
//! let hello = {
//!     let key = EddsaPrivateKey::from_seed([7; 32]);
//!     builder.sign(&key, AbsoluteTime::NEVER, SignatureProfile::Gnunet029).unwrap()
//! };
//! let verified = hello.verify_at(SignatureProfile::Gnunet029, AbsoluteTime::UNIX_EPOCH).unwrap();
//! assert_eq!(verified.coverage(), SignatureCoverage::MetadataOnly);
//! assert_eq!(verified.hello(), hello);
//! ```
#![no_std]
#![forbid(unsafe_code)]

mod address;
mod url;
pub use address::{AddAddress, Address, Addresses, HelloBuilder, address_to_prefix};
use gnunet_crypto::{EddsaPublicKey, EddsaSignature, hash512};
use gnunet_types::Error;
pub use gnunet_wire::official::{AbsoluteTime, RelativeTime};
use gnunet_wire::official::{Frame, MessageHeader, message_type};

/// Public peer32, EdDSA signature64, expiration64.
pub const BLOCK_HEADER_LEN: usize = 104;
/// Common header4, reserved16, count16 and the complete block header.
pub const MESSAGE_FIXED_LEN: usize = 112;
/// Common header4, reserved16, count16, signature64 and expiration64.
pub const DHT_MESSAGE_FIXED_LEN: usize = 80;
/// Official `GNUNET_SIGNATURE_PURPOSE_HELLO`.
pub const SIGNATURE_PURPOSE: u32 = 7;
/// Purpose8, expiration8 and SHA512 address hash64.
pub const SIGNED_PAYLOAD_LEN: usize = 80;
/// Official default HELLO lifetime: two days, in microseconds.
pub const ADDRESS_EXPIRATION: RelativeTime = RelativeTime::from_micros(172_800_000_000);

/// Finite caller resource and work limits; no process-wide default is assumed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum complete block, frame or textual URL input inspected by a parser.
    pub maximum_input_bytes: usize,
    /// Maximum canonical NUL-delimited bytes retained in caller storage.
    pub maximum_address_bytes: usize,
    /// Maximum unique addresses; sorting and duplicate checks take bounded quadratic work.
    pub maximum_addresses: usize,
}
impl Limits {
    fn check_input(self, input: &[u8]) -> Result<(), Error> {
        if input.len() > self.maximum_input_bytes {
            return Err(Error::Capacity);
        }
        Ok(())
    }
}

/// Exact official `HELLO_DETERMINISTIC_PID_DERIVATION` compilation alternatives.
/// This is explicit: verification never tries a weaker profile after failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureProfile {
    /// Normal v0.29.1 build: addresses are omitted from the hash input.
    Gnunet029,
    /// Official conditional build: hash canonical NUL-terminated addresses.
    DeterministicPidDerivation,
}
impl SignatureProfile {
    /// What a successful signature can authenticate under this profile.
    #[must_use]
    pub const fn coverage(self) -> SignatureCoverage {
        match self {
            Self::Gnunet029 => SignatureCoverage::MetadataOnly,
            Self::DeterministicPidDerivation => SignatureCoverage::MetadataAndAddresses,
        }
    }
    fn hash(self, addresses: &[u8]) -> [u8; 64] {
        match self {
            Self::Gnunet029 => hash512(&[]),
            Self::DeterministicPidDerivation => hash512(addresses),
        }
    }
}
/// The precise fields authenticated by the selected official signature profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureCoverage {
    /// Peer identity and expiration; addresses remain unauthenticated claims.
    MetadataOnly,
    /// Peer identity, expiration and the canonical complete address set.
    MetadataAndAddresses,
}

/// Canonical HELLO bytes and public metadata, with no signature or time authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Hello<'a> {
    peer: EddsaPublicKey,
    signature: EddsaSignature,
    expiration: AbsoluteTime,
    addresses: &'a [u8],
    count: usize,
}
impl<'a> Hello<'a> {
    /// Parse a raw block and normalize its addresses into caller storage.
    /// Duplicate and invalid addresses fail; failed parsing may change scratch storage.
    pub fn parse_block(input: &[u8], storage: &'a mut [u8], limits: Limits) -> Result<Self, Error> {
        limits.check_input(input)?;
        if input.len() < BLOCK_HEADER_LEN {
            return Err(Error::Truncated);
        }
        let peer =
            EddsaPublicKey::from_bytes(input[..32].try_into().map_err(|_| Error::Truncated)?);
        let signature =
            EddsaSignature::from_bytes(input[32..96].try_into().map_err(|_| Error::Truncated)?);
        let expiration = AbsoluteTime::decode(&input[96..104])?;
        let mut builder = HelloBuilder::new(storage, limits);
        builder.parse_raw(&input[104..])?;
        Ok(builder.finish(peer, signature, expiration))
    }
    /// Parse exactly one HELLO_URI or DHT_P2P_HELLO frame.
    ///
    /// As in the normal C parser, reserved/count fields are ignored; actual
    /// addresses determine the set. DHT messages require an external claimed peer.
    /// This structural operation does not verify it or compare expiration to UTC.
    pub fn parse_message(
        input: &[u8],
        claimed_peer: Option<EddsaPublicKey>,
        storage: &'a mut [u8],
        limits: Limits,
    ) -> Result<Self, Error> {
        limits.check_input(input)?;
        let frame = Frame::decode(input)?;
        if frame.header().message_type() == message_type::HELLO_URI {
            if input.len() < MESSAGE_FIXED_LEN {
                return Err(Error::Truncated);
            }
            Self::parse_block(&input[8..], storage, limits)
        } else if frame.header().message_type() == message_type::DHT_P2P_HELLO {
            if input.len() < DHT_MESSAGE_FIXED_LEN {
                return Err(Error::Truncated);
            }
            let peer = claimed_peer.ok_or(Error::InvalidInput)?;
            let signature =
                EddsaSignature::from_bytes(input[8..72].try_into().map_err(|_| Error::Truncated)?);
            let expiration = AbsoluteTime::decode(&input[72..80])?;
            let mut builder = HelloBuilder::new(storage, limits);
            builder.parse_raw(&input[80..])?;
            Ok(builder.finish(peer, signature, expiration))
        } else {
            Err(Error::Unsupported)
        }
    }
    /// Parse an official `gnunet://hello/` URL without authenticating it.
    /// Text follows the C encoding, including literal `+` during decoding.
    pub fn parse_url(input: &[u8], storage: &'a mut [u8], limits: Limits) -> Result<Self, Error> {
        url::parse(input, storage, limits)
    }
    /// Claimed public identity; use signature verification before attributing metadata.
    #[must_use]
    pub const fn peer(self) -> EddsaPublicKey {
        self.peer
    }
    /// Signature bytes, without a validity claim.
    #[must_use]
    pub const fn signature(self) -> EddsaSignature {
        self.signature
    }
    /// Absolute microsecond expiration, including the never sentinel.
    #[must_use]
    pub const fn expiration(self) -> AbsoluteTime {
        self.expiration
    }
    /// Unique canonical address count; raw blocks may exceed a message's 16-bit count.
    #[must_use]
    pub const fn address_count(self) -> usize {
        self.count
    }
    /// Canonical descending NUL-delimited address bytes.
    #[must_use]
    pub const fn address_bytes(self) -> &'a [u8] {
        self.addresses
    }
    /// Iterate over public address claims in reference canonical order.
    #[must_use]
    pub fn addresses(self) -> Addresses<'a> {
        Addresses::new(self.addresses, self.count)
    }
    /// Copy the set into independently owned caller storage, preserving peer metadata separately.
    pub fn to_builder<'b>(
        self,
        storage: &'b mut [u8],
        limits: Limits,
    ) -> Result<HelloBuilder<'b>, Error> {
        let mut builder = HelloBuilder::new(storage, limits);
        builder.parse_raw(self.addresses)?;
        Ok(builder)
    }
    /// Compute the hash that the selected official C profile signs.
    #[must_use]
    pub fn address_hash(self, profile: SignatureProfile) -> [u8; 64] {
        profile.hash(self.addresses)
    }
    /// Exact purpose7 region; public and suitable for independent reference comparison.
    pub fn signed_payload(
        self,
        profile: SignatureProfile,
    ) -> Result<[u8; SIGNED_PAYLOAD_LEN], Error> {
        signed_payload(self.expiration, &self.address_hash(profile))
    }
    /// Check the ordinary Ed25519 signature without consulting a clock.
    pub fn verify_signature(self, profile: SignatureProfile) -> Result<SignatureCoverage, Error> {
        self.peer.verify(
            SIGNATURE_PURPOSE,
            &self.signed_payload(profile)?,
            &self.signature,
        )?;
        Ok(profile.coverage())
    }
    /// Check signature, then reject expiration strictly earlier than `now`.
    /// A successful result records this observation time; it is not a lasting dial capability.
    pub fn verify_at(
        self,
        profile: SignatureProfile,
        now: AbsoluteTime,
    ) -> Result<VerifiedHello<'a>, Error> {
        let coverage = self.verify_signature(profile)?;
        if self.expiration < now {
            return Err(Error::Timeout);
        }
        Ok(VerifiedHello {
            hello: self,
            coverage,
            checked_at: now,
        })
    }
    /// Raw block byte length.
    pub fn block_len(self) -> Result<usize, Error> {
        BLOCK_HEADER_LEN
            .checked_add(self.addresses.len())
            .ok_or(Error::Overflow)
    }
    /// HELLO_URI frame length, rejecting official 16-bit count or total-size overflow.
    pub fn message_len(self) -> Result<usize, Error> {
        self.frame_len(MESSAGE_FIXED_LEN, message_type::HELLO_URI)
    }
    /// DHT message length, rejecting official framing overflow.
    pub fn dht_message_len(self) -> Result<usize, Error> {
        self.frame_len(DHT_MESSAGE_FIXED_LEN, message_type::DHT_P2P_HELLO)
    }
    fn frame_len(
        self,
        fixed: usize,
        kind: gnunet_wire::official::MessageType,
    ) -> Result<usize, Error> {
        u16::try_from(self.count).map_err(|_| Error::TooLarge)?;
        let n = fixed
            .checked_add(self.addresses.len())
            .ok_or(Error::Overflow)?;
        MessageHeader::from_total_size(kind, n)?;
        Ok(n)
    }
    /// Encode a raw block; refusal leaves the complete output slice unchanged.
    pub fn encode_block(self, output: &mut [u8]) -> Result<usize, Error> {
        let n = self.block_len()?;
        if output.len() < n {
            return Err(Error::Capacity);
        }
        output[..32].copy_from_slice(self.peer.as_bytes());
        output[32..96].copy_from_slice(self.signature.as_bytes());
        output[96..104].copy_from_slice(&self.expiration.to_be_bytes());
        output[104..n].copy_from_slice(self.addresses);
        Ok(n)
    }
    /// Encode HELLO_URI with zero reserved bits and the true canonical count.
    pub fn encode_message(self, output: &mut [u8]) -> Result<usize, Error> {
        let n = self.message_len()?;
        if output.len() < n {
            return Err(Error::Capacity);
        }
        MessageHeader::from_total_size(message_type::HELLO_URI, n)?.encode(output)?;
        output[4..6].fill(0);
        output[6..8].copy_from_slice(&(self.count as u16).to_be_bytes());
        self.encode_block(&mut output[8..n])?;
        Ok(n)
    }
    /// Encode direct DHT HELLO, whose claimed peer identity is carried externally.
    pub fn encode_dht_message(self, output: &mut [u8]) -> Result<usize, Error> {
        let n = self.dht_message_len()?;
        if output.len() < n {
            return Err(Error::Capacity);
        }
        MessageHeader::from_total_size(message_type::DHT_P2P_HELLO, n)?.encode(output)?;
        output[4..6].fill(0);
        output[6..8].copy_from_slice(&(self.count as u16).to_be_bytes());
        output[8..72].copy_from_slice(self.signature.as_bytes());
        output[72..80].copy_from_slice(&self.expiration.to_be_bytes());
        output[80..n].copy_from_slice(self.addresses);
        Ok(n)
    }
    /// Number of bytes in the canonical textual URL, without a NUL terminator.
    pub fn url_len(self) -> Result<usize, Error> {
        url::length(self)
    }
    /// Write canonical uppercase Crockford and C-compatible percent encoding.
    /// Refusal leaves output unchanged. The URL may not roundtrip a body containing
    /// spaces: C formats them as `+` and parses `+` literally.
    pub fn write_url(self, output: &mut [u8]) -> Result<&str, Error> {
        url::write(self, output)
    }
}

/// A signature checked at one explicit UTC value, with precisely stated coverage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedHello<'a> {
    hello: Hello<'a>,
    coverage: SignatureCoverage,
    checked_at: AbsoluteTime,
}
impl<'a> VerifiedHello<'a> {
    /// Public structured bytes; extracting them does not extend their lifetime validity.
    #[must_use]
    pub const fn hello(self) -> Hello<'a> {
        self.hello
    }
    /// Whether the address list itself is authenticated.
    #[must_use]
    pub const fn coverage(self) -> SignatureCoverage {
        self.coverage
    }
    /// Caller-provided UTC instant at which expiration was checked.
    #[must_use]
    pub const fn checked_at(self) -> AbsoluteTime {
        self.checked_at
    }
}

/// Add the official default two-day lifetime, saturating to GNUnet's never sentinel.
#[must_use]
pub const fn default_expiration(now: AbsoluteTime) -> AbsoluteTime {
    AbsoluteTime::from_micros(
        now.as_micros()
            .saturating_add(ADDRESS_EXPIRATION.as_micros()),
    )
}

/// Official persistence helper semantics, after safe exact frame validation.
/// HELLO_URI with no addresses yields zero; an empty DHT message retains its expiry.
/// This helper never verifies a signature and must not authorize a peer.
pub fn message_expiration(input: &[u8]) -> Result<AbsoluteTime, Error> {
    let frame = Frame::decode(input)?;
    if frame.header().message_type() == message_type::HELLO_URI {
        if input.len() < MESSAGE_FIXED_LEN {
            return Err(Error::Truncated);
        }
        if input.len() == MESSAGE_FIXED_LEN {
            return Ok(AbsoluteTime::UNIX_EPOCH);
        }
        AbsoluteTime::decode(&input[104..112])
    } else if frame.header().message_type() == message_type::DHT_P2P_HELLO {
        if input.len() < DHT_MESSAGE_FIXED_LEN {
            return Err(Error::Truncated);
        }
        AbsoluteTime::decode(&input[72..80])
    } else {
        Err(Error::Unsupported)
    }
}
fn signed_payload(
    expiration: AbsoluteTime,
    hash: &[u8; 64],
) -> Result<[u8; SIGNED_PAYLOAD_LEN], Error> {
    let mut result = [0; SIGNED_PAYLOAD_LEN];
    gnunet_wire::official::hello::encode_signed_payload(expiration, hash, &mut result)?;
    Ok(result)
}
