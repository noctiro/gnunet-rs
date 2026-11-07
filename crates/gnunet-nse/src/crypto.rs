//! NSE purpose14 verification and caller-memory work, separate from round policy.
use gnunet_crypto::{EddsaPublicKey, EddsaSignature, hash512, pow};
use gnunet_types::Error;
use gnunet_wire::official::nse::flood::{self, Fields, Message};

/// Exact source salt: all16 ASCII bytes, without an additional NUL.
pub const SALT: [u8; 16] = *b"gnunet-nse-proof";
/// Normal unchanged GNUnet work requirement.
pub const DEFAULT_WORK_BITS: u16 = 15;

/// Explicit legal work factor. Zero is an unauthenticated configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkBits(u16);
impl WorkBits {
    /// Reference permits0..511; its normal configuration selects15.
    pub fn new(bits: u16) -> Result<Self, Error> {
        if bits >= 512 {
            return Err(Error::InvalidInput);
        }
        Ok(Self(bits))
    }
    /// Original configured bit count.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}
impl Default for WorkBits {
    fn default() -> Self {
        Self(DEFAULT_WORK_BITS)
    }
}

/// Source-specific internal timestamp-memory interpretation. It changes no wire field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceEndian {
    /// Hash the native integer's little-endian bytes.
    Little,
    /// Hash the native integer's big-endian bytes.
    Big,
}
impl ReferenceEndian {
    /// The current build's pinned C source profile, without runtime discovery.
    #[must_use]
    pub const fn native() -> Self {
        if cfg!(target_endian = "little") {
            Self::Little
        } else {
            Self::Big
        }
    }
    /// Timestamp bytes used by the source's SHA512 distance calculation.
    #[must_use]
    pub const fn timestamp(self, time: u64) -> [u8; 8] {
        match self {
            Self::Little => time.to_le_bytes(),
            Self::Big => time.to_be_bytes(),
        }
    }
}

/// Byte-order-independent leading zero count for the standard hash bytes.
#[must_use]
pub fn leading_zeros(hash: &[u8; 64]) -> u16 {
    let mut count = 0;
    for byte in hash {
        count += byte.leading_zeros() as u16;
        if *byte != 0 {
            break;
        }
    }
    count
}

/// Reference distance for local generation; receiving does not recompute claims.
#[must_use]
pub fn matching_bits(time: u64, identity: &[u8; 32], endian: ReferenceEndian) -> u32 {
    let time_hash = hash512(&endian.timestamp(time));
    let peer_hash = hash512(identity);
    let xor = core::array::from_fn(|i| time_hash[i] ^ peer_hash[i]);
    u32::from(leading_zeros(&xor))
}

/// Compute work on original raw proof bytes plus origin. Scratch remains caller-owned.
pub fn proof_hash(
    identity: &[u8; 32],
    proof: &[u8; 8],
    memory: &mut [pow::Block],
) -> Result<[u8; 64], Error> {
    let mut input = [0; 40];
    input[..8].copy_from_slice(proof);
    input[8..].copy_from_slice(identity);
    let mut output = [0; 64];
    pow::hash(&SALT, &input, &mut output, memory)?;
    Ok(output)
}

/// Validate a configured threshold. Zero accepts every proof without expensive work.
pub fn valid_proof(
    bits: WorkBits,
    identity: &[u8; 32],
    proof: &[u8; 8],
    memory: &mut [pow::Block],
) -> Result<bool, Error> {
    if bits.get() == 0 {
        return Ok(true);
    }
    Ok(leading_zeros(&proof_hash(identity, proof, memory)?) >= bits.get())
}

/// The security mode actually established by admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Authentication {
    /// Signature and configured positive work threshold both checked.
    SignatureAndWork,
    /// Configured zero mode skips cryptographic authentication, as the reference permits.
    ZeroWorkUnauthenticated,
}

/// Structurally accepted packet with the configured crypto gate applied.
/// Its fields do not independently establish claimed distance or freshness.
#[derive(Clone, Copy, Debug)]
pub struct Admitted {
    pub(crate) fields: Fields,
    authentication: Authentication,
}
impl Admitted {
    /// Original public fields after the configured admission gate.
    #[must_use]
    pub const fn fields(self) -> Fields {
        self.fields
    }
    /// Never confuse zero mode with a default15-bit authenticated packet.
    #[must_use]
    pub const fn authentication(self) -> Authentication {
        self.authentication
    }
}

/// Parse and validate the original signed region and exact raw proof.
/// A capacity error is a local resource refusal, not an invalid cryptographic proof.
pub fn admit(bytes: &[u8], work: WorkBits, memory: &mut [pow::Block]) -> Result<Admitted, Error> {
    let message = Message::decode(bytes)?;
    let fields = message.fields()?;
    if !valid_proof(work, &fields.origin, &fields.proof, memory)? {
        return Err(Error::Authentication);
    }
    let authentication = if work.get() == 0 {
        Authentication::ZeroWorkUnauthenticated
    } else {
        EddsaPublicKey::from_bytes(fields.origin).verify(
            flood::SIGNATURE_PURPOSE,
            message.signed_bytes(),
            &EddsaSignature::from_bytes(fields.signature),
        )?;
        Authentication::SignatureAndWork
    };
    Ok(Admitted {
        fields,
        authentication,
    })
}
