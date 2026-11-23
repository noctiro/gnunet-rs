//! Official GNUnet IDENTITY secret ownership and bounded service transactions.
//! Wire interoperability is independent of private storage and process APIs.
#![no_std]
#![forbid(unsafe_code)]
#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
mod service;
#[cfg(feature = "alloc")]
pub use service::{Change, Core, Decision, Ego, Limits, Snapshot, StageView, Transaction};
/// Bounded, allocation-free ego inventory and synchronous mutation owner.
#[cfg(feature = "fixed")]
pub mod fixed;
#[cfg(any(feature = "alloc", feature = "fixed"))]
mod names;
#[cfg(any(feature = "alloc", feature = "fixed"))]
#[rustfmt::skip]
mod tables;

use core::fmt;
use gnunet_crypto::{EddsaPrivateKey, Entropy, gns::PkeySecret};
use gnunet_types::Error;
pub use gnunet_wire::official::identity::{KEY_LEN, KeyType, SecretKeyView};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// Largest name fitting an official UPDATE with a serialized private key.
pub const MAX_NAME_BYTES: usize = 65535 - 12 - 36 - 1;

/// Requested mutation. Preparation alone has no committed effect.
#[derive(Clone, Copy, Debug)]
pub enum Mutation<'a> {
    /// Create or import one key and normalize its supplied name.
    Create {
        /// Requested name before normalization.
        name: &'a [u8],
        /// Structurally validated supplied private key.
        key: SecretKeyView<'a>,
    },
    /// Normalize both names, then rename the old ego.
    Rename {
        /// Existing name before normalization.
        old: &'a [u8],
        /// New name before normalization.
        new: &'a [u8],
    },
    /// Normalize the name, then remove the ego.
    Delete {
        /// Existing name before normalization.
        name: &'a [u8],
    },
}

/// Inventory change kind. CREATE replies before UPDATE. RENAME and DELETE
/// update before their success reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChangeKind {
    /// New ego at index zero of the after snapshot.
    Create,
    /// Existing ego renamed in place.
    Rename,
    /// Ego removed from the after snapshot.
    Delete,
}

/// Official result code, preserving unknown future service codes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Code(u32);
impl Code {
    /// Mutation committed successfully.
    pub const NONE: Self = Self(0);
    /// An actual operation failed without a more specific official code.
    pub const UNKNOWN: Self = Self(1);
    /// The requested ego does not exist.
    pub const NOT_FOUND: Self = Self(200);
    /// The normalized new name is already present.
    pub const NAME_CONFLICT: Self = Self(201);
    /// An identity name or supplied value is invalid.
    pub const INVALID: Self = Self(202);
    /// Retain an actual numeric result without assuming it means success.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }
    /// Official numeric result value.
    pub const fn value(self) -> u32 {
        self.0
    }
}

/// Opaque private key owner. All retained key bytes are erased on drop. Copying
/// for an immutable snapshot requires the explicit sensitive-copy operation.
/// There is no ordinary Clone, equality/hash implementation, or secret Debug.
pub struct SecretKey {
    bytes: Zeroizing<[u8; KEY_LEN]>,
    kind: KeyType,
}
impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey([REDACTED])")
    }
}
impl SecretKey {
    /// Import the exact official tag and key bytes. No scalar validation beyond
    /// the official IDENTITY service's structural import policy is imposed.
    /// The by-value input copy is erased on success and failure.
    pub fn new(mut bytes: [u8; KEY_LEN]) -> Result<Self, Error> {
        let kind = match SecretKeyView::new(&bytes) {
            Ok(v) => v.key_type(),
            Err(e) => {
                bytes.zeroize();
                return Err(e);
            }
        };
        let owned = Self {
            bytes: Zeroizing::new(bytes),
            kind,
        };
        bytes.zeroize();
        Ok(owned)
    }
    /// Copy one explicitly exposed sensitive serialization into an erased owner.
    pub fn from_serialized(bytes: &[u8]) -> Result<Self, Error> {
        SecretKeyView::new(bytes)?;
        let mut owned = Zeroizing::new([0; KEY_LEN]);
        owned.copy_from_slice(bytes);
        Self::new(*owned)
    }
    /// Supported official key type.
    pub const fn key_type(&self) -> KeyType {
        self.kind
    }
    /// Explicit sensitive borrow, suitable only for protocol/persistence owners.
    pub fn expose_serialized(&self) -> &[u8; KEY_LEN] {
        &self.bytes
    }
    /// Borrow the no-allocation official wire view. The owner invariant makes a
    /// validation error impossible without memory corruption; no panic is used.
    pub fn view(&self) -> Result<SecretKeyView<'_>, Error> {
        SecretKeyView::new(self.expose_serialized())
    }
    /// Explicitly make a separately zeroizing secret owner for a new immutable
    /// snapshot. This copies fixed storage and allocates no heap memory.
    pub fn try_clone_secret(&self) -> Self {
        Self {
            bytes: Zeroizing::new(*self.bytes),
            kind: self.kind,
        }
    }
    /// Compare all serialized bytes without data-dependent early exit. This is
    /// only private in-process ego matching, never a public secret-derived ID.
    pub fn constant_time_eq(&self, other: &Self) -> bool {
        bool::from(self.bytes[..].ct_eq(&other.bytes[..]))
    }
    /// Generate a new key from the original caller's cryptographic entropy port.
    /// ECDSA uses the official scalar clamping; EdDSA keeps its seed unclamped.
    pub fn generate(kind: KeyType, entropy: &mut impl Entropy) -> Result<Self, Error> {
        let mut bytes = Zeroizing::new([0; KEY_LEN]);
        bytes[..4].copy_from_slice(&kind.value().to_be_bytes());
        entropy.fill(&mut bytes[4..])?;
        if kind == KeyType::Ecdsa {
            bytes[4] &= 248;
            bytes[35] &= 127;
            bytes[35] |= 64;
        }
        Self::new(*bytes)
    }
    /// Standard public anonymous EdDSA seed from crypto_ecc.c: little-endian
    /// integer one. This is a published constant, never a secret file import.
    pub fn anonymous() -> Self {
        let mut bytes = Zeroizing::new([0; KEY_LEN]);
        bytes[..4].copy_from_slice(&KeyType::Eddsa.value().to_be_bytes());
        bytes[4] = 1;
        Self {
            bytes,
            kind: KeyType::Eddsa,
        }
    }
    /// Derive the official serialized public key. Import accepts the same raw
    /// keys as C; an invalid zero ECDSA scalar can therefore fail here later.
    /// Temporary secret copies and primitive secret owners erase on every path.
    pub fn public_key(&self) -> Result<[u8; KEY_LEN], Error> {
        let mut raw = Zeroizing::new([0; 32]);
        raw.copy_from_slice(&self.bytes[4..]);
        let public = match self.kind {
            KeyType::Ecdsa => PkeySecret::from_bytes(*raw)?.public_key(),
            KeyType::Eddsa => *EddsaPrivateKey::from_seed(*raw).public_key().as_bytes(),
        };
        let mut out = [0; KEY_LEN];
        out[..4].copy_from_slice(&self.kind.value().to_be_bytes());
        out[4..].copy_from_slice(&public);
        Ok(out)
    }
}

/// Locale-neutral Unicode18 lowercase followed by canonical NFD, using the same
/// fixed profile and tables as ego names. The function uses the caller's
/// buffers for all normalization work.
///
/// Caller scalar buffers are scratch and may change on error; output is written
/// only after complete validation/capacity preflight. Its owner must erase any
/// sensitive output/scratch. Input is canonical UTF-8 without NUL, at most65530
/// bytes; no ego-name byte limit, IDNA mapping or ASCII approximation is imposed.
#[cfg(any(feature = "alloc", feature = "fixed"))]
pub fn normalize_name_into(
    input: &[u8],
    output: &mut [u8],
    lowered: &mut [u32],
    normalized: &mut [u32],
    ordering: &mut [u32],
) -> Result<usize, gnunet_types::Error> {
    names::normalize_into(input, output, lowered, normalized, ordering)
}
