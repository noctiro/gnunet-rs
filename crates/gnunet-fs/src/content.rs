//! Deterministic official FS content blocks with caller-owned storage.
//!
//! These are local artifacts. No datastore, scheduling, publication, lookup or
//! file I/O is implicit. Plaintext SHA-512 determines the standard GNUnet HKDF
//! key/nonce; ciphertext followed by its detached tag determines the query.

mod frontier;
mod geometry;
mod reader;
mod traversal;
mod tree;
use crate::Content;
pub use frontier::{IndexInput, ReferenceFrontier};
pub use geometry::{Layout, MAX_FRONTIER_KEYS, MAX_TREE_LEVELS, Node};
use gnunet_crypto::{hash512, hkdf_gnunet};
use gnunet_session_crypto::aead::{xchacha20poly1305_open, xchacha20poly1305_seal};
use gnunet_types::Error;
pub use reader::{FileReader, RangeReader, VerifiedChunk, VerifiedFile, VerifiedRange};
use subtle::ConstantTimeEq;
pub use traversal::{DataSlice, NodeRef, OpenedNode, RangeTraversal};
pub use tree::{EncodedNode, FileEncoder};
use zeroize::{Zeroize, Zeroizing};

/// Maximum plaintext bytes of either a DBLOCK or an IBLOCK.
pub const BLOCK_BYTES: usize = 32 * 1024;
/// Bytes of an index entry: plaintext hash followed by ciphertext query hash.
pub const CHK_BYTES: usize = 128;
/// Maximum number of ordered child entries in one IBLOCK.
pub const MAX_CHILDREN: usize = BLOCK_BYTES / CHK_BYTES;
/// XChaCha20-Poly1305 tag appended to the encrypted plaintext.
pub const TAG_BYTES: usize = 16;

/// Untrusted public content-hash key pair. Authenticity is established by open,
/// never by constructing or copying these bytes. Default is zeroed scratch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockKey {
    /// SHA-512 of exact plaintext bytes.
    pub key: [u8; 64],
    /// SHA-512 of exact ciphertext followed by its 16-byte tag.
    pub query: [u8; 64],
}
impl Default for BlockKey {
    fn default() -> Self {
        Self {
            key: [0; 64],
            query: [0; 64],
        }
    }
}
impl BlockKey {
    /// Bind this root key pair to an explicit file byte length for its CHK URI.
    #[must_use]
    pub const fn content(self, size: u64) -> Content {
        Content {
            key: self.key,
            query: self.query,
            size,
        }
    }
}

/// One encoded block borrowing the exact written output prefix.
#[derive(Clone, Copy, Debug)]
pub struct Encoded<'a> {
    key: BlockKey,
    bytes: &'a [u8],
}
impl<'a> Encoded<'a> {
    /// Plaintext key and ciphertext query of this block.
    #[must_use]
    pub const fn key(self) -> BlockKey {
        self.key
    }
    /// Exact ciphertext followed by its detached 16-byte tag.
    #[must_use]
    pub const fn bytes(self) -> &'a [u8] {
        self.bytes
    }
}

struct Material {
    secret: Zeroizing<[u8; 32]>,
    nonce: Zeroizing<[u8; 24]>,
}
fn material(hash: &[u8; 64]) -> Result<Material, Error> {
    let mut key = Zeroizing::new([0; 32]);
    let mut nonce = Zeroizing::new([0; 24]);
    hkdf_gnunet(b"Hash key derivation", hash, &[], key.as_mut())?;
    hkdf_gnunet(
        b"Initialization vector derivation",
        hash,
        &[],
        nonce.as_mut(),
    )?;
    Ok(Material { secret: key, nonce })
}

/// Encode a DBLOCK, including an empty plaintext block. Output capacity refusal
/// leaves the entire buffer unchanged; bytes after the written prefix are kept.
/// No private header, type tag, AAD or padding is introduced.
pub fn encode_data<'a>(plaintext: &[u8], output: &'a mut [u8]) -> Result<Encoded<'a>, Error> {
    if plaintext.len() > BLOCK_BYTES {
        return Err(Error::TooLarge);
    }
    let length = plaintext.len() + TAG_BYTES;
    if output.len() < length {
        return Err(Error::Capacity);
    }
    let key = hash512(plaintext);
    let derived = material(&key)?;
    let target = &mut output[..length];
    target[..plaintext.len()].copy_from_slice(plaintext);
    match xchacha20poly1305_seal(
        &derived.secret,
        &derived.nonce,
        &[],
        &mut target[..plaintext.len()],
    ) {
        Ok(tag) => target[plaintext.len()..].copy_from_slice(&tag),
        Err(error) => {
            target.zeroize();
            return Err(error);
        }
    }
    let query = hash512(target);
    Ok(Encoded {
        key: BlockKey { key, query },
        bytes: target,
    })
}

fn plain_len(ciphertext: &[u8]) -> Result<usize, Error> {
    let length = ciphertext
        .len()
        .checked_sub(TAG_BYTES)
        .ok_or(Error::Truncated)?;
    if length > BLOCK_BYTES {
        return Err(Error::TooLarge);
    }
    Ok(length)
}

/// Authenticate a DBLOCK's query, AEAD tag and plaintext hash before returning
/// borrowed plaintext. Authentication failure wipes its output prefix; capacity
/// and framing errors leave output unchanged. The rest of output is untouched.
pub fn open_data<'a>(
    key: BlockKey,
    ciphertext: &[u8],
    output: &'a mut [u8],
) -> Result<&'a [u8], Error> {
    let length = plain_len(ciphertext)?;
    if output.len() < length {
        return Err(Error::Capacity);
    }
    let target = &mut output[..length];
    if !bool::from(hash512(ciphertext).ct_eq(&key.query)) {
        target.zeroize();
        return Err(Error::Authentication);
    }
    let derived = material(&key.key)?;
    let mut tag = [0; TAG_BYTES];
    tag.copy_from_slice(&ciphertext[length..]);
    target.copy_from_slice(&ciphertext[..length]);
    xchacha20poly1305_open(&derived.secret, &derived.nonce, &[], target, &tag)?;
    if !bool::from(hash512(target).ct_eq(&key.key)) {
        target.zeroize();
        return Err(Error::Authentication);
    }
    Ok(target)
}

/// Encode an IBLOCK with 1..=256 ordered children, retaining duplicates. Scratch
/// holds the raw key/query pairs; no count or type header is serialized. Capacity
/// or child-count rejection leaves both scratch and output unchanged.
pub fn encode_index<'a>(
    children: &[BlockKey],
    scratch: &mut [u8],
    output: &'a mut [u8],
) -> Result<Encoded<'a>, Error> {
    if children.is_empty() || children.len() > MAX_CHILDREN {
        return Err(Error::InvalidInput);
    }
    let length = children.len() * CHK_BYTES;
    if scratch.len() < length || output.len() < length + TAG_BYTES {
        return Err(Error::Capacity);
    }
    let target = &mut scratch[..length];
    for (chunk, child) in target
        .as_chunks_mut::<CHK_BYTES>()
        .0
        .iter_mut()
        .zip(children)
    {
        chunk[..64].copy_from_slice(&child.key);
        chunk[64..].copy_from_slice(&child.query);
    }
    encode_data(target, output)
}

/// An authenticated payload interpreted as ordered child references. The block
/// has no type header or type AAD: the same bytes can also represent file data.
/// File roots select their interpretation using the claimed file length.
#[derive(Clone, Copy, Debug)]
pub struct Index<'a> {
    bytes: &'a [u8],
}
impl<'a> Index<'a> {
    /// Number of ordered child key pairs.
    #[must_use]
    pub const fn len(self) -> usize {
        self.bytes.len() / CHK_BYTES
    }
    /// An authenticated index always has at least one child.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.bytes.is_empty()
    }
    /// Obtain one untrusted child reference. Its data needs separate authentication.
    pub fn key(self, index: usize) -> Result<BlockKey, Error> {
        if index >= self.len() {
            return Err(Error::InvalidInput);
        }
        Ok(read_key(&self.bytes.as_chunks::<CHK_BYTES>().0[index]))
    }
    /// Iterate child references in exact serialized order, including duplicates.
    pub fn keys(self) -> impl ExactSizeIterator<Item = BlockKey> + 'a {
        self.bytes.as_chunks::<CHK_BYTES>().0.iter().map(read_key)
    }
}
fn read_key(bytes: &[u8; CHK_BYTES]) -> BlockKey {
    let mut key = [0; 64];
    let mut query = [0; 64];
    key.copy_from_slice(&bytes[..64]);
    query.copy_from_slice(&bytes[64..128]);
    BlockKey { key, query }
}

/// Open an IBLOCK into caller storage. Require an exact, nonempty sequence of
/// at most256 child entries before touching output; then check all CHK layers.
pub fn open_index<'a>(
    key: BlockKey,
    ciphertext: &[u8],
    output: &'a mut [u8],
) -> Result<Index<'a>, Error> {
    let length = plain_len(ciphertext)?;
    if length == 0 || !length.is_multiple_of(CHK_BYTES) {
        return Err(Error::Malformed);
    }
    open_data(key, ciphertext, output).map(|bytes| Index { bytes })
}
