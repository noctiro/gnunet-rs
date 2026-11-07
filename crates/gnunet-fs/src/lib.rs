//! Official GNUnet FS artifacts and bounded content/directory ownership.
//!
//! CHK identifies content, SKS names a namespace entry, KSK carries keyword terms,
//! and LOC adds a verified peer placement signature. Parsing a signed LOC does
//! not establish that a peer is reachable, still stores the file, or is unexpired.
//! Block retrieval, publication, metadata extraction and native FS services use
//! separate host owners. Default protocol builds require no runtime or heap
//! allocator. The optional `alloc` feature supports bounded larger GAP filters.
//! ```
//! use gnunet_fs::{Content, Limits, Uri};
//! let content = Content { key: [1; 64], query: [2; 64], size: 42 };
//! let mut bytes = [0; 244];
//! let n = content.uri().encode(&mut bytes)?;
//! let parsed = Uri::parse(&bytes[..n], Limits::default())?;
//! assert!(matches!(parsed, Uri::Content(value) if value == content));
//! # Ok::<(), gnunet_types::Error>(())
//! ```
#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod client;
mod codec;
pub mod content;
pub mod directory;
pub mod gap;
mod keywords;
pub mod metadata;
pub mod service;
pub mod ublock;
use codec::{Writer, base32, decimal, decimal_len};
use gnunet_crypto::{EddsaPrivateKey, EddsaPublicKey, EddsaSignature};
use gnunet_types::Error;
use gnunet_wire::official::AbsoluteTime;
pub use keywords::{Keyword, KeywordBytes, Keywords, KeywordsIter};

const PREFIX: &[u8] = b"gnunet://fs/";
/// Exact signature purpose used for the official LOC placement artifact.
pub const PLACEMENT_PURPOSE: u32 = 5;
/// Complete LOC signed-region byte length, including its purpose header.
pub const PLACEMENT_SIGNED_BYTES: usize = 184;

/// Caller-selected parse resource limits. They constrain untrusted input only;
/// explicit constructors borrow their caller-owned data without hidden work.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum complete URI or user-keyword input bytes.
    pub max_input_bytes: usize,
    /// Maximum number of KSK keyword terms, retaining duplicates.
    pub max_keywords: usize,
    /// Maximum decoded payload bytes in any KSK term.
    pub max_keyword_bytes: usize,
    /// Maximum raw SKS identifier bytes.
    pub max_identifier_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_input_bytes: 16_384,
            max_keywords: 256,
            max_keyword_bytes: 8192,
            max_identifier_bytes: 8192,
        }
    }
}

/// A content-hash key and exact file length. The URI carries both public hash
/// values in key/query order; no actual content validation or I/O occurs here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Content {
    /// SHA-512 hash-derived content encryption key.
    pub key: [u8; 64],
    /// SHA-512 content lookup hash.
    pub query: [u8; 64],
    /// Total file length in bytes, including zero and all representable u64 values.
    pub size: u64,
}
impl Content {
    /// Convert this content identifier into its CHK artifact view.
    #[must_use]
    pub const fn uri(self) -> Uri<'static> {
        Uri::Content(self)
    }
}

/// Namespace entry retaining the identifier literally, including empty values,
/// slashes, percent signs and opaque non-UTF-8 bytes. It is not a DNS name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Namespace<'a> {
    key: EddsaPublicKey,
    identifier: &'a [u8],
}
impl<'a> Namespace<'a> {
    /// Borrow a namespace entry; NUL is excluded because it cannot occur in the
    /// official C-string URI artifact. No percent decoding or key authentication.
    pub fn new(key: EddsaPublicKey, identifier: &'a [u8]) -> Result<Self, Error> {
        if identifier.contains(&0) {
            return Err(Error::InvalidInput);
        }
        Ok(Self { key, identifier })
    }
    /// Namespace public-key bytes (not a claim of possession).
    #[must_use]
    pub const fn key(self) -> EddsaPublicKey {
        self.key
    }
    /// Exact identifier bytes after the namespace separator.
    #[must_use]
    pub const fn identifier(self) -> &'a [u8] {
        self.identifier
    }
}

/// Authenticated LOC artifact. Verification establishes the exact signed claim,
/// independently of current time, revocation, network reachability or file presence.
/// A reference-permissive parsed timestamp can wrap to non-whole microseconds;
/// canonical URI encoding rejects that state to preserve the signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Location {
    content: Content,
    peer: EddsaPublicKey,
    signature: EddsaSignature,
    expiration: AbsoluteTime,
}
impl Location {
    /// Assemble the exact official purpose-prefixed signed bytes. File length
    /// precedes key/query in this region even though URI text prints hashes first.
    #[must_use]
    pub fn signing_region(
        content: Content,
        peer: EddsaPublicKey,
        expiration: AbsoluteTime,
    ) -> [u8; PLACEMENT_SIGNED_BYTES] {
        let mut out = [0; PLACEMENT_SIGNED_BYTES];
        out[..4].copy_from_slice(&(PLACEMENT_SIGNED_BYTES as u32).to_be_bytes());
        out[4..8].copy_from_slice(&PLACEMENT_PURPOSE.to_be_bytes());
        out[8..16].copy_from_slice(&expiration.as_micros().to_be_bytes());
        out[16..24].copy_from_slice(&content.size.to_be_bytes());
        out[24..88].copy_from_slice(&content.key);
        out[88..152].copy_from_slice(&content.query);
        out[152..184].copy_from_slice(peer.as_bytes());
        out
    }
    /// Sign with an explicit pure key capability and explicit expiration. As in
    /// official construction, expiration is rounded down to complete seconds.
    pub fn sign(
        content: Content,
        signer: &EddsaPrivateKey,
        expiration: AbsoluteTime,
    ) -> Result<Self, Error> {
        let expiration = AbsoluteTime::from_micros(expiration.as_micros() / 1_000_000 * 1_000_000);
        let peer = signer.public_key();
        let signature = signer.sign(
            PLACEMENT_PURPOSE,
            &Self::signing_region(content, peer, expiration),
        )?;
        Ok(Self {
            content,
            peer,
            signature,
            expiration,
        })
    }
    /// Authenticate a separately obtained signature. Whole-second expiration is
    /// required so the standard textual artifact preserves its signed timestamp.
    /// No clock is sampled and an expired signature is still an authentic claim.
    pub fn from_signed(
        content: Content,
        peer: EddsaPublicKey,
        signature: EddsaSignature,
        expiration: AbsoluteTime,
    ) -> Result<Self, Error> {
        if !expiration.as_micros().is_multiple_of(1_000_000) {
            return Err(Error::InvalidInput);
        }
        Self::verified(content, peer, signature, expiration)
    }
    fn verified(
        content: Content,
        peer: EddsaPublicKey,
        signature: EddsaSignature,
        expiration: AbsoluteTime,
    ) -> Result<Self, Error> {
        peer.verify(
            PLACEMENT_PURPOSE,
            &Self::signing_region(content, peer, expiration),
            &signature,
        )?;
        Ok(Self {
            content,
            peer,
            signature,
            expiration,
        })
    }
    /// Exact authenticated CHK content and file length.
    #[must_use]
    pub const fn content(self) -> Content {
        self.content
    }
    /// Exact authenticated peer identity.
    #[must_use]
    pub const fn peer(self) -> EddsaPublicKey {
        self.peer
    }
    /// Ordinary Ed25519 signature over the complete 184-byte region.
    #[must_use]
    pub const fn signature(self) -> EddsaSignature {
        self.signature
    }
    /// Authenticated expiration in microseconds. Callers decide current validity.
    #[must_use]
    pub const fn expiration(self) -> AbsoluteTime {
        self.expiration
    }
}

/// One validated public FS URI. Variable-sized fields remain borrowed from the
/// original input or caller-provided keyword list; no OS, allocator or C FFI.
#[derive(Clone, Copy, Debug)]
pub enum Uri<'a> {
    /// Content-hash-key file artifact.
    Content(Content),
    /// Signed-key-space namespace entry (the name itself is unsigned).
    Namespace(Namespace<'a>),
    /// Keyword search artifact; no search is issued.
    Keywords(Keywords<'a>),
    /// Verified peer placement claim.
    Location(Location),
}
impl<'a> Uri<'a> {
    /// Parse with explicit work/storage bounds. Scheme/type spelling is exact.
    /// Crockford aliases and padding, literal SKS identifiers and the pinned
    /// parser's unsigned numeric-prefix behavior are preserved. KSK percent
    /// escapes require two hexadecimal digits; unsafe/truncated scanf inputs
    /// are rejected rather than emulating C reads beyond the supplied string.
    /// Optional empty KSK payloads and raw double quotes are rejected because
    /// their permissive C representations can lose a term or change its payload
    /// on canonical round-trip.
    /// A marker-only mandatory term is preserved and encodes as `%2B`.
    pub fn parse(input: &'a [u8], limits: Limits) -> Result<Self, Error> {
        if input.len() > limits.max_input_bytes {
            return Err(Error::Capacity);
        }
        if input.contains(&0) {
            return Err(Error::Malformed);
        }
        let tail = input.strip_prefix(PREFIX).ok_or(Error::Malformed)?;
        if let Some(body) = tail.strip_prefix(b"chk/") {
            return Ok(Self::Content(content(body)?));
        }
        if let Some(body) = tail.strip_prefix(b"sks/") {
            let (name, id) = separate(body, b'/')?;
            if id.len() > limits.max_identifier_bytes {
                return Err(Error::Capacity);
            }
            return Ok(Self::Namespace(Namespace {
                key: EddsaPublicKey::from_bytes(base32(name)?),
                identifier: id,
            }));
        }
        if let Some(body) = tail.strip_prefix(b"ksk/") {
            return Keywords::parse(body, limits).map(Self::Keywords);
        }
        if let Some(body) = tail.strip_prefix(b"loc/") {
            let fixed = body.get(..208).ok_or(Error::Malformed)?;
            let rest = body.get(208..).ok_or(Error::Malformed)?;
            let (size, rest) = separate(rest, b'.')?;
            let (peer, rest) = separate(rest, b'.')?;
            let (signature, expiry) = separate(rest, b'.')?;
            let content = Content {
                key: base32(&fixed[..103])?,
                query: base32(&fixed[104..207])?,
                size: decimal(size)?,
            };
            if fixed[103] != b'.' || fixed[207] != b'.' {
                return Err(Error::Malformed);
            }
            let expiration = AbsoluteTime::from_micros(decimal(expiry)?.wrapping_mul(1_000_000));
            return Location::verified(
                content,
                EddsaPublicKey::from_bytes(base32(peer)?),
                EddsaSignature::from_bytes(base32(signature)?),
                expiration,
            )
            .map(Self::Location);
        }
        Err(Error::Unsupported)
    }
    /// Exact number of bytes in the canonical C-compatible textual representation,
    /// without a terminating NUL. Noncanonical numeric suffixes are normalized.
    /// Returns `InvalidInput` for an authenticated LOC timestamp that cannot be
    /// expressed in whole seconds without changing the signed microseconds.
    pub fn encoded_len(self) -> Result<usize, Error> {
        let tail = match self {
            Self::Content(c) => 208 + decimal_len(c.size),
            Self::Namespace(n) => 53_usize
                .checked_add(n.identifier.len())
                .ok_or(Error::Overflow)?,
            Self::Keywords(k) => k.encoded_len()?,
            Self::Location(l) => {
                if !l.expiration.as_micros().is_multiple_of(1_000_000) {
                    return Err(Error::InvalidInput);
                }
                208 + decimal_len(l.content.size)
                    + 158
                    + decimal_len(l.expiration.as_micros() / 1_000_000)
            }
        };
        tail.checked_add(PREFIX.len() + 4).ok_or(Error::Overflow)
    }
    /// Write the complete URI after preflighting capacity, without a NUL terminator.
    /// Any error leaves the output unchanged. LOC expiration uses whole seconds;
    /// an authenticated wrapped timestamp that cannot retain its signature in
    /// that representation is rejected with `InvalidInput` before writing.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let length = self.encoded_len()?;
        if output.len() < length {
            return Err(Error::Capacity);
        }
        let mut w = Writer::new(&mut output[..length]);
        w.put(PREFIX);
        match self {
            Self::Content(c) => {
                w.put(b"chk/");
                write_content(c, &mut w);
            }
            Self::Namespace(n) => {
                w.put(b"sks/");
                w.encoded(n.key.as_bytes());
                w.byte(b'/');
                w.put(n.identifier);
            }
            Self::Keywords(k) => {
                w.put(b"ksk/");
                k.encode(&mut w);
            }
            Self::Location(l) => {
                w.put(b"loc/");
                write_content(l.content, &mut w);
                w.byte(b'.');
                w.encoded(l.peer.as_bytes());
                w.byte(b'.');
                w.encoded(l.signature.as_bytes());
                w.byte(b'.');
                w.decimal(l.expiration.as_micros() / 1_000_000);
            }
        }
        Ok(length)
    }
}
fn separate(input: &[u8], separator: u8) -> Result<(&[u8], &[u8]), Error> {
    let p = input
        .iter()
        .position(|b| *b == separator)
        .ok_or(Error::Malformed)?;
    Ok((&input[..p], &input[p + 1..]))
}
fn content(body: &[u8]) -> Result<Content, Error> {
    if body.get(103) != Some(&b'.') || body.get(207) != Some(&b'.') {
        return Err(Error::Malformed);
    }
    Ok(Content {
        key: base32(body.get(..103).ok_or(Error::Malformed)?)?,
        query: base32(body.get(104..207).ok_or(Error::Malformed)?)?,
        size: decimal(body.get(208..).ok_or(Error::Malformed)?)?,
    })
}
fn write_content(c: Content, w: &mut Writer<'_>) {
    w.encoded(&c.key);
    w.byte(b'.');
    w.encoded(&c.query);
    w.byte(b'.');
    w.decimal(c.size);
}
