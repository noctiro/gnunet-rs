//! Official keyword/namespace UBLOCK artifacts over caller-owned storage.
//! Derived signatures, queries and AEAD do not imply lookup, availability,
//! namespace freshness or durable publication. Labels remain exact raw bytes.
use crate::{Uri, metadata};
use gnunet_crypto::{
    gns::{self, EdkeyDerivedSecret, EdkeySecret},
    hash512, hkdf_gnunet,
};
use gnunet_session_crypto::aead::{xchacha20poly1305_open, xchacha20poly1305_seal};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// Official FS UBLOCK signature purpose.
pub const PURPOSE: u32 = 17;
/// Signature64 + purpose8 + verification-key32.
pub const HEADER_BYTES: usize = 104;
/// Detached XChaCha20Poly1305 tag, appended to the ciphertext.
pub const TAG_BYTES: usize = 16;
/// Original publisher's header+plaintext budget before adding the MAC.
pub const PUBLISHER_BYTES: usize = 60 * 1024;
/// The C publisher adds its MAC after its60KiB cap. Caller wire policy can be
/// stricter; no private padding is inserted to imitate C search stack tails.
pub const DEFAULT_WIRE_BYTES: usize = PUBLISHER_BYTES + TAG_BYTES;
const CONTEXT: &[u8] = b"fs-ublock";

/// Explicit search interpretation; it is not an extra field on the wire.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// Anonymous namespace, one raw keyword and an empty update identifier.
    Keyword,
    /// Caller-supplied namespace and identifier, with optional update identifier.
    Namespace,
}
/// Resource bounds, distinct from C reader permissiveness and metadata policy.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Complete signature/header/ciphertext/tag bytes accepted or emitted.
    pub max_wire_bytes: usize,
    /// Maximum exact label bytes used by public/signing/encryption derivations.
    pub max_label_bytes: usize,
    /// URI parsing/signature limits after authentication.
    pub uri: crate::Limits,
    /// Optional metadata decoding and decompression bounds.
    pub metadata: metadata::Limits,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_wire_bytes: DEFAULT_WIRE_BYTES,
            max_label_bytes: 4096,
            uri: crate::Limits::default(),
            metadata: metadata::Limits::default(),
        }
    }
}
/// UBLOCK failures retain their URI/metadata/cryptographic cause.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// An exact C-string label contains NUL.
    Label,
    /// Update identifier contains NUL or a keyword producer supplied an update.
    Update,
    /// A mandatory header/token/tag is truncated or its declared size differs.
    Framing,
    /// Explicit wire/label or official publisher budget exceeded.
    Limit,
    /// Caller output or plaintext storage is too small.
    Capacity,
    /// Checked length representation failed.
    Overflow,
    /// Namespace, label, query or derived verification key differs.
    Authentication,
    /// A raw v1-null marker is not a present optional metadata value.
    NullMetadata,
    /// Signature, public derivation, KDF or actual AEAD refused.
    Crypto(gnunet_types::Error),
    /// Authenticated URI bytes failed the real URI parser/encoder.
    Uri(gnunet_types::Error),
    /// The real metadata codec/planner refused.
    Metadata(metadata::Error),
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ublock {self:?}")
    }
}
impl core::error::Error for Error {}

/// Signed block whose exact purpose, signature and expected query were checked.
/// It does not assert that a caller knows the namespace/label or decrypted it.
pub struct VerifiedBlock<'a> {
    bytes: &'a [u8],
    query: [u8; 64],
}
impl VerifiedBlock<'_> {
    /// Complete original wire bytes.
    #[must_use]
    pub const fn bytes(&self) -> &[u8] {
        self.bytes
    }
    /// Hash of the original derived verification key.
    #[must_use]
    pub const fn query(&self) -> &[u8; 64] {
        &self.query
    }
}
/// Validate the complete official BLOCK FS UBLOCK envelope, including signed
/// empty payloads. This verifies purpose/size/signature and hash(verification
/// key); encrypted artifact interpretation may impose stricter payload bounds.
pub fn verify_envelope(block: &[u8], query: &[u8; 64]) -> Result<(), gnunet_types::Error> {
    if block.len() < 104 {
        return Err(gnunet_types::Error::Malformed);
    }
    let size = u32::from_be_bytes(
        block[64..68]
            .try_into()
            .map_err(|_| gnunet_types::Error::Malformed)?,
    ) as usize;
    let purpose = u32::from_be_bytes(
        block[68..72]
            .try_into()
            .map_err(|_| gnunet_types::Error::Malformed)?,
    );
    if size.checked_add(64) != Some(block.len()) || purpose != crate::ublock::PURPOSE {
        return Err(gnunet_types::Error::Malformed);
    }
    let public: &[u8; 32] = block[72..104]
        .try_into()
        .map_err(|_| gnunet_types::Error::Malformed)?;
    if !bool::from(hash512(public).ct_eq(query)) {
        return Err(gnunet_types::Error::Authentication);
    }
    let signature: &[u8; 64] = block[..64]
        .try_into()
        .map_err(|_| gnunet_types::Error::Malformed)?;
    gns::verify_edkey(public, crate::ublock::PURPOSE, &[&block[64..]], signature)
}

/// Check the original plugin's purpose/size/signature and an exact expected
/// query before any plaintext is written. max_wire_bytes is a caller bound.
pub fn verify_block<'a>(
    wire: &'a [u8],
    expected_query: &[u8; 64],
    max_wire_bytes: usize,
) -> Result<VerifiedBlock<'a>, Error> {
    if wire.len() > max_wire_bytes {
        return Err(Error::Limit);
    }
    if wire.len() < HEADER_BYTES + TAG_BYTES + 2 {
        return Err(Error::Framing);
    }
    let size = u32::try_from(wire.len() - 64).map_err(|_| Error::Overflow)?;
    if wire[64..68] != size.to_be_bytes() || wire[68..72] != PURPOSE.to_be_bytes() {
        return Err(Error::Framing);
    }
    let public: &[u8; 32] = wire[72..104].try_into().map_err(|_| Error::Framing)?;
    let signature: &[u8; 64] = wire[..64].try_into().map_err(|_| Error::Framing)?;
    let query = hash512(public);
    if !bool::from(query.ct_eq(expected_query)) {
        return Err(Error::Authentication);
    }
    gns::verify_edkey(public, PURPOSE, &[&wire[64..]], signature).map_err(Error::Crypto)?;
    Ok(VerifiedBlock { bytes: wire, query })
}
struct Material {
    key: Zeroizing<[u8; 32]>,
    nonce: Zeroizing<[u8; 24]>,
}
fn material(namespace: &[u8; 32], label: &[u8]) -> Result<Material, Error> {
    let mut hash = Zeroizing::new([0; 64]);
    hkdf_gnunet(b"UBLOCK-ENC", label, &[namespace], hash.as_mut()).map_err(Error::Crypto)?;
    let mut key = Zeroizing::new([0; 32]);
    let mut nonce = Zeroizing::new([0; 24]);
    hkdf_gnunet(b"Hash key derivation", hash.as_ref(), &[], key.as_mut()).map_err(Error::Crypto)?;
    hkdf_gnunet(
        b"Initialization vector derivation",
        hash.as_ref(),
        &[],
        nonce.as_mut(),
    )
    .map_err(Error::Crypto)?;
    Ok(Material { key, nonce })
}
fn anonymous() -> EdkeySecret {
    let mut seed = Zeroizing::new([0; 32]);
    seed[0] = 1;
    EdkeySecret::from_seed(*seed)
}
/// One prepared namespace/label context. Derived material is computed once,
/// retained without allocation and erased on drop. No normalization is applied.
pub struct Context<'a> {
    namespace: [u8; 32],
    label: &'a [u8],
    public: [u8; 32],
    query: [u8; 64],
    material: Material,
    kind: Kind,
    limits: Limits,
}
impl<'a> Context<'a> {
    fn from_public(
        namespace: [u8; 32],
        label: &'a [u8],
        public: [u8; 32],
        kind: Kind,
        limits: Limits,
    ) -> Result<Self, Error> {
        if label.len() > limits.max_label_bytes {
            return Err(Error::Limit);
        }
        if label.contains(&0) {
            return Err(Error::Label);
        }
        Ok(Self {
            namespace,
            label,
            public,
            query: hash512(&public),
            material: material(&namespace, label)?,
            kind,
            limits,
        })
    }
    /// Prepare a namespace lookup using its ordinary public key and raw label.
    pub fn namespace(namespace: &[u8; 32], label: &'a [u8], limits: Limits) -> Result<Self, Error> {
        if label.len() > limits.max_label_bytes {
            return Err(Error::Limit);
        }
        if label.contains(&0) {
            return Err(Error::Label);
        }
        let public = gns::derive_public_bytes(namespace, label, CONTEXT).map_err(Error::Crypto)?;
        Self::from_public(*namespace, label, public, Kind::Namespace, limits)
    }
    /// Prepare the exact official anonymous keyword namespace (`seed[0]=1`).
    pub fn keyword(label: &'a [u8], limits: Limits) -> Result<Self, Error> {
        let mut context = Self::namespace(&anonymous().public_key(), label, limits)?;
        context.kind = Kind::Keyword;
        Ok(context)
    }
    /// Expected query for datastore/search owners.
    #[must_use]
    pub const fn query(&self) -> &[u8; 64] {
        &self.query
    }
    /// Exact derived signing public key.
    #[must_use]
    pub const fn verification_key(&self) -> &[u8; 32] {
        &self.public
    }
    /// Original namespace public key; not the blinded signing key.
    #[must_use]
    pub const fn namespace_key(&self) -> &[u8; 32] {
        &self.namespace
    }
    /// Original raw label, without an implicit UTF8 or NFC requirement.
    #[must_use]
    pub const fn label(&self) -> &'a [u8] {
        self.label
    }
    /// Verify query, derived key and signature before AEAD/decryption. Framing,
    /// signature/query and capacity refusals preserve plaintext output. A bad
    /// AEAD tag wipes its written prefix. Returned plaintext is authenticated;
    /// decode separately for URI/metadata syntax and capacity retry.
    pub fn open<'p>(&self, wire: &[u8], plaintext: &'p mut [u8]) -> Result<Plaintext<'p>, Error> {
        let block = verify_block(wire, &self.query, self.limits.max_wire_bytes)?;
        if !bool::from(wire[72..104].ct_eq(&self.public)) {
            return Err(Error::Authentication);
        }
        let length = block.bytes.len() - HEADER_BYTES - TAG_BYTES;
        if plaintext.len() < length {
            return Err(Error::Capacity);
        }
        let target = &mut plaintext[..length];
        target.copy_from_slice(&wire[HEADER_BYTES..wire.len() - TAG_BYTES]);
        let tag: &[u8; TAG_BYTES] = wire[wire.len() - TAG_BYTES..]
            .try_into()
            .map_err(|_| Error::Framing)?;
        xchacha20poly1305_open(&self.material.key, &self.material.nonce, &[], target, tag)
            .map_err(Error::Crypto)?;
        Ok(Plaintext {
            bytes: target,
            query: self.query,
            kind: self.kind,
            limits: self.limits,
        })
    }
}
/// Prepared decryption material that owns no label borrow. It can be retained
/// by a native multi-query search without borrowing that search's label storage.
/// Construction performs the ordinary official Context derivation once; wire
/// validation, AEAD and plaintext interpretation are identical to Context::open.
pub struct Opener(Context<'static>);
impl Context<'_> {
    /// Keep derived public/symmetric material while releasing the source label
    /// borrow. The opener does not retain or expose a replacement label.
    #[must_use]
    pub fn into_opener(self) -> Opener {
        Opener(Context {
            namespace: self.namespace,
            label: &[],
            public: self.public,
            query: self.query,
            material: self.material,
            kind: self.kind,
            limits: self.limits,
        })
    }
}
impl Opener {
    /// Original authenticated lookup query.
    #[must_use]
    pub const fn query(&self) -> &[u8; 64] {
        &self.0.query
    }
    /// Original namespace public key (the official anonymous key for keywords).
    #[must_use]
    pub const fn namespace_key(&self) -> &[u8; 32] {
        &self.0.namespace
    }
    /// Selected keyword or namespace interpretation.
    #[must_use]
    pub const fn kind(&self) -> Kind {
        self.0.kind
    }
    /// Authenticate and decrypt with the same original Context implementation.
    pub fn open<'p>(&self, wire: &[u8], plaintext: &'p mut [u8]) -> Result<Plaintext<'p>, Error> {
        self.0.open(wire, plaintext)
    }
}
/// Authenticated plaintext, kept separate from URI/metadata interpretation so a
/// metadata capacity retry does not repeat signature verification or decryption.
pub struct Plaintext<'a> {
    bytes: &'a [u8],
    query: [u8; 64],
    kind: Kind,
    limits: Limits,
}
impl Plaintext<'_> {
    /// Exact authenticated update-NUL/URI-NUL/optional-metadata bytes; no MAC tail.
    #[must_use]
    pub const fn bytes(&self) -> &[u8] {
        self.bytes
    }
    /// Original verified lookup query, for the owner's request correlation.
    #[must_use]
    pub const fn query(&self) -> &[u8; 64] {
        &self.query
    }
    /// Parse exact C-string fields and optional metadata using a real explicit
    /// inflater. Absence differs from present-empty v2; v1-null refuses. Prefix
    /// mode remains visible in Metadata::is_complete/recovery. Scratch follows
    /// metadata's documented failure wiping; authenticated plaintext is retained.
    pub fn decode<'a>(
        &'a self,
        scratch: &'a mut [u8],
        inflater: &mut impl metadata::Inflater,
        mode: metadata::Mode,
    ) -> Result<Record<'a>, Error> {
        let first = self
            .bytes
            .iter()
            .position(|b| *b == 0)
            .ok_or(Error::Framing)?;
        if self.kind == Kind::Keyword && first != 0 {
            return Err(Error::Update);
        }
        let rest = &self.bytes[first + 1..];
        let uri_end = rest.iter().position(|b| *b == 0).ok_or(Error::Framing)?;
        let raw_uri = &rest[..uri_end];
        let _ = Uri::parse(raw_uri, self.limits.uri).map_err(Error::Uri)?;
        let raw_metadata = &rest[uri_end + 1..];
        let metadata = if raw_metadata.is_empty() {
            None
        } else {
            match metadata::decode(raw_metadata, scratch, inflater, self.limits.metadata, mode)
                .map_err(Error::Metadata)?
            {
                metadata::Decoded::NullMarker => return Err(Error::NullMetadata),
                metadata::Decoded::Present(value) => Some(value),
            }
        };
        Ok(Record {
            update: &self.bytes[..first],
            raw_uri,
            raw_metadata,
            metadata,
            query: self.query,
            kind: self.kind,
            uri_limits: self.limits.uri,
        })
    }
}
/// Authenticated and parsed record; child URI content and output remain separate.
pub struct Record<'a> {
    update: &'a [u8],
    raw_uri: &'a [u8],
    raw_metadata: &'a [u8],
    metadata: Option<metadata::Metadata<'a>>,
    query: [u8; 64],
    kind: Kind,
    uri_limits: crate::Limits,
}
impl<'a> Record<'a> {
    /// Original verified lookup query; a record from another request differs.
    #[must_use]
    pub const fn query(&self) -> &[u8; 64] {
        &self.query
    }
    /// Explicit interpretation selected by the authenticated lookup context.
    #[must_use]
    pub const fn kind(&self) -> Kind {
        self.kind
    }
    /// Raw update identifier without NUL; empty means no update link.
    #[must_use]
    pub const fn update_identifier(&self) -> &'a [u8] {
        self.update
    }
    /// Exact authenticated URI bytes, before optional canonicalization.
    #[must_use]
    pub const fn raw_uri(&self) -> &'a [u8] {
        self.raw_uri
    }
    /// Reparse the URI when needed, explicitly repeating any LOC signature work.
    pub fn uri(&self) -> Result<Uri<'a>, Error> {
        Uri::parse(self.raw_uri, self.uri_limits).map_err(Error::Uri)
    }
    /// Exact original optional metadata artifact; empty means absent.
    #[must_use]
    pub const fn raw_metadata(&self) -> &'a [u8] {
        self.raw_metadata
    }
    /// Present decoded metadata, retaining explicit prefix status; None is absent.
    #[must_use]
    pub const fn metadata(&self) -> Option<metadata::Metadata<'a>> {
        self.metadata
    }
}
/// Prepared publisher over an explicitly held original namespace signing key.
/// Scalar, nonce prefix and symmetric material are erased when this owner drops.
pub struct Publisher<'a> {
    context: Context<'a>,
    signer: EdkeyDerivedSecret,
}
impl<'a> Publisher<'a> {
    fn new(
        secret: &EdkeySecret,
        label: &'a [u8],
        kind: Kind,
        limits: Limits,
    ) -> Result<Self, Error> {
        if label.len() > limits.max_label_bytes {
            return Err(Error::Limit);
        }
        if label.contains(&0) {
            return Err(Error::Label);
        }
        let signer = secret.derive_bytes(label, CONTEXT).map_err(Error::Crypto)?;
        let context = Context::from_public(
            secret.public_key(),
            label,
            signer.public_key(),
            kind,
            limits,
        )?;
        Ok(Self { context, signer })
    }
    /// Prepare exact namespace signing/encryption without reading a key file.
    pub fn namespace(secret: &EdkeySecret, label: &'a [u8], limits: Limits) -> Result<Self, Error> {
        Self::new(secret, label, Kind::Namespace, limits)
    }
    /// Prepare the normal anonymous keyword signer.
    pub fn keyword(label: &'a [u8], limits: Limits) -> Result<Self, Error> {
        Self::new(&anonymous(), label, Kind::Keyword, limits)
    }
    /// Matching lookup/decryption context.
    #[must_use]
    pub const fn context(&self) -> &Context<'a> {
        &self.context
    }
    /// Exact metadata wire budget for a real Full/PART metadata planner. This
    /// never truncates labels, identifiers, URIs or silently selects metadata.
    pub fn metadata_budget(&self, update: &[u8], uri: Uri<'_>) -> Result<usize, Error> {
        if update.len() > PUBLISHER_BYTES {
            return Err(Error::Limit);
        }
        if update.contains(&0) || (self.context.kind == Kind::Keyword && !update.is_empty()) {
            return Err(Error::Update);
        }
        let uri_len = uri.encoded_len().map_err(Error::Uri)?;
        let fixed = HEADER_BYTES
            .checked_add(update.len())
            .and_then(|n| n.checked_add(2))
            .and_then(|n| n.checked_add(uri_len))
            .ok_or(Error::Overflow)?;
        let publisher = PUBLISHER_BYTES.checked_sub(fixed).ok_or(Error::Limit)?;
        let caller = self
            .context
            .limits
            .max_wire_bytes
            .checked_sub(fixed.checked_add(TAG_BYTES).ok_or(Error::Overflow)?)
            .ok_or(Error::Limit)?;
        Ok(publisher.min(caller))
    }
    /// Emit one complete ordinary block. None metadata preserves absence; an
    /// empty real Plan emits present-empty v2. A local PART selection is returned
    /// in Sealed::metadata_selection. All input/capacity errors preflight output;
    /// a later cryptographic failure wipes its written prefix. Tail is untouched.
    pub fn seal<'o>(
        &self,
        update: &[u8],
        uri: Uri<'_>,
        metadata: Option<&metadata::Plan<'_>>,
        output: &'o mut [u8],
    ) -> Result<Sealed<'o>, Error> {
        let budget = self.metadata_budget(update, uri)?;
        let selection = metadata.map(metadata::Plan::report);
        let md_len = selection.map_or(0, |report| report.wire_bytes);
        if md_len > budget {
            return Err(Error::Limit);
        }
        let uri_len = uri.encoded_len().map_err(Error::Uri)?;
        let length = HEADER_BYTES + update.len() + 2 + uri_len + md_len + TAG_BYTES;
        if output.len() < length {
            return Err(Error::Capacity);
        }
        let target = &mut output[..length];
        let result = (|| {
            target[..HEADER_BYTES].fill(0);
            let mut at = HEADER_BYTES;
            target[at..at + update.len()].copy_from_slice(update);
            at += update.len();
            target[at] = 0;
            at += 1;
            uri.encode(&mut target[at..at + uri_len])
                .map_err(Error::Uri)?;
            at += uri_len;
            target[at] = 0;
            at += 1;
            if let Some(plan) = metadata {
                plan.write(&mut target[at..at + md_len])
                    .map_err(Error::Metadata)?;
            }
            let end = length - TAG_BYTES;
            let tag = xchacha20poly1305_seal(
                &self.context.material.key,
                &self.context.material.nonce,
                &[],
                &mut target[HEADER_BYTES..end],
            )
            .map_err(Error::Crypto)?;
            target[end..].copy_from_slice(&tag);
            let signed = u32::try_from(length - 64).map_err(|_| Error::Overflow)?;
            target[64..68].copy_from_slice(&signed.to_be_bytes());
            target[68..72].copy_from_slice(&PURPOSE.to_be_bytes());
            target[72..104].copy_from_slice(&self.context.public);
            let signature = self
                .signer
                .sign(PURPOSE, &[&target[64..]])
                .map_err(Error::Crypto)?;
            target[..64].copy_from_slice(&signature);
            Ok(())
        })();
        if let Err(error) = result {
            target.zeroize();
            return Err(error);
        }
        Ok(Sealed {
            bytes: target,
            query: self.context.query,
            selection,
        })
    }
}
/// Complete actual wire artifact and its exact explicit metadata selection.
pub struct Sealed<'a> {
    bytes: &'a [u8],
    query: [u8; 64],
    selection: Option<metadata::Report>,
}
impl Sealed<'_> {
    /// Complete signature/purpose/key/ciphertext/tag bytes.
    #[must_use]
    pub const fn bytes(&self) -> &[u8] {
        self.bytes
    }
    /// Actual datastore lookup key derived from the original signing public key.
    #[must_use]
    pub const fn query(&self) -> &[u8; 64] {
        &self.query
    }
    /// Exact local metadata PART/Full report; None means metadata was absent.
    #[must_use]
    pub const fn metadata_selection(&self) -> Option<metadata::Report> {
        self.selection
    }
}
