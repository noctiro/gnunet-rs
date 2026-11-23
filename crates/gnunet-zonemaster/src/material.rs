//! Real official normalization/serialization/sealing. No secret Debug/hash ID.
use alloc::{sync::Arc, vec::Vec};
use core::{
    fmt,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT_MATERIAL: AtomicU64 = AtomicU64::new(0);
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct Origin(u64);
fn origin() -> Result<Origin, Error> {
    Ok(Origin(
        NEXT_MATERIAL
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| Error::Overflow)?
            .checked_add(1)
            .ok_or(Error::Overflow)?,
    ))
}
use crate::projection::{self, EMPTY_RECORD, Lane, Source, Values};
pub use crate::projection::{Input, Limits};
use gnunet_gnscrypto::ZoneSecret;
use gnunet_gnsrecord::{RecordData, RecordType, ZoneKey};
use gnunet_identity::SecretKey;
use gnunet_types::Error;
use zeroize::Zeroizing;

/// Actual destinations selected by the allocated publication scheduler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Destinations {
    /// Prepare only the public projection when NAMECACHE is disabled.
    PublicOnly,
    /// Also prepare the complete authoritative local NAMECACHE view.
    PublicAndLocal,
}

impl From<Destinations> for projection::Destinations {
    fn from(destinations: Destinations) -> Self {
        match destinations {
            Destinations::PublicOnly => Self::PublicOnly,
            Destinations::PublicAndLocal => Self::PublicAndLocal,
        }
    }
}
struct Rdata {
    bytes: Arc<Zeroizing<Vec<u8>>>,
    expiration: u64,
}
fn shared_rdata(public: &Option<Rdata>, local: &Option<Rdata>) -> bool {
    matches!((public, local), (Some(p), Some(l)) if Arc::ptr_eq(&p.bytes, &l.bytes))
}
/// Sensitive worker material for at least one actual selected output. No ordinary
/// Clone/Serialize/secret Debug; retained secret/plaintext/label bytes erase.
pub struct Prepared {
    origin: Origin,
    key: SecretKey,
    label: Zeroizing<Vec<u8>>,
    public: Option<Rdata>,
    local: Option<Rdata>,
    public_count: usize,
    private_records: bool,
    min_relative: Option<u64>,
}
impl fmt::Debug for Prepared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Prepared")
            .field("public_count", &self.public_count)
            .field("contents", &"[REDACTED]")
            .finish()
    }
}
fn reserve<T>(n: usize) -> Result<Vec<T>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Error::Capacity)?;
    Ok(v)
}
fn bytes(input: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut v = reserve(input.len())?;
    v.extend_from_slice(input);
    Ok(Zeroizing::new(v))
}
fn serialize(records: &[RecordData<'_>], max: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    let n = gnunet_gnsrecord::serialized_len(records)?;
    if n > max {
        return Err(Error::Capacity);
    }
    let mut out = Zeroizing::new(reserve(n)?);
    out.resize(n, 0);
    gnunet_gnsrecord::serialize_to_size(records, &mut out)?;
    Ok(out)
}
/// Prepare only the selected destinations at one coherent source time, before
/// worker queuing. Relative times convert once here, never at late signing.
/// PublicOnly retains no full local RDATA and returns None when no public output
/// exists, without retaining a worker key or minting a material origin. None
/// still participates in the caller's original supersession/retirement path.
pub fn prepare(
    input: Input<'_>,
    now: u64,
    limits: Limits,
    critical: fn(RecordType) -> bool,
    destinations: Destinations,
) -> Result<Option<Prepared>, Error> {
    projection::validate_input(&input, limits, now)?;
    let mut scalars = Zeroizing::new(reserve(4096)?);
    scalars.resize(4096, '\0');
    let mut canonical = Zeroizing::new(reserve(limits.label_bytes)?);
    canonical.resize(limits.label_bytes, 0);
    projection::canonical_label(input.label, &mut scalars, &mut canonical)?;
    let count = input.records.len();
    let mut source = reserve(count)?;
    source.resize(count, EMPTY_RECORD);
    let Some(source) = Source::read(&input, now, destinations.into(), &mut source)? else {
        return Ok(None);
    };
    let mut indices = reserve(count)?;
    indices.resize(count, 0);
    let mut projected = reserve(count)?;
    projected.resize(count, EMPTY_RECORD);
    let (public, public_count, mut min_relative) =
        match source.project(Lane::Public, &mut projected, &mut indices, critical)? {
            Some(selected) => (
                Some(Rdata {
                    expiration: selected.expiration,
                    bytes: Arc::new(serialize(selected.records, limits.plaintext_bytes)?),
                }),
                selected.records.len(),
                selected.minimum_relative,
            ),
            None => (None, 0, None),
        };
    let (local, private_records) = if destinations == Destinations::PublicAndLocal {
        let selected = source
            .project(Lane::Local, &mut projected, &mut indices, critical)?
            .ok_or(Error::Conflict)?;
        min_relative = selected.minimum_relative;
        let serialized = serialize(selected.records, limits.plaintext_bytes)?;
        let data = if let Some(p) = &public
            && p.bytes.as_ref().as_slice() == serialized.as_slice()
        {
            p.bytes.clone()
        } else {
            Arc::new(serialized)
        };
        (
            Some(Rdata {
                bytes: data,
                expiration: selected.expiration,
            }),
            selected.private,
        )
    } else {
        (None, false)
    };
    if public.is_none() && local.is_none() {
        return Ok(None);
    }
    Ok(Some(Prepared {
        origin: origin()?,
        key: SecretKey::from_serialized(input.zone.expose_serialized())?,
        label: bytes(input.label)?,
        public,
        local,
        public_count,
        private_records,
        min_relative,
    }))
}
/// Public-only publish product. Construction is private to the real worker.
/// A DHT port accepts this type and has no method accepting LocalCache.
pub struct PublicPublication {
    bytes: Arc<Zeroizing<Vec<u8>>>,
    query: [u8; 64],
    zone: ZoneKey,
    expires: u64,
}
impl fmt::Debug for PublicPublication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicPublication")
            .field("bytes", &self.bytes.len())
            .field("expires", &self.expires)
            .finish_non_exhaustive()
    }
}
impl PublicPublication {
    /// Complete official signed/encrypted public block.
    pub fn bytes(&self) -> &[u8] {
        self.bytes.as_ref().as_slice()
    }
    /// Exact original public query derived from zone+canonical label.
    pub const fn query(&self) -> &[u8; 64] {
        &self.query
    }
    /// Actual original zone authority.
    pub const fn zone(&self) -> ZoneKey {
        self.zone
    }
    /// Assigned absolute expiration, at least the public record-derived minimum.
    pub const fn expires(&self) -> u64 {
        self.expires
    }
    /// Retain this exact already-public ciphertext for one original native PUT.
    /// This creates no new signature, job/source identity or publication receipt.
    pub fn retain(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            query: self.query,
            zone: self.zone,
            expires: self.expires,
        }
    }
}
/// Complete private/public local-cache product; it cannot construct a public
/// publication and implements neither ordinary Clone nor payload Debug.
pub struct LocalCache {
    bytes: Arc<Zeroizing<Vec<u8>>>,
    query: [u8; 64],
    expires: u64,
}
impl fmt::Debug for LocalCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalCache")
            .field("bytes", &self.bytes.len())
            .field("contents", &"[REDACTED]")
            .finish()
    }
}
impl LocalCache {
    /// Explicit sensitive ciphertext borrow for official NAMECACHE only.
    pub fn bytes(&self) -> &[u8] {
        self.bytes.as_ref().as_slice()
    }
    /// Query implied by the original authoritative zone/label.
    pub const fn query(&self) -> &[u8; 64] {
        &self.query
    }
    /// Assigned absolute expiration, at least the original NAMESTORE full-set minimum.
    pub const fn expires(&self) -> u64 {
        self.expires
    }
}
/// Real worker output. Public and local ciphertext may share the same allocation
/// only when their complete prepared plaintext and expiration were identical.
pub struct Sealed {
    /// None if all live retained records are private.
    pub(crate) public: Option<PublicPublication>,
    /// Actual complete local block, absent when NAMECACHE was disabled.
    pub(crate) local: Option<LocalCache>,
    /// Original relative minimum, governing refresh/4.
    pub(crate) minimum_relative: Option<u64>,
    origin: Origin,
    private_cache: bool,
}
impl Sealed {
    pub(crate) const fn origin(&self) -> Origin {
        self.origin
    }
    /// A distinct full private set must reach the enabled local cache before
    /// the paired public projection can become visible through the DHT.
    pub(crate) const fn requires_private_cache(&self) -> bool {
        self.private_cache
    }
    /// Borrow only the checked public-filtered product; no mutation is exposed.
    pub fn public(&self) -> Option<&PublicPublication> {
        self.public.as_ref()
    }
    /// Borrow an actual complete local-cache product. PublicOnly never creates one.
    pub const fn local(&self) -> Option<&LocalCache> {
        self.local.as_ref()
    }
    /// Actual output selection, independent of any cache/native receipt.
    pub const fn destinations(&self) -> Destinations {
        if self.local.is_some() {
            Destinations::PublicAndLocal
        } else {
            Destinations::PublicOnly
        }
    }
    /// Original relative lifetime minimum used to schedule refreshes.
    pub const fn minimum_relative(&self) -> Option<u64> {
        self.minimum_relative
    }

    /// Actual immutable ciphertext capacity, counting a shared public/local
    /// allocation exactly once. This does not include a transient worker input.
    pub fn retained_bytes(&self) -> usize {
        let local = self.local.as_ref().map_or(0, |l| l.bytes.capacity());
        local
            + self.public.as_ref().map_or(0, |p| {
                if self
                    .local
                    .as_ref()
                    .is_some_and(|l| Arc::ptr_eq(&p.bytes, &l.bytes))
                {
                    0
                } else {
                    p.bytes.capacity()
                }
            })
    }
}
impl Prepared {
    pub(crate) const fn origin(&self) -> Origin {
        self.origin
    }
    /// Check exact original local authority/label binding without a secret hash.
    pub fn matches_identity(&self, key: &SecretKey, label: &[u8]) -> bool {
        self.key.constant_time_eq(key) && self.label.as_slice() == label
    }

    /// Actual selected destinations, retained with this original material.
    pub const fn destinations(&self) -> Destinations {
        if self.local.is_some() {
            Destinations::PublicAndLocal
        } else {
            Destinations::PublicOnly
        }
    }
    /// Total retained plaintext/label bytes, counting shared storage only once.
    pub fn retained_bytes(&self) -> usize {
        self.label.capacity()
            + self.public.as_ref().map_or(0, |p| p.bytes.capacity())
            + if shared_rdata(&self.public, &self.local) {
                0
            } else {
                self.local.as_ref().map_or(0, |l| l.bytes.capacity())
            }
    }
    /// Reserve only actual selected output buffers, plus their original input.
    /// Each selected block adds at most128 bytes of existing crypto overhead.
    pub fn worker_reservation(&self) -> Result<usize, Error> {
        let public = self
            .public
            .as_ref()
            .map(|p| p.bytes.len().checked_add(128).ok_or(Error::Overflow))
            .transpose()?
            .unwrap_or(0);
        let local = if shared_rdata(&self.public, &self.local) {
            0
        } else {
            self.local
                .as_ref()
                .map(|l| l.bytes.len().checked_add(128).ok_or(Error::Overflow))
                .transpose()?
                .unwrap_or(0)
        };
        self.retained_bytes()
            .checked_add(public)
            .and_then(|n| n.checked_add(local))
            .ok_or(Error::Overflow)
    }
    /// Original relative minimum for scheduling; no absolute target is reminted.
    pub const fn minimum_relative(&self) -> Option<u64> {
        self.min_relative
    }
    /// Derive one exact storage-key request from this original material. No
    /// encrypted block is produced until an explicitly assigned expiration is
    /// returned to the resulting plan. The production host durably reserves it.
    pub fn into_sealing(self) -> Result<SealPlan, Error> {
        let secret = projection::secret(self.key.view()?)?;
        let zone = secret.public_key();
        let mut scalars = Zeroizing::new(reserve(4096)?);
        scalars.resize(4096, '\0');
        let mut label_bytes = Zeroizing::new(reserve(self.label.len())?);
        label_bytes.resize(self.label.len(), 0);
        let label = projection::canonical_label(&self.label, &mut scalars, &mut label_bytes)?;
        let query = gnunet_gnscrypto::query(zone, label)?;
        Ok(SealPlan {
            input: self,
            secret,
            zone,
            query,
            requested: false,
        })
    }
}

impl Prepared {
    fn minimum_values(&self) -> Result<Values, Error> {
        Values::minima(
            self.public.as_ref().map(|rdata| rdata.expiration),
            self.local.as_ref().map(|rdata| rdata.expiration),
            shared_rdata(&self.public, &self.local),
        )
    }
}
/// One original material's official storage-key request for actual selected
/// outputs. It contains no secret/payload and has no public constructor.
/// Computing a candidate assignment is not a persistence receipt.
pub struct ExpirationRequest {
    origin: Origin,
    query: [u8; 64],
    minimum: Values,
}
impl ExpirationRequest {
    /// Actual official storage query, never a private-key hash identifier.
    #[must_use]
    pub const fn storage_key(&self) -> &[u8; 64] {
        &self.query
    }
    /// Compute values from this exact nonempty output shape and explicit history.
    /// None differs from an earlier zero. Consume maximum() durably before any
    /// seal, including when later work is canceled or never submits a product.
    /// Distinct local output must dominate its paired public cache projection;
    /// PublicOnly has no unused local value and may assign a final public MAX.
    pub fn after(&self, previous: Option<u64>) -> Result<Expirations, Error> {
        let values = self.minimum.after(previous)?;
        Ok(Expirations {
            origin: self.origin,
            values,
        })
    }
}
/// Consumed explicit assignment for one original plan. It proves no durability;
/// the caller's actual authority must reserve it. Neither Clone nor Copy.
pub struct Expirations {
    origin: Origin,
    values: Values,
}
impl Expirations {
    /// Highest actual selected value to consume irrevocably before sealing.
    #[must_use]
    pub fn maximum(&self) -> u64 {
        self.values.maximum()
    }
    /// Actual nonce values consumed; absent outputs consume nothing.
    #[must_use]
    pub const fn allocations(&self) -> u8 {
        self.values.allocations()
    }
}
/// One original prepared secret and official query, awaiting explicit assigned
/// expirations. Dropping it erases its original private material; no seal occurs.
pub struct SealPlan {
    input: Prepared,
    secret: ZoneSecret,
    zone: ZoneKey,
    query: [u8; 64],
    requested: bool,
}
impl SealPlan {
    /// Issue the actual original allocation request once. The host coordinates
    /// its storage-key highwater before returning an assignment for this plan.
    pub fn request(&mut self) -> Result<ExpirationRequest, Error> {
        if self.requested {
            return Err(Error::Replay);
        }
        let minimum = self.input.minimum_values()?;
        self.requested = true;
        Ok(ExpirationRequest {
            origin: self.input.origin,
            query: self.query,
            minimum,
        })
    }
    /// Seal only these original assigned outputs. The production caller must
    /// first obtain its durable reservation receipt and still check the
    /// original job/cancellation bounds before any cache/DHT submission.
    pub fn seal(self, assigned: Expirations) -> Result<Sealed, Error> {
        let minimum = self.input.minimum_values()?;
        let shared = shared_rdata(&self.input.public, &self.input.local);
        if !self.requested
            || assigned.origin != self.input.origin
            || !assigned.values.meets(minimum)
        {
            return Err(Error::Stale);
        }
        let mut scalars = Zeroizing::new(reserve(4096)?);
        scalars.resize(4096, '\0');
        let mut label_bytes = Zeroizing::new(reserve(self.input.label.len())?);
        label_bytes.resize(self.input.label.len(), 0);
        let label = projection::canonical_label(&self.input.label, &mut scalars, &mut label_bytes)?;
        let capacity = |n: usize| {
            n.checked_add(gnunet_gnscrypto::BLOCK_HEADER_LEN + 16)
                .ok_or(Error::Overflow)
        };
        let public = match (&self.input.public, assigned.values.public()) {
            (Some(data), Some(expiration)) => {
                let n = capacity(data.bytes.len())?;
                let mut bytes = Zeroizing::new(reserve(n)?);
                bytes.resize(n, 0);
                let written = self
                    .secret
                    .seal(label, expiration, &data.bytes, &mut bytes)?
                    .as_bytes()
                    .len();
                bytes.truncate(written);
                Some(PublicPublication {
                    bytes: Arc::new(bytes),
                    query: self.query,
                    zone: self.zone,
                    expires: expiration,
                })
            }
            (None, None) => None,
            _ => return Err(Error::Stale),
        };
        let local = match (&self.input.local, assigned.values.local()) {
            (Some(data), Some(expiration)) => {
                let bytes = if shared {
                    public.as_ref().ok_or(Error::Conflict)?.bytes.clone()
                } else {
                    let n = capacity(data.bytes.len())?;
                    let mut bytes = Zeroizing::new(reserve(n)?);
                    bytes.resize(n, 0);
                    let written = self
                        .secret
                        .seal_for_namecache(label, expiration, &data.bytes, &mut bytes)?
                        .as_bytes()
                        .len();
                    bytes.truncate(written);
                    Arc::new(bytes)
                };
                Some(LocalCache {
                    bytes,
                    query: self.query,
                    expires: expiration,
                })
            }
            (None, None) => None,
            _ => return Err(Error::Stale),
        };
        let private_cache =
            self.input.private_records && public.is_some() && local.is_some() && !shared;
        Ok(Sealed {
            origin: self.input.origin,
            private_cache,
            public,
            local,
            minimum_relative: self.input.min_relative,
        })
    }
}
