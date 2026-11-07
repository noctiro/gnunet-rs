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
use gnunet_crypto::gns::{EdkeySecret, PkeySecret};
use gnunet_gnscrypto::{Label, ZoneSecret};
use gnunet_gnsrecord::{RecordData, RecordFlags as Flags, RecordSet, RecordType, ZoneKey};
use gnunet_identity::{KeyType, SecretKey, SecretKeyView};
use gnunet_namestore::{Filter, normalize_records};
use gnunet_types::Error;
use zeroize::Zeroizing;
/// Explicit finite per-label preparation/worker ceilings.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Count bound, capped by existing cryptographic record codec.
    pub records: usize,
    /// Canonical label bytes, excluding terminating NUL.
    pub label_bytes: usize,
    /// Raw/padded plaintext bytes per public/local block.
    pub plaintext_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            records: gnunet_gnscrypto::MAX_RECORDS,
            label_bytes: 255,
            plaintext_bytes: gnunet_gnsrecord::MAX_BLOCK_SIZE,
        }
    }
}
/// Actual original NAMESTORE record set and its returned block expiration.
/// Every field borrows the exact original zeroizing native reply.
pub struct Input<'a> {
    /// Original private authority, never a synthesized key ID.
    pub zone: SecretKeyView<'a>,
    /// Original canonical label, without NUL.
    pub label: &'a [u8],
    /// Exact count-validated original record serialization.
    pub records: RecordSet<'a>,
    /// Actual full-set source expiration, including tombstone floor. Used for
    /// the complete local output; it never substitutes for the public floor.
    pub source_expiry: u64,
}
/// Actual destinations chosen before retaining worker material. PublicOnly is
/// the explicit NAMECACHE-disabled mode, not a fabricated complete local set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Destinations {
    /// Prepare and seal only an existing public projection.
    PublicOnly,
    /// Also prepare the complete authoritative local NAMECACHE view.
    PublicAndLocal,
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
fn empty() -> RecordData<'static> {
    RecordData {
        expiration_time: 0,
        record_type: RecordType::ANY,
        flags: Flags::from_bits_preserve(0),
        data: &[],
    }
}
fn serialize(
    records: &[RecordData<'_>],
    now: u64,
    max: usize,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut absolute = reserve(records.len())?;
    for r in records {
        let mut value = *r;
        if value.has_relative_expiration() {
            value.expiration_time = now.saturating_add(value.expiration_time);
            value.flags = value.flags.without(Flags::RELATIVE_EXPIRATION);
        }
        absolute.push(value)
    }
    let n = gnunet_gnsrecord::serialized_len(&absolute)?;
    if n > max {
        return Err(Error::Capacity);
    }
    let mut out = reserve(n)?;
    out.resize(n, 0);
    gnunet_gnsrecord::serialize(&absolute, &mut out)?;
    Ok(Zeroizing::new(out))
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
    if limits.records == 0
        || limits.records > gnunet_gnscrypto::MAX_RECORDS
        || limits.label_bytes > 255
        || limits.plaintext_bytes > gnunet_gnsrecord::MAX_BLOCK_SIZE
    {
        return Err(Error::InvalidInput);
    }
    if input.records.len() > limits.records
        || input.label.len() > limits.label_bytes
        || input.label.contains(&0)
        || input.label.contains(&b'.')
    {
        return Err(Error::Capacity);
    }
    let label_text = core::str::from_utf8(input.label).map_err(|_| Error::Malformed)?;
    let mut scalars = Zeroizing::new(reserve(4096)?);
    scalars.resize(4096, '\0');
    let mut canonical = Zeroizing::new(reserve(limits.label_bytes)?);
    canonical.resize(limits.label_bytes, 0);
    let label = Label::normalize(label_text, &mut scalars, &mut canonical)?;
    if label.as_str().as_bytes() != input.label {
        return Err(Error::Malformed);
    }
    if input.records.is_empty() {
        return Ok(None);
    }
    if destinations == Destinations::PublicAndLocal && input.source_expiry <= now {
        return Err(Error::Deadline);
    }
    let mut records = reserve(input.records.len())?;
    let mut min_relative = None;
    for record in input.records.iter() {
        let r = record?;
        r.validate_fixed_size()?;
        if r.has_relative_expiration() {
            min_relative =
                Some(min_relative.map_or(r.expiration_time, |n: u64| n.min(r.expiration_time)));
        }
        records.push(r)
    }
    let mut indices = reserve(records.len())?;
    indices.resize(records.len(), 0);
    let mut public_out = reserve(records.len())?;
    public_out.resize(records.len(), empty());
    let public = normalize_records(
        input.label,
        &records,
        now,
        Filter::OMIT_PRIVATE,
        &mut public_out,
        &mut indices,
        critical,
    )?;
    let public_count = public.records().len();
    if destinations == Destinations::PublicOnly {
        if public_count == 0 {
            return Ok(None);
        }
        if public.expires() <= now {
            return Err(Error::Deadline);
        }
        // Private lifetimes do not schedule refreshes for an absent local lane.
        min_relative = public
            .records()
            .iter()
            .filter(|r| r.has_relative_expiration())
            .map(|r| r.expiration_time)
            .min();
    }
    let public = if public_count > 0 {
        Some(Rdata {
            expiration: public.expires(),
            bytes: Arc::new(serialize(public.records(), now, limits.plaintext_bytes)?),
        })
    } else {
        None
    };
    let (local, private_records) = if destinations == Destinations::PublicAndLocal {
        let mut local_out = reserve(records.len())?;
        local_out.resize(records.len(), empty());
        let local = normalize_records(
            input.label,
            &records,
            now,
            Filter::NONE,
            &mut local_out,
            &mut indices,
            critical,
        )?;
        // Retain private shadows too: they may become applicable before expiry.
        let private_records = local
            .records()
            .iter()
            .any(|r| r.flags.contains(Flags::PRIVATE));
        let serialized = serialize(local.records(), now, limits.plaintext_bytes)?;
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
                expiration: input.source_expiry,
            }),
            private_records,
        )
    } else {
        (None, false)
    };
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
        let mut raw = Zeroizing::new([0; 32]);
        raw.copy_from_slice(&self.key.expose_serialized()[4..]);
        let secret = match self.key.key_type() {
            KeyType::Ecdsa => ZoneSecret::Pkey(PkeySecret::from_bytes(*raw)?),
            KeyType::Eddsa => ZoneSecret::Edkey(EdkeySecret::from_seed(*raw)),
        };
        let zone = secret.public_key();
        let mut scalars = Zeroizing::new(reserve(4096)?);
        scalars.resize(4096, '\0');
        let mut label_bytes = Zeroizing::new(reserve(self.label.len())?);
        label_bytes.resize(self.label.len(), 0);
        let label = Label::normalize(
            core::str::from_utf8(&self.label).map_err(|_| Error::Malformed)?,
            &mut scalars,
            &mut label_bytes,
        )?;
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

/// Actual nonempty output shape. It is private so no caller can manufacture an
/// empty assignment or a local product that was never requested.
#[derive(Clone, Copy)]
enum Values {
    Public(u64),
    Local(u64),
    Shared(u64),
    Distinct { public: u64, local: u64 },
}
impl Values {
    const fn public(self) -> Option<u64> {
        match self {
            Self::Public(n) | Self::Shared(n) => Some(n),
            Self::Distinct { public, .. } => Some(public),
            Self::Local(_) => None,
        }
    }
    const fn local(self) -> Option<u64> {
        match self {
            Self::Local(n) | Self::Shared(n) => Some(n),
            Self::Distinct { local, .. } => Some(local),
            Self::Public(_) => None,
        }
    }
    fn same_shape(self, other: Self) -> bool {
        matches!(
            (self, other),
            (Self::Public(_), Self::Public(_))
                | (Self::Local(_), Self::Local(_))
                | (Self::Shared(_), Self::Shared(_))
                | (Self::Distinct { .. }, Self::Distinct { .. })
        )
    }
    fn maximum(self) -> u64 {
        match self {
            Self::Public(n) | Self::Local(n) | Self::Shared(n) => n,
            Self::Distinct { public, local } => public.max(local),
        }
    }
}
impl Prepared {
    fn minimum_values(&self) -> Result<Values, Error> {
        match (&self.public, &self.local) {
            (Some(p), Some(l)) if shared_rdata(&self.public, &self.local) => {
                Ok(Values::Shared(p.expiration.max(l.expiration)))
            }
            (Some(p), Some(l)) => Ok(Values::Distinct {
                public: p.expiration,
                local: l.expiration,
            }),
            (Some(p), None) => Ok(Values::Public(p.expiration)),
            (None, Some(l)) => Ok(Values::Local(l.expiration)),
            (None, None) => Err(Error::InvalidInput),
        }
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
        let next = previous
            .map(|n| n.checked_add(1).ok_or(Error::Overflow))
            .transpose()?;
        let floor = |minimum: u64| next.map_or(minimum, |n| minimum.max(n));
        let values = match self.minimum {
            Values::Public(n) => Values::Public(floor(n)),
            Values::Local(n) => Values::Local(floor(n)),
            Values::Shared(n) => Values::Shared(floor(n)),
            Values::Distinct { public, local } => {
                let public = floor(public);
                let local = local.max(public.checked_add(1).ok_or(Error::Overflow)?);
                Values::Distinct { public, local }
            }
        };
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
        if matches!(self.values, Values::Distinct { .. }) {
            2
        } else {
            1
        }
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
            || !assigned.values.same_shape(minimum)
            || assigned
                .values
                .public()
                .zip(minimum.public())
                .is_some_and(|(n, floor)| n < floor)
            || assigned
                .values
                .local()
                .zip(minimum.local())
                .is_some_and(|(n, floor)| n < floor)
            || matches!(assigned.values, Values::Distinct { public, local } if local <= public)
        {
            return Err(Error::Stale);
        }
        let mut scalars = Zeroizing::new(reserve(4096)?);
        scalars.resize(4096, '\0');
        let mut label_bytes = Zeroizing::new(reserve(self.input.label.len())?);
        label_bytes.resize(self.input.label.len(), 0);
        let label = Label::normalize(
            core::str::from_utf8(&self.input.label).map_err(|_| Error::Malformed)?,
            &mut scalars,
            &mut label_bytes,
        )?;
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
