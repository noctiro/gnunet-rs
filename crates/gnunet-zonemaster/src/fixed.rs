//! Allocation-free authoritative projection and exact expiration reservation.

use crate::Error;
use crate::projection::{self, EMPTY_RECORD, Lane, Projection, Source, Values};
use core::ptr;
use gnunet_gnscrypto::{BLOCK_HEADER_LEN, Block, Label, ZoneSecret};
use gnunet_gnsrecord::{RecordData, RecordType, ZoneKey, ZoneKeyType};
use zeroize::Zeroize;

pub use crate::projection::{Destinations, Input, Limits};

/// Caller-owned preparation workspace. Plaintext spans used by a plan are
/// erased when it seals, fails or is dropped. Label storage belongs to the caller.
pub struct Preparation<'a> {
    /// Unicode normalization scratch.
    pub scalars: &'a mut [char],
    /// Canonical label storage retained until preparation retires.
    pub label: &'a mut [u8],
    /// Caller capacity for canonical padded public plaintext.
    pub public_rdata: &'a mut [u8],
    /// Caller capacity for canonical padded local plaintext; ignored in PublicOnly.
    pub local_rdata: &'a mut [u8],
}

/// Caller-owned exact sealed frame storage. Shared projections use only `public`.
pub struct Output<'a> {
    /// Public frame storage, absent output requires no capacity.
    pub public: &'a mut [u8],
    /// Full local frame, unused when absent or sharing identical public data.
    pub local: &'a mut [u8],
}

struct Plaintext<'a> {
    bytes: &'a mut [u8],
    expires: u64,
}

impl<'a> Plaintext<'a> {
    fn new(
        selected: &Projection<'_, '_>,
        limit: usize,
        bytes: &'a mut [u8],
    ) -> Result<Self, Error> {
        let len = gnunet_gnsrecord::serialized_len(selected.records)?;
        if len > limit {
            return Err(Error::Capacity);
        }
        let plain = Self {
            bytes: bytes.get_mut(..len).ok_or(Error::Capacity)?,
            expires: selected.expiration,
        };
        gnunet_gnsrecord::serialize_to_size(selected.records, &mut *plain.bytes)?;
        Ok(plain)
    }

    fn check_output(&self, output: &[u8], overhead: usize) -> Result<(), Error> {
        let len = self
            .bytes
            .len()
            .checked_add(overhead)
            .ok_or(Error::Overflow)?;
        if output.len() < len {
            return Err(Error::Capacity);
        }
        Ok(())
    }
}

impl Drop for Plaintext<'_> {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

enum Local<'a> {
    Shared { expires: u64 },
    Distinct(Plaintext<'a>),
}

impl Local<'_> {
    const fn expires(&self) -> u64 {
        match self {
            Self::Shared { expires } => *expires,
            Self::Distinct(plaintext) => plaintext.expires,
        }
    }
}

/// Exact sensitive material awaiting one durable reservation and seal.
pub struct Prepared<'a> {
    secret: ZoneSecret,
    zone: ZoneKey,
    label: Label<'a>,
    query: [u8; 64],
    public: Option<Plaintext<'a>>,
    local: Option<Local<'a>>,
    minimum_relative: Option<u64>,
    public_minimum_relative: Option<u64>,
    private_cache: bool,
}

/// Exact identity of a prepared public projection before terminal expiry is
/// consumed. The query and padded public plaintext are committed separately.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicBinding {
    query: [u8; 64],
    digest: [u8; 32],
}

impl PublicBinding {
    /// Official public query for the original zone and label.
    #[must_use]
    pub const fn query(&self) -> &[u8; 64] {
        &self.query
    }

    /// Domain-separated commitment to the exact prepared public plaintext.
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

/// Prepare the same two projections as the allocated publisher. `RECORDS`
/// bounds temporary descriptor/order slots. The borrowed input can be released
/// after return. A live tombstone-only set may still seal a zero-record local
/// ciphertext; an actually empty input never requests an expiration.
pub fn prepare<'scratch, 'data, const RECORDS: usize>(
    input: Input<'data>,
    now: u64,
    limits: Limits,
    critical: fn(RecordType) -> bool,
    destinations: Destinations,
    scratch: Preparation<'scratch>,
) -> Result<Option<Prepared<'scratch>>, Error> {
    projection::validate_input(&input, limits, now)?;
    let label = projection::canonical_label(input.label, scratch.scalars, scratch.label);
    scratch.scalars.zeroize();
    let label = label?;
    let mut source: [RecordData<'data>; RECORDS] = [EMPTY_RECORD; RECORDS];
    let Some(source) = Source::read(&input, now, destinations, &mut source)? else {
        return Ok(None);
    };
    let mut projected: [RecordData<'data>; RECORDS] = [EMPTY_RECORD; RECORDS];
    let mut indices = [0; RECORDS];
    let (public, public_minimum_relative) = if destinations.public() {
        match source.project(Lane::Public, &mut projected, &mut indices, critical)? {
            Some(selected) => (
                Some(Plaintext::new(
                    &selected,
                    limits.plaintext_bytes,
                    scratch.public_rdata,
                )?),
                selected.minimum_relative,
            ),
            None => (None, None),
        }
    } else {
        (None, None)
    };
    let mut minimum_relative = public_minimum_relative;
    let mut private_cache = false;
    let local = if destinations.local() {
        let selected = source
            .project(Lane::Local, &mut projected, &mut indices, critical)?
            .ok_or(Error::Conflict)?;
        minimum_relative = selected.minimum_relative;
        let plaintext = Plaintext::new(&selected, limits.plaintext_bytes, scratch.local_rdata)?;
        let local = if public
            .as_ref()
            .is_some_and(|public| public.bytes == plaintext.bytes)
        {
            Local::Shared {
                expires: plaintext.expires,
            }
        } else {
            private_cache = public.is_some() && selected.private;
            Local::Distinct(plaintext)
        };
        Some(local)
    } else {
        None
    };
    if public.is_none() && local.is_none() {
        return Ok(None);
    }
    let secret = projection::secret(input.zone)?;
    let zone = secret.public_key();
    let query = gnunet_gnscrypto::query(zone, label)?;
    Ok(Some(Prepared {
        secret,
        zone,
        label,
        query,
        public,
        local,
        minimum_relative,
        public_minimum_relative,
        private_cache,
    }))
}

struct Original {
    _identity: u8,
}

/// One exact plan's request for the durable per-query expiration authority.
pub struct ExpirationRequest<'origin> {
    origin: &'origin Original,
    query: &'origin [u8; 64],
    minimum: Values,
}

impl<'origin> ExpirationRequest<'origin> {
    /// Official zone/label storage query.
    #[must_use]
    pub const fn storage_key(&self) -> &'origin [u8; 64] {
        self.query
    }

    /// Assign the exact selected output expirations from durable prior history.
    /// The caller's authority must consume this assignment's maximum before returning it.
    pub fn after(&self, previous: Option<u64>) -> Result<Assigned<'origin>, Error> {
        Ok(Assigned {
            origin: self.origin,
            values: self.minimum.after(previous)?,
        })
    }

    /// Resume an interrupted first terminal publication. The caller must
    /// have recovered a matching immutable public intent and confirmed that
    /// its expiration floor is already durably at `u64::MAX`. A distinct
    /// private output cannot share this nonce.
    pub fn resume_terminal_public(&self) -> Result<Assigned<'origin>, Error> {
        let values = match self.minimum {
            Values::Public(_) => Values::Public(u64::MAX),
            Values::Shared(_) => Values::Shared(u64::MAX),
            _ => return Err(Error::Overflow),
        };
        Ok(Assigned {
            origin: self.origin,
            values,
        })
    }
}

/// Exact selected expiration allocation, scoped to one original reserve call.
pub struct Assigned<'origin> {
    origin: &'origin Original,
    values: Values,
}

impl Assigned<'_> {
    /// Highest selected expiration to durably consume before any seal.
    #[must_use]
    pub fn maximum(&self) -> u64 {
        self.values.maximum()
    }

    /// Exact selected public expiration, if this assignment owns a public lane.
    #[must_use]
    pub const fn public_expiration(&self) -> Option<u64> {
        self.values.public()
    }

    /// Number of actual selected nonce values, counting a shared block once.
    #[must_use]
    pub const fn allocations(&self) -> u8 {
        self.values.allocations()
    }
}

impl Prepared<'_> {
    /// Smallest original relevant relative lifetime for republish scheduling.
    #[must_use]
    pub const fn minimum_relative(&self) -> Option<u64> {
        self.minimum_relative
    }

    /// Bind a terminal intent only to real public bytes. Local-only plans
    /// cannot mint a public binding.
    #[must_use]
    pub fn public_binding(&self) -> Option<PublicBinding> {
        self.public.as_ref().map(|public| self.bind(public.bytes))
    }

    fn bind(&self, plaintext: &[u8]) -> PublicBinding {
        PublicBinding {
            query: self.query,
            digest: gnunet_crypto::hash256_parts(&[
                b"GNUnet terminal public zone projection v1",
                &self.query,
                plaintext,
            ]),
        }
    }

    /// Discard a distinct local projection when recovering an existing public
    /// terminal intent. A local projection identical to public can still use
    /// the exact same sealed ciphertext.
    #[must_use]
    pub fn terminal_public_only(mut self) -> Self {
        if matches!(self.local, Some(Local::Distinct(_))) {
            self.local = None;
            self.minimum_relative = self.public_minimum_relative;
            self.private_cache = false;
        }
        self
    }

    /// Qualify an exact retained terminal public ciphertext against the
    /// current original public projection. This verifies signing authority,
    /// expiry and exact decrypted bytes without sealing or reserving a nonce.
    /// The local lane is lent only when it is already identical to public.
    pub fn replay_terminal<'out>(
        &self,
        bytes: &'out [u8],
        verification: &mut [u8],
        now: u64,
    ) -> Result<Sealed<'out>, Error> {
        if now == u64::MAX {
            return Err(Error::TimeUncertain);
        }
        let public = self.public.as_ref().ok_or(Error::InvalidInput)?;
        let original = Block::decode(bytes)?;
        if original.expiration()? != u64::MAX {
            return Err(Error::Authentication);
        }
        let tag = if self.zone.kind() == ZoneKeyType::Edkey {
            16
        } else {
            0
        };
        if original.ciphertext().len().checked_sub(tag) != Some(public.bytes.len()) {
            return Err(Error::Authentication);
        }
        let checked = original.verify_for(self.zone, self.label)?;
        let verification = verification
            .get_mut(..public.bytes.len())
            .ok_or(Error::Capacity)?;
        let result = checked
            .open_at(now, verification)
            .map(|_| ())
            .and_then(|()| {
                if *verification == *public.bytes {
                    Ok(())
                } else {
                    Err(Error::Authentication)
                }
            });
        verification.zeroize();
        result?;
        let local = matches!(self.local, Some(Local::Shared { .. })).then_some(LocalCache {
            bytes,
            query: self.query,
            expires: u64::MAX,
        });
        Ok(Sealed {
            public: Some(PublicPublication {
                bytes,
                query: self.query,
                zone: self.zone,
                expires: u64::MAX,
                terminal: Some(self.bind(public.bytes)),
            }),
            local,
            minimum_relative: self.minimum_relative,
            public_minimum_relative: self.public_minimum_relative,
            private_cache: false,
        })
    }

    /// Preflight output capacity, durably consume the exact assigned expiration
    /// via the caller's reservation authority, then seal each selected lane once.
    /// A failed or canceled seal does not return consumed expiration values.
    pub fn seal<'out>(
        self,
        output: Output<'out>,
        reserve: impl for<'origin> FnOnce(
            ExpirationRequest<'origin>,
        ) -> Result<Assigned<'origin>, Error>,
    ) -> Result<Sealed<'out>, Error> {
        let overhead = BLOCK_HEADER_LEN
            + if self.zone.kind() == ZoneKeyType::Edkey {
                16
            } else {
                0
            };
        if let Some(public) = &self.public {
            public.check_output(output.public, overhead)?;
        }
        if let Some(Local::Distinct(local)) = &self.local {
            local.check_output(output.local, overhead)?;
        }
        let minimum = Values::minima(
            self.public.as_ref().map(|rdata| rdata.expires),
            self.local.as_ref().map(Local::expires),
            matches!(&self.local, Some(Local::Shared { .. })),
        )?;
        let origin = Original { _identity: 1 };
        let assigned = reserve(ExpirationRequest {
            origin: &origin,
            query: &self.query,
            minimum,
        })?;
        if !ptr::eq(&origin, assigned.origin) || !assigned.values.meets(minimum) {
            return Err(Error::Stale);
        }
        let public = if let (Some(rdata), Some(expires)) = (&self.public, assigned.values.public())
        {
            let bytes = self
                .secret
                .seal(self.label, expires, rdata.bytes, output.public)?
                .as_bytes();
            Some(PublicPublication {
                bytes,
                zone: self.zone,
                query: self.query,
                expires,
                terminal: (expires == u64::MAX).then(|| self.bind(rdata.bytes)),
            })
        } else {
            None
        };
        let local = match (&self.local, assigned.values.local()) {
            (Some(Local::Shared { .. }), Some(expires)) => {
                let bytes = public.as_ref().ok_or(Error::Conflict)?.bytes;
                Some(LocalCache {
                    bytes,
                    query: self.query,
                    expires,
                })
            }
            (Some(Local::Distinct(rdata)), Some(expires)) => {
                let bytes = self
                    .secret
                    .seal_for_namecache(self.label, expires, rdata.bytes, output.local)?
                    .as_bytes();
                Some(LocalCache {
                    bytes,
                    query: self.query,
                    expires,
                })
            }
            (None, None) => None,
            _ => return Err(Error::Conflict),
        };
        Ok(Sealed {
            public,
            local,
            minimum_relative: self.minimum_relative,
            public_minimum_relative: self.public_minimum_relative,
            private_cache: self.private_cache,
        })
    }
}

/// Complete official public-only DHT ciphertext and its authority metadata.
pub struct PublicPublication<'a> {
    bytes: &'a [u8],
    query: [u8; 64],
    zone: ZoneKey,
    expires: u64,
    terminal: Option<PublicBinding>,
}

impl PublicPublication<'_> {
    /// Exact sealed public ciphertext.
    #[must_use]
    pub const fn bytes(&self) -> &[u8] {
        self.bytes
    }
    /// Exact original public query derived from zone and label.
    #[must_use]
    pub const fn query(&self) -> &[u8; 64] {
        &self.query
    }
    /// Original public zone authority.
    #[must_use]
    pub const fn zone(&self) -> ZoneKey {
        self.zone
    }
    /// Assigned absolute expiration.
    #[must_use]
    pub const fn expires(&self) -> u64 {
        self.expires
    }

    /// Exact public plaintext binding proven by this terminal ciphertext.
    #[must_use]
    pub const fn terminal_binding(&self) -> Option<PublicBinding> {
        self.terminal
    }

    /// Keep the authority of these exact public bytes in caller-owned storage.
    /// A retry can lend the same ciphertext without re-sealing or reserving a
    /// second nonce. A retained network retry does not carry journal authority.
    #[must_use]
    pub fn retain(&self) -> RetainedPublic {
        RetainedPublic {
            length: self.bytes.len(),
            digest: gnunet_crypto::hash256(self.bytes),
            query: self.query,
            zone: self.zone,
            expires: self.expires,
        }
    }
}

/// A commitment to one actual sealed public output, independent of its buffer.
pub struct RetainedPublic {
    length: usize,
    digest: [u8; 32],
    query: [u8; 64],
    zone: ZoneKey,
    expires: u64,
}

impl RetainedPublic {
    /// Borrow the original public ciphertext from its storage. Any change,
    /// including replacement by a locally sealed block, refuses the loan.
    pub fn lend<'a>(&self, storage: &'a [u8]) -> Result<PublicPublication<'a>, Error> {
        let bytes = storage.get(..self.length).ok_or(Error::Truncated)?;
        if gnunet_crypto::hash256(bytes) != self.digest {
            return Err(Error::Authentication);
        }
        Ok(PublicPublication {
            bytes,
            query: self.query,
            zone: self.zone,
            expires: self.expires,
            terminal: None,
        })
    }
}

/// Full signed NAMECACHE ciphertext. This view may contain private records.
pub struct LocalCache<'a> {
    bytes: &'a [u8],
    query: [u8; 64],
    expires: u64,
}

impl LocalCache<'_> {
    /// Exact sealed local ciphertext.
    #[must_use]
    pub const fn bytes(&self) -> &[u8] {
        self.bytes
    }
    /// Same original zone/label query as the paired public lane, if present.
    #[must_use]
    pub const fn query(&self) -> &[u8; 64] {
        &self.query
    }
    /// Assigned absolute expiration, strictly later than distinct public data.
    #[must_use]
    pub const fn expires(&self) -> u64 {
        self.expires
    }
}

/// Exact selected ciphertext outputs borrowing distinct or shared caller storage.
pub struct Sealed<'a> {
    public: Option<PublicPublication<'a>>,
    local: Option<LocalCache<'a>>,
    minimum_relative: Option<u64>,
    public_minimum_relative: Option<u64>,
    private_cache: bool,
}

impl<'a> Sealed<'a> {
    /// Checked pure public payload accepted by the DHT backend.
    #[must_use]
    pub const fn public(&self) -> Option<&PublicPublication<'a>> {
        self.public.as_ref()
    }
    /// Complete selected NAMECACHE payload.
    #[must_use]
    pub const fn local(&self) -> Option<&LocalCache<'a>> {
        self.local.as_ref()
    }
    /// Actual original relative minimum for allocating the next refresh.
    #[must_use]
    pub const fn minimum_relative(&self) -> Option<u64> {
        self.minimum_relative
    }
    /// Smallest relative lifetime among records in the public output only.
    #[must_use]
    pub const fn public_minimum_relative(&self) -> Option<u64> {
        self.public_minimum_relative
    }
    /// Whether local cache acceptance must precede the paired public PUT.
    #[must_use]
    pub const fn requires_private_cache(&self) -> bool {
        self.private_cache
    }
}
