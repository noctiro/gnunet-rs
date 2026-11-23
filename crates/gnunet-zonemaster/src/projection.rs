//! Shared authoritative normalization and block-expiration policy.

use gnunet_crypto::gns::{EdkeySecret, PkeySecret};
use gnunet_gnscrypto::{Label, ZoneSecret};
use gnunet_gnsrecord::{RecordData, RecordFlags, RecordSet, RecordType};
use gnunet_identity::{KeyType, SecretKeyView};
use gnunet_namestore::{Filter, normalize_records};
use gnunet_types::Error;
use zeroize::Zeroizing;

/// Finite per-label preparation limits.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Count bound, capped by the official record codec.
    pub records: usize,
    /// Canonical label bytes, excluding terminating NUL.
    pub label_bytes: usize,
    /// Padded plaintext byte bound per public or local block.
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

/// Original authoritative record set and its full-set source expiration.
pub struct Input<'a> {
    /// Original private authority.
    pub zone: SecretKeyView<'a>,
    /// Original canonical label, without NUL.
    pub label: &'a [u8],
    /// Exact count-validated original record serialization.
    pub records: RecordSet<'a>,
    /// Actual local source expiration, including the tombstone floor.
    pub source_expiry: u64,
}

/// Selected destinations for one original preparation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Destinations {
    /// Prepare and seal only an existing public projection.
    PublicOnly,
    /// Refresh only the complete authoritative local NAMECACHE view.
    LocalOnly,
    /// Also prepare the complete authoritative local NAMECACHE view.
    PublicAndLocal,
}

impl Destinations {
    pub(crate) const fn public(self) -> bool {
        !matches!(self, Self::LocalOnly)
    }

    pub(crate) const fn local(self) -> bool {
        !matches!(self, Self::PublicOnly)
    }
}

pub(crate) const EMPTY_RECORD: RecordData<'static> = RecordData {
    expiration_time: 0,
    record_type: RecordType::ANY,
    flags: RecordFlags::NONE,
    data: &[],
};

pub(crate) fn validate_input(input: &Input<'_>, limits: Limits, now: u64) -> Result<(), Error> {
    if limits.records == 0
        || limits.records > gnunet_gnscrypto::MAX_RECORDS
        || limits.label_bytes > 255
        || limits.plaintext_bytes > gnunet_gnsrecord::MAX_BLOCK_SIZE
    {
        return Err(Error::InvalidInput);
    }
    if now == u64::MAX {
        return Err(Error::TimeUncertain);
    }
    if input.records.len() > limits.records
        || input.label.len() > limits.label_bytes
        || input.label.contains(&0)
        || input.label.contains(&b'.')
    {
        return Err(Error::Capacity);
    }
    Ok(())
}

pub(crate) fn canonical_label<'a>(
    input: &[u8],
    scalars: &mut [char],
    output: &'a mut [u8],
) -> Result<Label<'a>, Error> {
    let text = core::str::from_utf8(input).map_err(|_| Error::Malformed)?;
    let label = Label::normalize(text, scalars, output)?;
    if label.as_str().as_bytes() != input {
        return Err(Error::Malformed);
    }
    Ok(label)
}

pub(crate) fn secret(key: SecretKeyView<'_>) -> Result<ZoneSecret, Error> {
    let mut raw = Zeroizing::new([0; 32]);
    raw.copy_from_slice(&key.expose_serialized()[4..]);
    match key.key_type() {
        KeyType::Ecdsa => Ok(ZoneSecret::Pkey(PkeySecret::from_bytes(*raw)?)),
        KeyType::Eddsa => Ok(ZoneSecret::Edkey(EdkeySecret::from_seed(*raw))),
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Lane {
    Public,
    Local,
}

pub(crate) struct Projection<'records, 'data> {
    pub records: &'records [RecordData<'data>],
    pub expiration: u64,
    pub minimum_relative: Option<u64>,
    pub private: bool,
}

pub(crate) struct Source<'records, 'data> {
    original: &'records [RecordData<'data>],
    label: &'data [u8],
    local_expiry: u64,
    now: u64,
    destinations: Destinations,
}

impl<'records, 'data> Source<'records, 'data> {
    pub(crate) fn read(
        input: &Input<'data>,
        now: u64,
        destinations: Destinations,
        records: &'records mut [RecordData<'data>],
    ) -> Result<Option<Self>, Error> {
        if input.records.is_empty() {
            return Ok(None);
        }
        if destinations.local() && input.source_expiry <= now {
            return Err(Error::Deadline);
        }
        let original = records
            .get_mut(..input.records.len())
            .ok_or(Error::Capacity)?;
        for (slot, record) in original.iter_mut().zip(input.records.iter()) {
            let record = record?;
            record.validate_fixed_size()?;
            *slot = record;
        }
        Ok(Some(Self {
            original,
            label: input.label,
            local_expiry: input.source_expiry,
            now,
            destinations,
        }))
    }

    pub(crate) fn project<'out>(
        &self,
        lane: Lane,
        scratch: &'out mut [RecordData<'data>],
        indices: &mut [usize],
        critical: fn(RecordType) -> bool,
    ) -> Result<Option<Projection<'out, 'data>>, Error> {
        let filter = match lane {
            Lane::Public => Filter::OMIT_PRIVATE,
            Lane::Local => Filter::NONE,
        };
        let selected = normalize_records(
            self.label,
            self.original,
            self.now,
            filter,
            scratch,
            indices,
            critical,
        )?;
        let expiration = match lane {
            Lane::Public if selected.records().is_empty() => return Ok(None),
            Lane::Public
                if self.destinations == Destinations::PublicOnly
                    && selected.expires() <= self.now =>
            {
                return Err(Error::Deadline);
            }
            Lane::Public => selected.expires(),
            Lane::Local => self.local_expiry,
        };
        let count = selected.records().len();
        let lifetimes = match lane {
            Lane::Public => selected.records(),
            Lane::Local => self.original,
        };
        let minimum_relative = lifetimes
            .iter()
            .filter(|r| r.has_relative_expiration())
            .map(|r| r.expiration_time)
            .min();
        let private = selected
            .records()
            .iter()
            .any(|r| r.flags.contains(RecordFlags::PRIVATE));
        let records = &mut scratch[..count];
        for record in records.iter_mut().filter(|r| r.has_relative_expiration()) {
            record.expiration_time = self.now.saturating_add(record.expiration_time);
            record.flags = record.flags.without(RecordFlags::RELATIVE_EXPIRATION);
        }
        Ok(Some(Projection {
            records,
            expiration,
            minimum_relative,
            private,
        }))
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Values {
    Public(u64),
    Local(u64),
    Shared(u64),
    Distinct { public: u64, local: u64 },
}

impl Values {
    pub(crate) fn minima(
        public: Option<u64>,
        local: Option<u64>,
        shared: bool,
    ) -> Result<Self, Error> {
        match (public, local) {
            (Some(public), Some(local)) if shared => Ok(Self::Shared(public.max(local))),
            (Some(public), Some(local)) => Ok(Self::Distinct { public, local }),
            (Some(public), None) => Ok(Self::Public(public)),
            (None, Some(local)) => Ok(Self::Local(local)),
            (None, None) => Err(Error::InvalidInput),
        }
    }

    pub(crate) const fn public(self) -> Option<u64> {
        match self {
            Self::Public(n) | Self::Shared(n) => Some(n),
            Self::Distinct { public, .. } => Some(public),
            Self::Local(_) => None,
        }
    }

    pub(crate) const fn local(self) -> Option<u64> {
        match self {
            Self::Local(n) | Self::Shared(n) => Some(n),
            Self::Distinct { local, .. } => Some(local),
            Self::Public(_) => None,
        }
    }

    pub(crate) fn maximum(self) -> u64 {
        match self {
            Self::Public(n) | Self::Local(n) | Self::Shared(n) => n,
            Self::Distinct { public, local } => public.max(local),
        }
    }

    pub(crate) const fn allocations(self) -> u8 {
        if matches!(self, Self::Distinct { .. }) {
            2
        } else {
            1
        }
    }

    pub(crate) fn after(self, previous: Option<u64>) -> Result<Self, Error> {
        let next = previous
            .map(|n| n.checked_add(1).ok_or(Error::Overflow))
            .transpose()?;
        let floor = |minimum: u64| next.map_or(minimum, |n| minimum.max(n));
        Ok(match self {
            Self::Public(n) => Self::Public(floor(n)),
            Self::Local(n) => Self::Local(floor(n)),
            Self::Shared(n) => Self::Shared(floor(n)),
            Self::Distinct { public, local } => {
                let public = floor(public);
                let local = local.max(public.checked_add(1).ok_or(Error::Overflow)?);
                Self::Distinct { public, local }
            }
        })
    }

    pub(crate) fn meets(self, minimum: Self) -> bool {
        match (self, minimum) {
            (Self::Public(n), Self::Public(floor))
            | (Self::Local(n), Self::Local(floor))
            | (Self::Shared(n), Self::Shared(floor)) => n >= floor,
            (
                Self::Distinct { public, local },
                Self::Distinct {
                    public: p,
                    local: l,
                },
            ) => public >= p && local >= l && local > public,
            _ => false,
        }
    }
}
