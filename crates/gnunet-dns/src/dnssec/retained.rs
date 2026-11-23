use super::{Rrset, TrustedKeys};
use crate::{Error, MAX_WIRE_NAME_LENGTH, Name, Type};

/// A bounded, in-memory copy of an authenticated DNSKEY RRset. It carries the
/// original validation time and cannot be populated with unauthenticated bytes.
pub struct RetainedKeys<const BYTES: usize, const KEYS: usize> {
    zone: [u8; MAX_WIRE_NAME_LENGTH],
    bytes: [u8; BYTES],
    ends: [usize; KEYS],
    validity: Option<Validity>,
}

#[derive(Clone, Copy)]
struct Validity {
    zone_len: usize,
    count: usize,
    class: u16,
    set_ttl: u32,
    verified_at: u32,
    ttl: u32,
}

impl<const BYTES: usize, const KEYS: usize> RetainedKeys<BYTES, KEYS> {
    /// Empty caller-owned storage.
    pub const EMPTY: Self = Self {
        zone: [0; MAX_WIRE_NAME_LENGTH],
        bytes: [0; BYTES],
        ends: [0; KEYS],
        validity: None,
    };

    /// Replace the current keyset atomically. An oversized set leaves it intact.
    pub fn store(&mut self, keys: TrustedKeys<'_>) -> Result<(), Error> {
        let count = keys.set.records.len();
        let total = keys.set.records.iter().try_fold(0usize, |size, key| {
            size.checked_add(key.len()).ok_or(Error::Overflow)
        })?;
        if count > KEYS || total > BYTES {
            return Err(Error::Capacity);
        }
        let zone = keys.zone.wire();
        self.zone[..zone.len()].copy_from_slice(zone);
        let mut start = 0;
        for (key, end) in keys.set.records.iter().zip(&mut self.ends) {
            *end = start + key.len();
            self.bytes[start..*end].copy_from_slice(key);
            start = *end;
        }
        self.validity = Some(Validity {
            zone_len: zone.len(),
            count,
            class: keys.set.class,
            set_ttl: keys.set.ttl,
            verified_at: keys.verified_at,
            ttl: keys.ttl,
        });
        Ok(())
    }

    /// Borrow the retained keyset without renewing its validation lifetime.
    pub fn keys<'a>(
        &'a self,
        now: u32,
        records: &'a mut [&'a [u8]],
    ) -> Result<TrustedKeys<'a>, Error> {
        let meta = self.validity.ok_or(Error::NotReady)?;
        let zone = Name::from_wire(&self.zone[..meta.zone_len])?;
        let records = records.get_mut(..meta.count).ok_or(Error::Capacity)?;
        let mut start = 0;
        for (record, &end) in records.iter_mut().zip(&self.ends) {
            *record = &self.bytes[start..end];
            start = end;
        }
        let keys = TrustedKeys {
            zone,
            set: Rrset {
                owner: zone,
                kind: Type::DNSKEY.0,
                class: meta.class,
                ttl: meta.set_ttl,
                records,
            },
            verified_at: meta.verified_at,
            ttl: meta.ttl,
        };
        keys.remaining(now)?;
        Ok(keys)
    }

    /// Invalidate retained trust before reusing the same memory.
    pub fn clear(&mut self) {
        self.validity = None;
    }
}
