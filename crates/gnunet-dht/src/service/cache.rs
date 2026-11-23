//! Bounded DHT storage for validated blocks from local IPC and original peers.
use super::{Entry, Limits, ValidatedBlock, reserved};
use crate::routing;
use alloc::vec::Vec;
use core::cmp::Reverse;
use gnunet_types::Error;
use gnunet_wire::official::dht::{PATH_ELEMENT_LEN, RouteOptions};

const HEAP_PRIORITY_BUCKETS: usize = 24;

pub(super) struct Cache {
    entries: Vec<Entry>,
    scratch: Vec<usize>,
    payload_bytes: usize,
    path_bytes: usize,
    record_limit: usize,
    payload_limit: usize,
    approximate_keys: usize,
    anchor: Option<[u8; 64]>,
    path_limit: usize,
}

impl Cache {
    pub(super) fn new(limits: Limits) -> Result<Self, Error> {
        Ok(Self {
            entries: reserved(limits.cache_records)?,
            scratch: reserved(limits.cache_records)?,
            payload_bytes: 0,
            path_bytes: 0,
            record_limit: limits.cache_records,
            payload_limit: limits.cache_bytes,
            approximate_keys: limits.approximate_keys,
            anchor: None,
            path_limit: 0,
        })
    }

    pub(super) fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub(super) fn selected(&self) -> &[usize] {
        &self.scratch
    }

    pub(super) const fn payload_bytes(&self) -> usize {
        self.payload_bytes
    }

    pub(super) const fn path_bytes(&self) -> usize {
        self.path_bytes
    }

    pub(super) fn set_routing_scope(&mut self, identity: &[u8; 32], path_limit: usize) {
        self.anchor = Some(routing::peer_key(identity));
        self.path_limit = path_limit;
    }

    pub(super) fn rotate_identity(&mut self, identity: &[u8; 32]) {
        self.anchor = Some(routing::peer_key(identity));
        // The old last signature named the previous identity as its successor.
        for entry in &mut self.entries {
            if let Some(last) = entry.put_path.last_chunk::<PATH_ELEMENT_LEN>() {
                let mut predecessor = [0; 32];
                predecessor.copy_from_slice(&last[64..]);
                entry.truncated_peer = Some(predecessor);
                entry.options |= u32::from(RouteOptions::TRUNCATED.bits());
            }
            entry.put_path = Vec::new();
        }
        self.path_bytes = 0;
    }

    pub(super) fn expire(&mut self, now: u64) {
        self.entries.retain(|entry| {
            if entry.expiration >= now {
                return true;
            }
            self.payload_bytes -= entry.payload.capacity();
            self.path_bytes -= entry.put_path.capacity();
            false
        });
    }

    pub(super) fn clear(&mut self) {
        self.entries.clear();
        self.payload_bytes = 0;
        self.path_bytes = 0;
    }

    /// Retain the exact validated value and path if they can fit. On pressure,
    /// reserve the whole change before evicting any previously stored value.
    pub(super) fn store(&mut self, block: &ValidatedBlock<'_>, now: u64) -> bool {
        self.scratch.clear();
        let reply = &block.reply;
        let existing = self.entries.iter().position(|old| {
            old.key == *reply.key
                && old.kind == reply.kind
                && old.hash == block.hash
                && old.payload == reply.payload
        });
        if existing.is_some_and(|index| self.entries[index].expiration >= reply.expiration) {
            return true;
        }
        if self.record_limit == 0
            || reply.payload.len() > self.payload_limit
            || reply
                .put
                .as_bytes()
                .len()
                .saturating_add(reply.get.as_bytes().len())
                > self.path_limit
        {
            return false;
        }
        let Ok(entry) = block.retain() else {
            return false;
        };
        if entry.payload.capacity() > self.payload_limit
            || entry.put_path.capacity() > self.path_limit
        {
            return false;
        }
        let (old_payload, old_path) = existing.map_or((0, 0), |index| {
            let old = &self.entries[index];
            (old.payload.capacity(), old.put_path.capacity())
        });
        let Some(mut payload) =
            (self.payload_bytes - old_payload).checked_add(entry.payload.capacity())
        else {
            return false;
        };
        let Some(mut paths) = (self.path_bytes - old_path).checked_add(entry.put_path.capacity())
        else {
            return false;
        };
        let mut records = self.entries.len() + usize::from(existing.is_none());
        let fits = |records, payload, paths| {
            records <= self.record_limit
                && payload <= self.payload_limit
                && paths <= self.path_limit
        };
        if !fits(records, payload, paths) {
            self.scratch
                .extend((0..self.entries.len()).filter(|index| Some(*index) != existing));
            let anchor = self.anchor.as_ref();
            let incoming = eviction_priority(&entry, anchor, now, self.entries.len());
            let rank = |&index: &usize| eviction_priority(&self.entries[index], anchor, now, index);
            let contributes = |victim: &Entry, records, payload, paths| {
                records > self.record_limit
                    || (payload > self.payload_limit && victim.payload.capacity() > 0)
                    || (paths > self.path_limit && victim.put_path.capacity() > 0)
            };
            let Some(weakest) = self
                .scratch
                .iter()
                .copied()
                .filter(|&index| contributes(&self.entries[index], records, payload, paths))
                .min_by_key(rank)
            else {
                return false;
            };
            if rank(&weakest) >= incoming {
                return false;
            }
            let victim = &self.entries[weakest];
            if fits(
                records - 1,
                payload - victim.payload.capacity(),
                paths - victim.put_path.capacity(),
            ) {
                self.scratch.clear();
                self.scratch.push(weakest);
            } else {
                self.scratch.sort_unstable_by_key(rank);
            }
            let mut removed = 0;
            for candidate in 0..self.scratch.len() {
                let index = self.scratch[candidate];
                let victim = &self.entries[index];
                if !contributes(victim, records, payload, paths) {
                    continue;
                }
                if rank(&index) >= incoming {
                    return false;
                }
                records -= 1;
                payload -= victim.payload.capacity();
                paths -= victim.put_path.capacity();
                self.scratch[removed] = index;
                removed += 1;
                if fits(records, payload, paths) {
                    break;
                }
            }
            if !fits(records, payload, paths) {
                return false;
            }
            self.scratch.truncate(removed);
            self.scratch.sort_unstable();
        }

        let existing =
            existing.map(|index| index - self.scratch.partition_point(|&victim| victim < index));
        if !self.scratch.is_empty() {
            let mut victims = self.scratch.iter().copied().peekable();
            let mut index = 0;
            self.entries.retain(|_| {
                let remove = victims.next_if_eq(&index).is_some();
                index += 1;
                !remove
            });
        }
        if let Some(index) = existing {
            self.entries[index] = entry;
        } else {
            self.entries.push(entry);
        }
        self.payload_bytes = payload;
        self.path_bytes = paths;
        true
    }

    pub(super) fn select(&mut self, target: &[u8; 64], kind: u32, options: u32, now: u64) {
        let order = &mut self.scratch;
        order.clear();
        let approximate = options & u32::from(RouteOptions::FIND_APPROXIMATE.bits()) != 0;
        for (index, entry) in self.entries.iter().enumerate() {
            if entry.expiration >= now
                && (kind == 0 || kind == entry.kind)
                && (approximate || entry.key == *target)
            {
                order.push(index);
            }
        }
        order.sort_unstable_by(|&a, &b| {
            let left = &self.entries[a];
            let right = &self.entries[b];
            let order = || Reverse(left.expiration).cmp(&Reverse(right.expiration));
            if approximate {
                routing::distance_cmp(&left.key, &right.key, target).then_with(order)
            } else {
                order()
            }
            .then_with(|| a.cmp(&b))
        });
        let mut last = None;
        let mut keys = 0;
        if let Some(end) = order.iter().position(|&index| {
            let key = &self.entries[index].key;
            if last != Some(key) {
                keys += 1;
                last = Some(key);
            }
            keys > self.approximate_keys
        }) {
            order.truncate(end);
        }
    }
}

fn eviction_priority(
    entry: &Entry,
    anchor: Option<&[u8; 64]>,
    now: u64,
    index: usize,
) -> (bool, usize, u64, usize) {
    let live = entry.expiration >= now;
    let proximity = if live {
        anchor.map_or(0, |anchor| {
            routing::bucket(anchor, &entry.key)
                .unwrap_or(512)
                .min(HEAP_PRIORITY_BUCKETS - 1)
        })
    } else {
        0
    };
    (live, proximity, entry.expiration, index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::Reply;
    use gnunet_wire::official::dht::Path;

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Check the exact cache state after exhausting only its path quota"
    )]
    fn path_pressure_preserves_records_that_cannot_release_path_bytes() -> Result<(), Error> {
        let mut cache = Cache::new(Limits {
            cache_records: 4,
            cache_bytes: 4,
            ..Limits::default()
        })?;
        cache.path_limit = PATH_ELEMENT_LEN;
        let path = Path::new(&[7; PATH_ELEMENT_LEN])?;
        for (key, expiration, put) in [(1, 10, Path::empty()), (2, 20, path), (3, 30, path)] {
            let block = ValidatedBlock {
                reply: Reply {
                    key: &[key; 64],
                    kind: 13,
                    options: 0,
                    expiration,
                    payload: &[key],
                    put,
                    get: Path::empty(),
                    truncated: None,
                },
                hash: [key; 64],
            };
            assert!(cache.store(&block, 1));
        }
        assert_eq!(cache.entries().len(), 2);
        assert_eq!(cache.entries()[0].key, [1; 64]);
        assert_eq!(cache.entries()[1].key, [3; 64]);
        assert_eq!(cache.payload_bytes(), 2);
        assert_eq!(cache.path_bytes(), PATH_ELEMENT_LEN);
        Ok(())
    }
}
