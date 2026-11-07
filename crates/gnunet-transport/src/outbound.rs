//! Owned original transmissions and bounded peer-bound remote acknowledgement state.
//! Local communicator callbacks deliberately remain a separate engine owner.
use crate::{ClientId, PeerId};
use alloc::vec::Vec;
use gnunet_types::Error;
use zeroize::Zeroizing;

pub(crate) const LOCAL_HANDOFF_TIMEOUT: u64 = 5_000_000;
pub(crate) const RETENTION: u64 = 4 * 60 * 1_000_000;
const MAX_ALIASES: usize = 4;
const DEFAULT_RTO: u64 = 4_000_000;
const MIN_RTO: u64 = 40_000;
const MAX_RTO: u64 = 60_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Span {
    pub(crate) start: usize,
    pub(crate) end: usize,
}
impl Span {
    pub(crate) fn len(self) -> usize {
        self.end - self.start
    }
}
/// Compact settled-byte coverage; no packet bodies or C fragment tree copies.
pub(crate) struct Coverage {
    bits: Vec<u8>,
    length: usize,
    settled: usize,
}
impl Coverage {
    pub(crate) fn new(length: usize, prefix: usize) -> Result<Self, Error> {
        if prefix > length {
            return Err(Error::InvalidInput);
        }
        let mut bits = Vec::new();
        bits.try_reserve_exact(length.div_ceil(8))
            .map_err(|_| Error::Capacity)?;
        bits.resize(length.div_ceil(8), 0);
        let mut value = Self {
            bits,
            length,
            settled: 0,
        };
        value.mark(Span {
            start: 0,
            end: prefix,
        });
        Ok(value)
    }
    pub(crate) fn charge(&self) -> usize {
        self.bits.len()
    }
    pub(crate) fn complete(&self) -> bool {
        self.settled == self.length
    }
    pub(crate) const fn covered_bytes(&self) -> usize {
        self.settled
    }
    pub(crate) const fn total_bytes(&self) -> usize {
        self.length
    }
    pub(crate) fn mark(&mut self, span: Span) {
        debug_assert!(span.start <= span.end && span.end <= self.length);
        for i in span.start..span.end {
            let mask = 1 << (i % 8);
            if self.bits[i / 8] & mask == 0 {
                self.bits[i / 8] |= mask;
                self.settled += 1;
            }
        }
    }
    pub(crate) fn gap(&self, span: Span) -> Option<Span> {
        let start = (span.start..span.end).find(|i| self.bits[i / 8] & (1 << (i % 8)) == 0)?;
        let end = (start..span.end)
            .find(|i| self.bits[i / 8] & (1 << (i % 8)) != 0)
            .unwrap_or(span.end);
        Some(Span { start, end })
    }
}
#[derive(Clone, Copy)]
pub(crate) struct FragmentSend {
    pub(crate) id: [u8; 8],
    pub(crate) offset: usize,
}
/// The immutable original belongs to the local submitter until explicit retirement.
pub(crate) struct Job {
    pub(crate) id: u64,
    pub(crate) route: Option<u64>,
    pub(crate) peer: PeerId,
    pub(crate) message: Zeroizing<Vec<u8>>,
    pub(crate) fragment: Option<FragmentSend>,
    pub(crate) origin: Option<ClientId>,
    pub(crate) core: Option<ClientId>,
    pub(crate) control: bool,
    pub(crate) preferences: u32,
    pub(crate) coverage: Option<Coverage>,
    pub(crate) whole_sent: bool,
    pub(crate) expires: u64,
    pub(crate) deferred: Option<Error>,
}
impl Job {
    pub(crate) fn charge(&self) -> usize {
        self.message.len()
    }
    pub(crate) fn fresh_offset(&self) -> usize {
        self.fragment.map_or(
            if self.whole_sent {
                self.message.len()
            } else {
                0
            },
            |f| f.offset,
        )
    }
    pub(crate) fn fresh(&self) -> bool {
        self.fresh_offset() < self.message.len()
    }
    pub(crate) fn complete(&self) -> bool {
        !self.fresh() && self.coverage.as_ref().is_none_or(Coverage::complete)
    }
}
#[derive(Clone, Copy)]
struct Alias {
    uuid: [u8; 16],
    span: Span,
    sent: u64,
}
struct Pending {
    id: u64,
    job: u64,
    peer: PeerId,
    span: Span,
    aliases: [Option<Alias>; MAX_ALIASES],
    next_alias: usize,
    local_mid: Option<[u8; 8]>,
    due: u64,
    sends: u32,
    whole: bool,
}
#[derive(Clone, Copy)]
pub(crate) struct Retry {
    pub(crate) record: u64,
    pub(crate) span: Span,
    pub(crate) uuid: Option<[u8; 16]>,
}
#[derive(Clone, Copy)]
pub(crate) struct Acknowledged {
    pub(crate) job: u64,
    pub(crate) span: Span,
    pub(crate) rtt: Option<u64>,
}
/// Preallocated metadata for bounded spans and four delayed-attempt aliases each.
/// A peer uses at most min(32,ceil(maximum/2)) records, and one original at most
/// min(8,ceil(maximum/4)); a blackholed sender cannot monopolize the global table.
/// UUIDs are associated with a peer and an original job, never an arrival queue.
pub(crate) struct Book {
    entries: Vec<Pending>,
    maximum: usize,
    per_peer: usize,
    per_job: usize,
    serial: u64,
}
impl Book {
    pub(crate) fn new(maximum: usize) -> Result<Self, Error> {
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(maximum)
            .map_err(|_| Error::Capacity)?;
        Ok(Self {
            entries,
            maximum,
            per_peer: maximum.div_ceil(2).min(32),
            per_job: maximum.div_ceil(4).min(8),
            serial: 0,
        })
    }
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
    pub(crate) fn room(&self, job: u64, peer: PeerId) -> bool {
        self.entries.len() < self.maximum
            && self.entries.iter().filter(|e| e.peer == peer).count() < self.per_peer
            && self.entries.iter().filter(|e| e.job == job).count() < self.per_job
    }
    pub(crate) fn next_id(&self) -> Result<u64, Error> {
        self.serial.checked_add(1).ok_or(Error::Overflow)
    }
    pub(crate) fn unique(&self, uuid: [u8; 16]) -> bool {
        !self
            .entries
            .iter()
            .any(|e| e.aliases.iter().flatten().any(|a| a.uuid == uuid))
    }
    pub(crate) fn next(&self, job: u64, now: u64, coverage: &Coverage) -> Option<Retry> {
        self.entries
            .iter()
            .filter(|e| e.job == job && e.local_mid.is_none() && e.due != u64::MAX && now >= e.due)
            .find_map(|e| {
                coverage.gap(e.span).map(|span| Retry {
                    record: e.id,
                    span,
                    uuid: if e.whole {
                        e.aliases.iter().flatten().next().map(|a| a.uuid)
                    } else {
                        None
                    },
                })
            })
    }
    pub(crate) fn prepare(
        &self,
        retry: Option<Retry>,
        job: u64,
        peer: PeerId,
    ) -> Result<u64, Error> {
        if let Some(r) = retry {
            if self.entries.iter().any(|e| e.id == r.record) {
                return Ok(r.record);
            }
            return Err(Error::Stale);
        }
        if !self.room(job, peer) {
            return Err(Error::WouldBlock);
        }
        self.next_id()
    }
    /// Caller completed entropy/storage/wire preflight. A missing prepared
    /// original rejects before mutation; every commit thereafter is reserved.
    #[expect(
        clippy::too_many_arguments,
        reason = "Exact original range, alias, clock and local MID are separate authorities"
    )]
    pub(crate) fn commit(
        &mut self,
        id: u64,
        retry: Option<Retry>,
        job: u64,
        peer: PeerId,
        span: Span,
        uuid: [u8; 16],
        mid: [u8; 8],
        now: u64,
        rtt: u64,
        whole: bool,
    ) -> Result<(), Error> {
        let index = if retry.is_some() {
            self.entries
                .iter()
                .position(|e| e.id == id)
                .ok_or(Error::Stale)?
        } else {
            self.serial = id;
            self.entries.push(Pending {
                id,
                job,
                peer,
                span,
                aliases: [None; MAX_ALIASES],
                next_alias: 0,
                local_mid: None,
                due: u64::MAX,
                sends: 0,
                whole,
            });
            self.entries.len() - 1
        };
        let e = &mut self.entries[index];
        e.whole &= whole;
        if let Some(existing) = e.aliases.iter_mut().flatten().find(|a| a.uuid == uuid) {
            existing.sent = now;
        } else {
            e.aliases[e.next_alias] = Some(Alias {
                uuid,
                span,
                sent: now,
            });
            e.next_alias = (e.next_alias + 1) % MAX_ALIASES;
        }
        e.local_mid = Some(mid);
        e.sends = e.sends.saturating_add(1);
        let base = if rtt == 0 {
            DEFAULT_RTO
        } else {
            rtt.saturating_mul(4).max(MIN_RTO)
        };
        let delay = base
            .saturating_mul(1u64 << e.sends.saturating_sub(1).min(16))
            .min(MAX_RTO);
        e.due = now.saturating_add(delay);
        Ok(())
    }
    pub(crate) fn local_done(&mut self, id: u64, mid: [u8; 8]) {
        if let Some(e) = self
            .entries
            .iter_mut()
            .find(|e| e.id == id && e.local_mid == Some(mid))
        {
            e.local_mid = None;
        }
    }
    pub(crate) fn acknowledged(
        &self,
        peer: PeerId,
        uuid: [u8; 16],
        delay: u64,
        now: u64,
    ) -> Option<Acknowledged> {
        self.entries
            .iter()
            .filter(|e| e.peer == peer)
            .find_map(|e| {
                e.aliases
                    .iter()
                    .flatten()
                    .find(|a| a.uuid == uuid)
                    .map(|a| Acknowledged {
                        job: e.job,
                        span: a.span,
                        rtt: if e.sends == 1 && now >= a.sent {
                            Some(now.saturating_sub(a.sent).saturating_sub(delay))
                        } else {
                            None
                        },
                    })
            })
    }
    pub(crate) fn settled(&mut self, job: u64, coverage: &Coverage, confirmed: Span, now: u64) {
        self.entries
            .retain(|e| e.job != job || coverage.gap(e.span).is_some());
        for e in self.entries.iter_mut().filter(|e| {
            e.job == job && e.span.start <= confirmed.start && e.span.end >= confirmed.end
        }) {
            e.due = e.due.min(now);
        }
    }
    pub(crate) fn remove_job(&mut self, job: u64) {
        self.entries.retain(|e| e.job != job);
    }
}
