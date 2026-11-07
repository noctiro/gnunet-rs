use super::Preference;
use crate::{ClientId, PeerId};
use alloc::vec::Vec;
use gnunet_types::Error;
// Local retry policy, not a promise of exact C scheduler timing.
const RETRY_MIN: u64 = 1_000_000;
const RETRY_MAX: u64 = 60_000_000;
/// One original address-discovery lease for a live application suggestion.
/// A matching peer or integer alone cannot reconstruct its authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Discovery {
    owner: ClientId,
    request: u64,
    attempt: u64,
    peer: PeerId,
    cursor: usize,
}
impl Discovery {
    /// Expected peer. Addresses remain untrusted until communicator authentication.
    #[must_use]
    pub const fn peer(&self) -> PeerId {
        self.peer
    }
    /// Resume position within the source's bounded candidate enumeration.
    /// It is local scheduling metadata, not protocol correlation or authority.
    #[must_use]
    pub const fn cursor(&self) -> usize {
        self.cursor
    }
}
struct Request {
    owner: ClientId,
    id: u64,
    preference: Preference,
    leased: Option<u64>,
    due: u64,
    backoff: u64,
    cursor: usize,
    connected: bool,
}
pub(crate) struct Demands {
    requests: Vec<Request>,
    maximum: usize,
    serial: u64,
    turn: usize,
}
impl Demands {
    pub(crate) fn new(maximum: usize) -> Result<Self, Error> {
        let mut requests = Vec::new();
        requests
            .try_reserve_exact(maximum)
            .map_err(|_| Error::Capacity)?;
        Ok(Self {
            requests,
            maximum,
            serial: 0,
            turn: 0,
        })
    }
    pub(crate) fn add(
        &mut self,
        owner: ClientId,
        preference: Preference,
        now: u64,
    ) -> Result<(), Error> {
        if self
            .requests
            .iter()
            .any(|r| r.owner == owner && r.preference.peer == preference.peer)
        {
            return Err(Error::Conflict);
        }
        if self.requests.len() == self.maximum {
            // This is a bounded request refusal, not allocator/storage failure.
            // The host retires only this original local MQ; other clients live.
            return Err(Error::WouldBlock);
        }
        let id = self.serial.checked_add(1).ok_or(Error::Overflow)?;
        self.requests.push(Request {
            owner,
            id,
            preference,
            leased: None,
            due: now,
            backoff: RETRY_MIN,
            cursor: 0,
            connected: false,
        });
        self.serial = id;
        Ok(())
    }
    pub(crate) fn cancel(&mut self, owner: &ClientId, peer: PeerId) -> Result<(), Error> {
        let i = self
            .requests
            .iter()
            .position(|r| r.owner == *owner && r.preference.peer == peer)
            .ok_or(Error::NotFound)?;
        self.requests.remove(i);
        Ok(())
    }
    pub(crate) fn close(&mut self, owner: &ClientId) {
        self.requests.retain(|r| r.owner != *owner);
    }
    pub(crate) fn live(&self, id: &Discovery) -> bool {
        self.requests.iter().any(|r| {
            r.owner == id.owner
                && r.id == id.request
                && r.leased == Some(id.attempt)
                && r.preference.peer == id.peer
        })
    }
    pub(crate) fn next(
        &mut self,
        now: u64,
        connected: impl Fn(PeerId) -> bool,
    ) -> Result<Option<Discovery>, Error> {
        for offset in 0..self.requests.len() {
            let i = (self.turn + offset) % self.requests.len();
            let r = &mut self.requests[i];
            let up = connected(r.preference.peer);
            if up {
                r.connected = true;
                continue;
            }
            if r.connected {
                r.connected = false;
                r.due = now;
                r.backoff = RETRY_MIN;
                r.cursor = 0;
            }
            if r.leased.is_some() || r.due > now {
                continue;
            }
            let attempt = self.serial.checked_add(1).ok_or(Error::Overflow)?;
            r.leased = Some(attempt);
            self.serial = attempt;
            self.turn = i + 1;
            return Ok(Some(Discovery {
                owner: r.owner.clone(),
                request: r.id,
                attempt,
                peer: r.preference.peer,
                cursor: r.cursor,
            }));
        }
        Ok(None)
    }
    pub(crate) fn complete(
        &mut self,
        id: &Discovery,
        now: u64,
        cursor: usize,
        finished: bool,
    ) -> Result<(), Error> {
        if !self.live(id) {
            return Err(Error::Stale);
        }
        let r = self
            .requests
            .iter_mut()
            .find(|r| r.id == id.request)
            .ok_or(Error::Stale)?;
        let due = now
            .checked_add(if finished { r.backoff } else { RETRY_MIN })
            .ok_or(Error::Overflow)?;
        r.cursor = if finished { 0 } else { cursor };
        r.leased = None;
        r.due = due;
        if finished {
            r.backoff = r.backoff.saturating_mul(2).min(RETRY_MAX);
        }
        Ok(())
    }
    pub(crate) fn len(&self) -> usize {
        self.requests.len()
    }
}
