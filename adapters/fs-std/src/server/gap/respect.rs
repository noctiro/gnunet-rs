//! FS respect balances owned by the original peer identity.

use super::respect_store::{Event, LoadedBalance, LossCause, Outcome, Store, Submission};
use gnunet_service_runtime::clock::{Deadline, RuntimeClock};
use gnunet_types::{AbsoluteTime, Error as Fault};
use std::{
    error::Error as StdError,
    fmt,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::time::{Instant, Sleep};

const FLUSH_INTERVAL: u64 = 300_000_000;
const JOB_TIMEOUT: u64 = 5_000_000;
const RETRY_DELAY: u64 = 1_000_000;
const MAX_ATTEMPTS: u8 = 3;
const STOP_MICROS: u64 = 10_000_000;

type StoreError = super::respect_store::Error;
type Identity = [u8; 32];

#[derive(Debug)]
pub(super) enum Error {
    Protocol(Fault),
    Store(StoreError),
    Unpersisted {
        peer: Identity,
        failure: PersistenceFailure,
    },
}

#[derive(Debug)]
pub(super) enum PersistenceFailure {
    Native(StoreError),
    UnqualifiedRead(Outcome),
    InvalidWidth,
    SaveRejected(Outcome),
    SaveUncertain(Outcome),
    Shutdown,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "FS respect bookkeeping: {error}"),
            Self::Store(error) => write!(f, "FS respect PEERSTORE: {error}"),
            Self::Unpersisted { peer, failure } => {
                write!(f, "FS respect for peer {peer:02x?}: ")?;
                match failure {
                    PersistenceFailure::Native(error) => fmt::Display::fmt(error, f),
                    PersistenceFailure::UnqualifiedRead(outcome) => {
                        write!(f, "unqualified prior value ({outcome:?})")
                    }
                    PersistenceFailure::InvalidWidth => f.write_str("invalid prior value width"),
                    PersistenceFailure::SaveRejected(outcome) => {
                        write!(f, "snapshot rejected ({outcome:?})")
                    }
                    PersistenceFailure::SaveUncertain(outcome) => {
                        write!(f, "snapshot may have been applied ({outcome:?})")
                    }
                    PersistenceFailure::Shutdown => f.write_str("snapshot unsettled at shutdown"),
                }
            }
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::Store(error)
            | Self::Unpersisted {
                failure: PersistenceFailure::Native(error),
                ..
            } => Some(error),
            _ => None,
        }
    }
}

impl From<Fault> for Error {
    fn from(error: Fault) -> Self {
        Self::Protocol(error)
    }
}

impl From<StoreError> for Error {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

#[derive(Clone, Copy)]
struct Retry {
    at: u64,
    failures: u8,
}

impl Retry {
    const fn new(at: u64) -> Self {
        Self { at, failures: 0 }
    }

    fn failed(&mut self, now: u64) -> bool {
        self.failures += 1;
        self.at = later(now, RETRY_DELAY);
        self.failures < MAX_ATTEMPTS
    }
}

enum Disk {
    Loading(Retry),
    Known {
        saved: u32,
        flush_at: u64,
        retry: Retry,
    },
    ReadFailed(PersistenceFailure),
    SaveFailed {
        saved: u32,
        failure: PersistenceFailure,
    },
    SaveUncertain(PersistenceFailure),
}

struct Peer {
    identity: Identity,
    connected: bool,
    available: u32,
    disk: Disk,
}

impl Peer {
    fn next(&self, stopping: bool) -> Option<(u64, Work)> {
        match self.disk {
            Disk::Loading(retry) if !stopping && (self.connected || self.available != 0) => {
                Some((retry.at, Work::Load))
            }
            Disk::Known {
                saved,
                flush_at,
                retry,
            } if saved != self.available => {
                let at = if self.connected && !stopping {
                    flush_at.max(retry.at)
                } else {
                    retry.at
                };
                Some((at, Work::Save(self.available)))
            }
            _ => None,
        }
    }

    fn dirty(&self) -> bool {
        match self.disk {
            Disk::Loading(_) | Disk::ReadFailed(_) => self.available != 0,
            Disk::Known { saved, .. } | Disk::SaveFailed { saved, .. } => saved != self.available,
            // A lost original STORE may change disk after the local balance
            // returns to its previous qualified value.
            Disk::SaveUncertain(_) => true,
        }
    }

    fn loaded(&mut self, saved: u32, now: u64) {
        // Only credit earned since attachment is available before this receipt.
        self.available = self.available.saturating_add(saved);
        self.saved(saved, now);
    }

    fn saved(&mut self, balance: u32, now: u64) {
        self.disk = Disk::Known {
            saved: balance,
            flush_at: later(now, FLUSH_INTERVAL),
            retry: Retry::new(now),
        };
    }

    fn failure(&mut self, failure: PersistenceFailure, now: u64) -> Result<(), Fault> {
        match &mut self.disk {
            Disk::Loading(retry) => {
                if !retry.failed(now) {
                    self.disk = Disk::ReadFailed(failure);
                }
            }
            Disk::Known { saved, retry, .. } => {
                if !retry.failed(now) {
                    self.disk = Disk::SaveFailed {
                        saved: *saved,
                        failure,
                    };
                }
            }
            _ => return Err(Fault::Conflict),
        }
        Ok(())
    }

    fn take_failure(&mut self) -> PersistenceFailure {
        match std::mem::replace(
            &mut self.disk,
            Disk::SaveUncertain(PersistenceFailure::Shutdown),
        ) {
            Disk::ReadFailed(failure)
            | Disk::SaveFailed { failure, .. }
            | Disk::SaveUncertain(failure) => failure,
            _ => PersistenceFailure::Shutdown,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Work {
    Load,
    Save(u32),
}

#[derive(Clone, Copy)]
struct Original {
    peer: Identity,
    token: u64,
    work: Work,
}

struct Stop {
    expires: u64,
    hard: Instant,
    alarm: Option<Pin<Box<Sleep>>>,
}

impl Stop {
    fn expired(&mut self, cx: &mut Context<'_>, now: u64) -> bool {
        now >= self.expires
            || self
                .alarm
                .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(self.hard)))
                .as_mut()
                .poll(cx)
                .is_ready()
    }
}

/// The bounded peer ledger retains a detached identity through its last original
/// PEERSTORE operation. A replacement generation adopts that same live balance.
pub(super) struct Book<'c> {
    store: Store<'c>,
    clock: Arc<dyn RuntimeClock>,
    peers: Vec<Peer>,
    capacity: usize,
    serial: u64,
    active: Option<Original>,
    timer: Option<(u64, Deadline)>,
    recovery: Option<Retry>,
    waker: Option<Waker>,
    stop: Option<Stop>,
    closed: bool,
}

/// Only an attached original peer can supply and settle a forwarding budget.
pub(super) struct Account<'a> {
    balance: &'a mut u32,
    waker: Option<&'a Waker>,
}

impl Account<'_> {
    pub(super) fn budget(&self, load: gnunet_fs::gap::load::Load) -> gnunet_fs::gap::GetBudget {
        gnunet_fs::gap::GetBudget::new(*self.balance, load)
    }

    pub(super) fn debit(&mut self, amount: u32) -> Result<(), Fault> {
        self.change(self.balance.checked_sub(amount).ok_or(Fault::Conflict)?);
        Ok(())
    }

    pub(super) fn credit(&mut self, amount: u32) {
        self.change(self.balance.saturating_add(amount));
    }

    fn change(&mut self, updated: u32) {
        if updated != *self.balance {
            *self.balance = updated;
            if let Some(waker) = self.waker {
                waker.wake_by_ref();
            }
        }
    }
}

impl<'c> Book<'c> {
    pub(super) fn new(store: Store<'c>, capacity: usize) -> Result<Self, Error> {
        if capacity == 0 || store.pending() != 0 {
            return Err(Fault::InvalidInput.into());
        }
        let mut peers = Vec::new();
        peers
            .try_reserve_exact(capacity)
            .map_err(|_| Fault::Capacity)?;
        Ok(Self {
            clock: store.clock(),
            store,
            peers,
            capacity,
            serial: 0,
            active: None,
            timer: None,
            recovery: None,
            waker: None,
            stop: None,
            closed: false,
        })
    }

    pub(super) fn clock(&self) -> Arc<dyn RuntimeClock> {
        Arc::clone(&self.clock)
    }

    fn position(&self, peer: &Identity) -> Option<usize> {
        self.peers.iter().position(|entry| &entry.identity == peer)
    }

    fn forget_settled(&mut self) {
        let active = self.active.map(|work| work.peer);
        self.peers
            .retain(|entry| entry.connected || entry.dirty() || active == Some(entry.identity));
    }

    fn wake(&self) {
        if let Some(waker) = &self.waker {
            waker.wake_by_ref();
        }
    }

    pub(super) fn attach(&mut self, peer: Identity, now: u64) -> Result<(), Error> {
        if self.stop.is_some() || self.closed {
            return Err(Fault::Closed.into());
        }
        if let Some(index) = self.position(&peer) {
            let entry = &mut self.peers[index];
            if !entry.connected {
                entry.connected = true;
                match entry.disk {
                    Disk::ReadFailed(_) => entry.disk = Disk::Loading(Retry::new(now)),
                    Disk::SaveFailed { saved, .. } => {
                        entry.disk = Disk::Known {
                            saved,
                            flush_at: now,
                            retry: Retry::new(now),
                        };
                    }
                    _ => {}
                }
            }
            self.wake();
            return Ok(());
        }
        self.forget_settled();
        if self.peers.len() >= self.capacity {
            return Err(Fault::Capacity.into());
        }
        self.peers.push(Peer {
            identity: peer,
            connected: true,
            available: 0,
            disk: Disk::Loading(Retry::new(now)),
        });
        self.wake();
        Ok(())
    }

    pub(super) fn detach(&mut self, peer: Identity, now: u64) {
        if let Some(index) = self.position(&peer) {
            let entry = &mut self.peers[index];
            entry.connected = false;
            if let Disk::Known { flush_at, .. } = &mut entry.disk {
                *flush_at = (*flush_at).min(now);
            }
        }
        self.forget_settled();
        self.wake();
    }

    pub(super) fn account(&mut self, peer: &Identity) -> Result<Account<'_>, Fault> {
        if self.stop.is_some() || self.closed {
            return Err(Fault::Closed);
        }
        let peer = self
            .peers
            .iter_mut()
            .find(|entry| entry.connected && &entry.identity == peer)
            .ok_or(Fault::StaleGeneration)?;
        Ok(Account {
            balance: &mut peer.available,
            waker: self.waker.as_ref(),
        })
    }

    pub(super) fn request_stop(&mut self, now: u64) {
        if self.stop.is_some() {
            return;
        }
        let started = Instant::now();
        self.stop = Some(Stop {
            expires: later(now, STOP_MICROS),
            hard: started
                .checked_add(Duration::from_micros(STOP_MICROS))
                .unwrap_or(started),
            alarm: None,
        });
        for peer in &mut self.peers {
            peer.connected = false;
        }
        self.wake();
    }

    pub(super) fn quiesced(&self) -> bool {
        (self.stop.is_some() || self.closed)
            && self.active.is_none()
            && self.store.pending() == 0
            && (self.closed || !self.peers.iter().any(|peer| peer.next(true).is_some()))
    }

    fn settle(&mut self, peer: Identity, token: u64, work: Work) -> Result<&mut Peer, Fault> {
        let original = self.active.ok_or(Fault::StaleGeneration)?;
        if original.peer != peer || original.token != token || original.work != work {
            return Err(Fault::Authentication);
        }
        let index = self.position(&peer).ok_or(Fault::StaleGeneration)?;
        self.active = None;
        Ok(&mut self.peers[index])
    }

    fn event(&mut self, event: Event, now: u64) -> Result<(), Error> {
        match event {
            Event::Loaded {
                token,
                peer,
                value,
                outcome,
            } => {
                let entry = self.settle(peer, token, Work::Load)?;
                match (value, outcome) {
                    (LoadedBalance::Value(value), _) => entry.loaded(value, now),
                    (LoadedBalance::NoRecord, Outcome::IterationEnd(1)) => entry.loaded(0, now),
                    (LoadedBalance::InvalidWidth, _) => {
                        entry.disk = Disk::ReadFailed(PersistenceFailure::InvalidWidth);
                    }
                    _ => entry.failure(PersistenceFailure::UnqualifiedRead(outcome), now)?,
                }
            }
            Event::Saved {
                token,
                peer,
                balance,
                outcome,
            } => {
                let entry = self.settle(peer, token, Work::Save(balance))?;
                match outcome {
                    Outcome::StoreResult(1) => entry.saved(balance, now),
                    Outcome::Local {
                        submission: Submission::Unsent,
                        ..
                    } => {
                        entry.failure(PersistenceFailure::SaveRejected(outcome), now)?;
                    }
                    Outcome::StoreResult(_) => {
                        let Disk::Known { saved, .. } = entry.disk else {
                            return Err(Fault::Conflict.into());
                        };
                        entry.disk = Disk::SaveFailed {
                            saved,
                            failure: PersistenceFailure::SaveRejected(outcome),
                        };
                    }
                    _ => {
                        // No new snapshot overtakes an original possibly
                        // applied STORE after losing its authoritative receipt.
                        entry.disk =
                            Disk::SaveUncertain(PersistenceFailure::SaveUncertain(outcome));
                    }
                }
            }
            Event::Lost(LossCause::Clock(_) | LossCause::Ports(_)) => {
                self.recovery = Some(Retry::new(now));
            }
            Event::Activity | Event::Lost(_) => {}
        }
        self.forget_settled();
        Ok(())
    }

    fn start(&mut self, index: usize, work: Work, now: u64) -> Result<(), Error> {
        let peer = self.peers[index].identity;
        let expires = later(now, JOB_TIMEOUT);
        let expires = self
            .stop
            .as_ref()
            .map_or(expires, |stop| expires.min(stop.expires));
        if expires <= now {
            return Err(Fault::TimeUncertain.into());
        }
        let token = self.serial.checked_add(1).ok_or(Fault::Overflow)?;
        let admission = match work {
            Work::Load => self.store.load(token, peer, expires),
            Work::Save(balance) => self.store.save(token, peer, balance, expires),
        };
        match admission {
            Ok(()) => {
                self.serial = token;
                self.active = Some(Original { peer, token, work });
            }
            Err(error) => self.peers[index].failure(PersistenceFailure::Native(error), now)?,
        }
        Ok(())
    }

    fn wait(&mut self, cx: &mut Context<'_>, at: u64) -> Result<bool, Error> {
        if self
            .timer
            .as_ref()
            .is_none_or(|(original, _)| *original != at)
        {
            let deadline = Deadline::at(self.clock(), AbsoluteTime::from_micros(at))?;
            self.timer = Some((at, deadline));
        }
        if let Some((_, deadline)) = &mut self.timer
            && let Poll::Ready(result) = Pin::new(deadline).poll(cx)
        {
            self.timer = None;
            result?;
            return Ok(true);
        }
        Ok(false)
    }

    pub(super) fn poll(&mut self, cx: &mut Context<'_>, now: u64) -> Result<bool, Error> {
        if self
            .waker
            .as_ref()
            .is_none_or(|waker| !waker.will_wake(cx.waker()))
        {
            self.waker = Some(cx.waker().clone());
        }
        if !self.closed && self.stop.as_mut().is_some_and(|stop| stop.expired(cx, now)) {
            self.close_native()?;
            return Ok(true);
        }
        if self.store.pending() != 0 {
            return match self.store.poll(cx) {
                Poll::Ready(event) => {
                    self.event(event?, now)?;
                    Ok(true)
                }
                Poll::Pending => Ok(false),
            };
        }
        if self.closed {
            return Ok(false);
        }

        let next = self
            .peers
            .iter()
            .enumerate()
            .filter_map(|(index, peer)| {
                peer.next(self.stop.is_some())
                    .map(|(at, work)| (at, index, work))
            })
            .min_by_key(|(at, _, _)| *at);
        let Some((at, index, work)) = next else {
            self.timer = None;
            return Ok(false);
        };
        let at = self.recovery.map_or(at, |retry| at.max(retry.at));
        if now < at {
            return self.wait(cx, at);
        }
        self.timer = None;
        if let Some(mut retry) = self.recovery {
            self.recovery = None;
            if let Err(error) = self.store.recover() {
                if retry.failed(now) {
                    self.recovery = Some(retry);
                } else {
                    return Err(error.into());
                }
                return Ok(true);
            }
        }
        self.start(index, work, now)?;
        Ok(true)
    }

    fn close_native(&mut self) -> Result<(), Error> {
        if !self.closed {
            self.closed = true;
            self.timer = None;
            self.store.close()?;
        }
        Ok(())
    }

    pub(super) fn close(&mut self) -> Result<(), Error> {
        self.close_native()?;
        let mut cx = Context::from_waker(Waker::noop());
        // There is only one original logical job. Permit its terminal result,
        // any independent original native debt, and explicit physical close.
        for _ in 0..4 {
            if self.store.pending() == 0 {
                break;
            }
            match self.store.poll(&mut cx) {
                Poll::Ready(event) => self.event(event?, 0)?,
                Poll::Pending => return Err(Fault::WouldBlock.into()),
            }
        }
        if self.active.is_some() || self.store.pending() != 0 {
            return Err(Fault::WouldBlock.into());
        }
        if let Some(entry) = self.peers.iter_mut().find(|entry| entry.dirty()) {
            return Err(Error::Unpersisted {
                peer: entry.identity,
                failure: entry.take_failure(),
            });
        }
        Ok(())
    }
}

fn later(now: u64, delay: u64) -> u64 {
    now.saturating_add(delay).min(u64::MAX - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_save_ack_leaves_new_changes_dirty() {
        let mut peer = Peer {
            identity: [1; 32],
            connected: true,
            available: 2,
            disk: Disk::Loading(Retry::new(1)),
        };
        assert!(matches!(peer.next(false), Some((1, Work::Load))));
        assert!(peer.next(true).is_none());
        peer.loaded(5, 2);
        assert_eq!(peer.available, 7);
        assert!(matches!(peer.next(false), Some((at, Work::Save(7))) if at == 2 + FLUSH_INTERVAL));
        peer.available += 1;
        peer.saved(7, 3);
        assert!(peer.dirty());
        peer.connected = false;
        assert!(matches!(peer.next(false), Some((3, Work::Save(8)))));
    }

    #[test]
    fn uncertain_save_retains_its_fence_after_local_balance_returns() {
        let peer = Peer {
            identity: [1; 32],
            connected: false,
            available: 0,
            disk: Disk::SaveUncertain(PersistenceFailure::Shutdown),
        };
        assert!(peer.dirty());
        assert!(peer.next(false).is_none());
        assert!(peer.next(true).is_none());
    }
}
