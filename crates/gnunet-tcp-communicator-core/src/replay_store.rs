//! Synchronous durable history for caller-driven TCP sessions.
use crate::{
    registry::Instance,
    session::{Effect, Phase, REPLAY_CAPACITY, ReplayKind, ResultKind, Session, Ticket, Time},
};
use core::fmt;
use gnunet_crypto::{EddsaPublicKey, Entropy};
use gnunet_types::Error;

/// Verified result of an atomic maximum update.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Commit {
    /// The exact requested value advanced durable history.
    Advanced,
    /// The exact requested value was already durable. No write occurred.
    Current,
    /// The verified durable value was greater than the request. No write occurred.
    Newer(u64),
}

/// The physical outcome of a failed synchronous commit.
#[derive(Debug)]
pub enum CommitFailure<E> {
    /// The operation conclusively did not change durable history.
    Failed(E),
    /// Recovery must establish the actual floor before further admissions.
    OutcomeUnknown(E),
}

/// Original storage for the official replay keys of one local identity.
///
/// The owner keeps this namespace bound to that identity. Records are keyed by
/// the verified remote peer and the official replay key. Corrupt, incomplete or
/// unreadable history fails lookup. A fresh namespace or an absent record has
/// no floor.
pub trait Backend {
    /// Diagnostic from the original storage operation.
    type Error;

    /// Read one consistent snapshot of the durable maximum.
    fn load_max(
        &mut self,
        peer: EddsaPublicKey,
        kind: ReplayKind,
    ) -> Result<Option<u64>, Self::Error>;

    /// Compare and commit in one operation, including across concurrent writers.
    ///
    /// Wait for durable publication before reporting an advance. An equal or
    /// newer value retains its original storage. Return unknown when a failure
    /// leaves the effect of publication uncertain.
    fn commit_max(
        &mut self,
        peer: EddsaPublicKey,
        kind: ReplayKind,
        value: u64,
    ) -> Result<Commit, CommitFailure<Self::Error>>;
}

/// A failed replay effect and its original cause.
#[derive(Debug)]
pub enum ReplayError<E> {
    /// The session or the adapter refused the original operation.
    Session(Error),
    /// The original storage failed to read or conclusively failed to commit.
    Storage(E),
    /// The original commit was uncertain. This adapter has closed admission.
    OutcomeUnknown(E),
    /// Further lookups and writes are refused while history remains uncertain.
    Fenced,
    /// The received signed time is older than verified durable history.
    Older {
        /// Exact value bound to the original replay effect.
        received: u64,
        /// Actual durable maximum at lookup or commit.
        floor: u64,
    },
}

impl<E> From<Error> for ReplayError<E> {
    fn from(error: Error) -> Self {
        Self::Session(error)
    }
}

impl<E: fmt::Display> fmt::Display for ReplayError<E> {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Session(error) => write!(out, "TCP replay operation failed ({error})"),
            Self::Storage(error) => write!(out, "TCP replay storage failed ({error})"),
            Self::OutcomeUnknown(error) => {
                write!(out, "TCP replay commit outcome is unknown ({error})")
            }
            Self::Fenced => out.write_str("TCP replay history requires recovery"),
            Self::Older { received, floor } => {
                write!(
                    out,
                    "TCP replay time {received} is older than durable floor {floor}"
                )
            }
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for ReplayError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Session(error) => Some(error),
            Self::Storage(error) | Self::OutcomeUnknown(error) => Some(error),
            Self::Fenced | Self::Older { .. } => None,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum IteratorState {
    RecordDelivered,
    Ended,
}

#[derive(Clone, Copy)]
struct Scan<'scope> {
    owner: Instance<'scope>,
    original: Ticket<'scope>,
    peer: EddsaPublicKey,
    kind: ReplayKind,
    received: u64,
    state: IteratorState,
}

/// Bounded synchronous owner of a durable replay backend and its original scans.
///
/// Admission is limited to one replay transaction per session and key kind.
/// The host drives replay before ordinary effects or network I/O and continues
/// to drive original cancellation effects on failure. Drive all native close
/// effects before reusing the physical session's buffers or slot.
pub struct ReplayStore<'scope, B, const N: usize = REPLAY_CAPACITY> {
    backend: B,
    scans: [Option<Scan<'scope>>; N],
    fenced: bool,
}

impl<'scope, B, const N: usize> ReplayStore<'scope, B, N> {
    /// Take one already opened and verified durable history backend.
    #[must_use]
    pub const fn new(backend: B) -> Self {
        Self {
            backend,
            scans: [None; N],
            fenced: false,
        }
    }

    /// Whether an original scan or its terminal store remains outstanding.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        self.scans.iter().any(Option::is_some)
    }

    /// Whether future history operations require explicit backend recovery.
    #[must_use]
    pub const fn is_fenced(&self) -> bool {
        self.fenced
    }
}

impl<'scope, B: Backend, const N: usize> ReplayStore<'scope, B, N> {
    /// Execute the current session's original replay lease.
    ///
    /// `Ok(false)` leaves a non-replay lease with its host. An error is terminal
    /// for ordinary work on this session. The caller must retire the original
    /// native stream, replay cancellations and any already-admitted callbacks.
    pub fn drive(
        &mut self,
        session: &mut Session<'scope>,
        ticket: Ticket<'scope>,
        time: Time,
        entropy: &mut impl Entropy,
    ) -> Result<bool, ReplayError<B::Error>> {
        let effect = session.effect(ticket)?;
        let owner = session.instance();
        if closing(session.phase()) {
            for entry in &mut self.scans {
                if entry
                    .is_some_and(|scan| scan.owner == owner && scan.state == IteratorState::Ended)
                {
                    *entry = None;
                }
            }
        }
        match effect {
            Effect::ReplayStart {
                kind,
                peer,
                received,
            } => {
                if closing(session.phase()) {
                    session.acknowledge(ticket, ResultKind::Failed, time, entropy)?;
                    return Ok(true);
                }
                if self.fenced {
                    return reject(session, ticket, time, entropy, ReplayError::Fenced);
                }
                if self
                    .scans
                    .iter()
                    .flatten()
                    .any(|scan| scan.owner == owner && scan.kind == kind)
                {
                    return reject(session, ticket, time, entropy, Error::Conflict.into());
                }
                let Some(slot) = self.scans.iter().position(Option::is_none) else {
                    return reject(session, ticket, time, entropy, Error::Capacity.into());
                };
                let floor = match self.backend.load_max(peer, kind) {
                    Ok(floor) => floor,
                    Err(error) => {
                        return reject(session, ticket, time, entropy, ReplayError::Storage(error));
                    }
                };
                if let Some(floor) = floor
                    && floor > received
                {
                    return reject(
                        session,
                        ticket,
                        time,
                        entropy,
                        ReplayError::Older { received, floor },
                    );
                }
                let value = floor.map(u64::to_be_bytes);
                self.scans[slot] = Some(Scan {
                    owner,
                    original: ticket,
                    peer,
                    kind,
                    received,
                    state: IteratorState::RecordDelivered,
                });
                session.acknowledge(ticket, ResultKind::Success, time, entropy)?;
                session.replay_record(ticket, value.as_ref().map(<[u8; 8]>::as_slice), time)?;
                if value.is_none() {
                    self.end_scan(slot, session.phase());
                }
            }
            Effect::ReplayNext(kind, original) => {
                let Some(slot) = self.open_scan(original, kind) else {
                    return reject(session, ticket, time, entropy, Error::Stale.into());
                };
                if self.fenced {
                    self.scans[slot] = None;
                    session.replay_failed(original, time)?;
                    return Err(ReplayError::Fenced);
                }
                session.acknowledge(ticket, ResultKind::Success, time, entropy)?;
                // The single verified maximum has been delivered. This is the
                // end of the original local snapshot, with no further read.
                session.replay_record(original, None, time)?;
                self.end_scan(slot, session.phase());
            }
            Effect::ReplayStore { kind, peer, value } => {
                if closing(session.phase()) {
                    session.acknowledge(ticket, ResultKind::Failed, time, entropy)?;
                    return Ok(true);
                }
                let received = u64::from_be_bytes(value);
                let Some(slot) = self.scans.iter().position(|entry| {
                    entry.is_some_and(|scan| {
                        scan.owner == owner && scan.kind == kind && scan.peer == peer
                    })
                }) else {
                    return reject(session, ticket, time, entropy, Error::Stale.into());
                };
                let scan = self.scans[slot].take().ok_or(Error::Stale)?;
                if scan.state != IteratorState::Ended || scan.received != received {
                    if scan.state == IteratorState::RecordDelivered {
                        self.scans[slot] = Some(scan);
                    }
                    return reject(session, ticket, time, entropy, Error::Conflict.into());
                }
                if self.fenced {
                    return reject(session, ticket, time, entropy, ReplayError::Fenced);
                }
                let completion = match self.backend.commit_max(peer, kind, received) {
                    Ok(Commit::Advanced | Commit::Current) => Ok(()),
                    Ok(Commit::Newer(floor)) if floor > received => {
                        Err(ReplayError::Older { received, floor })
                    }
                    Ok(Commit::Newer(_)) => {
                        self.fenced = true;
                        Err(ReplayError::Session(Error::Conflict))
                    }
                    Err(CommitFailure::Failed(error)) => Err(ReplayError::Storage(error)),
                    Err(CommitFailure::OutcomeUnknown(error)) => {
                        self.fenced = true;
                        Err(ReplayError::OutcomeUnknown(error))
                    }
                };
                // This original synchronous commit already ran. Its execution
                // and its durable result settle the two session obligations.
                session.acknowledge(ticket, ResultKind::Success, time, entropy)?;
                session.replay_stored(ticket, completion.is_ok())?;
                completion?;
            }
            Effect::ReplayCancel(kind, false, original) => {
                let Some(slot) = self.open_scan(original, kind) else {
                    return reject(session, ticket, time, entropy, Error::Stale.into());
                };
                self.scans[slot] = None;
                session.acknowledge(ticket, ResultKind::Success, time, entropy)?;
            }
            Effect::ReplayCancel(_, true, _) => {
                // A synchronous store has no live backend handle to cancel.
                return reject(session, ticket, time, entropy, Error::Stale.into());
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn open_scan(&self, original: Ticket<'scope>, kind: ReplayKind) -> Option<usize> {
        self.scans.iter().position(|entry| {
            entry.is_some_and(|scan| {
                scan.original == original
                    && scan.kind == kind
                    && scan.state == IteratorState::RecordDelivered
            })
        })
    }

    fn end_scan(&mut self, slot: usize, phase: Phase) {
        if closing(phase) {
            self.scans[slot] = None;
        } else if let Some(scan) = self.scans[slot].as_mut() {
            scan.state = IteratorState::Ended;
        }
    }
}

fn closing(phase: Phase) -> bool {
    matches!(
        phase,
        Phase::Finishing | Phase::Closing | Phase::Detached | Phase::Closed
    )
}

fn reject<E>(
    session: &mut Session<'_>,
    ticket: Ticket<'_>,
    time: Time,
    entropy: &mut impl Entropy,
    error: ReplayError<E>,
) -> Result<bool, ReplayError<E>> {
    session.acknowledge(ticket, ResultKind::Failed, time, entropy)?;
    session.finish(time)?;
    Err(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        session::{Buffers, CIPHERTEXT_CAPACITY, CompletionSlot, Identity, KeyRing, Policy, Scope},
        wire,
    };
    use core::num::NonZeroUsize;

    const TIME: Time = Time { now: 1, signed: 40 };

    struct Random(u64);
    impl Entropy for Random {
        fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
            for byte in bytes {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                *byte = self.0 as u8;
            }
            Ok(())
        }
    }

    struct History {
        peer: EddsaPublicKey,
        floor: u64,
        commit: Option<Result<Commit, CommitFailure<Error>>>,
    }
    impl Backend for History {
        type Error = Error;

        fn load_max(
            &mut self,
            peer: EddsaPublicKey,
            kind: ReplayKind,
        ) -> Result<Option<u64>, Error> {
            if peer != self.peer || kind != ReplayKind::Handshake {
                return Err(Error::Authentication);
            }
            Ok(Some(self.floor))
        }

        fn commit_max(
            &mut self,
            peer: EddsaPublicKey,
            kind: ReplayKind,
            value: u64,
        ) -> Result<Commit, CommitFailure<Error>> {
            if peer != self.peer || kind != ReplayKind::Handshake || value != TIME.signed {
                return Err(CommitFailure::Failed(Error::Authentication));
            }
            self.commit
                .take()
                .ok_or(CommitFailure::Failed(Error::Conflict))?
        }
    }

    #[test]
    fn real_handshake_scan_requires_next_and_fences_an_uncertain_commit()
    -> Result<(), ReplayError<Error>> {
        let mut random = Random(41);
        let local = KeyRing::from_seed([11; 32]);
        let remote = KeyRing::from_seed([23; 32]);
        let mut policy = Policy::reference(NonZeroUsize::new(128).ok_or(Error::InvalidInput)?);
        policy.max_backpressure = 1;
        let mut send_scope = Scope::new();
        let mut send_rx = std::vec![0; wire::MAX_RECORD];
        let mut send_tx = std::vec![0; CIPHERTEXT_CAPACITY];
        let mut send_plain = std::vec![0; wire::MAX_RECORD];
        let mut send_completions = [CompletionSlot::default()];
        let mut sender = Session::new(
            &mut send_scope,
            Identity::from_keys(&remote),
            Some(local.public()),
            Buffers {
                receive: &mut send_rx,
                transmit: &mut send_tx,
                plaintext: &mut send_plain,
                completions: &mut send_completions,
            },
            policy,
            TIME,
            &mut random,
        )?;
        let write = sender
            .write_ready(TIME, &mut random)?
            .ok_or(Error::NotReady)?;
        let initial = sender.write_bytes(write)?;

        for (floor, commit, uncertain) in [
            (TIME.signed, Ok(Commit::Current), false),
            (
                TIME.signed - 1,
                Err(CommitFailure::OutcomeUnknown(Error::Io)),
                true,
            ),
        ] {
            let mut scope = Scope::new();
            let mut rx = std::vec![0; wire::MAX_RECORD];
            let mut tx = std::vec![0; CIPHERTEXT_CAPACITY];
            let mut plain = std::vec![0; wire::MAX_RECORD];
            let mut completions = [CompletionSlot::default()];
            let mut receiver = Session::new(
                &mut scope,
                Identity::from_keys(&local),
                None,
                Buffers {
                    receive: &mut rx,
                    transmit: &mut tx,
                    plaintext: &mut plain,
                    completions: &mut completions,
                },
                policy,
                TIME,
                &mut random,
            )?;
            if receiver.ingest(initial, TIME, &mut random)? != initial.len() {
                return Err(Error::Conflict.into());
            }
            let mut storage = ReplayStore::<_, 1>::new(History {
                peer: remote.public(),
                floor,
                commit: Some(commit),
            });
            let start = receiver.next_effect()?.ok_or(Error::NotReady)?;
            if !storage.drive(&mut receiver, start, TIME, &mut random)? || !storage.has_pending() {
                return Err(Error::Conflict.into());
            }
            let next = receiver.next_effect()?.ok_or(Error::NotReady)?;
            if !matches!(receiver.effect(next)?, Effect::ReplayNext(ReplayKind::Handshake, original) if original == start)
                || !storage.drive(&mut receiver, next, TIME, &mut random)?
                || !storage.has_pending()
            {
                return Err(Error::Conflict.into());
            }
            let store = receiver.next_effect()?.ok_or(Error::NotReady)?;
            let committed = storage.drive(&mut receiver, store, TIME, &mut random);
            if uncertain {
                if !matches!(committed, Err(ReplayError::OutcomeUnknown(Error::Io)))
                    || !storage.is_fenced()
                    || receiver.phase() != Phase::Closing
                {
                    return Err(Error::Conflict.into());
                }
                let close = receiver.next_effect()?.ok_or(Error::NotReady)?;
                if !matches!(receiver.effect(close)?, Effect::Close)
                    || storage.drive(&mut receiver, close, TIME, &mut random)?
                    || receiver.next_effect()? != Some(close)
                {
                    return Err(Error::Conflict.into());
                }
            } else if !committed? || storage.is_fenced() || closing(receiver.phase()) {
                return Err(Error::Conflict.into());
            }
            if storage.has_pending() || storage.backend.commit.is_some() {
                return Err(Error::Conflict.into());
            }
        }
        Ok(())
    }
}
