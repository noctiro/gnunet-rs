//! Bounded PEERSTORE operations for the original FS peer's respect record.

use gnunet_peerstore_client_host as ps;
pub use gnunet_peerstore_client_host::{
    EndpointSource, Error, Instance, Limits, LossCause, Outcome, Submission,
};
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_types::Error as Fault;
use std::{
    future::Future,
    pin::pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

const SUBSYSTEM: &[u8] = b"fs";
const KEY: &[u8] = b"respect";
const REPLACE: u32 = 1;

/// First-row semantics for the original exact respect filter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoadedBalance {
    /// No row was observed. Only a successful iteration end establishes absence.
    NoRecord,
    /// The first matching record had a value other than a native `u32`.
    InvalidWidth,
    /// The first matching record's native `u32` value.
    Value(u32),
}

/// Qualification and completion of one originally admitted PEERSTORE job.
#[derive(Debug)]
pub enum Event {
    /// PEERSTORE progressed without settling an original job.
    Activity,
    /// The original one-row iteration has retired.
    Loaded {
        /// The caller's original job token.
        token: u64,
        /// CORE peer from the original iteration filter.
        peer: [u8; 32],
        /// Actual first-row observation, separate from the original outcome.
        value: LoadedBalance,
        /// Original iteration result or local retirement, with its certainty.
        outcome: Outcome,
    },
    /// The original replace operation has retired.
    Saved {
        /// The caller's original job token.
        token: u64,
        /// CORE peer from the original store request.
        peer: [u8; 32],
        /// Exact native value submitted for the original store.
        balance: u32,
        /// Actual result or local retirement. A local write alone is not a save.
        outcome: Outcome,
    },
    /// Original native PEERSTORE stream retired.
    Lost(LossCause),
}

enum Phase {
    Read,
    StopRead(Option<u32>),
    Write(u32),
}

struct Pending<'id> {
    operation: ps::Operation<'id>,
    token: u64,
    peer: [u8; 32],
    phase: Phase,
}

/// Caller-polled original PEERSTORE client for FS respect. One operation or
/// physical retirement debt occupies the slot at a time.
pub struct Store<'id> {
    client: ps::Client<'id>,
    clock: Arc<dyn RuntimeClock>,
    pending: Option<Pending<'id>>,
}

impl<'id> Store<'id> {
    /// Reserve the original general PEERSTORE client and its job slot.
    pub fn new(
        instance: &'id mut Instance,
        source: EndpointSource,
        limits: Limits,
    ) -> Result<Self, Error> {
        let clock = source.clock();
        let client = ps::Client::new(instance, source, limits)?;
        Ok(Self {
            client,
            clock,
            pending: None,
        })
    }

    /// Same canonical clock as the native PEERSTORE endpoint.
    #[must_use]
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        Arc::clone(&self.clock)
    }

    /// Number of original jobs or STOP debts still tracked by this owner.
    #[must_use]
    pub fn pending(&self) -> usize {
        usize::from(self.pending.is_some() || !self.client.is_idle())
    }

    fn admit(&self) -> Result<(), Error> {
        if self.pending() != 0 {
            return Err(Fault::WouldBlock.into());
        }
        Ok(())
    }

    /// Load the first matching original record. `expires` is the finite
    /// absolute UTC deadline of this operation.
    pub fn load(&mut self, token: u64, peer: [u8; 32], expires: u64) -> Result<(), Error> {
        self.admit()?;
        let operation = self.client.iterate(filter(peer), expires)?;
        self.pending = Some(Pending {
            operation,
            token,
            peer,
            phase: Phase::Read,
        });
        Ok(())
    }

    /// Replace the original peer's respect record. The stored value retains
    /// the native FS ABI and forever expiry, independently of `expires`.
    pub fn save(
        &mut self,
        token: u64,
        peer: [u8; 32],
        balance: u32,
        expires: u64,
    ) -> Result<(), Error> {
        self.admit()?;
        let bytes = balance.to_ne_bytes();
        let operation = self.client.store(
            ps::Record {
                peer,
                expiry: u64::MAX,
                subsystem: Some(SUBSYSTEM),
                key: Some(KEY),
                value: &bytes,
            },
            REPLACE,
            expires,
        )?;
        self.pending = Some(Pending {
            operation,
            token,
            peer,
            phase: Phase::Write(balance),
        });
        Ok(())
    }

    /// Recover an explicitly refused CLIENT clock or resolver port. Original
    /// read and write jobs never replay across PEERSTORE MQ retirement.
    pub fn recover(&mut self) -> Result<(), Error> {
        self.client.recover_ports()
    }

    /// Physically close the original client. Its terminal job outcomes remain
    /// available through `poll` until every original job is drained.
    pub fn close(&mut self) -> Result<(), Error> {
        self.client.close().map(|_| ())
    }

    fn on_record(&mut self, observation: ps::Observation<'id>) -> Result<(), Error> {
        let operation = observation.operation();
        let job = self
            .pending
            .as_mut()
            .filter(|job| job.operation == operation)
            .ok_or(Fault::Stale)?;
        if !matches!(job.phase, Phase::Read) {
            return Err(Fault::Malformed.into());
        }
        // The general client already matched the original operation and filter.
        let record = observation.record()?.record;
        let balance = <[u8; 4]>::try_from(record.value)
            .ok()
            .map(u32::from_ne_bytes);
        // Credit starts at one. The first row settles the selection even if its
        // width is wrong. No further credit is issued on this iterator.
        job.phase = Phase::StopRead(balance);
        self.client.cancel(operation).map(|_| ())
    }

    fn complete(
        &mut self,
        operation: ps::Operation<'id>,
        outcome: Outcome,
    ) -> Result<Event, Error> {
        let Pending {
            token, peer, phase, ..
        } = self
            .pending
            .take_if(|job| job.operation == operation)
            .ok_or(Fault::Stale)?;
        Ok(match phase {
            Phase::Read => Event::Loaded {
                token,
                peer,
                value: LoadedBalance::NoRecord,
                outcome,
            },
            Phase::StopRead(balance) => Event::Loaded {
                token,
                peer,
                value: balance.map_or(LoadedBalance::InvalidWidth, LoadedBalance::Value),
                outcome,
            },
            Phase::Write(balance) => Event::Saved {
                token,
                peer,
                balance,
                outcome,
            },
        })
    }

    /// Advance one bounded native action. Idle clients do not open a new MQ.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Event, Error>> {
        if self.pending() == 0 {
            return Poll::Pending;
        }
        if let Some(job) = self.pending.as_ref().filter(|job| {
            matches!(job.phase, Phase::StopRead(_)) && self.client.live(job.operation)
        }) {
            self.client.cancel(job.operation)?;
            return Poll::Ready(Ok(Event::Activity));
        }
        let progress = {
            let mut drive = pin!(self.client.drive(None));
            ready!(drive.as_mut().poll(cx))?
        };
        Poll::Ready(match progress {
            ps::Progress::Record(record) => self.on_record(record).map(|()| Event::Activity),
            ps::Progress::Completed {
                operation, outcome, ..
            } => self.complete(operation, outcome),
            ps::Progress::Lost { cause, .. } => Ok(Event::Lost(cause)),
            ps::Progress::Unavailable(error) => Err(error),
            ps::Progress::Capacity(_) => Err(Fault::Capacity.into()),
            ps::Progress::Closed => Err(Fault::Stale.into()),
            _ => Ok(Event::Activity),
        })
    }
}

fn filter(peer: [u8; 32]) -> ps::Filter<'static> {
    ps::Filter {
        peer: Some(peer),
        subsystem: Some(SUBSYSTEM),
        key: Some(KEY),
    }
}

#[cfg(all(test, unix))]
mod tests;
