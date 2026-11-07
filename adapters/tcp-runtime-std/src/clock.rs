//! Canonical logical time, independent durable signed time and owned failures.
use crate::epoch::{self, Epoch, Quiescent};
use gnunet_crypto::EddsaPublicKey;
use gnunet_service_runtime::clock::{ClockSubscription, RuntimeClock};
use gnunet_tcp_communicator_core::session::Time;
use gnunet_tcp_communicator_host::Clock;
use gnunet_types::Error;
use std::{
    path::PathBuf,
    sync::Arc,
    task::{Context, Poll},
};
/// Actual clock or native persistence cause, retained by this original owner.
#[derive(Debug)]
pub enum Failure {
    /// Canonical clock subscription/sample refused.
    Clock(Error),
    /// Original frontier/file/namespace failure.
    History(epoch::Failure),
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::History(original) => Some(original),
            Self::Clock(_) => None,
        }
    }
}
/// Separate explicit canonical clock subscription plus one original durable
/// signed-time writer. It never spawns a backend or implicit timer task.
pub struct ClockPort {
    source: Arc<dyn RuntimeClock>,
    subscription: Option<Box<dyn ClockSubscription>>,
    revision: u64,
    store: epoch::Store,
    last: u64,
    end: u64,
    last_time: Option<Time>,
    fault: Option<Failure>,
    refused: bool,
}
impl ClockPort {
    /// Reserve the original clock listener and kernel file fence once. No native
    /// signature timestamp exists until a dirty epoch and durable range are admitted.
    pub fn new(source: Arc<dyn RuntimeClock>, path: PathBuf) -> Result<Self, Failure> {
        let subscription = source.subscribe().map_err(Failure::Clock)?;
        let store = epoch::Store::open(path).map_err(Failure::History)?;
        Ok(Self {
            source,
            subscription: Some(subscription),
            revision: 0,
            store,
            last: 0,
            end: 0,
            last_time: None,
            fault: None,
            refused: false,
        })
    }
    /// Same actual source used by native CLIENT/Resolver identity/service ports.
    #[must_use]
    pub fn source(&self) -> Arc<dyn RuntimeClock> {
        self.source.clone()
    }
    /// Persist original min0/public LedgerId intent before opening the ledger.
    /// This grants no epoch, signature timestamp or replay authorization.
    pub fn prepare_replay(
        &mut self,
        peer: EddsaPublicKey,
        ledger_directory: &std::path::Path,
    ) -> Result<(), Failure> {
        if self.refused {
            return Err(Failure::Clock(Error::Closed));
        }
        self.store
            .prepare_replay(peer, ledger_directory)
            .map_err(Failure::History)
    }
    /// Attach only the complete actual initialized/recovered replay catalog.
    /// This does not make an old V1 frontier recoverable or create quiescence.
    pub fn attach_catalog(
        &mut self,
        catalog: &gnunet_tcp_replay_host::Catalog<'_>,
    ) -> Result<(), Failure> {
        if self.refused {
            return Err(Failure::Clock(Error::Closed));
        }
        let lease = catalog.lease().map_err(Failure::Clock)?;
        self.store.attach_catalog(lease).map_err(Failure::History)
    }
    /// Commit the actual floor's generation into the original frontier before
    /// the corresponding PS STORE is queued. Failure preserves that same Floor.
    pub fn authorize_replay(
        &mut self,
        floor: gnunet_tcp_replay_host::Floor,
    ) -> Result<epoch::ReplayPermit, epoch::ReplayRejected> {
        if self.refused {
            return Err(epoch::ReplayRejected {
                floor,
                error: epoch::Failure {
                    stage: epoch::Stage::BackendQuarantine,
                    outcome: epoch::Outcome::Unknown,
                    cause: std::io::Error::other(
                        "original canonical ClockPort refused new replay authorization",
                    ),
                },
            });
        }
        self.store.authorize_replay(floor)
    }
    /// Recheck the same actual original permit immediately before PS enqueue.
    pub fn validate_replay(&self, permit: &epoch::ReplayPermit) -> Result<(), Error> {
        if self.refused {
            return Err(Error::Closed);
        }
        self.store.validate_replay(permit)
    }
    /// Admit one original persistent backend epoch under the actual current peer,
    /// after attach_catalog supplied the exact durable initialized ledger. All
    /// reserved signed time remains burned across dirty-catalog recovery.
    pub fn begin_epoch(&mut self, peer: EddsaPublicKey) -> Result<Epoch, Failure> {
        if self.refused {
            return Err(Failure::Clock(Error::Closed));
        }
        let reserved = self
            .store
            .loaded()
            .map_err(Failure::History)?
            .map_or(0, |s| s.reserved);
        let epoch = self.store.begin(peer).map_err(Failure::History)?;
        self.last = reserved;
        self.end = reserved;
        Ok(epoch)
    }
    /// Last actual successful sample, for retiring already-destroyed sessions only.
    /// It grants no permission to generate new signatures or drive an active epoch.
    #[must_use]
    pub fn last_time(&self) -> Option<Time> {
        self.last_time
    }
    /// Transfer the actual original cause without clearing permanent refusal.
    pub fn take_failure(&mut self) -> Option<Failure> {
        self.fault.take()
    }
    /// Reconcile/clean only the original consumed-pool proof. Failure returns it
    /// unchanged; a clock refusal never manufactures quiescence or a fresh sample.
    pub fn finish_epoch(&mut self, proof: Quiescent) -> Result<(), epoch::FinishRejected> {
        self.store.finish(proof)
    }
    /// Release this native listener without touching the original file fence. A
    /// permanently closed foreground must not resubscribe through this value.
    pub fn close(&mut self) {
        self.refused = true;
        self.subscription = None;
    }
    fn refuse(&mut self, failure: Failure) -> Error {
        let reason = match &failure {
            Failure::Clock(e) => *e,
            Failure::History(e) if e.outcome == epoch::Outcome::Unknown => Error::OutcomeUnknown,
            Failure::History(_) => Error::Io,
        };
        self.fault = Some(failure);
        self.refused = true;
        self.subscription = None;
        reason
    }
}
impl Clock for ClockPort {
    fn read(&mut self) -> Result<Time, Error> {
        if self.refused {
            return Err(Error::Closed);
        }
        let sample = match self.source.sample() {
            Ok(s) => s,
            Err(e) => return Err(self.refuse(Failure::Clock(e))),
        };
        self.revision = sample.revision;
        // A cached reservation cannot outlive its original namespace authority.
        if let Err(error) = self.store.loaded() {
            return Err(self.refuse(Failure::History(error)));
        }
        let wanted = match self.last.checked_add(1) {
            Some(v) => sample.now.as_micros().max(v),
            None => return Err(self.refuse(Failure::Clock(Error::Overflow))),
        };
        let signed = if wanted > self.end {
            match self.store.reserve(wanted, 1_000_000) {
                Ok((first, end)) => {
                    self.end = end;
                    first
                }
                Err(e) => return Err(self.refuse(Failure::History(e))),
            }
        } else {
            wanted
        };
        self.last = signed;
        let time = Time {
            now: sample.now.as_micros(),
            signed,
        };
        self.last_time = Some(time);
        Ok(time)
    }
    fn revision(&self) -> u64 {
        self.revision
    }
    fn poll_change(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if self.refused {
            return Poll::Ready(());
        }
        let Some(subscription) = &mut self.subscription else {
            return Poll::Ready(());
        };
        match subscription.poll_changed(cx, self.revision) {
            Poll::Ready(Ok(sample)) => {
                self.revision = sample.revision;
                Poll::Ready(())
            }
            Poll::Ready(Err(e)) => {
                let _reason = self.refuse(Failure::Clock(e));
                Poll::Ready(())
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
