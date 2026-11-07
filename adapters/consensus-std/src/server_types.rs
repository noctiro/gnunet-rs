//! Actual SERVICE source selectors, explicit admission limits and original reports.
use crate::{Error, Limits, core};
use gnunet_client_host::EndpointSource;
use gnunet_pils_host::client as pils;
use gnunet_service_runtime::{accepted::SocketEvent, clock::RuntimeClock, service::PeerAddress};
use gnunet_set_client_host as set;
use gnunet_types::Error as Fault;
use std::{fmt, sync::Arc, time::Duration};
/// One coherent frozen configured source view. It preserves the same actual
/// clock/Resolver ports, not a cross-MQ remote-daemon identity handshake.
pub struct Sources {
    pub(crate) pils: EndpointSource,
    pub(crate) set: EndpointSource,
    pub(crate) clock: Arc<dyn RuntimeClock>,
    pub(crate) storage_bytes: usize,
}
impl Sources {
    /// Freeze PILS and SET together; start no source, socket or hidden resolver.
    pub fn new(pils: EndpointSource, set: EndpointSource) -> Result<Self, Error> {
        let clock = pils.clock();
        if !Arc::ptr_eq(&clock, &set.clock()) {
            return Err(Fault::Conflict.into());
        }
        let [pils, set] = EndpointSource::snapshot_all([&pils, &set])?;
        let pils = pils.fixed_endpoint()?;
        let set = set.fixed_endpoint()?;
        let pils_bytes = pils
            .fixed_endpoint_storage_bytes()?
            .ok_or(Fault::NotReady)?;
        let set_bytes = set.fixed_endpoint_storage_bytes()?.ok_or(Fault::NotReady)?;
        let storage_bytes = pils_bytes.checked_add(set_bytes).ok_or(Fault::Overflow)?;
        Ok(Self {
            pils,
            set,
            clock,
            storage_bytes,
        })
    }
    pub(crate) fn duplicate(&self) -> Result<Self, Error> {
        Ok(Self {
            pils: self.pils.duplicate()?,
            set: self.set.duplicate()?,
            clock: self.clock.clone(),
            storage_bytes: self.storage_bytes,
        })
    }
    /// Actual selected endpoint storage, charged once per original role selection;
    /// duplicates share both Arc payloads rather than cloning a Configuration.
    #[must_use]
    pub const fn retained_bytes(&self) -> usize {
        self.storage_bytes
    }
    /// Actual caller-owned shared process clock.
    #[must_use]
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.clock.clone()
    }
}
/// Finite original IPC, per-session reservation and native dependency policies.
#[derive(Clone, Copy, Debug)]
pub struct ServerLimits {
    /// Actual core/SET bridge capacities; never a private wire profile.
    pub bridge: Limits,
    /// Maximum original local IPC owners, including physical cleanup.
    pub clients: usize,
    /// Conservative reservation per original session, not eager allocation/RSS.
    pub session_bytes: usize,
    /// Aggregate concurrent reservation; no new admission exceeds it.
    pub total_retained_bytes: usize,
    /// Actual complete IPC frame cap.
    pub frame_bytes: usize,
    /// Maximum bytes per original IPC syscall.
    pub io_slice_bytes: usize,
    /// Fixed first original JOIN input interval, starting at acceptance.
    pub first_input: Duration,
    /// Fixed partial input interval; bytes never renew it.
    pub partial_input: Duration,
    /// Fixed whole original session native/canonical maximum.
    pub operation: Duration,
    /// Independent finite physical retirement grace, not a renewed operation.
    pub retirement_grace: Duration,
    /// Actual identity-only native PILS client resources; one pending slot.
    pub pils: pils::Limits,
    /// Actual public HELLO validation/address bounds.
    pub hello: gnunet_pils::HelloLimits,
    /// One explicit official PILS source profile, without fallback.
    pub profile: gnunet_pils::Profile,
}
impl Default for ServerLimits {
    fn default() -> Self {
        Self {
            bridge: Limits::default(),
            clients: 16,
            session_bytes: 256 * 1024 * 1024,
            total_retained_bytes: 1024 * 1024 * 1024,
            frame_bytes: 65535,
            io_slice_bytes: 65535,
            first_input: Duration::from_secs(30),
            partial_input: Duration::from_secs(15),
            operation: Duration::from_secs(300),
            retirement_grace: Duration::from_secs(5),
            pils: pils::Limits {
                pending_operations: 1,
                ..pils::Limits::default()
            },
            hello: gnunet_pils::HelloLimits {
                maximum_input_bytes: 65535,
                maximum_address_bytes: 65535,
                maximum_addresses: 256,
            },
            profile: gnunet_pils::Profile::Reference029,
        }
    }
}
impl ServerLimits {
    /// Validate selected source limits and conservative aggregate admission before
    /// actual readiness. This is a reservation bound, not measured memory usage.
    pub fn validate(self) -> Result<(), Error> {
        self.bridge.validate()?;
        if !(1..=4096).contains(&self.clients)
            || !(88..=65535).contains(&self.frame_bytes)
            || self.io_slice_bytes == 0
            || self.total_retained_bytes < self.session_bytes
            || self.pils.pending_operations != 1
            || !(176..=65535).contains(&self.pils.frame_bytes)
            || self.pils.io_slice_bytes == 0
            || self.hello.maximum_input_bytes < 176
            || self.hello.maximum_address_bytes == 0
            || self.hello.maximum_addresses == 0
        {
            return Err(Fault::InvalidInput.into());
        }
        let ipc = self
            .bridge
            .core
            .element_bytes
            .checked_add(6)
            .ok_or(Fault::Overflow)?;
        let result = self
            .bridge
            .core
            .element_bytes
            .checked_add(3)
            .and_then(|n| n.checked_add(self.bridge.set.abi.result_len()))
            .ok_or(Fault::Overflow)?;
        let join = self
            .bridge
            .core
            .peers
            .min(2045)
            .checked_mul(32)
            .and_then(|n| n.checked_add(88))
            .ok_or(Fault::Overflow)?;
        if self.frame_bytes < ipc.max(join) || self.bridge.set.frame_bytes < result {
            return Err(Fault::Capacity.into());
        }
        let native = self
            .bridge
            .set
            .queued_bytes
            .checked_add(self.bridge.set.frame_bytes)
            .and_then(|n| {
                self.bridge
                    .set
                    .operations
                    .checked_mul(1024)
                    .and_then(|m| n.checked_add(m))
            })
            .and_then(|n| {
                self.bridge
                    .set
                    .queued_frames
                    .checked_mul(256)
                    .and_then(|m| n.checked_add(m))
            })
            .and_then(|n| n.checked_add(65536))
            .and_then(|n| n.checked_mul(self.bridge.core.sets))
            .ok_or(Fault::Overflow)?;
        let need = self
            .bridge
            .core
            .retained_bytes
            .checked_add(self.bridge.retained_bytes)
            .and_then(|n| n.checked_add(native))
            .and_then(|n| {
                self.frame_bytes
                    .checked_mul(4)
                    .and_then(|m| n.checked_add(m))
            })
            .and_then(|n| {
                self.hello
                    .maximum_address_bytes
                    .checked_mul(2)
                    .and_then(|m| n.checked_add(m))
            })
            .ok_or(Fault::Overflow)?;
        if self.session_bytes < need {
            return Err(Fault::Capacity.into());
        }
        for life in [
            self.first_input,
            self.partial_input,
            self.operation,
            self.retirement_grace,
        ] {
            if life.is_zero() || std::time::Instant::now().checked_add(life).is_none() {
                return Err(Fault::InvalidInput.into());
            }
        }
        Ok(())
    }
}
/// Original session facts. Exact dependency failures/unknown receipts remain
/// owned here; aggregate counters do not replace them or imply interop acceptance.
#[derive(Default)]
pub struct SessionReport {
    /// First original IPC/native/policy error.
    pub primary: Option<Error>,
    /// Independent first cleanup error.
    pub cleanup: Option<Error>,
    /// Actual pure outcome, absent before real JOIN/identity admission.
    pub outcome: Option<core::Outcome>,
    /// Actual public local peer, never a `participant[0]` or configured guess.
    pub local_peer: Option<[u8; 32]>,
    /// Core's explicitly bounded original task first-cause/count summary.
    pub task_failures: Option<(Option<Fault>, u64)>,
    /// Immutable first-failure phase, leader and original task metadata captured
    /// by the pure owner before retirement clears its current phase rows.
    pub failure_context: Option<core::FailureContext>,
    /// Exact original SDK source loss and its separately labelled observations.
    pub first_source_loss: Option<crate::SourceLossContext>,
    /// Local population admission refusals; these do not fail the whole session.
    pub source_refusals: u64,
    /// First original local refusal, retained without an unbounded error queue.
    pub first_source_refusal: Option<crate::SourceRefusal>,
    /// Actual whole original core effect receipts.
    pub written: u64,
    /// Actual zero-exposure original effect dispositions.
    pub unsent: u64,
    /// Actual original effect unknown-exposure dispositions.
    pub lost: u64,
    /// Actual original cleanup effect retirements.
    pub retired: u64,
    /// Actual bytes written to the original IPC source.
    pub client_bytes: usize,
    /// Actual already admitted core/native operation associations.
    pub operations_bound: u64,
    /// Actual pre-attachment dependency retries, never mutation replay.
    pub connect_retries: u64,
    /// Last real pre-attachment transient syscall error.
    pub last_retry: Option<std::io::Error>,
    /// Original PILS source loss, independent of bridge/IPC cleanup.
    pub pils_loss: Option<pils::LossCause>,
    /// Actual still-pending PILS operations at its physical close.
    pub pils_pending: usize,
    /// Original crypto/FEED retention observed at actual PILS loss, not replayed.
    pub pils_loss_retained: usize,
    /// Original unacknowledged FEED count at actual loss; identity-only must be0.
    pub pils_loss_feeds: usize,
    /// Actual original output prefix if bookkeeping could not drain.
    pub pending_output_bytes: usize,
    /// Actual original output wholewrite fact, even if terminal application failed.
    pub pending_output_whole: bool,
    /// Actual remote full SET terminal frames, not local write acknowledgements.
    pub set_done: u64,
    /// Actual remote SET FAILURE terminal frames.
    pub set_failed: u64,
    /// Actual nonterminal HALF_DONE observations.
    pub set_half_done: u64,
    /// Rejected original incoming contexts; not a whole-session failure count.
    pub rejected_offers: u64,
    /// First scoped original rejection classification.
    pub first_rejection: Option<Fault>,
    /// Exact original SET source failures or unfinished native receipts, moved
    /// into pre-reserved slots; normal empty requested closes are counted below.
    pub set_losses: Vec<set::SetLoss>,
    /// Original overflow receipt if an internal bound is violated; unresolved
    /// debt remains explicit and admission stops instead of claiming success.
    pub extra_set_loss: Option<set::SetLoss>,
    /// Actual original listener failure/retirement.
    pub listener_loss: Option<set::ListenerLoss>,
    /// Independent actual listener close after its original loss, if any.
    pub listener_cleanup: Option<set::ListenerLoss>,
    /// Actual original native SET source physical retirements.
    pub sources_retired: u64,
    /// Actual partial response bytes retired; no complete frame is invented.
    pub retired_input_bytes: usize,
    /// Actual original IPC and every dependency physically closed.
    pub physical_closed: bool,
    /// Original actual bookkeeping debt after bounded cleanup; never success.
    pub undrained: usize,
}
impl SessionReport {
    pub(crate) fn record_source_refusal(&mut self, refusal: crate::SourceRefusal) {
        self.source_refusals = self.source_refusals.saturating_add(1);
        self.first_source_refusal.get_or_insert(refusal);
    }
}
impl fmt::Debug for SessionReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionReport")
            .field("primary", &self.primary)
            .field("cleanup", &self.cleanup)
            .field("outcome", &self.outcome)
            .field("local_peer", &self.local_peer)
            .field("task_failures", &self.task_failures)
            .field("failure_context", &self.failure_context)
            .field("first_source_loss", &self.first_source_loss)
            .field("source_refusals", &self.source_refusals)
            .field("first_source_refusal", &self.first_source_refusal)
            .field("written", &self.written)
            .field("unsent", &self.unsent)
            .field("lost", &self.lost)
            .field("retired", &self.retired)
            .field("client_bytes", &self.client_bytes)
            .field("operations_bound", &self.operations_bound)
            .field("connect_retries", &self.connect_retries)
            .field("last_retry", &self.last_retry)
            .field("pils_loss", &self.pils_loss)
            .field("pils_pending", &self.pils_pending)
            .field("set_losses", &LossDiagnostics(&self.set_losses))
            .field(
                "listener_cause",
                &self.listener_loss.as_ref().map(|l| &l.cause),
            )
            .field(
                "listener_deadline",
                &self
                    .listener_loss
                    .as_ref()
                    .and_then(|loss| loss.deadline.as_deref()),
            )
            .field(
                "listener_cleanup_cause",
                &self.listener_cleanup.as_ref().map(|l| &l.cause),
            )
            .field(
                "extra_set_loss_cause",
                &self.extra_set_loss.as_ref().map(|l| &l.cause),
            )
            .field("pending_output_bytes", &self.pending_output_bytes)
            .field("pending_output_whole", &self.pending_output_whole)
            .field("set_done", &self.set_done)
            .field("set_failed", &self.set_failed)
            .field("set_half_done", &self.set_half_done)
            .field("rejected_offers", &self.rejected_offers)
            .field("first_rejection", &self.first_rejection)
            .field("sources_retired", &self.sources_retired)
            .field("retired_input_bytes", &self.retired_input_bytes)
            .field("physical_closed", &self.physical_closed)
            .field("undrained", &self.undrained)
            .finish()
    }
}
/// Actual terminal counts; full causes stay with the original Closed event.
#[derive(Clone, Copy, Debug, Default)]
pub struct Report {
    /// Actual original local IPC owners admitted.
    pub accepted: u64,
    /// Actual original owners whose physical close was observed.
    pub closed: u64,
    /// Sessions whose actual original525 was whole-written.
    pub results_written: u64,
    /// Sessions with an actual original primary/core failure.
    pub failed: u64,
    /// Actual original unresolved debt; not inferred from pending counts alone.
    pub undrained: usize,
}
/// Actual caller-driven SERVICE progress.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerProgress {
    /// Real admission, original session work or terminal cleanup progress.
    Activity,
    /// Only the caller's observation wait elapsed.
    WaitDeadline,
    /// Admission stopped and all actual original sessions retired.
    Stopped,
}
/// Synchronous actual SERVICE observations, without raw application payload/key logs.
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "Original causes and pre-owned native loss receipts move inline without allocation on failure"
)]
pub enum Event {
    /// Actual native accept/initialization diagnostic.
    Socket(SocketEvent),
    /// Actual original source refused by standard ACL/credentials.
    Rejected(PeerAddress),
    /// Actual admission failed before a session owner was installed.
    AdmissionFailed(Error),
    /// Original local session diagnostic serial, not a wire request ID.
    Accepted(u64),
    /// Actual complete original session report and independent cleanup causes.
    Closed {
        /// Original local session serial.
        client: u64,
        /// Original actual receipt/cause summary and retained unknowns.
        report: SessionReport,
    },
}

struct LossDiagnostics<'a>(&'a [set::SetLoss]);
struct OneLoss<'a>(&'a set::SetLoss);
impl fmt::Debug for LossDiagnostics<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.0.iter().map(OneLoss)).finish()
    }
}
impl fmt::Debug for OneLoss<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SetLoss")
            .field("cause", &self.0.cause)
            .field("deadline", &self.0.deadline)
            .field("cleanup", &self.0.cleanup)
            .field("transport", &self.0.transport)
            .field("unfinished_operations", &self.0.operations.len())
            .field("unfinished_mutations", &self.0.mutations.len())
            .finish()
    }
}
