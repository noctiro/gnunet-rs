//! Actual DV actor ↔ existing TRANSPORT native/Engine ports. This owns no MQ,
//! worker, key, entropy source, Flow implementation or background task. The
//! caller polls its same actual Server and Runtime, then dispatches their facts.
#![cfg(unix)]
#![forbid(unsafe_code)]
use gnunet_transport::{PeerId, Signer, Times, dv_bridge as engine};
use gnunet_transport_dv_runtime_host::{self as runtime, Runtime, Token};
use gnunet_transport_dv_store_host::box_admission;
use gnunet_transport_host::{Server, dv_bridge as native};
use gnunet_types::Error as Protocol;
use std::collections::VecDeque;
mod delivery;
mod task_failure;
mod transmit;
pub use task_failure::{TaskFailure, TaskFailureScope};
use tokio::time::Instant;
pub use transmit::{SendDiagnostic, SendVirtual, VirtualIntent};

/// The existing Engine owns the original non-clone carrier/FC attribution.
/// Probe and forwarded outputs have no external J; virtual CORE TX is separate.
#[derive(Debug)]
pub enum Origin {
    /// Actual original physical carrier/MQ/FC owner.
    Ingress(engine::Ingress),
    /// Actual original common Job/UUID/span attempt; never a direct queue.
    Outbound(engine::VirtualAttempt),
}
/// One actual caller-driven actor with its independent PILS/worker owners.
pub type Actor<'id, 'source, 'pils, 'slots, 'out, const N: usize = 32> =
    Runtime<'id, 'source, 'pils, 'slots, 'out, Origin, N>;
/// Explicit bounded bridge metadata; no maximum-sized packet pool per peer.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Actual direct queue bindings, including distinct same-peer alternatives.
    pub neighbours: usize,
    /// Original actual native output receipts awaiting actor settlement.
    pub outputs: usize,
    /// Original finished FC debts waiting for the actual native output barrier.
    pub finished: usize,
    /// Actual usable signed target/path metadata, independent of neighbour count.
    pub paths: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            neighbours: 64,
            outputs: 16,
            finished: 16,
            paths: 64,
        }
    }
}
/// Actual original failures. No variant contains plaintext or secret material.
#[derive(Debug)]
pub enum Cause {
    /// Pure resource/ownership/time/codec refusal.
    Protocol(Protocol),
    /// Actual original actor/PILS/provider/crypto failure.
    Actor(runtime::Error),
    /// Actual original native enqueue failure plus its independent rollback cause.
    Queue(native::QueueError),
    /// Actual original private grant refusal.
    Grant(box_admission::Reason),
}
/// Preserve cleanup independently; never overwrite the triggering failure.
#[derive(Debug)]
pub struct Error {
    /// Original cause.
    pub cause: Cause,
    /// Independent physical/source retirement failure, if any.
    pub cleanup: Option<Cause>,
}
impl From<Protocol> for Error {
    fn from(e: Protocol) -> Self {
        Self {
            cause: Cause::Protocol(e),
            cleanup: None,
        }
    }
}
impl From<runtime::Error> for Error {
    fn from(e: runtime::Error) -> Self {
        Self {
            cause: Cause::Actor(e),
            cleanup: None,
        }
    }
}
impl From<native::QueueError> for Error {
    fn from(e: native::QueueError) -> Self {
        Self {
            cause: Cause::Queue(e),
            cleanup: None,
        }
    }
}
impl From<box_admission::Reason> for Error {
    fn from(e: box_admission::Reason) -> Self {
        Self {
            cause: Cause::Grant(e),
            cleanup: None,
        }
    }
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "DV bridge: {:?}; cleanup={:?}", self.cause, self.cleanup)
    }
}
impl std::error::Error for Error {}
struct Binding<'id> {
    queue: engine::DirectQueue,
    neighbour: runtime::Neighbour<'id>,
}
struct Send<'id> {
    actor: Token<'id>,
    native: engine::TransferId,
    queued: bool,
    exposed: bool,
    notified: bool,
    written: bool,
    actor_finished: bool,
    budget: runtime::Budget,
}
struct Path<'id> {
    target: PeerId,
    id: engine::PathId,
    route: gnunet_transport::dv::routes::RouteId<'id>,
    hard: Instant,
    mtu: usize,
    policy: runtime::SendPolicy,
}
/// Actual finished original input and the separate unresolved worker debt.
/// This does not claim peer/application processing or filesystem rollback.
pub struct Finished<'id> {
    /// Actual actor processing outcome for the original input.
    pub disposition: runtime::Disposition,
    /// Actual original FC disposition; AckQueued is a local IPC enqueue only.
    pub flow_control: engine::IngressEnd,
    /// Original disk operation remains with the same Provider until drained.
    pub disk_debt: Option<box_admission::Debt<'id>>,
}
/// One actual original input admission attempt. Deferred retains native RX and
/// its original deadline; caller must wait on Server/actor/provider progress.
pub enum Receive<'id> {
    /// No complete original DV frame is retained right now.
    Empty,
    /// Original complete reassembly deadline expired and it was actually dropped.
    Expired {
        /// Actual local original FC disposition, never a remote ACK.
        flow_control: engine::IngressEnd,
    },
    /// Real actor admitted the SAME original frame and non-clone FC owner.
    Admitted(Token<'id>),
    /// Real actor refused; no frame was consumed or mutation replayed.
    Deferred(runtime::InputRefused<Origin>),
    /// Permanent per-input admission refusal was actually consumed/dropped;
    /// original FC result is local only, not a Granted/application assertion.
    Discarded {
        /// Actual original refusal and opaque stale reservation metadata.
        original: runtime::InputRefused<Origin>,
        /// Actual original physical FC disposition.
        flow_control: engine::IngressEnd,
    },
}
/// Admission to the actual common Engine Job, separate from native MQ facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Queued {
    /// Original immutable output staged under its actual direct queue lease.
    Staged,
    /// The same original output already has that one common Job.
    AlreadyStaged,
    /// Original parent was actually retired; its Actor operation was canceled.
    /// Any earlier native admission keeps its real physical retirement outcome.
    Retired,
}
/// Original native facts after the actor was notified. Packet completion means
/// only the communicator's official original1210 result, never CORE delivery.
pub struct SendProgress<'id> {
    /// Exact original actor operation.
    pub token: Token<'id>,
    /// Actual original IPC and packet/source facts.
    pub physical: engine::TransferState,
}
/// Explicit callable bridge. Source retirement must follow actual actor closure;
/// drop alone neither closes caller Server nor invents physical write callbacks.
#[must_use = "close actor and retire this source; drain original FC/native/worker debts"]
pub struct Bridge<'id> {
    source: engine::Source,
    native_epoch: Instant,
    paths: Vec<Path<'id>>,
    targets: Vec<PeerId>,
    active: bool,
    closing: bool,
    alarm: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
    bindings: Vec<Binding<'id>>,
    sends: Vec<Send<'id>>,
    finished: VecDeque<runtime::Finished<'id, Origin>>,
    input_cursor: usize,
    inbox_turn: bool,
    send_cursor: usize,
    limits: Limits,
}
impl<'id> Bridge<'id> {
    /// Bind only the real ready actor's actual local PILS identity. Construction
    /// reserves bounded metadata and opens no source, socket, task or worker.
    pub fn adopt_at<const N: usize>(
        server: &mut Server,
        actor: &Actor<'id, '_, '_, '_, '_, N>,
        limits: Limits,
        native_epoch: Instant,
    ) -> Result<Self, Error> {
        if limits.neighbours == 0
            || limits.outputs == 0
            || limits.finished == 0
            || limits.paths == 0
        {
            return Err(Protocol::InvalidInput.into());
        }
        let mut bindings = Vec::new();
        let mut sends = Vec::new();
        let mut finished = VecDeque::new();
        bindings
            .try_reserve_exact(limits.neighbours)
            .map_err(|_| Protocol::Capacity)?;
        sends
            .try_reserve_exact(limits.outputs)
            .map_err(|_| Protocol::Capacity)?;
        finished
            .try_reserve_exact(limits.finished)
            .map_err(|_| Protocol::Capacity)?;
        let mut paths = Vec::new();
        paths
            .try_reserve_exact(limits.paths)
            .map_err(|_| Protocol::Capacity)?;
        let mut targets = Vec::new();
        targets
            .try_reserve_exact(limits.paths)
            .map_err(|_| Protocol::Capacity)?;
        let local = PeerId(*actor.identity().peer().as_bytes());
        let source = server.dv_attach_source(local)?;
        Ok(Self {
            source,
            native_epoch,
            paths,
            targets,
            active: true,
            closing: false,
            alarm: None,
            bindings,
            sends,
            finished,
            input_cursor: 0,
            inbox_turn: false,
            send_cursor: 0,
            limits,
        })
    }
    /// Synchronize exact Engine-minted current validated direct generations.
    /// The standard QueueSetup describes a bidirectional queue; this does not
    /// authenticate its remote peer or fabricate an end-to-end DV route.
    pub fn sync_neighbours<const N: usize>(
        &mut self,
        server: &Server,
        actor: &mut Actor<'id, '_, '_, '_, '_, N>,
        times: Times,
    ) -> Result<(), Error> {
        if !self.active {
            return Err(Protocol::Closed.into());
        }
        server.engine().validate_times(times)?;
        let mut i = 0;
        while i < self.bindings.len() {
            if server
                .dv_direct_queues(times)
                .any(|q| q == self.bindings[i].queue)
            {
                i += 1;
                continue;
            }
            let result = actor.detach(&self.bindings[i].neighbour);
            if !actor.neighbours().any(|n| n == &self.bindings[i].neighbour) {
                self.bindings.swap_remove(i);
            } else {
                i += 1;
            }
            result?;
        }
        for queue in server.dv_direct_queues(times) {
            if self.bindings.iter().any(|b| b.queue == queue) {
                continue;
            }
            if self.bindings.len() == self.limits.neighbours {
                return Err(Protocol::Capacity.into());
            }
            let neighbour =
                actor.attach(queue.owner().clone(), queue.peer(), queue.queue(), true)?;
            self.bindings.push(Binding { queue, neighbour });
        }
        Ok(())
    }
    /// Try one fair retained RX. No payload copy is made by this bridge: Actor
    /// owns its one fallible copy before Server releases the original frame.
    pub fn receive_one<const N: usize>(
        &mut self,
        server: &mut Server,
        actor: &mut Actor<'id, '_, '_, '_, '_, N>,
        times: Times,
    ) -> Result<Receive<'id>, Error> {
        if !self.active || self.closing {
            return Err(Protocol::Closed.into());
        }
        let native_client = server.dv_next_input(&mut self.input_cursor);
        self.inbox_turn = !self.inbox_turn;
        if let Some(inbox) = server.dv_inbox()
            && (self.inbox_turn || native_client.is_none())
        {
            let id = inbox.id.clone();
            let hard = self
                .native_epoch
                .checked_add(std::time::Duration::from_micros(inbox.until.0))
                .ok_or(Protocol::Overflow)?;
            if Instant::now() >= hard
                || inbox
                    .absolute_until
                    .is_some_and(|until| times.absolute() >= until)
            {
                let flow_control = server.dv_discard_inbox(&id)?;
                return Ok(Receive::Expired { flow_control });
            }
            let identity_until = actor.identity().expiration();
            let budget = runtime::Budget {
                until: inbox
                    .absolute_until
                    .unwrap_or(identity_until)
                    .min(identity_until),
                hard,
            };
            let result = server.dv_try_inbox_generic(&id, |queue, origin, bytes| {
                let Some(binding) = self.bindings.iter().find(|b| b.queue == queue) else {
                    return Err(runtime::InputRefused {
                        origin: Origin::Ingress(origin),
                        error: runtime::Error::Protocol(Protocol::NotReady),
                        disposition: runtime::InputRefusalDisposition::Deferred,
                    });
                };
                actor.receive_with_budget(
                    &binding.neighbour,
                    Origin::Ingress(origin),
                    bytes,
                    budget,
                )
            })?;
            return match result {
                Ok(token) => Ok(Receive::Admitted(token)),
                Err(native::InboxRefusal { original, current }) => {
                    dispose_input_refusal(original, || server.dv_discard_inbox(&current))
                }
            };
        }
        let Some(client) = native_client else {
            return Ok(Receive::Empty);
        };
        let result = server.dv_try_input_generic(
            &self.source,
            &client,
            times,
            |queue, origin, bytes, budget| {
                let Some(binding) = self.bindings.iter().find(|b| b.queue == queue) else {
                    return Err(runtime::InputRefused {
                        origin: Origin::Ingress(origin),
                        error: runtime::Error::Protocol(Protocol::NotReady),
                        disposition: runtime::InputRefusalDisposition::Deferred,
                    });
                };
                actor.receive_with_budget(
                    &binding.neighbour,
                    Origin::Ingress(origin),
                    bytes,
                    runtime::Budget {
                        until: budget.until,
                        hard: budget.hard,
                    },
                )
            },
        )?;
        match result {
            None => Ok(Receive::Empty),
            Some(Ok(token)) => Ok(Receive::Admitted(token)),
            Some(Err(original)) => dispose_input_refusal(original, || {
                server.dv_discard_original_input(&self.source, &client, times)
            }),
        }
    }
    /// Consume only the ACTUAL private durable/replay/AEAD/signature grant from
    /// this original actor input. Carrier/FC source stays the original Ingress;
    /// decrypted sender is used only for existing virtual peer/Flow/CORE state.
    pub fn deliver<const N: usize>(
        &mut self,
        server: &mut Server,
        actor: &mut Actor<'id, '_, '_, '_, '_, N>,
        token: Token<'id>,
        times: Times,
        signer: &mut impl Signer,
    ) -> Result<engine::Delivery, TaskFailure> {
        self.check_task_source(server, times)?;
        let original = match actor
            .input_origin(token)
            .map_err(|error| TaskFailure::source(error.into()))?
        {
            Origin::Ingress(origin) => origin.id(),
            Origin::Outbound(_) => {
                return Err(TaskFailure::source(Protocol::Authentication.into()));
            }
        };
        let local = PeerId(*actor.identity().peer().as_bytes());
        if original.source() != &self.source {
            return Err(TaskFailure::source(Protocol::Stale.into()));
        }
        if signer.identity() != local {
            return Err(TaskFailure::source(Protocol::Authentication.into()));
        }
        // Borrow only the actual original grant. Route measurement remains
        // optional and cannot establish an authenticated return path.
        let sender = {
            let granted = actor.delivery(token).map_err(task_failure::actor)?;
            let binding = granted.binding();
            if binding.target() != local {
                return Err(TaskFailure::task(Protocol::Stale.into()));
            }
            binding.sender()
        };
        let estimate = actor
            .route(sender, true)
            .map_err(|error| TaskFailure::source(error.into()))?
            .and_then(|route| route.rtt.map(|rtt| (route.id, rtt)));
        let measured = match estimate {
            Some((route, rtt)) => actor
                .route_life(sender, true)
                .map_err(|error| TaskFailure::source(error.into()))?
                .filter(|life| life.route == route)
                .map(|life| (rtt, life)),
            None => None,
        };
        let granted = actor.delivery(token).map_err(task_failure::actor)?;
        let binding = granted.binding();
        if binding.target() != local || binding.sender() != sender {
            return Err(TaskFailure::task(Protocol::Stale.into()));
        }
        let hard = granted.native_deadline();
        if Instant::now() >= hard {
            return Err(TaskFailure::task(Protocol::Deadline.into()));
        }
        let bytes = granted.message().map_err(delivery::grant_failure)?;
        if Instant::now() >= hard {
            return Err(TaskFailure::task(Protocol::Deadline.into()));
        }
        if let Some((rtt, life)) = measured
            && let Ok(left) = life.remaining()
        {
            match server.burst_dv_path(&self.source, sender, rtt, left, times) {
                Ok(()) | Err(Protocol::Capacity | Protocol::Deadline) => {}
                Err(error) => return Err(TaskFailure::source(error.into())),
            }
        }
        if Instant::now() >= hard {
            return Err(TaskFailure::task(Protocol::Deadline.into()));
        }
        // Observe the actual provider call separately: Capacity from this
        // signer is not Engine packet-buffer pressure with the same code.
        let mut observed = delivery::ObservedSigner::new(signer, local);
        let outcome = server.dv_deliver(&original, binding.sender(), bytes, times, &mut observed);
        let provider_failure = observed.failure();
        match outcome {
            Err(error) => Err(delivery::engine_failure(error, provider_failure)),
            Ok(outcome) => {
                // Store actual admission before any independent failure can
                // escape. This exact receipt creates no clock or native IO.
                actor
                    .delivered(token)
                    .map_err(|error| TaskFailure::source(error.into()))?;
                if let Some(error) = provider_failure {
                    return Err(TaskFailure::source(error.into()));
                }
                Ok(outcome)
            }
        }
    }
    /// Take the real actor's finished J only after reserving its bounded debt
    /// slot. If FC enqueue is blocked, keep the exact same J/debt for retry.
    pub fn finish_input<const N: usize>(
        &mut self,
        actor: &mut Actor<'id, '_, '_, '_, '_, N>,
        token: Token<'id>,
    ) -> Result<(), Error> {
        if self.finished.len() == self.limits.finished {
            return Err(Protocol::WouldBlock.into());
        }
        let original = actor.take_finished(token)?;
        self.finished.push_back(original);
        Ok(())
    }
    /// Retry only an actual local1203 enqueue, never actor processing, crypto or
    /// store mutation. The unresolved original worker debt is returned intact.
    pub fn release_input(&mut self, server: &mut Server) -> Result<Option<Finished<'id>>, Error> {
        let Some(original) = self.finished.pop_front() else {
            return Ok(None);
        };
        let runtime::Finished {
            origin,
            disposition,
            disk_debt,
        } = original;
        let origin = match origin {
            Origin::Ingress(origin) => origin,
            other => {
                self.finished.push_back(runtime::Finished {
                    origin: other,
                    disposition,
                    disk_debt,
                });
                return Err(Protocol::Malformed.into());
            }
        };
        match server.dv_finish_input(origin) {
            Ok(flow_control) => Ok(Some(Finished {
                disposition,
                flow_control,
                disk_debt,
            })),
            Err(refused) => {
                self.finished.push_back(runtime::Finished {
                    origin: Origin::Ingress(refused.value),
                    disposition,
                    disk_debt,
                });
                Err(refused.reason.into())
            }
        }
    }
    /// Begin actual source retirement; keep Owner's source-active gate while
    /// original native/FC and worker obligations still exist. Clock-free.
    pub fn begin_close<const N: usize>(
        &mut self,
        server: &mut Server,
        actor: &mut Actor<'id, '_, '_, '_, '_, N>,
    ) -> Result<(), Error> {
        actor.close();
        self.closing = true;
        let mut first = server.dv_begin_retire_source(&self.source).err();
        for send in &self.sends {
            if let Err(e) = server.dv_retire_transfer(&send.native) {
                first.get_or_insert(e);
            }
        }
        first.map_or(Ok(()), |e| Err(e.into()))
    }
    /// Release the same Owner source gate only after actual actor/worker join,
    /// original input/FC completion, all physical and reliability Jobs settled.
    pub fn close<const N: usize>(
        &mut self,
        server: &mut Server,
        actor: &Actor<'id, '_, '_, '_, '_, N>,
    ) -> Result<(), Error> {
        if !self.closing
            || !actor.is_quiescent()
            || !self.sends.is_empty()
            || !self.finished.is_empty()
            || server.dv_source_debts(&self.source) != 0
        {
            return Err(Protocol::NotReady.into());
        }
        if self.active {
            server.dv_retire_source(&self.source)?;
            self.active = false;
        }
        Ok(())
    }
    /// Original Engine-minted local source lease. Reading it is not remote
    /// authentication or permission to manufacture route/RTT/store evidence.
    pub fn source(&self) -> &engine::Source {
        &self.source
    }
    /// External original native debts still awaiting settlement; not a claim of
    /// remote delivery, source quiescence or worker/storage completion.
    pub fn native_outputs_pending(&self) -> usize {
        self.sends.len()
    }
    /// Original finished FC owners still retained by this bridge.
    pub fn pending_flow_control(&self) -> usize {
        self.finished.len()
    }
}

/// Apply the admission boundary's explicit decision to this original input.
/// A discard refusal retains its same input, debt and disposition for retry;
/// shared-source failures never consume a frame as a remote protocol refusal.
fn dispose_input_refusal<'id>(
    original: runtime::InputRefused<Origin>,
    discard: impl FnOnce() -> Result<engine::IngressEnd, Protocol>,
) -> Result<Receive<'id>, Error> {
    use runtime::InputRefusalDisposition;
    match original.disposition {
        InputRefusalDisposition::Deferred => Ok(Receive::Deferred(original)),
        InputRefusalDisposition::Source => Err(original.error.into()),
        InputRefusalDisposition::Rejected | InputRefusalDisposition::Expired => match discard() {
            Ok(flow_control) => {
                if original.disposition == InputRefusalDisposition::Expired {
                    Ok(Receive::Expired { flow_control })
                } else {
                    Ok(Receive::Discarded {
                        original,
                        flow_control,
                    })
                }
            }
            Err(Protocol::Capacity | Protocol::WouldBlock) => Ok(Receive::Deferred(original)),
            Err(cause) => Err(Error {
                cause: Cause::Actor(original.error),
                cleanup: Some(Cause::Protocol(cause)),
            }),
        },
    }
}
