//! Actual bounded caller-driven DV LEARN/BOX actor. This owns one real PILS MQ
//! and one independent durable DV worker, not a per-peer crypto connection. It
//! never sends raw TRANSPORT_DV_LEARN/BOX into CORE or fabricates write/FC results.
#![cfg(unix)]
#![forbid(unsafe_code)]
use gnunet_crypto::{EddsaPublicKey, EddsaSignature, Entropy};
use gnunet_pils::client::{Completion, Identity, Inbound, KeyTarget, OperationId};
use gnunet_pils_host::client::{Client, Progress};
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_transport::{PeerId, dv};
use gnunet_transport_dv_crypto::{Source, Task, cache, replay};
use gnunet_transport_dv_crypto_host::cache::{OperationBounds, ReceiveJob, SealJob};
use gnunet_transport_dv_store_host::{self as store, box_admission};
use gnunet_types::{Duration, Error as Protocol};
use gnunet_wire::official::Frame;
use std::{
    cell::Cell,
    fmt,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::time::{Instant, Sleep};
use zeroize::{Zeroize, Zeroizing};
mod types;
pub use types::*;
mod material;
use material::MaterialLease;
mod runtime;
/// Actual route evidence required for selection and exact original send admission.
pub use gnunet_transport::dv::routes::SendPolicy;
pub use runtime::Runtime;

/// Readonly actual input readiness, without sampling clock or granting proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputProgress {
    /// Actual crypto/provider/forward work remains.
    Working,
    /// Actual verified LEARN is ready for its one bounded fanout planner.
    LearnReady,
    /// Actual private Granted is ready for same-input Engine delivery.
    DeliveryReady,
    /// Processing retired but original child outputs still need physical facts.
    Retiring,
    /// Actual original metadata can be taken; no child physical debt remains.
    Finished,
}
/// Readonly actual output readiness, independent of message bytes or clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputProgress {
    /// Actual crypto/signing operation remains.
    Working,
    /// Original immutable frame is ready, before actual native admission.
    Ready,
    /// Actual native admission happened, still awaiting original packet result.
    Queued,
    /// Original queued physical output must be drained/closed.
    Retiring,
    /// Original output terminal metadata can be taken.
    Finished,
}
/// One actual bounded progress item. Query accessors borrow retained immutable
/// bytes/proofs, and all completion/cancellation methods require the same token.
#[derive(Debug)]
pub enum Step<'id> {
    /// Signature/durable watermark processing admitted real local route facts.
    LearnReady {
        /// Original incoming physical-frame owner.
        input: Token<'id>,
        /// Number of actual route facts changed by this admission.
        changed: usize,
        /// Whether the admitted original sender watermark advanced.
        freshness: dv::routes::Freshness,
    },
    /// Original immutable official frame is available for a real direct send.
    OutputReady(Token<'id>),
    /// Original externally queued output needs actual cancel/drain/physical
    /// retirement. Actor close alone does not settle its transport owner.
    RetireOutput(Token<'id>),
    /// Actual AEAD + signature + original persisted watermark + live replay
    /// grant is retained. This is not yet Engine/FC/application completion.
    DeliveryReady(Token<'id>),
    /// Original input is done/dropped and can be taken with its original origin.
    InputFinished(Token<'id>),
    /// Original local output fact can be taken with its exact caller origin.
    OutputFinished(Token<'id>),
    /// Real source/job/protocol progress without a new delivery statement.
    Activity,
    /// Exact input/output failed. Its original origin remains retrievable.
    Failed {
        /// Original retained input or output owner.
        token: Token<'id>,
        /// Actual refusal or native/provider failure.
        error: Error,
        /// Original bounded row/source facts captured before its state moved
        /// or cancellation replaced it with a terminal/retiring phase.
        context: FailureContext<'id>,
    },
    /// Actual provider event, including canceled commit/Unknown; not a new send.
    Store(store::Event<'id>),
    /// Original native source was actually closed. No pending work is replayed.
    Stopped,
}
/// Borrowed immutable outgoing official DV packet and exact direct queue lease.
pub struct Output<'a, 'id> {
    /// Original private local output identity.
    pub token: Token<'id>,
    /// Original selected direct queue; raw PID is not its authority.
    pub neighbour: &'a Neighbour<'id>,
    /// Exact encoded whole packet. Retries keep these bytes/nonce/signature.
    pub bytes: &'a [u8],
    /// Original bypass window policy carried by the official header.
    pub without_fc: bool,
    /// Original immutable native deadline; enqueue/partial I/O never renew it.
    pub hard: Instant,
    /// Same original logical bound; complete local write cannot renew it.
    pub until: gnunet_wire::official::AbsoluteTime,
}
/// Original external output debt that still requires a real native outcome.
pub struct Retirement<'a, 'id> {
    /// Same immutable output identity used at original queue admission.
    pub token: Token<'id>,
    /// Original direct queue owner, never a current same-number replacement.
    pub neighbour: &'a Neighbour<'id>,
    /// Some(true) only after an actual positive-write callback; otherwise the
    /// runtime has no authority to infer an unexposed native cursor.
    pub exposed: Option<bool>,
    /// Original absolute native target, never extended by cancellation/retry.
    pub hard: Instant,
}
/// Actual route validity in a native coordinate that can be compared across
/// independent Engine/actor monotonic epochs. This is readonly metadata, never
/// an Engine virtual-peer or native-admission authority by itself.
#[derive(Clone, Copy, Debug)]
pub struct RouteLife<'id> {
    /// Original actual route generation.
    pub route: dv::routes::RouteId<'id>,
    /// Original fixed native expiration, not a freshly extended cache deadline.
    pub hard: Instant,
    /// Original confirmed/passive routing evidence.
    pub freshness: dv::routes::Freshness,
}
impl RouteLife<'_> {
    /// Recompute from the ORIGINAL native expiration at actual bridge admission;
    /// no actor/Engine raw monotonic integer is reinterpreted as another epoch.
    pub fn remaining(&self) -> Result<Duration, Protocol> {
        let left = self
            .hard
            .checked_duration_since(Instant::now())
            .ok_or(Protocol::Deadline)?;
        let micros = u64::try_from(left.as_micros()).map_err(|_| Protocol::Overflow)?;
        if micros == 0 {
            return Err(Protocol::Deadline);
        }
        Ok(Duration(micros))
    }
}
/// Actual eligible source/route and maximum inner packet. This is not a
/// fabricated direct queue or a raw integer lifetime in another clock epoch.
pub struct SendPath<'id> {
    /// Exact evidence policy checked for this original route selection.
    pub policy: SendPolicy,
    /// Original route admission and fixed native expiration.
    pub life: RouteLife<'id>,
    /// Largest complete inner GNUnet frame fitting this actual BOX/path policy.
    pub max_plaintext: usize,
    /// Actual measured nonce RTT; unknown remains None.
    pub rtt: Option<Duration>,
}
/// Explicit original Engine packet policy, separate from actual crypto results.
pub struct SendOptions<'id> {
    /// Original final destination, not physical first-hop identity.
    pub target: PeerId,
    /// Actual caller-reserved persistent DV wire stamp for a new certificate.
    pub stamp: u64,
    /// Engine's original control-window bypass policy.
    pub without_fc: bool,
    /// Original task budget; waiting cannot renew either target.
    pub original: Option<Budget>,
    /// Exact route evidence policy, checked again at actual send admission.
    pub policy: SendPolicy,
    /// When supplied, require the SAME eligible route generation and target.
    pub route: Option<dv::routes::RouteId<'id>>,
}
/// Exact original output and external metadata, never a remote delivery proof.
pub struct OutputFinished<'id, J> {
    /// Actual external application metadata, absent for LEARN/BOX forwarding.
    pub origin: Option<J>,
    /// Original direct queue lease, including its local owner generation.
    pub neighbour: Option<Neighbour<'id>>,
    /// Actual original write outcome.
    pub outcome: WriteOutcome,
}

struct Bound {
    until: u64,
    hard: Instant,
}
impl Bound {
    fn budget(&self) -> Budget {
        Budget {
            until: gnunet_wire::official::AbsoluteTime::from_micros(self.until),
            hard: self.hard,
        }
    }
    fn new(now: u64, expiry: u64, limits: Limits) -> Result<Self, Protocol> {
        let until = now
            .checked_add(limits.operation.0)
            .ok_or(Protocol::Overflow)?
            .min(expiry);
        let hard = Instant::now()
            .checked_add(limits.native_operation)
            .ok_or(Protocol::Overflow)?;
        if until <= now {
            return Err(Protocol::Deadline);
        }
        Ok(Self { until, hard })
    }
    fn operation(&self) -> OperationBounds {
        OperationBounds::new(self.until, self.hard.into_std())
    }
    fn check(&self, now: u64) -> Result<(), Protocol> {
        if Instant::now() >= self.hard || now >= self.until {
            Err(Protocol::Deadline)
        } else {
            Ok(())
        }
    }
}
struct InputRow<'source, 'id, 'pils, 'out, J> {
    token: Token<'id>,
    neighbour: Neighbour<'id>,
    origin: Option<J>,
    bytes: Vec<u8>,
    received: std::time::Instant,
    bounds: Bound,
    state: InputState<'source, 'id, 'pils, 'out>,
    forwards: usize,
    planning: bool,
    disposition: Disposition,
    debt: Option<box_admission::Debt<'id>>,
}
enum InputState<'source, 'id, 'pils, 'out> {
    Learn,
    LearnWork(dv::routes::SourceWork<'id>),
    LearnStore(store::Operation<'id>),
    LearnReady,
    Box,
    Forwarding,
    Decapsulating {
        job: ReceiveJob<'source, 'id, 'pils>,
        lease: MaterialLease,
    },
    Material(cache::ReceiveId<'id>),
    Waiting(box_admission::Waiting<'source, 'id, 'out>),
    Ready(box_admission::Ready<'source, 'id, 'out>),
    Refused(box_admission::Refused<'source, 'id, 'out>),
    Granted(box_admission::Granted<'source, 'id, 'out>),
    Finished,
}
impl InputState<'_, '_, '_, '_> {
    fn phase(&self) -> InputPhase {
        match self {
            Self::Learn => InputPhase::Learn,
            Self::LearnWork(dv::routes::SourceWork::Load { .. }) => InputPhase::LearnSourceLoad,
            Self::LearnWork(dv::routes::SourceWork::Store { .. }) => InputPhase::LearnSourceStore,
            Self::LearnStore(_) => InputPhase::LearnStore,
            Self::LearnReady => InputPhase::LearnReady,
            Self::Box => InputPhase::Box,
            Self::Forwarding => InputPhase::Forwarding,
            Self::Decapsulating { .. } => InputPhase::Decapsulating,
            Self::Material(_) => InputPhase::Material,
            Self::Waiting(_) => InputPhase::Waiting,
            Self::Ready(_) => InputPhase::Ready,
            Self::Refused(_) => InputPhase::Refused,
            Self::Granted(_) => InputPhase::Granted,
            Self::Finished => InputPhase::Finished,
        }
    }
}
impl<'id, J> InputRow<'_, 'id, '_, '_, J> {
    // Only the original child's terminal outcome releases a forwarded input.
    // LEARN fanout keeps its existing planner/remaining-child completion gate.
    fn child_finished(&mut self, outcome: WriteOutcome) -> bool {
        self.forwards = self.forwards.saturating_sub(1);
        if matches!(self.state, InputState::Forwarding) {
            self.state = InputState::Finished;
            self.planning = false;
            self.disposition = Disposition::Forwarded(outcome);
        }
        matches!(self.state, InputState::LearnReady)
    }
    fn failure(
        &self,
        outputs: &[OutputRow<'_, 'id, '_, J>],
        source: Budget,
        identity_until: gnunet_wire::official::AbsoluteTime,
        observed_native: Instant,
        observed_absolute: Option<gnunet_wire::official::AbsoluteTime>,
    ) -> FailureContext<'id> {
        let forwarding_child = if matches!(self.state, InputState::Forwarding) {
            let mut children = outputs
                .iter()
                .filter(|child| child.parent == Some(self.token));
            match (children.next(), children.next()) {
                (Some(child), None) => Some(ForwardChildFailure {
                    token: child.token,
                    phase: child.state.phase(),
                    queued: child.queued,
                    exposed: child.exposed,
                    outcome: child.state.outcome(),
                    budget: child.bounds.budget(),
                }),
                _ => None,
            }
        } else {
            None
        };
        FailureContext {
            budget: self.bounds.budget(),
            source,
            identity_until,
            observed_native,
            observed_absolute,
            neighbour: self.neighbour.clone(),
            state: FailureState::Input {
                phase: self.state.phase(),
                age: self.received.elapsed(),
                forwards: self.forwards,
                planning: self.planning,
                detached_disk_debt: self.debt.is_some(),
                forwarding_child,
            },
        }
    }
}
struct OutputRow<'source, 'id, 'pils, J> {
    token: Token<'id>,
    neighbour: Neighbour<'id>,
    origin: Option<J>,
    parent: Option<Token<'id>>,
    bounds: Bound,
    state: OutputState<'source, 'id, 'pils>,
    bytes: Vec<u8>,
    without_fc: bool,
    // Only ordinary locally generated BOXes join the per-target causal chain.
    // The original source's token serial orders them independently of Vec slots.
    ordered_target: Option<PeerId>,
    exposed: bool,
    queued: bool,
    probe: Option<dv::routes::ProbeId<'id>>,
}
impl<J> OutputRow<'_, '_, '_, J> {
    fn progress(&self) -> OutputProgress {
        match &self.state {
            OutputState::Ready if self.queued => OutputProgress::Queued,
            OutputState::Ready => OutputProgress::Ready,
            OutputState::AwaitPhysical => OutputProgress::Retiring,
            OutputState::Finished(_) => OutputProgress::Finished,
            _ => OutputProgress::Working,
        }
    }
}
impl<'id, J> OutputRow<'_, 'id, '_, J> {
    fn failure(
        &self,
        source: Budget,
        identity_until: gnunet_wire::official::AbsoluteTime,
        observed_native: Instant,
        observed_absolute: Option<gnunet_wire::official::AbsoluteTime>,
    ) -> FailureContext<'id> {
        FailureContext {
            budget: self.bounds.budget(),
            source,
            identity_until,
            observed_native,
            observed_absolute,
            neighbour: self.neighbour.clone(),
            state: FailureState::Output {
                phase: self.state.phase(),
                parent: self.parent,
                ordered_target: self.ordered_target,
                queued: self.queued,
                exposed: self.exposed,
                outcome: self.state.outcome(),
            },
        }
    }
}
// Charge each retained packet allocation once, including unused tail capacity
// after an in-place BOX route strip. This is not allocator overhead or RSS.
fn retained_packet_bytes<J>(
    inputs: &[InputRow<'_, '_, '_, '_, J>],
    outputs: &[OutputRow<'_, '_, '_, J>],
) -> usize {
    inputs
        .iter()
        .map(|row| row.bytes.capacity())
        .chain(outputs.iter().map(|row| {
            row.bytes.capacity().saturating_add(match &row.state {
                OutputState::Seal { message, .. } => message.capacity(),
                _ => 0,
            })
        }))
        .fold(0, usize::saturating_add)
}
fn ordered_predecessor<J>(
    outputs: &[OutputRow<'_, '_, '_, J>],
    output: &OutputRow<'_, '_, '_, J>,
) -> bool {
    let Some(target) = output.ordered_target else {
        return false;
    };
    outputs.iter().any(|earlier| {
        earlier.ordered_target == Some(target)
            && core::ptr::eq(earlier.token.domain, output.token.domain)
            && earlier.token.serial < output.token.serial
            && earlier.state.outcome().is_none()
    })
}
fn admissible_output<J>(
    outputs: &[OutputRow<'_, '_, '_, J>],
    output: &OutputRow<'_, '_, '_, J>,
) -> bool {
    matches!(output.state, OutputState::Ready)
        && !output.queued
        && !ordered_predecessor(outputs, output)
}
enum OutputState<'source, 'id, 'pils> {
    Probe {
        task: Task<'source, 'id>,
        operation: OperationId<'pils>,
        challenge: [u8; 32],
    },
    Forward {
        task: Task<'source, 'id>,
        operation: OperationId<'pils>,
        reverse: bool,
    },
    Seal {
        // Allocate pending certification only on a material-cache miss rather
        // than padding every ready, forwarded and finished output row.
        job: Box<SealJob<'source, 'id, 'pils>>,
        lease: MaterialLease,
        message: Zeroizing<Vec<u8>>,
        route: Vec<PeerId>,
    },
    Ready,
    AwaitPhysical,
    Finished(WriteOutcome),
}
impl OutputState<'_, '_, '_> {
    fn outcome(&self) -> Option<WriteOutcome> {
        match self {
            Self::Finished(outcome) => Some(*outcome),
            _ => None,
        }
    }
    fn phase(&self) -> OutputPhase {
        match self {
            Self::Probe { .. } => OutputPhase::Probe,
            Self::Forward { .. } => OutputPhase::Forward,
            Self::Seal { .. } => OutputPhase::Seal,
            Self::Ready => OutputPhase::Ready,
            Self::AwaitPhysical => OutputPhase::AwaitPhysical,
            Self::Finished(_) => OutputPhase::Finished,
        }
    }
}
/// Original retained probe state, independent of output-row recycling. Only
/// the runtime's actual written callback can set sent=true.
#[derive(Clone, Copy, Debug)]
pub struct ProbeStatus {
    /// Original fixed canonical/native targets.
    pub budget: Budget,
    /// Observed actual whole physical output, including a late retired output.
    pub sent: bool,
    /// Its original route-learning lease has irreversibly ended.
    pub retired: bool,
    /// Actual original physical output fact, if known; never remote delivery.
    pub outcome: Option<WriteOutcome>,
}
struct ProbeTrack<'id> {
    token: Token<'id>,
    neighbour: Neighbour<'id>,
    probe: Option<dv::routes::ProbeId<'id>>,
    budget: Budget,
    sent: bool,
    outcome: Option<WriteOutcome>,
}
struct Retiring<I> {
    operation: I,
    hard: Instant,
}
fn copy(bytes: &[u8]) -> Result<Vec<u8>, Protocol> {
    let mut out = Vec::new();
    out.try_reserve_exact(bytes.len())
        .map_err(|_| Protocol::Capacity)?;
    out.extend_from_slice(bytes);
    Ok(out)
}
fn sized(bytes: usize) -> Result<Vec<u8>, Protocol> {
    let mut out = Vec::new();
    out.try_reserve_exact(bytes)
        .map_err(|_| Protocol::Capacity)?;
    out.resize(bytes, 0);
    Ok(out)
}
fn signature<'a>(
    completion: &'a Completion<'_>,
    operation: OperationId<'_>,
    original: Identity<'_>,
    local: PeerId,
    now: u64,
) -> Result<&'a EddsaSignature, Error> {
    if completion.operation() != operation {
        return Err(Protocol::Stale.into());
    }
    match completion {
        Completion::Signature {
            peer,
            signature,
            announced: Some(actual),
            ..
        } if peer.as_bytes() == &local.0
            && actual.epoch() == original.epoch()
            && actual.peer() == original.peer()
            && now < actual.expiration().as_micros()
            && now < original.expiration().as_micros() =>
        {
            Ok(signature)
        }
        Completion::Failed { reason, .. } => Err(Error::Crypto(
            gnunet_transport_dv_crypto_host::Error::Rejected(*reason),
        )),
        _ => Err(Protocol::Authentication.into()),
    }
}

#[cfg(test)]
mod output_order_tests {
    use super::*;

    fn check(value: bool) -> Result<(), Protocol> {
        if value {
            Ok(())
        } else {
            Err(Protocol::Conflict)
        }
    }
    fn token(instance: &Instance) -> Result<Token<'_>, Protocol> {
        Ok(Token {
            domain: instance,
            serial: instance.next()?,
        })
    }
    fn row<'id>(
        instance: &'id Instance,
        owner: &gnunet_transport::ClientId,
        target: Option<PeerId>,
        without_fc: bool,
    ) -> Result<OutputRow<'id, 'id, 'id, ()>, Protocol> {
        // Only the production scheduling policy is exercised here. These empty
        // metadata rows claim no crypto, native admission or physical outcome.
        Ok(OutputRow {
            token: token(instance)?,
            neighbour: Neighbour {
                token: token(instance)?,
                client: owner.clone(),
                peer: PeerId([2; 32]),
                queue: 1,
                reverse: true,
            },
            origin: None,
            parent: None,
            bounds: Bound {
                until: 100,
                hard: Instant::now()
                    .checked_add(std::time::Duration::from_secs(30))
                    .ok_or(Protocol::Overflow)?,
            },
            state: OutputState::Ready,
            bytes: Vec::new(),
            without_fc,
            ordered_target: target,
            exposed: false,
            queued: false,
            probe: None,
        })
    }
    fn index<J>(outputs: &[OutputRow<'_, '_, '_, J>], token: Token<'_>) -> Result<usize, Protocol> {
        outputs
            .iter()
            .position(|output| output.token == token)
            .ok_or(Protocol::NotFound)
    }
    fn allowed<J>(
        outputs: &[OutputRow<'_, '_, '_, J>],
        token: Token<'_>,
    ) -> Result<bool, Protocol> {
        Ok(admissible_output(outputs, &outputs[index(outputs, token)?]))
    }

    #[test]
    fn local_target_order_survives_swap_remove_partial_and_retirement() -> Result<(), Protocol> {
        let domain = Instance::new();
        let mut engine =
            gnunet_transport::Engine::new(PeerId([1; 32]), gnunet_transport::Limits::default())?;
        let owner = engine.accept()?;
        let target = PeerId([3; 32]);
        let mut rows = vec![
            row(&domain, &owner, None, false)?,
            row(&domain, &owner, Some(target), false)?,
            row(&domain, &owner, None, true)?,
            row(&domain, &owner, Some(PeerId([4; 32])), false)?,
            row(&domain, &owner, Some(target), false)?,
        ];
        let first = rows[1].token;
        let control = rows[2].token;
        let other = rows[3].token;
        let second = rows[4].token;
        rows[0].state = OutputState::Finished(WriteOutcome::Written);
        check(allowed(&rows, first)? && !allowed(&rows, second)?)?;
        let _retired = rows.swap_remove(0);
        check(index(&rows, second)? < index(&rows, first)?)?;
        check(allowed(&rows, first)? && !allowed(&rows, second)?)?;

        // Queueing and a partial write do not settle the predecessor. Its own
        // native continuation remains permissible, while new staging does not.
        let i = index(&rows, first)?;
        rows[i].queued = true;
        rows[i].exposed = true;
        check(!ordered_predecessor(&rows, &rows[i]))?;
        check(!allowed(&rows, first)? && !allowed(&rows, second)?)?;
        rows[i].state = OutputState::AwaitPhysical;
        check(!allowed(&rows, second)?)?;
        check(allowed(&rows, control)? && allowed(&rows, other)?)?;

        // A terminal failure releases order without needing metadata removal;
        // this is a policy fixture, not a report of an executed native write.
        rows[i].state = OutputState::Finished(WriteOutcome::Lost(Some(true)));
        check(allowed(&rows, second)?)?;
        let _retired = rows.swap_remove(i);
        check(allowed(&rows, second)?)
    }

    #[test]
    fn control_and_forwarded_outputs_do_not_join_a_local_target_chain() -> Result<(), Protocol> {
        let domain = Instance::new();
        let mut engine =
            gnunet_transport::Engine::new(PeerId([1; 32]), gnunet_transport::Limits::default())?;
        let owner = engine.accept()?;
        let target = PeerId([3; 32]);
        let mut rows = vec![
            row(&domain, &owner, Some(target), false)?,
            row(&domain, &owner, None, false)?,
            row(&domain, &owner, None, true)?,
            row(&domain, &owner, Some(target), false)?,
        ];
        let forwarded = rows[1].token;
        rows[1].parent = Some(token(&domain)?);
        let control = rows[2].token;
        let second = rows[3].token;
        check(allowed(&rows, forwarded)? && allowed(&rows, control)?)?;
        check(!allowed(&rows, second)?)?;
        rows[0].state = OutputState::Finished(WriteOutcome::Unsent);
        check(allowed(&rows, second)?)?;
        // Both bypass rows remain unsettled; neither can hold local data back.
        check(rows[1].state.outcome().is_none() && rows[2].state.outcome().is_none())?;
        check(allowed(&rows, forwarded)? && allowed(&rows, control)?)
    }
}
