//! Concrete actual actor/common-Job/native composition, no second Flow engine.
use super::*;
use gnunet_crypto::Entropy;
use gnunet_service_runtime::service::Listener;
use std::future::Future;
use std::task::{Context, Poll};

/// Original common-transmit packet and immutable actual budget. Only this real
/// bridge constructs it after matching its installed actually usable Actor path.
pub struct VirtualIntent<'id> {
    id: engine::VirtualId,
    path: engine::PathId,
    route: gnunet_transport::dv::routes::RouteId<'id>,
    target: PeerId,
    bypass: bool,
    policy: runtime::SendPolicy,
    budget: runtime::Budget,
}
impl VirtualIntent<'_> {
    /// Exact original budget for the one shared actual DV stamp allocator.
    pub fn budget(&self) -> runtime::Budget {
        self.budget
    }
    /// Actual final target, not an invented direct queue.
    pub const fn target(&self) -> PeerId {
        self.target
    }
}
/// Fixed facts for the exact original Actor-to-native transfer association.
/// This copy contains no owner/callback token and changes no runtime decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendDiagnostic {
    /// Actual native queue admission was reported for this original transfer.
    pub queued: bool,
    /// Actual positive native IPC bytes were reported on that original owner.
    pub exposed: bool,
    /// The original local packet/source outcome was applied to the Actor.
    pub notified: bool,
    /// The complete original transfer had a successful local1210 outcome.
    pub written: bool,
    /// Original Actor output metadata was actually taken after termination.
    pub actor_finished: bool,
    /// Exact original Engine transfer facts, absent if no longer retained there.
    pub engine: Option<engine::TransferDiagnostic>,
}
/// Actual original Actor admission, not physical write or remote processing.
pub enum SendVirtual<'id> {
    /// This SAME common packet/attempt was admitted to actual Actor processing.
    Submitted(Token<'id>),
    /// Actual zero-admission refusal, including its original opaque metadata.
    Deferred(runtime::Refused<Origin>),
}
impl<'id> Bridge<'id> {
    /// Copy one exact original output association without borrowing the Actor,
    /// sampling a clock, rerunning preflight or granting mutable owner authority.
    /// A foreign/unstaged token returns None, and unavailable diagnostics do not
    /// alter any original failure, progress or retirement obligation.
    pub fn output_diagnostic(&self, server: &Server, token: Token<'id>) -> Option<SendDiagnostic> {
        let send = self.sends.iter().find(|send| send.actor == token)?;
        Some(SendDiagnostic {
            queued: send.queued,
            exposed: send.exposed,
            notified: send.notified,
            written: send.written,
            actor_finished: send.actor_finished,
            engine: server.dv_transfer_diagnostic(&send.native),
        })
    }
    /// Install/update only actual current bidirectional-send-eligible Actor
    /// routes. Signed inverse paths keep Passive freshness and unknown RTT;
    /// eligibility is not a local nonce/probe confirmation. Returns true only
    /// after an actual original path installation or withdrawal, so native
    /// callers continue driving newly created CORE/control work without a lost
    /// local wakeup. Readonly target enumeration grants no route authenticity.
    pub fn sync_paths<const N: usize>(
        &mut self,
        server: &mut Server,
        actor: &mut Actor<'id, '_, '_, '_, '_, N>,
        times: Times,
    ) -> Result<bool, Error> {
        if !self.active || self.closing {
            return Err(Protocol::Closed.into());
        }
        server.engine().validate_times(times)?;
        let mut changed = false;
        self.targets.clear();
        for peer in actor.route_targets() {
            if self.targets.contains(&peer) {
                continue;
            }
            if self.targets.len() == self.limits.paths {
                return Err(Protocol::Capacity.into());
            }
            self.targets.push(peer);
        }
        let mut i = 0;
        while i < self.paths.len() {
            let peer = self.paths[i].target;
            if actor
                .send_path_with_policy(peer, runtime::SendPolicy::Bidirectional)?
                .is_some()
            {
                i += 1;
                continue;
            }
            server.dv_withdraw_path(&self.paths[i].id)?;
            self.paths.swap_remove(i);
            changed = true;
        }
        for i in 0..self.targets.len() {
            let target = self.targets[i];
            let Some(actual) =
                actor.send_path_with_policy(target, runtime::SendPolicy::Bidirectional)?
            else {
                continue;
            };
            if self.paths.iter().any(|p| {
                p.target == target
                    && p.route == actual.life.route
                    && p.hard == actual.life.hard
                    && p.mtu == actual.max_plaintext
                    && p.policy == actual.policy
            }) {
                continue;
            }
            let previous = self.paths.iter().position(|p| p.target == target);
            if previous.is_none() && self.paths.len() == self.limits.paths {
                return Err(Protocol::Capacity.into());
            }
            let remaining = match actual.life.remaining() {
                Ok(left) => left,
                Err(Protocol::Deadline) => {
                    if let Some(i) = previous {
                        server.dv_withdraw_path(&self.paths[i].id)?;
                        self.paths.swap_remove(i);
                        changed = true;
                    }
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            // Install the replacement before changing this bridge's ledger.
            // Engine replaces visibility atomically, retaining original Jobs
            // and canceled old Actor leases without a false CORE disconnect.
            let id = server.dv_install_path(
                &self.source,
                target,
                actual.max_plaintext,
                remaining,
                times,
            )?;
            let path = Path {
                target,
                id,
                route: actual.life.route,
                hard: actual.life.hard,
                mtu: actual.max_plaintext,
                policy: actual.policy,
            };
            if let Some(i) = previous {
                self.paths[i] = path;
            } else {
                self.paths.push(path);
            }
            changed = true;
        }
        Ok(changed)
    }
    /// Exact parent Job mono deadline uses Owner Clock's ORIGINAL mono0 native
    /// epoch. No new now/UTC offset is invented when a packet waits for range IO.
    pub fn prepare_virtual<const N: usize>(
        &self,
        server: &Server,
        actor: &Actor<'id, '_, '_, '_, '_, N>,
    ) -> Result<Option<VirtualIntent<'id>>, Error> {
        if !self.active || self.closing {
            return Err(Protocol::Closed.into());
        }
        let Some(packet) =
            server.dv_virtual_packet_where(|packet| !actor.send_material_pending(packet.target))
        else {
            return Ok(None);
        };
        let path = self
            .paths
            .iter()
            .find(|p| p.id == packet.path && p.target == packet.target)
            .ok_or(Protocol::Stale)?;
        let hard = self
            .native_epoch
            .checked_add(std::time::Duration::from_micros(packet.until.0))
            .ok_or(Protocol::Overflow)?
            .min(path.hard);
        if Instant::now() >= hard {
            return Err(Protocol::Deadline.into());
        }
        Ok(Some(VirtualIntent {
            id: packet.id,
            path: packet.path,
            route: path.route,
            target: packet.target,
            bypass: packet.without_fc,
            policy: path.policy,
            budget: runtime::Budget {
                until: actor.identity().expiration(),
                hard,
            },
        }))
    }
    /// Trusted low-level stamp port. Production dv_transmit consumes the actual
    /// private persisted Scheduler::Stamp immediately before calling this. It
    /// does not construct a verified stamp from this numeric wire scalar.
    pub fn send_virtual<const N: usize>(
        &mut self,
        server: &mut Server,
        actor: &mut Actor<'id, '_, '_, '_, '_, N>,
        original: VirtualIntent<'id>,
        stamp: u64,
        entropy: &mut impl Entropy,
    ) -> Result<SendVirtual<'id>, Error> {
        if !self.active || self.closing {
            return Err(Protocol::Closed.into());
        }
        original.budget.check_native()?;
        if server.dv_virtual_canceled(&original.id)
            || !self.paths.iter().any(|p| {
                p.id == original.path
                    && p.route == original.route
                    && p.target == original.target
                    && p.policy == original.policy
            })
        {
            return Err(Protocol::Stale.into());
        }
        let options = runtime::SendOptions {
            target: original.target,
            stamp,
            without_fc: original.bypass,
            original: Some(original.budget),
            route: Some(original.route),
            policy: original.policy,
        };
        let result = server.dv_try_virtual_generic(&original.id, |lease, bytes| {
            actor.send_with_options(options, Origin::Outbound(lease), bytes, entropy)
        })?;
        Ok(match result {
            Ok(id) => SendVirtual::Submitted(id),
            Err(original) => SendVirtual::Deferred(original),
        })
    }
    /// Stage the immutable real Actor output as ONE existing direct Job. All
    /// chunks/reliability use transmit_job and the same queue serial. The actual
    /// NativeObserver, not staging, reports Actor.queued before any physical IO.
    pub fn queue_output<const N: usize>(
        &mut self,
        server: &mut Server,
        actor: &mut Actor<'id, '_, '_, '_, '_, N>,
        token: Token<'id>,
        times: Times,
    ) -> Result<Queued, TaskFailure> {
        self.check_task_source(server, times)?;
        if self
            .parent_retired(server.engine(), actor, token)
            .map_err(TaskFailure::source)?
        {
            self.cancel_parent(server, actor, token)
                .map_err(TaskFailure::source)?;
            return Ok(Queued::Retired);
        }
        if self.sends.iter().any(|s| s.actor == token) {
            return Ok(Queued::AlreadyStaged);
        }
        if self.sends.len() == self.limits.outputs {
            return Err(TaskFailure::deferred(Protocol::Capacity.into()));
        }
        let output = actor.output(token).map_err(task_failure::actor)?;
        let binding = self
            .bindings
            .iter()
            .find(|b| &b.neighbour == output.neighbour)
            .ok_or_else(|| TaskFailure::task(Protocol::Stale.into()))?;
        let native = server
            .dv_enqueue_output(
                &self.source,
                &binding.queue,
                output.bytes,
                output.without_fc,
                output.hard,
                times,
            )
            .map_err(task_failure::enqueue)?;
        self.sends.push(Send {
            actor: token,
            native,
            queued: false,
            exposed: false,
            notified: false,
            written: false,
            actor_finished: false,
            budget: runtime::Budget {
                until: output.until,
                hard: output.hard,
            },
        });
        Ok(Queued::Staged)
    }
    /// Check the exact shared Engine epoch and time before interpreting any
    /// synchronous per-task admission refusal. There is no await or replacement
    /// source between this check and the original enqueue/delivery attempt.
    pub(super) fn check_task_source(
        &self,
        server: &Server,
        times: Times,
    ) -> Result<(), TaskFailure> {
        if !self.active || self.closing {
            return Err(TaskFailure::source(Protocol::Closed.into()));
        }
        if server.engine().dv_current_source() != Some(&self.source)
            || !server.engine().dv_source_accepting()
        {
            return Err(TaskFailure::source(Protocol::Stale.into()));
        }
        server
            .engine()
            .validate_times(times)
            .map_err(|error| TaskFailure::source(error.into()))
    }
    /// Observe ONLY real packet/source facts. Ordinary native queue/exposure
    /// callbacks have already run synchronously through poll_server/poll_tick.
    pub fn settle_send<const N: usize>(
        &mut self,
        server: &mut Server,
        actor: &mut Actor<'id, '_, '_, '_, '_, N>,
    ) -> Result<Option<SendProgress<'id>>, Error> {
        if self.sends.is_empty() {
            return Ok(None);
        }
        for _ in 0..self.sends.len() {
            let i = self.send_cursor % self.sends.len();
            self.send_cursor = self.send_cursor.wrapping_add(1);
            if self.sends[i].notified || self.sends[i].actor_finished {
                continue;
            }
            let state = server.dv_transfer_state(&self.sends[i].native)?;
            let token = self.sends[i].actor;
            let Some(outcome) = state.outcome else {
                continue;
            };
            if outcome == engine::TransferOutcome::Incomplete && !self.sends[i].queued {
                // Positive original chunk facts cannot be relabelled unsent
                // when their native admission observation is missing.
                return Err(Protocol::Conflict.into());
            }
            let result = if !self.sends[i].queued {
                // No real native admission was reported; retire the original
                // common Job/source before confirming actor's unsent outcome.
                server.dv_retire_transfer(&self.sends[i].native)?;
                actor.cancel(token)
            } else {
                match outcome {
                    engine::TransferOutcome::Written => {
                        self.sends[i].written = true;
                        actor.written(token)
                    }
                    engine::TransferOutcome::Unsent => return Err(Protocol::Conflict.into()),
                    engine::TransferOutcome::Incomplete
                    | engine::TransferOutcome::Failed(_)
                    | engine::TransferOutcome::SourceLost => {
                        server.dv_retire_transfer(&self.sends[i].native)?;
                        actor.output_lost(token, Some(state.exposed))
                    }
                }
            };
            self.sends[i].notified = true;
            result?;
            return Ok(Some(SendProgress {
                token,
                physical: state,
            }));
        }
        Ok(None)
    }
    /// Retire the exact original output. Unknown native chunks require the
    /// same physical source's closure; settled incomplete work preserves it.
    /// No protocol CANCEL or complete packet write is invented.
    pub fn retire_output<const N: usize>(
        &mut self,
        server: &mut Server,
        actor: &mut Actor<'id, '_, '_, '_, '_, N>,
        token: Token<'id>,
    ) -> Result<(), Error> {
        actor.retirement(token)?;
        let i = self
            .sends
            .iter()
            .position(|s| s.actor == token)
            .ok_or(Protocol::Stale)?;
        let state = server.dv_transfer_state(&self.sends[i].native)?;
        if state.outcome == Some(engine::TransferOutcome::Written) {
            self.sends[i].written = true;
            actor.written(token)?;
        } else {
            server.dv_retire_transfer(&self.sends[i].native)?;
            let actual = server.dv_transfer_state(&self.sends[i].native)?;
            actor.output_lost(token, Some(actual.exposed))?;
        }
        self.sends[i].notified = true;
        Ok(())
    }
    /// Consume actual Actor completion, then release only the SAME original
    /// virtual attempt's local ACK gate. Reliable remote coverage remains the
    /// original Book's concern and causes a fresh BOX nonce on a true retry.
    pub fn finish_output<const N: usize>(
        &mut self,
        server: &mut Server,
        actor: &mut Actor<'id, '_, '_, '_, '_, N>,
        token: Token<'id>,
    ) -> Result<runtime::OutputFinished<'id, Origin>, Error> {
        // Native retirement must not cancel a still-working Actor output.
        if actor.output_state(token)? != runtime::OutputProgress::Finished {
            return Err(Protocol::NotReady.into());
        }
        if actor.output_outcome(token)?.is_none() {
            return Err(Protocol::Conflict.into());
        }
        let send = self.sends.iter().position(|s| s.actor == token);
        if let Some(i) = send
            && !self.sends[i].queued
        {
            if server.dv_transfer_state(&self.sends[i].native)?.outcome
                == Some(engine::TransferOutcome::Written)
            {
                // Preserve the positive native fact and the original Actor
                // owner when its queue-admission observation is missing.
                return Err(Protocol::Conflict.into());
            }
            // The common Job may finish while frames, SendRows and grants
            // remain staged. Any refusal here leaves completion in the Actor.
            server.dv_retire_transfer(&self.sends[i].native)?;
        }
        let output = actor.try_take_output_finished(token, |origin| match origin {
            Some(Origin::Outbound(original)) => match server.dv_finish_virtual(original) {
                Ok(()) => Ok(None),
                Err(refused) => Err((refused.reason, Some(Origin::Outbound(refused.value)))),
            },
            other => Ok(other),
        })??;
        if let Some(i) = send {
            self.sends[i].actor_finished = true;
        }
        // Independent Engine metadata reclamation belongs to reap_transfers;
        // it cannot turn this completed ownership handoff into a lost result.
        Ok(output)
    }
    fn parent_retired<const N: usize>(
        &self,
        engine: &gnunet_transport::Engine,
        actor: &Actor<'id, '_, '_, '_, '_, N>,
        token: Token<'id>,
    ) -> Result<bool, Error> {
        Ok(match actor.output_origin(token)? {
            Some(Origin::Outbound(parent)) => engine.dv_virtual_canceled(&parent.id()),
            _ => false,
        })
    }
    fn cancel_parent<const N: usize>(
        &mut self,
        server: &mut Server,
        actor: &mut Actor<'id, '_, '_, '_, '_, N>,
        token: Token<'id>,
    ) -> Result<(), Error> {
        actor.cancel(token)?;
        if let Some(i) = self.sends.iter().position(|s| s.actor == token) {
            server.dv_retire_transfer(&self.sends[i].native)?;
            let actual = server.dv_transfer_state(&self.sends[i].native)?;
            if actor.output_state(token)? == runtime::OutputProgress::Retiring {
                if actual.outcome == Some(engine::TransferOutcome::Written) {
                    self.sends[i].written = true;
                    actor.written(token)?;
                } else {
                    actor.output_lost(token, Some(actual.exposed))?;
                }
            }
            self.sends[i].notified = true;
        }
        Ok(())
    }
    /// Cancel one exact original admitted Actor output whose CORE Job retired.
    /// Processing/ready work is really canceled; earlier native queue/partial
    /// work is physically retired on that same MQ, never reported as unsent.
    /// No clock, cloned payload, replacement source or wire CANCEL is required.
    pub fn cancel_retired<const N: usize>(
        &mut self,
        server: &mut Server,
        actor: &mut Actor<'id, '_, '_, '_, '_, N>,
    ) -> Result<bool, Error> {
        let mut selected = None;
        for token in actor.output_tokens() {
            if matches!(
                actor.output_state(token)?,
                runtime::OutputProgress::Retiring | runtime::OutputProgress::Finished
            ) {
                continue;
            }
            if self.parent_retired(server.engine(), actor, token)? {
                selected = Some(token);
                break;
            }
        }
        if let Some(token) = selected {
            self.cancel_parent(server, actor, token)?;
            return Ok(true);
        }
        Ok(false)
    }
    /// Retire local written/reliability metadata only when BOTH actual native
    /// result and original Job/remote ACK debt ended. No ACK is synthesized.
    pub fn reap_transfers(&mut self, server: &mut Server) -> Result<(), Error> {
        let mut i = 0;
        while i < self.sends.len() {
            if !self.sends[i].actor_finished {
                i += 1;
                continue;
            }
            let state = server.dv_transfer_state(&self.sends[i].native)?;
            if state.job_pending || state.outcome.is_none() {
                i += 1;
                continue;
            }
            match server.dv_take_transfer(self.sends[i].native.clone()) {
                Ok(_) => {
                    self.sends.swap_remove(i);
                }
                Err(r) if r.reason == Protocol::NotReady => {
                    i += 1;
                }
                Err(r) => return Err(r.reason.into()),
            }
        }
        Ok(())
    }
    /// Drive actual accepted MQs using the concrete actor observer. Dropping the
    /// future/poll wait preserves every original cursor, token and budget.
    pub fn poll_server<
        S: Signer,
        E: Entropy,
        A: gnunet_transport_host::AddressStore,
        const N: usize,
    >(
        &mut self,
        server: &mut Server,
        actor: &mut Actor<'id, '_, '_, '_, '_, N>,
        cx: &mut Context<'_>,
        listener: Option<Listener<'_>>,
        times: Times,
        ports: native::Ports<'_, S, E, A>,
    ) -> Poll<Result<gnunet_transport_host::Step, Error>> {
        match self.poll_guard(server, cx) {
            Ok(true) => return Poll::Ready(Ok(gnunet_transport_host::Step::Progress)),
            Ok(false) => {}
            Err(e) => return Poll::Ready(Err(e)),
        }
        match self.cancel_retired(server, actor) {
            Ok(true) => return Poll::Ready(Ok(gnunet_transport_host::Step::Progress)),
            Ok(false) => {}
            Err(e) => return Poll::Ready(Err(e)),
        }
        let mut observer = Observer {
            bridge: &mut *self,
            actor: &mut *actor,
            failure: None,
            cleanup: None,
            retire: None,
        };
        let result = server.poll_step_observed_at(cx, listener, times, ports, &mut observer);
        observer.finish(server, result)
    }
    /// Actual original timer/retry latch and common Jobs with synchronous native
    /// callbacks. No fresh Tick is created while the original barrier is Pending.
    pub fn poll_tick<E: Entropy, A: gnunet_transport_host::AddressStore, const N: usize>(
        &mut self,
        server: &mut Server,
        actor: &mut Actor<'id, '_, '_, '_, '_, N>,
        cx: &mut Context<'_>,
        times: Times,
        entropy: &mut E,
        store: &mut A,
    ) -> Poll<Result<gnunet_transport_host::Step, Error>> {
        match self.cancel_retired(server, actor) {
            Ok(true) => return Poll::Ready(Ok(gnunet_transport_host::Step::Progress)),
            Ok(false) => {}
            Err(e) => return Poll::Ready(Err(e)),
        }
        let mut observer = Observer {
            bridge: &mut *self,
            actor: &mut *actor,
            failure: None,
            cleanup: None,
            retire: None,
        };
        let result = server.poll_tick_observed_at(cx, times, entropy, store, &mut observer);
        observer.finish(server, result)
    }
    /// Retry an actual retained preflight only on its real resource policy wake;
    /// does not replay IPC, reseal a queued BOX or refresh the parent's deadline.
    pub fn poll_retry<E: Entropy, A: gnunet_transport_host::AddressStore, const N: usize>(
        &mut self,
        server: &mut Server,
        actor: &mut Actor<'id, '_, '_, '_, '_, N>,
        cx: &mut Context<'_>,
        times: Times,
        entropy: &mut E,
        store: &mut A,
    ) -> Poll<Result<gnunet_transport_host::Step, Error>> {
        match self.cancel_retired(server, actor) {
            Ok(true) => return Poll::Ready(Ok(gnunet_transport_host::Step::Progress)),
            Ok(false) => {}
            Err(e) => return Poll::Ready(Err(e)),
        }
        let mut observer = Observer {
            bridge: &mut *self,
            actor: &mut *actor,
            failure: None,
            cleanup: None,
            retire: None,
        };
        let result = server.poll_retry_observed_at(cx, times, entropy, store, &mut observer);
        observer.finish(server, result)
    }
    /// Bounded one-row cleanup of actual never-admitted staging after source,
    /// path or parent deadline retirement. No actor/native fact is fabricated.
    pub fn discard_retired(&mut self, server: &mut Server, times: Times) -> Result<bool, Error> {
        Ok(server.dv_discard_retired(times)?)
    }
}
struct Observer<'a, 'id, 'source, 'pils, 'slots, 'out, const N: usize> {
    bridge: &'a mut Bridge<'id>,
    actor: &'a mut Actor<'id, 'source, 'pils, 'slots, 'out, N>,
    failure: Option<runtime::Error>,
    cleanup: Option<Protocol>,
    retire: Option<Token<'id>>,
}
impl<const N: usize> Observer<'_, '_, '_, '_, '_, '_, N> {
    /// Consume this synchronous observation before another native operation.
    /// All poll entrances use the same original-parent retirement and error
    /// precedence; no observer borrow, task or receipt survives this handoff.
    fn finish(
        self,
        server: &mut Server,
        result: Poll<Result<gnunet_transport_host::Step, Protocol>>,
    ) -> Poll<Result<gnunet_transport_host::Step, Error>> {
        if let Some(token) = self.retire {
            return Poll::Ready(
                self.bridge
                    .cancel_parent(server, self.actor, token)
                    .map(|()| gnunet_transport_host::Step::Progress),
            );
        }
        finish_observation(result, self.failure, self.cleanup)
    }
}
fn finish_observation<T>(
    result: Poll<Result<T, Protocol>>,
    actor_failure: Option<runtime::Error>,
    cleanup: Option<Protocol>,
) -> Poll<Result<T, Error>> {
    if let Some(cause) = actor_failure {
        return Poll::Ready(Err(Error {
            cause: Cause::Actor(cause),
            cleanup: cleanup.map(Cause::Protocol),
        }));
    }
    // Native protocol failures can also trigger a failed physical close. Keep
    // that independent result even when no Actor error supplied a proxy cause.
    result.map(|r| {
        r.map_err(|cause| Error {
            cause: Cause::Protocol(cause),
            cleanup: cleanup.map(Cause::Protocol),
        })
    })
}
impl<const N: usize> native::NativeObserver for Observer<'_, '_, '_, '_, '_, '_, N> {
    fn links(
        &mut self,
        original: &gnunet_transport::Engine,
        selector: PeerId,
    ) -> Result<gnunet_transport::monitor::Links, Protocol> {
        if !self.bridge.active
            || self.bridge.closing
            || original.dv_current_source() != Some(&self.bridge.source)
            || !original.dv_source_accepting()
        {
            return Err(Protocol::StaleGeneration);
        }
        self.bridge.targets.clear();
        for target in self.actor.route_targets() {
            if selector.0 != [0; 32] && selector != target {
                continue;
            }
            if self.bridge.targets.contains(&target) {
                continue;
            }
            if self.bridge.targets.len() >= self.bridge.limits.paths
                || self.bridge.targets.len() >= original.monitor_link_limit()
            {
                return Err(Protocol::Capacity);
            }
            self.bridge.targets.push(target);
        }
        let mut rows = Vec::new();
        rows.try_reserve_exact(self.bridge.targets.len())
            .map_err(|_| Protocol::Capacity)?;
        for target in &self.bridge.targets {
            let route = match self.actor.route(*target, false) {
                Ok(Some(route)) if route.path.len() >= 2 => (
                    route.id,
                    route.path[0],
                    u32::try_from(route.path.len() - 2).map_err(|_| Protocol::Overflow)?,
                ),
                Ok(_) => continue,
                Err(e) => {
                    self.failure.get_or_insert(e);
                    return Err(Protocol::Io);
                }
            };
            let life = match self.actor.route_life(*target, false) {
                Ok(Some(life)) if life.route == route.0 && Instant::now() < life.hard => life,
                Ok(_) => continue,
                Err(e) => {
                    self.failure.get_or_insert(e);
                    return Err(Protocol::Io);
                }
            };
            rows.push(gnunet_transport::monitor::DvLink {
                target: *target,
                first_hop: route.1,
                distance: route.2,
                confirmed: self.bridge.paths.iter().any(|p| {
                    p.target == *target
                        && p.route == route.0
                        && p.hard == life.hard
                        && Instant::now() < p.hard
                }),
            });
        }
        Ok(gnunet_transport::monitor::Links {
            source: Some(self.bridge.source.clone()),
            rows,
        })
    }

    fn ready(
        &mut self,
        parent: &engine::TransferId,
        original: &gnunet_transport::Engine,
    ) -> Result<native::NativeAdmission, Protocol> {
        let Some(i) = self.bridge.sends.iter().position(|s| &s.native == parent) else {
            return Err(Protocol::Stale);
        };
        let r = &self.bridge.sends[i];
        if !r.actor_finished {
            match self.bridge.parent_retired(original, self.actor, r.actor) {
                Ok(true) => {
                    self.retire = Some(r.actor);
                    return Ok(native::NativeAdmission::Retiring);
                }
                Ok(false) => {}
                Err(e) => {
                    if let Cause::Actor(cause) = e.cause {
                        self.failure.get_or_insert(cause);
                    }
                    return Err(Protocol::Stale);
                }
            }
        }
        if !self.bridge.active || self.bridge.closing {
            return Err(Protocol::Deadline);
        }
        if Instant::now() >= r.budget.hard {
            if !r.actor_finished {
                self.retire = Some(r.actor);
                return Ok(native::NativeAdmission::Retiring);
            }
            return Err(Protocol::Deadline);
        }
        if let Err(e) = self.actor.check_budget(r.budget) {
            if matches!(&e, runtime::Error::TaskBudgetExpired) && !r.actor_finished {
                self.retire = Some(r.actor);
                return Ok(native::NativeAdmission::Retiring);
            }
            self.failure.get_or_insert(e);
            return Err(Protocol::Io);
        }
        if r.actor_finished || r.written {
            return Ok(native::NativeAdmission::Admit);
        }
        if let Err(e) = self.actor.output(r.actor) {
            if matches!(&e, runtime::Error::TaskBudgetExpired) {
                self.retire = Some(r.actor);
                return Ok(native::NativeAdmission::Retiring);
            }
            self.failure.get_or_insert(e);
            return Err(Protocol::Io);
        }
        Ok(native::NativeAdmission::Admit)
    }
    fn queued(&mut self, parent: &engine::TransferId) -> Result<(), Protocol> {
        let Some(i) = self.bridge.sends.iter().position(|s| &s.native == parent) else {
            return Err(Protocol::Stale);
        };
        if self.bridge.sends[i].queued || self.bridge.sends[i].actor_finished {
            return Ok(());
        }
        if let Err(e) = self.actor.queued(self.bridge.sends[i].actor) {
            self.failure.get_or_insert(e);
            return Err(Protocol::Io);
        }
        self.bridge.sends[i].queued = true;
        Ok(())
    }
    fn exposed(&mut self, parent: &engine::TransferId, bytes: usize) -> Result<(), Protocol> {
        if bytes == 0 {
            return Err(Protocol::InvalidInput);
        }
        let Some(i) = self.bridge.sends.iter().position(|s| &s.native == parent) else {
            return Err(Protocol::Stale);
        };
        if self.bridge.sends[i].exposed
            || self.bridge.sends[i].actor_finished
            || self.bridge.sends[i].written
        {
            return Ok(());
        }
        if !self.bridge.sends[i].queued {
            return Err(Protocol::Conflict);
        }
        if let Err(e) = self.actor.exposed(self.bridge.sends[i].actor) {
            self.failure.get_or_insert(e);
            return Err(Protocol::Io);
        }
        self.bridge.sends[i].exposed = true;
        Ok(())
    }
    fn cleanup(&mut self, error: Protocol) {
        self.cleanup.get_or_insert(error);
    }
}
impl Bridge<'_> {
    /// Register and enforce original inbox native deadlines before any actual
    /// canonical sample. An already-expired blocked ACK waits on real output IO,
    /// not an immediately-ready expired sleep busy loop.
    pub fn poll_guard(&mut self, server: &mut Server, cx: &mut Context<'_>) -> Result<bool, Error> {
        let Some(until) = server.dv_inbox_deadline() else {
            self.alarm = None;
            return Ok(false);
        };
        let due = self
            .native_epoch
            .checked_add(std::time::Duration::from_micros(until.0))
            .ok_or(Protocol::Overflow)?;
        let now = Instant::now();
        if now >= due {
            self.alarm = None;
            let elapsed = now
                .checked_duration_since(self.native_epoch)
                .ok_or(Protocol::TimeUncertain)?;
            let through = gnunet_types::MonoInstant(
                u64::try_from(elapsed.as_micros()).map_err(|_| Protocol::Overflow)?,
            );
            return match server.dv_expire_inbox_native(&self.source, through) {
                Ok(progress) => Ok(progress),
                Err(Protocol::Capacity | Protocol::WouldBlock) => Ok(false),
                Err(e) => Err(e.into()),
            };
        }
        let alarm = self
            .alarm
            .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(due)));
        alarm.as_mut().reset(due);
        if alarm.as_mut().poll(cx).is_ready() {
            cx.waker().wake_by_ref();
        }
        Ok(false)
    }
    /// Same parent/path/source is still locally eligible. This is not a new
    /// route or durability fact; actual Actor rechecks exact original route.
    pub fn intent_live(&self, server: &Server, intent: &VirtualIntent<'_>) -> bool {
        self.active
            && !self.closing
            && Instant::now() < intent.budget.hard
            && !server.dv_virtual_canceled(&intent.id)
            && self.paths.iter().any(|p| p.id == intent.path)
    }
    /// A common direct Job already owns this actual Actor immutable output.
    /// Does not claim that native queue admission or write has happened.
    pub fn output_staged(&self, token: Token<'_>) -> bool {
        self.sends.iter().any(|r| r.actor == token)
    }
}
impl Bridge<'_> {
    /// Clock-free cleanup of original unadmitted complete/held DV inputs. The
    /// same original physical source is closed before dropping any FC metadata.
    pub fn discard_inbox(&mut self, server: &mut Server) -> Result<bool, Error> {
        if !self.closing {
            return Err(Protocol::NotReady.into());
        }
        Ok(server.dv_discard_unadmitted_source(&self.source)?)
    }
    /// Clock-free cleanup of every never-admitted original staging identity of
    /// the retiring source; does not need synthetic Times after clock failure.
    pub fn drain_unadmitted(&mut self, server: &mut Server) -> Result<bool, Error> {
        if !self.closing {
            return Err(Protocol::NotReady.into());
        }
        let mut progress = server.dv_discard_unadmitted_source(&self.source)?;
        progress |= server.dv_discard_virtual_source(&self.source)?;
        Ok(progress)
    }
}

#[cfg(test)]
mod observer_tests {
    use super::*;

    #[test]
    fn native_primary_retains_independent_physical_cleanup() {
        let actual =
            finish_observation::<()>(Poll::Ready(Err(Protocol::Stale)), None, Some(Protocol::Io));
        assert!(matches!(
            actual,
            Poll::Ready(Err(Error {
                cause: Cause::Protocol(Protocol::Stale),
                cleanup: Some(Cause::Protocol(Protocol::Io)),
            }))
        ));
    }

    #[test]
    fn actor_failure_keeps_precedence_over_native_proxy_error() {
        let actual = finish_observation::<()>(
            Poll::Ready(Err(Protocol::Io)),
            Some(runtime::Error::TaskBudgetExpired),
            Some(Protocol::Capacity),
        );
        assert!(matches!(
            actual,
            Poll::Ready(Err(Error {
                cause: Cause::Actor(runtime::Error::TaskBudgetExpired),
                cleanup: Some(Cause::Protocol(Protocol::Capacity)),
            }))
        ));
    }
}
