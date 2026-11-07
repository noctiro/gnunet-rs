//! Real persistent control owner; completion authority remains in the core.
use crate::{
    Clock, HostError, Limits, Progress,
    endpoint::Source,
    launch::LocalLauncher,
    mq::{Mq, Physical, Pulse, Tx, Wake},
    process::readiness::RegisteredReadiness,
};
use gnunet_arm_core::{
    ConnectionEpoch,
    client::{
        Client, ConnectionStatus, Effect, Inbound, OperationId, RetirementEffect, StartupResult,
        StdioInheritance,
    },
};
use gnunet_config::Configuration;
use gnunet_types::Error;
use std::{
    future::{Future, poll_fn},
    io,
    path::PathBuf,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::time::{Instant, Sleep};
struct SignalSlot {
    operation: OperationId,
    reader: Option<RegisteredReadiness>,
    notified: bool,
}
fn close_signals(signals: &mut [SignalSlot]) {
    for slot in signals {
        slot.reader = None;
    }
}
fn size(limits: Limits, name: Option<&[u8]>, local_start: bool) -> Result<(), HostError> {
    let n = if let Some(name) = name {
        let n = name.iter().position(|b| *b == 0).unwrap_or(name.len());
        if local_start && name[..n].eq_ignore_ascii_case(b"arm") {
            return Ok(());
        }
        16usize
            .checked_add(n)
            .and_then(|n| n.checked_add(1))
            .ok_or(Error::Overflow)?
    } else {
        16
    };
    if n > limits.max_frame_bytes {
        Err(Error::Capacity.into())
    } else {
        Ok(())
    }
}
/// Restricted synchronous callback port. Borrowed list bytes cannot escape the
/// callback. Disconnect closes physical I/O now; remaining failure callbacks drain
/// after the current callback returns, without re-entering user code recursively.
pub struct CallbackContext<'h, 'a> {
    core: &'h mut Client<'a>,
    physical: &'h mut Physical,
    tx: &'h mut Tx,
    signals: &'h mut [SignalSlot],
    limits: Limits,
    clock: &'h Clock,
}
impl CallbackContext<'_, '_> {
    /// Queue a real official LIST without fabricated completion.
    pub fn request_service_list(&mut self) -> Result<OperationId, HostError> {
        size(self.limits, None, false)?;
        Ok(self.core.request_service_list()?)
    }
    /// Queue remote START or local ARM setup, driven by the owning reactor.
    pub fn request_service_start(
        &mut self,
        name: &[u8],
        stdio: StdioInheritance,
    ) -> Result<OperationId, HostError> {
        size(self.limits, Some(name), true)?;
        Ok(self
            .core
            .request_service_start(name, stdio, self.clock.now()?)?)
    }
    /// Queue official STOP, retaining ARM's exact STOPPING/EOF distinction.
    pub fn request_service_stop(&mut self, name: &[u8]) -> Result<OperationId, HostError> {
        size(self.limits, Some(name), false)?;
        Ok(self.core.request_service_stop(name)?)
    }
    /// Suppress only this operation's callback; queued frames still execute.
    pub fn operation_cancel(&mut self, id: OperationId) -> Result<(), HostError> {
        self.core.operation_cancel(id)?;
        for slot in &mut *self.signals {
            if slot.operation == id {
                slot.reader = None;
            }
        }
        Ok(())
    }
    /// Close original MQ/signal owners immediately. No child is signalled.
    pub fn disconnect(&mut self) {
        let _original = self.core.disconnect();
        self.physical.retire();
        self.tx.clear();
        close_signals(self.signals);
    }
    /// Original callback authority, independent of already queued wire frames.
    pub fn owns_operation(&self, id: OperationId) -> bool {
        self.core.owns_operation(id)
    }
}
#[expect(
    clippy::too_many_arguments,
    reason = "The callback borrows separate original core, stream, TX and signal owners while RX bytes remain immutably borrowed"
)]
fn dispatch<'b, 'a>(
    core: &mut Client<'a>,
    physical: &mut Physical,
    tx: &mut Tx,
    signals: &mut [SignalSlot],
    limits: Limits,
    clock: &Clock,
    event: Inbound<'b>,
    callback: &mut impl FnMut(Inbound<'_>, &mut CallbackContext<'_, 'a>),
) {
    callback(
        event,
        &mut CallbackContext {
            core,
            physical,
            tx,
            signals,
            limits,
            clock,
        },
    );
}
/// Caller-owned control connection with persistent actual RX/TX/startup resources.
/// Its bounded core borrows the caller's original backing; no self-reference or
/// allocation-dependent address stability is required for this host value.
pub struct ClientHost<'a, 'registry> {
    core: Client<'a>,
    source: Source,
    mq: Mq,
    signals: Vec<SignalSlot>,
    launcher: LocalLauncher<'registry>,
    limits: Limits,
    clock: Clock,
    wake: Wake,
    last_io_error: Option<io::Error>,
    pending_start: Option<(OperationId, StartupResult, bool)>,
}
impl<'a, 'registry> ClientHost<'a, 'registry> {
    /// Validate/admit a real logical MQ synchronously, before callers queue work.
    /// Initial configuration failure invokes exactly Error and returns Err. No
    /// socket is yet connected and TEST alone will establish currently_up.
    pub fn connect(
        core: Client<'a>,
        config: Configuration,
        resolution: gnunet_client_host::resolution::SharedResolution,
        mut launcher: LocalLauncher<'registry>,
        limits: Limits,
        clock: Clock,
        initial_failure: impl FnOnce(ConnectionStatus),
    ) -> Result<Self, HostError> {
        launcher.configure(config.duplicate()?)?;
        Self::construct(
            core,
            Source::Configuration {
                config: Box::new(config),
                resolution,
                service: b"arm",
            },
            launcher,
            limits,
            clock,
            initial_failure,
        )
    }
    /// Create a logical MQ from a caller-shared live service configuration.
    /// TCP fields are cached per MQ; later Unix attempts and new MQ construction
    /// sample the live store at their distinct native read points. Resolver
    /// configuration is an explicit independently selected context. Replacing a
    /// store does not replace current attempts/streams or pending operation IDs.
    pub fn connect_live(
        core: Client<'a>,
        config: crate::LiveConfiguration,
        resolution: gnunet_client_host::resolution::SharedResolution,
        mut launcher: LocalLauncher<'registry>,
        limits: Limits,
        clock: Clock,
        initial_failure: impl FnOnce(ConnectionStatus),
    ) -> Result<Self, HostError> {
        launcher.configure(config.snapshot()?)?;
        Self::construct(
            core,
            Source::Live {
                config,
                resolution,
                service: b"arm",
            },
            launcher,
            limits,
            clock,
            initial_failure,
        )
    }

    /// Direct official Unix endpoint convenience for an isolated local embedding.
    /// Local ARM startup still uses the explicitly supplied launcher's config.
    pub fn connect_unix(
        core: Client<'a>,
        path: PathBuf,
        launcher: LocalLauncher<'registry>,
        limits: Limits,
        clock: Clock,
        initial_failure: impl FnOnce(ConnectionStatus),
    ) -> Result<Self, HostError> {
        Self::construct(
            core,
            Source::Unix(path),
            launcher,
            limits,
            clock,
            initial_failure,
        )
    }
    fn construct(
        mut core: Client<'a>,
        source: Source,
        mut launcher: LocalLauncher<'registry>,
        limits: Limits,
        clock: Clock,
        initial_failure: impl FnOnce(ConnectionStatus),
    ) -> Result<Self, HostError> {
        limits.validate()?;
        let mut signals = Vec::new();
        signals
            .try_reserve_exact(limits.max_startup_signals)
            .map_err(|_| Error::Capacity)?;
        let mut mq = Mq::new(limits)?;
        let Some(Effect::Connect(epoch)) = core.take_effect(clock.now()?)? else {
            return Err(Error::InvalidInput.into());
        };
        let endpoint = match source.resolve() {
            Ok(endpoint) => endpoint,
            Err(e) => {
                core.connection_unavailable(epoch)?;
                initial_failure(ConnectionStatus::Error);
                return Err(e.into());
            }
        };
        core.connection_admitted(epoch)?;
        launcher.prepare_if_runtime()?;
        mq.physical.admit(epoch, endpoint);
        Ok(Self {
            core,
            source,
            mq,
            signals,
            launcher,
            limits,
            clock,
            wake: Wake::new(),
            last_io_error: None,
            pending_start: None,
        })
    }
    /// Queue official LIST; no operation deadline is invented.
    pub fn request_service_list(&mut self) -> Result<OperationId, HostError> {
        size(self.limits, None, false)?;
        Ok(self.core.request_service_list()?)
    }
    /// Admit remote START or local ARM startup. Local OS effects execute on drive;
    /// callers retain an OperationId to cancel/suppress its callback safely.
    pub fn request_service_start(
        &mut self,
        name: &[u8],
        stdio: StdioInheritance,
    ) -> Result<OperationId, HostError> {
        size(self.limits, Some(name), true)?;
        Ok(self
            .core
            .request_service_start(name, stdio, self.clock.now()?)?)
    }
    /// Admit remote STOP. Stopped is never inferred from EOF without the core's
    /// prior actual STOPPING result for that original ARM-stop operation.
    pub fn request_service_stop(&mut self, name: &[u8]) -> Result<OperationId, HostError> {
        size(self.limits, Some(name), false)?;
        Ok(self.core.request_service_stop(name)?)
    }
    /// Suppress callback authority and synchronously close its original signal
    /// read end. Already queued remote messages are deliberately not removed.
    pub fn operation_cancel(&mut self, id: OperationId) -> Result<(), HostError> {
        self.core.operation_cancel(id)?;
        for slot in &mut self.signals {
            if slot.operation == id {
                slot.reader = None;
            }
        }
        Ok(())
    }
    /// Whether original callback authority remains, including across drive cancel.
    pub fn owns_operation(&self, id: OperationId) -> bool {
        self.core.owns_operation(id)
    }
    /// True only after actual TEST confirmation, not MQ/socket/helper creation.
    pub fn currently_up(&self) -> bool {
        self.core.currently_up()
    }
    /// Original logical MQ; socket attempt changes do not replace its epoch.
    pub fn connection_epoch(&self) -> Option<ConnectionEpoch> {
        self.mq.physical.epoch
    }
    /// Take actual last physical socket error without reclassifying it as a
    /// configuration failure or successful operation result.
    pub fn take_io_error(&mut self) -> Option<io::Error> {
        self.last_io_error.take()
    }
    /// Explicit child-registry ownership. Cancel/disconnect never kills children;
    /// retain this host and drain/reap created children separately when desired.
    pub fn launcher_mut(&mut self) -> &mut LocalLauncher<'registry> {
        &mut self.launcher
    }
    fn callbacks(
        &mut self,
        callback: &mut impl FnMut(Inbound<'_>, &mut CallbackContext<'_, 'a>),
    ) -> bool {
        let mut any = false;
        while let Some(event) = self.core.next_event() {
            any = true;
            dispatch(
                &mut self.core,
                &mut self.mq.physical,
                &mut self.mq.tx,
                &mut self.signals,
                self.limits,
                &self.clock,
                Inbound::Event(event),
                callback,
            );
        }
        if self.core.is_closed() && self.signals.is_empty() && self.pending_start.is_none() {
            self.clock.retire();
        }
        any
    }
    fn acknowledge_closed(&mut self, id: OperationId) -> Result<(), HostError> {
        let index = self
            .signals
            .iter()
            .position(|s| s.operation == id)
            .ok_or(Error::StaleGeneration)?;
        self.signals[index].reader = None;
        self.core.startup_signal_closed(id)?;
        self.signals.swap_remove(index);
        Ok(())
    }
    fn effect(&mut self) -> Result<bool, HostError> {
        let now = self.clock.now()?;
        if let Some((id, result, has_pipe)) = self.pending_start {
            self.core.startup_report(id, result, has_pipe, now)?;
            self.pending_start = None;
            return Ok(true);
        }
        let available = self.signals.len() < self.limits.max_startup_signals
            && self.launcher.child_capacity_available();
        let Some(effect) = self
            .core
            .take_effect_with_startup_capacity(now, available)?
        else {
            return Ok(false);
        };
        match effect {
            Effect::CloseStartupSignal { operation } => self.acknowledge_closed(operation)?,
            Effect::Connect(epoch) => match self.source.resolve() {
                Ok(endpoint) => {
                    self.core.connection_admitted(epoch)?;
                    self.mq.retire();
                    self.mq.physical.admit(epoch, endpoint);
                }
                Err(error) => {
                    self.core.connection_unavailable(epoch)?;
                    return Err(error.into());
                }
            },
            Effect::StartArm { operation, stdio } => {
                // Cancellation before any actual host setup must not spawn a new
                // child. Report no returned resource; canceled callback is absent.
                if !self.core.owns_operation(operation) {
                    self.core
                        .startup_report(operation, StartupResult::Failed, false, now)?;
                    return Ok(true);
                }
                // A leased start retains its previously admitted resource credit.
                // No await or other start can consume it before this report.
                if self.signals.len() == self.limits.max_startup_signals {
                    return Err(Error::Capacity.into());
                }
                // Sample only when this original local effect begins. A pending
                // actual spawn result retains its child and is never replayed.
                if let Some(configuration) = self.source.launch_configuration()? {
                    self.launcher.configure(configuration)?;
                }
                let started = self.launcher.start(stdio)?;
                let has_pipe = started.signal.is_some();
                if has_pipe {
                    self.signals.push(SignalSlot {
                        operation,
                        reader: started.signal,
                        notified: false,
                    });
                }
                // Store the real outcome before reporting; a core refusal/canceled
                // drive can retry this report without running a second child.
                self.pending_start = Some((operation, started.result, has_pipe));
                self.core
                    .startup_report(operation, started.result, has_pipe, self.clock.now()?)?;
                self.pending_start = None;
            }
        }
        Ok(true)
    }
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
        wait: &mut Option<Pin<Box<Sleep>>>,
        callback: &mut impl FnMut(Inbound<'_>, &mut CallbackContext<'_, 'a>),
    ) -> Poll<Result<Progress, HostError>> {
        // Explicit disconnect/callback cancellation retirement must precede
        // every fresh clock read, including after a previous clock failure.
        if self.core.is_disconnecting() {
            return Poll::Ready(self.drain_retirement(callback).map(|()| Progress::Closed));
        }
        // Fully retired owners need no source sampling, waiter or fresh OS work.
        // is_closed includes all original immediate callbacks/resources.
        if self.core.is_closed() && self.signals.is_empty() && self.pending_start.is_none() {
            self.mq.retire();
            self.clock.retire();
            return Poll::Ready(Ok(Progress::Closed));
        }
        if wait
            .as_mut()
            .is_some_and(|s| s.as_mut().poll(cx).is_ready())
        {
            return Poll::Ready(Ok(Progress::WaitDeadline));
        }
        let now = match self.clock.now() {
            Ok(now) => now,
            Err(e) => return Poll::Ready(Err(e)),
        };
        match self.launcher.reap_completed() {
            Ok(n) if n > 0 => return Poll::Ready(Ok(Progress::Activity)),
            Ok(_) => {}
            Err(e) => return Poll::Ready(Err(e.into())),
        }
        if let Err(e) = self.core.tick(now) {
            return Poll::Ready(Err(e.into()));
        }
        if self.callbacks(callback) {
            return Poll::Ready(Ok(Progress::Activity));
        }
        match self.effect() {
            Ok(true) => {
                self.callbacks(callback);
                return Poll::Ready(Ok(Progress::Activity));
            }
            Err(e) => {
                self.callbacks(callback);
                return Poll::Ready(Err(e));
            }
            Ok(false) => {}
        }
        if self.core.is_closed() && self.signals.is_empty() {
            self.mq.retire();
            self.clock.retire();
            return Poll::Ready(Ok(Progress::Closed));
        }
        for slot in &mut self.signals {
            if !slot.notified
                && let Some(reader) = &slot.reader
            {
                match reader.poll_ready(cx) {
                    Poll::Ready(Ok(_readiness)) => {
                        slot.notified = true;
                        if let Err(e) = self.core.startup_signal_ready(slot.operation) {
                            return Poll::Ready(Err(e.into()));
                        }
                        self.callbacks(callback);
                        return Poll::Ready(Ok(Progress::Activity));
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                    Poll::Pending => {}
                }
            }
        }
        if self.mq.physical.epoch.is_some() && self.mq.tx.ticket.is_none() {
            match self.core.take_frame() {
                Ok(ticket) => {
                    self.mq.tx.ticket = ticket;
                    self.mq.tx.written = 0;
                }
                Err(e) => return Poll::Ready(Err(e.into())),
            }
        }
        let frame = if let Some(ticket) = self.mq.tx.ticket {
            match self.core.frame(ticket) {
                Ok(f) => Some(f),
                Err(e) => return Poll::Ready(Err(e.into())),
            }
        } else {
            None
        };
        match self.mq.poll(cx, frame, &mut self.clock) {
            Poll::Ready(Pulse::Boundary(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Pulse::Connected | Pulse::Io) => {
                return Poll::Ready(Ok(Progress::Activity));
            }
            Poll::Ready(Pulse::ConnectRetry(e)) => {
                self.last_io_error = Some(e);
                return Poll::Ready(Ok(Progress::Activity));
            }
            Poll::Ready(Pulse::Written(ticket)) => {
                if let Err(e) = self.core.frame_written(ticket) {
                    return Poll::Ready(Err(e.into()));
                }
                self.mq.tx.clear();
                return Poll::Ready(Ok(Progress::Activity));
            }
            Poll::Ready(Pulse::Lost(e)) => {
                let Some(epoch) = self.mq.physical.epoch else {
                    return Poll::Ready(Err(Error::StaleGeneration.into()));
                };
                self.last_io_error = Some(e);
                self.mq.retire();
                if let Err(e) = self.core.connection_lost(epoch, now) {
                    return Poll::Ready(Err(e.into()));
                }
                self.callbacks(callback);
                return Poll::Ready(Ok(Progress::Activity));
            }
            Poll::Ready(Pulse::Received) => {
                let Some(epoch) = self.mq.physical.epoch else {
                    return Poll::Ready(Err(Error::StaleGeneration.into()));
                };
                let parsed = self.core.receive(epoch, self.mq.rx.frame(), now);
                match parsed {
                    Ok(Some(inbound)) => dispatch(
                        &mut self.core,
                        &mut self.mq.physical,
                        &mut self.mq.tx,
                        &mut self.signals,
                        self.limits,
                        &self.clock,
                        inbound,
                        callback,
                    ),
                    Ok(None) => {}
                    Err(_) => {
                        self.mq.physical.retire();
                        self.mq.tx.clear();
                    }
                }
                self.mq.rx.clear();
                self.callbacks(callback);
                return Poll::Ready(Ok(Progress::Activity));
            }
            Poll::Pending => {}
        }
        match self.launcher.poll_child_signal(cx) {
            Poll::Ready(Ok(())) => return Poll::Ready(Ok(Progress::Activity)),
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
            Poll::Pending => {}
        }
        match self.wake.poll(cx, &mut self.clock, self.core.next_wakeup()) {
            Ok(Poll::Ready(())) => cx.waker().wake_by_ref(),
            Err(e) => return Poll::Ready(Err(e)),
            _ => {}
        }
        Poll::Pending
    }
    /// Drive one genuine progress step. Dropping this future preserves original
    /// partial RX/TX, connect attempt, startup read ends and all absolute timers.
    ///
    /// RX-backed list values cannot escape an invocation:
    /// ```compile_fail
    /// # use gnunet_arm_host::ClientHost;
    /// # use gnunet_arm_core::client::Inbound;
    /// async fn cannot_keep_rx(host: &mut ClientHost<'_, '_>) {
    ///     let mut retained = None;
    ///     let _ = host.drive(None, |event, _| {
    ///         if let Inbound::List { list, .. } = event { retained = Some(list); }
    ///     }).await;
    ///     drop(retained);
    /// }
    /// ```
    /// Copying the required values during the callback is valid:
    /// ```
    /// # use gnunet_arm_host::ClientHost;
    /// # use gnunet_arm_core::client::Inbound;
    /// async fn keep_owned(host: &mut ClientHost<'_, '_>) {
    ///     let mut retained = Vec::new();
    ///     let _ = host.drive(None, |event, _| {
    ///         if let Inbound::List { list, .. } = event {
    ///             if let Ok(Some(row)) = list.get(0) { retained.push(row.name.to_vec()); }
    ///         }
    ///     }).await;
    ///     drop(retained);
    /// }
    /// ```
    pub async fn drive(
        &mut self,
        wait_until: Option<Instant>,
        mut callback: impl FnMut(Inbound<'_>, &mut CallbackContext<'_, 'a>),
    ) -> Result<Progress, HostError> {
        let mut wait = wait_until.map(|at| Box::pin(tokio::time::sleep_until(at)));
        poll_fn(|cx| self.poll(cx, &mut wait, &mut callback)).await
    }
    fn drain_retirement(
        &mut self,
        callback: &mut impl FnMut(Inbound<'_>, &mut CallbackContext<'_, 'a>),
    ) -> Result<(), HostError> {
        self.mq.retire();
        self.clock.retire();
        close_signals(&mut self.signals);
        // Copy until the core accepts the exact original report. A refusal must
        // not discard real startup/pipe metadata or authorize another launch.
        if let Some((id, result, has_pipe)) = self.pending_start {
            self.core.retire_startup(id, result, has_pipe)?;
            self.pending_start = None;
        }
        loop {
            self.callbacks(callback);
            match self.core.take_retirement_effect()? {
                Some(RetirementEffect::CloseStartupSignal { operation }) => {
                    self.acknowledge_closed(operation)?
                }
                Some(RetirementEffect::ReportStartup { operation }) => {
                    // No host outcome was retained: this original lease was
                    // not performed. Closing must never execute its command.
                    self.core
                        .retire_startup(operation, StartupResult::Failed, false)?;
                }
                None => break,
            }
        }
        if self.core.is_closed() && self.signals.is_empty() && self.pending_start.is_none() {
            Ok(())
        } else {
            Err(Error::NotReady.into())
        }
    }
    /// Explicitly close physical I/O now and synchronously drain failure callbacks
    /// plus original signal-close obligations without a fresh clock sample.
    /// It never waits/kills any child or starts another command/connection.
    pub fn disconnect(
        &mut self,
        mut callback: impl FnMut(Inbound<'_>, &mut CallbackContext<'_, 'a>),
    ) -> Result<(), HostError> {
        let _original = self.core.disconnect();
        self.drain_retirement(&mut callback)
    }
}
