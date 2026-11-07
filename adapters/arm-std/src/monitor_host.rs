//! Independent actual MONITOR connection with original callback/retry semantics.
use crate::{
    Clock, HostError, Limits, Progress,
    endpoint::Source,
    mq::{Mq, Physical, Pulse, Tx, Wake},
};
use gnunet_arm_core::{
    monitor::{Monitor, Unavailable},
    wire::Status,
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
/// Original public monitor callback observation; Unavailable corresponds exactly
/// to C service=NULL/statusSTOPPED, not an invented named service notification.
#[derive(Clone, Copy, Debug)]
pub enum MonitorEvent<'a> {
    /// Actual checked STATUS bytes, borrowed only during this callback.
    Status(Status<'a>),
    /// Actual logical MQ configuration/creation failure.
    Unavailable(Unavailable),
}
/// Safe synchronous monitor callback control. Stop closes its physical MQ now;
/// borrowed status bytes remain alive until the callback returns.
pub struct MonitorContext<'h, 'a> {
    core: &'h mut Monitor<'a>,
    physical: &'h mut Physical,
    tx: &'h mut Tx,
}
impl MonitorContext<'_, '_> {
    /// Stop and immediately close only this monitor's original physical resources.
    pub fn stop(&mut self) {
        let _original = self.core.stop();
        self.physical.retire();
        self.tx.clear();
    }
}
/// Persistent native monitor owner. No initial snapshot or unused5s timeout is
/// added, and receiving a status does not reset the core's escalating retry.
pub struct MonitorHost<'a> {
    core: Monitor<'a>,
    source: Source,
    mq: Mq,
    clock: Clock,
    wake: Wake,
    last_io_error: Option<io::Error>,
    last_endpoint_error: Option<crate::IpcError>,
}
impl<'a> MonitorHost<'a> {
    /// Synchronously validate/admit its MQ and queue MONITOR. A genuine initial
    /// configuration failure invokes initial_failure once and returns Err.
    pub fn start(
        core: Monitor<'a>,
        config: Configuration,
        resolution: gnunet_client_host::resolution::SharedResolution,
        limits: Limits,
        clock: Clock,
        initial_failure: impl FnOnce(Unavailable),
    ) -> Result<Self, HostError> {
        Self::construct(
            core,
            Source::Configuration {
                config: Box::new(config),
                resolution,
                service: b"arm",
            },
            limits,
            clock,
            initial_failure,
        )
    }
    /// Start from explicit live service/resolver configurations. Changes only
    /// affect later native read points, never the current stream/attempt. A new
    /// MQ's actual configuration failure emits Unavailable once without retry.
    pub fn start_live(
        core: Monitor<'a>,
        config: crate::LiveConfiguration,
        resolution: gnunet_client_host::resolution::SharedResolution,
        limits: Limits,
        clock: Clock,
        initial_failure: impl FnOnce(Unavailable),
    ) -> Result<Self, HostError> {
        Self::construct(
            core,
            Source::Live {
                config,
                resolution,
                service: b"arm",
            },
            limits,
            clock,
            initial_failure,
        )
    }

    /// Explicit official Unix endpoint convenience for an isolated embedding.
    pub fn start_unix(
        core: Monitor<'a>,
        path: PathBuf,
        limits: Limits,
        clock: Clock,
        initial_failure: impl FnOnce(Unavailable),
    ) -> Result<Self, HostError> {
        Self::construct(core, Source::Unix(path), limits, clock, initial_failure)
    }
    fn construct(
        mut core: Monitor<'a>,
        source: Source,
        limits: Limits,
        clock: Clock,
        initial_failure: impl FnOnce(Unavailable),
    ) -> Result<Self, HostError> {
        limits.validate()?;
        let mut mq = Mq::new(limits)?;
        let epoch = core
            .take_connect(clock.now()?)?
            .ok_or(Error::InvalidInput)?;
        let endpoint = match source.resolve() {
            Ok(endpoint) => endpoint,
            Err(e) => {
                initial_failure(core.connection_unavailable(epoch)?);
                return Err(e.into());
            }
        };
        core.connection_admitted(epoch)?;
        mq.physical.admit(epoch, endpoint);
        Ok(Self {
            core,
            source,
            mq,
            clock,
            wake: Wake::new(),
            last_io_error: None,
            last_endpoint_error: None,
        })
    }
    /// Immediately close this monitor, cancel retries and invalidate stale input.
    pub fn stop(&mut self) {
        let _original = self.core.stop();
        self.mq.retire();
        self.clock.retire();
    }
    /// Detailed last actual socket error, not a fabricated service-status callback.
    pub fn take_io_error(&mut self) -> Option<io::Error> {
        self.last_io_error.take()
    }
    /// Detailed actual retry-time MQ configuration error. Its unavailable event
    /// is delivered once and no new automatic retry is fabricated.
    pub fn take_endpoint_error(&mut self) -> Option<crate::IpcError> {
        self.last_endpoint_error.take()
    }
    /// Whether this monitor has been permanently stopped.
    pub fn is_closed(&self) -> bool {
        self.core.is_closed()
    }
    /// Current logical owner backoff in microseconds; status does not reset it.
    pub fn retry_backoff(&self) -> u64 {
        self.core.retry_backoff()
    }
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
        wait: &mut Option<Pin<Box<Sleep>>>,
        callback: &mut impl FnMut(MonitorEvent<'_>, &mut MonitorContext<'_, 'a>),
    ) -> Poll<Result<Progress, HostError>> {
        if wait
            .as_mut()
            .is_some_and(|s| s.as_mut().poll(cx).is_ready())
        {
            return Poll::Ready(Ok(Progress::WaitDeadline));
        }
        if self.core.is_closed() {
            self.mq.retire();
            self.clock.retire();
            return Poll::Ready(Ok(Progress::Closed));
        }
        let now = match self.clock.now() {
            Ok(now) => now,
            Err(e) => return Poll::Ready(Err(e)),
        };
        match self.core.take_connect(now) {
            Ok(Some(epoch)) => {
                match self.source.resolve() {
                    Ok(endpoint) => {
                        if let Err(e) = self.core.connection_admitted(epoch) {
                            return Poll::Ready(Err(e.into()));
                        }
                        self.mq.retire();
                        self.mq.physical.admit(epoch, endpoint);
                    }
                    Err(e) => {
                        let event = match self.core.connection_unavailable(epoch) {
                            Ok(event) => event,
                            Err(e) => return Poll::Ready(Err(e.into())),
                        };
                        self.last_endpoint_error = Some(e);
                        callback(
                            MonitorEvent::Unavailable(event),
                            &mut MonitorContext {
                                core: &mut self.core,
                                physical: &mut self.mq.physical,
                                tx: &mut self.mq.tx,
                            },
                        );
                    }
                }
                return Poll::Ready(Ok(Progress::Activity));
            }
            Err(e) => return Poll::Ready(Err(e.into())),
            Ok(None) => {}
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
                return Poll::Ready(Ok(Progress::Activity));
            }
            Poll::Ready(Pulse::Received) => {
                let Some(epoch) = self.mq.physical.epoch else {
                    return Poll::Ready(Err(Error::StaleGeneration.into()));
                };
                match self.core.receive(epoch, self.mq.rx.frame(), now) {
                    Ok(Some(status)) => callback(
                        MonitorEvent::Status(status),
                        &mut MonitorContext {
                            core: &mut self.core,
                            physical: &mut self.mq.physical,
                            tx: &mut self.mq.tx,
                        },
                    ),
                    Ok(None) => {}
                    Err(_) => {
                        self.mq.physical.retire();
                        self.mq.tx.clear();
                    }
                }
                self.mq.rx.clear();
                if self.core.is_closed() {
                    self.clock.retire();
                }
                return Poll::Ready(Ok(Progress::Activity));
            }
            Poll::Pending => {}
        }
        match self.wake.poll(cx, &mut self.clock, self.core.next_wakeup()) {
            Ok(Poll::Ready(())) => cx.waker().wake_by_ref(),
            Err(e) => return Poll::Ready(Err(e)),
            _ => {}
        }
        Poll::Pending
    }
    /// Drive one actual step, retaining every partial cursor/connect future and
    /// source timer if this waiting future is canceled before completion.
    ///
    /// Callback service bytes are tied to the original RX invocation:
    /// ```compile_fail
    /// # use gnunet_arm_host::{MonitorHost, MonitorEvent};
    /// async fn cannot_keep_rx(host: &mut MonitorHost<'_>) {
    ///     let mut retained = None;
    ///     let _ = host.drive(None, |event, _| {
    ///         if let MonitorEvent::Status(status) = event { retained = Some(status.service); }
    ///     }).await;
    ///     drop(retained);
    /// }
    /// ```
    /// Explicit owned copies remain valid:
    /// ```
    /// # use gnunet_arm_host::{MonitorHost, MonitorEvent};
    /// async fn keep_owned(host: &mut MonitorHost<'_>) {
    ///     let mut retained = Vec::new();
    ///     let _ = host.drive(None, |event, _| {
    ///         if let MonitorEvent::Status(status) = event { retained.push(status.service.to_vec()); }
    ///     }).await;
    ///     drop(retained);
    /// }
    /// ```
    pub async fn drive(
        &mut self,
        wait_until: Option<Instant>,
        mut callback: impl FnMut(MonitorEvent<'_>, &mut MonitorContext<'_, 'a>),
    ) -> Result<Progress, HostError> {
        let mut wait = wait_until.map(|at| Box::pin(tokio::time::sleep_until(at)));
        poll_fn(|cx| self.poll(cx, &mut wait, &mut callback)).await
    }
}
