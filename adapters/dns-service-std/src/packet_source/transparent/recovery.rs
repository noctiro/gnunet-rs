//! Restore capture from a fresh topology and leave the original upstream marked.
use super::{
    Active, Open, Session, State, Transparent,
    topology::{Event, IngressWatch},
};
use crate::packet_source::{Retirement, SourceEvent};
use gnunet_native::transparent_dns::{
    NetworkNamespace,
    exclusion::{ConfiguredIngresses, Ingresses},
    link::LinkMonitor,
};
use std::{
    future::{Future, poll_fn},
    io,
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    task::{Context, Poll, ready},
    thread,
    time::{Duration, Instant},
};
use tokio::time::Sleep;

mod worker;
pub(super) use worker::Restart;

pub(super) const OUTAGE_LIMIT: Duration = Duration::from_secs(10);
const RETRY_DELAY: Duration = Duration::from_millis(250);

pub(super) struct Prepared {
    monitor: LinkMonitor,
    ingress: Ingresses,
}

pub(super) struct Observed {
    pub(super) watch: IngressWatch,
    pub(super) ingress: Ingresses,
}

impl Observed {
    fn register(prepared: Prepared) -> io::Result<Self> {
        Ok(Self {
            watch: IngressWatch::register(prepared.monitor)?,
            ingress: prepared.ingress,
        })
    }

    pub(super) async fn startup(
        interfaces: std::sync::Arc<ConfiguredIngresses>,
    ) -> io::Result<Self> {
        let until = Instant::now() + OUTAGE_LIMIT;
        let mut worker = Restart::startup(interfaces, until)?;
        let prepared = tokio::time::timeout_at(until.into(), poll_fn(|cx| worker.poll(cx)))
            .await
            .map_err(|_| expired())??;
        Self::register(prepared)
    }
}

pub(super) enum Refresh {
    Waiting {
        window: RetryWindow,
        timer: Pin<Box<Sleep>>,
    },
    Resolving {
        restart: Restart,
        deadline: Pin<Box<Sleep>>,
    },
    Watching {
        observed: Box<Observed>,
        until: Instant,
    },
}

impl Refresh {
    fn retry(cx: &mut Context<'_>, until: Instant) -> Self {
        let window = RetryWindow::later(until);
        let timer = Box::pin(tokio::time::sleep_until(window.after.into()));
        // The next poll registers the wait. No reactor wakeup is needed from
        // a discarded worker, a failed registration, or the active capture.
        cx.waker().wake_by_ref();
        Self::Waiting { window, timer }
    }

    fn resolve(session: &Session, until: Instant) -> io::Result<Self> {
        let deadline = Box::pin(tokio::time::sleep_until(until.into()));
        let restart = Restart::launch(session, until)?;
        Ok(Self::Resolving { restart, deadline })
    }
}

#[derive(Clone, Copy)]
pub(super) struct RetryWindow {
    after: Instant,
    until: Instant,
}

enum RetryDecision {
    Wait,
    Attempt,
    Expired,
}

impl RetryWindow {
    fn new(after: Instant, until: Instant) -> Self {
        Self {
            after: after.min(until),
            until,
        }
    }

    fn later(until: Instant) -> Self {
        Self::new(Instant::now() + RETRY_DELAY, until)
    }

    fn decision(self, now: Instant) -> RetryDecision {
        if now >= self.until {
            RetryDecision::Expired
        } else if now < self.after {
            RetryDecision::Wait
        } else {
            RetryDecision::Attempt
        }
    }

    fn poll(self, cx: &mut Context<'_>, mut timer: Pin<&mut Sleep>) -> Poll<io::Result<()>> {
        match self.decision(Instant::now()) {
            RetryDecision::Expired => Poll::Ready(Err(expired())),
            RetryDecision::Attempt => Poll::Ready(Ok(())),
            RetryDecision::Wait => {
                timer.as_mut().reset(self.after.into());
                ready!(timer.poll(cx));
                // A wakeup can be delayed past the original deadline.
                Poll::Ready(if Instant::now() >= self.until {
                    Err(expired())
                } else {
                    Ok(())
                })
            }
        }
    }
}

fn prepare(
    interfaces: &ConfiguredIngresses,
    namespace: Option<NetworkNamespace>,
    until: Instant,
    cancelled: &AtomicBool,
) -> io::Result<Prepared> {
    loop {
        if cancelled.load(Ordering::Acquire) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        if Instant::now() >= until {
            return Err(expired());
        }
        let attempt = (|| {
            // Watch first so any link changes during resolution are queued on
            // this exact descriptor before the generation starts admitting.
            let monitor = LinkMonitor::subscribe()?;
            let stop = || cancelled.load(Ordering::Acquire);
            let ingress = if let Some(namespace) = namespace {
                namespace.require(monitor.namespace())?;
                Ingresses::resolve_available_before(interfaces, until, stop)?
            } else {
                Ingresses::resolve_before(interfaces, until, stop)?
            };
            monitor.namespace().require(ingress.namespace())?;
            Ok::<_, io::Error>(Prepared { monitor, ingress })
        })();
        match attempt {
            Err(error) if namespace.is_some() && retryable(&error) => {
                thread::park_timeout(
                    RETRY_DELAY.min(until.saturating_duration_since(Instant::now())),
                );
            }
            result => return result,
        }
    }
}

fn retryable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::TimedOut | io::ErrorKind::NetworkDown
    ) || matches!(
        error.raw_os_error(),
        Some(
            libc::ENODEV
                | libc::ENXIO
                | libc::ENOBUFS
                | libc::EAGAIN
                | libc::EINTR
                | libc::EMFILE
                | libc::ENFILE
                | libc::ENOMEM
                | libc::ENOSPC
        )
    )
}

fn expired() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "transparent DNS topology did not recover before its outage deadline",
    )
}

impl<'id> Transparent<'id> {
    pub(super) fn replace_and_retire(&mut self, next: State<'id>) {
        let previous = std::mem::replace(&mut self.state, next);
        let restart = match previous {
            State::Restarting(restart) => Some(restart),
            State::Active(active)
            | State::Validating {
                candidate: active, ..
            } => {
                debug_assert!(self.retiring_probe.is_none());
                self.retiring_probe = Some(active.open.probes.retire());
                match active.refresh {
                    Some(Refresh::Resolving { restart, .. }) => Some(restart),
                    _ => None,
                }
            }
            _ => None,
        };
        if let Some(restart) = restart
            && !restart.is_joined()
        {
            // New observation work only starts after this slot has drained.
            debug_assert!(self.retiring_restart.is_none());
            restart.cancel();
            self.retiring_restart = Some(restart);
        }
    }

    fn poll_stopped_workers(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(restart) = &mut self.retiring_restart {
            // A cancelled observation cannot authorize another capture.
            let _retired = ready!(restart.poll(cx));
            self.retiring_restart = None;
        }
        if let Some(worker) = &mut self.retiring_probe {
            let result = ready!(worker.poll_retired(cx));
            self.retiring_probe = None;
            return Poll::Ready(result);
        }
        Poll::Ready(Ok(()))
    }

    pub(in crate::packet_source) fn poll_retirement(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Retirement> {
        if self.retirement.is_none() {
            return Poll::Pending;
        }
        if let Err(error) = ready!(self.poll_stopped_workers(cx))
            && let Some(retirement) = &mut self.retirement
        {
            retirement.probe_error = Some(error);
        }
        self.take_retirement().map_or(Poll::Pending, Poll::Ready)
    }

    pub(super) fn topology_lost(&mut self, reason: io::Error) -> SourceEvent<'id> {
        self.detach(Instant::now() + OUTAGE_LIMIT, None, reason)
    }

    fn detach(
        &mut self,
        until: Instant,
        observed: Option<Box<Observed>>,
        reason: io::Error,
    ) -> SourceEvent<'id> {
        let pending = self.pending();
        self.replace_and_retire(State::Detached {
            until,
            pending,
            observed,
        });
        SourceEvent::Suspended(reason)
    }

    pub(super) fn poll_refresh(&mut self, cx: &mut Context<'_>) -> Poll<SourceEvent<'id>> {
        let Some(session) = &self.session else {
            return Poll::Pending;
        };
        let State::Active(active) = &mut self.state else {
            return Poll::Pending;
        };
        if active.open.watch.backlogged() {
            return Poll::Pending;
        }
        if active.refresh.is_none() && std::mem::take(&mut active.refresh_requested) {
            active.refresh = Some(Refresh::retry(cx, Instant::now() + OUTAGE_LIMIT));
        }
        if let Some(Refresh::Waiting { window, timer }) = &mut active.refresh {
            let until = window.until;
            active.refresh = match ready!(window.poll(cx, timer.as_mut())) {
                Ok(()) => match Refresh::resolve(session, until) {
                    Ok(refresh) => Some(refresh),
                    Err(error) if retryable(&error) => Some(Refresh::retry(cx, until)),
                    Err(_) => None,
                },
                Err(_) => None,
            };
        }
        if let Some(Refresh::Resolving { restart, deadline }) = &mut active.refresh {
            let until = restart.until;
            let overdue = Instant::now() >= until || deadline.as_mut().poll(cx).is_ready();
            if overdue {
                restart.cancel();
            }
            let result = ready!(restart.poll(cx));
            active.refresh = if overdue || Instant::now() >= until {
                None
            } else {
                match result.and_then(Observed::register) {
                    Ok(observed) => Some(Refresh::Watching {
                        observed: Box::new(observed),
                        until,
                    }),
                    Err(error) if retryable(&error) => Some(Refresh::retry(cx, until)),
                    Err(_) => None,
                }
            };
        }
        let Some(Refresh::Watching { observed, until }) = &mut active.refresh else {
            if active.refresh_requested {
                cx.waker().wake_by_ref();
            }
            return Poll::Pending;
        };
        let until = *until;
        if Instant::now() >= until {
            active.refresh = None;
            if active.refresh_requested {
                cx.waker().wake_by_ref();
            }
            return Poll::Pending;
        }
        match observed
            .watch
            .poll(cx, &mut observed.ingress, &session.interfaces)
        {
            Poll::Ready(Event::Returning | Event::Lost(_)) => {
                active.refresh = Some(Refresh::retry(cx, until));
                return Poll::Pending;
            }
            Poll::Ready(Event::Failed(error)) if retryable(&error) => {
                active.refresh = Some(Refresh::retry(cx, until));
                return Poll::Pending;
            }
            Poll::Ready(Event::Failed(_)) => {}
            Poll::Ready(Event::IngressRetired) | Poll::Pending => {
                if observed.watch.backlogged() || observed.watch.has_pending_return() {
                    return Poll::Pending;
                }
                if observed.ingress.introduces_ingress(&active.open.ingress) {
                    let Some(Refresh::Watching { observed, .. }) = active.refresh.take() else {
                        return Poll::Pending;
                    };
                    return Poll::Ready(self.detach(
                        until,
                        Some(observed),
                        io::Error::other("configured transparent DNS ingress returned"),
                    ));
                }
            }
        }
        active.refresh = None;
        if active.refresh_requested {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }

    pub(super) fn poll_recovery(&mut self, cx: &mut Context<'_>) -> Poll<SourceEvent<'id>> {
        if let State::Detached {
            until,
            pending,
            observed,
        } = &mut self.state
        {
            let pending = pending.take();
            self.state = match observed.take() {
                Some(observed) => State::Rebinding {
                    until: *until,
                    observed,
                },
                None => State::Retry {
                    after: Instant::now(),
                    until: *until,
                },
            };
            return Poll::Ready(SourceEvent::Detached {
                retirement: Retirement::TransparentGeneration,
                pending,
            });
        }
        if let State::Retry { until, .. } | State::Rebinding { until, .. } = self.state {
            match self.poll_stopped_workers(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(SourceEvent::Failed(error)),
                Poll::Pending => {
                    // A retiring worker cannot extend the replacement's outage window.
                    self.timer.as_mut().reset(until.into());
                    if Instant::now() >= until || self.timer.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(SourceEvent::Failed(expired()));
                    }
                    return Poll::Pending;
                }
            }
        }
        let Some(session) = &self.session else {
            return Poll::Pending;
        };
        if let State::Retry { after, until } = self.state {
            if let Err(error) = ready!(RetryWindow::new(after, until).poll(cx, self.timer.as_mut()))
            {
                return Poll::Ready(SourceEvent::Failed(error));
            }
            match Restart::launch(session, until) {
                Ok(restart) => self.state = State::Restarting(restart),
                Err(error) => return self.recovery_failure(cx, until, error),
            }
        }
        if matches!(self.state, State::Validating { .. }) {
            return self.poll_candidate(cx);
        }
        if matches!(self.state, State::Rebinding { .. })
            && let State::Rebinding { observed, until } =
                std::mem::replace(&mut self.state, State::Closed)
        {
            return self.bind_candidate(cx, *observed, until);
        }
        let State::Restarting(restart) = &mut self.state else {
            return Poll::Pending;
        };
        let until = restart.until;
        if Instant::now() >= until {
            return Poll::Ready(SourceEvent::Failed(expired()));
        }
        self.timer.as_mut().reset(until.into());
        if self.timer.as_mut().poll(cx).is_ready() {
            return Poll::Ready(SourceEvent::Failed(expired()));
        }
        let prepared = match restart.poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(prepared)) => prepared,
            Poll::Ready(Err(error)) => return self.recovery_failure(cx, until, error),
        };
        match Observed::register(prepared) {
            Ok(observed) => self.bind_candidate(cx, observed, until),
            Err(error) => self.recovery_failure(cx, until, error),
        }
    }

    fn bind_candidate(
        &mut self,
        cx: &mut Context<'_>,
        observed: Observed,
        until: Instant,
    ) -> Poll<SourceEvent<'id>> {
        if Instant::now() >= until {
            return Poll::Ready(SourceEvent::Failed(expired()));
        }
        let Some(session) = &self.session else {
            return Poll::Ready(SourceEvent::Failed(io::ErrorKind::NotConnected.into()));
        };
        match Open::start(
            observed.watch,
            observed.ingress,
            session.families,
            session.port,
            session.bypass_mark,
        ) {
            Ok(open) => {
                self.state = State::Validating {
                    candidate: Box::new(Active::new(open)),
                    until,
                };
                self.poll_candidate(cx)
            }
            Err(error) => self.recovery_failure(cx, until, error),
        }
    }

    fn poll_candidate(&mut self, cx: &mut Context<'_>) -> Poll<SourceEvent<'id>> {
        let State::Validating { candidate, until } = &mut self.state else {
            return Poll::Pending;
        };
        if Instant::now() >= *until {
            return Poll::Ready(SourceEvent::Failed(expired()));
        }
        let Some(session) = &self.session else {
            return Poll::Ready(SourceEvent::Failed(io::ErrorKind::NotConnected.into()));
        };
        let open = &mut candidate.open;
        match open.poll_watch(cx, &session.interfaces) {
            Poll::Ready(Event::Lost(_) | Event::Returning) => {
                // Discard the candidate before attaching it. Pace retries
                // within the original outage window.
                let until = *until;
                return self.defer_recovery(cx, until);
            }
            Poll::Ready(Event::Failed(error)) => {
                let until = *until;
                return self.recovery_failure(cx, until, error);
            }
            Poll::Ready(Event::IngressRetired) | Poll::Pending => {}
        }
        if open.watch.backlogged() || open.watch.has_pending_return() {
            return Poll::Pending;
        }
        // Advertise recovery only after the fresh watch's first drain. A
        // second overrun during startup cannot reset the outage deadline.
        let state = std::mem::replace(&mut self.state, State::Closed);
        if let State::Validating { candidate, .. } = state {
            self.state = State::Active(candidate);
            self.read_cursor = 0;
            Poll::Ready(SourceEvent::Attached)
        } else {
            Poll::Ready(SourceEvent::Failed(io::ErrorKind::NotConnected.into()))
        }
    }

    fn recovery_failure(
        &mut self,
        cx: &mut Context<'_>,
        until: Instant,
        error: io::Error,
    ) -> Poll<SourceEvent<'id>> {
        if retryable(&error) {
            self.defer_recovery(cx, until)
        } else {
            Poll::Ready(SourceEvent::Failed(error))
        }
    }

    fn defer_recovery(&mut self, cx: &mut Context<'_>, until: Instant) -> Poll<SourceEvent<'id>> {
        if Instant::now() >= until {
            return Poll::Ready(SourceEvent::Failed(expired()));
        }
        let window = RetryWindow::later(until);
        self.replace_and_retire(State::Retry {
            after: window.after,
            until: window.until,
        });
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_setup_failures_keep_the_original_recovery_deadline() {
        let start = Instant::now();
        let until = start + OUTAGE_LIMIT;
        let first = RetryWindow::new(start + RETRY_DELAY, until);
        assert!(matches!(first.decision(start), RetryDecision::Wait));
        assert!(matches!(
            first.decision(start + RETRY_DELAY),
            RetryDecision::Attempt
        ));

        let near_deadline = until - Duration::from_millis(1);
        let last = RetryWindow::new(near_deadline + RETRY_DELAY, until);
        assert_eq!(last.after, until);
        assert!(matches!(last.decision(near_deadline), RetryDecision::Wait));
        assert!(matches!(last.decision(until), RetryDecision::Expired));
    }

    #[test]
    fn temporary_setup_resource_errors_can_resynchronize_topology() {
        for errno in [libc::ENOBUFS, libc::EAGAIN, libc::EMFILE, libc::ENOSPC] {
            assert!(retryable(&io::Error::from_raw_os_error(errno)));
        }
        for errno in [libc::EPERM, libc::EINVAL, libc::EADDRINUSE] {
            assert!(!retryable(&io::Error::from_raw_os_error(errno)));
        }
        assert!(!retryable(&io::ErrorKind::Interrupted.into()));
    }
}
