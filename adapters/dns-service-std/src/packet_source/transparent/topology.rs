//! Follow original Linux ingress lifetime ahead of incoming and outgoing DNS.
use gnunet_native::transparent_dns::{
    NetworkNamespace,
    exclusion::{ConfiguredIngresses, Ingresses, Observation},
    link::{EVENT_BUFFER_BYTES, LinkMonitor},
};
use gnunet_service_runtime::readiness::RegisteredIo;
use std::{
    io,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Instant;

const WATCH_DATAGRAMS: usize = 4;
const DRAIN_LIMIT: Duration = Duration::from_secs(3);

pub(super) enum Event {
    IngressRetired,
    Returning,
    Lost(io::Error),
    Failed(io::Error),
}

pub(super) struct IngressWatch {
    io: RegisteredIo<LinkMonitor>,
    buffer: Vec<u8>,
    state: State,
    returning: bool,
}

enum State {
    Ready,
    Draining { until: Instant },
    Retired,
}

impl State {
    fn defer(&mut self, now: Instant) {
        if matches!(self, Self::Ready) {
            *self = Self::Draining {
                until: now + DRAIN_LIMIT,
            };
        }
    }

    fn expired(&self, now: Instant) -> bool {
        matches!(self, Self::Draining { until } if now >= *until)
    }
}

impl IngressWatch {
    pub(super) fn register(monitor: LinkMonitor) -> io::Result<Self> {
        let io = RegisteredIo::from_descriptor(monitor).map_err(|(_, error)| error)?;
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(EVENT_BUFFER_BYTES)
            .map_err(io::Error::other)?;
        buffer.resize(EVENT_BUFFER_BYTES, 0);
        Ok(Self {
            io,
            buffer,
            state: State::Ready,
            returning: false,
        })
    }

    pub(super) const fn usable(&self) -> bool {
        !matches!(self.state, State::Retired)
    }

    pub(super) fn namespace(&self) -> NetworkNamespace {
        self.io.descriptor().namespace()
    }

    pub(super) const fn backlogged(&self) -> bool {
        matches!(self.state, State::Draining { .. })
    }

    // A full budget yields to other service work while packet I/O stays paused.
    pub(super) fn poll(
        &mut self,
        cx: &mut Context<'_>,
        ingress: &mut Ingresses,
        configured: &ConfiguredIngresses,
    ) -> Poll<Event> {
        if !self.usable() {
            return Poll::Ready(Event::Failed(io::ErrorKind::NotConnected.into()));
        }
        let now = Instant::now();
        if self.state.expired(now) {
            self.state = State::Retired;
            return Poll::Ready(Event::Lost(io::Error::new(
                io::ErrorKind::TimedOut,
                "original transparent DNS link notifications did not drain",
            )));
        }
        let mut retired = ingress.take_validation_retirement();
        if retired && !ingress.has_active() {
            self.state = State::Retired;
            return Poll::Ready(Event::Lost(inactive_ingress()));
        }
        for _ in 0..WATCH_DATAGRAMS {
            let mut incomplete = false;
            match self.io.poll_guard_read_on(cx, |monitor| {
                monitor.read(&mut self.buffer, |event| {
                    match ingress.observe(event) {
                        Observation::Unchanged => {}
                        Observation::Retired => retired = true,
                        Observation::Incomplete => incomplete = true,
                    }
                    self.returning |= ingress.might_return(configured, event);
                })
            }) {
                Poll::Pending => {
                    self.state = State::Ready;
                    break;
                }
                Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Interrupted => {
                    // A signal proves neither notification loss nor an empty
                    // queue. Keep packet I/O paused until the watch is drained.
                    self.state.defer(now);
                    break;
                }
                Poll::Ready(Err(error)) => {
                    self.state = State::Retired;
                    return Poll::Ready(if LinkMonitor::is_notification_loss(&error) {
                        Event::Lost(error)
                    } else {
                        Event::Failed(error)
                    });
                }
                Poll::Ready(Ok(())) => {}
            }
            if incomplete {
                self.state = State::Retired;
                return Poll::Ready(Event::Lost(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "original transparent DNS link notification lacks identity",
                )));
            }
            if retired && !ingress.has_active() {
                self.state = State::Retired;
                return Poll::Ready(Event::Lost(inactive_ingress()));
            }
            self.state.defer(now);
        }
        if self.backlogged() || (retired && self.returning) {
            cx.waker().wake_by_ref();
        }
        if retired {
            Poll::Ready(Event::IngressRetired)
        } else if !self.backlogged() && std::mem::take(&mut self.returning) {
            Poll::Ready(Event::Returning)
        } else {
            Poll::Pending
        }
    }

    pub(super) const fn has_pending_return(&self) -> bool {
        self.returning
    }
}

fn inactive_ingress() -> io::Error {
    io::Error::new(
        io::ErrorKind::NetworkDown,
        "all original transparent DNS ingress interfaces retired",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_continuing_backlog_keeps_its_first_deadline() {
        let first = Instant::now();
        let mut state = State::Ready;
        state.defer(first);
        state.defer(first + Duration::from_secs(2));
        assert!(!state.expired(first + Duration::from_secs(2)));
        assert!(state.expired(first + DRAIN_LIMIT));
    }
}
