//! Give a pending original routing notification precedence over packet I/O.
use super::scope::Scope;
use gnunet_native::pf_scope::{Event, MESSAGE_BYTES, Monitor};
use gnunet_service_runtime::readiness::RegisteredIo;
use std::{
    io,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Instant;

const RECORDS_PER_POLL: usize = 8;
const DRAIN_LIMIT: Duration = Duration::from_secs(3);

pub(in crate::platform) struct Topology {
    monitor: RegisteredIo<Monitor>,
    buffer: Vec<u8>,
    recheck: bool,
    backlog_until: Option<Instant>,
}

impl Topology {
    pub(in crate::platform) fn subscribe() -> io::Result<Self> {
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(MESSAGE_BYTES)
            .map_err(io::Error::other)?;
        buffer.resize(MESSAGE_BYTES, 0);
        let monitor =
            RegisteredIo::from_descriptor(Monitor::subscribe()?).map_err(|(_, error)| error)?;
        Ok(Self {
            monitor,
            buffer,
            recheck: false,
            backlog_until: None,
        })
    }

    /// Ready means packet I/O may continue. Pending means the original route
    /// backlog has priority even when a separate pump direction is ready.
    pub(in crate::platform) fn poll(
        &mut self,
        cx: &mut Context<'_>,
        original: &Scope,
    ) -> Poll<io::Result<()>> {
        if self
            .backlog_until
            .is_some_and(|until| Instant::now() >= until)
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "PF original route backlog did not drain",
            )));
        }
        for _ in 0..RECORDS_PER_POLL {
            let event = match self
                .monitor
                .poll_guard_read_on(cx, |monitor| monitor.read(&mut self.buffer))
            {
                Poll::Ready(Ok(event)) => event,
                Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Interrupted => {
                    return self.pause_for_backlog(cx);
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => {
                    self.backlog_until = None;
                    if std::mem::take(&mut self.recheck) {
                        let current = gnunet_native::interfaces::snapshot(Default::default())?;
                        original.require_same(&Scope::new(current)?)?;
                    }
                    return Poll::Ready(Ok(()));
                }
            };
            self.observe(original, event)?;
        }
        self.pause_for_backlog(cx)
    }

    fn pause_for_backlog(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.backlog_until
            .get_or_insert_with(|| Instant::now() + DRAIN_LIMIT);
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn observe(&mut self, original: &Scope, event: Event) -> io::Result<()> {
        match event {
            Event::AddressRemoved(index) | Event::InterfaceDeparted(index)
                if original.contains_interface(index) =>
            {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "PF original address interface changed; repeat startup state retirement",
                ));
            }
            Event::AddressAdded | Event::AddressRemoved(_) => self.recheck = true,
            Event::InterfaceDeparted(_) | Event::Other => {}
        }
        Ok(())
    }
}
