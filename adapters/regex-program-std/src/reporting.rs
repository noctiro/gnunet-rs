//! Selected Logger ownership. Fixed call-site severity avoids cached suppression.
use gnunet_program_host::{logging::Logger, policy::Level, service, shared_clock::SharedClock};
use gnunet_regex_server_host::{Event, driver::Progress};
use std::{
    cell::RefCell,
    fmt, io,
    task::{Context, Waker},
};
pub(crate) struct Diagnostics<'a> {
    pub(crate) logger: RefCell<Logger<'a>>,
    clock: SharedClock,
    failure: RefCell<Option<io::Error>>,
    waker: RefCell<Option<Waker>>,
}
impl<'a> Diagnostics<'a> {
    pub(crate) fn new(logger: Logger<'a>, clock: SharedClock) -> Self {
        Self {
            logger: RefCell::new(logger),
            clock,
            failure: RefCell::new(None),
            waker: RefCell::new(None),
        }
    }
    pub(crate) fn message(
        &self,
        site: &'static str,
        level: Level,
        args: fmt::Arguments<'_>,
    ) -> io::Result<()> {
        service::diagnostic(
            &mut self.logger.borrow_mut(),
            &self.clock,
            site,
            level,
            args,
        )
    }
    pub(crate) fn observe(&self, site: &'static str, level: Level, args: fmt::Arguments<'_>) {
        if self.failure.borrow().is_some() {
            return;
        }
        if let Err(error) = self.message(site, level, args) {
            *self.failure.borrow_mut() = Some(error);
            if let Some(waker) = self.waker.borrow().as_ref() {
                waker.wake_by_ref();
            }
        }
    }
    pub(crate) fn host(&self, event: Event) {
        let failed = matches!(&event, Event::AdmissionFailed(_) | Event::Cleanup { .. })
            || matches!(
                &event,
                Event::Socket(gnunet_service_runtime::accepted::SocketEvent::Failed(_))
            )
            || matches!(
                &event,
                Event::Closed {
                    cause: gnunet_regex_server_host::CloseCause::Fault(_),
                    ..
                }
            );
        let (site, level) = if failed {
            ("regex.host.failed", Level::WARNING)
        } else {
            ("regex.host.activity", Level::DEBUG)
        };
        self.observe(site, level, format_args!("REGEX IPC {event:?}"));
    }
    pub(crate) fn driver(&self, event: Progress<'_>) {
        match event {
            Progress::DhtSourceFailure(error) => self.observe(
                "regex.dht.source", Level::WARNING,
                format_args!("REGEX original DHT source: {error}; readonly intents remain owned")),
            Progress::Publication { job, retiring } => self.observe(
                "regex.dht.putwritten", Level::DEBUG,
                format_args!("REGEX original DHT PUT {job:?} locally whole-written, retiring={retiring}; no remote acknowledgement")),
            Progress::BackendFailure { job, error } => self.observe(
                "regex.backend.failed",
                Level::WARNING,
                format_args!("REGEX original backend {job:?} failed: {error}"),
            ),
            Progress::Rejected { job, error } => self.observe(
                "regex.record.rejected",
                Level::WARNING,
                format_args!("REGEX original query {job:?} refused record: {error}"),
            ),
            Progress::Identity(peer) => self.observe(
                "regex.peer",
                Level::INFO,
                format_args!("REGEX actual public PILS identity: {peer:?}"),
            ),
            Progress::Pils(event) => self.pils(event),
            Progress::Submitted => self.observe(
                "regex.work.queued",
                Level::DEBUG,
                format_args!("REGEX original work admitted locally; no publication ACK"),
            ),
            Progress::Activity | Progress::WaitDeadline | Progress::Closed => {}
        }
    }
    fn pils(&self, event: gnunet_pils_host::client::Progress<'_, 1>) {
        use gnunet_pils_host::client::Progress as P;
        match event {
            P::Lost {
                epoch,
                cause,
                report: _,
            } => self.observe(
                "regex.pils.lost",
                Level::WARNING,
                format_args!("REGEX original PILS {epoch:?} lost: {cause:?}"),
            ),
            P::ConnectRetry {
                epoch,
                retry_after,
                error,
            } => self.observe(
                "regex.pils.retry",
                Level::WARNING,
                format_args!("REGEX actual PILS attempt {epoch:?}: {error}; retry {retry_after:?}"),
            ),
            P::Unavailable(error) => self.observe(
                "regex.pils.unavailable",
                Level::WARNING,
                format_args!("REGEX PILS endpoint unavailable: {error}"),
            ),
            P::Connected(epoch) => self.observe(
                "regex.pils.connected",
                Level::DEBUG,
                format_args!("REGEX actual PILS MQ {epoch:?}; identity pending"),
            ),
            // Never format crypto result ownership, even though this signer only
            // requests public signatures. No secret field reaches diagnostics.
            P::Inbound(_) | P::Written(_) | P::Activity { .. } | P::WaitDeadline | P::Closed => {}
        }
    }
    pub(crate) fn failed(&self, cx: &Context<'_>) -> bool {
        let mut waker = self.waker.borrow_mut();
        if waker.as_ref().is_none_or(|old| !old.will_wake(cx.waker())) {
            *waker = Some(cx.waker().clone());
        }
        self.failure.borrow().is_some()
    }
    pub(crate) fn take_failure(&self) -> Option<io::Error> {
        self.failure.borrow_mut().take()
    }
}
