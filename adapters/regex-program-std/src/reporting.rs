//! Selected Logger ownership. Fixed call-site severity avoids cached suppression.
use gnunet_program_host::{policy::Level, reporting::Reporter};
use gnunet_regex_server_host::{Event, driver::Progress};
use std::{fmt, io, task::Context};
pub(crate) struct Diagnostics {
    reports: Reporter,
}
impl Diagnostics {
    pub(crate) fn new(reports: Reporter) -> Self {
        Self { reports }
    }
    pub(crate) fn reporter(&self) -> &Reporter {
        &self.reports
    }
    pub(crate) fn message(
        &self,
        site: &'static str,
        level: Level,
        args: fmt::Arguments<'_>,
    ) -> io::Result<()> {
        self.reports.message(level, site, args);
        if let Some(error) = self.reports.take_error() {
            return Err(error);
        }
        if self.reports.failed() {
            return Err(io::Error::other(
                "REGEX selected diagnostic owner already failed",
            ));
        }
        Ok(())
    }
    pub(crate) fn observe(&self, site: &'static str, level: Level, args: fmt::Arguments<'_>) {
        self.reports.message(level, site, args);
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
        self.reports.register(cx);
        self.reports.failed()
    }
    pub(crate) fn take_failure(&self) -> Option<io::Error> {
        self.reports.take_error()
    }
}
