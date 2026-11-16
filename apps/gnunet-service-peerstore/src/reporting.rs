//! One shared selected Reporter, retained through actual worker retirement.
use crate::Failure;
use gnunet_peerstore_host::{
    server::{CloseCause, Event},
    worker::Completion,
};
use gnunet_program_host::{policy::Level, reporting::Reporter};
use gnunet_service_runtime::accepted::SocketEvent;
use std::{fmt, io, task::Context};
pub(crate) struct Reports(Reporter);
impl Reports {
    pub(crate) fn new(reporter: Reporter) -> Self {
        Self(reporter)
    }
    pub(crate) fn reporter(&self) -> &Reporter {
        &self.0
    }
    pub(crate) fn register(&self, cx: &Context<'_>) {
        self.0.register(cx);
    }
    pub(crate) fn failed(&self) -> bool {
        self.0.failed()
    }
    pub(crate) fn startup_check(&self) -> Result<(), Failure> {
        if let Some(error) = self.0.take_error() {
            return Err(error.into());
        }
        if self.0.failed() {
            return Err(io::Error::other("PEERSTORE selected logger already failed").into());
        }
        Ok(())
    }
    pub(crate) fn message(&self, level: Level, site: &'static str, message: fmt::Arguments<'_>) {
        self.0.message(level, site, message);
    }
    pub(crate) fn warning(&self, site: &'static str, message: fmt::Arguments<'_>) {
        self.message(Level::WARNING, site, message);
    }
    pub(crate) fn observe(&self, event: Event<'_>) {
        match event {
            Event::Socket(SocketEvent::Failed(error)) if error.is_emfile() => {}
            Event::Socket(SocketEvent::Failed(error)) => self.warning(
                "peerstore.socket.failed",
                format_args!("peerstore socket: {error}"),
            ),
            Event::Socket(event) => self.message(
                Level::DEBUG,
                "peerstore.socket.activity",
                format_args!("peerstore socket: {event:?}"),
            ),
            Event::Closed { loss, cause } => {
                let (level, site) = if matches!(&cause, CloseCause::Fault(_)) {
                    (Level::WARNING, "peerstore.source.failed")
                } else {
                    (Level::INFO, "peerstore.source.closed")
                };
                self.message(level,site,format_args!("peerstore source={} pending={:?} exposed={} store={:?} unknown={:?} cause={cause:?}",loss.client.value(),loss.pending,loss.exposed,loss.pending_store,loss.unknown_store));
            }
            Event::AdmissionFailed(error) => self.warning(
                "peerstore.admission",
                format_args!("peerstore admission: {error}"),
            ),
            Event::Storage {
                job,
                client,
                failure: Some(error),
            } => self.warning(
                "peerstore.storage.failed",
                format_args!(
                    "peerstore storage job={} client={:?} actual={error}",
                    job.value(),
                    client.map(|c| c.value())
                ),
            ),
            _ => {}
        }
    }
    pub(crate) fn completion(&self, completion: Completion) {
        self.message(
            Level::DEBUG,
            "peerstore.worker.retired",
            format_args!(
                "peerstore original worker completion retired: job={}",
                completion.job().value()
            ),
        );
    }
}
