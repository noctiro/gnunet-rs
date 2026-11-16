//! Bounded original callback, source and cleanup observations.
use crate::{Cause, output};
use gnunet_program_host::reporting::Reporter;
use gnunet_resolver_broker::{BrokerError, Completion, Driver, DriverEvent};
use gnunet_service_startup::StopError;
use gnunet_types::{Error as Fault, GenerationalId};
use std::{cell::Cell, error::Error, fmt, io};

#[derive(Default)]
pub(super) struct Report {
    pub(super) token: Option<GenerationalId>,
    pub(super) rows: usize,
    pub(super) lines_written: usize,
    pub(super) bytes_written: usize,
    pub(super) completion: Option<Completion>,
    pub(super) stopped: bool,
    pub(super) stream_closed: bool,
    pub(super) cancelled: bool,
    pub(super) disconnect: bool,
    pub(super) driver_dropped: bool,
    pub(super) output_closed: bool,
    pub(super) output_flushed: bool,
    pub(super) pending_requests: Option<usize>,
    pub(super) queued_frames: Option<usize>,
    pub(super) pending_line: Option<(usize, usize)>,
    pub(super) connected: Option<u64>,
    pub(super) idle_closed: Option<u64>,
    pub(super) socket_retries: u64,
    pub(super) io_errors: [Option<io::Error>; 4],
    pub(super) connect_errors: [Option<BrokerError>; 4],
    pub(super) additional_errors: u64,
}
impl fmt::Debug for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolverReport")
            .field("token", &self.token)
            .field("rows", &self.rows)
            .field("lines_written", &self.lines_written)
            .field("bytes_written", &self.bytes_written)
            .field("completion", &self.completion)
            .field("stopped", &self.stopped)
            .field("stream_closed", &self.stream_closed)
            .field("cancelled", &self.cancelled)
            .field("disconnect", &self.disconnect)
            .field("driver_dropped", &self.driver_dropped)
            .field("output_closed", &self.output_closed)
            .field("output_flushed", &self.output_flushed)
            .field("pending_requests", &self.pending_requests)
            .field("queued_frames", &self.queued_frames)
            .field("pending_line", &self.pending_line)
            .field("connected", &self.connected)
            .field("idle_closed", &self.idle_closed)
            .field("socket_retries", &self.socket_retries)
            .field("io_errors", &self.io_errors)
            .field("connect_errors", &self.connect_errors)
            .field("additional_errors", &self.additional_errors)
            .finish()
    }
}
#[derive(Default, Debug)]
pub(super) struct Errors {
    pub(super) original: [Option<Cause>; 4],
    pub(super) additional: u64,
    pub(super) cancel: Option<BrokerError>,
    pub(super) signal: Option<StopError>,
    pub(super) output: Option<io::Error>,
    pub(super) output_retirement: Option<output::Retired>,
    pub(super) driver: Option<BrokerError>,
    pub(super) disconnect: Option<BrokerError>,
    pub(super) source_lost: Option<(u64, Fault)>,
    pub(super) unavailable: bool,
    pub(super) logging: Option<io::Error>,
}
impl Errors {
    pub(super) fn record(&mut self, error: Cause) {
        if let Some(slot) = self.original.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(error);
        } else {
            self.additional = self.additional.saturating_add(1);
        }
    }
    pub(super) fn failed(&self) -> bool {
        self.original.iter().any(Option::is_some)
            || self.additional != 0
            || self.cancel.is_some()
            || self.signal.is_some()
            || self.output.is_some()
            || self.output_retirement.is_some()
            || self.driver.is_some()
            || self.disconnect.is_some()
            || self.source_lost.is_some()
            || self.unavailable
            || self.logging.is_some()
    }
}
#[derive(Debug)]
pub(super) struct Failed {
    pub(super) report: Report,
    pub(super) errors: Errors,
}
impl fmt::Display for Failed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Resolver query terminal facts: {:?}; causes: {:?}",
            self.report, self.errors
        )
    }
}
impl Error for Failed {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.errors
            .original
            .iter()
            .find_map(|error| error.as_deref())
            .or_else(|| self.errors.cancel.as_ref().map(|error| error as &dyn Error))
            .or_else(|| self.errors.signal.as_ref().map(|error| error as &dyn Error))
            .or_else(|| self.errors.output.as_ref().map(|error| error as &dyn Error))
            .or_else(|| {
                self.errors
                    .output_retirement
                    .as_ref()
                    .map(|error| error as &dyn Error)
            })
            .or_else(|| self.errors.driver.as_ref().map(|error| error as &dyn Error))
            .or_else(|| {
                self.errors
                    .disconnect
                    .as_ref()
                    .map(|error| error as &dyn Error)
            })
            .or_else(|| {
                self.errors
                    .source_lost
                    .as_ref()
                    .map(|(_, error)| error as &dyn Error)
            })
            .or_else(|| {
                self.errors
                    .logging
                    .as_ref()
                    .map(|error| error as &dyn Error)
            })
    }
}
#[derive(Clone, Copy, Default)]
pub(super) struct Observed {
    pub(super) connected: Option<u64>,
    pub(super) lost: Option<(u64, Fault)>,
    pub(super) unavailable: bool,
    pub(super) idle: Option<u64>,
    pub(super) retries: u64,
    pub(super) changed: bool,
}
pub(super) fn observation(event: DriverEvent, cell: &Cell<Observed>, reporter: &Reporter) {
    let mut current = cell.get();
    current.changed = true;
    match event {
        DriverEvent::Connected(epoch) => current.connected = Some(epoch.value()),
        DriverEvent::SocketRetry { .. } => current.retries = current.retries.saturating_add(1),
        DriverEvent::Lost { epoch, cause } => current.lost = Some((epoch.value(), cause)),
        DriverEvent::Unavailable => current.unavailable = true,
        DriverEvent::IdleClosed(epoch) => current.idle = Some(epoch.value()),
    }
    cell.set(current);
    reporter.debug(
        "resolver.driver.activity",
        format_args!("Resolver owner: {event:?}"),
    );
}
pub(super) fn take_errors(driver: &mut Driver<16, 64>, report: &mut Report) {
    if let Some(error) = driver.take_io_error() {
        if let Some(slot) = report.io_errors.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(error);
        } else {
            report.additional_errors = report.additional_errors.saturating_add(1);
        }
    }
    if let Some(error) = driver.take_connect_error() {
        if let Some(slot) = report.connect_errors.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(error);
        } else {
            report.additional_errors = report.additional_errors.saturating_add(1);
        }
    }
}
pub(super) fn observed(value: Observed, report: &mut Report, errors: &mut Errors) {
    if value.connected.is_some() {
        report.connected = value.connected;
    }
    if value.idle.is_some() {
        report.idle_closed = value.idle;
    }
    report.socket_retries = report.socket_retries.saturating_add(value.retries);
    if let Some(lost) = value.lost {
        errors.source_lost = Some(lost);
    }
    errors.unavailable |= value.unavailable;
}
