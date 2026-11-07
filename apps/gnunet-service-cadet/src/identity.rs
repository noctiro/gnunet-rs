use crate::{
    control::Signals,
    foreground::{Failures, Stage},
    settings::Settings,
};
use gnunet_pils::client::{Identity, Inbound};
use gnunet_pils_host::client::{Client, Error as PilsError, LossCause, Progress};
use gnunet_program_host::reporting::Reporter;
use gnunet_resolver_broker::{BrokerError, Driver, DriverEvent};
use gnunet_service_runtime::clock::{Deadline, RuntimeClock};
use gnunet_types::Error as ProtocolError;
use std::{
    error::Error,
    fmt,
    future::{Future, poll_fn},
    io,
    sync::Arc,
    task::Poll,
    time::Duration,
};
pub(super) type Pils<'a> = Client<'a, 1>;
pub(super) type Resolver = Driver<16, 256>;
#[cfg(test)]
mod profile_tests;
/// One original observation-only client on the node's selected public source.
/// This retains the existing resource policy and constructs no physical socket.
pub(super) fn observer<'a>(
    instance: &'a mut gnunet_pils::client::Instance,
    source: gnunet_client_host::EndpointSource,
    settings: &Settings,
) -> Result<Pils<'a>, PilsError> {
    Pils::new(
        instance,
        source,
        settings.pils_profile,
        gnunet_pils_host::client::Limits {
            pending_operations: 1,
            io_slice_bytes: settings.native.io_slice_bytes,
            ..Default::default()
        },
        gnunet_pils::HelloLimits {
            maximum_input_bytes: 65535,
            maximum_address_bytes: 65535,
            maximum_addresses: 128,
        },
    )
}
pub(super) struct Dependencies<'a, 'stats> {
    pub statistics: crate::statistics::Owner<'stats>,
    pub pils: Pils<'a>,
    pub resolver: Resolver,
    pub signals: Signals,
    pub reporter: Reporter,
    last_retry: Option<io::Error>,
}
#[derive(Debug)]
struct IdentityLoss {
    epoch: u64,
    cause: LossCause,
    feeds: usize,
    retained: usize,
}
impl fmt::Display for IdentityLoss {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "actual PILS identity MQ lost: epoch={} cause={:?} feeds={} retained={}",
            self.epoch, self.cause, self.feeds, self.retained
        )
    }
}
impl Error for IdentityLoss {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.cause {
            LossCause::Io(error) => Some(error),
            LossCause::Protocol(error) | LossCause::Resource(error) => Some(error),
            LossCause::Setup(error) => Some(error),
            LossCause::Eof | LossCause::Requested => None,
        }
    }
}
pub(super) fn provider_loss<const O: usize>(progress: Progress<'_, O>) -> Box<dyn Error> {
    match progress {
        Progress::Lost {
            epoch,
            cause,
            report,
        } => Box::new(IdentityLoss {
            epoch: epoch.value(),
            cause,
            feeds: report.feeds().count(),
            retained: report.retained(),
        }),
        Progress::Unavailable(error) => Box::new(error),
        Progress::ConnectRetry { error, .. } => Box::new(error),
        Progress::Connected(_) => Box::new(ProtocolError::StaleGeneration),
        _ => Box::new(ProtocolError::Closed),
    }
}
#[derive(Debug)]
struct StartupTimeout {
    last_retry: Option<io::Error>,
}
impl fmt::Display for StartupTimeout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "no verified PILS identity before configured startup deadline; original socket retry={:?}",
            self.last_retry
        )
    }
}
impl Error for StartupTimeout {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.last_retry
            .as_ref()
            .map(|error| error as &(dyn Error + 'static))
    }
}
pub(super) fn resolver_event(reporter: &Reporter, event: DriverEvent) {
    match event {
        DriverEvent::Lost { .. } | DriverEvent::Unavailable | DriverEvent::SocketRetry { .. } => {
            reporter.warning(
                "cadet.resolver.failed",
                format_args!("cadet resolver: {event:?}"),
            )
        }
        _ => reporter.debug(
            "cadet.resolver.activity",
            format_args!("cadet resolver: {event:?}"),
        ),
    }
}
impl<'a, 'stats> Dependencies<'a, 'stats> {
    pub(super) fn new(
        pils: Pils<'a>,
        resolver: Resolver,
        signals: Signals,
        reporter: Reporter,
        statistics: crate::statistics::Owner<'stats>,
    ) -> Self {
        Self {
            statistics,
            pils,
            resolver,
            signals,
            reporter,
            last_retry: None,
        }
    }
    pub(super) fn native_resolver_diagnostics(&mut self) {
        if let Some(error) = self.resolver.take_io_error() {
            self.reporter.warning(
                "cadet.resolver.io",
                format_args!("cadet resolver native IO: {error}"),
            );
        }
        if let Some(error) = self.resolver.take_connect_error() {
            self.reporter.warning(
                "cadet.resolver.endpoint",
                format_args!("cadet resolver endpoint: {error}"),
            );
        }
    }
    // Inspect a ready result before permitting any further local application IO.
    // A healthy busy PILS source still gets only one bounded poll alongside MQs.
    pub(super) fn fatal(
        result: &Result<Progress<'a, 1>, PilsError>,
        expected: Identity<'a>,
    ) -> bool {
        match result {
            Err(_) => true,
            Ok(
                Progress::Lost { .. }
                | Progress::Unavailable(_)
                | Progress::Closed
                | Progress::ConnectRetry { .. },
            ) => true,
            Ok(Progress::Connected(epoch)) => *epoch != expected.epoch(),
            Ok(Progress::Inbound(Inbound::Identity { identity, .. })) => {
                identity.peer() != expected.peer() || identity.epoch() != expected.epoch()
            }
            _ => false,
        }
    }
    pub(super) fn observe_pils(
        &mut self,
        result: Result<Progress<'a, 1>, PilsError>,
        expected: Option<Identity<'a>>,
        failures: &mut Failures,
    ) -> Option<Identity<'a>> {
        match result {
            Err(error) | Ok(Progress::Unavailable(error)) => {
                failures.record(Stage::Identity, Box::new(error))
            }
            Ok(Progress::Inbound(Inbound::Identity { identity, .. })) => {
                if expected.is_some_and(|expected| {
                    identity.peer() != expected.peer() || identity.epoch() != expected.epoch()
                }) {
                    failures.record(Stage::Identity, Box::new(io::Error::other("PILS changed the actual original identity/MQ while the CADET service was active; restart is required")));
                } else {
                    return Some(identity);
                }
            }
            Ok(Progress::Lost {
                epoch,
                cause,
                report,
            }) => failures.record(
                Stage::Identity,
                Box::new(IdentityLoss {
                    epoch: epoch.value(),
                    cause,
                    feeds: report.feeds().count(),
                    retained: report.retained(),
                }),
            ),
            Ok(Progress::ConnectRetry { epoch, error, .. }) => {
                self.reporter.warning(
                    "cadet.pils.retry",
                    format_args!("cadet PILS socket retry epoch={}: {error}", epoch.value()),
                );
                if expected.is_some() {
                    failures.record(Stage::Identity, Box::new(error));
                } else if self.last_retry.is_none() {
                    self.last_retry = Some(error);
                }
            }
            Ok(Progress::Connected(epoch))
                if expected.is_some_and(|expected| expected.epoch() != epoch) =>
            {
                failures.record(Stage::Identity, Box::new(ProtocolError::StaleGeneration))
            }
            Ok(Progress::Closed) => {
                failures.record(Stage::Identity, Box::new(ProtocolError::Closed))
            }
            Ok(_) => {}
        }
        None
    }
    /// A verified healthy announcement can initiate a controlled identity cut.
    /// Physical loss or replacement of the actual observer remains a failure.
    /// The caller must retire its identity-bound providers before applying it.
    pub(super) fn observe_identity_update(
        &mut self,
        result: Result<Progress<'a, 1>, PilsError>,
        expected: Identity<'a>,
        failures: &mut Failures,
    ) -> Option<Identity<'a>> {
        if let Ok(Progress::Inbound(Inbound::Identity { identity, .. })) = &result
            && identity.epoch() == expected.epoch()
        {
            return Some(*identity);
        }
        self.observe_pils(result, Some(expected), failures)
    }
    pub(super) async fn wait_identity(
        &mut self,
        clock: Arc<dyn RuntimeClock>,
        timeout: Duration,
        failures: &mut Failures,
    ) -> Option<Identity<'a>> {
        let deadline = match Deadline::after(clock, timeout) {
            Ok(deadline) => deadline,
            Err(error) => {
                failures.record(Stage::Identity, Box::new(error));
                return None;
            }
        };
        let mut deadline = std::pin::pin!(deadline);
        let reporter = self.reporter.clone();
        loop {
            let mut announced = None;
            let mut resolved: Option<Result<gnunet_resolver_broker::Progress, BrokerError>> = None;
            let mut stopping = None;
            let mut timeout = None;
            {
                let mut driving = std::pin::pin!(self.pils.drive(None));
                let mut resolving = std::pin::pin!(
                    self.resolver
                        .drive_waiting(None, |event| resolver_event(&reporter, event))
                );
                poll_fn(|cx| {
                    reporter.register(cx);
                    if reporter.failed() {
                        stopping = Some(Ok(()));
                        return Poll::Ready(());
                    }
                    if let Poll::Ready(result) = self.signals.poll(cx) {
                        stopping = Some(result);
                        return Poll::Ready(());
                    }
                    let guarded = self.statistics.native_guard(cx).is_ready();
                    if reporter.failed() {
                        self.statistics.abort();
                        stopping = Some(Ok(()));
                        return Poll::Ready(());
                    }
                    if guarded {
                        return Poll::Ready(());
                    }
                    if let Poll::Ready(result) = deadline.as_mut().poll(cx) {
                        timeout = Some(result);
                        return Poll::Ready(());
                    }
                    let stats_progress = self.statistics.poll(cx).is_ready();
                    if reporter.failed() {
                        self.statistics.abort();
                        stopping = Some(Ok(()));
                        return Poll::Ready(());
                    }
                    if let Poll::Ready(result) = driving.as_mut().poll(cx) {
                        announced = Some(result);
                    }
                    if let Poll::Ready(result) = resolving.as_mut().poll(cx) {
                        resolved = Some(result);
                    }
                    if announced.is_some() || resolved.is_some() || stats_progress {
                        Poll::Ready(())
                    } else {
                        Poll::Pending
                    }
                })
                .await;
            }
            self.native_resolver_diagnostics();
            if let Some(result) = stopping {
                if let Err(error) = result {
                    failures.record(Stage::Control, Box::new(error));
                }
                return None;
            }
            if let Some(result) = timeout {
                failures.record(
                    Stage::Identity,
                    match result {
                        Ok(()) => Box::new(StartupTimeout {
                            last_retry: self.last_retry.take(),
                        }) as Box<dyn Error>,
                        Err(error) => Box::new(error),
                    },
                );
                return None;
            }
            if let Some(Err(error)) = resolved {
                failures.record(Stage::Resolver, Box::new(error));
            }
            let identity = announced.and_then(|result| self.observe_pils(result, None, failures));
            if !failures.is_empty() || reporter.failed() {
                return None;
            }
            if identity.is_some() {
                return identity;
            }
        }
    }
    // These independent cleanup calls run even after local/identity failure.
    pub(super) fn close(&mut self, failures: &mut Failures) {
        self.statistics.abort();
        self.statistics.finish(failures);
        let retired = self.pils.close();
        if retired.iter().any(Option::is_some) {
            failures.record(Stage::Identity, Box::new(io::Error::other("PILS observation-only client unexpectedly retained an application operation at close")));
        }
        if let Err(error) = self.resolver.disconnect() {
            failures.record(Stage::Resolver, Box::new(error));
        }
        self.native_resolver_diagnostics();
    }
}
