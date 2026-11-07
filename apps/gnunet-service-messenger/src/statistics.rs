//! Official six nonpersistent keys through the existing bounded native owner.
use crate::Failure;
use gnunet_client::statistics_handle::{DestroyOutcome, DestroyReport, GetFlow};
use gnunet_client_host::resolution::SharedResolution;
use gnunet_ipc_unix::{IpcError, handle};
use gnunet_messenger_service_host::server::Statistics;
use gnunet_program_host::reporting::Reporter;
use gnunet_resolver_broker::{Driver as ResolverDriver, LiveConfiguration};
use std::{
    future::{Future, poll_fn},
    io,
    task::{Context, Poll},
};
use tokio::time::Instant;
type Native<'id> = handle::StatisticsHandle<'id, 8, 64, 1, 1, 8>;
const COUNTERS: [&[u8]; 4] = [
    b"# room openings",
    b"# room entries",
    b"# room closings",
    b"# message notifications",
];
#[derive(Debug)]
struct Loss {
    epoch: u64,
    cause: gnunet_types::Error,
}
impl std::fmt::Display for Loss {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "original statistics epoch={} cause={:?}",
            self.epoch, self.cause
        )
    }
}
#[derive(Debug)]
struct Errors {
    original: Option<IpcError>,
    loss: Option<Loss>,
    subsequent: Option<IpcError>,
    transport: Option<io::Error>,
    connection: Option<IpcError>,
    destroyed: Option<DestroyReport>,
    cleanup: Option<IpcError>,
}
impl std::fmt::Display for Errors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MESSENGER STATISTICS loss=")?;
        if let Some(loss) = &self.loss {
            write!(f, "{loss}")?;
        } else {
            f.write_str("none")?;
        }
        write!(
            f,
            "; original={:?}; subsequent={:?}; transport={:?}; connection={:?}; destroyed={:?}; cleanup={:?}",
            self.original,
            self.subsequent,
            self.transport,
            self.connection,
            self.destroyed,
            self.cleanup
        )
    }
}
impl std::error::Error for Errors {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original
            .as_ref()
            .map(|error| error as &dyn std::error::Error)
            .or_else(|| {
                self.loss
                    .as_ref()
                    .map(|loss| &loss.cause as &dyn std::error::Error)
            })
            .or_else(|| {
                self.subsequent
                    .as_ref()
                    .map(|error| error as &dyn std::error::Error)
            })
            .or_else(|| {
                self.transport
                    .as_ref()
                    .map(|error| error as &dyn std::error::Error)
            })
            .or_else(|| {
                self.connection
                    .as_ref()
                    .map(|error| error as &dyn std::error::Error)
            })
            .or_else(|| {
                self.cleanup
                    .as_ref()
                    .map(|error| error as &dyn std::error::Error)
            })
    }
}
pub(super) struct Forwarder<'id> {
    owner: Option<Native<'id>>,
    gauges: [Option<u64>; 2],
    admitted: [u64; 4],
    original_error: Option<IpcError>,
    cleanup_error: Option<IpcError>,
    loss: Option<Loss>,
    subsequent: Option<IpcError>,
    transport: Option<io::Error>,
    connection: Option<IpcError>,
    destroyed: Option<DestroyReport>,
    terminal_problem: bool,
    reports: Reporter,
}
impl<'id> Forwarder<'id> {
    pub(super) fn new(
        instance: &'id mut handle::Instance,
        live: LiveConfiguration,
        resolution: SharedResolution,
        reports: Reporter,
    ) -> Result<Self, IpcError> {
        // The selected source provides the same original Resolver/clock domain.
        let owner = Native::from_live_config(
            instance,
            live,
            resolution,
            b"messenger",
            handle::Limits {
                max_frame_bytes: 256,
                write_chunk_bytes: 256,
            },
        )?;
        Ok(Self {
            owner,
            gauges: [None; 2],
            admitted: [0; 4],
            original_error: None,
            cleanup_error: None,
            loss: None,
            subsequent: None,
            transport: None,
            connection: None,
            destroyed: None,
            terminal_problem: false,
            reports,
        })
    }
    fn stop_owner(&mut self) {
        if let Some(mut owner) = self.owner.take() {
            // Borrowed drive has ended. Preserve real native detail before the
            // same original owner is physically retired and dropped.
            if self.transport.is_none() {
                self.transport = owner.take_io_error();
            }
            if self.connection.is_none() {
                self.connection = owner.take_connect_error();
            }
            if !owner.is_closed()
                && let Err(error) = owner.destroy(false)
                && self.cleanup_error.is_none()
            {
                self.cleanup_error = Some(error);
            }
        }
        // Permanent allocation fence: refresh cannot create a replacement MQ.
        // Admitted/partial relative frames remain uncertain and are never replayed.
    }
    fn fail(&mut self, error: IpcError) {
        self.reports.warning(
            "messenger.statistics.failed",
            format_args!("messenger STATISTICS stopped: {error}"),
        );
        if self.original_error.is_none() {
            self.original_error = Some(error);
        }
        self.stop_owner();
    }
    fn admit(&mut self, observed: Statistics) -> Result<(), IpcError> {
        let Some(owner) = self.owner.as_mut() else {
            return Ok(());
        };
        for (i, value) in [observed.handles_connected, observed.rooms_active]
            .into_iter()
            .enumerate()
        {
            if self.gauges[i] != Some(value) {
                owner.set(
                    if i == 0 {
                        b"# handles connected"
                    } else {
                        b"# rooms active"
                    },
                    value,
                    false,
                )?;
                self.gauges[i] = Some(value);
            }
        }
        for (i, value) in [
            observed.room_openings,
            observed.room_entries,
            observed.room_closings,
            observed.message_notifications,
        ]
        .into_iter()
        .enumerate()
        {
            let delta = value.saturating_sub(self.admitted[i]).min(i64::MAX as u64);
            if delta != 0 {
                let signed = i64::try_from(delta).map_err(|_| {
                    IpcError::Io(std::io::Error::other("STATISTICS delta overflow"))
                })?;
                owner.update(COUNTERS[i], signed, false)?;
                self.admitted[i] += delta;
            }
        }
        Ok(())
    }
    pub(super) fn refresh(&mut self, observed: Statistics) {
        if let Err(error) = self.admit(observed) {
            self.fail(error)
        }
    }
    pub(super) fn poll(&mut self, cx: &mut Context<'_>, until: Option<Instant>) -> Poll<()> {
        let mut lost = None;
        let mut destroyed = None;
        let result = {
            let Some(owner) = self.owner.as_mut() else {
                return Poll::Pending;
            };
            // A closed native owner may still own the original Destroyed event;
            // drive it once instead of losing that factual terminal report.
            if owner.is_idle() && !owner.is_closed() {
                return Poll::Pending;
            }
            let mut driving = std::pin::pin!(owner.drive(until, |event, _| {
                self.reports.debug(
                    "messenger.statistics.event",
                    format_args!("messenger STATISTICS={event:?}"),
                );
                match event {
                    handle::Event::ConnectionLost { epoch, cause } => {
                        lost = Some(Loss {
                            epoch: epoch.value(),
                            cause,
                        })
                    }
                    handle::Event::Destroyed(report) => destroyed = Some(report),
                    _ => {}
                }
                GetFlow::Continue
            }));
            driving.as_mut().poll(cx)
        };
        // No new setter, destroy or owner drop while its original future borrows it.
        if let Some(loss) = lost {
            self.reports.warning(
                "messenger.statistics.source_lost",
                format_args!("messenger {loss}; original publisher permanently fenced"),
            );
            self.loss = Some(loss);
            if let Poll::Ready(Err(error)) = result {
                self.subsequent = Some(error);
            }
            if let Some(report) = destroyed {
                self.destroyed = Some(report);
            }
            self.stop_owner();
            return Poll::Ready(());
        }
        if let Some(report) = destroyed {
            self.destroyed = Some(report);
            self.terminal_problem = report.queued_mutations_discarded != 0
                || matches!(
                    report.outcome,
                    DestroyOutcome::Deadline | DestroyOutcome::ConnectionLost
                );
            if self.terminal_problem {
                self.reports.warning("messenger.statistics.terminal", format_args!("messenger original STATISTICS terminal={report:?}; processing/durability not inferred"));
            }
            if let Poll::Ready(Err(error)) = result {
                self.original_error = Some(error);
            }
            self.stop_owner();
            return Poll::Ready(());
        }
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(handle::Progress::Closed)) => {
                self.fail(IpcError::Closed);
                Poll::Ready(())
            }
            Poll::Ready(Ok(_)) => Poll::Ready(()),
            Poll::Ready(Err(error)) => {
                self.fail(error);
                Poll::Ready(())
            }
        }
    }
    /// Exact original terminal native report. Unconfirmed mutations are metadata,
    /// never remote acceptance, persistence or a reason to replay old deltas.
    pub(super) fn destroy_report(&self) -> Option<DestroyReport> {
        self.destroyed
    }
    /// Finish the original native owner's best-effort processing barrier under
    /// an independent finite native cleanup limit. Confirmation is not persistence.
    /// A logging failure cannot skip physical close or trigger a delta replay.
    pub(super) async fn finish(
        &mut self,
        resolver: &mut ResolverDriver<8, 256>,
        until: Instant,
    ) -> Option<Failure> {
        if let Some(owner) = self.owner.as_mut()
            && !owner.is_closed()
            && let Err(error) = owner.destroy(true)
        {
            self.fail(error)
        }
        let mut alarm = std::pin::pin!(tokio::time::sleep_until(until));
        let reports = self.reports.clone();
        let mut resolver_first = false;
        // Even immediate native destruction owns a pending Destroyed event.
        // Keep the original allocation until poll consumes that actual report.
        while self.owner.is_some() && !reports.failed() {
            let result = {
                let mut resolving =
                    std::pin::pin!(resolver.drive_waiting(Some(until), |event| reports.debug(
                        "messenger.statistics.resolver",
                        format_args!("messenger cleanup Resolver={event:?}")
                    )));
                poll_fn(|cx| {
                    reports.register(cx);
                    if reports.failed()
                        || Instant::now() >= until
                        || alarm.as_mut().poll(cx).is_ready()
                    {
                        return Poll::Ready(Ok(false));
                    }
                    for n in 0..2 {
                        if reports.failed() {
                            return Poll::Ready(Ok(false));
                        }
                        if (n == 0) == resolver_first {
                            if let Poll::Ready(result) = resolving.as_mut().poll(cx) {
                                return Poll::Ready(result.map(|_| true));
                            }
                        } else if self.poll(cx, Some(until)).is_ready() {
                            return Poll::Ready(Ok(true));
                        }
                    }
                    Poll::Pending
                })
                .await
            };
            resolver_first = !resolver_first;
            match result {
                Ok(false) => break,
                Ok(true) => {}
                Err(error) => {
                    // Retain this actual Resolver failure independently of any
                    // Stats failure; physical Stats close still happens below.
                    self.stop_owner();
                    let stats = self.close();
                    return Some(Box::new(FinishError {
                        resolver: Box::new(error),
                        statistics: stats,
                    }));
                }
            }
        }
        self.close()
    }
    pub(super) fn close(&mut self) -> Option<Failure> {
        self.stop_owner();
        let original = self.original_error.take();
        let loss = self.loss.take();
        let subsequent = self.subsequent.take();
        let transport = self.transport.take();
        let connection = self.connection.take();
        let cleanup = self.cleanup_error.take();
        let terminal_problem = std::mem::take(&mut self.terminal_problem);
        if original.is_none()
            && loss.is_none()
            && subsequent.is_none()
            && transport.is_none()
            && connection.is_none()
            && cleanup.is_none()
            && !terminal_problem
        {
            None
        } else {
            Some(Box::new(Errors {
                original,
                loss,
                subsequent,
                transport,
                connection,
                destroyed: self.destroyed,
                cleanup,
            }))
        }
    }
}
#[derive(Debug)]
struct FinishError {
    resolver: Failure,
    statistics: Option<Failure>,
}
impl std::fmt::Display for FinishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MESSENGER STATISTICS cleanup Resolver={}; STATISTICS={:?}",
            self.resolver, self.statistics
        )
    }
}
impl std::error::Error for FinishError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.resolver.as_ref())
    }
}
