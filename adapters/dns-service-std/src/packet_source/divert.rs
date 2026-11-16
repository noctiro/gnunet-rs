//! Windows capture/injection with immutable upstream exemptions and original routes.
use super::{Packet, PacketExposure, PendingOutput, Retirement, Route, SourceEvent, Write};
use crate::{Error, Upstream, core};
use gnunet_dnsstub_host::SocketReservations;
use gnunet_native::windivert::{Completion, Driver, Limits, Request, Session};
use gnunet_service_runtime::framing::OwnedFrame;
use gnunet_types::Error as Fault;
use std::{
    ffi::CString,
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::time::{Instant, Sleep};
/// Independent capture shutdown and native-loan retirement observations.
#[derive(Debug, Default)]
pub struct CaptureRetirement {
    /// Original shutdown call failure.
    pub shutdown_error: Option<io::Error>,
    /// Original filter close failure; never retried against a reused handle.
    pub close_error: Option<io::Error>,
    /// First cancellation request failure, independent of completion.
    pub cancellation_error: Option<io::Error>,
    /// First native completion failure beyond normal shutdown cancellation.
    pub completion_error: Option<io::Error>,
    /// Original admitted injection whose delivery was not observed before stop.
    pub pending_packet: Option<usize>,
}
impl CaptureRetirement {
    /// Whether shutdown, cancellation, close or final completion reported a fault.
    pub fn has_failure(&self) -> bool {
        self.shutdown_error.is_some()
            || self.close_error.is_some()
            || self.cancellation_error.is_some()
            || self.completion_error.is_some()
    }
}
const INJECTION_RETIRE_GRACE: std::time::Duration = std::time::Duration::from_secs(5);
const ROUTE_REFRESH: std::time::Duration = std::time::Duration::from_secs(1);
const ROUTE_REFRESH_MIN: std::time::Duration = std::time::Duration::from_millis(100);
enum OutputPhase {
    Active,
    Cancelling { until: Instant },
}
#[derive(Debug)]
struct InjectionExpired {
    completion: io::Result<usize>,
}
impl std::fmt::Display for InjectionExpired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "original injection expired; completion={:?}",
            self.completion
        )
    }
}
impl std::error::Error for InjectionExpired {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.completion.as_ref().err().map(|error| error as _)
    }
}
struct Output<'id> {
    effect: core::Effect<'id>,
    request: Option<Request>,
    bytes: usize,
    until: Instant,
    phase: OutputPhase,
}
pub(super) struct Capture<'id> {
    session: Session,
    reservations: Option<SocketReservations>,
    receive: Option<Request>,
    output: Option<Output<'id>>,
    closing: bool,
    report: Option<CaptureRetirement>,
    timer: Pin<Box<Sleep>>,
    route_timer: Pin<Box<Sleep>>,
    route_attempt: Instant,
}
impl<'id> Capture<'id> {
    pub fn open(
        driver: &Driver,
        reservations: SocketReservations,
        limits: Limits,
    ) -> io::Result<Self> {
        let mut filter = String::from("outbound and udp.DstPort == 53 and not (");
        for (at, (socket, endpoint)) in reservations.endpoints().enumerate() {
            if endpoint.port() == 0 {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            if at != 0 {
                filter.push_str(" or ");
            }
            use std::fmt::Write;
            write!(
                &mut filter,
                "({} and udp.SrcPort == {})",
                match socket.family() {
                    gnunet_dnsstub_host::Family::V4 => "ip",
                    gnunet_dnsstub_host::Family::V6 => "ipv6",
                },
                endpoint.port()
            )
            .map_err(io::Error::other)?;
        }
        if reservations.endpoints().len() == 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        filter.push(')');
        let filter = CString::new(filter).map_err(io::Error::other)?;
        let now = Instant::now();
        let timer = Box::pin(tokio::time::sleep_until(now));
        let route_timer = Box::pin(tokio::time::sleep_until(now + ROUTE_REFRESH));
        let session = match driver.open(&filter, 0, limits) {
            Ok(session) => session,
            Err(error) => {
                if error
                    .get_ref()
                    .and_then(|source| {
                        source.downcast_ref::<gnunet_native::windivert::OpenFailure>()
                    })
                    .is_some_and(|failure| failure.close.is_some())
                {
                    quarantine(reservations);
                }
                return Err(error);
            }
        };
        Ok(Self {
            session,
            reservations: Some(reservations),
            receive: None,
            output: None,
            closing: false,
            report: Some(CaptureRetirement::default()),
            timer,
            route_timer,
            route_attempt: now,
        })
    }
    pub fn matches(&self, stub: &Upstream) -> bool {
        self.reservations
            .as_ref()
            .is_some_and(|lease| lease.belongs_to(stub))
    }
    pub fn initialized(&self) -> bool {
        !self.closing
    }
    pub fn writable(&self) -> bool {
        !self.closing && self.output.is_none()
    }
    pub fn pending(&self) -> Option<PendingOutput<'id>> {
        self.output.as_ref().map(|output| PendingOutput {
            effect: output.effect,
            exposure: PacketExposure::InjectionPending,
            total: output.bytes,
        })
    }
    pub fn queue(
        &mut self,
        effect: core::Effect<'id>,
        frame: OwnedFrame,
        until: Instant,
        route: &Route,
    ) -> Result<(), (Error, OwnedFrame)> {
        if !self.writable() {
            return Err((Fault::WouldBlock.into(), frame));
        }
        if Instant::now() >= until {
            return Err((Fault::Deadline.into(), frame));
        }
        let Route::Captured(address) = route else {
            return Err((Fault::StaleGeneration.into(), frame));
        };
        let mut packet = Vec::new();
        if packet.try_reserve_exact(frame.len()).is_err() {
            return Err((Fault::Capacity.into(), frame));
        }
        packet.extend_from_slice(frame.bytes());
        match self.session.send(packet, address) {
            Ok(request) => {
                self.output = Some(Output {
                    effect,
                    request: Some(request),
                    bytes: frame.len(),
                    until,
                    phase: OutputPhase::Active,
                });
                Ok(())
            }
            Err(error) => Err((error.into(), frame)),
        }
    }
    pub fn cancel_output(&mut self, request: core::Request<'id>) -> Result<(), Error> {
        let output = self
            .output
            .as_mut()
            .filter(|output| output.effect.request() == request)
            .ok_or(Fault::StaleGeneration)?;
        if matches!(output.phase, OutputPhase::Cancelling { .. }) {
            return Ok(());
        }
        let until = output
            .until
            .min(Instant::now())
            .checked_add(INJECTION_RETIRE_GRACE)
            .ok_or(Fault::Overflow)?;
        output
            .request
            .as_mut()
            .ok_or(Fault::StaleGeneration)?
            .request_cancel()?;
        output.phase = OutputPhase::Cancelling { until };
        Ok(())
    }
    pub fn close(&mut self) {
        if self.closing {
            return;
        }
        self.closing = true;
        let Some(report) = &mut self.report else {
            return;
        };
        report.pending_packet = self.output.as_ref().map(|output| output.bytes);
        report.shutdown_error = self.session.shutdown().err();
        if let Some(receive) = &mut self.receive {
            report.cancellation_error = receive.request_cancel().err();
        }
        if let Some(output) = &mut self.output
            && let Some(request) = &mut output.request
            && let Err(error) = request.request_cancel()
            && report.cancellation_error.is_none()
        {
            report.cancellation_error = Some(error);
        }
        report.close_error = self.session.close().err();
        if report.close_error.is_some() {
            // Without a confirmed filter close the excluded ports must never be
            // rebound by another query source. Quarantine this finite original
            // lease until process exit; no handle retry or replacement is safe.
            if let Some(reservations) = self.reservations.take() {
                quarantine(reservations);
            }
        }
    }
    fn retain_completion(&mut self, result: io::Result<Completion>) {
        let result = result.map(|completion| {
            if let Completion::Received { mut packet, .. } = completion {
                zeroize::Zeroize::zeroize(&mut packet);
            }
        });
        if let Err(error) = result
            && !matches!(error.raw_os_error(), Some(995 | 232))
            && let Some(report) = &mut self.report
            && report.completion_error.is_none()
        {
            report.completion_error = Some(error);
        }
    }
    pub fn poll_retirement(&mut self, cx: &mut Context<'_>) -> Poll<Retirement> {
        if !self.closing {
            return Poll::Pending;
        }
        if let Some(receive) = &mut self.receive
            && let Poll::Ready(result) = receive.poll_complete(cx)
        {
            self.receive = None;
            self.retain_completion(result);
        }
        if let Some(output) = &mut self.output {
            match output
                .request
                .as_mut()
                .map(|request| request.poll_complete(cx))
            {
                Some(Poll::Pending) => {}
                completed => {
                    self.output = None;
                    if let Some(Poll::Ready(result)) = completed {
                        self.retain_completion(result);
                    }
                }
            }
        }
        self.take_retirement().map_or(Poll::Pending, Poll::Ready)
    }
    pub fn take_retirement(&mut self) -> Option<Retirement> {
        if self.closing
            && self.receive.is_none()
            && self
                .output
                .as_ref()
                .is_none_or(|output| output.request.is_none())
        {
            self.output = None;
            return self.report.take().map(Retirement::Capture);
        }
        None
    }
    pub fn poll_guard(&mut self, cx: &mut Context<'_>) -> Poll<SourceEvent<'id>> {
        if self.closing {
            return self.poll_retirement(cx).map(SourceEvent::Retired);
        }
        // This only observes already admitted native I/O; retirement must not
        // depend on a fresh canonical-clock sample or new packet admission.
        if let ready @ Poll::Ready(_) = self.write(cx) {
            return ready;
        }
        if let Some(output) = &self.output {
            let until = match output.phase {
                OutputPhase::Active => output.until,
                OutputPhase::Cancelling { until } => until,
            };
            if Instant::now() >= until {
                if matches!(output.phase, OutputPhase::Active) {
                    return Poll::Ready(match self.cancel_output(output.effect.request()) {
                        Ok(()) => SourceEvent::Activity,
                        Err(error) => SourceEvent::Failed(io::Error::other(error)),
                    });
                }
                return Poll::Ready(SourceEvent::Failed(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "original canceled injection did not retire",
                )));
            }
            self.timer.as_mut().reset(until);
            if self.timer.as_mut().poll(cx).is_ready() {
                cx.waker().wake_by_ref();
            }
        }
        Poll::Pending
    }
    fn read(&mut self, cx: &mut Context<'_>) -> Poll<SourceEvent<'id>> {
        if self.receive.is_none() {
            match self.session.receive(65575) {
                Ok(request) => self.receive = Some(request),
                Err(error) => return Poll::Ready(SourceEvent::Failed(error)),
            }
        }
        let result = match self.receive.as_mut() {
            Some(request) => request.poll_complete(cx),
            None => Poll::Pending,
        };
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.receive = None;
                match result {
                    Ok(Completion::Received { packet, address }) => {
                        let mut packet = zeroize::Zeroizing::new(packet);
                        let parsed = match gnunet_vpn::packet::Packet::parse(&packet) {
                            Ok(parsed) => parsed,
                            Err(_) => return Poll::Ready(SourceEvent::Activity),
                        };
                        if parsed.protocol() != gnunet_vpn::packet::UDP
                            || !parsed.ports().is_ok_and(|ports| ports.1 == 53)
                        {
                            return Poll::Ready(SourceEvent::Activity);
                        }
                        let segment = parsed.segment();
                        if segment.len() < 8
                            || usize::from(u16::from_be_bytes([segment[4], segment[5]]))
                                != segment.len()
                        {
                            return Poll::Ready(SourceEvent::Activity);
                        }
                        let (source, destination) = (parsed.source(), parsed.destination());
                        if (source.family() == gnunet_vpn::packet::Family::V6) != address.ipv6() {
                            return Poll::Ready(SourceEvent::Failed(io::Error::other(
                                "capture packet/metadata family mismatch",
                            )));
                        }
                        let (ip_valid, udp_valid) = address.checksums();
                        if ((!address.ipv6() && !ip_valid) || !udp_valid)
                            && let Err(error) =
                                gnunet_vpn::packet::rewrite(&mut packet, source, destination, None)
                        {
                            return Poll::Ready(SourceEvent::Failed(io::Error::other(error)));
                        }
                        let route = match address.reply() {
                            Ok(route) => route,
                            Err(error) => {
                                let next =
                                    Instant::now().max(self.route_attempt + ROUTE_REFRESH_MIN);
                                if next < self.route_timer.deadline() {
                                    self.route_timer.as_mut().reset(next);
                                }
                                return Poll::Ready(SourceEvent::Refused(
                                    io::Error::other(error).into(),
                                ));
                            }
                        };
                        Poll::Ready(SourceEvent::Packet(Packet::captured(
                            std::mem::take(&mut *packet),
                            route,
                        )))
                    }
                    Ok(_) => Poll::Ready(SourceEvent::Failed(io::Error::other(
                        "capture receive returned an injection receipt",
                    ))),
                    Err(error) => Poll::Ready(SourceEvent::Failed(error)),
                }
            }
        }
    }
    fn write(&mut self, cx: &mut Context<'_>) -> Poll<SourceEvent<'id>> {
        let Some(output) = &mut self.output else {
            return Poll::Pending;
        };
        let Some(request) = &mut output.request else {
            return Poll::Pending;
        };
        let result = match request.poll_complete(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result,
        };
        let Some(mut output) = self.output.take() else {
            return Poll::Pending;
        };
        output.request = None;
        let result = match result {
            Ok(Completion::Sent { bytes }) if bytes == output.bytes => Ok(bytes),
            Ok(Completion::Received { mut packet, .. }) => {
                zeroize::Zeroize::zeroize(&mut packet);
                self.output = Some(output);
                return Poll::Ready(SourceEvent::Failed(io::Error::other(
                    "capture injection returned a receive receipt",
                )));
            }
            Ok(_) => Err(io::Error::other(
                "capture injection did not match original extent",
            )),
            Err(error) => Err(error),
        };
        let result = match result {
            Err(error)
                if error.get_ref().is_some_and(|cause| {
                    cause.is::<gnunet_native::windivert::InjectionLengthError>()
                }) =>
            {
                self.output = Some(output);
                return Poll::Ready(SourceEvent::Failed(error));
            }
            result => result,
        };
        if matches!(output.phase, OutputPhase::Cancelling { .. }) || Instant::now() >= output.until
        {
            let exposure = if result.is_ok() {
                PacketExposure::InjectionAccepted
            } else {
                PacketExposure::InjectionPending
            };
            return Poll::Ready(SourceEvent::OutputStopped {
                effect: output.effect,
                exposure,
                total: output.bytes,
                reason: io::Error::new(
                    io::ErrorKind::TimedOut,
                    InjectionExpired { completion: result },
                )
                .into(),
            });
        }
        match result {
            Ok(bytes) => Poll::Ready(SourceEvent::Written {
                effect: output.effect,
                observation: Write::Injection { bytes },
            }),
            Err(error) if matches!(error.raw_os_error(), Some(1231 | 1232 | 1168)) => {
                Poll::Ready(SourceEvent::OutputStopped {
                    effect: output.effect,
                    exposure: PacketExposure::InjectionPending,
                    total: output.bytes,
                    reason: error.into(),
                })
            }
            Err(error) => {
                self.output = Some(output);
                Poll::Ready(SourceEvent::Failed(error))
            }
        }
    }
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<SourceEvent<'id>> {
        if let ready @ Poll::Ready(_) = self.poll_guard(cx) {
            return ready;
        }
        if self.closing {
            return Poll::Pending;
        }
        if self.route_timer.as_mut().poll(cx).is_ready() {
            self.route_attempt = Instant::now();
            self.route_timer
                .as_mut()
                .reset(self.route_attempt + ROUTE_REFRESH);
            return Poll::Ready(match self.session.refresh_routes() {
                Ok(()) => SourceEvent::Activity,
                Err(error) => SourceEvent::RouteObservationFailed(error),
            });
        }
        self.read(cx)
    }
}
impl Drop for Capture<'_> {
    fn drop(&mut self) {
        self.close();
    }
}

#[expect(
    clippy::mem_forget,
    reason = "An unconfirmed native filter close must retain its finite original port exemptions until process exit; rebinding or retrying a possibly reused handle is unsafe"
)]
fn quarantine(reservations: SocketReservations) {
    std::mem::forget(reservations);
}
