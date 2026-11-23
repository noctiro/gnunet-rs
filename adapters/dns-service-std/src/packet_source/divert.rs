//! Windows capture/injection with immutable upstream exemptions and original routes.
mod retirement;

use super::{PacketExposure, PendingOutput, Retirement, Route, SourceEvent, Write, raw};
use crate::{Error, Upstream, core};
use gnunet_dnsstub_host::SocketReservations;
use gnunet_native::windivert::{Completion, Driver, Limits, Request, Session};
use gnunet_service_runtime::framing::OwnedFrame;
use gnunet_types::Error as Fault;
use retirement::{Cancellation, Job, Receipt, SendRequest, Worker};
use std::{
    ffi::CString,
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll, Waker},
};
use tokio::time::{Instant, Sleep};
/// Independent capture shutdown and native-loan retirement observations.
#[derive(Debug, Default)]
pub struct CaptureRetirement {
    /// Original shutdown call failure.
    pub shutdown_error: Option<io::Error>,
    /// Original filter close failure; never retried against a reused handle.
    pub close_error: Option<io::Error>,
    /// Failure to hand the original job to its worker or observe that worker's exit.
    pub worker_error: Option<io::Error>,
    /// First cancellation request failure, independent of completion.
    pub cancellation_error: Option<io::Error>,
    /// First native completion failure beyond normal shutdown cancellation.
    pub completion_error: Option<io::Error>,
    /// Original admitted injection whose complete native acceptance was not observed.
    pub pending_packet: Option<usize>,
    /// Whole native injection accepted during shutdown. No delivery is inferred.
    pub accepted_injection: Option<usize>,
    /// The original receive completion was still unobserved at the shutdown deadline.
    pub unconfirmed_receive: bool,
    /// Length of the original injection still awaiting native completion at the deadline.
    pub unconfirmed_injection: Option<usize>,
    /// The original native shutdown call had no observed result.
    pub unconfirmed_shutdown: bool,
    /// The original native filter close had no observed result.
    pub unconfirmed_close: bool,
}
impl CaptureRetirement {
    /// Whether shutdown, cancellation, close or final completion reported a fault.
    pub fn has_failure(&self) -> bool {
        self.shutdown_error.is_some()
            || self.close_error.is_some()
            || self.worker_error.is_some()
            || self.cancellation_error.is_some()
            || self.completion_error.is_some()
            || self.unconfirmed_receive
            || self.unconfirmed_injection.is_some()
            || self.unconfirmed_shutdown
            || self.unconfirmed_close
    }

    fn observe_injection(&mut self, result: io::Result<Completion>, expected: usize) {
        let failure = match result {
            Ok(Completion::Received { mut packet, .. }) => {
                zeroize::Zeroize::zeroize(&mut packet);
                Some(io::Error::other(
                    "capture injection returned a receive receipt during shutdown",
                ))
            }
            Ok(Completion::Sent { bytes }) if expected == bytes => {
                self.accepted_injection = Some(bytes);
                self.pending_packet = None;
                None
            }
            Ok(_) => Some(io::Error::other(
                "capture shutdown returned an inconsistent completion",
            )),
            Err(error) => Some(error),
        };
        if let Some(error) = failure {
            self.record_completion_error(error);
        }
    }

    fn record_completion_error(&mut self, error: io::Error) {
        if !matches!(error.raw_os_error(), Some(995 | 232)) && self.completion_error.is_none() {
            self.completion_error = Some(error);
        }
    }

    fn observe(&mut self, receipt: Receipt) {
        match receipt {
            Receipt::Shutdown(result) => {
                self.unconfirmed_shutdown = false;
                self.shutdown_error = result.err();
            }
            Receipt::Cancellation(Err(error)) => {
                self.cancellation_error.get_or_insert(error);
            }
            Receipt::WorkerFailed(error) => {
                self.worker_error.get_or_insert(error);
            }
            Receipt::Close(result) => {
                self.unconfirmed_close = false;
                self.close_error = result.err();
            }
            Receipt::Receive(result) => {
                self.unconfirmed_receive = false;
                if let Err(error) = result {
                    self.record_completion_error(error);
                }
            }
            Receipt::Send { bytes, result } => {
                self.unconfirmed_injection = None;
                self.observe_injection(result, bytes);
            }
            Receipt::Cancellation(Ok(())) | Receipt::Finished => {}
        }
    }
}
const INJECTION_RETIRE_GRACE: std::time::Duration = std::time::Duration::from_secs(5);
const SHUTDOWN_RETIRE_GRACE: std::time::Duration = std::time::Duration::from_secs(5);
const ROUTE_REFRESH: std::time::Duration = std::time::Duration::from_secs(1);
const ROUTE_REFRESH_MIN: std::time::Duration = std::time::Duration::from_millis(100);
enum OutputPhase {
    Active(Option<Request>),
    AwaitingCancellation {
        ticket: Cancellation,
        stop: InjectionStop,
    },
    Retiring {
        request: Option<Request>,
        stop: InjectionStop,
    },
    CancellationLost(InjectionStop),
}
#[derive(Clone, Copy)]
struct InjectionStop {
    until: Instant,
    reason: StopReason,
}
#[derive(Clone, Copy, Debug)]
enum StopReason {
    Cancelled,
    Deadline,
}
#[derive(Debug)]
struct InjectionStopped {
    reason: StopReason,
    completion: io::Error,
}
impl std::fmt::Display for InjectionStopped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let action = match self.reason {
            StopReason::Cancelled => "cancelled",
            StopReason::Deadline => "expired",
        };
        write!(
            f,
            "original injection {action} (completion={:?})",
            self.completion
        )
    }
}
impl std::error::Error for InjectionStopped {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.completion)
    }
}
struct Output<'id> {
    effect: core::Effect<'id>,
    bytes: usize,
    until: Instant,
    phase: OutputPhase,
}
impl Output<'_> {
    fn fences_native_io(&self) -> bool {
        matches!(
            self.phase,
            OutputPhase::AwaitingCancellation { .. } | OutputPhase::CancellationLost(_)
        )
    }

    fn deadline(&self) -> Instant {
        match &self.phase {
            OutputPhase::Active(_) => self.until,
            OutputPhase::AwaitingCancellation { stop, .. }
            | OutputPhase::Retiring { stop, .. }
            | OutputPhase::CancellationLost(stop) => stop.until,
        }
    }

    fn poll_cancellation(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let OutputPhase::AwaitingCancellation { ticket, stop } = &mut self.phase else {
            return Poll::Ready(Ok(()));
        };
        let result = std::task::ready!(ticket.poll(cx));
        let stop = *stop;
        match result {
            Ok((request, result)) => {
                self.phase = OutputPhase::Retiring {
                    request: Some(request),
                    stop,
                };
                Poll::Ready(result)
            }
            Err(error) => {
                self.phase = OutputPhase::CancellationLost(stop);
                Poll::Ready(Err(error))
            }
        }
    }

    fn into_retirement(self, shutdown_until: Instant) -> Option<retirement::RetiringInjection> {
        let (request, until) = match self.phase {
            OutputPhase::Active(request) => (SendRequest::CancelRequired(request?), shutdown_until),
            OutputPhase::AwaitingCancellation { ticket, stop } => (
                SendRequest::AwaitingCancellation(ticket),
                stop.until.min(shutdown_until),
            ),
            OutputPhase::Retiring { request, stop } => (
                SendRequest::CancelAttempted(request?),
                stop.until.min(shutdown_until),
            ),
            OutputPhase::CancellationLost(_) => return None,
        };
        Some(retirement::RetiringInjection {
            request,
            bytes: self.bytes,
            until,
        })
    }
}
struct Active {
    session: Session,
    reservations: SocketReservations,
    worker: Worker,
    receive: Option<Request>,
}
struct Closing {
    until: Instant,
    receipts: Option<tokio::sync::mpsc::Receiver<Receipt>>,
    report: CaptureRetirement,
}
impl Closing {
    fn poll(&mut self, cx: &mut Context<'_>, timer: Pin<&mut Sleep>) -> Poll<()> {
        let Some(receipts) = &mut self.receipts else {
            return Poll::Ready(());
        };
        loop {
            match receipts.poll_recv(cx) {
                Poll::Ready(Some(Receipt::Finished)) => return Poll::Ready(()),
                Poll::Ready(Some(receipt)) => self.report.observe(receipt),
                Poll::Ready(None) => {
                    self.report.worker_error = Some(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "original WinDivert retirement worker ended without a final receipt",
                    ));
                    return Poll::Ready(());
                }
                Poll::Pending if Instant::now() >= self.until => return Poll::Ready(()),
                Poll::Pending => return timer.poll(cx),
            }
        }
    }
}
enum State {
    Active(Active),
    Closing(Closing),
    Retired,
}
pub(super) struct Capture<'id> {
    state: State,
    output: Option<Output<'id>>,
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
        let worker = Worker::new()?;
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
            state: State::Active(Active {
                session,
                reservations,
                worker,
                receive: None,
            }),
            output: None,
            timer,
            route_timer,
            route_attempt: now,
        })
    }
    pub fn matches(&self, stub: &Upstream) -> bool {
        matches!(&self.state, State::Active(active) if stub
            .standard_owner()
            .is_some_and(|owner| active.reservations.belongs_to(owner)))
    }
    pub fn initialized(&self) -> bool {
        matches!(self.state, State::Active(_))
    }
    pub fn writable(&self) -> bool {
        self.initialized() && self.output.is_none()
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
        let State::Active(active) = &self.state else {
            return Err((Fault::WouldBlock.into(), frame));
        };
        if self.output.is_some() {
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
        match active.session.send(packet, address) {
            Ok(request) => {
                self.output = Some(Output {
                    effect,
                    bytes: frame.len(),
                    until,
                    phase: OutputPhase::Active(Some(request)),
                });
                Ok(())
            }
            Err(error) => Err((error.into(), frame)),
        }
    }
    pub fn cancel_output(&mut self, request: core::Request<'id>) -> Result<(), Error> {
        let State::Active(active) = &self.state else {
            return Err(Fault::StaleGeneration.into());
        };
        let output = self
            .output
            .as_mut()
            .filter(|output| output.effect.request() == request)
            .ok_or(Fault::StaleGeneration)?;
        let OutputPhase::Active(original) = &mut output.phase else {
            return Ok(());
        };
        let now = Instant::now();
        let reason = if now >= output.until {
            StopReason::Deadline
        } else {
            StopReason::Cancelled
        };
        let until = output
            .until
            .min(now)
            .checked_add(INJECTION_RETIRE_GRACE)
            .ok_or(Fault::Overflow)?;
        match active
            .worker
            .cancel(original.take().ok_or(Fault::StaleGeneration)?)
        {
            Ok(ticket) => {
                output.phase = OutputPhase::AwaitingCancellation {
                    ticket,
                    stop: InjectionStop { until, reason },
                };
                Ok(())
            }
            Err((request, error)) => {
                *original = Some(request);
                Err(error.into())
            }
        }
    }
    pub fn close(&mut self) {
        if !self.initialized() {
            return;
        }
        let State::Active(active) = std::mem::replace(&mut self.state, State::Retired) else {
            return;
        };
        let until = Instant::now() + SHUTDOWN_RETIRE_GRACE;
        self.timer.as_mut().reset(until);
        let output = self.output.take();
        let pending_packet = output.as_ref().map(|output| output.bytes);
        let lost = output
            .as_ref()
            .is_some_and(|output| matches!(output.phase, OutputPhase::CancellationLost(_)));
        let send = output.and_then(|output| output.into_retirement(until));
        let mut report = CaptureRetirement {
            pending_packet,
            unconfirmed_receive: active.receive.is_some(),
            unconfirmed_injection: if lost {
                pending_packet
            } else {
                send.as_ref().map(|send| send.bytes)
            },
            unconfirmed_shutdown: true,
            unconfirmed_close: true,
            ..CaptureRetirement::default()
        };
        let receipts = match active.worker.submit(Job {
            session: active.session,
            reservations: active.reservations,
            receive: active.receive,
            send,
            until,
        }) {
            Ok(receipts) => Some(receipts),
            Err(original) => {
                original.quarantine();
                report.worker_error = Some(io::Error::other(
                    "original WinDivert retirement worker did not accept its job",
                ));
                None
            }
        };
        self.state = State::Closing(Closing {
            until,
            receipts,
            report,
        });
    }
    pub fn poll_retirement(&mut self, cx: &mut Context<'_>) -> Poll<Retirement> {
        let State::Closing(closing) = &mut self.state else {
            return Poll::Pending;
        };
        std::task::ready!(closing.poll(cx, self.timer.as_mut()));
        let State::Closing(closing) = std::mem::replace(&mut self.state, State::Retired) else {
            return Poll::Pending;
        };
        Poll::Ready(Retirement::Capture(closing.report))
    }
    pub fn take_retirement(&mut self) -> Option<Retirement> {
        match self.poll_retirement(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(retirement) => Some(retirement),
            Poll::Pending => None,
        }
    }
    pub fn poll_guard(&mut self, cx: &mut Context<'_>) -> Poll<SourceEvent<'id>> {
        if !self.initialized() {
            return self.poll_retirement(cx).map(SourceEvent::Retired);
        }
        // This only observes already admitted native I/O; retirement must not
        // depend on a fresh canonical-clock sample or new packet admission.
        if let Some(output) = &mut self.output
            && let Poll::Ready(Err(error)) = output.poll_cancellation(cx)
        {
            return Poll::Ready(SourceEvent::Failed(error));
        }
        if let ready @ Poll::Ready(_) = self.write(cx) {
            return ready;
        }
        if let Some(output) = &self.output {
            let until = output.deadline();
            if Instant::now() >= until {
                if matches!(output.phase, OutputPhase::Active(_)) {
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
        let State::Active(active) = &mut self.state else {
            return Poll::Pending;
        };
        if active.receive.is_none() {
            match active.session.receive(65575) {
                Ok(request) => active.receive = Some(request),
                Err(error) => return Poll::Ready(SourceEvent::Failed(error)),
            }
        }
        let result = match active.receive.as_mut() {
            Some(request) => request.poll_complete(cx),
            None => Poll::Pending,
        };
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                active.receive = None;
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
                        Poll::Ready(SourceEvent::Input(raw::captured(
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
        let request = match &mut output.phase {
            OutputPhase::Active(request) | OutputPhase::Retiring { request, .. } => request,
            OutputPhase::AwaitingCancellation { .. } | OutputPhase::CancellationLost(_) => {
                return Poll::Pending;
            }
        };
        let Some(original) = request else {
            return Poll::Pending;
        };
        let result = match original.poll_complete(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result,
        };
        if let Some(original) = request.take() {
            original.detach();
        }
        let Some(output) = self.output.take() else {
            return Poll::Pending;
        };
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
        let stop = match &output.phase {
            OutputPhase::Retiring { stop, .. } => Some(stop.reason),
            _ => (Instant::now() >= output.until).then_some(StopReason::Deadline),
        };
        if let Some(reason) = stop {
            let exposure = if result.is_ok() {
                PacketExposure::InjectionAccepted
            } else {
                PacketExposure::InjectionPending
            };
            return Poll::Ready(SourceEvent::OutputStopped {
                effect: output.effect,
                exposure,
                total: output.bytes,
                reason: match result {
                    Ok(_) => match reason {
                        StopReason::Cancelled => Fault::Cancelled,
                        StopReason::Deadline => Fault::Deadline,
                    }
                    .into(),
                    Err(error) => {
                        let kind = match reason {
                            StopReason::Cancelled => io::ErrorKind::Other,
                            StopReason::Deadline => io::ErrorKind::TimedOut,
                        };
                        io::Error::new(
                            kind,
                            InjectionStopped {
                                reason,
                                completion: error,
                            },
                        )
                        .into()
                    }
                },
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
        if self.output.as_ref().is_some_and(Output::fences_native_io) {
            return Poll::Pending;
        }
        let State::Active(active) = &self.state else {
            return Poll::Pending;
        };
        if self.route_timer.as_mut().poll(cx).is_ready() {
            self.route_attempt = Instant::now();
            self.route_timer
                .as_mut()
                .reset(self.route_attempt + ROUTE_REFRESH);
            return Poll::Ready(match active.session.refresh_routes() {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_distinguishes_native_acceptance_and_uncertain_exposure() {
        let mut accepted = CaptureRetirement {
            pending_packet: Some(64),
            ..CaptureRetirement::default()
        };
        accepted.observe_injection(Ok(Completion::Sent { bytes: 64 }), 64);
        assert_eq!(accepted.accepted_injection, Some(64));
        assert_eq!(accepted.pending_packet, None);
        assert!(!accepted.has_failure());

        let mut uncertain = CaptureRetirement {
            pending_packet: Some(64),
            ..CaptureRetirement::default()
        };
        uncertain.observe_injection(Err(io::Error::from_raw_os_error(995)), 64);
        assert_eq!(uncertain.accepted_injection, None);
        assert_eq!(uncertain.pending_packet, Some(64));
        assert!(!uncertain.has_failure());
        uncertain.observe_injection(Ok(Completion::Sent { bytes: 63 }), 64);
        assert_eq!(uncertain.pending_packet, Some(64));
        assert!(uncertain.has_failure());
    }

    #[test]
    fn either_remaining_native_waiter_makes_shutdown_unconfirmed() {
        let receive = CaptureRetirement {
            unconfirmed_receive: true,
            ..CaptureRetirement::default()
        };
        let injection = CaptureRetirement {
            pending_packet: Some(64),
            unconfirmed_injection: Some(64),
            ..CaptureRetirement::default()
        };
        assert!(receive.has_failure());
        assert!(injection.has_failure());
    }

    #[test]
    fn retirement_deadline_preserves_observed_shutdown_and_unconfirmed_close() -> io::Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()?;
        let _runtime = runtime.enter();
        let (sender, receipts) = tokio::sync::mpsc::channel(1);
        sender
            .try_send(Receipt::Shutdown(Ok(())))
            .map_err(io::Error::other)?;
        let until = Instant::now();
        let mut timer = Box::pin(tokio::time::sleep_until(until));
        let mut closing = Closing {
            until,
            receipts: Some(receipts),
            report: CaptureRetirement {
                unconfirmed_shutdown: true,
                unconfirmed_close: true,
                unconfirmed_receive: true,
                unconfirmed_injection: Some(64),
                pending_packet: Some(64),
                ..CaptureRetirement::default()
            },
        };
        let result = closing.poll(&mut Context::from_waker(Waker::noop()), timer.as_mut());
        let report = closing.report;
        if result.is_pending()
            || report.unconfirmed_shutdown
            || !report.unconfirmed_close
            || !report.unconfirmed_receive
            || report.unconfirmed_injection != Some(64)
            || report.pending_packet != Some(64)
            || report.worker_error.is_some()
        {
            return Err(io::Error::other(
                "retirement cutoff changed the original native observations",
            ));
        }
        drop(sender);
        Ok(())
    }
}
