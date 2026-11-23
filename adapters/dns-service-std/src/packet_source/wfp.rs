//! Actual started WFP device ownership and original service completion correlation.
use super::{
    Error, OriginalInput, PacketExposure, PendingOutput, ReplyPermit, Retirement, SourceEvent,
    Write, core, input,
};
use crate::Upstream;
use gnunet_dnsstub_host::SocketReservations;
use gnunet_native::event_wait::Wait;
use gnunet_service_runtime::framing::OwnedFrame;
use gnunet_types::Error as Fault;
use gnunet_wfp_dns::device as record;
use gnunet_wfp_dns_host::device::{self, Started};
use std::{
    io,
    os::windows::io::{AsRawSocket, AsSocket},
    pin::Pin,
    sync::Arc,
    time::Duration,
};
use tokio::{
    sync::oneshot,
    time::{Instant, Sleep},
};

mod connect;
mod poll;
mod recovery;
mod report;
mod retirement;
mod token;
mod worker;
pub use report::WfpRetirement;
pub(super) use token::Endpoint;
use token::{Owner, Token};

/// Bounded original WFP return owners and service retirement observation time.
#[derive(Clone, Copy, Debug)]
pub struct WfpLimits {
    /// Maximum dequeued requests retained by this service source.
    pub requests: usize,
    /// Observation budget for each initial or replacement device open and START.
    pub open_timeout: Duration,
    /// Observation budget for a canceled reply and for closing an original file.
    /// Native calls still running at shutdown retain their original owners.
    pub retirement_timeout: Duration,
}
impl Default for WfpLimits {
    fn default() -> Self {
        Self {
            requests: 32,
            open_timeout: Duration::from_secs(5),
            retirement_timeout: Duration::from_secs(5),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StopRequest {
    Cancelled,
    Deadline,
}

impl StopRequest {
    const fn fault(self) -> Fault {
        match self {
            Self::Cancelled => Fault::Cancelled,
            Self::Deadline => Fault::Deadline,
        }
    }
}

#[derive(Clone, Copy)]
struct Cancellation {
    reason: StopRequest,
    retire_at: Instant,
}

enum Phase {
    Queued(OwnedFrame),
    DiscardQueued(StopRequest),
    Submitted,
    CancelRequested(Cancellation),
    Cancelling {
        cancellation: Cancellation,
        error: Option<device::Error>,
    },
}

impl Phase {
    fn is_submitted(&self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::CancelRequested(_) | Self::Cancelling { .. }
        )
    }

    fn request_cancel(
        &mut self,
        reason: StopRequest,
        hard_deadline: Instant,
        now: Instant,
        grace: Duration,
    ) {
        *self = match self {
            Self::Queued(_) => Self::DiscardQueued(reason),
            Self::Submitted => Self::CancelRequested(Cancellation {
                reason,
                retire_at: hard_deadline.min(now).checked_add(grace).unwrap_or(now),
            }),
            _ => return,
        };
    }

    fn cancellation(&self) -> Option<Cancellation> {
        match self {
            Self::CancelRequested(cancellation) | Self::Cancelling { cancellation, .. } => {
                Some(*cancellation)
            }
            _ => None,
        }
    }

    fn cancellation_deadline(&self) -> Option<Instant> {
        self.cancellation()
            .map(|cancellation| cancellation.retire_at)
    }

    fn stop_request(&self) -> Option<StopRequest> {
        match self {
            Self::DiscardQueued(reason) => Some(*reason),
            _ => self.cancellation().map(|cancellation| cancellation.reason),
        }
    }

    fn begin_cancel(&mut self, now: Instant) -> io::Result<bool> {
        let Some(cancellation) = self.cancellation() else {
            return Ok(false);
        };
        if now >= cancellation.retire_at {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original canceled WFP reply did not retire",
            ));
        }
        if !matches!(self, Self::CancelRequested(_)) {
            return Ok(false);
        }
        *self = Self::Cancelling {
            cancellation,
            error: None,
        };
        Ok(true)
    }

    fn cancellation_error(&self) -> Option<device::Error> {
        match self {
            Self::Cancelling { error, .. } => *error,
            _ => None,
        }
    }
}
struct Output<'id> {
    effect: core::Effect<'id>,
    endpoint: Endpoint,
    bytes: usize,
    until: Instant,
    phase: Phase,
}

pub(super) struct Wfp<'id> {
    // Drop the original channel before releasing the host socket lease. Kernel
    // handle custody survives it until STOP or original FILE_OBJECT cleanup.
    started: Option<Started>,
    reservations: Option<Arc<SocketReservations>>,
    owner: Arc<Owner>,
    slots: Vec<Option<Arc<Token>>>,
    read_buffer: Vec<u8>,
    write_buffer: Vec<u8>,
    wait: Option<Wait>,
    output: Option<Output<'id>>,
    startup_error: Option<io::Error>,
    ready: bool,
    closing: bool,
    report: Option<WfpRetirement>,
    limits: WfpLimits,
    retirement_until: Option<Instant>,
    worker: worker::Worker,
    retiring: Option<oneshot::Receiver<worker::Receipt>>,
    timer: Pin<Box<Sleep>>,
    recovery: Option<recovery::Recovery>,
}

impl<'id> Wfp<'id> {
    pub async fn open(reservations: SocketReservations, limits: WfpLimits) -> io::Result<Self> {
        let now = Instant::now();
        if !(1..=usize::from(u16::MAX)).contains(&limits.requests)
            || limits.retirement_timeout.is_zero()
            || now.checked_add(limits.retirement_timeout).is_none()
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let until = now
            .checked_add(limits.open_timeout)
            .filter(|target| *target > now)
            .ok_or(io::ErrorKind::InvalidInput)?;
        // Start the single retirement worker before any live capture exists.
        let worker = worker::Worker::new()?;
        let started = connect::open(&reservations, until).await?;
        Ok(Self::adopt(started, reservations, limits, worker, until))
    }

    fn adopt(
        started: Started,
        reservations: SocketReservations,
        limits: WfpLimits,
        worker: worker::Worker,
        until: Instant,
    ) -> Self {
        let mut source = Self {
            started: Some(started),
            reservations: Some(Arc::new(reservations)),
            owner: Arc::new(Owner::new()),
            slots: Vec::new(),
            read_buffer: Vec::new(),
            write_buffer: Vec::new(),
            wait: None,
            output: None,
            startup_error: None,
            ready: false,
            closing: false,
            report: Some(WfpRetirement::default()),
            limits,
            retirement_until: None,
            worker,
            retiring: None,
            timer: Box::pin(tokio::time::sleep_until(Instant::now())),
            recovery: None,
        };
        match source.prepare() {
            Ok(()) if Instant::now() < until => source.ready = true,
            Ok(()) => source.startup_error = Some(connect::start_timeout()),
            Err(error) => source.startup_error = Some(error),
        }
        source
    }

    fn prepare(&mut self) -> io::Result<()> {
        let started = self.started.as_ref().ok_or(io::ErrorKind::NotConnected)?;
        self.verify_started(started)?;
        self.slots
            .try_reserve_exact(self.limits.requests)
            .map_err(io::Error::other)?;
        self.slots.resize_with(self.limits.requests, || None);
        for buffer in [&mut self.read_buffer, &mut self.write_buffer] {
            buffer
                .try_reserve_exact(record::MAX_RECORD_BYTES)
                .map_err(io::Error::other)?;
            buffer.resize(record::MAX_RECORD_BYTES, 0);
        }
        self.wait = Some(started.event_wait()?);
        Ok(())
    }

    fn verify_started(&self, started: &Started) -> io::Result<()> {
        let reservations = self
            .reservations
            .as_ref()
            .ok_or(io::ErrorKind::NotConnected)?;
        if started.is_stopped() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let expected = started.upstreams();
        if reservations.sockets().len() != expected.len() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        for (socket, expected) in reservations.sockets().zip(expected) {
            // The internal factory passed these same retained socket objects
            // to START. Their live owners exclude handle reuse between that
            // native endpoint validation and this infallible identity check.
            if socket.as_socket().as_raw_socket() as usize as u64 != expected.socket.get() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "WFP START does not match the original reserved DNSSTUB sockets",
                ));
            }
        }
        Ok(())
    }

    pub fn initialized(&self) -> bool {
        self.ready && !self.closing
    }
    pub fn writable(&self) -> bool {
        self.initialized() && self.output.is_none()
    }
    pub fn take_startup_error(&mut self) -> Option<io::Error> {
        self.startup_error.take()
    }
    pub fn matches(&self, stub: &Upstream) -> bool {
        self.reservations.as_ref().is_some_and(|lease| {
            stub.standard_owner()
                .is_some_and(|owner| lease.belongs_to(owner))
        })
    }
    pub fn accepts(&self, endpoint: &Endpoint) -> bool {
        self.initialized()
            && endpoint.token.belongs_to(&self.owner)
            && endpoint.token.held()
            && self
                .slots
                .get(endpoint.token.index)
                .and_then(Option::as_ref)
                .is_some_and(|token| Arc::ptr_eq(token, &endpoint.token))
    }
    pub fn pending(&self) -> Option<PendingOutput<'id>> {
        self.output.as_ref().map(|output| PendingOutput {
            effect: output.effect,
            exposure: if output.phase.is_submitted() {
                PacketExposure::InjectionPending
            } else {
                PacketExposure::UnsubmittedPacket
            },
            total: output.bytes,
        })
    }

    #[expect(
        clippy::result_large_err,
        reason = "Pre-admission failure preserves the unique reply permit and original bytes without allocating an error"
    )]
    pub fn queue(
        &mut self,
        effect: core::Effect<'id>,
        frame: OwnedFrame,
        until: Instant,
        permit: ReplyPermit<'id>,
    ) -> Result<(), (Error, OwnedFrame, ReplyPermit<'id>)> {
        let fault = if !self.writable() {
            Some(Fault::WouldBlock)
        } else if Instant::now() >= until {
            Some(Fault::Deadline)
        } else {
            None
        };
        if let Some(error) = fault {
            return Err((error.into(), frame, permit));
        }
        let input::ReplyOwner::Wfp(endpoint) = &permit.owner else {
            return Err((Fault::InvalidInput.into(), frame, permit));
        };
        if !self.accepts(endpoint) {
            return Err((Fault::StaleGeneration.into(), frame, permit));
        }
        let (identity, owner) = permit.into_parts();
        let input::ReplyOwner::Wfp(endpoint) = owner else {
            return Err((
                Fault::InvalidInput.into(),
                frame,
                identity.with_owner(owner),
            ));
        };
        self.output = Some(Output {
            effect,
            bytes: frame.len(),
            endpoint,
            until,
            phase: Phase::Queued(frame),
        });
        Ok(())
    }

    pub fn cancel_output(&mut self, request: core::Request<'id>) -> Result<(), Error> {
        let output = self
            .output
            .as_mut()
            .filter(|output| output.effect.request() == request)
            .ok_or(Fault::StaleGeneration)?;
        let now = Instant::now();
        let reason = if now >= output.until {
            StopRequest::Deadline
        } else {
            StopRequest::Cancelled
        };
        output
            .phase
            .request_cancel(reason, output.until, now, self.limits.retirement_timeout);
        Ok(())
    }

    fn retire_token(&mut self, token: &Arc<Token>) {
        token.retire();
        if let Some(slot) = self.slots.get_mut(token.index)
            && slot
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, token))
        {
            *slot = None;
        }
    }
}
