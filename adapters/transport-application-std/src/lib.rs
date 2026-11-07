//! Original TRANSPORT application1300/1301/1302 source. Hints are candidates,
//! never address authentication, connection success or a service ACK.
#![forbid(unsafe_code)]
#![cfg(unix)]
mod budget;
/// Actual public TRANSPORT monitor/link listing owner, separate from hints.
pub mod observation;
use crate::budget::Bound;
pub use budget::Bounds;
pub use gnunet_client_host::ConnectError as Error;
use gnunet_client_host::{
    ConnectGuard, EndpointSource,
    channel::{Channel, ConnectionStep},
};
use gnunet_service_runtime::framing::{
    Accounting, Budget, Class, Limits as FrameLimits, OwnedFrame, ReadStep,
};
use gnunet_transport::{
    PeerId,
    application::{Preference, ValidateAddress},
};
use gnunet_types::Error as Fault;
use gnunet_wire::official::{MessageHeader, MessageType};
use std::{
    io,
    task::{Context, Poll},
    time::Duration,
};
#[derive(Clone, Copy)]
struct Origin {
    epoch: u64,
    sequence: u64,
}
/// Actual local byte facts after the original physical source retired. These
/// facts do not acknowledge remote validation or authorize replaying a hint.
pub struct Retired {
    /// Original actual attached epoch;0 means no source attached.
    pub epoch: u64,
    /// Whether an original frame remained pending at retirement.
    pub submitted: bool,
    /// Positive native bytes written from that pending original frame.
    pub written: usize,
    /// Original framing bytes still retained immediately before physical close.
    pub remaining: usize,
}
/// One actual original-source observation. There is no application reply/ACK
/// on the fire-and-forget1300/1301/1302 wire.
pub enum Step {
    /// The original native connection attached; carries this owner's epoch.
    Attached(u64),
    /// Positive native bytes on the pending original frame.
    Activity,
    /// Entire original frame wrote locally, without a remote-processing claim.
    Written {
        /// Same actual attached source epoch.
        epoch: u64,
        /// Total positive native bytes of this one original frame.
        bytes: usize,
    },
    /// Original physical source closed before returning its facts.
    Lost {
        /// Original outstanding frame/prefix facts.
        report: Retired,
        /// Actual socket/framing cause;None only for clean source EOF.
        cause: Option<io::Error>,
    },
    /// Actual failed connect attempt; same source retains its retry/deadline.
    Retry(io::Error),
}
struct Pending {
    bound: Bound,
    sequence: u64,
    written: usize,
}
/// Caller-driven original TRANSPORT application source, with at most one
/// pending frame and explicit physical retirement before replacement.
pub struct Application {
    source: EndpointSource,
    channel: Channel<Origin>,
    epoch: u64,
    next: u64,
    attached: bool,
    pending: Option<Pending>,
    initial: Bound,
    source_life: Option<Duration>,
    guard: Option<ConnectGuard>,
    io: usize,
    closed: bool,
}
fn framing(io: usize) -> FrameLimits {
    FrameLimits {
        frame_bytes: 65535,
        ordinary: Budget {
            frames: 2,
            bytes: 131070,
        },
        reserved: Budget::default(),
        accounting: Accounting::Retained,
        io_slice_bytes: io,
    }
}
impl Application {
    /// Create an original source using the caller's shared clock/resolution.
    /// No socket IO or implicit Resolver/task starts in this constructor.
    pub fn new(
        source: EndpointSource,
        io: usize,
        initial: Duration,
        source_life: Duration,
    ) -> Result<Self, Error> {
        let first = Bound::new(source.clock().as_ref(), initial)?;
        Ok(Self {
            channel: Channel::new(source.duplicate()?, framing(io))?,
            source,
            epoch: 0,
            next: 0,
            attached: false,
            pending: None,
            initial: first,
            source_life: Some(source_life),
            guard: None,
            io,
            closed: false,
        })
    }
    /// Create one source epoch capped by the caller's already captured absolute
    /// targets. Attachment never renews them. The retained guard reaches native
    /// connection attempts and runs after clock providers, before each actual
    /// frame read/write and admission. It supplies cancellation, not peer success.
    /// A replacement requires a new owner after physically closing this one.
    pub fn new_bounded_guarded(
        source: EndpointSource,
        io: usize,
        bounds: Bounds,
        guard: ConnectGuard,
    ) -> Result<Self, Error> {
        bounds.check(source.clock().as_ref())?;
        guard()?;
        let clock = source.clock();
        let callback = guard.clone();
        let connect: ConnectGuard = std::sync::Arc::new(move || {
            if std::time::Instant::now() >= bounds.hard {
                return Err(io::Error::other(Fault::Deadline));
            }
            callback()?;
            bounds.check(clock.as_ref()).map_err(io::Error::other)
        });
        let channel = Channel::new_guarded(source.duplicate()?, framing(io), connect)?;
        Ok(Self {
            source,
            channel,
            epoch: 0,
            next: 0,
            attached: false,
            pending: None,
            initial: Bound::targets(bounds),
            source_life: None,
            guard: Some(guard),
            io,
            closed: false,
        })
    }
    fn check_io(&self, admission: Option<Bounds>) -> Result<(), Error> {
        let pending = admission.or_else(|| self.pending.as_ref().map(|p| p.bound.targets));
        let native_expired = || {
            let now = std::time::Instant::now();
            now >= self.initial.targets.hard || pending.is_some_and(|b| now >= b.hard)
        };
        if native_expired() {
            return Err(Fault::Deadline.into());
        }
        if let Some(guard) = &self.guard {
            guard()?;
        }
        if native_expired() {
            return Err(Fault::Deadline.into());
        }
        // One final coherent canonical sample checks the source and this
        // original pending/admitting operation after every external callback.
        let now = self.source.clock().sample()?.now.as_micros();
        if native_expired()
            || now >= self.initial.targets.expires
            || pending.is_some_and(|b| now >= b.expires)
        {
            return Err(Fault::Deadline.into());
        }
        Ok(())
    }
    /// Whether one new operation can be admitted to this attached original MQ.
    #[must_use]
    pub fn idle(&self) -> bool {
        self.attached && self.pending.is_none() && !self.closed
    }
    /// Whether one original admitted frame remains retained, possibly partial.
    #[must_use]
    pub fn pending(&self) -> bool {
        self.pending.is_some()
    }
    /// Convert one public HELLO URI to its official communicator address and
    /// enqueue validation with unspecified network type0. No remote result is
    /// inferred. Use validate for an actual network-classified address.
    pub fn hint(&mut self, peer: [u8; 32], uri: &[u8], bounds: Bounds) -> Result<(), Error> {
        let bound = Bound::targets(bounds);
        bound.check(self.source.clock().as_ref())?;
        let address = gnunet_hello::Address::from_uri(uri)?;
        let n = address
            .scheme()
            .len()
            .checked_add(1)
            .and_then(|n| n.checked_add(address.body().len()))
            .ok_or(Fault::Overflow)?;
        let total = n.checked_add(41).ok_or(Fault::Overflow)?;
        if total > 65535 {
            return Err(Fault::TooLarge.into());
        }
        let mut bytes = buffer(total)?;
        MessageHeader::from_total_size(MessageType::new(1302), total)?.encode(&mut bytes)?;
        bytes[4..8].copy_from_slice(&0u32.to_be_bytes());
        bytes[8..40].copy_from_slice(&peer);
        let split = 40 + address.scheme().len();
        bytes[40..split].copy_from_slice(address.scheme());
        bytes[split] = b'-';
        bytes[split + 1..total - 1].copy_from_slice(address.body());
        bytes[total - 1] = 0;
        // Reuse the actual public codec to check the official producer shape.
        ValidateAddress::decode(&bytes)?;
        self.enqueue(OwnedFrame::new(bytes), bound)
    }
    /// Enqueue one exact NUL-free official communicator address with the
    /// caller's actual network classification. This remains only a validation
    /// request, never an authenticated queue or a remote validation receipt.
    pub fn validate(
        &mut self,
        peer: [u8; 32],
        address: &[u8],
        network: u32,
        bounds: Bounds,
    ) -> Result<(), Error> {
        let bound = Bound::targets(bounds);
        bound.check(self.source.clock().as_ref())?;
        let total = address
            .len()
            .checked_add(41)
            .filter(|total| *total <= 65535)
            .ok_or(Fault::TooLarge)?;
        if address.is_empty() || address.contains(&0) {
            return Err(Fault::InvalidInput.into());
        }
        let mut bytes = buffer(total)?;
        MessageHeader::from_total_size(MessageType::new(1302), total)?.encode(&mut bytes)?;
        bytes[4..8].copy_from_slice(&network.to_be_bytes());
        bytes[8..40].copy_from_slice(&peer);
        bytes[40..total - 1].copy_from_slice(address);
        bytes[total - 1] = 0;
        ValidateAddress::decode(&bytes)?;
        self.enqueue(OwnedFrame::new(bytes), bound)
    }
    /// Enqueue the original public preference1/cancel1300/1301 operation.
    pub fn preference(
        &mut self,
        peer: [u8; 32],
        cancel: bool,
        bounds: Bounds,
    ) -> Result<(), Error> {
        let bound = Bound::targets(bounds);
        let mut bytes = buffer(44)?;
        Preference {
            priority: 1,
            peer: PeerId(peer),
            bandwidth: 0,
        }
        .encode(cancel, &mut bytes)?;
        self.enqueue(OwnedFrame::new(bytes), bound)
    }
    fn enqueue(&mut self, frame: OwnedFrame, bound: Bound) -> Result<(), Error> {
        if !self.idle() {
            return Err(Fault::WouldBlock.into());
        }
        self.check_io(Some(bound.targets))?;
        let sequence = self.next.checked_add(1).ok_or(Fault::Overflow)?;
        let framed = self.channel.framing_mut().ok_or(Fault::NotReady)?;
        framed.reserve(frame.len(), Class::Ordinary)?;
        // Preserve the same hard after clock/reservation, immediately before
        // actual queue admission. This is still not a complete write receipt.
        if std::time::Instant::now() >= bound.targets.hard {
            return Err(Fault::Deadline.into());
        }
        framed
            .enqueue_owned(
                frame,
                Origin {
                    epoch: self.epoch,
                    sequence,
                },
                Class::Ordinary,
            )
            .map_err(|e| e.reason)?;
        self.next = sequence;
        self.pending = Some(Pending {
            bound,
            sequence,
            written: 0,
        });
        Ok(())
    }
    /// Native-first deadline observation/registration without a canonical
    /// sample or new IO. On expiry physically closes the same original source.
    pub fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Option<Retired> {
        if self.closed {
            return None;
        }
        if self.initial.poll_native(cx)
            || self
                .pending
                .as_mut()
                .is_some_and(|p| p.bound.poll_native(cx))
        {
            return Some(self.close());
        }
        None
    }
    /// Drive one original connection/frame observation under its fixed budget.
    /// Any returned error still requires explicit close to preserve Retired.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Step, Error>> {
        if self.closed {
            return Poll::Pending;
        }
        self.check_io(None)?;
        match self.channel.poll_clock(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result?,
        }
        self.check_io(None)?;
        if !self.attached {
            return match self.channel.poll_connect(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Ready(Ok(ConnectionStep::Attached)) => {
                    self.epoch = self.epoch.checked_add(1).ok_or(Fault::Overflow)?;
                    self.attached = true;
                    if let Some(life) = self.source_life {
                        self.initial = Bound::new(self.source.clock().as_ref(), life)?;
                    }
                    Poll::Ready(Ok(Step::Attached(self.epoch)))
                }
                Poll::Ready(Ok(ConnectionStep::Retry { error, .. })) => {
                    Poll::Ready(Ok(Step::Retry(error)))
                }
                Poll::Ready(Ok(ConnectionStep::Unavailable(error))) => Poll::Ready(Err(error)),
            };
        }
        if let Some(pending) = self.pending.as_ref() {
            pending.bound.check(self.source.clock().as_ref())?;
        }
        if self.pending.is_some() {
            self.check_io(None)?;
            match self
                .channel
                .framing_mut()
                .ok_or(Fault::NotReady)?
                .poll_write(cx)
            {
                Poll::Ready(Ok(progress)) => {
                    let pending = self.pending.as_mut().ok_or(Fault::Stale)?;
                    if progress.origin.epoch != self.epoch
                        || progress.origin.sequence != pending.sequence
                    {
                        return Poll::Ready(Err(Fault::Stale.into()));
                    }
                    pending.written = pending
                        .written
                        .checked_add(progress.bytes)
                        .ok_or(Fault::Overflow)?;
                    if progress.complete {
                        let pending = self.pending.take().ok_or(Fault::Stale)?;
                        return Poll::Ready(Ok(Step::Written {
                            epoch: self.epoch,
                            bytes: pending.written,
                        }));
                    }
                    return Poll::Ready(Ok(Step::Activity));
                }
                Poll::Ready(Err(error)) => {
                    return Poll::Ready(Ok(Step::Lost {
                        report: self.close(),
                        cause: Some(error),
                    }));
                }
                Poll::Pending => {}
            }
        }
        self.check_io(None)?;
        match self
            .channel
            .framing_mut()
            .ok_or(Fault::NotReady)?
            .poll_read(cx)
        {
            Poll::Ready(Ok(ReadStep::Eof)) => Poll::Ready(Ok(Step::Lost {
                report: self.close(),
                cause: None,
            })),
            Poll::Ready(Err(error)) => Poll::Ready(Ok(Step::Lost {
                report: self.close(),
                cause: Some(error),
            })),
            Poll::Ready(Ok(ReadStep::Progress { .. })) => {
                let report = self.close();
                Poll::Ready(Ok(Step::Lost {
                    report,
                    cause: Some(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected TRANSPORT application response",
                    )),
                }))
            }
            Poll::Pending => Poll::Pending,
        }
    }
    /// Source/partial frame ownership is physically closed before returning facts.
    pub fn close(&mut self) -> Retired {
        let remaining = self.channel.framing().map_or(0, |f| f.remaining_bytes());
        self.channel.close();
        self.closed = true;
        self.attached = false;
        let pending = self.pending.take();
        Retired {
            epoch: self.epoch,
            submitted: pending.is_some(),
            written: pending.map_or(0, |p| p.written),
            remaining,
        }
    }
    /// Explicit replacement only after the old source physically closed. No old
    /// hint or exposed suffix is replayed into this newly created selector.
    pub fn restart(&mut self, initial: Duration) -> Result<(), Error> {
        if !self.closed || self.pending.is_some() || self.source_life.is_none() {
            return Err(Fault::Conflict.into());
        }
        let channel = Channel::new(self.source.duplicate()?, framing(self.io))?;
        let first = Bound::new(self.source.clock().as_ref(), initial)?;
        self.channel = channel;
        self.initial = first;
        self.closed = false;
        Ok(())
    }
}
fn buffer(n: usize) -> Result<Vec<u8>, Error> {
    let mut b = Vec::new();
    b.try_reserve_exact(n).map_err(|_| Fault::Capacity)?;
    b.resize(n, 0);
    Ok(b)
}
