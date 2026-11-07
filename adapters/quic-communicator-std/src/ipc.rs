//! Actual original standard communicator MQ; no backend or peer proof is hidden.
use crate::types::TransportLoss;
use gnunet_client_host::{
    EndpointSource,
    channel::{Channel, ConnectionStep},
};
use gnunet_service_runtime::framing::{Accounting, Budget, Class, Limits, OwnedFrame, ReadStep};
use gnunet_types::Error as Protocol;
use gnunet_wire::official::communicator::{Request, Response};
use std::{
    collections::VecDeque,
    task::{Context, Poll},
};
use tokio::time::Instant;
use zeroize::Zeroizing;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Role {
    Register,
    Address,
    Advert(u32),
    Queue(u32),
    Down(u32),
    Credit(u32),
    Available(u32),
    Sent(u32, [u8; 8]),
    Incoming([u8; 8]),
    Control,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Write {
    serial: u64,
}
struct Output {
    id: Write,
    role: Role,
    hard: Instant,
    bytes: usize,
}
#[derive(Debug)]
pub(crate) enum Failure {
    Protocol(Protocol),
    Client(gnunet_client_host::ConnectError),
    Io(std::io::Error),
    Lost,
}
impl From<Protocol> for Failure {
    fn from(e: Protocol) -> Self {
        Self::Protocol(e)
    }
}
impl From<gnunet_client_host::ConnectError> for Failure {
    fn from(e: gnunet_client_host::ConnectError) -> Self {
        Self::Client(e)
    }
}
impl From<std::io::Error> for Failure {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
pub(crate) enum Step {
    Pending,
    Attached,
    Activity,
    Written {
        role: Role,
        bytes: usize,
        complete: bool,
    },
    Frame,
    Lost {
        facts: TransportLoss,
        cause: Failure,
    },
}
pub(crate) struct Ipc {
    channel: Channel<Write>,
    outputs: VecDeque<Output>,
    next: u64,
    frames: usize,
    bytes: usize,
    attached: bool,
    closed: bool,
    paused: bool,
    hard: Instant,
    input: Option<Instant>,
    operation: std::time::Duration,
    generation: u64,
    read_first: bool,
    announcement_fence: u64,
    whole_write: u64,
}
impl Ipc {
    pub(crate) fn new(
        source: EndpointSource,
        frames: usize,
        bytes: usize,
        slice: usize,
        hard: Instant,
        operation: std::time::Duration,
    ) -> Result<Self, Failure> {
        if frames < 4 || bytes < 131070 || slice == 0 || operation.is_zero() {
            return Err(Protocol::InvalidInput.into());
        }
        let mut outputs = VecDeque::new();
        outputs
            .try_reserve_exact(frames)
            .map_err(|_| Protocol::Capacity)?;
        let channel = Channel::new(
            source,
            Limits {
                frame_bytes: 65535,
                ordinary: Budget { frames, bytes },
                reserved: Budget::default(),
                accounting: Accounting::Retained,
                io_slice_bytes: slice,
            },
        )?;
        Ok(Self {
            channel,
            outputs,
            next: 0,
            frames,
            bytes,
            attached: false,
            closed: false,
            paused: false,
            hard,
            input: None,
            operation,
            generation: 1,
            read_first: false,
            announcement_fence: 0,
            whole_write: 0,
        })
    }
    pub(crate) fn room(&self, frames: usize, bytes: usize) -> bool {
        self.attached
            && !self.closed
            && self.outputs.len().saturating_add(frames) <= self.frames
            && self
                .channel
                .framing()
                .is_some_and(|f| bytes <= self.bytes.saturating_sub(f.charged_bytes()))
    }
    /// Preflight the same encoded extent that enqueue will reserve. A caller
    /// keeps its original input/result until this returns true; lack of space
    /// is backpressure, not a terminal failure of the shared communicator.
    pub(crate) fn room_request(&self, request: Request<'_>) -> Result<bool, Failure> {
        Ok(self.room(1, request.encoded_len()?))
    }
    pub(crate) fn enqueue(
        &mut self,
        request: Request<'_>,
        role: Role,
        hard: Instant,
    ) -> Result<(), Failure> {
        let hard = hard.min(self.hard).min(
            Instant::now()
                .checked_add(self.operation)
                .ok_or(Protocol::Overflow)?,
        );
        if Instant::now() >= hard {
            return Err(Protocol::Deadline.into());
        }
        let len = request.encoded_len()?;
        if !self.room(1, len) {
            return Err(Protocol::WouldBlock.into());
        }
        let next = self.next.checked_add(1).ok_or(Protocol::Overflow)?;
        let id = Write { serial: next };
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(len)
            .map_err(|_| Protocol::Capacity)?;
        bytes.resize(len, 0);
        request.encode(&mut bytes)?;
        self.channel
            .framing_mut()
            .ok_or(Protocol::NotReady)?
            .enqueue_owned(
                OwnedFrame::new(std::mem::take(&mut *bytes)),
                id,
                Class::Ordinary,
            )
            .map_err(|r| r.reason)?;
        self.next = next;
        if matches!(
            role,
            Role::Register | Role::Advert(_) | Role::Address | Role::Queue(_) | Role::Down(_)
        ) {
            self.announcement_fence = next;
        }
        self.outputs.push_back(Output {
            id,
            role,
            hard,
            bytes: 0,
        });
        Ok(())
    }
    /// Exact whole-write prefix of current announcement intents, including a
    /// removal admitted while restoration was in progress. Later data does not
    /// have to empty the FIFO for this historical control boundary to settle.
    pub(crate) fn announcements_written(&self) -> bool {
        self.announcement_fence != 0 && self.whole_write >= self.announcement_fence
    }
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
    pub(crate) fn input_hard(&self) -> Option<Instant> {
        self.input
    }
    pub(crate) fn frame(&self) -> Result<Option<Response<'_>>, Failure> {
        self.channel
            .framing()
            .and_then(|f| f.frame())
            .map(Response::decode)
            .transpose()
            .map_err(Failure::Protocol)
    }
    pub(crate) fn release(&mut self) -> Result<(), Failure> {
        if !self
            .channel
            .framing_mut()
            .ok_or(Protocol::NotReady)?
            .release_frame()
        {
            return Err(Protocol::NotReady.into());
        }
        self.input = None;
        Ok(())
    }
    pub(crate) fn earliest(&self) -> Instant {
        self.outputs
            .iter()
            .map(|o| o.hard)
            .fold(self.input.unwrap_or(self.hard).min(self.hard), Instant::min)
    }
    pub(crate) fn poll(&mut self, cx: &mut Context<'_>) -> Result<Step, Failure> {
        // Native bounds/independent physical MQ close precede any canonical
        // revision race; the outer owner also closes its actual QUIC/PILS source.
        if self.closed {
            return Err(Protocol::Closed.into());
        }
        if Instant::now() >= self.earliest() {
            self.close();
            return Err(Protocol::Deadline.into());
        }
        if self.paused {
            return Ok(Step::Pending);
        }
        match self.channel.poll_clock(cx) {
            Poll::Pending => return Ok(Step::Pending),
            Poll::Ready(Err(e)) => return Err(e.into()),
            Poll::Ready(Ok(())) => {}
        }
        if !self.attached {
            return match self.channel.poll_connect(cx) {
                Poll::Pending => Ok(Step::Pending),
                Poll::Ready(Err(e)) => Err(e.into()),
                Poll::Ready(Ok(ConnectionStep::Attached)) => {
                    self.attached = true;
                    Ok(Step::Attached)
                }
                Poll::Ready(Ok(ConnectionStep::Retry { .. })) => Ok(Step::Activity),
                Poll::Ready(Ok(ConnectionStep::Unavailable(e))) => Err(e.into()),
            };
        }
        // Both directions register real readiness. Continuous outgoing traffic
        // must not hide source EOF or a service command/FC callback indefinitely.
        for offset in 0..2 {
            let read = (usize::from(self.read_first) + offset) % 2 == 1;
            let step = if read {
                self.poll_read(cx)?
            } else {
                self.poll_write(cx)?
            };
            if !matches!(step, Step::Pending) {
                self.read_first = !read;
                return Ok(step);
            }
        }
        Ok(Step::Pending)
    }
    fn poll_write(&mut self, cx: &mut Context<'_>) -> Result<Step, Failure> {
        if self.outputs.is_empty() {
            return Ok(Step::Pending);
        }
        let framing = self.channel.framing_mut().ok_or(Protocol::NotReady)?;
        match framing.poll_write(cx) {
            Poll::Pending => Ok(Step::Pending),
            Poll::Ready(Err(error)) => Err(error.into()),
            Poll::Ready(Ok(progress)) => {
                let output = self.outputs.front_mut().ok_or(Protocol::Stale)?;
                if output.id != progress.origin {
                    return Err(Protocol::Stale.into());
                }
                output.bytes = output
                    .bytes
                    .checked_add(progress.bytes)
                    .ok_or(Protocol::Overflow)?;
                let role = output.role;
                if progress.complete {
                    self.whole_write = output.id.serial;
                    self.outputs.pop_front();
                }
                Ok(Step::Written {
                    role,
                    bytes: progress.bytes,
                    complete: progress.complete,
                })
            }
        }
    }
    fn poll_read(&mut self, cx: &mut Context<'_>) -> Result<Step, Failure> {
        let framing = self.channel.framing_mut().ok_or(Protocol::NotReady)?;
        // A held complete frame is returned by the outer poll only after the
        // opposite direction got its turn; it is not fresh native progress.
        if framing.frame().is_some() {
            return Ok(Step::Frame);
        }
        match framing.poll_read(cx) {
            Poll::Pending => Ok(Step::Pending),
            Poll::Ready(Err(e)) => Err(e.into()),
            Poll::Ready(Ok(ReadStep::Eof)) => Err(Failure::Lost),
            Poll::Ready(Ok(ReadStep::Progress { bytes, complete })) => {
                if bytes > 0 && self.input.is_none() {
                    self.input = Some(
                        Instant::now()
                            .checked_add(self.operation)
                            .ok_or(Protocol::Overflow)?
                            .min(self.hard),
                    );
                }
                Ok(if complete {
                    Step::Frame
                } else {
                    Step::Activity
                })
            }
        }
    }
    /// Recover only physical transport loss. Configuration, malformed framing,
    /// resource/clock/Resolver-port refusal still belongs to the fatal boundary.
    pub(crate) fn poll_recovering(
        &mut self,
        cx: &mut Context<'_>,
        mut retired: impl FnMut(u64, Role, usize),
    ) -> Result<Step, Failure> {
        let cause = match self.poll(cx) {
            Ok(step) => return Ok(step),
            Err(Failure::Lost) => Failure::Lost,
            Err(Failure::Io(error)) if recoverable_io(&error) => Failure::Io(error),
            Err(error) => return Err(error),
        };
        let facts = self.retire_source(&mut retired)?;
        self.resume_source()?;
        Ok(Step::Lost { facts, cause })
    }
    /// Suspend the physical source until its domain has retired old peer work.
    /// Existing input/output is canceled, with original exposure metadata kept.
    pub(crate) fn retire_source(
        &mut self,
        mut retired: impl FnMut(u64, Role, usize),
    ) -> Result<TransportLoss, Failure> {
        if self.closed || self.paused {
            return Err(Protocol::Closed.into());
        }
        let next_generation = self.generation.checked_add(1).ok_or(Protocol::Overflow)?;
        let mut facts = TransportLoss {
            generation: self.generation,
            next_generation,
            input_bytes: self
                .channel
                .framing()
                .map_or(0, |f| f.read_progress_bytes()),
            held_input: self.channel.framing().is_some_and(|f| f.frame().is_some()),
            outputs: self.outputs.len(),
            exposed_outputs: 0,
            output_bytes: 0,
        };
        // Physical detach precedes retirement callbacks. No retained bytes or
        // tags cross this boundary, including zero-exposure control/SEND input.
        self.channel.detach();
        for output in self.outputs.drain(..) {
            facts.exposed_outputs += usize::from(output.bytes != 0);
            facts.output_bytes = facts
                .output_bytes
                .checked_add(output.bytes)
                .ok_or(Protocol::Overflow)?;
            retired(self.generation, output.role, output.bytes);
        }
        self.input = None;
        self.attached = false;
        self.read_first = false;
        self.announcement_fence = 0;
        self.whole_write = 0;
        self.generation = next_generation;
        self.paused = true;
        Ok(facts)
    }
    pub(crate) fn resume_source(&mut self) -> Result<(), Failure> {
        if self.closed || !self.paused {
            return Err(Protocol::NotReady.into());
        }
        self.channel.schedule_retry()?;
        self.paused = false;
        Ok(())
    }
    /// Actual original MQ is closed first. All original output metadata remains
    /// available to the enclosing close report; no outstanding send is replayed.
    pub(crate) fn close(&mut self) {
        self.channel.close();
        self.closed = true;
        self.attached = false
    }
}

fn recoverable_io(error: &std::io::Error) -> bool {
    gnunet_client_host::resolution::PortError::from_io(error).is_none()
        && matches!(
            error.kind(),
            std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::NotConnected
                | std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::WriteZero
        )
}
impl Role {
    pub(crate) fn queue(self) -> Option<u32> {
        match self {
            Self::Queue(q)
            | Self::Down(q)
            | Self::Credit(q)
            | Self::Available(q)
            | Self::Sent(q, _) => Some(q),
            _ => None,
        }
    }
    pub(crate) fn message(self) -> Option<[u8; 8]> {
        match self {
            Self::Sent(_, mid) => Some(mid),
            _ => None,
        }
    }
    pub(crate) fn flow(self) -> Option<[u8; 8]> {
        match self {
            Self::Incoming(flow) => Some(flow),
            _ => None,
        }
    }
    pub(crate) fn kind(self) -> &'static str {
        match self {
            Self::Register => "register",
            Self::Address | Self::Advert(_) => "address",
            Self::Queue(_) => "queue",
            Self::Down(_) => "down",
            Self::Credit(_) | Self::Available(_) => "capacity",
            Self::Sent(..) => "sent",
            Self::Incoming(_) => "incoming",
            Self::Control => "control",
        }
    }
}

#[cfg(test)]
mod tests;
