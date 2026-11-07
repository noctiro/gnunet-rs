//! Persistent physical socket state for one original logical MQ incarnation.
use crate::{Clock, HostError, Limits};
use gnunet_client_host::{ConnectionAttempt, Endpoint};
use gnunet_service_runtime::connection::Connection as Stream;
type Connect = Pin<Box<ConnectionAttempt>>;
use gnunet_arm_core::{ConnectionEpoch, FrameTicket};
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::{Instant, Sleep},
};
pub(crate) fn bytes(n: usize) -> Result<Vec<u8>, HostError> {
    let mut b = Vec::new();
    b.try_reserve_exact(n)
        .map_err(|_| gnunet_types::Error::Capacity)?;
    b.resize(n, 0);
    Ok(b)
}
pub(crate) struct Physical {
    pub epoch: Option<ConnectionEpoch>,
    endpoint: Option<Endpoint>,
    stream: Option<Stream>,
    connect: Option<Connect>,
    pending_native_error: Option<io::Error>,
    retry: Option<gnunet_types::AbsoluteTime>,
    wake: Wake,
    backoff: u64,
    round: bool,
}
impl Physical {
    pub fn new() -> Self {
        Self {
            epoch: None,
            endpoint: None,
            stream: None,
            connect: None,
            pending_native_error: None,
            retry: None,
            wake: Wake::new(),
            backoff: 0,
            round: false,
        }
    }
    pub fn admit(&mut self, epoch: ConnectionEpoch, endpoint: Endpoint) {
        self.retire();
        self.epoch = Some(epoch);
        self.endpoint = Some(endpoint);
    }
    pub fn retire(&mut self) {
        self.stream = None;
        self.connect = None;
        self.pending_native_error = None;
        self.endpoint = None;
        self.epoch = None;
        self.retry = None;
        self.wake = Wake::new();
        self.backoff = 0;
        self.round = false;
    }
    fn poll_connect(
        &mut self,
        cx: &mut Context<'_>,
        clock: &mut Clock,
    ) -> Poll<Result<bool, HostError>> {
        if self.stream.is_some() {
            return Poll::Ready(Ok(false));
        }
        if self.epoch.is_none() {
            return Poll::Pending;
        }
        if let Some(at) = self.retry {
            match self.wake.poll(cx, clock, Some(at)) {
                Ok(Poll::Pending) => return Poll::Pending,
                Err(error) => return Poll::Ready(Err(error)),
                Ok(Poll::Ready(())) => {}
            }
            self.retry = None;
            self.wake = Wake::new();
        }
        if self.pending_native_error.is_some() {
            return self.register_native_failure(clock);
        }
        // Sample before polling the original connect future. A clock error then
        // returns without any new socket/DNS effect or consuming its authority.
        if let Err(error) = clock.now() {
            return Poll::Ready(Err(error));
        }
        if self.connect.is_none() {
            let Some(endpoint) = self.endpoint.clone() else {
                return Poll::Ready(Err(gnunet_types::Error::NotReady.into()));
            };
            self.connect = Some(Box::pin(endpoint.attempt(u64::from(self.round))));
            self.round = !self.round;
        }
        let result = self
            .connect
            .as_mut()
            .map(|f| f.as_mut().poll(cx))
            .unwrap_or(Poll::Pending);
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(stream)) => {
                self.connect = None;
                self.stream = Some(stream);
                Poll::Ready(Ok(true))
            }
            Poll::Ready(Err(error)) => {
                if gnunet_client_host::resolution::PortError::from_io(&error).is_some() {
                    // Retain this terminal attempt and all MQ/frame authority.
                    // A caller port refusal is never a native socket retry.
                    return Poll::Ready(Err(HostError::Endpoint(
                        gnunet_client_host::ConnectError::Io(error),
                    )));
                }
                self.connect = None;
                self.pending_native_error = Some(error);
                self.register_native_failure(clock)
            }
        }
    }
    fn register_native_failure(&mut self, clock: &Clock) -> Poll<Result<bool, HostError>> {
        // connect_fail_continuation/add_delayed samples after the actual socket
        // failure. A failed time sample retains the exact consumed native error;
        // the next drive only completes this registration, never polls that
        // completed future or repeats its socket effect/backoff increment.
        let now = match clock.now() {
            Ok(now) => now,
            Err(error) => return Poll::Ready(Err(error)),
        };
        let Some(error) = self.pending_native_error.take() else {
            return Poll::Ready(Err(gnunet_types::Error::NotReady.into()));
        };
        self.backoff = self.backoff.max(1000).saturating_mul(2).min(900_000_000);
        self.retry = Some(gnunet_types::AbsoluteTime::from_micros(
            now.as_micros().saturating_add(self.backoff),
        ));
        self.wake = Wake::new();
        Poll::Ready(Err(error.into()))
    }
}
pub(crate) struct Rx {
    pub bytes: Vec<u8>,
    pub used: usize,
    pub expected: usize,
}
impl Rx {
    pub fn new(max: usize) -> Result<Self, HostError> {
        Ok(Self {
            bytes: bytes(max)?,
            used: 0,
            expected: 4,
        })
    }
    pub fn clear(&mut self) {
        self.used = 0;
        self.expected = 4;
    }
    pub fn frame(&self) -> &[u8] {
        &self.bytes[..self.expected]
    }
}
#[derive(Default)]
pub(crate) struct Tx {
    pub ticket: Option<FrameTicket>,
    pub written: usize,
}
impl Tx {
    pub fn clear(&mut self) {
        self.ticket = None;
        self.written = 0;
    }
}
pub(crate) enum Pulse {
    Connected,
    ConnectRetry(io::Error),
    Boundary(HostError),
    Io,
    Received,
    Written(FrameTicket),
    Lost(io::Error),
}
pub(crate) struct Mq {
    pub physical: Physical,
    pub rx: Rx,
    pub tx: Tx,
    read_first: bool,
    limits: Limits,
}
impl Mq {
    pub fn new(limits: Limits) -> Result<Self, HostError> {
        Ok(Self {
            physical: Physical::new(),
            rx: Rx::new(limits.max_frame_bytes)?,
            tx: Tx::default(),
            read_first: false,
            limits,
        })
    }
    pub fn retire(&mut self) {
        self.physical.retire();
        self.rx.clear();
        self.tx.clear();
    }
    fn read(&mut self, cx: &mut Context<'_>) -> Poll<Pulse> {
        let Some(stream) = &mut self.physical.stream else {
            return Poll::Pending;
        };
        let end = self
            .rx
            .expected
            .min(self.rx.used.saturating_add(self.limits.io_slice_bytes));
        let mut buf = ReadBuf::new(&mut self.rx.bytes[self.rx.used..end]);
        match Pin::new(stream).poll_read(cx, &mut buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Pulse::Lost(e)),
            Poll::Ready(Ok(())) if buf.filled().is_empty() => {
                Poll::Ready(Pulse::Lost(io::ErrorKind::UnexpectedEof.into()))
            }
            Poll::Ready(Ok(())) => {
                self.rx.used += buf.filled().len();
                if self.rx.used == 4 && self.rx.expected == 4 {
                    let n = usize::from(u16::from_be_bytes([self.rx.bytes[0], self.rx.bytes[1]]));
                    if n < 4 || n > self.rx.bytes.len() {
                        return Poll::Ready(Pulse::Lost(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "ARM frame outside explicit RX capacity",
                        )));
                    }
                    self.rx.expected = n;
                }
                Poll::Ready(if self.rx.used == self.rx.expected {
                    Pulse::Received
                } else {
                    Pulse::Io
                })
            }
        }
    }
    fn write(&mut self, cx: &mut Context<'_>, frame: Option<&[u8]>) -> Poll<Pulse> {
        let (Some(stream), Some(frame), Some(ticket)) =
            (&mut self.physical.stream, frame, self.tx.ticket)
        else {
            return Poll::Pending;
        };
        let end = frame
            .len()
            .min(self.tx.written.saturating_add(self.limits.io_slice_bytes));
        if self.tx.written >= frame.len() {
            return Poll::Ready(Pulse::Written(ticket));
        }
        match Pin::new(stream).poll_write(cx, &frame[self.tx.written..end]) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Pulse::Lost(e)),
            Poll::Ready(Ok(0)) => Poll::Ready(Pulse::Lost(io::ErrorKind::WriteZero.into())),
            Poll::Ready(Ok(n)) => {
                self.tx.written += n;
                Poll::Ready(if self.tx.written == frame.len() {
                    Pulse::Written(ticket)
                } else {
                    Pulse::Io
                })
            }
        }
    }
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        frame: Option<&[u8]>,
        clock: &mut Clock,
    ) -> Poll<Pulse> {
        if self.physical.stream.is_none() {
            return match self.physical.poll_connect(cx, clock) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Ok(true)) => Poll::Ready(Pulse::Connected),
                Poll::Ready(Ok(false)) => Poll::Pending,
                Poll::Ready(Err(HostError::Io(e))) => Poll::Ready(Pulse::ConnectRetry(e)),
                Poll::Ready(Err(error)) => Poll::Ready(Pulse::Boundary(error)),
            };
        }
        let result = if self.read_first {
            match self.read(cx) {
                Poll::Pending => self.write(cx, frame),
                r => r,
            }
        } else {
            match self.write(cx, frame) {
                Poll::Pending => self.read(cx),
                r => r,
            }
        };
        if result.is_ready() {
            self.read_first = !self.read_first;
        }
        result
    }
}
pub(crate) struct Wake {
    target: Option<gnunet_types::AbsoluteTime>,
    revision: u64,
    sleep: Option<Pin<Box<Sleep>>>,
}
impl Wake {
    pub fn new() -> Self {
        Self {
            target: None,
            revision: 0,
            sleep: None,
        }
    }
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        clock: &mut Clock,
        next: Option<gnunet_types::AbsoluteTime>,
    ) -> Result<Poll<()>, HostError> {
        let subscription = clock
            .subscription
            .as_mut()
            .ok_or(gnunet_types::Error::Closed)?;
        let sample = match subscription.poll_changed(cx, self.revision) {
            Poll::Ready(sample) => sample?,
            Poll::Pending => clock.source.sample()?,
        };
        let next = next.filter(|at| at.as_micros() != u64::MAX);
        let changed = self.target != next || self.revision != sample.revision;
        self.revision = sample.revision;
        self.target = next;
        let Some(deadline) = next else {
            self.sleep = None;
            return Ok(Poll::Pending);
        };
        if deadline <= sample.now {
            self.sleep = None;
            return Ok(Poll::Ready(()));
        }
        if changed || self.sleep.is_none() {
            self.arm(deadline.as_micros() - sample.now.as_micros())?;
        }
        let ready = self
            .sleep
            .as_mut()
            .is_some_and(|s| s.as_mut().poll(cx).is_ready());
        if ready {
            // A wall-clock rollback without an explicit revision can outlive the
            // original native Sleep. Recheck the same logical absolute target.
            let now = clock.source.sample()?.now;
            if deadline <= now {
                self.sleep = None;
                return Ok(Poll::Ready(()));
            }
            self.arm(deadline.as_micros() - now.as_micros())?;
            if let Some(s) = &mut self.sleep
                && s.as_mut().poll(cx).is_ready()
            {
                cx.waker().wake_by_ref();
            }
        }
        Ok(Poll::Pending)
    }
    fn arm(&mut self, us: u64) -> Result<(), HostError> {
        let at = Instant::now()
            .checked_add(std::time::Duration::from_micros(us))
            .ok_or(gnunet_types::Error::Overflow)?;
        self.sleep = Some(Box::pin(tokio::time::sleep_until(at)));
        Ok(())
    }
}

#[cfg(test)]
mod clock_wait_tests {
    use super::*;
    use gnunet_service_runtime::clock::{ClockSample, RuntimeClock};
    use gnunet_types::{AbsoluteTime, Error};
    struct Frozen;
    impl RuntimeClock for Frozen {
        fn sample(&self) -> Result<ClockSample, Error> {
            Ok(ClockSample {
                now: gnunet_types::AbsoluteTime::from_micros(0),
                revision: 0,
            })
        }
        fn subscribe(
            &self,
        ) -> Result<Box<dyn gnunet_service_runtime::clock::ClockSubscription>, Error> {
            RuntimeClock::subscribe(&gnunet_service_runtime::clock::SystemClock)
        }
    }
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "A finite source absolute deadline must remain representable across the entire u64 clock domain"
    )]
    fn finite_large_native_sleep_never_changes_the_original_logical_deadline()
    -> Result<(), Box<dyn std::error::Error>> {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()?
            .block_on(async {
                let mut clock = Clock::new(std::sync::Arc::new(Frozen))?;
                let mut wake = Wake::new();
                let mut context = Context::from_waker(std::task::Waker::noop());
                let original = AbsoluteTime::from_micros(u64::MAX - 1);
                let observed = wake.poll(&mut context, &mut clock, Some(original));
                assert!(
                    matches!(observed, Ok(Poll::Pending)),
                    "finite source wait was refused by native representation: {observed:?}"
                );
                assert_eq!(wake.target, Some(original));
                Ok(())
            })
    }
}
