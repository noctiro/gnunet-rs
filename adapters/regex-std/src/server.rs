use crate::types::*;
use gnunet_regex_service::{Admission, ClientId, Core, OutputId, Times};
use gnunet_service_runtime::{
    accepted::{AcceptState, AcceptedConnection},
    clock::ClockSubscription,
    framing::{Class, Framed, OwnedFrame, ReadStep},
    service::Listener,
};
use gnunet_types::Error as Fault;
use gnunet_wire::official::regex::Request;
use std::{
    future::{Future, poll_fn},
    pin::Pin,
    task::{Context, Poll},
};
use tokio::time::{Instant, Sleep};
enum Input {
    Admitted(Admission),
    Ignored,
}
struct Pending {
    id: OutputId,
    write: u64,
    hard: Instant,
    total: usize,
    bytes: usize,
    mq_queued: bool,
    core_queued: bool,
}
struct Peer {
    client: ClientId,
    io: Option<Framed<u64>>,
    first_until: Option<Instant>,
    partial_until: Option<Instant>,
    output: Option<Pending>,
    detached: bool,
}
impl Peer {
    fn expired(&self) -> bool {
        let now = Instant::now();
        [
            self.first_until,
            self.partial_until,
            self.output.as_ref().map(|out| out.hard),
        ]
        .into_iter()
        .flatten()
        .any(|at| now >= at)
    }
}
/// One caller-driven kernel IPC server over the supplied actual distributed Core.
/// Core owns request/session/job/result authority; local write serials merely
/// correlate exact Framed receipts. Actual PILS/DHT effects are driven externally
/// through core_mut and must settle before the caller drops this allocation.
pub struct Server {
    core: Core,
    limits: Limits,
    ports: Ports,
    peers: Vec<Option<Peer>>,
    scratch: Vec<u8>,
    subscription: Option<Box<dyn ClockSubscription>>,
    revision: u64,
    native_epoch: Instant,
    timer: Option<Pin<Box<Sleep>>>,
    accept: AcceptState,
    cursor: usize,
    listener_cursor: usize,
    next_write: u64,
    shutdown: bool,
    physical_reported: bool,
    report: Report,
}
impl Server {
    /// Construct bounded metadata/shared encode storage and one original clock
    /// subscription. The supplied fresh Core/factory provides no hidden backend.
    pub fn new(core: Core, limits: Limits, ports: Ports) -> Result<Self, Failure> {
        limits.validate()?;
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(Fault::Unavailable.into());
        }
        let native_epoch = Instant::now();
        let subscription = ports.clock.subscribe()?;
        let sample = ports.clock.sample()?;
        let mut peers = Vec::new();
        peers
            .try_reserve_exact(limits.clients)
            .map_err(|_| Fault::Capacity)?;
        peers.resize_with(limits.clients, || None);
        let mut scratch = Vec::new();
        scratch
            .try_reserve_exact(limits.frame_bytes)
            .map_err(|_| Fault::Capacity)?;
        scratch.resize(limits.frame_bytes, 0);
        Ok(Self {
            core,
            limits,
            ports,
            peers,
            scratch,
            subscription: Some(subscription),
            revision: sample.revision,
            native_epoch,
            timer: None,
            accept: AcceptState::default(),
            cursor: 0,
            listener_cursor: 0,
            next_write: 0,
            shutdown: false,
            physical_reported: false,
            report: Report::default(),
        })
    }
    /// Original distributed state; projections confer no backend success.
    #[must_use]
    pub fn core(&self) -> &Core {
        &self.core
    }
    /// Drive the exact original sign/DHT jobs. A backend must retain borrowed
    /// work or copy its payload before submitting; completion must use its token.
    pub fn core_mut(&mut self) -> &mut Core {
        &mut self.core
    }
    /// Original shared UTC authority; does not create an independent source.
    #[must_use]
    pub fn clock(&self) -> std::sync::Arc<dyn gnunet_service_runtime::clock::RuntimeClock> {
        self.ports.clock.clone()
    }
    /// Sample the sole native epoch and owned canonical source used by this Core.
    /// On failure the coordinator must close_all before abandoning original jobs.
    pub fn sample_times(&self) -> Result<Times, Failure> {
        let monotonic = Instant::now()
            .checked_duration_since(self.native_epoch)
            .ok_or(Fault::TimeUncertain)?
            .as_micros();
        let monotonic = u64::try_from(monotonic).map_err(|_| Fault::Overflow)?;
        let absolute = self.ports.clock.sample()?.now.as_micros();
        Ok(Times {
            monotonic,
            absolute,
        })
    }
    /// Actual local source counters, never a DHT completion report.
    #[must_use]
    pub fn report(&self) -> Report {
        self.report
    }
    /// Physical MQ ownership remaining in this allocation.
    #[must_use]
    pub fn physical_clients(&self) -> usize {
        self.peers
            .iter()
            .flatten()
            .filter(|p| p.io.is_some())
            .count()
    }
    /// All Host-created clients have also passed Core's original debt check.
    /// The external factory still owns its physical operation retirement contract.
    #[must_use]
    pub fn is_drained(&self) -> bool {
        self.shutdown && self.peers.iter().all(Option::is_none) && self.core.quiescent()
    }
    fn arm(&mut self, cx: &mut Context<'_>, target: Option<Instant>) {
        match target {
            Some(target) => {
                if let Some(timer) = &mut self.timer {
                    if timer.deadline() != target {
                        timer.as_mut().reset(target);
                    }
                } else {
                    self.timer = Some(Box::pin(tokio::time::sleep_until(target)));
                }
                if let Some(timer) = &mut self.timer {
                    let _wake = timer.as_mut().poll(cx);
                }
            }
            None => self.timer = None,
        }
    }
    fn native_target(&self) -> Option<Instant> {
        self.peers
            .iter()
            .flatten()
            .filter(|p| p.io.is_some())
            .flat_map(|p| {
                [
                    p.first_until,
                    p.partial_until,
                    p.output.as_ref().map(|o| o.hard),
                ]
            })
            .flatten()
            .min()
    }
    fn index(&self, client: &ClientId) -> Result<usize, Failure> {
        self.peers
            .iter()
            .position(|p| p.as_ref().is_some_and(|p| &p.client == client))
            .ok_or_else(|| Fault::Stale.into())
    }
    fn finish_close(
        &mut self,
        index: usize,
        observe: &mut impl FnMut(Event),
    ) -> Result<bool, gnunet_regex_service::Error> {
        let Some(peer) = &mut self.peers[index] else {
            return Ok(false);
        };
        if peer.io.is_some() {
            return Ok(false);
        }
        if !peer.detached {
            if let Err(error) = self.core.disconnect(&peer.client) {
                observe(Event::Cleanup {
                    client: peer.client.clone(),
                    error,
                });
                return Err(error);
            }
            peer.detached = true;
        }
        if let Some(output) = &peer.output {
            if output.core_queued
                && let Err(error) = self.core.aborted(&output.id)
            {
                observe(Event::Cleanup {
                    client: peer.client.clone(),
                    error,
                });
                return Err(error);
            }
            // Unqueued Ready outputs were cleared by the actual disconnect.
            peer.output = None;
        }
        if self.core.release(&peer.client)? {
            let client = peer.client.clone();
            self.peers[index] = None;
            self.report.released = self.report.released.saturating_add(1);
            observe(Event::Released(client));
            return Ok(true);
        }
        Ok(false)
    }
    fn stop_index(
        &mut self,
        index: usize,
        cause: CloseCause,
        observe: &mut impl FnMut(Event),
    ) -> Result<bool, Failure> {
        let peer = self.peers[index].as_mut().ok_or(Fault::Stale)?;
        let Some(mut io) = peer.io.take() else {
            return self.finish_close(index, observe).map_err(Into::into);
        };
        io.retire();
        drop(io);
        self.accept.client_closed();
        peer.first_until = None;
        peer.partial_until = None;
        self.report.closed = self.report.closed.saturating_add(1);
        let output = peer.output.as_ref().map(|o| OutputLoss {
            output: o.id.clone(),
            total: o.total,
            written: o.bytes,
            queued: o.mq_queued,
        });
        observe(Event::Closed {
            client: peer.client.clone(),
            cause,
            output,
        });
        self.finish_close(index, observe)?;
        Ok(true)
    }
    /// Stop this physical MQ before Core cancellation, preserving original
    /// queued/exposed facts and backend retire jobs. No clock sample is needed.
    pub fn close_client(
        &mut self,
        client: &ClientId,
        observe: &mut impl FnMut(Event),
    ) -> Result<(), Failure> {
        let index = self.index(client)?;
        self.stop_index(index, CloseCause::Requested, observe)?;
        Ok(())
    }
    /// Reconcile only already physically closed rows after the original external
    /// backend returns retirement receipts. This cleanup requires no clock.
    pub fn reap(&mut self, observe: &mut impl FnMut(Event)) -> Result<bool, Failure> {
        let mut changed = false;
        let mut first = None;
        for index in 0..self.peers.len() {
            if self.peers[index]
                .as_ref()
                .is_some_and(|peer| peer.io.is_none())
            {
                match self.finish_close(index, observe) {
                    Ok(progress) => changed |= progress,
                    Err(error) if first.is_none() => first = Some(error),
                    Err(_) => {}
                }
            }
        }
        if let Some(error) = first {
            Err(error.into())
        } else {
            Ok(changed)
        }
    }
    /// Stop all original MQs independently before cancel/release bookkeeping.
    /// Core jobs remain accessible for the actual external factory to retire.
    pub fn close_all(&mut self, mut observe: impl FnMut(Event)) -> Result<Report, Failure> {
        self.shutdown = true;
        self.subscription = None;
        self.timer = None;
        let mut first = None;
        for i in 0..self.peers.len() {
            if self.peers[i].is_some()
                && let Err(error) = self.stop_index(i, CloseCause::Shutdown, &mut observe)
                && first.is_none()
            {
                first = Some(error);
            }
        }
        if let Some(error) = first {
            Err(error)
        } else {
            Ok(self.report)
        }
    }
    /// Check/register only original native MQ phase alarms. This does not sample
    /// logical time or poll network/PILS/DHT, and may physically retire expired
    /// sources even while a canonical-clock waiter is Pending or failed.
    pub fn poll_native_guard(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event),
    ) -> Result<bool, Failure> {
        self.arm(cx, self.native_target());
        let now = Instant::now();
        let mut changed = false;
        let mut first = None;
        for i in 0..self.peers.len() {
            let expired = self.peers[i].as_ref().is_some_and(|p| {
                p.io.is_some()
                    && [
                        p.first_until,
                        p.partial_until,
                        p.output.as_ref().map(|o| o.hard),
                    ]
                    .into_iter()
                    .flatten()
                    .any(|at| now >= at)
            });
            let result = if expired {
                self.stop_index(i, CloseCause::Deadline, observe)
            } else if self.peers[i].as_ref().is_some_and(|p| p.io.is_none()) {
                self.finish_close(i, observe).map_err(Into::into)
            } else {
                continue;
            };
            match result {
                Ok(progress) => changed |= progress,
                Err(error) if first.is_none() => first = Some(error),
                Err(_) => {}
            }
        }
        self.arm(cx, self.native_target());
        if let Some(error) = first {
            Err(error)
        } else {
            Ok(changed)
        }
    }
    fn attach(
        &mut self,
        accepted: AcceptedConnection,
        observe: &mut impl FnMut(Event),
    ) -> Result<bool, Failure> {
        let accepted_at = Instant::now();
        let (connection, peer, diagnostics) = accepted.into_parts();
        for diagnostic in diagnostics {
            observe(Event::Socket(
                gnunet_service_runtime::accepted::SocketEvent::Diagnostic(diagnostic),
            ));
        }
        let allowed = if connection.is_unix() {
            match self.ports.unix.allows(&connection) {
                Ok(allowed) => allowed,
                Err(error) => {
                    drop(connection);
                    self.report.rejected = self.report.rejected.saturating_add(1);
                    observe(Event::AdmissionFailed(error.into()));
                    return Ok(true);
                }
            }
        } else {
            match peer {
                gnunet_service_runtime::service::PeerAddress::Tcp(address) => {
                    self.ports.options.access.allows(address.ip())
                }
                _ => false,
            }
        };
        if !allowed {
            drop(connection);
            self.report.rejected = self.report.rejected.saturating_add(1);
            observe(Event::Rejected(peer));
            return Ok(true);
        }
        let Some(index) = self.peers.iter().position(Option::is_none) else {
            drop(connection);
            self.report.rejected = self.report.rejected.saturating_add(1);
            observe(Event::Rejected(peer));
            return Ok(true);
        };
        let hard = accepted_at
            .checked_add(self.limits.first_input)
            .ok_or(Fault::Overflow)?;
        let mut io = match Framed::new(connection, self.limits.framing()) {
            Ok(io) => io,
            Err(error) => {
                self.report.rejected = self.report.rejected.saturating_add(1);
                observe(Event::AdmissionFailed(error.into()));
                return Ok(true);
            }
        };
        if Instant::now() >= hard {
            io.retire();
            self.report.rejected = self.report.rejected.saturating_add(1);
            observe(Event::AdmissionFailed(Fault::Deadline.into()));
            return Ok(true);
        }
        let client = match self.core.attach() {
            Ok(client) => client,
            Err(error) => {
                io.retire();
                self.report.rejected = self.report.rejected.saturating_add(1);
                observe(Event::AdmissionFailed(error.into()));
                return Ok(true);
            }
        };
        self.peers[index] = Some(Peer {
            client: client.clone(),
            io: Some(io),
            first_until: Some(hard),
            partial_until: None,
            output: None,
            detached: false,
        });
        self.report.accepted = self.report.accepted.saturating_add(1);
        observe(Event::Accepted(client));
        Ok(true)
    }
    fn input(&mut self, index: usize, times: Times) -> Result<Option<Input>, Failure> {
        let peer = self.peers[index].as_mut().ok_or(Fault::Stale)?;
        if peer.expired() {
            return Err(Fault::Deadline.into());
        }
        let io = peer.io.as_mut().ok_or(Fault::Closed)?;
        let Some(frame) = io.frame() else {
            return Ok(None);
        };
        let request = match Request::decode(frame) {
            Ok(request) => request,
            Err(Fault::Unsupported) if self.ports.options.tolerant => {
                if !io.release_frame() {
                    return Err(Fault::Conflict.into());
                }
                peer.partial_until = None;
                return Ok(Some(Input::Ignored));
            }
            Err(error) => return Err(error.into()),
        };
        let admission = self.core.handle(&peer.client, request, times)?;
        self.report.inputs = self.report.inputs.saturating_add(1);
        // Compilation may consume a bounded synchronous work budget. If the
        // original phase elapsed meanwhile, close/cancel its planned jobs before
        // the external factory can admit any new work from this source.
        if [peer.first_until, peer.partial_until]
            .into_iter()
            .flatten()
            .any(|at| Instant::now() >= at)
        {
            return Err(Fault::Deadline.into());
        }
        if !io.release_frame() {
            return Err(Fault::Conflict.into());
        }
        peer.first_until = None;
        peer.partial_until = None;
        Ok(Some(Input::Admitted(admission)))
    }
    fn queue_output(
        &mut self,
        index: usize,
        observe: &mut impl FnMut(Event),
    ) -> Result<bool, Failure> {
        let peer = self.peers[index].as_mut().ok_or(Fault::Stale)?;
        let io = peer.io.as_mut().ok_or(Fault::Closed)?;
        if peer.output.is_none()
            && let Some(id) = self.core.next_output(&peer.client)?
        {
            let value = self.core.output(&id)?;
            let total = value.encoded_len()?;
            if total > self.limits.frame_bytes {
                return Err(Fault::TooLarge.into());
            }
            let hard = Instant::now()
                .checked_add(self.limits.output_lifetime)
                .ok_or(Fault::Overflow)?;
            let write = self.next_write.checked_add(1).ok_or(Fault::Overflow)?;
            self.next_write = write;
            peer.output = Some(Pending {
                id,
                write,
                hard,
                total,
                bytes: 0,
                mq_queued: false,
                core_queued: false,
            });
        }
        let Some(output) = &mut peer.output else {
            return Ok(false);
        };
        if output.mq_queued {
            return Ok(false);
        }
        if Instant::now() >= output.hard {
            return Err(Fault::Deadline.into());
        }
        if !io.capacity(output.total, Class::Ordinary) {
            return Ok(false);
        }
        io.reserve(output.total, Class::Ordinary)?;
        let value = self.core.output(&output.id)?;
        let n = value.encode(&mut self.scratch)?;
        if n != output.total {
            return Err(Fault::Conflict.into());
        }
        let frame = OwnedFrame::copy_from(&self.scratch[..n])?;
        if Instant::now() >= output.hard {
            return Err(Fault::Deadline.into());
        }
        io.enqueue_owned(frame, output.write, Class::Ordinary)
            .map_err(|e| Failure::Protocol(e.reason))?;
        output.mq_queued = true;
        self.core.queued(&output.id)?;
        output.core_queued = true;
        self.report.queued = self.report.queued.saturating_add(1);
        observe(Event::Queued(output.id.clone()));
        Ok(true)
    }
    fn write(
        &mut self,
        index: usize,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event),
    ) -> Result<bool, Failure> {
        let peer = self.peers[index].as_mut().ok_or(Fault::Stale)?;
        if peer.expired() {
            return Err(Fault::Deadline.into());
        }
        let io = peer.io.as_mut().ok_or(Fault::Closed)?;
        let progress = match io.poll_write(cx) {
            Poll::Pending => return Ok(false),
            Poll::Ready(result) => result?,
        };
        let output = peer.output.as_mut().ok_or(Fault::Stale)?;
        if output.write != progress.origin || !output.core_queued {
            return Err(Fault::Stale.into());
        }
        output.bytes = output
            .bytes
            .checked_add(progress.bytes)
            .ok_or(Fault::Overflow)?;
        if output.bytes > output.total || progress.complete != (output.bytes == output.total) {
            return Err(Fault::Conflict.into());
        }
        // Preserve actual positive facts before any subsequent core transition.
        self.report.written_bytes = self
            .report
            .written_bytes
            .saturating_add(progress.bytes as u64);
        if progress.complete {
            self.report.written_frames = self.report.written_frames.saturating_add(1);
        }
        observe(Event::Write {
            output: output.id.clone(),
            bytes: progress.bytes,
            complete: progress.complete,
        });
        self.core.exposed(&output.id)?;
        if progress.complete {
            self.core.written(&output.id)?;
            peer.output = None;
        }
        Ok(true)
    }
    fn peer_step(
        &mut self,
        index: usize,
        cx: &mut Context<'_>,
        times: Times,
        observe: &mut impl FnMut(Event),
    ) -> Result<bool, Failure> {
        let Some(peer) = &self.peers[index] else {
            return Ok(false);
        };
        if peer.io.is_none() {
            return self.finish_close(index, observe).map_err(Into::into);
        }
        if peer.expired() {
            return self.stop_index(index, CloseCause::Deadline, observe);
        }
        if self.core.needs_close(&peer.client)? {
            return self.stop_index(index, CloseCause::CoreRequested, observe);
        }
        let result = (|| -> Result<bool, Failure> {
            let mut changed = self.queue_output(index, observe)?;
            if self.write(index, cx, observe)? {
                return Ok(true);
            }
            if let Some(input) = self.input(index, times)? {
                let client = self.peers[index]
                    .as_ref()
                    .ok_or(Fault::Stale)?
                    .client
                    .clone();
                match input {
                    Input::Admitted(admission) => observe(Event::Input { client, admission }),
                    Input::Ignored => observe(Event::Ignored(client)),
                }
                return Ok(true);
            }
            let peer = self.peers[index].as_mut().ok_or(Fault::Stale)?;
            if peer.expired() {
                return Err(Fault::Deadline.into());
            }
            let step = match peer.io.as_mut().ok_or(Fault::Closed)?.poll_read(cx) {
                Poll::Pending => return Ok(changed),
                Poll::Ready(result) => result?,
            };
            match step {
                ReadStep::Eof => self.stop_index(index, CloseCause::Eof, observe),
                ReadStep::Progress { bytes, complete } => {
                    if bytes > 0 && peer.partial_until.is_none() {
                        peer.partial_until = Some(
                            Instant::now()
                                .checked_add(self.limits.partial_input)
                                .ok_or(Fault::Overflow)?,
                        );
                    }
                    changed |= bytes > 0;
                    if complete && let Some(input) = self.input(index, times)? {
                        let client = self.peers[index]
                            .as_ref()
                            .ok_or(Fault::Stale)?
                            .client
                            .clone();
                        match input {
                            Input::Admitted(admission) => {
                                observe(Event::Input { client, admission })
                            }
                            Input::Ignored => observe(Event::Ignored(client)),
                        }
                        changed = true;
                    }
                    Ok(changed)
                }
            }
        })();
        match result {
            Ok(changed) => Ok(changed),
            Err(error) => self.stop_index(index, CloseCause::Fault(error), observe),
        }
    }
    fn poll_inner(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        wait: Option<Instant>,
        observe: &mut impl FnMut(Event),
    ) -> Poll<Result<Progress, Failure>> {
        let mut changed = self.poll_native_guard(cx, observe)?;
        if self.shutdown {
            if self.is_drained() {
                return Poll::Ready(Ok(Progress::Stopped));
            }
            if self.physical_clients() == 0 && !self.physical_reported {
                self.physical_reported = true;
                return Poll::Ready(Ok(Progress::PhysicalStopped));
            }
            if changed {
                return Poll::Ready(Ok(Progress::Activity));
            }
            self.arm(cx, wait);
            return if wait.is_some_and(|at| Instant::now() >= at) {
                Poll::Ready(Ok(Progress::WaitDeadline))
            } else {
                Poll::Pending
            };
        }
        if let Some(subscription) = &mut self.subscription {
            match subscription.poll_changed(cx, self.revision) {
                Poll::Ready(Ok(sample)) => {
                    self.revision = sample.revision;
                    changed = true;
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                Poll::Pending => {}
            }
        }
        let times = self.sample_times()?;
        changed |= self.poll_native_guard(cx, observe)?;
        let due = self
            .core
            .next_wakeup()
            .is_some_and(|at| at <= times.monotonic);
        self.core.tick(times)?;
        changed |= due;
        if self.accept.ready() && self.peers.iter().any(Option::is_none) && !listeners.is_empty() {
            for _ in 0..listeners.len() {
                let i = self.listener_cursor % listeners.len();
                self.listener_cursor = self.listener_cursor.wrapping_add(1);
                match listeners[i].poll_canonical_connection(cx) {
                    Poll::Pending => {}
                    Poll::Ready(Ok(connection)) => {
                        changed |= self.attach(connection, observe)?;
                        break;
                    }
                    Poll::Ready(Err(error)) => {
                        observe(Event::Socket(self.accept.failed(error)));
                        changed = true;
                        break;
                    }
                }
            }
        }
        for _ in 0..self.limits.quantum.min(self.peers.len()) {
            let index = self.cursor % self.peers.len();
            self.cursor = self.cursor.wrapping_add(1);
            changed |= self.peer_step(index, cx, times, observe)?;
        }
        let core_wake = self
            .core
            .next_wakeup()
            .map(|at| {
                self.native_epoch
                    .checked_add(std::time::Duration::from_micros(at))
                    .ok_or(Fault::Overflow)
            })
            .transpose()?;
        let target = [self.native_target(), core_wake, wait]
            .into_iter()
            .flatten()
            .min();
        self.arm(cx, target);
        if changed {
            Poll::Ready(Ok(Progress::Activity))
        } else if wait.is_some_and(|at| Instant::now() >= at) {
            Poll::Ready(Ok(Progress::WaitDeadline))
        } else {
            Poll::Pending
        }
    }
    /// Fair bounded actual IPC progress. Any global clock/core error first stops
    /// all original physical MQs, leaving backend retirement work in Core.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        wait: Option<Instant>,
        mut observe: impl FnMut(Event),
    ) -> Poll<Result<Progress, Failure>> {
        match self.poll_inner(cx, listeners, wait, &mut observe) {
            Poll::Ready(Err(original)) => {
                let result = match self.close_all(&mut observe) {
                    Ok(_) => original,
                    Err(cleanup) => Failure::Cleanup {
                        original: Box::new(original),
                        cleanup: Box::new(cleanup),
                    },
                };
                Poll::Ready(Err(result))
            }
            result => result,
        }
    }
    /// Canceling observation preserves original frames/cursors/phase deadlines.
    /// It does not cancel the announcement/search or permit replacing its MQ.
    pub async fn drive(
        &mut self,
        listeners: &[Listener<'_>],
        wait: Option<Instant>,
        mut observe: impl FnMut(Event),
    ) -> Result<Progress, Failure> {
        poll_fn(|cx| self.poll(cx, listeners, wait, &mut observe)).await
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        let _original_close = self.close_all(|_| {});
    }
}
