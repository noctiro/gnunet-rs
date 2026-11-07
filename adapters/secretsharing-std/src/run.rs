use crate::{ClientReport, DecryptFacts, Error, Limits, Sources, generate};
use gnunet_secretsharing_decrypt_host as decrypt;
use gnunet_service_runtime::{
    clock::{Deadline, RuntimeClock},
    framing::{Class, Framed, ReadStep},
};
use gnunet_types::Error as Fault;
use gnunet_wire::official::{Frame, MessageHeader, message_type as mt, secretsharing as ipc};
use std::{
    cell::{Cell, RefCell},
    future::{Future, poll_fn},
    mem::size_of,
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
pub(crate) type Origin = u64;
pub(crate) type Session = dyn Future<Output = Box<ClientReport>>;
pub(crate) struct Control {
    reason: Cell<Option<Fault>>,
}
impl Control {
    pub fn new() -> Self {
        Self {
            reason: Cell::new(None),
        }
    }
    pub fn cancel(&self, reason: Fault) {
        if self.reason.get().is_none() {
            self.reason.set(Some(reason));
        }
    }
    pub fn reason(&self) -> Option<Fault> {
        self.reason.get()
    }
}
pub(crate) struct Registry {
    operations: Cell<usize>,
    bytes: Cell<usize>,
    failed: Cell<bool>,
    limits: Limits,
    waiter: RefCell<Option<Waker>>,
}
impl Registry {
    pub fn new(limits: Limits, fixed: usize) -> Result<Self, Error> {
        if fixed > limits.total_retained_bytes {
            return Err(Fault::Capacity.into());
        }
        Ok(Self {
            operations: Cell::new(0),
            bytes: Cell::new(fixed),
            failed: Cell::new(false),
            limits,
            waiter: RefCell::new(None),
        })
    }
    pub fn healthy(&self) -> bool {
        !self.failed.get()
    }
    pub fn pending(&self) -> usize {
        self.operations.get()
    }
    pub fn wait(&self, cx: &Context<'_>) {
        let replacement = cx.waker().clone();
        let old = self.waiter.borrow_mut().replace(replacement);
        drop(old);
    }
    fn wake(&self) {
        let wake = self.waiter.borrow_mut().take();
        if let Some(wake) = wake {
            wake.wake();
        }
    }
    pub fn storage(self: &Rc<Self>, bytes: usize) -> Result<Storage, Error> {
        let total = self.bytes.get().checked_add(bytes).ok_or(Fault::Overflow)?;
        if !self.healthy() {
            return Err(Fault::NotReady.into());
        }
        if total > self.limits.total_retained_bytes {
            return Err(Fault::Capacity.into());
        }
        self.bytes.set(total);
        Ok(Storage {
            registry: self.clone(),
            bytes,
        })
    }
    fn permit(self: &Rc<Self>) -> Result<Permit, Error> {
        if !self.healthy() {
            return Err(Fault::NotReady.into());
        }
        let count = self
            .operations
            .get()
            .checked_add(1)
            .ok_or(Fault::Overflow)?;
        let bytes = self
            .bytes
            .get()
            .checked_add(self.limits.operation_bytes)
            .ok_or(Fault::Overflow)?;
        if count > self.limits.operations || bytes > self.limits.total_retained_bytes {
            return Err(Fault::WouldBlock.into());
        }
        self.operations.set(count);
        self.bytes.set(bytes);
        Ok(Permit {
            registry: self.clone(),
        })
    }
}
pub(crate) struct Storage {
    registry: Rc<Registry>,
    bytes: usize,
}
impl Drop for Storage {
    fn drop(&mut self) {
        if let Some(bytes) = self.registry.bytes.get().checked_sub(self.bytes) {
            self.registry.bytes.set(bytes);
        } else {
            self.registry.failed.set(true);
        }
        self.registry.wake();
    }
}
struct Permit {
    registry: Rc<Registry>,
}
impl Drop for Permit {
    fn drop(&mut self) {
        match (
            self.registry.operations.get().checked_sub(1),
            self.registry
                .bytes
                .get()
                .checked_sub(self.registry.limits.operation_bytes),
        ) {
            (Some(count), Some(bytes)) => {
                self.registry.operations.set(count);
                self.registry.bytes.set(bytes);
            }
            _ => self.registry.failed.set(true),
        }
        self.registry.wake();
    }
}
#[derive(Clone, Copy)]
pub(crate) struct Targets {
    pub canonical: u64,
    pub hard: Instant,
}
impl Targets {
    pub fn new(clock: &dyn RuntimeClock, life: Duration) -> Result<Self, Error> {
        let native = Instant::now();
        let hard = native.checked_add(life).ok_or(Fault::Overflow)?;
        let now = clock.sample()?.now.as_micros();
        if life.is_zero() || Instant::now() >= hard {
            return Err(Fault::Deadline.into());
        }
        let canonical = now
            .checked_add(u64::try_from(life.as_micros()).map_err(|_| Fault::Overflow)?)
            .filter(|v| *v != u64::MAX)
            .ok_or(Fault::Overflow)?;
        Ok(Self { canonical, hard })
    }
    fn capped(self, parent: Self) -> Self {
        Self {
            canonical: self.canonical.min(parent.canonical),
            hard: self.hard.min(parent.hard),
        }
    }
    pub(crate) fn native(self) -> Result<(), Error> {
        if Instant::now() >= self.hard {
            Err(Fault::Deadline.into())
        } else {
            Ok(())
        }
    }
    pub(crate) fn check(self, clock: &dyn RuntimeClock) -> Result<(), Error> {
        self.native()?;
        let now = clock.sample()?.now.as_micros();
        self.native()?;
        if now >= self.canonical {
            return Err(Fault::Deadline.into());
        }
        Ok(())
    }
    pub(crate) fn deadline(self, clock: &dyn RuntimeClock, deadline: u64) -> Result<Self, Error> {
        let native = Instant::now();
        let now = clock.sample()?.now.as_micros();
        let canonical = self.canonical.min(deadline);
        let remaining = canonical
            .checked_sub(now)
            .filter(|n| *n > 0)
            .ok_or(Fault::Deadline)?;
        // FOREVER/raw far-future requests are still limited by the finite
        // original service admission target, without overflowing a needless
        // intermediate native timestamp or extending that original hard.
        let native_budget = self
            .hard
            .checked_duration_since(native)
            .ok_or(Fault::Deadline)?;
        let remaining = Duration::from_micros(remaining);
        let hard = if remaining >= native_budget {
            self.hard
        } else {
            native.checked_add(remaining).ok_or(Fault::Overflow)?
        };
        let value = Self { canonical, hard };
        value.check(clock)?;
        Ok(value)
    }
    fn bounds(self) -> decrypt::Bounds {
        decrypt::Bounds {
            expires: self.canonical,
            hard: self.hard,
        }
    }
}
struct Alarm {
    targets: Targets,
    logical: Pin<Box<Deadline>>,
    native: Pin<Box<tokio::time::Sleep>>,
}
impl Alarm {
    fn new(targets: Targets, clock: Arc<dyn RuntimeClock>) -> Result<Self, Error> {
        Ok(Self {
            targets,
            logical: Box::pin(Deadline::at(
                clock,
                gnunet_types::AbsoluteTime::from_micros(targets.canonical),
            )?),
            native: Box::pin(tokio::time::sleep_until(targets.hard.into())),
        })
    }
    fn poll(&mut self, cx: &mut Context<'_>, clock: &dyn RuntimeClock) -> Result<(), Error> {
        self.targets.native()?;
        if self.native.as_mut().poll(cx).is_ready() {
            return Err(Fault::Deadline.into());
        }
        self.targets.check(clock)?;
        match self.logical.as_mut().poll(cx) {
            Poll::Pending => Ok(()),
            Poll::Ready(Ok(())) => Err(Fault::Deadline.into()),
            Poll::Ready(Err(error)) => Err(error.into()),
        }
    }
}
pub(crate) struct Admission {
    pub whole: Targets,
    pub first: Targets,
}
impl Admission {
    pub fn new(clock: &dyn RuntimeClock, limits: Limits) -> Result<Self, Error> {
        let whole = Targets::new(clock, limits.operation)?;
        let first = Targets::new(clock, limits.first_input)?.capped(whole);
        Ok(Self { whole, first })
    }
}
#[expect(
    clippy::large_enum_variant,
    reason = "One bounded owned request is charged in the original client future; keep the existing private decrypt request inline without another heap allocation"
)]
enum Request {
    Decrypt(decrypt::Request),
    Generate(generate::Request),
}
struct Io {
    io: Framed<Origin>,
    sources: Sources,
    limits: Limits,
    registry: Rc<Registry>,
    control: Rc<Control>,
    report: Box<ClientReport>,
    request: Option<Request>,
    whole: Alarm,
    first: Option<Alarm>,
    partial: Option<Alarm>,
    output: Option<Alarm>,
    active: bool,
    classified: bool,
    turn: bool,
    finished: bool,
    tolerant: bool,
}
enum Input {
    Activity,
    Complete,
}
impl Io {
    fn new(
        io: Framed<Origin>,
        sources: Sources,
        limits: Limits,
        registry: Rc<Registry>,
        control: Rc<Control>,
        tolerant: bool,
        admission: Admission,
    ) -> Result<Self, Error> {
        let clock = sources.clock();
        let whole = Alarm::new(admission.whole, clock.clone())?;
        let first = Some(Alarm::new(admission.first, clock)?);
        Ok(Self {
            io,
            sources,
            limits,
            registry,
            control,
            report: Box::new(ClientReport::default()),
            request: None,
            whole,
            first,
            partial: None,
            output: None,
            active: false,
            classified: false,
            turn: false,
            finished: false,
            tolerant,
        })
    }
    fn guard(&mut self, cx: &mut Context<'_>) -> Result<(), Error> {
        if let Some(reason) = self.control.reason() {
            return Err(reason.into());
        }
        if !self.registry.healthy() {
            return Err(Fault::NotReady.into());
        }
        let clock = self.sources.clock.as_ref();
        self.whole.poll(cx, clock)?;
        for alarm in self
            .first
            .iter_mut()
            .chain(self.partial.iter_mut())
            .chain(self.output.iter_mut())
        {
            alarm.poll(cx, clock)?;
        }
        Ok(())
    }
    fn storage_bound(&self) -> Result<(), Error> {
        let maximum = self
            .limits
            .frame_bytes
            .checked_mul(8)
            .ok_or(Fault::Overflow)?;
        if self.io.retained_storage_bytes()? > maximum {
            return Err(Fault::Capacity.into());
        }
        Ok(())
    }
    fn read(&mut self, cx: &mut Context<'_>) -> Poll<Result<Input, Error>> {
        self.guard(cx)?;
        if self.io.frame().is_some() {
            if self.active {
                return Poll::Ready(Err(Error::DuplicateRequest));
            }
            return Poll::Ready(Ok(Input::Complete));
        }
        let candidate = if self.partial.is_none() {
            Some(
                Targets::new(self.sources.clock.as_ref(), self.limits.partial_input)?
                    .capped(self.whole.targets),
            )
        } else {
            None
        };
        // A provider sample above cannot renew an already existing input bound.
        self.guard(cx)?;
        match self.io.poll_read(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
            Poll::Ready(Ok(ReadStep::Eof)) => Poll::Ready(Err(Error::Eof)),
            Poll::Ready(Ok(ReadStep::Progress { bytes, complete })) => {
                self.report.bytes.0 = self
                    .report
                    .bytes
                    .0
                    .checked_add(u64::try_from(bytes).map_err(|_| Fault::Overflow)?)
                    .ok_or(Fault::Overflow)?;
                self.storage_bound()?;
                if self.active && bytes != 0 {
                    return Poll::Ready(Err(Error::DuplicateRequest));
                }
                if let Some(targets) = candidate
                    && bytes != 0
                {
                    self.partial = Some(Alarm::new(targets, self.sources.clock())?);
                }
                self.guard(cx)?;
                if complete {
                    self.partial = None;
                    self.report.input_complete = true;
                    Poll::Ready(Ok(Input::Complete))
                } else {
                    Poll::Ready(Ok(Input::Activity))
                }
            }
        }
    }
    fn classify(&mut self, cx: &mut Context<'_>) -> Result<bool, Error> {
        self.guard(cx)?;
        let frame = self.io.frame().ok_or(Fault::NotReady)?;
        let header = MessageHeader::decode(frame)?;
        if !matches!(
            header.message_type(),
            mt::SECRETSHARING_CLIENT_GENERATE | mt::SECRETSHARING_CLIENT_DECRYPT
        ) {
            if self.tolerant {
                if !self.io.release_frame() {
                    return Err(Fault::Conflict.into());
                }
                self.partial = None;
                return Ok(false);
            }
            return Err(Fault::Unsupported.into());
        }
        if !self.classified {
            let deadline = match ipc::Request::decode(Frame::decode(frame)?)? {
                ipc::Request::Decrypt { deadline, .. } => deadline,
                ipc::Request::Generate(raw) => {
                    if raw.start >= raw.deadline {
                        return Err(Fault::InvalidInput.into());
                    }
                    raw.deadline
                }
            };
            let target = self
                .whole
                .targets
                .deadline(self.sources.clock.as_ref(), deadline)?;
            self.whole = Alarm::new(target, self.sources.clock())?;
            self.classified = true;
            self.first = None;
        }
        self.guard(cx)?;
        Ok(true)
    }
    fn prepare(&mut self, cx: &mut Context<'_>) -> Result<(), Error> {
        self.guard(cx)?;
        if self.request.is_some() {
            return Ok(());
        }
        let frame = self.io.frame().ok_or(Fault::NotReady)?;
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(frame.len())
            .map_err(|_| Fault::Capacity)?;
        if bytes.capacity() > self.limits.frame_bytes {
            return Err(Fault::Capacity.into());
        }
        bytes.extend_from_slice(frame);
        // Both exact capacities are already reserved. Erase Framed's used
        // original before retaining one private queued Request. Socket EOF can
        // now be observed even while waiting for the actual operation permit.
        if !self.io.release_frame() {
            return Err(Fault::Conflict.into());
        }
        self.partial = None;
        let request = match MessageHeader::decode(&bytes)?.message_type() {
            mt::SECRETSHARING_CLIENT_DECRYPT => Request::Decrypt(decrypt::Request::from_frame(
                bytes,
                self.limits.index_order,
                self.limits.decrypt,
            )?),
            mt::SECRETSHARING_CLIENT_GENERATE => {
                self.report.generating = true;
                Request::Generate(generate::Request::from_frame(bytes, self.limits)?)
            }
            _ => return Err(Fault::Conflict.into()),
        };
        self.guard(cx)?;
        self.report.requests = 1;
        self.active = true;
        self.request = Some(request);
        Ok(())
    }
    fn claim(&mut self, cx: &mut Context<'_>) -> Result<Option<(Request, Permit)>, Error> {
        self.guard(cx)?;
        let permit = match self.registry.permit() {
            Ok(permit) => permit,
            Err(Error::Protocol(Fault::WouldBlock)) => {
                self.registry.wait(cx);
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let request = self.request.take().ok_or(Fault::NotReady)?;
        self.report.operation_admitted = true;
        Ok(Some((request, permit)))
    }
    fn result(
        &mut self,
        plain: gnunet_secretsharing_decrypt_host::Progress,
        cx: &mut Context<'_>,
    ) -> Result<(), Error> {
        self.guard(cx)?;
        let decrypt::Progress::Done(plain) = plain else {
            return Err(Fault::Conflict.into());
        };
        // This branch alone owns a real mathematical result. Zeroizing stack
        // copies exist only through the standard782 secure framing admission.
        self.report.mathematical_done = true;
        let encoded = plain.to_bytes();
        let mut frame = Zeroizing::new([0u8; 136]);
        ipc::Response::DecryptDone {
            success: 1,
            plaintext: &encoded,
        }
        .encode(frame.as_mut())?;
        self.response(frame.as_ref(), cx)
    }
    fn generated(
        &mut self,
        generated: generate::Generated,
        cx: &mut Context<'_>,
    ) -> Result<(), Error> {
        self.guard(cx)?;
        self.report.mathematical_done = true;
        self.response(generated.bytes(), cx)
    }
    fn response(&mut self, frame: &[u8], cx: &mut Context<'_>) -> Result<(), Error> {
        let target = Targets::new(self.sources.clock.as_ref(), self.limits.output)?
            .capped(self.whole.targets);
        self.output = Some(Alarm::new(target, self.sources.clock())?);
        self.guard(cx)?;
        self.io.enqueue_copy(frame, 1, Class::Ordinary)?;
        self.report.response = (frame.len(), 0);
        self.storage_bound()?;
        Ok(())
    }
    fn work<T>(
        &mut self,
        cx: &mut Context<'_>,
        mut poll: impl FnMut(&mut Context<'_>) -> Poll<Result<Option<T>, Error>>,
    ) -> Poll<Result<T, Error>> {
        self.guard(cx)?;
        self.turn = !self.turn;
        for class in 0..2 {
            if (class == 0) == self.turn {
                match self.read(cx) {
                    Poll::Pending => {}
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(_)) => {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
            } else {
                self.guard(cx)?;
                match poll(cx) {
                    Poll::Pending => {}
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(Some(done))) => {
                        self.guard(cx)?;
                        return Poll::Ready(Ok(done));
                    }
                    Poll::Ready(Ok(None)) => {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
            }
        }
        Poll::Pending
    }
    fn write(&mut self, cx: &mut Context<'_>) -> Poll<Result<bool, Error>> {
        self.guard(cx)?;
        match self.io.poll_write(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
            Poll::Ready(Ok(progress)) => {
                if progress.origin != 1 {
                    return Poll::Ready(Err(Fault::StaleGeneration.into()));
                }
                self.report.bytes.1 = self
                    .report
                    .bytes
                    .1
                    .checked_add(u64::try_from(progress.bytes).map_err(|_| Fault::Overflow)?)
                    .ok_or(Fault::Overflow)?;
                self.report.response.1 = self
                    .report
                    .response
                    .1
                    .checked_add(progress.bytes)
                    .ok_or(Fault::Overflow)?;
                if self.report.response.0 == 0
                    || self.report.response.1 > self.report.response.0
                    || progress.complete != (self.report.response.1 == self.report.response.0)
                {
                    return Poll::Ready(Err(Fault::Conflict.into()));
                }
                if progress.complete {
                    self.report.results_written = 1;
                }
                // Apply the actual prefix/whole fact before any later clock
                // refusal; keep a late/error result distinct from zero write.
                self.guard(cx)?;
                if progress.complete {
                    self.output = None;
                }
                Poll::Ready(Ok(progress.complete))
            }
        }
    }
    fn retire(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        self.io.retire();
        // A merely quota-queued private Request is also explicitly erased on
        // retirement, before diagnostics or user callbacks may block.
        self.request = None;
        self.report.physical_closed = true;
        self.report.output_retired =
            self.report.response.0 != 0 && self.report.results_written == 0;
    }
}
impl Drop for Io {
    fn drop(&mut self) {
        self.retire();
    }
}
struct Inputs {
    io: Io,
    spare: Box<ClientReport>,
}
pub(crate) fn session(
    io: Framed<Origin>,
    sources: Sources,
    limits: Limits,
    registry: Rc<Registry>,
    control: Rc<Control>,
    tolerant: bool,
    admission: Admission,
) -> Result<impl Future<Output = Box<ClientReport>>, Error> {
    let input = Inputs {
        io: Io::new(io, sources, limits, registry, control, tolerant, admission)?,
        spare: Box::new(ClientReport::default()),
    };
    Ok(async move {
        let Inputs { mut io, spare } = input;
        let mut instance = gnunet_pils::client::Instance::new();
        let mut generation_instance = gnunet_pils::client::Instance::new();
        let mut owner = None;
        let mut generator = None;
        let mut permit = None;
        let result = async {
            let request = poll_fn(|cx| {
                io.guard(cx)?;
                if io.request.is_none() && io.io.frame().is_some() {
                    if !io.classify(cx)? {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    io.prepare(cx)?;
                }
                if io.request.is_some()
                    && let Some((request, admitted)) = io.claim(cx)?
                {
                    permit = Some(admitted);
                    return Poll::Ready(Ok::<_, Error>(request));
                }
                match io.read(cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                    Poll::Ready(Ok(_)) => {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                }
            })
            .await?;
            io.whole.targets.check(io.sources.clock.as_ref())?;
            match request {
                Request::Decrypt(request) => {
                    let sources = io.sources.native()?;
                    io.whole.targets.check(io.sources.clock.as_ref())?;
                    owner = Some(decrypt::Decrypt::new(
                        &mut instance,
                        sources,
                        request,
                        io.limits.decrypt,
                        io.whole.targets.bounds(),
                    )?);
                    io.report.owner_started = true;
                    let done = poll_fn(|cx| {
                        io.work(cx, |cx| {
                            match owner.as_mut().ok_or(Fault::NotReady)?.poll_progress(cx) {
                                Poll::Pending => Poll::Pending,
                                Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
                                Poll::Ready(Ok(done @ decrypt::Progress::Done(_))) => {
                                    Poll::Ready(Ok(Some(done)))
                                }
                                Poll::Ready(Ok(_)) => Poll::Ready(Ok(None)),
                            }
                        })
                    })
                    .await?;
                    let facts = owner
                        .as_mut()
                        .ok_or(Fault::NotReady)?
                        .take_report()
                        .ok_or(Fault::NotReady)?;
                    let healthy = facts.completed && facts.pils_idle;
                    io.report.decrypt = Some(DecryptFacts::from(facts));
                    drop(owner.take());
                    if !healthy {
                        io.report.undrained = io.report.undrained.saturating_add(1);
                        return Err(Fault::NotReady.into());
                    }
                    let mut done = Some(done);
                    poll_fn(|cx| Poll::Ready(io.result(done.take().ok_or(Fault::NotReady)?, cx)))
                        .await?;
                }
                Request::Generate(request) => {
                    generator = Some(generate::Owner::new(
                        &mut generation_instance,
                        &io.sources,
                        request,
                        io.limits,
                        io.whole.targets,
                    )?);
                    io.report.owner_started = true;
                    let done = poll_fn(|cx| {
                        io.work(cx, |cx| generator.as_mut().ok_or(Fault::NotReady)?.poll(cx))
                    })
                    .await?;
                    let facts = generator
                        .as_mut()
                        .ok_or(Fault::NotReady)?
                        .close()
                        .ok_or(Fault::NotReady)?;
                    let healthy = facts.completed && facts.pils_idle;
                    io.report.generate = Some(facts);
                    drop(generator.take());
                    if !healthy {
                        io.report.undrained = io.report.undrained.saturating_add(1);
                        return Err(Fault::NotReady.into());
                    }
                    let mut done = Some(done);
                    poll_fn(|cx| {
                        Poll::Ready(io.generated(done.take().ok_or(Fault::NotReady)?, cx))
                    })
                    .await?;
                }
            }
            poll_fn(|cx| {
                io.guard(cx)?;
                io.turn = !io.turn;
                for class in 0..2 {
                    if (class == 0) == io.turn {
                        match io.read(cx) {
                            Poll::Pending => {}
                            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                            Poll::Ready(Ok(_)) => {
                                cx.waker().wake_by_ref();
                                return Poll::Pending;
                            }
                        }
                    } else {
                        match io.write(cx) {
                            Poll::Pending => {}
                            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                            Poll::Ready(Ok(true)) => return Poll::Ready(Ok(())),
                            Poll::Ready(Ok(false)) => {
                                cx.waker().wake_by_ref();
                                return Poll::Pending;
                            }
                        }
                    }
                }
                Poll::Pending
            })
            .await
        }
        .await;
        // First physically fence this original IPC, then retire each actual
        // dependency and erase mathematical work. No further provider sample.
        io.retire();
        if let Some(native) = &mut owner {
            if let Some(report) = native.close() {
                if !report.pils_idle {
                    io.report.undrained = io.report.undrained.saturating_add(1);
                }
                io.report.decrypt = Some(DecryptFacts::from(report));
            } else {
                io.report.undrained = io.report.undrained.saturating_add(1);
                io.report
                    .cleanup
                    .get_or_insert_with(|| Fault::NotReady.into());
            }
        }
        if let Some(native) = &mut generator {
            if let Some(report) = native.close() {
                if !report.pils_idle {
                    io.report.undrained = io.report.undrained.saturating_add(1);
                }
                io.report.generate = Some(report);
            } else {
                io.report.undrained = io.report.undrained.saturating_add(1);
                io.report
                    .cleanup
                    .get_or_insert_with(|| Fault::NotReady.into());
            }
        }
        drop(generator.take());
        drop(owner.take());
        drop(permit);
        if let Err(error) = result {
            io.report.primary.get_or_insert(error);
        }
        // Move the report preallocated before any socket/math IO. Io Drop has
        // already been made idempotent, so no allocation follows retirement.
        std::mem::replace(&mut io.report, spare)
    })
}
pub(crate) fn future_bytes(
    value: &impl Future<Output = Box<ClientReport>>,
) -> Result<usize, Error> {
    std::mem::size_of_val(value)
        .checked_add(2 * size_of::<ClientReport>())
        .ok_or_else(|| Fault::Overflow.into())
}
