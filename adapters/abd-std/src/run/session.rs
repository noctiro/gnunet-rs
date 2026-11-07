use super::{
    Control, Mailbox, Output, Permit, QueryReport, Registry, StorageLease, Targets, query,
};
use crate::{ClientReport, Error, Limits, Sources};
use gnunet_service_runtime::framing::{Class, Framed, OwnedFrame, ReadStep};
use gnunet_types::Error as Fault;
use gnunet_wire::official::{MessageHeader, abd as ipc, message_type as mt};
use std::{
    cell::RefCell,
    collections::VecDeque,
    future::Future,
    mem::{size_of, size_of_val},
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
};
use tokio::time::Sleep;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct Origin {
    query: u64,
    terminal: bool,
}
struct Pending {
    terminal: bool,
    capacity: usize,
    written: usize,
    hard: std::time::Instant,
}
struct Row {
    permit: Permit,
    rid: u32,
    targets: Targets,
    mailbox: Mailbox,
    future: Option<Pin<Box<dyn Future<Output = QueryReport>>>>,
    report: Option<QueryReport>,
    pending: Option<Pending>,
}
pub(crate) struct Session {
    io: Framed<Origin>,
    sources: Sources,
    limits: Limits,
    registry: Rc<Registry>,
    control: Rc<Control>,
    storage: Option<StorageLease>,
    rows: Vec<Option<Row>>,
    order: VecDeque<u64>,
    first: Option<Targets>,
    partial: Option<Targets>,
    admission: Option<Targets>,
    queued_capacity: usize,
    row_cursor: usize,
    class: usize,
    report: ClientReport,
    finished: bool,
    tolerant: bool,
    alarm: Pin<Box<Sleep>>,
}
impl Session {
    pub fn new(
        io: Framed<Origin>,
        sources: Sources,
        limits: Limits,
        registry: Rc<Registry>,
        control: Rc<Control>,
        tolerant: bool,
        first: Targets,
    ) -> Result<Self, Error> {
        first.check(sources.clock.as_ref())?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(limits.queries_per_client)
            .map_err(|_| Fault::Capacity)?;
        rows.resize_with(limits.queries_per_client, || None);
        let mut order = VecDeque::new();
        order
            .try_reserve_exact(limits.queries_per_client)
            .map_err(|_| Fault::Capacity)?;
        let mut value = Self {
            io,
            sources,
            limits,
            registry,
            control,
            storage: None,
            rows,
            order,
            first: Some(first),
            partial: None,
            admission: None,
            queued_capacity: 0,
            row_cursor: 0,
            class: 0,
            report: ClientReport::default(),
            finished: false,
            tolerant,
            alarm: Box::pin(tokio::time::sleep(std::time::Duration::ZERO)),
        };
        let bytes = value.storage_bytes()?;
        value.storage = Some(value.registry.reserve_storage(bytes)?);
        value.guard()?;
        Ok(value)
    }
    fn storage_bytes(&self) -> Result<usize, Error> {
        // Frame payloads move between mailbox and TX under their original query
        // reservation. Charge only RX+retained TX node storage here, avoiding
        // silently treating queue wire length as actual heap capacity.
        let frames = self
            .io
            .retained_storage_bytes()?
            .checked_sub(self.queued_capacity)
            .ok_or(Fault::Conflict)?;
        let rows = self
            .rows
            .capacity()
            .checked_mul(size_of::<Option<Row>>())
            .ok_or(Fault::Overflow)?;
        let order = self
            .order
            .capacity()
            .checked_mul(size_of::<u64>())
            .ok_or(Fault::Overflow)?;
        frames
            .checked_add(rows)
            .and_then(|n| n.checked_add(order))
            .and_then(|n| n.checked_add(size_of::<Self>() + size_of::<Sleep>()))
            .and_then(|n| n.checked_add(size_of::<Control>() + 2 * size_of::<usize>()))
            .ok_or_else(|| Fault::Overflow.into())
    }
    fn account(&mut self) -> Result<(), Error> {
        let actual = self.storage_bytes()?;
        self.storage.as_mut().ok_or(Fault::NotReady)?.resize(actual)
    }
    fn native_guard(&self) -> Result<(), Error> {
        if let Some(cause) = self.control.reason() {
            return Err(cause.into());
        }
        if !self.registry.healthy() {
            return Err(Fault::NotReady.into());
        }
        for target in self
            .first
            .into_iter()
            .chain(self.partial)
            .chain(self.admission)
            .chain(self.rows.iter().flatten().map(|r| r.targets))
        {
            target.native()?;
        }
        let now = std::time::Instant::now();
        if self
            .rows
            .iter()
            .flatten()
            .filter_map(|r| r.pending.as_ref())
            .any(|p| now >= p.hard)
        {
            return Err(Fault::Deadline.into());
        }
        Ok(())
    }
    fn guard(&self) -> Result<(), Error> {
        self.native_guard()?;
        let now = self.sources.clock.sample()?.now.as_micros();
        self.native_guard()?;
        if self
            .first
            .into_iter()
            .chain(self.partial)
            .chain(self.admission)
            .chain(self.rows.iter().flatten().map(|r| r.targets))
            .any(|t| now >= t.canonical)
        {
            return Err(Fault::Deadline.into());
        }
        Ok(())
    }
    fn merge(&mut self, mut report: QueryReport) {
        if let Some(error) = report.primary.take() {
            self.report.primary.get_or_insert(error);
        }
        if let Some(error) = report.cleanup.take() {
            self.report.cleanup.get_or_insert(error);
        }
        self.report.lookups = self.report.lookups.saturating_add(report.lookups);
        self.report.lookup_writes = self
            .report
            .lookup_writes
            .saturating_add(report.lookup_writes);
        self.report.answers = self.report.answers.saturating_add(report.answers);
        self.report.ignored_records = self.report.ignored_records.saturating_add(report.ignored);
        self.report.collection_writes = self
            .report
            .collection_writes
            .saturating_add(report.collection_writes);
        self.report.undrained = self.report.undrained.saturating_add(report.undrained);
    }
    fn incoming(&mut self, cx: &mut Context<'_>) -> Result<bool, Error> {
        self.guard()?;
        if let Some(frame) = self.io.frame() {
            let targets = match self.admission {
                Some(original) => original,
                None => {
                    let original =
                        Targets::new(self.sources.clock.as_ref(), self.limits.operation)?;
                    self.admission = Some(original);
                    original
                }
            };
            targets.check(self.sources.clock.as_ref())?;
            let header = MessageHeader::decode(frame)?;
            if header.message_type() != mt::ABD_VERIFY && header.message_type() != mt::ABD_COLLECT {
                if self.tolerant {
                    let released = self.io.release_frame();
                    if !released {
                        return Err(Fault::Conflict.into());
                    }
                    self.partial = None;
                    self.admission = None;
                    return Ok(true);
                }
                return Err(Fault::Unsupported.into());
            }
            let rid = match ipc::Request::decode(frame)? {
                ipc::Request::Verify { id, .. } | ipc::Request::Collect { id, .. } => id,
            };
            if self.rows.iter().flatten().any(|r| r.rid == rid) {
                return Err(Fault::Conflict.into());
            }
            let Some(index) = self.rows.iter().position(Option::is_none) else {
                return Ok(false);
            };
            let permit = match self.registry.reserve() {
                Ok(v) => v,
                Err(Error::Protocol(Fault::Capacity)) => return Ok(false),
                Err(e) => return Err(e),
            };
            let mut copied = Zeroizing::new(Vec::new());
            copied
                .try_reserve_exact(frame.len())
                .map_err(|_| Fault::Capacity)?;
            if copied.capacity() > self.limits.frame_bytes {
                return Err(Fault::Capacity.into());
            }
            copied.extend_from_slice(frame);
            let raw = OwnedFrame::new(std::mem::take(&mut *copied));
            targets.check(self.sources.clock.as_ref())?;
            let mailbox = Rc::new(RefCell::new(None));
            let future = query::run(
                raw,
                self.sources.duplicate()?,
                self.limits,
                targets,
                self.control.clone(),
                mailbox.clone(),
            );
            let overhead = self
                .limits
                .frame_bytes
                .max(self.limits.gns.frame_bytes)
                .max(self.limits.namestore.frame_bytes)
                .checked_mul(8)
                .and_then(|n| n.checked_add(256 * 1024))
                .ok_or(Fault::Overflow)?;
            if size_of_val(&future)
                .checked_add(self.limits.core.retained_bytes)
                .and_then(|n| n.checked_add(overhead))
                .is_none_or(|n| n > self.limits.query_bytes)
            {
                return Err(Fault::Capacity.into());
            }
            self.rows[index] = Some(Row {
                permit,
                rid,
                targets,
                mailbox,
                future: Some(Box::pin(future)),
                report: None,
                pending: None,
            });
            let released = self.io.release_frame();
            if !released {
                return Err(Fault::Conflict.into());
            }
            self.first = None;
            self.partial = None;
            self.admission = None;
            self.report.queries = self.report.queries.saturating_add(1);
            return Ok(true);
        }
        match self.io.poll_read(cx) {
            Poll::Pending => Ok(false),
            Poll::Ready(Err(error)) => Err(error.into()),
            Poll::Ready(Ok(ReadStep::Eof)) => Err(Fault::Closed.into()),
            Poll::Ready(Ok(ReadStep::Progress { bytes, complete })) => {
                self.report.read_bytes = self
                    .report
                    .read_bytes
                    .checked_add(u64::try_from(bytes).map_err(|_| Fault::Overflow)?)
                    .ok_or(Fault::Overflow)?;
                if bytes > 0 && self.partial.is_none() {
                    self.partial = Some(Targets::new(
                        self.sources.clock.as_ref(),
                        self.limits.partial_input,
                    )?);
                }
                if complete {
                    self.partial = None;
                    if self.admission.is_none() {
                        self.admission = Some(Targets::new(
                            self.sources.clock.as_ref(),
                            self.limits.operation,
                        )?);
                    }
                }
                self.native_guard()?;
                Ok(bytes > 0)
            }
        }
    }
    fn jobs(&mut self, cx: &mut Context<'_>) -> Result<bool, Error> {
        let count = self.rows.len();
        for offset in 0..count {
            let index = (self.row_cursor + offset) % count;
            let Some(row) = self.rows[index].as_mut() else {
                continue;
            };
            if let Some(future) = &mut row.future
                && let Poll::Ready(report) = future.as_mut().poll(cx)
            {
                row.future = None;
                if report.primary.is_some() || report.cleanup.is_some() || report.undrained != 0 {
                    self.row_cursor = (index + 1) % count;
                    self.merge(report);
                    return Err(Fault::Unavailable.into());
                }
                row.report = Some(report);
                self.row_cursor = (index + 1) % count;
                return Ok(true);
            }
        }
        self.row_cursor = (self.row_cursor + 1) % count;
        Ok(false)
    }
    fn queue_output(&mut self) -> Result<bool, Error> {
        self.guard()?;
        let count = self.rows.len();
        for offset in 0..count {
            let index = (self.row_cursor + offset) % count;
            let Some(row) = self.rows[index].as_mut() else {
                continue;
            };
            if row.pending.is_some() {
                continue;
            }
            let mut slot = row.mailbox.try_borrow_mut().map_err(|_| Fault::Conflict)?;
            let Some(output) = slot.as_ref() else {
                continue;
            };
            if output.terminal && row.report.is_none() {
                continue;
            }
            if !self.io.capacity(output.frame.len(), Class::Ordinary) {
                continue;
            }
            let original = row.targets;
            original.check(self.sources.clock.as_ref())?;
            if let Some(expiry) = output.valid_until {
                original
                    .observe(self.sources.clock.as_ref(), self.limits.utc_uncertainty)?
                    .valid_until(expiry)?;
            }
            self.order.try_reserve(1).map_err(|_| Fault::Capacity)?;
            let output = slot.take().ok_or(Fault::Conflict)?;
            let capacity = output.frame.retained_bytes();
            let terminal = output.terminal;
            let id = row.permit.id;
            let hard = std::time::Instant::now()
                .checked_add(self.limits.output)
                .ok_or(Fault::Overflow)?
                .min(original.hard);
            match self.io.enqueue_owned(
                output.frame,
                Origin {
                    query: id,
                    terminal,
                },
                Class::Ordinary,
            ) {
                Ok(()) => {}
                Err(rejected) => {
                    *slot = Some(Output {
                        frame: rejected.value.0,
                        terminal,
                        valid_until: output.valid_until,
                    });
                    return Err(rejected.reason.into());
                }
            }
            row.pending = Some(Pending {
                terminal,
                capacity,
                written: 0,
                hard,
            });
            self.queued_capacity = self
                .queued_capacity
                .checked_add(capacity)
                .ok_or(Fault::Overflow)?;
            self.order.push_back(id);
            drop(slot);
            self.account()?;
            self.row_cursor = (index + 1) % count;
            return Ok(true);
        }
        Ok(false)
    }
    fn write(&mut self, cx: &mut Context<'_>) -> Result<bool, Error> {
        self.guard()?;
        let Some(id) = self.order.front().copied() else {
            return Ok(false);
        };
        let index = self
            .rows
            .iter()
            .position(|r| r.as_ref().is_some_and(|r| r.permit.id == id))
            .ok_or(Fault::StaleGeneration)?;
        let row = self.rows[index].as_ref().ok_or(Fault::Stale)?;
        if let Some(output) = row.report.as_ref().and_then(|r| r.outcome)
            && let gnunet_abd::Outcome::Authorized { valid_until_us } = output
        {
            row.targets
                .observe(self.sources.clock.as_ref(), self.limits.utc_uncertainty)?
                .valid_until(valid_until_us)?;
        }
        self.native_guard()?;
        match self.io.poll_write(cx) {
            Poll::Pending => Ok(false),
            Poll::Ready(Err(error)) => Err(error.into()),
            Poll::Ready(Ok(progress)) => {
                if progress.origin.query != id {
                    return Err(Fault::StaleGeneration.into());
                }
                let row = self.rows[index].as_mut().ok_or(Fault::Stale)?;
                let pending = row.pending.as_mut().ok_or(Fault::Conflict)?;
                if progress.origin.terminal != pending.terminal {
                    return Err(Fault::StaleGeneration.into());
                }
                pending.written = pending
                    .written
                    .checked_add(progress.bytes)
                    .ok_or(Fault::Overflow)?;
                self.report.written_bytes = self
                    .report
                    .written_bytes
                    .checked_add(u64::try_from(progress.bytes).map_err(|_| Fault::Overflow)?)
                    .ok_or(Fault::Overflow)?;
                if progress.complete {
                    let pending = row.pending.take().ok_or(Fault::Conflict)?;
                    self.queued_capacity = self
                        .queued_capacity
                        .checked_sub(pending.capacity)
                        .ok_or(Fault::Conflict)?;
                    self.order.pop_front();
                    if pending.terminal {
                        let row = self.rows[index].take().ok_or(Fault::Stale)?;
                        self.merge(row.report.ok_or(Fault::NotReady)?);
                        self.report.results_written = self.report.results_written.saturating_add(1);
                    } else {
                        self.report.intermediates_written =
                            self.report.intermediates_written.saturating_add(1);
                    }
                    self.account()?;
                }
                Ok(true)
            }
        }
    }
    fn arm(&mut self, cx: &mut Context<'_>) {
        let at = self
            .first
            .into_iter()
            .chain(self.partial)
            .chain(self.admission)
            .map(|t| t.hard)
            .chain(self.rows.iter().flatten().map(|r| r.targets.hard))
            .chain(
                self.rows
                    .iter()
                    .flatten()
                    .filter_map(|r| r.pending.as_ref().map(|p| p.hard)),
            )
            .min();
        if let Some(at) = at {
            self.alarm.as_mut().reset(at.into());
            if self.alarm.as_mut().poll(cx).is_ready() {
                cx.waker().wake_by_ref();
            }
        }
    }
    fn finish(&mut self, error: Option<Error>) -> ClientReport {
        if let Some(error) = error {
            self.control.cancel(error.classified());
            self.report.primary.get_or_insert(error);
        } else {
            self.control.cancel(Fault::Cancelled);
        }
        self.io.retire();
        self.report.physical_closed = true;
        let mut cx = Context::from_waker(std::task::Waker::noop());
        for index in 0..self.rows.len() {
            let Some(mut row) = self.rows[index].take() else {
                continue;
            };
            if let Some(pending) = row.pending.take() {
                if pending.written == 0 {
                    self.report.outputs_retired_unwritten =
                        self.report.outputs_retired_unwritten.saturating_add(1);
                } else {
                    self.report.outputs_retired_partial =
                        self.report.outputs_retired_partial.saturating_add(1);
                }
            }
            if let Some(mut future) = row.future.take() {
                match future.as_mut().poll(&mut cx) {
                    Poll::Ready(report) => self.merge(report),
                    Poll::Pending => {
                        self.report.undrained = self.report.undrained.saturating_add(1);
                        self.report.cleanup.get_or_insert(Fault::NotReady.into());
                    }
                }
            } else if let Some(report) = row.report.take() {
                self.merge(report);
            }
        }
        self.order.clear();
        self.queued_capacity = 0;
        self.finished = true;
        self.storage = None;
        std::mem::take(&mut self.report)
    }
}
impl Future for Session {
    type Output = ClientReport;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.finished {
            return Poll::Ready(ClientReport::default());
        }
        if let Some(cause) = this.control.reason() {
            return Poll::Ready(this.finish(Some(cause.into())));
        }
        if let Err(error) = this.guard() {
            return Poll::Ready(this.finish(Some(error)));
        }
        for offset in 0..4 {
            if let Err(error) = this.native_guard() {
                return Poll::Ready(this.finish(Some(error)));
            }
            let class = (this.class + offset) % 4;
            let progress = match class {
                0 => this.write(cx),
                1 => this.incoming(cx),
                2 => this.jobs(cx),
                _ => this.queue_output(),
            };
            match progress {
                Err(error) => return Poll::Ready(this.finish(Some(error))),
                Ok(true) => {
                    this.class = (class + 1) % 4;
                    cx.waker().wake_by_ref();
                    this.arm(cx);
                    return Poll::Pending;
                }
                Ok(false) => {}
            }
        }
        this.class = (this.class + 1) % 4;
        this.arm(cx);
        Poll::Pending
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        if !self.finished {
            let _retired = self.finish(Some(Fault::Cancelled.into()));
        }
    }
}

pub(crate) fn session(
    io: Framed<Origin>,
    sources: Sources,
    limits: Limits,
    registry: Rc<Registry>,
    control: Rc<Control>,
    tolerant: bool,
    first: Targets,
) -> Result<Session, Error> {
    Session::new(io, sources, limits, registry, control, tolerant, first)
}
