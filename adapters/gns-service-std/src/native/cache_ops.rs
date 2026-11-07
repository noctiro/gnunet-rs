use super::{CacheReport, Error, Report, cache};
use crate::{Bounds, Close, Shared, Value};
use gnunet_types::Error as Fault;
use std::{
    cell::RefCell,
    rc::Rc,
    task::{Context, Poll, Waker},
};

pub(super) type SharedCache<'id> = Rc<RefCell<State<'id>>>;
#[derive(Clone, Copy)]
pub(super) struct Token {
    slot: usize,
    serial: u64,
}
struct Row<'id> {
    serial: u64,
    bounds: Bounds,
    report: CacheReport<'id>,
    value: Option<Result<Value, Error<'id>>>,
    settled: bool,
    closing: bool,
    wake: Option<Waker>,
    frame_bytes: usize,
}
pub(super) struct State<'id> {
    pub(super) client: cache::Client<'id>,
    rows: Vec<Option<Row<'id>>>,
    serial: u64,
    pending: Option<Error<'id>>,
    closed: bool,
    pub(super) close_report: Option<cache::Loss<'id>>,
}
impl<'id> State<'id> {
    pub(super) fn new(client: cache::Client<'id>, capacity: usize) -> Result<Self, Fault> {
        let mut rows = Vec::new();
        rows.try_reserve_exact(capacity)
            .map_err(|_| Fault::Capacity)?;
        rows.resize_with(capacity, || None);
        Ok(Self {
            client,
            rows,
            serial: 0,
            pending: None,
            closed: false,
            close_report: None,
        })
    }
    pub(super) fn admit(
        &mut self,
        key: Option<&[u8; 64]>,
        block: Option<&[u8]>,
        bounds: Bounds,
    ) -> Result<Token, Error<'id>> {
        super::guard(bounds)?;
        if self.closed {
            return Err(Fault::Closed.into());
        }
        let slot = self
            .rows
            .iter()
            .position(Option::is_none)
            .ok_or(Fault::WouldBlock)?;
        let serial = self.serial.checked_add(1).ok_or(Fault::Overflow)?;
        let (operation, kind, frame_bytes) = match (key, block) {
            (Some(key), None) => {
                super::guard(bounds)?;
                (
                    self.client.lookup(key, bounds.until().as_micros())?,
                    cache::Kind::Lookup,
                    72,
                )
            }
            (None, Some(block)) => {
                let bytes = cache::ipc::BLOCK_PREFIX
                    .checked_add(block.len())
                    .ok_or(Fault::Overflow)?;
                super::guard(bounds)?;
                (
                    self.client.cache(block, bounds.until().as_micros())?,
                    cache::Kind::Cache,
                    bytes,
                )
            }
            _ => return Err(Fault::InvalidInput.into()),
        };
        // query RID is genuine metadata from this same admitted operation.
        // Failure still leaves its native owner here; never return an unowned
        // constructor refusal after admitting the original row.
        let request_id = match self.client.request_id(operation) {
            Ok(rid) => rid,
            Err(error) => {
                if let Some(report) = self.client.close() {
                    self.pending = Some(Error::CacheLoss {
                        report,
                        cause: cache::LossCause::Requested,
                    });
                }
                self.closed = true;
                return Err(error.into());
            }
        };
        self.serial = serial;
        self.rows[slot] = Some(Row {
            serial,
            bounds,
            report: CacheReport {
                operation,
                request_id,
                kind,
                epoch: None,
                submission: cache::Submission::Unsent,
                status: None,
                lookup_reply: false,
                local: None,
                cancellation: None,
            },
            value: None,
            settled: false,
            closing: false,
            wake: None,
            frame_bytes,
        });
        Ok(Token { slot, serial })
    }
    fn row(&mut self, token: Token) -> Result<&mut Row<'id>, Fault> {
        self.rows
            .get_mut(token.slot)
            .and_then(Option::as_mut)
            .filter(|row| row.serial == token.serial)
            .ok_or(Fault::Stale)
    }
    fn observe(&mut self, progress: cache::Progress<'id>) -> Option<Error<'id>> {
        match progress {
            cache::Progress::Completed(done) => {
                let Some(row) = self
                    .rows
                    .iter_mut()
                    .flatten()
                    .find(|row| row.report.operation == done.operation)
                else {
                    return Some(Error::CacheOrphan(done));
                };
                row.report.epoch = done.epoch;
                row.settled = true;
                let value = match done.outcome {
                    cache::Outcome::Lookup(block) if row.report.kind == cache::Kind::Lookup => {
                        row.report.lookup_reply = true;
                        Ok(Value::Cache(block.map(cache::Block::into_bytes)))
                    }
                    cache::Outcome::Cache(status) if row.report.kind == cache::Kind::Cache => {
                        row.report.status = Some(status);
                        Ok(Value::Stored(status))
                    }
                    cache::Outcome::Local { reason, submission } => {
                        row.report.local = Some(reason);
                        row.report.submission = submission;
                        Err(Error::CacheLocal {
                            operation: done.operation,
                            reason,
                            submission,
                        })
                    }
                    _ => Err(Fault::Malformed.into()),
                };
                row.value = Some(value);
                if let Some(wake) = row.wake.take() {
                    wake.wake();
                }
                None
            }
            cache::Progress::Queued {
                operation, epoch, ..
            } => {
                if let Some(row) = self
                    .rows
                    .iter_mut()
                    .flatten()
                    .find(|row| row.report.operation == operation)
                {
                    row.report.epoch = Some(epoch);
                }
                None
            }
            cache::Progress::Written {
                operation, epoch, ..
            } => {
                if let Some(row) = self
                    .rows
                    .iter_mut()
                    .flatten()
                    .find(|row| row.report.operation == operation)
                {
                    row.report.epoch = Some(epoch);
                    row.report.submission = cache::Submission::Written {
                        bytes: row.frame_bytes,
                    };
                }
                None
            }
            cache::Progress::Lost { report, cause } => Some(Error::CacheLoss { report, cause }),
            cache::Progress::ConnectRetry { error, .. } => Some(Error::Connect(error)),
            cache::Progress::Unavailable(error) => Some(error.into()),
            cache::Progress::Closed => {
                self.closed = true;
                None
            }
            _ => None,
        }
    }
    pub(super) fn native_guard(&mut self, cx: &mut Context<'_>) -> Option<Error<'id>> {
        if let Some(error) = self.pending.take() {
            return Some(error);
        }
        let expired = self
            .rows
            .iter()
            .enumerate()
            .filter_map(|(slot, row)| {
                row.as_ref()
                    .filter(|row| {
                        !row.settled
                            && !row.closing
                            && tokio::time::Instant::now() >= row.bounds.hard()
                    })
                    .map(|row| Token {
                        slot,
                        serial: row.serial,
                    })
            })
            .next();
        if let Some(token) = expired
            && let Some(error) = self.cancel(token)
        {
            return Some(error);
        }
        self.client
            .poll_native_guard(cx)
            .and_then(|event| self.observe(event))
    }
    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Shared<Error<'id>>> {
        if let Some(error) = self.pending.take() {
            return Poll::Ready(Shared::Failed(error));
        }
        if let Some(error) = self.native_guard(cx) {
            return Poll::Ready(Shared::Failed(error));
        }
        // Do not create an idle connection. A canceled partial frame still has
        // a real native row, and continues under the client's own drain bound.
        if self.closed {
            if self.client.pending() != 0 {
                cx.waker().wake_by_ref();
            }
            return Poll::Pending;
        }
        if self.rows.iter().flatten().all(|row| row.settled) {
            return Poll::Pending;
        }
        let hard = self
            .rows
            .iter()
            .flatten()
            .filter(|row| !row.settled && !row.closing)
            .map(|row| row.bounds.hard())
            .min();
        match self.client.poll(cx, hard) {
            Poll::Pending | Poll::Ready(Ok(cache::Progress::Closed)) => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Shared::Failed(error.into())),
            Poll::Ready(Ok(event)) => {
                let recovered = matches!(&event, cache::Progress::Connected(_));
                match self.observe(event) {
                    Some(error) => Poll::Ready(Shared::Failed(error)),
                    None if recovered => Poll::Ready(Shared::Recovered),
                    None => Poll::Ready(Shared::Activity),
                }
            }
        }
    }
    pub(super) fn value(
        &mut self,
        token: Token,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Value, Error<'id>>> {
        let row = match self.row(token) {
            Ok(row) => row,
            Err(error) => return Poll::Ready(Err(error.into())),
        };
        row.wake = Some(cx.waker().clone());
        match row.value.take() {
            Some(value) => Poll::Ready(value),
            None => Poll::Pending,
        }
    }
    pub(super) fn cancel(&mut self, token: Token) -> Option<Error<'id>> {
        let row = match self.row(token) {
            Ok(row) => row,
            Err(error) => return Some(error.into()),
        };
        if row.closing {
            return None;
        }
        row.closing = true;
        if row.settled {
            return None;
        }
        let operation = row.report.operation;
        match self.client.cancel(operation) {
            Ok(cancellation) => {
                if let Ok(row) = self.row(token) {
                    row.report.cancellation = Some(cancellation);
                }
                None
            }
            Err(error) => {
                // Exact cancellation failed. Retire the real old MQ, preserving
                // each other operation's original local completion; never replay.
                match self.client.reconnect() {
                    Ok(event) => self.pending = self.observe(event),
                    Err(other) => self.pending = Some(other.into()),
                }
                Some(error.into())
            }
        }
    }
    pub(super) fn retired(
        &mut self,
        token: Token,
        cx: &mut Context<'_>,
    ) -> Poll<Close<Report<'id>, Error<'id>>> {
        let row = match self.row(token) {
            Ok(row) => row,
            Err(error) => return Poll::Ready(Close::Failed(error.into())),
        };
        row.wake = Some(cx.waker().clone());
        if !row.settled {
            return Poll::Pending;
        }
        // A result not consumed because of Stop/clock loss is still a fact.
        // Keep an actual local error as its own event before releasing metadata.
        if let Some(Err(error)) = row.value.take() {
            return Poll::Ready(Close::Failed(error));
        }
        let row = self.rows[token.slot].take();
        match row {
            Some(row) => Poll::Ready(Close::Closed(Report::Cache(row.report))),
            None => Poll::Ready(Close::Failed(Fault::Stale.into())),
        }
    }
    pub(super) fn close(&mut self) {
        if !self.closed {
            self.close_report = self.client.close();
            self.closed = true;
        }
    }
    pub(super) fn recover(&mut self) -> Result<(), Error<'id>> {
        if self.closed {
            return Err(Fault::Closed.into());
        }
        self.client.recover_ports()?;
        Ok(())
    }
    pub(super) fn retained(&self) -> usize {
        self.rows.iter().flatten().count()
    }
    pub(super) fn is_closed(&self) -> bool {
        self.closed && self.client.pending() == 0 && self.pending.is_none()
    }
}
