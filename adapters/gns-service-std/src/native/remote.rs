use super::{Error, RemoteEnd, RemoteReport, Report, dht};
use crate::{Bounds, Close, Shared, Value};
use gnunet_types::Error as Fault;
use std::{
    cell::RefCell,
    future::Future,
    pin::{Pin, pin},
    rc::Rc,
    task::{Context, Poll, Waker},
};
use tokio::time::{Instant, Sleep};

pub(super) type SharedRemote<'id> = Rc<RefCell<State<'id>>>;
#[derive(Clone, Copy)]
pub(super) struct Token {
    slot: usize,
    serial: u64,
}
struct Row<'id> {
    serial: u64,
    bounds: Bounds,
    report: RemoteReport<'id>,
    value: Option<Result<Value, Error<'id>>>,
    closing: bool,
    close_error: Option<Error<'id>>,
    wake: Option<Waker>,
}
pub(super) struct State<'id> {
    pub(super) client: dht::Client<'id>,
    rows: Vec<Option<Row<'id>>>,
    serial: u64,
    pending: Option<Error<'id>>,
    suspended: bool,
    closed: bool,
    pub(super) close_report: Option<(dht::Epoch<'id>, dht::Snapshot)>,
    maximum_block: usize,
    alarm: Option<Pin<Box<Sleep>>>,
    alarm_at: Option<Instant>,
}
impl<'id> State<'id> {
    pub(super) fn new(
        client: dht::Client<'id>,
        capacity: usize,
        maximum_block: usize,
    ) -> Result<Self, Fault> {
        let mut rows = Vec::new();
        rows.try_reserve_exact(capacity)
            .map_err(|_| Fault::Capacity)?;
        rows.resize_with(capacity, || None);
        Ok(Self {
            client,
            rows,
            serial: 0,
            pending: None,
            suspended: false,
            closed: false,
            close_report: None,
            maximum_block,
            alarm: None,
            alarm_at: None,
        })
    }
    fn row(&mut self, token: Token) -> Result<&mut Row<'id>, Fault> {
        self.rows
            .get_mut(token.slot)
            .and_then(Option::as_mut)
            .filter(|row| row.serial == token.serial)
            .ok_or(Fault::Stale)
    }
    pub(super) fn admit(&mut self, key: &[u8; 64], bounds: Bounds) -> Result<Token, Error<'id>> {
        super::guard(bounds)?;
        if self.closed {
            return Err(Fault::Closed.into());
        }
        if self.suspended {
            return Err(Fault::NotReady.into());
        }
        let slot = self
            .rows
            .iter()
            .position(Option::is_none)
            .ok_or(Fault::WouldBlock)?;
        let serial = self.serial.checked_add(1).ok_or(Fault::Overflow)?;
        super::guard(bounds)?;
        let get = self.client.get(dht::Get {
            key,
            block_type: gnunet_block::BlockType::GNS_NAMERECORD.0,
            options: u32::from(
                gnunet_wire::official::dht::RouteOptions::DEMULTIPLEX_EVERYWHERE.bits(),
            ),
            replication: 10,
            extended_query: &[],
        })?;
        self.serial = serial;
        self.rows[slot] = Some(Row {
            serial,
            bounds,
            report: RemoteReport {
                get,
                epoch: None,
                cancellation: None,
                end: None,
                candidates: 0,
            },
            value: None,
            closing: false,
            close_error: None,
            wake: None,
        });
        Ok(Token { slot, serial })
    }
    fn observe(&mut self, event: dht::Progress<'id>) -> Option<Error<'id>> {
        match event {
            dht::Progress::Inbound(received) => {
                let (get, epoch) = match received.event() {
                    dht::Event::Result { get, .. } => (*get, received.epoch()),
                    _ => return None,
                };
                let row = self
                    .rows
                    .iter_mut()
                    .flatten()
                    .find(|row| row.report.get == get && !row.closing)?;
                row.report.epoch = Some(epoch);
                let value = match received.result() {
                    Ok(result) if result.payload.len() <= self.maximum_block => {
                        let mut block = Vec::new();
                        match block.try_reserve_exact(result.payload.len()) {
                            Ok(()) => {
                                block.extend_from_slice(result.payload);
                                Ok(Value::Block(block))
                            }
                            Err(_) => Err(Fault::Capacity.into()),
                        }
                    }
                    Ok(_) => Err(Fault::TooLarge.into()),
                    Err(error) => Err(error.into()),
                };
                // poll() never reads a new frame while any mailbox is occupied.
                // A result is not dropped/replaced because the resolver is busy.
                row.value = Some(value);
                if let Some(wake) = row.wake.take() {
                    wake.wake();
                }
                None
            }
            dht::Progress::Written { epoch, action } => {
                match action {
                    dht::Action::Get(get) => {
                        if let Some(row) = self
                            .rows
                            .iter_mut()
                            .flatten()
                            .find(|row| row.report.get == get)
                        {
                            row.report.epoch = Some(epoch);
                        }
                    }
                    dht::Action::Stop(get) => {
                        if let Some(row) = self
                            .rows
                            .iter_mut()
                            .flatten()
                            .find(|row| row.report.get == get && row.closing)
                        {
                            row.report.end = Some(RemoteEnd::StopWritten(epoch));
                            if let Some(wake) = row.wake.take() {
                                wake.wake();
                            }
                        }
                    }
                    _ => {}
                }
                None
            }
            dht::Progress::Lost {
                epoch,
                cause,
                retained,
            } => {
                for row in self.rows.iter_mut().flatten() {
                    if row.closing && row.report.end.is_none() {
                        row.report.end = Some(RemoteEnd::SourceLost(epoch));
                        if let Some(wake) = row.wake.take() {
                            wake.wake();
                        }
                    }
                }
                Some(Error::DhtLoss {
                    epoch,
                    cause,
                    retained,
                })
            }
            dht::Progress::ConnectRetry { error, .. } => Some(Error::Connect(error)),
            dht::Progress::Unavailable(error) => {
                self.suspended = true;
                Some(error.into())
            }
            dht::Progress::Closed => {
                self.closed = true;
                for row in self.rows.iter_mut().flatten() {
                    row.report.end.get_or_insert(RemoteEnd::ProviderClosed);
                    if let Some(wake) = row.wake.take() {
                        wake.wake();
                    }
                }
                None
            }
            _ => None,
        }
    }
    pub(super) fn native_guard(&mut self, cx: &mut Context<'_>) -> Option<Error<'id>> {
        if let Some(error) = self.pending.take() {
            return Some(error);
        }
        let target = self
            .rows
            .iter()
            .flatten()
            .filter(|row| row.closing && row.report.end.is_none())
            .map(|row| row.bounds.hard())
            .min();
        if self.alarm_at != target {
            self.alarm_at = target;
            self.alarm = target.map(|at| Box::pin(tokio::time::sleep_until(at)));
        }
        if let Some(alarm) = &mut self.alarm {
            let _ready = alarm.as_mut().poll(cx);
        }
        // A GET canceled on a dead/unwritable MQ must not retain its original
        // STOP FIFO indefinitely. Retire that real MQ at the same original hard;
        // the client restores only the other still-live readonly intents.
        if !self.closed
            && self.rows.iter().flatten().any(|row| {
                row.closing && row.report.end.is_none() && Instant::now() >= row.bounds.hard()
            })
            && self.client.epoch().is_some()
        {
            match self.client.reconnect() {
                Ok(event) => return self.observe(event),
                Err(error) => {
                    self.suspended = true;
                    return Some(error.into());
                }
            }
        }
        None
    }
    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Shared<Error<'id>>> {
        if let Some(error) = self.pending.take() {
            return Poll::Ready(Shared::Failed(error));
        }
        if self.suspended || self.closed {
            return Poll::Pending;
        }
        if let Some(error) = self.native_guard(cx) {
            return Poll::Ready(Shared::Failed(error));
        }
        if self
            .rows
            .iter()
            .flatten()
            .all(|row| row.report.end.is_some())
        {
            return Poll::Pending;
        }
        if self
            .rows
            .iter()
            .flatten()
            .any(|row| row.value.is_some() && !row.closing)
        {
            return Poll::Pending;
        }
        // drive is only a poll_fn wrapper; dropping this temporary wait preserves
        // the same Client's actual partial cursors and all original GetIds.
        let event = {
            let hard = self
                .rows
                .iter()
                .flatten()
                .filter(|row| row.report.end.is_none())
                .map(|row| row.bounds.hard())
                .min();
            let future = self.client.drive(hard);
            let mut future = pin!(future);
            match future.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(event) => event,
            }
        };
        match event {
            Err(error) => {
                // Retain the primary error separately from actual old-MQ loss.
                // Recovery cannot redispatch a retained malformed old frame.
                if self.client.epoch().is_some() {
                    self.pending = match self.client.reconnect() {
                        Ok(event) => self.observe(event),
                        Err(other) => Some(other.into()),
                    };
                }
                self.suspended = true;
                Poll::Ready(Shared::Failed(error.into()))
            }
            Ok(event) => {
                let recovered = matches!(&event, dht::Progress::Connected(_));
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
            Some(value) => {
                if matches!(&value, Ok(Value::Block(_))) {
                    row.report.candidates = row.report.candidates.saturating_add(1);
                }
                Poll::Ready(value)
            }
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
        if let Some(Err(error)) = row.value.take() {
            row.close_error = Some(error);
        }
        let get = row.report.get;
        if row.report.end.is_some() {
            return None;
        }
        match self.client.stop(get) {
            Ok(cancel) => {
                if let Ok(row) = self.row(token) {
                    row.report.cancellation = Some(cancel);
                    if cancel == dht::Cancel::BeforeIssue {
                        row.report.end = Some(RemoteEnd::BeforeIssue);
                    }
                }
                None
            }
            Err(error) => {
                // An unexpected cancellation refusal must not leave a logical
                // GET that a future reconnect could reconstruct after its GNS
                // owner has gone. The whole broken source is physically closed.
                self.close();
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
        if let Some(error) = row.close_error.take() {
            return Poll::Ready(Close::Failed(error));
        }
        if row.report.end.is_none() {
            return Poll::Pending;
        }
        match self.rows[token.slot].take() {
            Some(row) => Poll::Ready(Close::Closed(Report::Remote(row.report))),
            None => Poll::Ready(Close::Failed(Fault::Stale.into())),
        }
    }
    pub(super) fn close(&mut self) {
        if !self.closed {
            if let Some(dht::Progress::Lost {
                epoch, retained, ..
            }) = self.client.close()
            {
                self.close_report = Some((epoch, retained));
            }
            self.closed = true;
            self.alarm = None;
            self.alarm_at = None;
            for row in self.rows.iter_mut().flatten() {
                row.report.end.get_or_insert(RemoteEnd::ProviderClosed);
                if let Some(wake) = row.wake.take() {
                    wake.wake();
                }
            }
        }
    }
    pub(super) fn recover(&mut self) -> Result<(), Error<'id>> {
        if self.closed {
            return Err(Fault::Closed.into());
        }
        self.client.recover_ports()?;
        self.suspended = false;
        Ok(())
    }
    pub(super) fn retained(&self) -> usize {
        self.rows.iter().flatten().count()
    }
    pub(super) fn is_closed(&self) -> bool {
        self.closed && self.pending.is_none()
    }
}
