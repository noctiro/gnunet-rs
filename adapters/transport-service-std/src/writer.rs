//! Actual ordinary PEERSTORE STORE jobs and API receipts. A successful result
//! proves only StoredByService, never a filesystem/fsync or remote receipt.
use crate::{Failure, time::Bounds};
use gnunet_client_host::EndpointSource;
use gnunet_peerstore_client_host as ps;
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_types::{Error as Fault, Rejected};
use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
/// Exact original outcome, preserving raw actual service code or local exposure.
pub enum Event<J> {
    /// Actual STORE_RESULT1 only, not a durable publication proof.
    StoredByService(J),
    /// Actual signed service failure result, retaining its raw value.
    Refused {
        /// Original caller effect.
        origin: J,
        /// Exact signed result.
        code: i32,
    },
    /// Actual local termination without a service processing assertion.
    Ended {
        /// Original caller effect.
        origin: J,
        /// Real original local reason.
        reason: ps::Reason,
        /// Known original Unsent/Unknown facts.
        submission: ps::Submission,
    },
    /// Actual source retired; remaining work cannot move to another MQ.
    SourceLost(Failure),
    /// Real socket/protocol progress only.
    Activity,
}
struct Row<'id, J> {
    operation: ps::Operation<'id>,
    epoch: Option<ps::Epoch<'id>>,
    origin: J,
    bounds: Bounds,
}
/// One explicitly polled bounded writer, independent from the validated barrier.
pub struct Writer<'id, J> {
    client: ps::Client<'id>,
    clock: Arc<dyn RuntimeClock>,
    rows: Vec<Row<'id, J>>,
    events: VecDeque<Event<J>>,
    maximum: usize,
    epoch: Option<ps::Epoch<'id>>,
    source: Bounds,
    initial: Option<Instant>,
    input: Option<Instant>,
    input_timeout: Duration,
    alarm: Option<Pin<Box<Sleep>>>,
    closed: bool,
}
impl<'id, J> Writer<'id, J> {
    /// Reserve one actual original CLIENT, never an embedded PEERSTORE server.
    pub fn new(
        instance: &'id mut ps::Instance,
        source: EndpointSource,
        client: ps::Limits,
        source_lifetime: Duration,
        initial: Duration,
        input: Duration,
    ) -> Result<Self, Failure> {
        if client.operations == 0 || initial.is_zero() || input.is_zero() {
            return Err(Fault::InvalidInput.into());
        }
        let clock = source.clock();
        let bounds = Bounds::after(clock.sample()?.now.as_micros(), source_lifetime)?;
        let initial = Some(
            Instant::now()
                .checked_add(initial)
                .ok_or(Fault::Overflow)?
                .min(bounds.hard),
        );
        let mut rows = Vec::new();
        rows.try_reserve_exact(client.operations)
            .map_err(|_| Fault::Capacity)?;
        let mut events = VecDeque::new();
        events
            .try_reserve_exact(client.operations + 2)
            .map_err(|_| Fault::Capacity)?;
        let maximum = client.operations;
        let client = ps::Client::new(instance, source, client)?;
        Ok(Self {
            client,
            clock,
            rows,
            events,
            maximum,
            epoch: None,
            source: bounds,
            initial,
            input: None,
            input_timeout: input,
            alarm: None,
            closed: false,
        })
    }
    /// Admit exactly one real immutable STORE. Refusal returns original caller
    /// metadata unchanged; no successful result or replacement retry is minted.
    pub fn store(
        &mut self,
        origin: J,
        record: ps::Record<'_>,
        options: u32,
        bounds: Bounds,
    ) -> Result<ps::Operation<'id>, Rejected<J>> {
        let reason = if self.closed {
            Some(Fault::Closed)
        } else if self.rows.len() >= self.maximum {
            Some(Fault::Capacity)
        } else {
            match self.clock.sample() {
                Ok(s) if bounds.live(s.now.as_micros()) => None,
                Ok(_) => Some(Fault::Deadline),
                Err(e) => Some(e),
            }
        };
        if let Some(reason) = reason {
            return Err(Rejected {
                value: origin,
                reason,
            });
        }
        let operation = match self.client.store(record, options, bounds.expires) {
            Ok(op) => op,
            Err(error) => {
                let reason = match error {
                    ps::Error::Protocol(e) => e,
                    other => {
                        self.stop(Box::new(other));
                        Fault::Io
                    }
                };
                return Err(Rejected {
                    value: origin,
                    reason,
                });
            }
        };
        self.rows.push(Row {
            operation,
            epoch: self.epoch,
            origin,
            bounds,
        });
        Ok(operation)
    }
    fn completion(&mut self, p: ps::Progress<'id>) -> Result<(), Failure> {
        let ps::Progress::Completed {
            epoch,
            operation,
            kind,
            outcome,
        } = p
        else {
            return Ok(());
        };
        let Some(i) = self.rows.iter().position(|r| r.operation == operation) else {
            return Ok(());
        };
        if kind != ps::Kind::Store
            || (matches!(outcome, ps::Outcome::StoreResult(_)) && self.rows[i].epoch != epoch)
        {
            return Err(Fault::Stale.into());
        }
        if matches!(outcome, ps::Outcome::IterationEnd(_)) {
            return Err(Fault::Malformed.into());
        }
        let row = self.rows.remove(i);
        self.events.push_back(match outcome {
            ps::Outcome::StoreResult(1) => Event::StoredByService(row.origin),
            ps::Outcome::StoreResult(code) => Event::Refused {
                origin: row.origin,
                code,
            },
            ps::Outcome::Local { reason, submission } => Event::Ended {
                origin: row.origin,
                reason,
                submission,
            },
            ps::Outcome::IterationEnd(_) => return Err(Fault::Malformed.into()),
        });
        Ok(())
    }
    fn stop(&mut self, cause: Failure) {
        if self.closed {
            return;
        }
        self.closed = true;
        // This first physically closes native debt; retained actual original
        // completion observations are then drained without new clock/IO.
        let cleanup = self.client.close().err();
        while let Some(p) = self.client.next_event() {
            if let Err(error) = self.completion(p) {
                self.events.push_back(Event::SourceLost(error));
            }
        }
        for row in self.rows.drain(..) {
            self.events.push_back(Event::Ended {
                origin: row.origin,
                reason: ps::Reason::Lost,
                submission: ps::Submission::Unknown,
            });
        }
        self.events.push_back(Event::SourceLost(cause));
        if let Some(error) = cleanup {
            self.events.push_back(Event::SourceLost(Box::new(error)));
        }
        self.epoch = None;
        self.initial = None;
        self.input = None;
        self.alarm = None;
    }
    /// Real no-clock physical retirement. Outstanding originals are returned via
    /// poll as actual local outcomes, never claimed rolled back or replayed.
    pub fn close(&mut self) {
        self.stop(Box::new(Fault::Closed));
    }
    /// Check/register original native targets before any enclosing clock wait.
    pub fn native_guard(&mut self, cx: &mut Context<'_>) {
        if self.closed {
            return;
        }
        let now = Instant::now();
        if now >= self.source.hard
            || self.initial.is_some_and(|at| now >= at)
            || self.input.is_some_and(|at| now >= at)
            || self.rows.iter().any(|r| now >= r.bounds.hard)
        {
            self.stop(Box::new(Fault::Deadline));
            return;
        }
        let due = Some(self.source.hard)
            .into_iter()
            .chain(self.initial)
            .chain(self.input)
            .chain(self.rows.iter().map(|r| r.bounds.hard))
            .min();
        if let Some(at) = due {
            let alarm = self
                .alarm
                .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(at)));
            alarm.as_mut().reset(at);
            if alarm.as_mut().poll(cx).is_ready() {
                cx.waker().wake_by_ref();
            }
        }
    }
    /// Actual source attachment only; no receipt/durability follows it.
    pub fn connected(&self) -> bool {
        self.epoch.is_some() && !self.closed
    }
    /// Whether the actual native source remains reusable. Already queued
    /// source-loss observations do not make a closed source healthy again.
    pub fn reusable(&self) -> bool {
        !self.closed
    }
    fn progress(&mut self, p: ps::Progress<'id>) -> Result<(), Failure> {
        match p {
            ps::Progress::Connected(epoch) => {
                self.epoch = Some(epoch);
                self.initial = None;
                for row in &mut self.rows {
                    if row.epoch.is_some_and(|e| e != epoch) {
                        return Err(Fault::Stale.into());
                    }
                    row.epoch = Some(epoch);
                }
            }
            p @ ps::Progress::Completed {
                outcome: ps::Outcome::Local { .. },
                ..
            } => {
                self.completion(p)?;
            }
            p @ ps::Progress::Completed { .. } => {
                self.input = None;
                self.completion(p)?;
            }
            ps::Progress::Activity {
                epoch, read_bytes, ..
            } => {
                if self.epoch != Some(epoch) {
                    return Err(Fault::Stale.into());
                }
                if read_bytes > 0 && self.input.is_none() {
                    self.input = Some(
                        Instant::now()
                            .checked_add(self.input_timeout)
                            .ok_or(Fault::Overflow)?,
                    );
                }
            }
            ps::Progress::Lost { epoch, cause, .. } => self.stop(
                format!("PEERSTORE own-publication original source {epoch:?}: {cause:?}").into(),
            ),
            ps::Progress::Unavailable(error) => self.stop(Box::new(error)),
            ps::Progress::ConnectRetry { error, .. } => self.stop(Box::new(error)),
            ps::Progress::Ignored(_) => self.input = None,
            ps::Progress::Capacity(_) => self.stop(Box::new(Fault::Capacity)),
            ps::Progress::Closed => self.stop(Box::new(Fault::Closed)),
            ps::Progress::Written { epoch, .. } => {
                if self.epoch != Some(epoch) {
                    return Err(Fault::Stale.into());
                }
            }
            ps::Progress::Record(_) | ps::Progress::Sync { .. } => {
                return Err(Fault::Malformed.into());
            }
            ps::Progress::WaitDeadline => {}
        }
        Ok(())
    }
    /// Poll real IO/receipts only. Metadata remains bounded by original jobs.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Event<J>, Failure>> {
        self.native_guard(cx);
        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(Ok(event));
        }
        if self.closed {
            return Poll::Pending;
        }
        let now = match self.clock.sample() {
            Ok(s) => s.now.as_micros(),
            Err(error) => {
                self.stop(Box::new(error));
                return Poll::Ready(Ok(self.events.pop_front().ok_or(Fault::NotReady)?));
            }
        };
        if now >= self.source.expires || self.rows.iter().any(|r| now >= r.bounds.expires) {
            self.stop(Box::new(Fault::Deadline));
            return Poll::Ready(Ok(self.events.pop_front().ok_or(Fault::NotReady)?));
        }
        let result = {
            let mut driving = std::pin::pin!(self.client.drive(None));
            driving.as_mut().poll(cx)
        };
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => {
                self.stop(Box::new(error));
                Poll::Ready(Ok(self.events.pop_front().ok_or(Fault::NotReady)?))
            }
            Poll::Ready(Ok(p)) => {
                if let Err(error) = self.progress(p) {
                    self.stop(error);
                }
                self.native_guard(cx);
                Poll::Ready(Ok(self.events.pop_front().unwrap_or(Event::Activity)))
            }
        }
    }
}
impl<J> Drop for Writer<'_, J> {
    fn drop(&mut self) {
        let _actual = self.client.close();
    }
}
