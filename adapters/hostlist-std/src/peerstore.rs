//! Real official hello_add: original scan, skip newer or REPLACE STORE, actual
//! results; dedicated monitor credit never shares its rid-less MQ with stores.
use crate::{Core, Error, Fault, HelloFrame, Job};
use gnunet_client_host::EndpointSource;
use gnunet_peerstore_client_host as ps;
use std::{
    future::Future,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Instant;
const SUBSYSTEM: &[u8] = b"peerstore";
const KEY: &[u8] = b"peerstore-peer-hello-uri";
/// Exact hello-add terminal outcome. Local writes are never named stored.
#[derive(Clone, Copy, Debug)]
pub enum AddStatus {
    /// Actual original STORE_RESULT raw signed value (1 is GNUNET_OK).
    Store(i32),
    /// Actual scan saw a newer verified record; actual original stop/loss follows.
    ExistingNewer(ps::Outcome),
    /// Original operation ended locally with preserved exposure.
    Local(ps::Outcome),
    /// No store was admitted; original scan may already have completed.
    NotSubmitted(Fault),
    /// Physical close occurred but an authoritative callback was unavailable.
    Indeterminate(Fault),
}
/// Original HTTP round/frame and exact actual PEERSTORE operation correlation.
#[derive(Debug)]
pub struct AddCompletion<'id> {
    /// Original fresh HTTP job, not a new provider generation.
    pub job: Job,
    /// Original full-frame index in its complete HTTP body.
    pub index: u32,
    /// Actual original scan operation.
    pub scan: ps::Operation<'id>,
    /// Actual admitted store operation, if one was admitted.
    pub store: Option<ps::Operation<'id>>,
    /// Actual original responding/writing MQ, if attached.
    pub epoch: Option<ps::Epoch<'id>>,
    /// Actual/local outcome, preserving native uncertainty.
    pub status: AddStatus,
}
/// Actual scoped observations emitted by the two original PEERSTORE owners.
#[derive(Debug)]
pub enum PeerstoreEvent<'id> {
    /// Actual general MQ attached.
    Connected(ps::Epoch<'id>),
    /// Actual original monitor MQ attached; SYNC has not been inferred.
    MonitorConnected(ps::Epoch<'id>),
    /// Actual original monitor initial enumeration finished.
    Sync(ps::Epoch<'id>),
    /// Actual immutable full-frame local write only.
    Written {
        /// Actual original physical source.
        epoch: ps::Epoch<'id>,
        /// Original operation.
        operation: ps::Operation<'id>,
        /// Actual original command.
        command: ps::Command,
    },
    /// Actual private hello-add result.
    Add(AddCompletion<'id>),
    /// Actual verified monitor record entered the bounded cache.
    Hello {
        /// Actual source.
        epoch: ps::Epoch<'id>,
        /// Verified public identity.
        peer: [u8; 32],
        /// Precise coverage; addresses may be unauthenticated.
        coverage: gnunet_hello::SignatureCoverage,
    },
    /// Actual consumed invalid/over-capacity record, without silent success.
    Rejected {
        /// Original source.
        epoch: ps::Epoch<'id>,
        /// Finite rejection classification.
        reason: Fault,
    },
    /// Original source actually retired; monitor/source knowledge is not fresh SYNC.
    Lost {
        /// Dedicated monitor or general MQ.
        monitor: bool,
        /// Original actual source, if attached.
        epoch: Option<ps::Epoch<'id>>,
        /// Original actual cause.
        cause: ps::LossCause,
    },
    /// Actual original connection attempt failure.
    Retry {
        /// Dedicated monitor or general MQ.
        monitor: bool,
        /// Original native error.
        error: std::io::Error,
    },
    /// Independent cleanup failure retained after another original cause.
    Cleanup(ps::Error),
}
#[derive(Clone, Copy)]
enum Stage<'id> {
    Scan(ps::Operation<'id>),
    Stopping(ps::Operation<'id>),
    ReadyStore,
    Store(ps::Operation<'id>),
}
struct Add<'id> {
    job: Job,
    index: u32,
    frame: HelloFrame,
    scan: ps::Operation<'id>,
    store: Option<ps::Operation<'id>>,
    epoch: Option<ps::Epoch<'id>>,
    stage: Stage<'id>,
    until: u64,
    hard: Instant,
    drain: Option<Instant>,
    grant: bool,
    retired: bool,
}
pub(crate) struct Port<'id> {
    general: ps::Client<'id>,
    monitor: ps::Client<'id>,
    general_epoch: Option<ps::Epoch<'id>>,
    monitor_epoch: Option<ps::Epoch<'id>>,
    synced: Option<ps::Epoch<'id>>,
    monitor_op: Option<ps::Operation<'id>>,
    monitor_enabled: bool,
    monitor_grant: bool,
    job: Option<Add<'id>>,
    scratch: Vec<u8>,
    hello_limits: gnunet_hello::Limits,
    profile: gnunet_hello::SignatureProfile,
    grace: Duration,
    pause: Option<Instant>,
    retry: Duration,
    turn: bool,
}
fn temporary(error: &ps::Error) -> bool {
    matches!(
        error,
        ps::Error::Protocol(Fault::Capacity | Fault::WouldBlock | Fault::NotReady)
    )
}
fn polled<'id>(
    client: &mut ps::Client<'id>,
    cx: &mut Context<'_>,
) -> Poll<Result<ps::Progress<'id>, ps::Error>> {
    let mut future = std::pin::pin!(client.drive(None));
    future.as_mut().poll(cx)
}
pub(crate) struct Options {
    pub native: ps::Limits,
    pub hello_limits: gnunet_hello::Limits,
    pub profile: gnunet_hello::SignatureProfile,
    pub grace: Duration,
    pub retry: Duration,
}
impl<'id> Port<'id> {
    pub fn new(
        general: &'id mut ps::Instance,
        monitor: &'id mut ps::Instance,
        source: EndpointSource,
        options: Options,
    ) -> Result<Self, Error> {
        let Options {
            native,
            hello_limits,
            profile,
            grace,
            retry,
        } = options;
        let mut scratch = Vec::new();
        scratch
            .try_reserve_exact(hello_limits.maximum_address_bytes)
            .map_err(|_| Fault::Capacity)?;
        scratch.resize(hello_limits.maximum_address_bytes, 0);
        Ok(Self {
            general: ps::Client::new(general, source.duplicate()?, native)?,
            monitor: ps::Client::new_monitor(monitor, source, native)?,
            general_epoch: None,
            monitor_epoch: None,
            synced: None,
            monitor_op: None,
            monitor_enabled: false,
            monitor_grant: false,
            job: None,
            scratch,
            hello_limits,
            profile,
            grace,
            pause: None,
            retry,
            turn: false,
        })
    }
    pub fn cancel(&mut self, observe: &mut impl FnMut(PeerstoreEvent<'id>)) -> Result<(), Error> {
        let Some(add) = &mut self.job else {
            return Ok(());
        };
        if add.drain.is_some() || add.retired {
            return Ok(());
        }
        let operation = match add.stage {
            Stage::Scan(op) | Stage::Stopping(op) | Stage::Store(op) => Some(op),
            Stage::ReadyStore => None,
        };
        if let Some(operation) = operation {
            match self.general.cancel(operation) {
                Ok(_) => {}
                Err(ps::Error::Protocol(Fault::Stale | Fault::StaleGeneration)) => {}
                Err(error) => return Err(error.into()),
            }
            add.drain = Some(
                Instant::now()
                    .min(add.hard)
                    .checked_add(self.grace)
                    .ok_or(Fault::Overflow)?,
            );
        } else {
            self.complete(AddStatus::NotSubmitted(Fault::Cancelled), observe)
        }
        Ok(())
    }
    pub fn connected(&self) -> bool {
        self.general_epoch.is_some()
    }
    pub fn synced(&self) -> bool {
        self.synced.is_some()
    }
    pub fn start_monitor(&mut self, until: u64) -> Result<(), Error> {
        self.monitor_enabled = true;
        if self.monitor_op.is_none() {
            self.monitor_op = Some(self.monitor.monitor(
                ps::Filter {
                    peer: None,
                    subsystem: Some(SUBSYSTEM),
                    key: Some(KEY),
                },
                true,
                until,
            )?)
        }
        Ok(())
    }
    pub fn start(
        &mut self,
        job: Job,
        index: u32,
        frame: HelloFrame,
        until: u64,
        hard: Instant,
    ) -> Result<(), Box<(Error, HelloFrame)>> {
        if self.job.is_some() {
            return Err(Box::new((Fault::WouldBlock.into(), frame)));
        }
        let scan = match self.general.iterate(
            ps::Filter {
                peer: Some(frame.peer()),
                subsystem: Some(SUBSYSTEM),
                key: Some(KEY),
            },
            until,
        ) {
            Ok(op) => op,
            Err(error) => return Err(Box::new((error.into(), frame))),
        };
        self.job = Some(Add {
            job,
            index,
            frame,
            scan,
            store: None,
            epoch: None,
            stage: Stage::Scan(scan),
            until,
            hard,
            drain: None,
            grant: false,
            retired: false,
        });
        Ok(())
    }
    fn complete(&mut self, status: AddStatus, observe: &mut impl FnMut(PeerstoreEvent<'id>)) {
        if let Some(add) = self.job.take() {
            observe(PeerstoreEvent::Add(AddCompletion {
                job: add.job,
                index: add.index,
                scan: add.scan,
                store: add.store,
                epoch: add.epoch,
                status,
            }))
        }
    }
    pub fn next_native(&self) -> Option<Instant> {
        self.job
            .as_ref()
            .filter(|j| !j.retired)
            .map(|j| j.drain.unwrap_or(j.hard))
            .into_iter()
            .chain(self.pause)
            .min()
    }
    pub fn expire(
        &mut self,
        now: Option<u64>,
        observe: &mut impl FnMut(PeerstoreEvent<'id>),
    ) -> Result<(), Error> {
        if self.job.as_ref().is_some_and(|job| {
            !job.retired && job.drain.is_some_and(|until| Instant::now() >= until)
        }) {
            let progress = self.general.reconnect()?;
            self.general_epoch = None;
            if let Some(job) = &mut self.job {
                job.retired = true;
            }
            if let ps::Progress::Lost { epoch, cause, .. } = progress {
                observe(PeerstoreEvent::Lost {
                    monitor: false,
                    epoch,
                    cause,
                })
            }
            // Private completions from the actual close can retire debt without
            // waiting for a future coherent logical clock.
            self.closed_completions(observe);
        }
        let Some(add) = &mut self.job else {
            return Ok(());
        };
        if add.drain.is_none()
            && (Instant::now() >= add.hard || now.is_some_and(|n| n >= add.until))
        {
            let operation = match add.stage {
                Stage::Scan(op) | Stage::Stopping(op) | Stage::Store(op) => Some(op),
                Stage::ReadyStore => None,
            };
            if let Some(operation) = operation {
                match self.general.cancel(operation) {
                    Ok(_) => {}
                    Err(ps::Error::Protocol(Fault::Stale | Fault::StaleGeneration)) => {}
                    Err(error) => return Err(error.into()),
                }
                add.drain = Some(
                    Instant::now()
                        .min(add.hard)
                        .checked_add(self.grace)
                        .ok_or(Fault::Overflow)?,
                )
            } else {
                self.complete(AddStatus::NotSubmitted(Fault::Deadline), observe)
            }
        }
        Ok(())
    }
    fn maintain(&mut self, observe: &mut impl FnMut(PeerstoreEvent<'id>)) -> Result<bool, Error> {
        if self.monitor_grant
            && let Some(operation) = self.monitor_op
        {
            match self.monitor.next(operation, 1) {
                Ok(()) => {
                    self.monitor_grant = false;
                    return Ok(true);
                }
                Err(error) if temporary(&error) => {}
                Err(error) => return Err(error.into()),
            }
        }
        let Some(add) = &mut self.job else {
            return Ok(false);
        };
        if add.drain.is_some() || add.retired {
            return Ok(false);
        }
        match add.stage {
            Stage::ReadyStore => {
                if add.epoch.is_none() || self.general.epoch() != add.epoch {
                    self.complete(AddStatus::NotSubmitted(Fault::Stale), observe);
                    return Ok(true);
                }
                match self.general.store(
                    ps::Record {
                        peer: add.frame.peer(),
                        expiry: add.frame.expires(),
                        subsystem: Some(SUBSYSTEM),
                        key: Some(KEY),
                        value: add.frame.bytes(),
                    },
                    1,
                    add.until,
                ) {
                    Ok(op) => {
                        add.store = Some(op);
                        add.stage = Stage::Store(op);
                        return Ok(true);
                    }
                    Err(error) if temporary(&error) => {}
                    Err(error) => return Err(error.into()),
                }
            }
            Stage::Scan(op) if add.grant => match self.general.next(op, 1) {
                Ok(()) => {
                    add.grant = false;
                    return Ok(true);
                }
                Err(error) if temporary(&error) => {}
                Err(error) => return Err(error.into()),
            },
            _ => {}
        }
        Ok(false)
    }
    fn general(
        &mut self,
        event: ps::Progress<'id>,
        now: u64,
        observe: &mut impl FnMut(PeerstoreEvent<'id>),
    ) -> Result<(), Error> {
        match event {
            ps::Progress::Connected(epoch) => {
                self.general_epoch = Some(epoch);
                observe(PeerstoreEvent::Connected(epoch))
            }
            ps::Progress::Record(record) => {
                let Some(add) = &mut self.job else {
                    return Err(Fault::Stale.into());
                };
                if !matches!(add.stage,Stage::Scan(op)if op==record.operation()) {
                    return Err(Fault::Stale.into());
                }
                add.epoch = Some(record.epoch());
                if add.drain.is_some() || add.retired {
                    return Ok(());
                }
                let stored = record.record()?.record;
                if stored.peer != add.frame.peer()
                    || stored.subsystem != Some(SUBSYSTEM)
                    || stored.key != Some(KEY)
                {
                    return Err(Fault::Malformed.into());
                }
                let newer = if stored.expiry > now && !stored.value.is_empty() {
                    HelloFrame::verify(
                        stored.value,
                        &mut self.scratch,
                        self.hello_limits,
                        self.profile,
                        now,
                    )
                    .is_ok_and(|frame| {
                        frame.peer() == add.frame.peer() && frame.expires() > add.frame.expires()
                    })
                } else {
                    false
                };
                if newer {
                    self.general.cancel(record.operation())?;
                    add.stage = Stage::Stopping(record.operation());
                    add.grant = false;
                } else {
                    add.grant = true
                }
            }
            ps::Progress::Written {
                epoch,
                operation,
                command,
                ..
            } => {
                if let Some(add) = &mut self.job
                    && matches!(add.stage,Stage::Scan(op)|Stage::Stopping(op)|Stage::Store(op)if op==operation)
                {
                    add.epoch = Some(epoch)
                }
                observe(PeerstoreEvent::Written {
                    epoch,
                    operation,
                    command,
                })
            }
            ps::Progress::Completed {
                epoch,
                operation,
                outcome,
                ..
            } => {
                let Some(add) = &mut self.job else {
                    return Ok(());
                };
                if !matches!(add.stage,Stage::Scan(op)|Stage::Stopping(op)|Stage::Store(op)if op==operation)
                {
                    return Err(Fault::Stale.into());
                }
                add.epoch = epoch;
                match (add.stage, outcome) {
                    (Stage::Scan(_), ps::Outcome::IterationEnd(1)) if add.drain.is_none() => {
                        add.stage = Stage::ReadyStore
                    }
                    (Stage::Stopping(_), _) => {
                        self.complete(AddStatus::ExistingNewer(outcome), observe)
                    }
                    (_, ps::Outcome::StoreResult(raw)) => {
                        self.complete(AddStatus::Store(raw), observe)
                    }
                    _ => self.complete(AddStatus::Local(outcome), observe),
                }
            }
            ps::Progress::Lost { epoch, cause, .. } => {
                self.general_epoch = None;
                if self
                    .job
                    .as_ref()
                    .is_some_and(|j| matches!(j.stage, Stage::ReadyStore))
                {
                    self.complete(AddStatus::NotSubmitted(Fault::Closed), observe)
                }
                observe(PeerstoreEvent::Lost {
                    monitor: false,
                    epoch,
                    cause,
                })
            }
            ps::Progress::ConnectRetry { error, .. } => observe(PeerstoreEvent::Retry {
                monitor: false,
                error,
            }),
            ps::Progress::Unavailable(error) => return Err(error.into()),
            ps::Progress::Capacity(_) => {
                self.pause = Some(
                    Instant::now()
                        .checked_add(self.retry)
                        .ok_or(Fault::Overflow)?,
                )
            }
            _ => {}
        }
        Ok(())
    }
    fn monitoring(
        &mut self,
        event: ps::Progress<'id>,
        core: &mut Core,
        now: u64,
        observe: &mut impl FnMut(PeerstoreEvent<'id>),
    ) -> Result<(), Error> {
        match event {
            ps::Progress::Connected(epoch) => {
                self.monitor_epoch = Some(epoch);
                self.synced = None;
                observe(PeerstoreEvent::MonitorConnected(epoch))
            }
            ps::Progress::Record(record) => {
                if Some(record.operation()) != self.monitor_op
                    || Some(record.epoch()) != self.monitor_epoch
                {
                    return Err(Fault::Stale.into());
                }
                let stored = record.record()?.record;
                if stored.subsystem != Some(SUBSYSTEM) || stored.key != Some(KEY) {
                    return Err(Fault::Malformed.into());
                }
                if stored.value.is_empty() {
                    core.remove(stored.peer)?;
                } else if stored.expiry > now {
                    match HelloFrame::verify(
                        stored.value,
                        &mut self.scratch,
                        self.hello_limits,
                        self.profile,
                        now,
                    ) {
                        Ok(frame) if frame.peer() == stored.peer => {
                            let coverage = frame.coverage();
                            match core.accept(frame, now) {
                                Ok(_) => observe(PeerstoreEvent::Hello {
                                    epoch: record.epoch(),
                                    peer: stored.peer,
                                    coverage,
                                }),
                                Err(reason) => observe(PeerstoreEvent::Rejected {
                                    epoch: record.epoch(),
                                    reason,
                                }),
                            }
                        }
                        Ok(_) => observe(PeerstoreEvent::Rejected {
                            epoch: record.epoch(),
                            reason: Fault::Authentication,
                        }),
                        Err(reason) => observe(PeerstoreEvent::Rejected {
                            epoch: record.epoch(),
                            reason,
                        }),
                    }
                }
                self.monitor_grant = true;
            }
            ps::Progress::Sync { epoch, operation } => {
                if Some(operation) != self.monitor_op || Some(epoch) != self.monitor_epoch {
                    return Err(Fault::Stale.into());
                }
                self.synced = Some(epoch);
                observe(PeerstoreEvent::Sync(epoch))
            }
            ps::Progress::Lost { epoch, cause, .. } => {
                self.monitor_epoch = None;
                self.synced = None;
                self.monitor_grant = false;
                observe(PeerstoreEvent::Lost {
                    monitor: true,
                    epoch,
                    cause,
                })
            }
            ps::Progress::Completed { operation, .. } => {
                if Some(operation) == self.monitor_op {
                    self.monitor_op = None;
                    self.synced = None;
                    self.monitor_grant = false
                }
            }
            ps::Progress::ConnectRetry { error, .. } => observe(PeerstoreEvent::Retry {
                monitor: true,
                error,
            }),
            ps::Progress::Unavailable(error) => return Err(error.into()),
            ps::Progress::Capacity(_) => {
                self.pause = Some(
                    Instant::now()
                        .checked_add(self.retry)
                        .ok_or(Fault::Overflow)?,
                )
            }
            _ => {}
        }
        Ok(())
    }
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        core: &mut Core,
        now: u64,
        observe: &mut impl FnMut(PeerstoreEvent<'id>),
    ) -> Poll<Result<(), Error>> {
        if self.pause.is_some_and(|until| Instant::now() < until) {
            return Poll::Pending;
        }
        self.pause = None;
        if self.maintain(observe)? {
            return Poll::Ready(Ok(()));
        }
        for monitor in [self.turn, !self.turn] {
            if monitor && !self.monitor_enabled {
                continue;
            }
            let event = if monitor {
                polled(&mut self.monitor, cx)
            } else {
                polled(&mut self.general, cx)
            };
            if let Poll::Ready(event) = event {
                self.turn = !monitor;
                let event = event?;
                if monitor {
                    self.monitoring(event, core, now, observe)?
                } else {
                    self.general(event, now, observe)?
                }
                return Poll::Ready(Ok(()));
            }
        }
        Poll::Pending
    }
    pub fn close(&mut self, observe: &mut impl FnMut(PeerstoreEvent<'id>)) -> Result<(), Error> {
        let general = self.general.close();
        let monitor = self.monitor.close();
        self.general_epoch = None;
        self.monitor_epoch = None;
        self.synced = None;
        self.closed_completions(observe);
        while self.monitor.next_event().is_some() {}
        if self.job.is_some() {
            self.complete(AddStatus::Indeterminate(Fault::OutcomeUnknown), observe)
        }
        match (general, monitor) {
            (Err(primary), Err(cleanup)) => {
                observe(PeerstoreEvent::Cleanup(cleanup));
                Err(primary.into())
            }
            (Err(error), _) | (_, Err(error)) => Err(error.into()),
            _ => Ok(()),
        }
    }
    fn closed_completions(&mut self, observe: &mut impl FnMut(PeerstoreEvent<'id>)) {
        while let Some(event) = self.general.next_event() {
            if let ps::Progress::Completed {
                epoch,
                operation,
                outcome,
                ..
            } = event
                && self
                    .job
                    .as_ref()
                    .is_some_and(|j| j.scan == operation || j.store == Some(operation))
            {
                if let Some(add) = &mut self.job {
                    add.epoch = epoch
                }
                self.complete(
                    match outcome {
                        ps::Outcome::StoreResult(raw) => AddStatus::Store(raw),
                        _ => AddStatus::Local(outcome),
                    },
                    observe,
                )
            }
        }
    }
}
