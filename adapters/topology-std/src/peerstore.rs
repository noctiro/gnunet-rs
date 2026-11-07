//! Official hello_add composition: exact iteration -> skip-newer or REPLACE store.
use crate::*;
const SUBSYSTEM: &[u8] = b"peerstore";
const KEY: &[u8] = b"peerstore-peer-hello-uri";
/// Original actual HELLO-add terminal observation, retaining CORE ingress scope.
#[derive(Debug)]
pub struct Outcome<'id> {
    /// Original sender source, not a new peer connection.
    pub core_epoch: core::ConnectionEpoch<'id>,
    /// Actual original sender public identity.
    pub sender: [u8; 32],
    /// Actual original PEERSTORE operation if admitted.
    pub operation: ps::Operation<'id>,
    /// Actual responding source if any.
    pub epoch: Option<ps::Epoch<'id>>,
    /// Exact outcome category.
    pub status: Status,
}
/// No local queue/write is called stored.
#[derive(Clone, Copy, Debug)]
pub enum Status {
    /// Actual original STORE_RESULT (one is GNUNET_OK).
    Store(i32),
    /// Actual scan saw a newer valid record; original iterator stopped.
    ExistingNewer(ps::Outcome),
    /// Original RPC ended locally; an exposed store may be unknown.
    Local(ps::Outcome),
    /// Original operation deadline before a STORE was admitted.
    NotSubmitted(Fault),
    /// Original source retired without an available authoritative store outcome.
    Indeterminate(Fault),
}
#[derive(Clone, Copy)]
enum Stage<'id> {
    Iterating(ps::Operation<'id>),
    ReadyStore,
    Storing(ps::Operation<'id>),
    Stopping(ps::Operation<'id>),
}
struct Job<'id> {
    input: Incoming<'id>,
    peer: [u8; 32],
    expiry: u64,
    stage: Stage<'id>,
    last: ps::Operation<'id>,
    epoch: Option<ps::Epoch<'id>>,
    grant: bool,
    drain: Option<Instant>,
    retired: bool,
}
pub(crate) struct Port<'id> {
    client: ps::Client<'id>,
    monitor: ps::Client<'id>,
    monitor_op: Option<ps::Operation<'id>>,
    monitor_grant: bool,
    job: Option<Job<'id>>,
    scratch: Vec<u8>,
    limits: Limits,
    first: bool,
    synced: Option<ps::Epoch<'id>>,
    paused: Option<Instant>,
}
fn temporary(e: &gnunet_client_host::ConnectError) -> bool {
    matches!(
        e,
        gnunet_client_host::ConnectError::Protocol(
            Fault::Capacity | Fault::WouldBlock | Fault::NotReady
        )
    )
}
impl<'id> Port<'id> {
    pub fn new(
        general: &'id mut ps::Instance,
        monitor: &'id mut ps::Instance,
        source: EndpointSource,
        limits: Limits,
    ) -> Result<Self, Error> {
        let native = ps::Limits {
            operations: 1,
            source_bytes: 2 * 65535,
            output: gnunet_service_runtime::framing::Budget {
                frames: 4,
                bytes: 4 * 65535,
            },
            io_slice_bytes: limits.io_slice,
            retirement_grace_micros: u64::try_from(limits.grace.as_micros())
                .map_err(|_| Fault::Overflow)?,
            ..Default::default()
        };
        Ok(Self {
            client: ps::Client::new(general, source.duplicate()?, native)?,
            monitor: ps::Client::new_monitor(monitor, source, native)?,
            monitor_op: None,
            monitor_grant: false,
            job: None,
            scratch: alloc(limits.hello.maximum_address_bytes)?,
            limits,
            first: false,
            synced: None,
            paused: None,
        })
    }
    pub fn synced(&self) -> Option<ps::Epoch<'id>> {
        self.synced
    }
    pub fn idle(&self) -> bool {
        self.job.is_none()
    }
    pub fn begin_monitor(&mut self, until: u64) -> Result<bool, Error> {
        if self.monitor_op.is_some() {
            return Ok(false);
        }
        let op = self.monitor.monitor(
            ps::Filter {
                peer: None,
                subsystem: Some(SUBSYSTEM),
                key: Some(KEY),
            },
            true,
            until,
        )?;
        self.monitor_op = Some(op);
        Ok(true)
    }
    pub fn start(
        &mut self,
        input: Incoming<'id>,
        peer: [u8; 32],
        expiry: u64,
    ) -> Result<(), Box<(Error, Incoming<'id>)>> {
        if self.job.is_some() {
            return Err(Box::new((Fault::WouldBlock.into(), input)));
        }
        let op = match self.client.iterate(
            ps::Filter {
                peer: Some(peer),
                subsystem: Some(SUBSYSTEM),
                key: Some(KEY),
            },
            input.bound.until,
        ) {
            Ok(op) => op,
            Err(e) => return Err(Box::new((e.into(), input))),
        };
        self.job = Some(Job {
            input,
            peer,
            expiry,
            stage: Stage::Iterating(op),
            last: op,
            epoch: None,
            grant: false,
            drain: None,
            retired: false,
        });
        Ok(())
    }
    fn output(job: Job<'id>, op: ps::Operation<'id>, status: Status) -> Outcome<'id> {
        Outcome {
            core_epoch: job.input.epoch,
            sender: job.input.sender,
            operation: op,
            epoch: job.epoch,
            status,
        }
    }
    pub fn expire(
        &mut self,
        now: Option<u64>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<(), Error> {
        let Some(job) = &mut self.job else {
            return Ok(());
        };
        let at = Instant::now();
        if !job.retired && job.drain.is_some_and(|d| at >= d) {
            let progress = self.client.reconnect()?;
            if let ps::Progress::Lost { .. } = progress {
                observe(Event::Lost("peerstore add original drain expired"));
            }
            job.retired = true;
            return Ok(());
        }
        if job.drain.is_none()
            && (at >= job.input.bound.hard || now.is_some_and(|n| n >= job.input.bound.until))
        {
            match job.stage {
                Stage::Iterating(op) | Stage::Storing(op) | Stage::Stopping(op) => {
                    let _cancel = self.client.cancel(op)?;
                    job.drain = Some(
                        job.input
                            .bound
                            .hard
                            .min(at)
                            .checked_add(self.limits.grace)
                            .ok_or(Fault::Overflow)?,
                    );
                }
                Stage::ReadyStore => {
                    let old = self.job.take().ok_or(Fault::Stale)?; // No STORE admitted; scan op is already terminal.
                    let operation = old.last;
                    observe(Event::HelloAdd(Self::output(
                        old,
                        operation,
                        Status::NotSubmitted(Fault::Deadline),
                    )));
                }
            }
        }
        Ok(())
    }
    pub fn next_native(&self) -> Option<Instant> {
        self.job
            .as_ref()
            .filter(|j| !j.retired)
            .map(|j| j.drain.unwrap_or(j.input.bound.hard))
    }
    pub fn next_logical(&self) -> Option<u64> {
        self.job
            .as_ref()
            .filter(|j| j.drain.is_none())
            .map(|j| j.input.bound.until)
    }
    pub fn rotate(&mut self, observe: &mut impl FnMut(Event<'id>)) -> Result<(), Error> {
        let a = self.client.reconnect();
        let b = self.monitor.reconnect();
        self.monitor_grant = false;
        self.synced = None;
        observe(Event::Lost("explicit peerstore source rotation"));
        match (a, b) {
            (Err(primary), Err(cleanup)) => {
                observe(Event::Cleanup(
                    "PEERSTORE monitor independent cleanup",
                    Error::Native(cleanup),
                ));
                Err(primary.into())
            }
            (Err(error), _) | (_, Err(error)) => Err(error.into()),
            _ => Ok(()),
        }
    }
    pub fn close(&mut self) -> Result<(), Error> {
        let a = self.client.close();
        let b = self.monitor.close();
        a?;
        b?;
        Ok(())
    }
    pub fn close_observed(&mut self, observe: &mut impl FnMut(Event<'id>)) -> Result<(), Error> {
        let a = self.client.close();
        let b = self.monitor.close();
        self.synced = None;
        while let Some(event) = self.client.next_event() {
            if let ps::Progress::Completed {
                epoch,
                operation,
                outcome,
                ..
            } = event
                && let Some(mut job) = self.job.take()
            {
                job.epoch = epoch;
                let status = match outcome {
                    ps::Outcome::StoreResult(raw) => Status::Store(raw),
                    _ => Status::Local(outcome),
                };
                observe(Event::HelloAdd(Self::output(job, operation, status)));
            }
        }
        while self.monitor.next_event().is_some() {}
        // Preserve the exact original input/RPC even when its callback was unavailable.
        if let Some(job) = self.job.take() {
            let operation = job.last;
            let status = if matches!(job.stage, Stage::ReadyStore) {
                Status::NotSubmitted(Fault::Closed)
            } else {
                Status::Indeterminate(Fault::OutcomeUnknown)
            };
            observe(Event::HelloAdd(Self::output(job, operation, status)));
        }
        match (a, b) {
            (Err(primary), Err(cleanup)) => {
                observe(Event::Cleanup(
                    "PEERSTORE monitor independent cleanup",
                    Error::Native(cleanup),
                ));
                Err(primary.into())
            }
            (Err(error), _) | (_, Err(error)) => Err(error.into()),
            _ => Ok(()),
        }
    }
    fn maintain(&mut self, now: u64) -> Result<bool, Error> {
        if self.monitor_grant
            && let Some(op) = self.monitor_op
        {
            match self.monitor.next(op, 1) {
                Ok(()) => {
                    self.monitor_grant = false;
                    return Ok(true);
                }
                Err(e) if temporary(&e) => {}
                Err(e) => return Err(e.into()),
            }
        }
        if let Some(job) = &mut self.job
            && job.drain.is_none()
            && now < job.input.bound.until
        {
            match job.stage {
                Stage::ReadyStore => {
                    match self.client.store(
                        ps::Record {
                            peer: job.peer,
                            expiry: job.expiry,
                            subsystem: Some(SUBSYSTEM),
                            key: Some(KEY),
                            value: &job.input.bytes,
                        },
                        1,
                        job.input.bound.until,
                    ) {
                        Ok(op) => {
                            job.stage = Stage::Storing(op);
                            job.last = op;
                            job.epoch = None;
                            return Ok(true);
                        }
                        Err(e) if temporary(&e) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
                Stage::Iterating(op) if job.grant => match self.client.next(op, 1) {
                    Ok(()) => {
                        job.grant = false;
                        return Ok(true);
                    }
                    Err(e) if temporary(&e) => {}
                    Err(e) => return Err(e.into()),
                },
                _ => {}
            }
        }
        Ok(false)
    }
    fn general(
        &mut self,
        progress: ps::Progress<'id>,
        now: u64,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<(), Error> {
        match progress {
            ps::Progress::Record(record) => {
                let Some(job) = &mut self.job else {
                    return Err(Fault::Stale.into());
                };
                if !matches!(job.stage,Stage::Iterating(op)if op==record.operation()) {
                    return Err(Fault::Stale.into());
                }
                job.epoch = Some(record.epoch());
                let stored = record.record()?.record;
                if stored.peer != job.peer {
                    return Err(Fault::Malformed.into());
                }
                let newer = if stored.value.is_empty() || stored.expiry <= now {
                    false
                } else {
                    match VerifiedFrame::verify(
                        stored.value,
                        &mut self.scratch,
                        self.limits.hello,
                        self.limits.profile,
                        now,
                    ) {
                        Ok(frame) => {
                            *frame.verified().hello().peer().as_bytes() == job.peer
                                && frame.verified().hello().expiration().as_micros() > job.expiry
                        }
                        Err(_) => false,
                    }
                };
                if newer {
                    let op = record.operation();
                    self.client.cancel(op)?;
                    job.stage = Stage::Stopping(op);
                    job.grant = false;
                } else {
                    job.grant = true;
                }
            }
            ps::Progress::Written {
                epoch, operation, ..
            } => {
                if let Some(job) = &mut self.job
                    && matches!(job.stage,Stage::Iterating(op)|Stage::Storing(op)|Stage::Stopping(op)if op==operation)
                {
                    job.epoch = Some(epoch);
                }
            }
            ps::Progress::Completed {
                epoch,
                operation,
                outcome,
                ..
            } => {
                let Some(job) = self.job.as_mut() else {
                    return Ok(());
                };
                let matches = matches!(job.stage,Stage::Iterating(op)|Stage::Storing(op)|Stage::Stopping(op)if op==operation);
                if !matches {
                    return Err(Fault::Stale.into());
                }
                job.epoch = epoch;
                match (job.stage, outcome) {
                    (Stage::Iterating(_), ps::Outcome::IterationEnd(1)) if job.drain.is_none() => {
                        job.stage = Stage::ReadyStore;
                    }
                    (Stage::Stopping(_), _) => {
                        let old = self.job.take().ok_or(Fault::Stale)?;
                        observe(Event::HelloAdd(Self::output(
                            old,
                            operation,
                            Status::ExistingNewer(outcome),
                        )));
                    }
                    (_, ps::Outcome::StoreResult(raw)) => {
                        let old = self.job.take().ok_or(Fault::Stale)?;
                        observe(Event::HelloAdd(Self::output(
                            old,
                            operation,
                            Status::Store(raw),
                        )));
                    }
                    _ => {
                        let old = self.job.take().ok_or(Fault::Stale)?;
                        observe(Event::HelloAdd(Self::output(
                            old,
                            operation,
                            Status::Local(outcome),
                        )));
                    }
                }
            }
            ps::Progress::Lost { .. } => observe(Event::Lost("peerstore general")),
            ps::Progress::ConnectRetry { error, .. } => {
                observe(Event::Io("peerstore retry", error))
            }
            ps::Progress::Unavailable(e) => return Err(e.into()),
            ps::Progress::Capacity(_) => {
                self.paused = Some(
                    Instant::now()
                        .checked_add(self.limits.tick)
                        .ok_or(Fault::Overflow)?,
                );
                observe(Event::Capacity("peerstore native record"));
            }
            _ => {}
        }
        Ok(())
    }
    fn monitoring(
        &mut self,
        progress: ps::Progress<'id>,
        engine: &mut Engine,
        now: u64,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<(), Error> {
        match progress {
            ps::Progress::Record(record) => {
                if Some(record.operation()) != self.monitor_op {
                    return Err(Fault::Stale.into());
                }
                let stored = record.record()?.record;
                if stored.subsystem != Some(SUBSYSTEM) || stored.key != Some(KEY) {
                    return Err(Fault::Malformed.into());
                }
                if stored.value.is_empty() {
                    engine.remove_hello(stored.peer, now)
                } else if stored.expiry > now
                    && let Ok(frame) = VerifiedFrame::verify(
                        stored.value,
                        &mut self.scratch,
                        self.limits.hello,
                        self.limits.profile,
                        now,
                    )
                {
                    if *frame.verified().hello().peer().as_bytes() != stored.peer {
                        return Err(Fault::Malformed.into());
                    }
                    let coverage = frame.verified().coverage();
                    match engine.learn(frame, now) {
                        Ok(_) => observe(Event::Hello(stored.peer, coverage)),
                        Err(Fault::Capacity) => observe(Event::Capacity("hello inventory")),
                        Err(e) => return Err(e.into()),
                    }
                }
                self.monitor_grant = true;
            }
            ps::Progress::Sync { epoch, operation } => {
                if Some(operation) != self.monitor_op {
                    return Err(Fault::Stale.into());
                }
                self.synced = Some(epoch);
                observe(Event::Sync(epoch));
            }
            ps::Progress::Lost { .. } => {
                self.monitor_grant = false;
                self.synced = None;
                observe(Event::Lost(
                    "peerstore monitor; fresh epoch requires actual SYNC",
                ));
            }
            ps::Progress::Completed { .. } => {
                self.monitor_op = None;
            }
            ps::Progress::ConnectRetry { error, .. } => observe(Event::Io("monitor retry", error)),
            ps::Progress::Unavailable(e) => return Err(e.into()),
            ps::Progress::Capacity(_) => {
                self.paused = Some(
                    Instant::now()
                        .checked_add(self.limits.tick)
                        .ok_or(Fault::Overflow)?,
                );
                observe(Event::Capacity("peerstore monitor record"));
            }
            _ => {}
        }
        Ok(())
    }
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        engine: &mut Engine,
        now: u64,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<(), Error>> {
        if self.paused.is_some_and(|at| Instant::now() < at) {
            return Poll::Pending;
        }
        self.paused = None;
        if self.maintain(now)? {
            return Poll::Ready(Ok(()));
        }
        for off in 0..2 {
            if (off == 0) == self.first {
                let step = {
                    let f = self.client.drive(None);
                    let mut f = std::pin::pin!(f);
                    f.as_mut().poll(cx)
                };
                if let Poll::Ready(result) = step {
                    self.first = !self.first;
                    self.general(result?, now, observe)?;
                    return Poll::Ready(Ok(()));
                }
            } else {
                let step = {
                    let f = self.monitor.drive(None);
                    let mut f = std::pin::pin!(f);
                    f.as_mut().poll(cx)
                };
                if let Poll::Ready(result) = step {
                    self.first = !self.first;
                    self.monitoring(result?, engine, now, observe)?;
                    return Poll::Ready(Ok(()));
                }
            }
        }
        Poll::Pending
    }
}
impl Drop for Port<'_> {
    fn drop(&mut self) {
        let _closed = self.close();
    }
}
