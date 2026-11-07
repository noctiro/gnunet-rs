//! One original DHT reader shared by bounded REGEX jobs.
use super::{Event, Failure, Get, Provider, Put};
use gnunet_dht_client_host as client;
use gnunet_regex_service::{JobId, Reply};
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_types::Error as Fault;
use gnunet_wire::official::AbsoluteTime;
use std::{
    error::Error,
    fmt,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};

/// Explicit native metadata, retained request and finite IO phase budgets.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum original jobs, including terminal metadata awaiting release.
    pub operations: usize,
    /// Independent retained native request and queued PUT-body budget.
    pub bytes: usize,
    /// Maximum original xquery extent, including its terminator.
    pub query_bytes: usize,
    /// Maximum original state/accepting payload.
    pub block_bytes: usize,
    /// Maximum combined predecessor identities copied from one original reply.
    pub paths: usize,
    /// Original PUT and GET registration/STOP write lifetime, not a search TTL.
    pub output_lifetime: Duration,
    /// Original partial response lifetime, beginning with its first actual byte.
    pub partial_input: Duration,
    /// Maximum bytes in one original native syscall.
    pub io_slice_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            operations: 1024,
            bytes: 32 * 1024 * 1024,
            query_bytes: 4097,
            block_bytes: gnunet_regex::MAX_BLOCK_BYTES - 1,
            paths: 128,
            output_lifetime: Duration::from_secs(30),
            partial_input: Duration::from_secs(15),
            io_slice_bytes: 65535,
        }
    }
}
struct WaitingPut {
    key: [u8; 64],
    kind: u32,
    options: u32,
    replication: u32,
    expires: u64,
    block: Vec<u8>,
}
enum Operation<'a> {
    Get(client::GetId<'a>),
    Waiting(WaitingPut),
    Put(client::OperationId<'a>),
    Refused,
}
struct Row<'a> {
    job: JobId,
    operation: Operation<'a>,
    hard: Option<Instant>,
    retiring: bool,
    quiet: bool,
    terminal: Option<client::Outcome>,
    failure: Option<Failure>,
}
struct ReplyOwner<'a> {
    job: JobId,
    received: client::Received<'a>,
    get_path: Vec<[u8; 32]>,
    put_path: Vec<[u8; 32]>,
}
enum Pending<'a> {
    Rejected(JobId, gnunet_regex_service::Error),
    Reply(ReplyOwner<'a>),
    Complete(JobId),
    Failed(JobId),
    Source(Failure),
}
impl Pending<'_> {
    fn job(&self) -> Option<&JobId> {
        match self {
            Self::Reply(reply) => Some(&reply.job),
            Self::Complete(job) | Self::Failed(job) | Self::Rejected(job, _) => Some(job),
            Self::Source(_) => None,
        }
    }
}
/// Original one-shot terminal observation. The local outcome never proves remote
/// storage, replication or processing; canceled writes retain their real fact.
#[derive(Debug)]
pub struct PutRetirement {
    /// Actual native client outcome for this same original PUT.
    pub outcome: client::Outcome,
}
impl fmt::Display for PutRetirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "original REGEX DHT PUT locally retired: {:?}",
            self.outcome
        )
    }
}
impl Error for PutRetirement {}
#[derive(Debug)]
struct SourceLoss(client::LossCause);
impl fmt::Display for SourceLoss {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "original REGEX DHT source lost: {:?}", self.0)
    }
}
impl Error for SourceLoss {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.0 {
            client::LossCause::Io(error) => Some(error),
            client::LossCause::Protocol(error) | client::LossCause::Resource(error) => Some(error),
            _ => None,
        }
    }
}
#[derive(Debug)]
struct Independent {
    original: Failure,
    cleanup: Failure,
}
impl fmt::Display for Independent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}; independent DHT cleanup: {}",
            self.original, self.cleanup
        )
    }
}
impl Error for Independent {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.original.as_ref())
    }
}
/// Real original native DHT provider. GETs are persistent; finite bounds apply
/// to registration/STOP/PUT and partial native input, never the full search.
/// The outer factory owns Instance; no task, Resolver or self-reference is added.
pub struct Native<'a> {
    client: client::Client<'a>,
    clock: Arc<dyn RuntimeClock>,
    limits: Limits,
    rows: Vec<Row<'a>>,
    refused: Option<JobId>,
    pending: Option<Pending<'a>>,
    deferred_source: Option<Failure>,
    startup: Option<Instant>,
    connection: Option<Instant>,
    partial: Option<Instant>,
    alarm: Option<Pin<Box<Sleep>>>,
    alarm_at: Option<Instant>,
    closing: bool,
    cursor: usize,
}
impl<'a> Native<'a> {
    /// Reserve original metadata and the one real DHT client without starting IO.
    pub fn new(
        instance: &'a mut client::Instance,
        source: client::EndpointSource,
        limits: Limits,
        startup_until: Instant,
    ) -> Result<Self, Failure> {
        if limits.operations == 0
            || limits.operations > 65536
            || limits.bytes < 65535
            || limits.query_bytes == 0
            || limits.query_bytes > 65536
            || limits.block_bytes == 0
            || limits.block_bytes >= gnunet_regex::MAX_BLOCK_BYTES
            || limits.paths > 65535
            || limits.io_slice_bytes == 0
            || Instant::now() >= startup_until
        {
            return Err(Fault::InvalidInput.into());
        }
        for duration in [limits.output_lifetime, limits.partial_input] {
            if duration.is_zero() || Instant::now().checked_add(duration).is_none() {
                return Err(Fault::Deadline.into());
            }
        }
        let mut rows = Vec::new();
        rows.try_reserve_exact(limits.operations)
            .map_err(|_| Fault::Capacity)?;
        let mut native = client::Limits::default();
        native.protocol.gets = limits.operations;
        native.protocol.operations = limits.operations;
        native.protocol.monitors = 0;
        native.protocol.hellos = 0;
        native.protocol.known_per_get = 0;
        native.protocol.attempts = 1;
        native.protocol.frame_bytes = 65535;
        native.protocol.source_bytes = limits.bytes;
        native.output.frames = 1;
        native.output.bytes = 65535;
        native.io_slice_bytes = limits.io_slice_bytes;
        native.hello.maximum_address_bytes = 0;
        native.hello.maximum_addresses = 0;
        let clock = source.clock();
        Ok(Self {
            client: client::Client::new(instance, source, native)?,
            clock,
            limits,
            rows,
            refused: None,
            pending: None,
            deferred_source: None,
            startup: Some(startup_until),
            connection: None,
            partial: None,
            alarm: None,
            alarm_at: None,
            closing: false,
            cursor: 0,
        })
    }
    /// Only an actual currently attached local DHT MQ qualifies initial readiness.
    pub fn ready(&self) -> bool {
        !self.closing && self.client.epoch().is_some()
    }
    fn index(&self, job: &JobId) -> Result<usize, Failure> {
        self.rows
            .iter()
            .position(|row| row.job == *job)
            .ok_or_else(|| Fault::Stale.into())
    }
    fn due(&self) -> Result<Instant, Failure> {
        Instant::now()
            .checked_add(self.limits.output_lifetime)
            .ok_or_else(|| Fault::Overflow.into())
    }
    fn reserve(&mut self, job: &JobId) -> Result<usize, Failure> {
        if self.rows.iter().any(|row| row.job == *job) {
            return Err(Fault::Conflict.into());
        }
        if self.refused.is_some() {
            return Err(Fault::NotReady.into());
        }
        if self.closing || self.rows.len() == self.limits.operations {
            self.refused = Some(job.clone());
            return Err(if self.closing {
                Fault::Closed
            } else {
                Fault::Capacity
            }
            .into());
        }
        let at = self.rows.len();
        self.rows.push(Row {
            job: job.clone(),
            operation: Operation::Refused,
            hard: None,
            retiring: false,
            quiet: true,
            terminal: None,
            failure: None,
        });
        Ok(at)
    }
    fn collected(&mut self, completion: client::Completion<'a>) -> Result<(), Failure> {
        let row = self
            .rows
            .iter_mut()
            .find(|row| matches!(row.operation, Operation::Put(id) if id == completion.operation))
            .ok_or(Fault::Stale)?;
        if row.terminal.is_some() {
            return Err(Fault::Conflict.into());
        }
        row.quiet = true;
        row.hard = None;
        row.terminal = Some(completion.outcome);
        Ok(())
    }
    fn collect(&mut self) -> Result<(), Failure> {
        while let Some(completion) = self.client.take_completion() {
            self.collected(completion)?;
        }
        Ok(())
    }
    fn detached(&mut self) {
        self.connection = None;
        self.partial = None;
        for row in &mut self.rows {
            if row.retiring && matches!(row.operation, Operation::Get(_)) {
                row.quiet = true;
                row.hard = None;
            }
        }
    }
    fn detach(&mut self) -> Result<(), Failure> {
        let result = self.client.retire_io();
        self.detached();
        match result {
            Ok(_) => self.collect(),
            Err(original) => {
                let _actual = self.client.close();
                self.closing = true;
                self.detached();
                let cleanup = self.collect().err();
                Err(match cleanup {
                    Some(cleanup) => Box::new(Independent {
                        original: Box::new(original),
                        cleanup,
                    }) as Failure,
                    None => Box::new(original),
                })
            }
        }
    }
    fn stop_row(&mut self, at: usize) -> Result<(), Failure> {
        self.collect()?;
        if self.rows[at].quiet {
            return Ok(());
        }
        self.rows[at].retiring = true;
        let result = match &self.rows[at].operation {
            Operation::Get(id) => self.client.stop(*id),
            Operation::Put(id) => self.client.cancel(*id),
            Operation::Waiting(_) | Operation::Refused => {
                self.rows[at].operation = Operation::Refused;
                self.rows[at].quiet = true;
                self.rows[at].hard = None;
                return Ok(());
            }
        };
        match result {
            Ok(client::Cancel::BeforeIssue) => {
                self.rows[at].quiet = true;
                self.rows[at].hard = None;
                self.rows[at].operation = Operation::Refused;
                Ok(())
            }
            Ok(client::Cancel::Draining) => {
                if self.rows[at].hard.is_none() {
                    self.rows[at].hard = Some(self.due()?);
                }
                Ok(())
            }
            Err(error) => Err(Box::new(error)),
        }
    }
    fn queued_bytes(&self) -> Result<usize, Failure> {
        self.rows.iter().try_fold(0usize, |sum, row| {
            let bytes = if let Operation::Waiting(wait) = &row.operation {
                wait.block.capacity()
            } else {
                0
            };
            sum.checked_add(bytes).ok_or_else(|| Fault::Overflow.into())
        })
    }
    fn issue_waiting(&mut self) -> Result<bool, Failure> {
        if self.closing || self.client.epoch().is_none() {
            return Ok(false);
        }
        let Some(at) = self
            .rows
            .iter()
            .position(|row| !row.retiring && matches!(row.operation, Operation::Waiting(_)))
        else {
            return Ok(false);
        };
        let now = self.clock.sample()?.now.as_micros();
        let expired = matches!(&self.rows[at].operation, Operation::Waiting(wait) if now > wait.expires)
            || self.rows[at]
                .hard
                .is_some_and(|hard| Instant::now() >= hard);
        if expired {
            self.rows[at].operation = Operation::Refused;
            self.rows[at].quiet = true;
            self.rows[at].hard = None;
            self.rows[at].failure = Some(Fault::Deadline.into());
            return Ok(true);
        }
        let Operation::Waiting(wait) = &self.rows[at].operation else {
            return Err(Fault::Conflict.into());
        };
        let result = self.client.put(client::ipc::Put {
            block_type: wait.kind,
            options: wait.options,
            replication: wait.replication,
            expiration: AbsoluteTime::from_micros(wait.expires),
            key: &wait.key,
            payload: &wait.block,
        });
        match result {
            Ok(id) => {
                self.rows[at].operation = Operation::Put(id);
            }
            Err(error) => {
                self.rows[at].operation = Operation::Refused;
                self.rows[at].quiet = true;
                self.rows[at].hard = None;
                self.rows[at].failure = Some(Box::new(error));
            }
        }
        Ok(true)
    }
    fn select_terminal(&mut self) -> Result<bool, Failure> {
        if self.pending.is_some() {
            return Ok(true);
        }
        let length = self.rows.len();
        for step in 0..length {
            let at = (self.cursor + step) % length;
            let row = &mut self.rows[at];
            if !row.quiet {
                continue;
            }
            if let Some(outcome) = row.terminal.take() {
                self.cursor = (at + 1) % length;
                if outcome == client::Outcome::Written && row.failure.is_none() {
                    self.pending = Some(Pending::Complete(row.job.clone()));
                } else {
                    let actual: Failure = Box::new(PutRetirement { outcome });
                    row.failure = Some(match row.failure.take() {
                        Some(original) => Box::new(Independent {
                            original,
                            cleanup: actual,
                        }),
                        None => actual,
                    });
                    self.pending = Some(Pending::Failed(row.job.clone()));
                }
                return Ok(true);
            }
            if row.failure.is_some() {
                self.cursor = (at + 1) % length;
                self.pending = Some(Pending::Failed(row.job.clone()));
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn observed(&mut self) -> Result<Event<'_>, Failure> {
        match self.pending.as_ref().ok_or(Fault::NotReady)? {
            Pending::Rejected(job, error) => Ok(Event::Rejected {
                job: job.clone(),
                error: *error,
            }),
            Pending::Complete(job) => Ok(Event::PutComplete(job.clone())),
            Pending::Failed(job) => {
                let row = &self.rows[self.index(job)?];
                Ok(Event::Failed {
                    job: job.clone(),
                    error: row.failure.as_deref().ok_or(Fault::NotReady)?,
                })
            }
            Pending::Source(error) => Ok(Event::SourceFailure {
                error: error.as_ref(),
            }),
            Pending::Reply(owner) => {
                let result = owner.received.result()?;
                Ok(Event::Reply {
                    job: owner.job.clone(),
                    reply: Reply {
                        expires: result.expiration.as_micros(),
                        key: *result.key,
                        kind: result.block_type,
                        block: result.payload,
                        get_path: &owner.get_path,
                        put_path: &owner.put_path,
                    },
                })
            }
        }
    }
    fn inbound(&mut self, received: client::Received<'a>) -> Result<(), Failure> {
        self.partial = None;
        let client::Event::Result { get, .. } = received.event() else {
            return Ok(());
        };
        let Some(at) = self.rows.iter().position(|row| {
            !row.retiring && matches!(row.operation, Operation::Get(id) if id == *get)
        }) else {
            return Ok(());
        };
        let result = received.result()?;
        if result.payload.len() > self.limits.block_bytes
            || result
                .get_path
                .len()
                .checked_add(result.put_path.len())
                .is_none_or(|n| n > self.limits.paths)
        {
            self.pending = Some(Pending::Rejected(
                self.rows[at].job.clone(),
                gnunet_regex_service::Error::Capacity,
            ));
            return Ok(());
        }
        let mut get_path = Vec::new();
        let mut put_path = Vec::new();
        get_path
            .try_reserve_exact(result.get_path.len())
            .map_err(|_| Fault::Capacity)?;
        put_path
            .try_reserve_exact(result.put_path.len())
            .map_err(|_| Fault::Capacity)?;
        for (path, source) in [
            (&mut get_path, result.get_path),
            (&mut put_path, result.put_path),
        ] {
            for element in source.elements() {
                let mut peer = [0; 32];
                peer.copy_from_slice(element.predecessor());
                path.push(peer);
            }
        }
        self.pending = Some(Pending::Reply(ReplyOwner {
            job: self.rows[at].job.clone(),
            received,
            get_path,
            put_path,
        }));
        Ok(())
    }
    fn source_failure(&mut self, error: Failure) -> Result<(), Failure> {
        if self.pending.is_none() {
            self.pending = Some(Pending::Source(error));
        } else if self.deferred_source.is_none() {
            self.deferred_source = Some(error);
        } else {
            return Err(Box::new(Independent {
                original: self.deferred_source.take().ok_or(Fault::NotReady)?,
                cleanup: error,
            }));
        }
        Ok(())
    }
    fn earliest(&self) -> Option<Instant> {
        self.rows
            .iter()
            .filter_map(|row| row.hard)
            .chain(self.startup)
            .chain(self.connection)
            .chain(self.partial)
            .min()
    }
    fn native_guard(&mut self, cx: &mut Context<'_>) -> Result<bool, Failure> {
        // Original settled PUT notices win over a later guard/cancel decision.
        self.collect()?;
        let target = self.earliest();
        if target != self.alarm_at {
            self.alarm_at = target;
            self.alarm = target.map(|at| Box::pin(tokio::time::sleep_until(at)));
        }
        if let Some(alarm) = &mut self.alarm {
            let _registered = alarm.as_mut().poll(cx);
        }
        let now = Instant::now();
        if self.startup.is_some_and(|hard| now >= hard) {
            self.startup = None;
            let original: Failure = Fault::Deadline.into();
            let cleanup = self.close().err();
            return Err(match cleanup {
                Some(cleanup) => Box::new(Independent { original, cleanup }),
                None => original,
            });
        }
        if self.connection.is_some_and(|hard| now >= hard)
            || self.partial.is_some_and(|hard| now >= hard)
        {
            if let Err(cleanup) = self.detach() {
                return Err(Box::new(Independent {
                    original: Fault::Deadline.into(),
                    cleanup,
                }));
            }
            self.source_failure(Fault::Deadline.into())?;
            return Ok(true);
        }
        if let Some(at) = self
            .rows
            .iter()
            .position(|row| !row.quiet && row.hard.is_some_and(|hard| now >= hard))
        {
            if let Err(cleanup) = self.stop_row(at).and_then(|()| self.detach()) {
                return Err(Box::new(Independent {
                    original: Fault::Deadline.into(),
                    cleanup,
                }));
            }
            self.rows[at].hard = None;
            if !self.rows[at].quiet {
                return Err(Fault::NotReady.into());
            }
            if self.rows[at].failure.is_none() {
                self.rows[at].failure = Some(Fault::Deadline.into());
            }
            return Ok(true);
        }
        Ok(false)
    }
    fn progress(&mut self, progress: client::Progress<'a>) -> Result<(), Failure> {
        match progress {
            client::Progress::Connected(_) => {
                self.startup = None;
                self.connection = None;
                self.partial = None;
                let hard = self.due()?;
                for row in &mut self.rows {
                    if !row.quiet
                        && !row.retiring
                        && row.hard.is_none()
                        && matches!(row.operation, Operation::Get(_))
                    {
                        row.hard = Some(hard);
                    }
                }
            }
            client::Progress::Completed(completion) => self.collected(completion)?,
            client::Progress::Written {
                action: client::Action::Get(id),
                ..
            } => {
                if let Some(row) = self
                    .rows
                    .iter_mut()
                    .find(|row| matches!(row.operation, Operation::Get(get) if get == id))
                    && !row.retiring
                {
                    row.hard = None;
                }
            }
            client::Progress::Written {
                action: client::Action::Stop(id),
                ..
            } => {
                if let Some(row) = self
                    .rows
                    .iter_mut()
                    .find(|row| matches!(row.operation, Operation::Get(get) if get == id))
                {
                    row.quiet = true;
                    row.hard = None;
                }
            }
            client::Progress::Inbound(received) => self.inbound(received)?,
            client::Progress::Lost { cause, .. } => {
                self.detached();
                self.collect()?;
                self.pending = Some(Pending::Source(Box::new(SourceLoss(cause))));
            }
            client::Progress::ConnectRetry { error, .. } => {
                self.connection = None;
                self.pending = Some(Pending::Source(Box::new(error)));
            }
            client::Progress::Unavailable(error) => {
                self.pending = Some(Pending::Source(Box::new(error)))
            }
            client::Progress::Capacity(_) => {
                self.pending = Some(Pending::Source(Fault::Capacity.into()))
            }
            client::Progress::Activity { read_bytes, .. }
                if read_bytes > 0 && self.partial.is_none() =>
            {
                self.partial = Some(
                    Instant::now()
                        .checked_add(self.limits.partial_input)
                        .ok_or(Fault::Overflow)?,
                );
            }
            client::Progress::Closed if !self.closing => {
                return Err(Fault::Closed.into());
            }
            _ => {}
        }
        Ok(())
    }
}
impl Provider for Native<'_> {
    fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.clock.clone()
    }
    fn put(&mut self, job: JobId, request: Put<'_>) -> Result<(), Failure> {
        let at = self.reserve(&job)?;
        let hard = self.due()?;
        if !matches!(request.kind, 22 | 23)
            || request.block.len() > self.limits.block_bytes
            || self.clock.sample()?.now.as_micros() > request.expires
        {
            return Err(Fault::InvalidInput.into());
        }
        if self.client.epoch().is_some() {
            let id = self.client.put(client::ipc::Put {
                block_type: request.kind,
                options: request.options,
                replication: request.replication,
                expiration: AbsoluteTime::from_micros(request.expires),
                key: &request.key,
                payload: request.block,
            })?;
            self.rows[at].operation = Operation::Put(id);
        } else {
            let queued = self.queued_bytes()?;
            if queued
                .checked_add(request.block.len())
                .is_none_or(|n| n > self.limits.bytes)
            {
                return Err(Fault::Capacity.into());
            }
            let mut block = Vec::new();
            block
                .try_reserve_exact(request.block.len())
                .map_err(|_| Fault::Capacity)?;
            if queued
                .checked_add(block.capacity())
                .is_none_or(|n| n > self.limits.bytes)
            {
                return Err(Fault::Capacity.into());
            }
            block.extend_from_slice(request.block);
            self.rows[at].operation = Operation::Waiting(WaitingPut {
                key: request.key,
                kind: request.kind,
                options: request.options,
                replication: request.replication,
                expires: request.expires,
                block,
            });
        }
        self.rows[at].quiet = false;
        self.rows[at].hard = Some(hard);
        Ok(())
    }
    fn get(&mut self, job: JobId, request: Get<'_>) -> Result<(), Failure> {
        let at = self.reserve(&job)?;
        let hard = self.due()?;
        if !matches!(request.kind, 22 | 23)
            || request.xquery.len() > self.limits.query_bytes
            || request.kind == 22 && request.xquery.last() != Some(&0)
            || request.kind == 23 && !request.xquery.is_empty()
        {
            return Err(Fault::InvalidInput.into());
        }
        let id = self.client.get(client::Get {
            key: &request.key,
            block_type: request.kind,
            options: request.options,
            replication: request.replication,
            extended_query: request.xquery,
        })?;
        self.rows[at].operation = Operation::Get(id);
        self.rows[at].quiet = false;
        self.rows[at].hard = Some(hard);
        Ok(())
    }
    fn retire(&mut self, job: &JobId) -> Result<(), Failure> {
        let at = self.index(job)?;
        self.stop_row(at)
    }
    fn quiescent(&self, job: &JobId) -> Result<bool, Failure> {
        if self.refused.as_ref() == Some(job) {
            return Ok(true);
        }
        let row = &self.rows[self.index(job)?];
        Ok(row.quiet && !matches!(&self.pending, Some(Pending::Reply(reply)) if reply.job == *job))
    }
    fn release(&mut self, job: &JobId) -> Result<bool, Failure> {
        if !self.quiescent(job)? {
            return Ok(false);
        }
        if self.refused.as_ref() == Some(job) {
            self.refused = None;
            return Ok(true);
        }
        let at = self.index(job)?;
        if self.pending.as_ref().and_then(Pending::job) == Some(job)
            || self.rows[at].terminal.is_some()
            || self.rows[at].failure.is_some()
        {
            return Ok(false);
        }
        self.rows.swap_remove(at);
        Ok(true)
    }
    fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Result<bool, Failure> {
        self.native_guard(cx)
    }
    fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<Result<Event<'_>, Failure>> {
        self.native_guard(cx)?;
        if self.pending.is_none()
            && let Some(error) = self.deferred_source.take()
        {
            self.pending = Some(Pending::Source(error));
        }
        if self.pending.is_none() {
            self.collect()?;
            if !self.select_terminal()? && !self.is_closed() {
                if self.issue_waiting()? {
                    cx.waker().wake_by_ref();
                } else {
                    if !self.closing && self.client.epoch().is_none() && self.connection.is_none() {
                        self.connection = Some(self.due()?);
                    }
                    match self.client.poll_with_input(cx, self.earliest(), true) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(Box::new(error))),
                        Poll::Ready(Ok(progress)) => self.progress(progress)?,
                    }
                }
                self.select_terminal()?;
            }
        }
        if self.pending.is_some() {
            Poll::Ready(self.observed())
        } else {
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
    fn consume(&mut self) -> Result<Option<Failure>, Failure> {
        // Every fallible preflight occurs while the exact original event is
        // still held. Err therefore permits retry without losing its cause.
        let terminal = match self.pending.as_ref().ok_or(Fault::NotReady)? {
            Pending::Complete(job) | Pending::Failed(job) => {
                let at = self.index(job)?;
                if !self.rows[at].quiet
                    || matches!(self.pending.as_ref(), Some(Pending::Failed(_)))
                        && self.rows[at].failure.is_none()
                {
                    return Err(Fault::NotReady.into());
                }
                Some(at)
            }
            _ => None,
        };
        let pending = self.pending.take().ok_or(Fault::NotReady)?;
        match (pending, terminal) {
            (Pending::Source(error), None) => Ok(Some(error)),
            (Pending::Reply(_) | Pending::Rejected(_, _), None) => Ok(None),
            (Pending::Complete(_), Some(at)) => {
                self.rows.swap_remove(at);
                Ok(None)
            }
            (Pending::Failed(job), Some(at)) => {
                let Some(error) = self.rows[at].failure.take() else {
                    self.pending = Some(Pending::Failed(job));
                    return Err(Fault::NotReady.into());
                };
                self.rows.swap_remove(at);
                Ok(Some(error))
            }
            (pending, _) => {
                self.pending = Some(pending);
                Err(Fault::NotReady.into())
            }
        }
    }
    fn close(&mut self) -> Result<(), Failure> {
        self.closing = true;
        self.startup = None;
        self.connection = None;
        self.partial = None;
        self.alarm = None;
        self.alarm_at = None;
        // Includes an idle native connect with no epoch. Existing complete PUT
        // notices survive the actual close, so collect never invents Lost.
        let _actual = self.client.close();
        for row in &mut self.rows {
            row.retiring = true;
            row.hard = None;
            if !matches!(row.operation, Operation::Put(_)) {
                row.operation = Operation::Refused;
                row.quiet = true;
            }
        }
        self.collect()
    }
    fn is_closed(&self) -> bool {
        self.closing
            && self.pending.is_none()
            && self.deferred_source.is_none()
            && self
                .rows
                .iter()
                .all(|row| row.quiet && row.terminal.is_none() && row.failure.is_none())
    }
}
