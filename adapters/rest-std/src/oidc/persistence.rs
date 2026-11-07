//! One explicit qualified private store, one original worker and one staged
//! durable change. Successful receipts come only from actual worker completion.
use super::*;
use gnunet_snapshot_host::{Namespace, backend, worker};
use std::{
    path::PathBuf,
    task::{Context as TaskContext, Poll},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::{mpsc, oneshot};
mod snapshot;
/// Explicit signer selection for a fresh owned store. Existing qualified stores
/// import their own original key; no new key is generated on recovery failure.
pub enum KeySource {
    /// Actual AWS-LC RSA generation for a new empty Rust namespace only.
    Rs256 {
        /// Original requested RSA width.
        bits: usize,
        /// Actual bounded backend policy.
        limits: gnunet_oidc_crypto_host::Limits,
    },
    /// Actual caller-selected HS512 secret, never an RSA fallback.
    Hs512 {
        /// Explicit opaque owned secret; erased on release.
        secret: Zeroizing<Vec<u8>>,
        /// Actual bounded backend policy.
        limits: gnunet_oidc_crypto_host::Limits,
    },
}
impl std::fmt::Debug for KeySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OidcKeySource([REDACTED])")
    }
}
/// Explicit persistent-provider inputs. No legacy/C store discovery or migration
/// exists. The directory must be new or already marked for this Rust namespace.
pub struct Options<'a> {
    /// Absolute explicitly owned private Rust state directory.
    pub directory: PathBuf,
    /// Explicit actual signing algorithm/key policy.
    pub signer: KeySource,
    /// Same original issuer URI used for JWT/discovery.
    pub origin: &'a [u8],
    /// Actual configured login UI.
    pub login_ui: &'a [u8],
    /// Explicit confidential-client secret, when configured.
    pub client_secret: Option<&'a [u8]>,
    /// Actual finite OIDC pools and lifetimes.
    pub limits: Limits,
    /// Complete serialized signer/config/issued-state byte ceiling.
    pub snapshot_bytes: usize,
}
/// Actual storage/source/apply failure. Secret bodies never enter diagnostics.
#[derive(Debug)]
pub enum Failure {
    /// Original shared store failure, including exact known/unknown publication
    /// stage and independent temporary cleanup failure.
    Store(Arc<backend::Failure>),
    /// Actual worker/channel/clock or original deadline failure.
    Source(Fault),
    /// Disk committed, but in-process original transaction ownership conflicted.
    Apply(Fault),
    /// Initial persistence failed after starting the original worker. Retain
    /// that cause and its actual independent drain/join report; no Drop proves
    /// an admitted initial image did not publish.
    Initialization {
        /// Original encode/submission/completion/receipt refusal.
        original: Box<Error>,
        /// Actual same-worker shutdown, including unmatched completions.
        stopped: Box<Stopped>,
    },
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OIDC persistence: {self:?}")
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Initialization { original, .. } => Some(original.as_ref()),
            _ => None,
        }
    }
}
impl Failure {
    fn error(self) -> Error {
        Error::OidcPersistence(Arc::new(self))
    }
}
pub(super) struct Material {
    tag: u8,
    key: Zeroizing<Vec<u8>>,
}
#[derive(Clone, Copy)]
struct Pending {
    serial: u64,
    issue: Option<(usize, u64)>,
}
struct Gate {
    next: u64,
    pending: Option<Pending>,
    failure: Option<Arc<Failure>>,
    closed: bool,
}
/// Prepared original business transition. No disk receipt is represented here.
pub(super) enum Change {
    Issue {
        row: usize,
        serial: u64,
        grant: Grant,
    },
    Exchange {
        row: usize,
        serial: u64,
        access_row: usize,
        access: Access,
    },
}
impl Change {
    fn pending(&self, serial: u64) -> Pending {
        Pending {
            serial,
            issue: match self {
                Self::Issue { row, serial, .. } => Some((*row, *serial)),
                Self::Exchange { .. } => None,
            },
        }
    }
    fn bound(&self, state: &State) -> Result<Bound, Fault> {
        match self {
            Self::Issue { grant, .. } => Ok(grant.bound),
            Self::Exchange {
                row,
                serial,
                access,
                ..
            } => {
                let grant = state
                    .grants
                    .get(*row)
                    .and_then(Option::as_ref)
                    .filter(|g| g.serial == *serial && matches!(g.state, GrantState::Issued { .. }))
                    .ok_or(Fault::StaleGeneration)?;
                Ok(Bound {
                    until: grant.bound.until.min(access.bound.until),
                    hard: grant.bound.hard.min(access.bound.hard),
                    wall_until: grant.bound.wall_until.min(access.bound.wall_until),
                })
            }
        }
    }
    fn abort(&self, state: &mut State) {
        if let Self::Issue { row, serial, .. } = self
            && state.grants[*row]
                .as_ref()
                .is_some_and(|g| g.serial == *serial && matches!(g.state, GrantState::Reserved))
        {
            state.grants[*row] = None;
        }
    }
    fn apply(self, state: &mut State, now: u64) -> Result<(), Fault> {
        match self {
            Self::Issue { row, serial, grant } => {
                let same = state.grants[row]
                    .as_ref()
                    .is_some_and(|g| g.serial == serial && matches!(g.state, GrantState::Reserved));
                if !same && (state.grants[row].is_some() || grant.bound.live(now)) {
                    return Err(Fault::Conflict);
                }
                state.grants[row] = grant.bound.live(now).then_some(grant);
            }
            Self::Exchange {
                row,
                serial,
                access_row,
                access,
            } => {
                if state.grants[row].as_ref().is_some_and(|g| {
                    g.serial != serial || !matches!(g.state, GrantState::Issued { .. })
                }) || state.accesses[access_row].as_ref().is_some_and(|old| {
                    old.subject != access.subject || !equal(&old.token, &access.token)
                }) {
                    return Err(Fault::Conflict);
                }
                state.grants[row] = None;
                state.accesses[access_row] = access.bound.live(now).then_some(access);
            }
        };
        Ok(())
    }
}
struct Command {
    serial: u64,
    change: Change,
    body: Zeroizing<Vec<u8>>,
    until: u64,
    hard: Instant,
    response: oneshot::Sender<Result<u64, Arc<Failure>>>,
}
pub(super) struct Port {
    sender: mpsc::Sender<Command>,
    gate: Rc<RefCell<Gate>>,
    material: Rc<Material>,
    max_bytes: usize,
}
impl Port {
    pub(super) fn clock_failed(&self, error: Fault) {
        let mut g = self.gate.borrow_mut();
        if g.failure.is_none() {
            g.failure = Some(Arc::new(Failure::Source(error)));
        }
        g.closed = true;
        // Keep any actual original admitted job identity until Driver observes it.
    }
    pub(super) fn available(&self) -> Result<(), Error> {
        let g = self.gate.borrow();
        if let Some(e) = &g.failure {
            return Err(Error::OidcPersistence(e.clone()));
        }
        if g.closed {
            return Err(Fault::Closed.into());
        }
        if g.pending.is_some() {
            return Err(Fault::WouldBlock.into());
        }
        Ok(())
    }
    pub(super) fn retains(&self, row: usize, serial: u64) -> bool {
        self.gate
            .borrow()
            .pending
            .is_some_and(|p| p.issue == Some((row, serial)))
    }
    pub(super) async fn submit(
        &self,
        provider: &Provider,
        change: Change,
        until: u64,
        hard: Instant,
    ) -> Result<(), Error> {
        self.available()?;
        let now = provider.now()?;
        let bound = change.bound(&provider.state.borrow())?;
        if !bound.live(now) || now >= until || Instant::now() >= hard {
            return Err(Error::Deadline);
        }
        let serial = self
            .gate
            .borrow()
            .next
            .checked_add(1)
            .ok_or(Fault::Overflow)?;
        let pending = change.pending(serial);
        let body = snapshot::encode(provider, &self.material, Some(&change), self.max_bytes)?;
        let (response, receiving) = oneshot::channel();
        let command = Command {
            serial,
            change,
            body,
            until: until.min(bound.until),
            hard: hard.min(bound.hard),
            response,
        };
        self.sender.try_send(command).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => Error::Core(Fault::WouldBlock),
            mpsc::error::TrySendError::Closed(_) => Error::Core(Fault::Closed),
        })?;
        {
            let mut g = self.gate.borrow_mut();
            g.next = serial;
            g.pending = Some(pending);
        }
        let committed = receiving
            .await
            .map_err(|_| Failure::Source(Fault::OutcomeUnknown).error())?;
        committed.map_err(Error::OidcPersistence)?;
        let gate = self.gate.borrow();
        if let Some(error) = &gate.failure {
            return Err(Error::OidcPersistence(error.clone()));
        }
        if gate.closed {
            return Err(Fault::Closed.into());
        }
        Ok(())
    }
}
struct Active {
    job: worker::Job,
    command: Command,
}
/// One original durable transition observation; counts/generation only, no token
/// or key content. It is not a RECLAIM issue/consume or HTTP-delivery receipt.
#[derive(Clone, Copy, Debug)]
pub enum Progress {
    /// Original request ended before worker admission; no filesystem command
    /// was admitted. Any prior RECLAIM operation remains its separate fact.
    NotAdmitted {
        /// Original local command serial.
        serial: u64,
    },
    /// Actual file+directory-synchronized committed generation.
    Committed {
        /// Original local command serial.
        serial: u64,
        /// Actual qualified store generation.
        generation: u64,
    },
}
/// Independent actual drain, original worker join and first latched failure.
/// None of these fields is substituted for another source's result.
pub struct Stopped {
    /// Actual original worker shutdown/join result, never a fabricated report.
    pub worker: Result<worker::Stopped, Fault>,
    /// First source/apply/storage latch, if any.
    pub failure: Option<Arc<Failure>>,
    /// Original independent reactor-drain failure.
    pub drain: Option<Error>,
    unmatched: Option<worker::Completion>,
}
impl Stopped {
    /// Whether any actual independent cleanup path failed or was unaccounted.
    pub fn failed(&self) -> bool {
        self.failure.is_some()
            || self.drain.is_some()
            || self.unmatched.is_some()
            || match &self.worker {
                Err(_) => true,
                Ok(w) => w.failure.is_some(),
            }
    }
    /// An actual unexpected original completion, retained rather than discarded.
    pub const fn unmatched(&self) -> Option<&worker::Completion> {
        self.unmatched.as_ref()
    }
}
impl std::fmt::Debug for Stopped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcStopped")
            .field("worker", &self.worker)
            .field("failure", &self.failure)
            .field("drain", &self.drain)
            .field("unmatched", &self.unmatched.is_some())
            .finish()
    }
}
impl std::fmt::Display for Stopped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OIDC shutdown: {self:?}")
    }
}
impl std::error::Error for Stopped {}
/// Explicit persistent owner. Foreground must poll it independently of HTTP
/// futures and drain/join after closing HTTP jobs. There is one disk worker.
pub struct Driver {
    worker: worker::Worker,
    receiver: mpsc::Receiver<Command>,
    gate: Rc<RefCell<Gate>>,
    state: Rc<RefCell<State>>,
    clock: Arc<dyn RuntimeClock>,
    generation: u64,
    active: Option<Active>,
    stopped: bool,
}
impl Driver {
    fn fail(&mut self, e: Arc<Failure>) {
        let mut g = self.gate.borrow_mut();
        if g.failure.is_none() {
            g.failure = Some(e);
        }
        g.pending = None;
        g.closed = true;
    }
    fn abort(&mut self, command: Command, error: Arc<Failure>) {
        command.change.abort(&mut self.state.borrow_mut());
        self.gate.borrow_mut().pending = None;
        let _delivered = command.response.send(Err(error));
    }
    /// Poll only actual original worker completion/admission. A dropped response
    /// future never discards an already-admitted file result or replays a job.
    pub fn poll(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<Progress, Error>> {
        if self.stopped {
            return Poll::Pending;
        }
        if self.active.is_some() {
            match self.worker.poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => {
                    let failure = Arc::new(Failure::Source(e));
                    self.fail(failure.clone());
                    if let Some(active) = self.active.take() {
                        self.abort(active.command, failure.clone());
                    }
                    return Poll::Ready(Err(Error::OidcPersistence(failure)));
                }
                Poll::Ready(Ok(None)) => {
                    let failure = Arc::new(Failure::Source(Fault::OutcomeUnknown));
                    self.fail(failure.clone());
                    if let Some(active) = self.active.take() {
                        self.abort(active.command, failure.clone());
                    }
                    return Poll::Ready(Err(Error::OidcPersistence(failure)));
                }
                Poll::Ready(Ok(Some(completion))) => {
                    let active = self.active.take().ok_or(Fault::StaleGeneration)?;
                    let (job, result) = completion.into_parts();
                    if job != active.job
                        || job.namespace() != Namespace::Oidc
                        || !self
                            .gate
                            .borrow()
                            .pending
                            .is_some_and(|p| p.serial == active.command.serial)
                    {
                        let failure = Arc::new(Failure::Apply(Fault::StaleGeneration));
                        self.fail(failure.clone());
                        self.abort(active.command, failure.clone());
                        return Poll::Ready(Err(Error::OidcPersistence(failure)));
                    }
                    match result {
                        Err(cause) => {
                            let failure = Arc::new(Failure::Store(cause));
                            self.fail(failure.clone());
                            self.abort(active.command, failure.clone());
                            return Poll::Ready(Err(Error::OidcPersistence(failure)));
                        }
                        Ok(receipt) => {
                            let Command {
                                serial,
                                change,
                                response,
                                ..
                            } = active.command;
                            if receipt.namespace() != Namespace::Oidc
                                || self.generation.checked_add(1) != Some(receipt.generation())
                            {
                                let failure = Arc::new(Failure::Apply(Fault::StaleGeneration));
                                self.fail(failure.clone());
                                let _delivered = response.send(Err(failure.clone()));
                                return Poll::Ready(Err(Error::OidcPersistence(failure)));
                            }
                            self.generation = receipt.generation();
                            let now = match self.clock.sample() {
                                Ok(n) => n.now.as_micros(),
                                Err(e) => {
                                    let failure = Arc::new(Failure::Apply(e));
                                    self.fail(failure.clone());
                                    let _delivered = response.send(Err(failure));
                                    return Poll::Ready(Err(Error::Clock(e)));
                                }
                            };
                            let applied = {
                                let mut state = self.state.borrow_mut();
                                change.apply(&mut state, now)
                            };
                            if let Err(e) = applied {
                                let failure = Arc::new(Failure::Apply(e));
                                self.fail(failure.clone());
                                let _delivered = response.send(Err(failure.clone()));
                                return Poll::Ready(Err(Error::OidcPersistence(failure)));
                            }
                            self.gate.borrow_mut().pending = None;
                            let _delivered = response.send(Ok(self.generation));
                            return Poll::Ready(Ok(Progress::Committed {
                                serial,
                                generation: self.generation,
                            }));
                        }
                    }
                }
            }
        }
        let command = match self.receiver.poll_recv(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(None) => return Poll::Pending,
            Poll::Ready(Some(c)) => c,
        };
        let now = match self.clock.sample() {
            Ok(n) => n.now.as_micros(),
            Err(e) => {
                let failure = Arc::new(Failure::Source(e));
                self.fail(failure.clone());
                self.abort(command, failure);
                return Poll::Ready(Err(Error::Clock(e)));
            }
        };
        if command.response.is_closed() || now >= command.until || Instant::now() >= command.hard {
            let serial = command.serial;
            self.abort(command, Arc::new(Failure::Source(Fault::Deadline)));
            return Poll::Ready(Ok(Progress::NotAdmitted { serial }));
        }
        // Move the exact original body to the sole actual worker; retain the
        // rest of the original command and completion sender in this owner.
        let mut command = command;
        let body = std::mem::replace(&mut command.body, Zeroizing::new(Vec::new()));
        match self.worker.submit(self.generation, body) {
            Ok(job) => {
                self.active = Some(Active { job, command });
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err((reason, body)) => {
                command.body = body;
                let failure = Arc::new(Failure::Source(reason));
                self.fail(failure.clone());
                self.abort(command, failure.clone());
                Poll::Ready(Err(Error::OidcPersistence(failure)))
            }
        }
    }
    /// Close admission, observe any queued intent and actual in-flight command,
    /// then join the original worker. No deadline pretends to cancel fsync.
    pub async fn shutdown(mut self) -> Stopped {
        self.gate.borrow_mut().closed = true;
        self.receiver.close();
        let mut drain = None;
        loop {
            if self.active.is_none() && self.receiver.is_empty() {
                break;
            }
            if let Err(error) = poll_fn(|cx| self.poll(cx)).await
                && drain.is_none()
            {
                drain = Some(error);
            }
        }
        self.stopped = true;
        self.worker.request_stop();
        let mut unmatched = None;
        let worker = self
            .worker
            .shutdown(|completion| {
                if unmatched.is_none() {
                    unmatched = Some(completion);
                }
            })
            .await;
        Stopped {
            worker,
            failure: self.gate.borrow().failure.clone(),
            drain,
            unmatched,
        }
    }
}
impl Drop for Driver {
    fn drop(&mut self) {
        self.gate.borrow_mut().closed = true;
        self.receiver.close();
    }
}
pub(super) fn wall_now() -> Result<u64, Fault> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Fault::TimeUncertain)?
            .as_micros(),
    )
    .map_err(|_| Fault::Overflow)
}
impl Provider {
    /// Explicitly claim only a new/qualified Rust private directory, recover its
    /// original signer/artifacts, or generate+commit a fresh signer once before
    /// returning readiness. It never reads C paths or falls back after corruption.
    pub async fn persistent(
        clock: Arc<dyn RuntimeClock>,
        options: Options<'_>,
    ) -> Result<(Self, Driver), Error> {
        if !options.directory.is_absolute()
            || options.directory.components().any(|c| {
                matches!(
                    c,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return Err(Fault::InvalidInput.into());
        }
        let (store, loaded) = backend::Store::open(
            Namespace::Oidc,
            &options.directory,
            backend::Limits {
                body_bytes: options.snapshot_bytes,
            },
        )
        .map_err(|e| Failure::Store(Arc::new(e)).error())?;
        if loaded.namespace() != Namespace::Oidc {
            return Err(Fault::Authentication.into());
        }
        let generation = loaded.generation();
        if generation == 0 && !loaded.created_directory() {
            return Err(Fault::NotReady.into());
        }
        let body = loaded.into_body();
        if (generation == 0) != body.is_empty() {
            return Err(Fault::Malformed.into());
        }
        let anchor = Instant::now();
        let now = clock.sample().map_err(Error::Clock)?.now.as_micros();
        let wall = wall_now()?;
        let (signer, material, state) = snapshot::recover(&body, &options, now, wall, anchor)?;
        drop(body);
        let mut provider = Provider::new(
            clock.clone(),
            signer,
            options.origin,
            options.login_ui,
            options.client_secret,
            options.limits,
        )?;
        if let Some(state) = state {
            provider.state = Rc::new(RefCell::new(state));
        }
        let material = Rc::new(material);
        let mut worker = worker::Worker::start(store)?;
        // Once Worker::start succeeded, every initial error must still drain
        // and join that same original owner before the public constructor errs.
        let initialized: Result<u64, Error> = async {
            let mut committed = generation;
            if generation == 0 {
                let body = snapshot::encode(&provider, &material, None, options.snapshot_bytes)?;
                let job = worker.submit(0, body).map_err(|(e, _)| e)?;
                let completion = poll_fn(|cx| worker.poll(cx))
                    .await?
                    .ok_or(Fault::OutcomeUnknown)?;
                let (actual, result) = completion.into_parts();
                if actual != job {
                    return Err(Fault::StaleGeneration.into());
                }
                let receipt = result.map_err(|e| Failure::Store(e).error())?;
                if receipt.namespace() != Namespace::Oidc || receipt.generation() != 1 {
                    return Err(Fault::StaleGeneration.into());
                }
                committed = 1;
            }
            Ok(committed)
        }
        .await;
        let committed = match initialized {
            Ok(generation) => generation,
            Err(original) => {
                let mut unmatched = None;
                let joined = worker
                    .shutdown(|completion| {
                        if unmatched.is_none() {
                            unmatched = Some(completion);
                        }
                    })
                    .await;
                return Err(Failure::Initialization {
                    original: Box::new(original),
                    stopped: Box::new(Stopped {
                        worker: joined,
                        failure: None,
                        drain: None,
                        unmatched,
                    }),
                }
                .error());
            }
        };
        let gate = Rc::new(RefCell::new(Gate {
            next: 0,
            pending: None,
            failure: None,
            closed: false,
        }));
        let (sender, receiver) = mpsc::channel(1);
        provider.persistent = Some(Port {
            sender,
            gate: gate.clone(),
            material,
            max_bytes: options.snapshot_bytes,
        });
        let driver = Driver {
            worker,
            receiver,
            gate,
            state: provider.state.clone(),
            clock,
            generation: committed,
            active: None,
            stopped: false,
        };
        Ok((provider, driver))
    }
}
