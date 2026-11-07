//! Dedicated never-evicted public TCP replay floors on the actual qualified
//! snapshot Store and one explicitly owned bounded Worker. No keys, ciphertext,
//! nonce disk protocol, C store, implicit retry or private IPC is involved.
#![cfg(unix)]
#![forbid(unsafe_code)]
mod format;
/// V2 public frontier image and actual original bootstrap barrier.
pub mod pairing;
use gnunet_crypto::EddsaPublicKey;
use gnunet_snapshot_host::{
    Namespace,
    backend::{self, Exposure, Store},
    worker::{Job, Stopped, Worker},
};
pub use gnunet_tcp_communicator_core::session::ReplayKind;
use gnunet_types::Error;
use std::{
    cell::{Cell, RefCell},
    fmt, io,
    path::Path,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
};
/// Dedicated namespace, never the T1 generation or DV watermark directory.
pub const NAMESPACE: Namespace = Namespace::TransportTcp;
/// Persisted public installation identity. Only actual initialized/recovered
/// ledger state creates one; public bytes are not a new authorization capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LedgerId([u8; 32]);
impl LedgerId {
    /// Exact public ID to persist in the new frontier binding.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
#[derive(Clone, Copy)]
struct Record {
    peer: EddsaPublicKey,
    kind: ReplayKind,
    stamp: u64,
}
/// Forever floor quota. No age, remote loss, cancellation or replacement peer
/// silently evicts old records and reauthorizes an older signed timestamp.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Distinct remote peer/kind rows for this fixed actual local identity.
    pub records: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self { records: 8192 }
    }
}
/// Original public storage/resource cause, preserving the shared backend's
/// publication exposure, errno and independent temporary cleanup failure.
#[derive(Debug)]
pub enum Cause {
    /// Original protocol/quota/ownership classification.
    Protocol(Error),
    /// Original worker-start or public-ID entropy failure.
    Io(io::Error),
    /// Actual qualified snapshot failure, never an inferred unsuccessful ACK.
    Snapshot(Arc<backend::Failure>),
}
/// Exact failed stage. An admitted unknown write permanently fences this owner;
/// it is never resubmitted under a new token or interpreted as persistence.
#[derive(Debug)]
pub struct Failure {
    /// Original stage name.
    pub stage: &'static str,
    /// Whether the original publication may have happened.
    pub uncertain: bool,
    /// Actual original cause.
    pub cause: Cause,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TCP replay {} uncertain={}: {:?}",
            self.stage, self.uncertain, self.cause
        )
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.cause {
            Cause::Protocol(error) => Some(error),
            Cause::Io(error) => Some(error),
            Cause::Snapshot(error) => Some(&**error),
        }
    }
}
fn fault(stage: &'static str, error: Error, uncertain: bool) -> Failure {
    Failure {
        stage,
        uncertain,
        cause: Cause::Protocol(error),
    }
}
fn storage(stage: &'static str, error: Arc<backend::Failure>) -> Failure {
    Failure {
        stage,
        uncertain: error.exposure == Exposure::Unknown,
        cause: Cause::Snapshot(error),
    }
}
/// Original operation identity, checked by owner allocation and serial. Numeric
/// value is diagnostic only; no arbitrary successful receipt constructor exists.
#[derive(Clone, Debug)]
pub struct Token {
    domain: Rc<()>,
    serial: u64,
}
impl PartialEq for Token {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.domain, &other.domain) && self.serial == other.serial
    }
}
impl Eq for Token {}
impl Token {
    /// Diagnostic original serial; cannot mint or retag an operation.
    #[must_use]
    pub const fn value(&self) -> u64 {
        self.serial
    }
}
struct Authority {
    id: LedgerId,
    local: EddsaPublicKey,
    generation: Cell<u64>,
    ready: Cell<bool>,
    pending: Cell<bool>,
    bound: Cell<bool>,
    frontier: RefCell<Option<Arc<()>>>,
}
/// Private actual committed/loaded floor for one original operation. This
/// proves local persistence only; frontier minGen must be committed before the
/// corresponding original PEERSTORE STORE is admitted. It never proves a remote
/// write, replay authentication, or old backend quiescence.
pub struct Floor {
    authority: Rc<Authority>,
    token: Token,
    peer: EddsaPublicKey,
    kind: ReplayKind,
    stamp: u64,
    generation: u64,
}
impl Floor {
    /// Validate the original live durable authority, including unknown/close.
    pub fn validate(&self) -> Result<(), Error> {
        if !self.authority.ready.get() {
            return Err(Error::Closed);
        }
        if self.generation > self.authority.generation.get() {
            return Err(Error::Stale);
        }
        Ok(())
    }
    /// Exact private-origin operation whose floor became durable.
    #[must_use]
    pub const fn token(&self) -> &Token {
        &self.token
    }
    /// Exact public installation identity, not a caller-supplied replacement.
    #[must_use]
    pub fn identity(&self) -> LedgerId {
        self.authority.id
    }
    /// Local peer bound into the complete catalog.
    #[must_use]
    pub fn local(&self) -> EddsaPublicKey {
        self.authority.local
    }
    /// Actual remote identity supplied by the original verified session effect.
    #[must_use]
    pub const fn peer(&self) -> EddsaPublicKey {
        self.peer
    }
    /// Exact distinct official watermark key family.
    #[must_use]
    pub const fn kind(&self) -> ReplayKind {
        self.kind
    }
    /// Actual committed maximum; equal received timestamps stay allowed.
    #[must_use]
    pub const fn stamp(&self) -> u64 {
        self.stamp
    }
    /// Actual loaded or committed original generation, never queue length.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}
impl fmt::Debug for Floor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Floor")
            .field("token", &self.token)
            .field("peer", &self.peer)
            .field("kind", &self.kind)
            .field("stamp", &self.stamp)
            .field("generation", &self.generation)
            .finish()
    }
}
/// Borrowed complete actual catalog. Borrowing prevents replacing/closing its
/// owner while a new frontier validates recovery; no u64/ID constructor exists.
pub struct Catalog<'a> {
    ledger: &'a Ledger,
}
impl Catalog<'_> {
    /// Retain this exact original actual initialized/loaded source for the
    /// frontier. Later unknown/close/pending recovery checks remain effective.
    pub fn lease(&self) -> Result<CatalogLease, Error> {
        self.validate()?;
        Ok(CatalogLease {
            authority: self.ledger.authority.clone(),
        })
    }

    /// Refuse uninitialized, pending, unknown, or closing catalog authority.
    pub fn validate(&self) -> Result<(), Error> {
        self.ledger.check_catalog()
    }
    /// Actual initialization identity, recovered from this complete image.
    #[must_use]
    pub fn identity(&self) -> LedgerId {
        self.ledger.authority.id
    }
    /// The original actual local identity of every catalog row.
    #[must_use]
    pub fn local(&self) -> EddsaPublicKey {
        self.ledger.authority.local
    }
    /// Actual complete image generation, never a predicted pending commit.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.ledger.authority.generation.get()
    }
    /// Persisted bootstrap phase, read only from this actual complete image.
    #[must_use]
    pub fn is_bound(&self) -> bool {
        self.ledger.authority.bound.get()
    }
    /// Actual local durable maximum for the original peer and distinct kind.
    pub fn floor(&self, peer: EddsaPublicKey, kind: ReplayKind) -> Result<Option<u64>, Error> {
        self.validate()?;
        if !self.ledger.authority.bound.get() {
            return Err(Error::NotReady);
        }
        Ok(self
            .ledger
            .find(peer, kind)
            .ok()
            .map(|i| self.ledger.records[i].stamp))
    }
}
/// Opaque live lease derived only from an actual complete Catalog. It retains
/// original source identity; it cannot turn an ID/generation into recovery proof.
#[derive(Clone)]
pub struct CatalogLease {
    authority: Rc<Authority>,
}
impl CatalogLease {
    /// Require the original durable source to remain known and active.
    pub fn validate(&self) -> Result<(), Error> {
        if !self.authority.ready.get() {
            return Err(Error::Closed);
        }
        if !self.authority.bound.get() {
            return Err(Error::NotReady);
        }
        Ok(())
    }
    /// Actual complete Unbound or Bound image, only for initialization pairing.
    pub fn validate_binding(&self) -> Result<(), Error> {
        if !self.authority.ready.get() {
            return Err(Error::Closed);
        }
        if self.authority.pending.get() {
            return Err(Error::WouldBlock);
        }
        Ok(())
    }
    /// Recovery additionally requires no unobserved original worker mutation.
    pub fn validate_recovery(&self) -> Result<(), Error> {
        self.validate_binding()?;
        if !self.authority.bound.get() {
            return Err(Error::NotReady);
        }
        Ok(())
    }
    /// Pin this actual ledger source to one original frontier writer allocation.
    /// The process persists its min0 initialization intent before ledger creation;
    /// the subsequent Unbound pairing cannot reset a Bound catalog or previously
    /// burned signed time. `owner` is uniqueness, not a receipt.
    pub fn claim_frontier(&self, owner: &Arc<()>, missing: bool) -> Result<(), Error> {
        self.validate_binding()?;
        if missing && self.authority.bound.get() {
            return Err(Error::Authentication);
        }
        let mut current = self
            .authority
            .frontier
            .try_borrow_mut()
            .map_err(|_| Error::Conflict)?;
        match &*current {
            Some(original) if !Arc::ptr_eq(original, owner) => Err(Error::Conflict),
            Some(_) => Ok(()),
            None => {
                *current = Some(owner.clone());
                Ok(())
            }
        }
    }
    /// Actual persisted installation identity.
    #[must_use]
    pub fn identity(&self) -> LedgerId {
        self.authority.id
    }
    /// Original fixed local identity.
    #[must_use]
    pub fn local(&self) -> EddsaPublicKey {
        self.authority.local
    }
    /// Actual persisted phase of this original initialized source.
    #[must_use]
    pub fn is_bound(&self) -> bool {
        self.authority.bound.get()
    }
    /// Current actually committed generation, never a queued generation.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.authority.generation.get()
    }
    /// Original source comparison, independent of matching printable IDs.
    #[must_use]
    pub fn owns(&self, floor: &Floor) -> bool {
        Rc::ptr_eq(&self.authority, &floor.authority)
    }
}
impl fmt::Debug for CatalogLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CatalogLease")
            .field("identity", &self.identity())
            .field("local", &self.local())
            .field("generation", &self.generation())
            .finish()
    }
}
/// An already durable equal value needs no replacement write; a higher verified
/// value waits for the exact original Worker job and generation receipt.
#[derive(Debug)]
pub enum Submission {
    /// Actual same original loaded/committed local value.
    Known(Floor),
    /// Admitted original worker job; not persistence or a remote STORE ACK.
    Queued(Token),
}
struct Pending {
    token: Token,
    job: Job,
    expected: u64,
    change: Option<Record>,
    bind: bool,
    cancelled: bool,
}
/// Actual original worker outcome. Cancellation does not cancel filesystem IO:
/// a committed canceled change still advances the catalog but gives no grant.
#[derive(Debug)]
pub enum Progress {
    /// Real initialization commit, making a complete empty catalog available.
    Initialized(Token),
    /// Actual Bound commit after the original public frontier durability barrier.
    Bound(Token),
    /// Actual original floor publication and private receipt.
    Persisted(Floor),
    /// Original job settled after cancellation/close; no new business grant.
    Retired {
        /// Original operation.
        token: Token,
        /// Actual definitely committed generation.
        generation: u64,
    },
    /// Original admitted IO or ownership failure, with the exact original token.
    Failed {
        /// Some for an actual pending operation; None for worker-domain loss.
        token: Option<Token>,
        /// Original actual cause, independently retained.
        error: Arc<Failure>,
    },
    /// Actual result channel ended. Thread join is still required.
    Drained,
}
/// Constructor rejection preserves a live original worker owner when one had
/// really started; its caller can perform explicit drain/join instead of treating
/// Drop or failed admission as quiescence.
pub struct OpenRejected {
    /// Actual original failure.
    pub error: Failure,
    /// Original worker owner, if the thread had started.
    pub owner: Option<Box<Ledger>>,
}
impl fmt::Debug for OpenRejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenRejected")
            .field("error", &self.error)
            .field("has_owner", &self.owner.is_some())
            .finish()
    }
}
impl fmt::Display for OpenRejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}
impl std::error::Error for OpenRejected {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}
impl From<Failure> for OpenRejected {
    fn from(error: Failure) -> Self {
        Self { error, owner: None }
    }
}
/// Actual thread-join result and independently retained earlier business/storage
/// failure. A failed join or unknown publication grants no recovery/clean proof.
#[derive(Debug)]
pub struct Shutdown {
    /// Actual original joined thread report, only on successful join.
    pub stopped: Option<Stopped>,
    /// First original ledger fault, if any.
    pub original: Option<Arc<Failure>>,
    /// Actual independent join failure.
    pub join: Option<Error>,
}
/// One fixed catalog and one physical shared snapshot worker. Only raw owned
/// zeroizing image bytes cross the thread; public proof/operation brands stay
/// on the reactor, without Atomic64 or per-peer worker allocation.
pub struct Ledger {
    authority: Rc<Authority>,
    domain: Rc<()>,
    next: u64,
    records: Vec<Record>,
    maximum: usize,
    worker: Option<Worker>,
    pending: Option<Pending>,
    initialized: bool,
    closing: bool,
    ended: bool,
    first: Option<Arc<Failure>>,
}
impl Ledger {
    /// Open only an explicitly selected qualified Rust directory. Existing empty
    /// marked directories without an image are refused, not initialized anew.
    /// A brand-new directory's random public identity is returned as authority
    /// only after its real initialization job commits. No old C store is read.
    pub fn open(
        directory: impl AsRef<Path>,
        local: EddsaPublicKey,
        limits: Limits,
        frontier: &Path,
    ) -> Result<Self, OpenRejected> {
        let maximum = format::maximum(limits.records).map_err(|e| fault("limits", e, false))?;
        // Actual original min0 intent is durable before any ledger marker or
        // directory can be created. It proves pre-Unbound bootstrap, unlike
        // created_this_process or a missing canonical image by itself.
        let intent = pairing::inspect(frontier).map_err(|error| Failure {
            stage: "frontier-intent",
            uncertain: false,
            cause: Cause::Io(error),
        })?;
        if intent.local != local {
            return Err(fault("frontier-local", Error::Authentication, false).into());
        }
        let (store, loaded) = Store::open(
            NAMESPACE,
            directory,
            backend::Limits {
                body_bytes: maximum,
            },
        )
        .map_err(|e| storage("open", Arc::new(e)))?;
        let generation = loaded.generation();
        if loaded.namespace() != NAMESPACE {
            return Err(fault("namespace", Error::Authentication, false).into());
        }
        let body = loaded.into_body();
        let (id, records, bound, initialize) = if generation == 0 {
            if intent.minimum != 0 || intent.dirty || intent.reserved != 0 || !body.is_empty() {
                return Err(fault("missing-initialization", Error::Authentication, false).into());
            }
            let id = intent.ledger;
            let mut records = Vec::new();
            records
                .try_reserve_exact(limits.records)
                .map_err(|_| fault("catalog-capacity", Error::Capacity, false))?;
            let id = LedgerId(id);
            let body = format::encode(id, local, &records, None, false)
                .map_err(|e| fault("initialize-image", e, false))?;
            (id, records, false, Some(body))
        } else {
            let (id, records, bound) = format::decode(&body, generation, local, limits.records)
                .map_err(|e| fault("complete-catalog", e, false))?;
            (id, records, bound, None)
        };
        if id.0 != intent.ledger
            || generation < intent.minimum
            || (bound && intent.minimum == 0)
            || (!bound && (intent.dirty || intent.reserved != 0 || intent.minimum > 1))
        {
            return Err(fault("frontier-catalog-binding", Error::Authentication, false).into());
        }
        drop(body);
        let worker = Worker::start(store).map_err(|e| Failure {
            stage: "worker-start",
            uncertain: false,
            cause: Cause::Io(e),
        })?;
        let mut ledger = Self {
            authority: Rc::new(Authority {
                id,
                local,
                generation: Cell::new(generation),
                ready: Cell::new(generation != 0),
                pending: Cell::new(false),
                bound: Cell::new(bound),
                frontier: RefCell::new(None),
            }),
            domain: Rc::new(()),
            next: 0,
            records,
            maximum: limits.records,
            worker: Some(worker),
            pending: None,
            initialized: generation != 0,
            closing: false,
            ended: false,
            first: None,
        };
        if let Some(body) = initialize {
            let result = ledger
                .worker
                .as_mut()
                .ok_or(Error::Closed)
                .and_then(|worker| worker.submit(0, body).map_err(|(error, _)| error));
            match result {
                Ok(job) => {
                    let token = Token {
                        domain: ledger.domain.clone(),
                        serial: 1,
                    };
                    ledger.next = 1;
                    ledger.authority.pending.set(true);
                    ledger.pending = Some(Pending {
                        token,
                        job,
                        expected: 1,
                        change: None,
                        bind: false,
                        cancelled: false,
                    });
                }
                Err(error) => {
                    ledger.begin_close();
                    return Err(OpenRejected {
                        error: fault("initial-admission", error, false),
                        owner: Some(Box::new(ledger)),
                    });
                }
            }
        }
        Ok(ledger)
    }
    fn find(&self, peer: EddsaPublicKey, kind: ReplayKind) -> Result<usize, usize> {
        self.records.binary_search_by(|value| {
            format::compare(
                value,
                &Record {
                    peer,
                    kind,
                    stamp: 0,
                },
            )
        })
    }
    fn check_catalog(&self) -> Result<(), Error> {
        if self.first.is_some() {
            return Err(Error::OutcomeUnknown);
        }
        if self.closing {
            return Err(Error::Closed);
        }
        // Fresh initialization already owns its original worker job but grants
        // no catalog until that actual completion has been consumed.
        if !self.initialized || self.pending.is_some() {
            return Err(Error::WouldBlock);
        }
        if !self.authority.ready.get() {
            return Err(Error::Closed);
        }
        Ok(())
    }
    /// Borrow only this complete actually loaded/committed catalog, with no IO.
    pub fn catalog(&self) -> Result<Catalog<'_>, Error> {
        self.check_catalog()?;
        Ok(Catalog { ledger: self })
    }
    /// Exact current pending operation, including initialization, without minting
    /// a successful floor or revealing the worker's private domain.
    #[must_use]
    pub fn pending(&self) -> Option<&Token> {
        self.pending.as_ref().map(|p| &p.token)
    }
    /// Borrow the first retained original failure; taking events never clears it.
    #[must_use]
    pub fn failure(&self) -> Option<&Arc<Failure>> {
        self.first.as_ref()
    }
    fn floor_receipt(&self, token: Token, record: Record, generation: u64) -> Floor {
        Floor {
            authority: self.authority.clone(),
            token,
            peer: record.peer,
            kind: record.kind,
            stamp: record.stamp,
            generation,
        }
    }
    /// Complete cross-crash initialization without resetting prior history.
    /// Only an actual empty Unbound catalog may use this path. The exact89B
    /// same-ID/local/frontier is really read, file+directory-synced and checked
    /// before a Bound snapshot job is admitted. Actual Bound completion, not
    /// this return value, enables signatures/floors or external PS effects.
    pub fn bind_frontier(&mut self, path: &Path) -> Result<Token, Failure> {
        self.check_catalog()
            .map_err(|e| fault("pair-catalog", e, false))?;
        if self.authority.bound.get()
            || !self.records.is_empty()
            || self
                .authority
                .frontier
                .try_borrow()
                .map_err(|_| fault("pair-frontier-borrow", Error::Conflict, false))?
                .is_none()
        {
            return Err(fault("pair-phase", Error::Conflict, false));
        }
        let generation = self.authority.generation.get();
        let expected = generation
            .checked_add(1)
            .ok_or_else(|| fault("pair-generation", Error::Overflow, false))?;
        let serial = self
            .next
            .checked_add(1)
            .ok_or_else(|| fault("pair-token", Error::Overflow, false))?;
        let body = format::encode(
            self.authority.id,
            self.authority.local,
            &self.records,
            None,
            true,
        )
        .map_err(|e| fault("pair-image", e, false))?;
        pairing::barrier(path, self.authority.id.0, self.authority.local, generation).map_err(
            |e| Failure {
                stage: "pair-frontier-barrier",
                uncertain: false,
                cause: Cause::Io(e),
            },
        )?;
        let job = self
            .worker
            .as_mut()
            .ok_or_else(|| fault("pair-worker", Error::Closed, false))?
            .submit(generation, body)
            .map_err(|(error, _)| fault("pair-admission", error, false))?;
        let token = Token {
            domain: self.domain.clone(),
            serial,
        };
        self.next = serial;
        self.authority.pending.set(true);
        self.pending = Some(Pending {
            token: token.clone(),
            job,
            expected,
            change: None,
            bind: true,
            cancelled: false,
        });
        Ok(token)
    }
    /// Submit the exact timestamp from an already signature-checked original
    /// Session replay effect. This does not verify arbitrary caller metadata.
    /// Less-than-local-floor is refused; equal remains valid as in official C.
    /// No catalog mutation occurs on capacity/encode/worker admission refusal.
    pub fn submit(
        &mut self,
        peer: EddsaPublicKey,
        kind: ReplayKind,
        stamp: u64,
    ) -> Result<Submission, Error> {
        self.check_catalog()?;
        if !self.authority.bound.get()
            || self
                .authority
                .frontier
                .try_borrow()
                .map_err(|_| Error::Conflict)?
                .is_none()
        {
            return Err(Error::NotReady);
        }
        let position = self.find(peer, kind);
        if let Ok(index) = position
            && self.records[index].stamp > stamp
        {
            return Err(Error::Stale);
        }
        if position.is_err() && self.records.len() == self.maximum {
            return Err(Error::Capacity);
        }
        let serial = self.next.checked_add(1).ok_or(Error::Overflow)?;
        let token = Token {
            domain: self.domain.clone(),
            serial,
        };
        if let Ok(index) = position
            && self.records[index].stamp == stamp
        {
            self.next = serial;
            return Ok(Submission::Known(self.floor_receipt(
                token,
                self.records[index],
                self.authority.generation.get(),
            )));
        }
        let record = Record { peer, kind, stamp };
        let generation = self.authority.generation.get();
        let expected = generation.checked_add(1).ok_or(Error::Overflow)?;
        let body = format::encode(
            self.authority.id,
            self.authority.local,
            &self.records,
            Some(record),
            true,
        )?;
        let job = self
            .worker
            .as_mut()
            .ok_or(Error::Closed)?
            .submit(generation, body)
            .map_err(|(error, _)| error)?;
        self.next = serial;
        self.authority.pending.set(true);
        self.pending = Some(Pending {
            token: token.clone(),
            job,
            expected,
            change: Some(record),
            bind: false,
            cancelled: false,
        });
        Ok(Submission::Queued(token))
    }
    /// Retire business permission only. Original admitted filesystem debt remains
    /// owned until its real completion and still updates the durable catalog.
    pub fn cancel(&mut self, token: &Token) -> Result<bool, Error> {
        let p = self
            .pending
            .as_mut()
            .filter(|p| p.token == *token)
            .ok_or(Error::Stale)?;
        let changed = !p.cancelled;
        p.cancelled = true;
        Ok(changed)
    }
    fn failed(&mut self, token: Option<Token>, error: Failure) -> Progress {
        self.authority.ready.set(false);
        self.closing = true;
        if let Some(worker) = &mut self.worker {
            worker.request_stop();
        }
        let error = Arc::new(error);
        if self.first.is_none() {
            self.first = Some(error.clone());
        }
        Progress::Failed { token, error }
    }
    /// Consume only original actual Worker completions. Future cancellation
    /// leaves the private job and physical publication debt unchanged.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Progress> {
        if self.ended {
            return Poll::Pending;
        }
        let result = match self.worker.as_mut() {
            Some(worker) => worker.poll(cx),
            None => return Poll::Pending,
        };
        let completion = match result {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => {
                let token = self.pending.take().map(|p| p.token);
                return Poll::Ready(self.failed(token, fault("worker-poll", error, true)));
            }
            Poll::Ready(Ok(None)) => {
                self.ended = true;
                self.begin_close();
                if let Some(p) = self.pending.take() {
                    return Poll::Ready(self.failed(
                        Some(p.token),
                        fault("worker-ended-with-debt", Error::OutcomeUnknown, true),
                    ));
                }
                return Poll::Ready(Progress::Drained);
            }
            Poll::Ready(Ok(Some(completion))) => completion,
        };
        let Some(pending) = self.pending.take() else {
            return Poll::Ready(
                self.failed(None, fault("unexpected-completion", Error::Stale, true)),
            );
        };
        self.authority.pending.set(false);
        let (job, result) = completion.into_parts();
        if job != pending.job || job.namespace() != NAMESPACE {
            return Poll::Ready(self.failed(
                Some(pending.token),
                fault("original-job", Error::Stale, true),
            ));
        }
        let committed = match result {
            Ok(committed) => committed,
            Err(error) => {
                return Poll::Ready(
                    self.failed(Some(pending.token), storage("publication", error)),
                );
            }
        };
        if committed.namespace() != NAMESPACE || committed.generation() != pending.expected {
            return Poll::Ready(self.failed(
                Some(pending.token),
                fault("original-generation", Error::Stale, true),
            ));
        }
        if let Some(record) = pending.change {
            match self.find(record.peer, record.kind) {
                Ok(i) => self.records[i] = record,
                Err(i) => self.records.insert(i, record),
            }
        }
        if pending.bind {
            self.authority.bound.set(true);
        }
        self.initialized = true;
        self.authority.generation.set(committed.generation());
        if self.closing || pending.cancelled {
            return Poll::Ready(Progress::Retired {
                token: pending.token,
                generation: committed.generation(),
            });
        }
        self.authority.ready.set(true);
        Poll::Ready(match pending.change {
            Some(record) => Progress::Persisted(self.floor_receipt(
                pending.token,
                record,
                committed.generation(),
            )),
            None if pending.bind => Progress::Bound(pending.token),
            None => Progress::Initialized(pending.token),
        })
    }
    /// Refuse new authority without clock sampling, preserving original IO debt.
    pub fn begin_close(&mut self) {
        self.closing = true;
        self.authority.ready.set(false);
        if let Some(p) = &mut self.pending {
            p.cancelled = true;
        }
        if let Some(worker) = &mut self.worker {
            worker.request_stop();
        }
    }
    /// Result-channel termination alone is not an actual joined-thread receipt.
    #[must_use]
    pub const fn is_drained(&self) -> bool {
        self.ended
    }
    /// Poll actual original thread join after real channel termination.
    pub fn poll_join(&mut self, cx: &mut Context<'_>) -> Poll<Result<Stopped, Error>> {
        if !self.ended {
            return Poll::Ready(Err(Error::WouldBlock));
        }
        let result = match &mut self.worker {
            Some(worker) => worker.poll_join(cx),
            None => return Poll::Ready(Err(Error::Stale)),
        };
        if matches!(&result, Poll::Ready(Ok(_) | Err(Error::OutcomeUnknown))) {
            self.worker = None;
        }
        result
    }
    /// Explicit stop, drain every original outcome, then join. Filesystem IO is
    /// not canceled by a socket deadline and queued never means committed.
    pub async fn shutdown(&mut self, mut observe: impl FnMut(Progress)) -> Shutdown {
        self.begin_close();
        while !self.ended {
            let event = std::future::poll_fn(|cx| self.poll(cx)).await;
            observe(event);
        }
        let joined = std::future::poll_fn(|cx| self.poll_join(cx)).await;
        match joined {
            Ok(stopped) => Shutdown {
                stopped: Some(stopped),
                original: self.first.clone(),
                join: None,
            },
            Err(error) => Shutdown {
                stopped: None,
                original: self.first.clone(),
                join: Some(error),
            },
        }
    }
}
impl Drop for Ledger {
    fn drop(&mut self) {
        self.authority.ready.set(false);
        if let Some(worker) = &mut self.worker {
            worker.request_stop();
        }
    }
}
