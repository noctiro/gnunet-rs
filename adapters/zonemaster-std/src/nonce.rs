//! Durable per-official-storage-key expiration allocation before any sealing.
//! No secret or record body is stored here. This is a private local namespace,
//! not a GNUnet protocol, a key import format, or proof of unknown prior history.
use gnunet_snapshot_host::backend::{Committed, Limits as StoreLimits, Namespace, Store};
use gnunet_types::Error as Fault;
use gnunet_zonemaster::material::{ExpirationRequest, Expirations};
use std::{
    error::Error,
    fmt, fs, io,
    path::PathBuf,
    sync::{
        Arc, Mutex, OnceLock, TryLockError,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};
use tokio::time::Instant;
use zeroize::Zeroizing;
const MAGIC: &[u8; 8] = b"GNSNON01";
const HEADER: usize = 12;
const ROW: usize = 72;
const STORE_MAX: usize = 64 * 1024 * 1024;

/// Explicit shared persistent namespace and lifetime-history bound. Construction
/// performs no IO; the ordinary worker opens this selected directory only after
/// UID/PROGRAM setup and actual source/job admission.
#[derive(Clone, Debug)]
pub struct Config {
    directory: PathBuf,
    keys: usize,
    body_bytes: usize,
}
impl Config {
    /// Select an absolute namespace. All cooperating publishers for a zone must
    /// retain and select the same ledger; copying a key to an unrelated namespace
    /// does not prove that its prior nonce history is known.
    pub fn new(directory: PathBuf, maximum_keys: usize) -> Result<Self, Fault> {
        let body_bytes = maximum_keys
            .checked_mul(ROW)
            .and_then(|n| n.checked_add(HEADER))
            .ok_or(Fault::Overflow)?;
        if !directory.is_absolute() || maximum_keys == 0 || body_bytes > STORE_MAX {
            return Err(Fault::InvalidInput);
        }
        Ok(Self {
            directory,
            keys: maximum_keys,
            body_bytes,
        })
    }
}

/// Original allocation failure, without a printable storage key or body.
#[derive(Debug)]
pub struct Failure {
    stage: &'static str,
    reason: Fault,
    original: Option<Box<dyn Error + Send + Sync>>,
}
impl Failure {
    fn state(stage: &'static str, reason: Fault) -> Self {
        Self {
            stage,
            reason,
            original: None,
        }
    }
    fn io(stage: &'static str, error: io::Error) -> Self {
        Self {
            stage,
            reason: Fault::Storage,
            original: Some(Box::new(error)),
        }
    }
    fn store(error: impl Into<Arc<gnunet_snapshot_host::backend::Failure>>) -> Self {
        let error = error.into();
        Self {
            stage: "qualified-store",
            reason: error.reason,
            original: Some(Box::new(error)),
        }
    }
    fn interrupted(reason: Fault, waiting: Option<Arc<Self>>) -> Arc<Self> {
        Arc::new(Self {
            stage: "original-reservation-wait",
            reason,
            original: waiting.map(|e| Box::new(e) as Box<dyn Error + Send + Sync>),
        })
    }
    /// Pure classification only; the original native cause remains in this value.
    #[must_use]
    pub const fn reason(&self) -> Fault {
        self.reason
    }
    pub(crate) fn has_original(&self) -> bool {
        self.original.is_some()
    }
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GNS expiration authority {}: {:?}",
            self.stage, self.reason
        )?;
        if let Some(error) = &self.original {
            write!(f, "; original: {error}")?;
        }
        Ok(())
    }
}
impl Error for Failure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original.as_ref().map(|e| e.as_ref() as &dyn Error)
    }
}
/// Actual successful local allocation transaction. Cloning this observation does
/// not mint an assignment or authorize another seal, submission or remote ACK.
#[derive(Clone, Copy, Debug)]
pub struct Receipt {
    committed: Committed,
    allocations: u8,
}
impl Receipt {
    /// Actual synchronized/read-back namespace generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.committed.generation()
    }
    /// Distinct nonce values irrevocably reserved by this original transaction.
    #[must_use]
    pub const fn allocations(self) -> u8 {
        self.allocations
    }
}
pub(crate) struct Granted {
    pub(crate) expirations: Expirations,
    pub(crate) receipt: Receipt,
}

/// One process's bounded coordination, with no cached ledger image or ranges.
/// The concrete snapshot lease serializes every cooperating process; the local
/// try-lock avoids redundant concurrent full-image loads in this same pool.
pub(crate) struct Authority {
    config: Config,
    serial: Mutex<()>,
    failure: OnceLock<Arc<Failure>>,
    observed: AtomicBool,
    latest: Mutex<Option<Receipt>>,
}
impl Authority {
    pub(crate) fn new(config: Config) -> Self {
        Self {
            config,
            serial: Mutex::new(()),
            failure: OnceLock::new(),
            observed: AtomicBool::new(false),
            latest: Mutex::new(None),
        }
    }
    fn fence(&self, error: Failure) -> Arc<Failure> {
        let error = Arc::new(error);
        let _first = self.failure.set(error.clone());
        self.failure.get().cloned().unwrap_or(error)
    }
    pub(crate) fn panicked(&self) -> Arc<Failure> {
        // A different worker may already have fenced an independent IO failure.
        // Keep this actual panic as its own cause, while still fencing new work.
        let error = Arc::new(Failure::state(
            "sealing-worker-panicked",
            Fault::OutcomeUnknown,
        ));
        let _first = self.failure.set(error.clone());
        error
    }
    pub(crate) fn failure(&self) -> Option<Arc<Failure>> {
        self.failure.get().cloned()
    }
    pub(crate) fn observe_failure(&self, error: &Arc<Failure>) -> bool {
        if self
            .failure
            .get()
            .is_some_and(|first| Arc::ptr_eq(first, error))
        {
            !self.observed.swap(true, Ordering::AcqRel)
        } else {
            true
        }
    }
    /// First original fenced error survives closure of the completion channel.
    pub(crate) fn take_failure(&self) -> Option<Arc<Failure>> {
        let error = self.failure.get()?;
        (!self.observed.swap(true, Ordering::AcqRel)).then(|| error.clone())
    }
    /// Only metadata, never a retained counter body. Called after actual joins.
    pub(crate) fn take_latest(&self) -> Option<Receipt> {
        match self.latest.lock() {
            Ok(mut latest) => latest.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        }
    }
    fn interruption(stop: &AtomicBool, cancel: &AtomicBool, hard: Instant) -> Option<Fault> {
        if stop.load(Ordering::Acquire) || cancel.load(Ordering::Acquire) {
            Some(Fault::Cancelled)
        } else if Instant::now() >= hard {
            Some(Fault::Deadline)
        } else {
            None
        }
    }
    pub(crate) fn reserve(
        &self,
        request: ExpirationRequest,
        stop: &AtomicBool,
        cancel: &AtomicBool,
        hard: Instant,
    ) -> Result<Granted, Arc<Failure>> {
        // Complete all predictable first-image admission before creating the
        // final namespace. A normal cancellation after fresh open must finish
        // that first durable image rather than leave a marked/missing store.
        let first = request
            .after(None)
            .map_err(|e| Arc::new(Failure::state("assignment", e)))?;
        let mut fresh = Zeroizing::new(Vec::new());
        fresh
            .try_reserve_exact(HEADER + ROW)
            .map_err(|_| Arc::new(Failure::state("first-body-allocation", Fault::Capacity)))?;
        fresh.extend_from_slice(MAGIC);
        fresh.extend_from_slice(&1u32.to_be_bytes());
        fresh.extend_from_slice(request.storage_key());
        fresh.extend_from_slice(&first.maximum().to_be_bytes());
        let mut waiting = None;
        loop {
            if let Some(error) = self.failure.get() {
                return Err(error.clone());
            }
            if let Some(reason) = Self::interruption(stop, cancel, hard) {
                return Err(Failure::interrupted(reason, waiting));
            }
            let guard = match self.serial.try_lock() {
                Ok(guard) => guard,
                Err(TryLockError::WouldBlock) => {
                    thread::sleep(Duration::from_millis(2));
                    continue;
                }
                Err(TryLockError::Poisoned(_)) => {
                    return Err(self.fence(Failure::state("allocation-owner-poisoned", Fault::Io)));
                }
            };
            if let Some(error) = self.failure.get() {
                return Err(error.clone());
            }
            if let Some(reason) = Self::interruption(stop, cancel, hard) {
                return Err(Failure::interrupted(reason, waiting));
            }
            let parent =
                self.config.directory.parent().ok_or_else(|| {
                    Arc::new(Failure::state("namespace-parent", Fault::InvalidInput))
                })?;
            fs::create_dir_all(parent)
                .map_err(|e| self.fence(Failure::io("create-selected-parent", e)))?;
            if let Some(reason) = Self::interruption(stop, cancel, hard) {
                return Err(Failure::interrupted(reason, waiting));
            }
            let opened = Store::open(
                Namespace::GnsPublication,
                &self.config.directory,
                StoreLimits {
                    body_bytes: self.config.body_bytes,
                },
            );
            let (mut store, loaded) = match opened {
                Ok(opened) => opened,
                Err(error)
                    if (error.stage == "writer-lock" && error.reason == Fault::Conflict)
                        || (error.stage == "initialization-pending"
                            && error.reason == Fault::NotReady) =>
                {
                    if waiting.is_none() {
                        waiting = Some(Arc::new(Failure::store(error)));
                    }
                    drop(guard);
                    thread::sleep(Duration::from_millis(2));
                    continue;
                }
                Err(error) => return Err(self.fence(Failure::store(error))),
            };
            if loaded.namespace() != Namespace::GnsPublication
                || store.namespace() != Namespace::GnsPublication
            {
                return Err(self.fence(Failure::state("namespace", Fault::Authentication)));
            }
            let generation = loaded.generation();
            let created = loaded.created_directory();
            let mut body = loaded.into_body();
            let assigned = if generation == 0 {
                if !created || !body.is_empty() {
                    return Err(self.fence(Failure::state(
                        "marked-canonical-image-required",
                        Fault::Storage,
                    )));
                }
                body = fresh;
                first
            } else {
                let count = inspect(&body, self.config.keys)
                    .map_err(|e| self.fence(Failure::state("canonical-body", e)))?;
                let (at, previous) = find(&body, count, request.storage_key());
                let assigned = request
                    .after(previous)
                    .map_err(|e| Arc::new(Failure::state("assignment-exhausted", e)))?;
                let offset = HEADER + at * ROW;
                if previous.is_none() {
                    if count == self.config.keys {
                        return Err(Arc::new(Failure::state(
                            "lifetime-key-history-full",
                            Fault::Capacity,
                        )));
                    }
                    body.try_reserve_exact(ROW)
                        .map_err(|_| Arc::new(Failure::state("body-growth", Fault::Capacity)))?;
                    let old = body.len();
                    body.resize(old + ROW, 0);
                    body.copy_within(offset..old, offset + ROW);
                    body[offset..offset + 64].copy_from_slice(request.storage_key());
                    let next = u32::try_from(count + 1)
                        .map_err(|_| Arc::new(Failure::state("body-count", Fault::Capacity)))?;
                    body[8..12].copy_from_slice(&next.to_be_bytes());
                }
                body[offset + 64..offset + ROW].copy_from_slice(&assigned.maximum().to_be_bytes());
                assigned
            };
            // Open admitted this non-recoverable local reservation transaction.
            // No cancel/hard check splits fresh initialization from its commit.
            // Any kernel IO may block; afterward the worker still refuses seal
            // if its original interest/target ended. Consumed values never return.
            let committed = store
                .commit(generation, body)
                .map_err(|e| self.fence(Failure::store(e)))?;
            if committed.namespace() != Namespace::GnsPublication
                || committed.generation() != store.generation()
            {
                return Err(self.fence(Failure::state("commit-binding", Fault::Stale)));
            }
            let receipt = Receipt {
                committed,
                allocations: assigned.allocations(),
            };
            match self.latest.lock() {
                Ok(mut latest) => *latest = Some(receipt),
                Err(poisoned) => *poisoned.into_inner() = Some(receipt),
            }
            drop(store);
            drop(guard);
            return Ok(Granted {
                expirations: assigned,
                receipt,
            });
        }
    }
}
fn inspect(body: &[u8], maximum: usize) -> Result<usize, Fault> {
    if body.len() < HEADER || &body[..8] != MAGIC {
        return Err(Fault::Storage);
    }
    let count = u32::from_be_bytes(body[8..12].try_into().map_err(|_| Fault::Storage)?) as usize;
    let length = count
        .checked_mul(ROW)
        .and_then(|n| n.checked_add(HEADER))
        .ok_or(Fault::Overflow)?;
    if count == 0 || count > maximum || length != body.len() {
        return Err(Fault::Storage);
    }
    let mut previous: Option<&[u8]> = None;
    for row in body[HEADER..].as_chunks::<ROW>().0 {
        let key = &row[..64];
        if previous.is_some_and(|old| old >= key) {
            return Err(Fault::Storage);
        }
        previous = Some(key);
    }
    Ok(count)
}
fn find(body: &[u8], count: usize, key: &[u8; 64]) -> (usize, Option<u64>) {
    let mut low = 0;
    let mut high = count;
    while low < high {
        let middle = low + (high - low) / 2;
        let offset = HEADER + middle * ROW;
        match body[offset..offset + 64].cmp(key.as_slice()) {
            std::cmp::Ordering::Less => low = middle + 1,
            std::cmp::Ordering::Greater => high = middle,
            std::cmp::Ordering::Equal => {
                let mut raw = [0; 8];
                raw.copy_from_slice(&body[offset + 64..offset + ROW]);
                return (middle, Some(u64::from_be_bytes(raw)));
            }
        }
    }
    (low, None)
}
