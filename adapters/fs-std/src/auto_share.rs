//! Directory-change driven automatic indexed FS publication.
//! Observation, immutable preparation, actual service receipts and durable local
//! bookkeeping are separate facts. This module never spawns gnunet-publish or
//! adopts the C .auto-share file. The caller owns the real Resolver and clock.
mod catalog;
mod runner;
mod scan;
mod worker;
use crate::{durable::store, publication};
use gnunet_types::Error as Protocol;
pub use runner::{Owner, PublicationFailure, RunFailure, RunReport};
pub use scan::{ScanError, ScanLimits};
use std::{
    fmt,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
/// Exact caller-selected publication policy. These values reach official PUTs.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// Official -a: default sender anonymity1.
    pub anonymity: u32,
    /// Official -p: default priority365.
    pub priority: u32,
    /// Official -r: default replication1.
    pub replication: u32,
    /// Official -D genuinely disables format extraction and automatic keywords.
    pub disable_extractor: bool,
    /// Official -d genuinely disables creation-time metadata.
    pub disable_creation_time: bool,
    /// None uses official UTC year+2 Jan1; an explicit relative caller policy
    /// still fixes its absolute result once for this original prepared version.
    pub content_lifetime: Option<Duration>,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            anonymity: 1,
            priority: 365,
            replication: 1,
            disable_extractor: false,
            disable_creation_time: false,
            content_lifetime: None,
        }
    }
}
/// Explicit finite resource profile, independent of GNUnet protocol sizes.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Source enumeration and retained raw-name budgets.
    pub scan: ScanLimits,
    /// Maximum remembered top-level items, including deleted historical names.
    pub entries: usize,
    /// Total version/task groups. Exhaustion is visible, never silently discarded.
    pub versions: usize,
    /// A stat tree must remain equal for this native duration before preparation.
    pub stability: Duration,
    /// Official minimum scan spacing (C macro is one minute, despite its comment).
    pub minimum_scan: Duration,
    /// Maximum adaptive scan spacing, default four hours.
    pub maximum_scan: Duration,
    /// Known-safe partial/refused work retries after this duration, never Unknown.
    pub retry: Duration,
    /// One original group run target, shared by content and every keyword task.
    pub operation: Duration,
    /// Finite overall foreground allocation lifetime.
    pub lifetime: Duration,
    /// Aggregate reserved logical owned-file bytes; not physical filesystem blocks.
    pub retained_bytes: u64,
    /// Logical bytes reserved before one version preparation can write any file.
    pub version_reservation: u64,
    /// Original catalog WAL bounds; current publication tasks have separate limits.
    pub catalog: store::Limits,
    /// Maximum retained typed last-failure owners for distinct versions.
    pub failures: usize,
    /// Actual bounded metadata/extraction/KSK preparation policy. UTC/extract flags
    /// are overwritten from this original operation's Options and source sample.
    pub preparation: publication::auto_prepare::Policy,
    /// Existing real immutable publication task/payload bounds.
    pub publication: publication::Limits,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            scan: ScanLimits::default(),
            entries: 1024,
            versions: 4096,
            stability: Duration::from_secs(2),
            minimum_scan: Duration::from_secs(60),
            maximum_scan: Duration::from_secs(4 * 60 * 60),
            retry: Duration::from_secs(60),
            operation: Duration::from_secs(300),
            lifetime: Duration::from_secs(24 * 60 * 60),
            retained_bytes: 64 * 1024 * 1024 * 1024,
            version_reservation: 8 * 1024 * 1024 * 1024,
            catalog: store::Limits {
                max_records: 65536,
                max_body_bytes: 256 * 1024,
                max_file_bytes: 64 * 1024 * 1024,
                max_scratch_bytes: 256 * 1024 + 160,
                ..store::Limits::default()
            },
            failures: 64,
            preparation: publication::auto_prepare::Policy::default(),
            publication: publication_limits(),
        }
    }
}
fn publication_limits() -> publication::Limits {
    let mut limits = publication::Limits::default();
    limits.storage.max_file_bytes = 16 * 1024 * 1024;
    limits.plan.max_stored_bytes = 512 * 1024 * 1024;
    limits.plan.file.max_file_bytes = 256 * 1024 * 1024;
    limits.plan.file.max_encoded_bytes = 512 * 1024 * 1024;
    limits
}
impl Limits {
    pub(crate) fn validate(self) -> Result<(), Error> {
        self.scan.validate()?;
        if self.failures == 0
            || self.failures > 4096
            || self.entries == 0
            || self.entries > 65536
            || self.versions == 0
            || self.versions > 1_000_000
            || self.version_reservation == 0
            || self.version_reservation > self.retained_bytes
        {
            return Err(Error::Protocol(Protocol::InvalidInput));
        }
        for d in [
            self.stability,
            self.minimum_scan,
            self.maximum_scan,
            self.retry,
            self.operation,
            self.lifetime,
        ] {
            if d.is_zero()
                || d.as_micros() > u64::MAX as u128
                || tokio::time::Instant::now().checked_add(d).is_none()
            {
                return Err(Error::Protocol(Protocol::InvalidInput));
            }
        }
        self.preparation
            .validate(self.publication)
            .map_err(Error::Preparation)?;
        if self.minimum_scan > self.maximum_scan {
            return Err(Error::Protocol(Protocol::InvalidInput));
        }
        Ok(())
    }
}
/// Explicit stop request, shared only with this original owner/worker. A stopped
/// allocation never resumes; a later owner must reopen and recheck its journals.
#[derive(Default)]
struct StopState {
    requested: AtomicBool,
    waker: Mutex<Option<std::task::Waker>>,
}
#[derive(Clone, Default)]
/// Shared stop request for this original coordinator and its preparation worker.
pub struct Stop(Arc<StopState>);
impl Stop {
    /// Request pause and physical native retirement, not rollback or cancellation ACK.
    pub fn request(&self) {
        self.0.requested.store(true, Ordering::Release);
        let wake = self
            .0
            .waker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(w) = wake {
            w.wake()
        }
    }
    /// Current original caller stop intent.
    pub fn requested(&self) -> bool {
        self.0.requested.load(Ordering::Acquire)
    }
    pub(crate) fn register(&self, cx: &std::task::Context<'_>) {
        if self.requested() {
            return;
        }
        let mut slot = self
            .0
            .waker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot.as_ref().is_none_or(|w| !w.will_wake(cx.waker())) {
            *slot = Some(cx.waker().clone())
        }
        if self.requested() {
            let wake = slot.take();
            drop(slot);
            if let Some(w) = wake {
                w.wake()
            }
        }
    }
}
/// Actual local/native preparation/catalog cause. No watched path is a peer ID.
#[derive(Debug)]
pub enum Error {
    /// Bounded source enumeration or a genuinely changed source.
    Scan(ScanError),
    /// Original marked catalog or task storage refusal, including certainty.
    Storage(store::Error),
    /// Exact native filesystem/thread/channel error.
    Io(std::io::Error),
    /// Existing real prepared publication failure.
    Preparation(publication::auto_prepare::Failure),
    /// Actual atomic local image failure. Visible means rename may have published;
    /// neither this flag nor successful bookkeeping is a remote service receipt.
    Catalog {
        /// Original local image operation that failed.
        stage: &'static str,
        /// Whether the original rename may already have become visible.
        visible: bool,
        /// Original filesystem error, preserved without a fabricated rollback.
        original: Arc<std::io::Error>,
        /// Independent cleanup error for that same original attempt.
        cleanup: Option<Arc<std::io::Error>>,
    },
    /// Original configured CLIENT/Resolver selection failure.
    Client(gnunet_client_host::ConnectError),
    /// The actual source UTC value is outside the mature calendar's range.
    Calendar(time::error::ComponentRange),
    /// Original task restore/state failure, preserving its native/storage cause.
    Task(Box<publication::Failure>),
    /// Original local failure and independent failure recording/cleaning it up.
    WithCleanup {
        /// Original operation failure.
        original: Box<Error>,
        /// Independent failure while recording or retiring that original operation.
        cleanup: Box<Error>,
    },
    /// Shared clock/client ownership or explicit capacity refusal.
    Protocol(Protocol),
    /// Actual root/journal/version binding mismatch; no mutation is authorized.
    Binding(&'static str),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scan(e) => e.fmt(f),
            Self::Storage(e) => e.fmt(f),
            Self::Io(e) => e.fmt(f),
            Self::Preparation(e) => e.fmt(f),
            Self::Protocol(e) => e.fmt(f),
            Self::Calendar(e) => e.fmt(f),
            Self::Task(e) => e.fmt(f),
            Self::WithCleanup { original, cleanup } => {
                write!(f, "{original}; independent cleanup: {cleanup}")
            }
            Self::Client(e) => e.fmt(f),
            Self::Catalog {
                stage,
                visible,
                original,
                cleanup,
            } => write!(
                f,
                "auto-share {stage} visible={visible}: {original}; cleanup={cleanup:?}"
            ),
            Self::Binding(e) => f.write_str(e),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Scan(e) => Some(e),
            Self::Storage(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::Preparation(e) => Some(e),
            Self::Protocol(e) => Some(e),
            Self::Calendar(e) => Some(e),
            Self::Task(e) => Some(e.as_ref()),
            Self::WithCleanup { original, .. } => Some(original.as_ref()),
            Self::Client(e) => Some(e),
            Self::Catalog { original, .. } => Some(original.as_ref()),
            Self::Binding(_) => None,
        }
    }
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<store::Error> for Error {
    fn from(e: store::Error) -> Self {
        Self::Storage(e)
    }
}
impl From<ScanError> for Error {
    fn from(e: ScanError) -> Self {
        Self::Scan(e)
    }
}
impl From<Protocol> for Error {
    fn from(e: Protocol) -> Self {
        Self::Protocol(e)
    }
}
/// Bounded actual observations. No scan/prepared event means published.
#[derive(Debug)]
pub enum Event<'a> {
    /// Current input scan succeeded; counts refer only to that completed scan.
    Scanned {
        /// Top-level entries in this completed snapshot.
        entries: usize,
        /// Objects visited by this completed bounded scan.
        objects: u64,
        /// Logical source bytes reported by this completed snapshot.
        bytes: u64,
    },
    /// A new immutable original version was prepared, before native submission.
    Prepared {
        /// Original durable version identifier.
        version: u64,
        /// Original raw top-level relative name.
        path: &'a [u8],
        /// Actual content and keyword tasks prepared for this version.
        tasks: usize,
    },
    /// Actual original group/task progress from the publication runner.
    Publication {
        /// Original durable version identifier.
        version: u64,
        /// Original task index within this version.
        task: usize,
        /// Borrowed actual progress for this synchronous observation.
        progress: &'a publication::Progress,
    },
    /// Original DATASTORE/FS replies and payload checks completed, then the local
    /// catalog recorded this version. This does not promise remote availability.
    Published {
        /// Original version whose complete task set finished.
        version: u64,
        /// Original raw top-level relative name.
        path: &'a [u8],
        /// Canonical URI for that original content.
        uri: &'a [u8],
    },
    /// This original version remains fenced/refused; no new task bypasses it.
    Blocked {
        /// Original refused or uncertain durable version.
        version: u64,
        /// Original raw top-level relative name.
        path: &'a [u8],
        /// Typed branch's fixed explanatory reason.
        reason: &'static str,
    },
    /// Deleted input stops new work, without claiming network erasure/unindexing.
    Removed {
        /// Raw name absent from the completed authoritative snapshot.
        path: &'a [u8],
    },
    /// Actual preparation/publication error, not a fabricated retry completion.
    Failed {
        /// Original durable version, if admission already assigned one.
        version: Option<u64>,
        /// Original affected top-level relative name.
        path: &'a [u8],
        /// Original operation failure for this synchronous observation.
        error: &'a dyn std::error::Error,
    },
}
pub(crate) const STATE: &[u8] = b".auto-share-rust";
pub(crate) fn component(bytes: &[u8]) -> Result<&std::ffi::OsStr, Error> {
    use std::os::unix::ffi::OsStrExt;
    if bytes.is_empty()
        || matches!(bytes, b"." | b"..")
        || bytes.contains(&0)
        || bytes.contains(&b'/')
    {
        return Err(Error::Binding("invalid auto-share component"));
    }
    Ok(std::ffi::OsStr::from_bytes(bytes))
}
pub(crate) fn relative(version: u64) -> PathBuf {
    PathBuf::from(format!("version-{version:016x}"))
}

impl From<gnunet_client_host::ConnectError> for Error {
    fn from(e: gnunet_client_host::ConnectError) -> Self {
        Self::Client(e)
    }
}

impl From<time::error::ComponentRange> for Error {
    fn from(e: time::error::ComponentRange) -> Self {
        Self::Calendar(e)
    }
}
pub(crate) fn expiration(sample: u64, relative: Option<Duration>) -> Result<u64, Error> {
    if let Some(duration) = relative {
        return sample
            .checked_add(
                u64::try_from(duration.as_micros())
                    .map_err(|_| Error::Binding("content lifetime overflow"))?,
            )
            .ok_or(Error::Binding("content expiration overflow"));
    }
    let observed = time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(sample) * 1000)?;
    let year = observed
        .year()
        .checked_add(2)
        .ok_or(Error::Binding("content expiration year overflow"))?;
    let expiry = time::Date::from_calendar_date(year, time::Month::January, 1)?
        .midnight()
        .assume_utc();
    u64::try_from(expiry.unix_timestamp_nanos() / 1000)
        .map_err(|_| Error::Binding("content expiration is not unsigned GNUnet time"))
}
