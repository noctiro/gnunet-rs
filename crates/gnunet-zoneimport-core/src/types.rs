use crate::Error;
use gnunet_wire::official::{AbsoluteTime, RelativeTime};
/// One caller's nondecreasing native-elapsed microsecond coordinate.
/// It is unrelated to UTC and does not itself attest an OS clock sample.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MonoInstant(u64);
impl MonoInstant {
    /// Capture the caller's original monotonic coordinate.
    #[must_use]
    pub const fn from_micros(value: u64) -> Self {
        Self(value)
    }
    /// Original elapsed microseconds, for mapping through the same native epoch.
    #[must_use]
    pub const fn as_micros(self) -> u64 {
        self.0
    }
}
/// Explicit independent scheduling and canonical absolute samples.
#[derive(Clone, Copy, Debug)]
pub struct Times {
    /// Caller-owned native elapsed sample.
    pub mono: MonoInstant,
    /// Canonical GNUnet absolute sample; corrections are allowed.
    pub absolute: AbsoluteTime,
}
/// First fixed operation targets, unchanged by retries of native admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bounds {
    /// First original action admission coordinate.
    pub started: MonoInstant,
    /// Native-elapsed deadline, mapped by the host through its original epoch.
    pub until: MonoInstant,
    /// Original canonical absolute deadline.
    pub expires: AbsoluteTime,
}
impl Bounds {
    /// Construct finite checked coordinate metadata; this installs no OS timer.
    pub fn new(now: Times, duration: RelativeTime) -> Result<Self, Error> {
        let n = duration.as_micros();
        if n == 0 || n == u64::MAX {
            return Err(Error::InvalidInput);
        }
        let until = now.mono.0.checked_add(n).ok_or(Error::Overflow)?;
        let expires = now
            .absolute
            .as_micros()
            .checked_add(n)
            .filter(|n| *n != u64::MAX)
            .ok_or(Error::Overflow)?;
        Ok(Self {
            started: now.mono,
            until: MonoInstant(until),
            expires: AbsoluteTime::from_micros(expires),
        })
    }
    /// Check both original targets. Clock rollback never extends the native bound.
    #[must_use]
    pub fn expired(self, now: Times) -> bool {
        now.mono >= self.until || now.absolute.as_micros() >= self.expires.as_micros()
    }
}
/// Independent next wake targets. Missing targets mean no local timer work.
#[derive(Clone, Copy, Debug, Default)]
pub struct Wakeup {
    /// Original operation/retry/dispatch native target.
    pub mono: Option<MonoInstant>,
    /// Actual cache/record expiry, without converting it into a new lifetime.
    pub absolute: Option<AbsoluteTime>,
}
/// Explicit finite metadata/work limits; record payload loans are host-owned.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum distinct input FQDNs.
    pub names: usize,
    /// Maximum existing and newly needed control zones combined.
    pub zones: usize,
    /// Maximum original jobs, including deferred/retiring jobs.
    pub jobs: usize,
    /// Combined retained canonical name/zone string bytes.
    pub name_bytes: usize,
    /// Maximum records in one actual cache/result set.
    pub records_per_set: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            names: 65536,
            zones: 4096,
            jobs: 100,
            name_bytes: 16 * 1024 * 1024,
            records_per_set: 4096,
        }
    }
}
impl Limits {
    /// Check finite resource bounds before reserving the core pools.
    pub fn validate(self) -> Result<(), Error> {
        if self.names == 0
            || self.names > 1_000_000
            || self.zones == 0
            || self.zones > 65536
            || self.jobs == 0
            || self.jobs > 4096
            || self.name_bytes == 0
            || self.name_bytes > 256 * 1024 * 1024
            || self.records_per_set == 0
            || self.records_per_set > 4096
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
}
/// Bounded scheduling policy. These are operation budgets, not fake receipts.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    /// First job budget; DNS UDP/TCP and its Store share the same original bound.
    pub operation: RelativeTime,
    /// Backoff after a settled failed read, with no replay of old mutations.
    pub retry: RelativeTime,
    /// Maximum DNS attempts per refresh cycle. Default6 matches C's `>5` cutoff.
    pub max_attempts: u32,
    /// Original DNS conversion minimum-expiry data floor; zero and FOREVER are valid.
    pub minimum_expiration: RelativeTime,
    /// Complete NOERROR/NODATA result's next refresh; default one day.
    pub empty_refresh: RelativeTime,
    /// New child delegation relative expiry; default one week.
    pub delegation_expiration: RelativeTime,
    /// Minimum spacing of newly admitted DNS attempts, default10 microseconds.
    pub dispatch_interval: RelativeTime,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            operation: RelativeTime::from_micros(30_000_000),
            retry: RelativeTime::from_micros(1_000_000),
            max_attempts: 6,
            minimum_expiration: RelativeTime::from_micros(0),
            empty_refresh: RelativeTime::from_micros(86_400_000_000),
            delegation_expiration: RelativeTime::from_micros(604_800_000_000),
            dispatch_interval: RelativeTime::from_micros(10),
        }
    }
}
impl Policy {
    /// Check finite scheduling intervals; conversion minimum is a data lifetime
    /// and may be zero or FOREVER without extending any active job budget.
    pub fn validate(self) -> Result<(), Error> {
        for n in [
            self.operation,
            self.retry,
            self.empty_refresh,
            self.delegation_expiration,
            self.dispatch_interval,
        ] {
            if n.as_micros() == 0 || n.as_micros() == u64::MAX {
                return Err(Error::InvalidInput);
            }
        }
        if self.max_attempts == 0 || self.max_attempts > 64 {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
}
/// Real port result classification, consumed only for the exact original job.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mutation {
    /// Actual original service result code. Zero is not an fsync proof.
    KnownCode(u32),
    /// Original operation physically settled without positive byte exposure.
    Unsent,
    /// Original operation physically settled with possible mutation and no result.
    Unknown,
}
/// Original query/iterator terminal failure; native causes stay owned in the host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadFailure {
    /// Actual complete DNS RCODE, including EDNS extensions and NXDOMAIN.
    Rcode(u16),
    /// A malformed or mismatched response was terminal for this original query.
    InvalidResponse,
    /// Actual original source could not complete.
    Source,
    /// Original fixed bound expired.
    Deadline,
    /// Real local stop/cancellation settled the original job.
    Cancelled,
}
/// Actual original iterator ending. A local failure is never an END receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadEnd {
    /// Actual original iterator END after the requested complete inventory.
    Complete,
    /// Original iterator physically retired without a complete END.
    Failed,
}
/// Actual original cancellation/retirement result. It never means remote rollback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Retirement {
    /// Original host operation settled with zero actual mutation exposure.
    Unsent,
    /// Original operation settled without a result and may have mutated storage.
    Unknown,
}
/// Stable business state observable without granting a new native operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    /// Waiting on startup inventory, ancestor preparation or cache scan.
    Preparing,
    /// Sleeping until actual record expiry or bounded retry.
    Waiting,
    /// One original read or write is outstanding.
    Pending,
    /// A possible mutation has no result; no automatic retry is allowed.
    Uncertain,
    /// This name/zone cannot progress in the current instance.
    Failed,
    /// Explicit stop prevents new work.
    Stopped,
}
/// Input names that cannot safely progress, distinct from healthy pending work.
/// Counts refer to retained business state; neither zero nor a cache hit is a
/// receipt that every input was stored successfully.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NameFailures {
    /// Input names with known terminal failure, including an original terminal
    /// CREATE/parent-STORE service rejection drained after stop. Known-unsent
    /// normal cancellation does not create a business failure.
    pub failed: usize,
    /// Input names fenced by an original mutation with no known result.
    pub uncertain: usize,
}
/// Original job kind; cancellation must retain that same native mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// Original IDENTITY create operation.
    CreateZone,
    /// Original complete NAMESTORE parent-label lookup.
    CheckDelegation,
    /// Original NAMESTORE parent delegation replacement.
    Delegate,
    /// Original startup NAMESTORE zone iterator.
    ScanCache,
    /// Original IN NS DNS query, including any same-budget TCP fallback.
    Query,
    /// Original DNS answer's complete NAMESTORE replacement.
    Store,
}
/// Business consequence only; it does not grant native, crypto or disk authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// Supplied actual result or observation applied to this business state.
    Applied,
    /// Original work settled and a separately bounded next stage may be scheduled.
    Retrying,
    /// No further work for the affected name/zone in this instance.
    Failed,
    /// A mutation without a result permanently fenced the affected name/zone.
    Unknown,
    /// Explicit stop continues only original retirement.
    Closed,
}
/// Actual cumulative business observations, separate from host source/write facts.
#[derive(Clone, Copy, Debug, Default)]
pub struct Metrics {
    /// Distinct input names retained.
    pub names: u64,
    /// Actual inventory plus locally required control-zone rows.
    pub zones: u64,
    /// DNS jobs actually admitted by the host port, not action peeks.
    pub dns_admitted: u64,
    /// Original DNS attempts ending without a usable full response.
    pub dns_failures: u64,
    /// Original DNS-derived STORE results with actual service code0.
    pub stored_sets: u64,
    /// Record counts in those actual code0 STORE results.
    pub stored_records: u64,
    /// Input names with a complete nonempty actual cache-set observation.
    pub cache_hits: u64,
    /// Original potentially exposed mutations with no known service result.
    pub unknown_mutations: u64,
}

#[cfg(feature = "alloc")]
mod owned {
    use super::*;
    use alloc::sync::Arc;
    use core::fmt;
    use gnunet_gnsrecord::{RecordData, ZoneKey};
    pub(crate) struct Brand;
    macro_rules! identifier {
        ($name:ident) => {
            #[doc = "Opaque identifier bound to one actual Core allocation."]
            #[derive(Clone)]
            pub struct $name {
                pub(crate) brand: Arc<Brand>,
                pub(crate) serial: u64,
            }
            impl PartialEq for $name {
                fn eq(&self, other: &Self) -> bool {
                    self.serial == other.serial && Arc::ptr_eq(&self.brand, &other.brand)
                }
            }
            impl Eq for $name {}
            impl fmt::Debug for $name {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.debug_tuple(stringify!($name))
                        .field(&self.serial)
                        .finish()
                }
            }
            impl $name {
                #[doc = "Diagnostic local number only, not a constructor or a receipt."]
                #[must_use]
                pub const fn diagnostic(&self) -> u64 {
                    self.serial
                }
            }
        };
    }
    identifier!(NameId);
    identifier!(ZoneId);
    identifier!(JobId);
    identifier!(AnswerId);
    /// An actual successful CREATE needs its same returned public key observation.
    #[derive(Clone, Copy, Debug)]
    pub enum Creation {
        /// Actual original CREATE succeeded with the same returned public key.
        Created(ZoneKey),
        /// Actual original service rejected creation with this code.
        Rejected(u32),
        /// Actual original operation retired without exposing a mutation byte.
        Unsent,
        /// Actual original operation retired with unknown mutation outcome.
        Unknown,
    }
    /// Read-only original action payload; the caller copies before an async wait.
    #[derive(Debug)]
    pub enum ActionKind<'a> {
        /// Create this missing control ego through the actual IDENTITY port.
        CreateZone {
            /// Same local zone allocation to bind to the returned secret owner.
            zone: ZoneId,
            /// Canonical ASCII zone name used as the intended ego name.
            name: &'a str,
        },
        /// Replace an observed-empty parent label with this child delegation.
        Delegate {
            /// Original controlling parent ego allocation.
            parent: ZoneId,
            /// Original actually created or inventoried child allocation.
            child: ZoneId,
            /// Parent-relative ASCII label; host applies its actual IDNA utility.
            label: &'a str,
            /// Standard raw32 delegation with relative lifetime, never a private key.
            record: RecordData<'a>,
        },
        /// Read the actual parent label before any delegation replacement.
        CheckDelegation {
            /// Same original parent ego allocation used by the native lookup.
            parent: ZoneId,
            /// Child whose public key must match any observed delegation.
            child: ZoneId,
            /// Exact parent-relative ASCII label to inspect.
            label: &'a str,
        },
        /// Obtain original complete cache observations using a real zone iterator.
        ScanCache {
            /// Actual controlling zone allocation.
            zone: ZoneId,
        },
        /// Query one IN NS question, preserving this same job through TCP fallback.
        Query {
            /// Exact input-name allocation.
            name: NameId,
            /// Complete canonical ASCII FQDN, not merely its first label.
            hostname: &'a str,
        },
        /// Replace one complete label set using the retained original answer bytes.
        Store {
            /// Same input-name allocation as the original DNS query.
            name: NameId,
            /// Original converted answer loan; it is not a native mutation receipt.
            answer: AnswerId,
            /// Actual controlling ego allocation for the native STORE.
            zone: ZoneId,
            /// Exact ASCII first label, projected by the host's same IDNA profile.
            label: &'a str,
        },
        /// Settle the original native operation; no normal business retry is implied.
        Retire {
            /// Kind of the same original job, not a newly created cancel job.
            kind: Kind,
            /// Core observed real host admission. It does not prove exposure or cancel.
            admitted: bool,
        },
    }
    /// Ready work remains retained until actual admission; peeking does not settle it.
    #[derive(Debug)]
    pub struct Action<'a> {
        /// Original immutable branded job token.
        pub job: JobId,
        /// First original targets; never reminted by action polling or fallback.
        pub bounds: Bounds,
        /// Borrowed original payload, with no hidden worker or side effect.
        pub kind: ActionKind<'a>,
    }
    /// Core transition result. Release only the named original payload loan.
    #[derive(Debug)]
    pub struct Completion {
        /// Actual terminal stage releases this same host-owned answer buffer.
        pub release: Option<AnswerId>,
        /// Business consequence, distinct from the supplied native receipt.
        pub outcome: Outcome,
    }
}
#[cfg(feature = "alloc")]
pub(crate) use owned::Brand;
#[cfg(feature = "alloc")]
pub use owned::*;
