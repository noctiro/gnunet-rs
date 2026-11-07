use crate::*;
/// Exact original provider boundary; no implicit service or resolver is created.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Provider {
    /// Actual IDENTITY IPC.
    Identity,
    /// Actual NAMESTORE IPC.
    Namestore,
    /// Existing actual GNS query client only.
    Gns,
}
/// Source-specific first failure, without private bytes, names or raw frames.
#[derive(Debug)]
pub enum Error {
    /// Pure format/bound/resource/deadline cause.
    Protocol(Fault),
    /// Actual SDK/OS/clock/source failure.
    Native(gnunet_client_host::ConnectError),
    /// Actual signal provider error.
    Signal(io::Error),
    /// Original private FIFO lookup/create result code.
    IdentityCode(u32),
    /// Original NAMESTORE result code.
    NamestoreCode(u32),
    /// Actual lookup found/status field.
    LookupCode(i16),
    /// Original IDENTITY local terminal outcome.
    IdentityLocal {
        /// Original reason.
        reason: identity::LocalReason,
        /// Original actual request exposure.
        submission: identity::Submission,
        /// Actual late code, if received.
        result_code: Option<u32>,
    },
    /// Original NAMESTORE local terminal outcome.
    NamestoreLocal {
        /// Original reason.
        reason: ns::LocalReason,
        /// Actual original exposure, not durability.
        submission: ns::Submission,
    },
    /// Actual original dependency source loss.
    SourceLost {
        /// Exact dependency.
        provider: Provider,
        /// Original attached source.
        epoch: Option<u64>,
        /// Original operations with any positive exposure, including retired
        /// readonly MQs; this grants no write credit on the reported epoch.
        exposed: usize,
        /// Actual original cause, without frames or key material.
        cause: Loss,
    },
}
impl From<Fault> for Error {
    fn from(e: Fault) -> Self {
        Self::Protocol(e)
    }
}
impl From<gnunet_client_host::ConnectError> for Error {
    fn from(e: gnunet_client_host::ConnectError) -> Self {
        Self::Native(e)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DID operation: {self:?}")
    }
}
impl std::error::Error for Error {}
/// Real source/lifecycle metadata. No secret key/document bytes are formatted.
#[derive(Debug)]
pub enum Event {
    /// Actual one-shot IDENTITY UPDATE hit; this message has no result code.
    LookupFound {
        /// Original lookup allocation.
        operation: u64,
        /// Original actual source, already retired by the lookup wrapper.
        epoch: Option<u64>,
    },
    /// Actual pre-attachment retry; never an exposed-operation replay.
    Retry {
        /// Original provider.
        provider: Provider,
        /// Original native connection error.
        error: io::Error,
        /// Original shared-CLIENT backoff.
        after: Duration,
    },
    /// Actual socket attached.
    Connected {
        /// Original dependency.
        provider: Provider,
        /// Original private SDK epoch diagnostic.
        epoch: u64,
    },
    /// Actual native immutable frame queued.
    Queued {
        /// Original dependency.
        provider: Provider,
        /// Original epoch.
        epoch: u64,
        /// Original operation allocation.
        operation: u64,
        /// Official RID, when present in the protocol.
        rid: Option<u32>,
    },
    /// Actual whole local write, never a service result.
    Written {
        /// Dependency.
        provider: Provider,
        /// Original epoch.
        epoch: u64,
        /// Original operation.
        operation: u64,
    },
    /// Actual raw service result/status.
    Result {
        /// Dependency.
        provider: Provider,
        /// Original operation.
        operation: u64,
        /// Raw result/found field, without normalization.
        code: i64,
    },
    /// Known native bytes, never application delivery.
    Bytes {
        /// Original dependency.
        provider: Provider,
        /// Actual read bytes.
        read: usize,
        /// Actual positive write bytes.
        written: usize,
    },
    /// Original physical owner retired, not remote rollback.
    Closed {
        /// Dependency.
        provider: Provider,
        /// Original attached epoch if any.
        epoch: Option<u64>,
        /// Original unsettled operation intents coordinated with retirement.
        operations: usize,
        /// Those original operations with positive exposure, including retired
        /// readonly MQs; individual source facts were observed separately.
        exposed: usize,
    },
    /// Original source failure retained before local cleanup.
    Lost {
        /// Original dependency.
        provider: Provider,
        /// Original epoch diagnostic, not a token constructor.
        epoch: Option<u64>,
        /// Original positive-exposure operation count.
        exposed: usize,
    },
    /// A physically lost GNS MQ retained this same readonly query. The actual
    /// cause and old exposure are history, never write credit on the next MQ.
    RetainedRead {
        /// Existing readonly provider.
        provider: Provider,
        /// Original retired physical MQ.
        epoch: u64,
        /// Same original logical query; no replacement admission occurred.
        operation: u64,
        /// Any actual positive write on this retired MQ.
        exposed: bool,
        /// Actual whole local write on this retired MQ, not a resolution result.
        written: bool,
        /// Actual independent original source cause.
        cause: Loss,
    },
    /// An independent cleanup failure; first operation error remains.
    Cleanup {
        /// Original provider.
        provider: Provider,
        /// Actual SDK failure.
        error: gnunet_client_host::ConnectError,
    },
    /// Actual completed original monitor initial list.
    Initialized {
        /// Original actual epoch.
        epoch: u64,
        /// Current bounded snapshot count.
        egos: usize,
    },
    /// Actual callback cancellation, no wire CANCEL/revocation ACK.
    Cancelled {
        /// Original dependency.
        provider: Provider,
        /// Original operation diagnostic.
        operation: u64,
    },
}
/// Exact source failure family, without extending old token lifetimes.
#[derive(Debug)]
pub enum Loss {
    /// Original identity SDK reason.
    Identity(identity::LossCause),
    /// Original namestore SDK reason.
    Namestore(ns::LossCause),
    /// Original existing GNS-client reason.
    Gns(gns::LossCause),
}
/// Explicit finite policy; defaults do not create hidden network resources.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// JSON body bytes (not a private protocol limit).
    pub document_bytes: usize,
    /// Original records in one lookup reply.
    pub records: usize,
    /// Full IDENTITY snapshot directory bound.
    pub egos: usize,
    /// JSON parser's finite scratch/work budget.
    pub json: gnunet_json::Limits,
    /// Actual syscall quantum.
    pub io_slice_bytes: usize,
    /// Original suffix/FIFO cleanup grace.
    pub retirement_grace: Duration,
    /// GNS policy bits.
    pub gns_options: u16,
    /// Actual ordinary API default128.
    pub gns_recursion: u16,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            document_bytes: 48 * 1024,
            records: 1024,
            egos: 256,
            json: gnunet_json::Limits {
                bytes: 48 * 1024,
                nodes: 4096,
                depth: 32,
                work: 4_000_000,
            },
            io_slice_bytes: 65535,
            retirement_grace: Duration::from_secs(5),
            gns_options: 0,
            gns_recursion: 128,
        }
    }
}
/// Original caller sources using one exact canonical clock Arc.
pub struct Sources {
    /// Original shared canonical clock; every present source must match it.
    pub clock: Arc<dyn RuntimeClock>,
    /// Actual identity endpoint.
    pub identity: Option<EndpointSource>,
    /// Actual namestore endpoint.
    pub namestore: Option<EndpointSource>,
    /// Existing GNS query service endpoint.
    pub gns: Option<EndpointSource>,
}
/// Stable caller domains; their private IDs never become a DID/wire field.
pub struct Instances<'i, 'n, 'g> {
    /// Stable identity allocation domain.
    pub identity: &'i identity::Instance,
    /// Stable namestore allocation domain.
    pub namestore: &'n ns::Instance,
    /// Exclusive existing query-client domain.
    pub gns: &'g mut gns::Instance,
}
/// One original finite logical/native budget, bound to this client's real clock.
/// Phases and retries never construct a replacement deadline from late time.
pub struct Deadline {
    pub(crate) clock: Arc<dyn RuntimeClock>,
    pub(crate) until: u64,
    pub(crate) hard: Instant,
    pub(crate) observed: std::cell::Cell<u64>,
}
impl Deadline {
    /// Original canonical absolute deadline.
    #[must_use]
    pub const fn until(&self) -> u64 {
        self.until
    }
}
/// Publication operation. Replace is real scoped record replacement, not the
/// empty pinned C callback or deleting unrelated root-label data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublishMode {
    /// Refuse an existing managed DID document.
    Create,
    /// Require and replace an existing managed DID document.
    Replace,
}
/// Public requested operation data. Key material is obtained only from the
/// explicit IDENTITY endpoint, or generated with the explicit entropy argument.
pub struct Publish<'a> {
    /// Actual ego name.
    pub ego: &'a [u8],
    /// Original JSON, or exact default template when absent.
    pub document: Option<&'a [u8]>,
    /// Relative microsecond record lifetime.
    pub expiration_micros: u64,
    /// Original create/replace intent.
    pub mode: PublishMode,
    /// Allow a real missing ego to be created; only Create.
    pub create_ego: bool,
}
/// One actual public monitor result; no private key or serialized frame escapes.
#[derive(Debug)]
pub struct NamedDid {
    /// Actual original ego name.
    pub name: Vec<u8>,
    /// Derived public DID, not authentication proof.
    pub did: did::Did,
}
/// One actual resolved document; private/raw Debug and implicit Clone are absent.
pub struct Resolved {
    pub(crate) did: did::Did,
    pub(crate) body: Zeroizing<Vec<u8>>,
    pub(crate) form: did::RecordForm,
}
impl Resolved {
    /// Original requested public zone.
    #[must_use]
    pub const fn did(&self) -> did::Did {
        self.did
    }
    /// Validated actual original JSON body, not a verified signature.
    #[must_use]
    pub fn json(&self) -> &[u8] {
        &self.body
    }
    /// Exact original source record form.
    #[must_use]
    pub const fn form(&self) -> did::RecordForm {
        self.form
    }
}
impl std::fmt::Debug for Resolved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedDID")
            .field("did", &self.did)
            .field("bytes", &self.body.len())
            .field("form", &self.form)
            .finish()
    }
}
