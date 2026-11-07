//! Original local tokens are not wire request ids or backend success receipts.
use ::core::fmt;
use alloc::sync::Arc;
use gnunet_regex::{BuildError, Hash};
#[derive(Debug)]
pub(crate) struct Brand;
#[derive(Clone)]
pub(crate) struct Key {
    pub brand: Arc<Brand>,
    pub sequence: u64,
}
impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.brand, &other.brand) && self.sequence == other.sequence
    }
}
impl Eq for Key {}
impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.sequence.fmt(f)
    }
}
macro_rules! token {
    ($name:ident) => {
        #[doc = "One opaque allocation-bound original local coordinate; not a remote receipt."]
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $name(pub(crate) Key);
    };
}
token!(ClientId);
token!(JobId);
token!(OutputId);
/// Separate scheduling and real absolute-record coordinates, in microseconds.
#[derive(Clone, Copy, Debug)]
pub struct Times {
    /// Independent nondecreasing host scheduling coordinate, in microseconds.
    pub monotonic: u64,
    /// Actual shared GNUnet logical UTC microseconds; wall adjustment is allowed.
    pub absolute: u64,
}
/// Resource admission and genuine original backend errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Original checked official representation/crypto refusal.
    Protocol(gnunet_types::Error),
    /// Actual complete bounded compiler refusal, without publication.
    Build(BuildError),
    /// An explicit resource or fallible allocation limit refused admission.
    Capacity,
    /// The original Core/client/job/identity generation no longer matches.
    Stale,
    /// This fact does not follow the original lifecycle.
    Order,
    /// The original source is retiring and admits no new business.
    Closing,
    /// The same original MQ already owns that request kind.
    Duplicate,
    /// The independently monotonic scheduling coordinate moved backward.
    Clock,
    /// The actual signed or DHT value is already past its absolute expiry.
    Expired,
}
impl From<gnunet_types::Error> for Error {
    fn from(e: gnunet_types::Error) -> Self {
        Self::Protocol(e)
    }
}
impl From<BuildError> for Error {
    fn from(e: BuildError) -> Self {
        Self::Build(e)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "REGEX service: {self:?}")
    }
}
impl ::core::error::Error for Error {}
/// One committed local admission, not a wire ACK or a DHT publication receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Admission {
    /// Actual local announcement admission, with no ACK message.
    Announce,
    /// Actual local persistent search admission, with no DONE message.
    Search,
}
/// Explicit finite compiler, operation, result and retained-byte bounds.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum retained original MQ allocations, including closing clients.
    pub clients: usize,
    /// Original backend credits; another equally sized retirement table is reserved.
    pub jobs: usize,
    /// Maximum distinct key/position/type queries in one search.
    pub branches: usize,
    /// Maximum retained actual accepting results, including queued/exposed debt.
    pub outputs: usize,
    /// Maximum retained exact DHT-result fingerprints across live original queries.
    pub seen_results: usize,
    /// Maximum combined GET/PUT predecessor identities per result.
    pub output_paths: usize,
    /// Maximum interpreted expression/search bytes before the C-string terminator.
    pub input_bytes: usize,
    /// Maximum complete checked state/accepting block bytes.
    pub block_bytes: usize,
    /// Conservative retained automaton and payload/path byte budget; not RSS.
    pub retained_bytes: usize,
    /// Maximum conservative retained bytes for one compiled announcement.
    pub announcement_bytes: usize,
    /// Independent complete compiler work/graph/proof/workspace limits.
    pub compiler: gnunet_regex::Limits,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            clients: 32,
            jobs: 1024,
            branches: 128,
            outputs: 128,
            seen_results: 4096,
            output_paths: 128,
            input_bytes: 4096,
            block_bytes: gnunet_regex::MAX_BLOCK_BYTES - 1,
            retained_bytes: 32 * 1024 * 1024,
            announcement_bytes: 4 * 1024 * 1024,
            compiler: gnunet_regex::Limits::default(),
        }
    }
}
/// Backend work remains owned by Core until the exact original completion/retire.
#[derive(Debug)]
pub enum Work<'a> {
    /// One exact original local DHT PUT, never remote replication proof.
    Put {
        /// Opaque original work id; a clone remains the same original id.
        job: JobId,
        /// The actual accepted original IPC allocation.
        client: ClientId,
        /// The original state proof key.
        key: Hash,
        /// Official block type22 or23.
        kind: u32,
        /// Official DHT options: demultiplex1, optionally record-route2.
        options: u32,
        /// Official replication level5.
        replication: u32,
        /// This new original PUT target, sampled once as absolute now+1h.
        expires: u64,
        /// Immutable original body; caller must copy/consume synchronously before reborrowing Core.
        block: &'a [u8],
    },
    /// One persistent original DHT GET with many replies until actual retirement.
    Get {
        /// Opaque original work id; a clone remains the same original id.
        job: JobId,
        /// The actual accepted original IPC allocation.
        client: ClientId,
        /// The original state proof key.
        key: Hash,
        /// Official block type22 or23.
        kind: u32,
        /// Official DHT options: demultiplex1, optionally record-route2.
        options: u32,
        /// Official replication level5.
        replication: u32,
        /// Type22 suffix WITH final NUL; type23 has exactly zero xquery bytes.
        xquery: &'a [u8],
    },
    /// One original peer-bound purpose18 signing job.
    Sign {
        /// Opaque original work id; a clone remains the same original id.
        job: JobId,
        /// The actual accepted original IPC allocation.
        client: ClientId,
        /// Actual original PILS peer public identity, not a secret.
        peer: [u8; 32],
        /// Exact original size80/purpose18/expiry/key signed region.
        material: &'a [u8; 80],
    },
    /// Actual retirement of this exact original target, with no wire extension.
    Retire {
        /// Opaque original work id; a clone remains the same original id.
        job: JobId,
        /// The actual accepted original IPC allocation.
        client: ClientId,
        /// The SAME original operation; admission/cancel-queued is not quiescence.
        target: JobId,
    },
}
/// Full original accepting-result payload. Paths are DHT predecessor metadata,
/// not peer authentication; the accepting block's signature is separately checked.
#[derive(Clone, Copy, Debug)]
pub struct Reply<'a> {
    /// Actual absolute DHT value expiry; equality with now remains current.
    pub expires: u64,
    /// Original exact DHT key, not a peer identity or transformed namespace.
    pub key: Hash,
    /// Official REGEX22 or REGEX_ACCEPT23 block type.
    pub kind: u32,
    /// Complete original returned block bytes; Core validates before authority.
    pub block: &'a [u8],
    /// Original GET predecessor identities in supplied order.
    pub get_path: &'a [[u8; 32]],
    /// Original PUT predecessor identities in supplied order.
    pub put_path: &'a [[u8; 32]],
}
