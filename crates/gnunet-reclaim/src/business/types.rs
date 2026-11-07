use super::{
    Blob,
    memory::{Lease, Quota},
};
use crate::{
    AttributeList, Credential, Identifier, Presentation,
    ipc::{Request, Response},
};
use alloc::rc::Rc;
use core::{cell::Cell, fmt};
use gnunet_gnsrecord::{RecordType, ZoneKey};
use gnunet_types::Error;
use gnunet_wire::official::{identity::SecretKeyView, namestore::Records};
/// Explicit aggregate business resources; no background IO or allocation domain.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Simultaneously live independent original business jobs.
    pub jobs: usize,
    /// Actual native provider sources shared across jobs.
    pub sources: usize,
    /// Maximum rows accepted in an original NAMESTORE snapshot scan.
    pub rows: usize,
    /// Maximum GNS records in one row/query completion.
    pub records: usize,
    /// Maximum requested attributes, presentations, ID rotations or mutation rows.
    pub items: usize,
    /// Aggregate retained payload, tables, job and source metadata bytes.
    pub bytes: usize,
    /// Maximum serialized object/row/output frame, at most65535.
    pub frame_bytes: usize,
    /// Official ticket record relative refresh interval in microseconds.
    pub refresh_micros: u64,
    /// Per-job record traversal, lookup and comparison budget, never renewed.
    pub work_units: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            jobs: 32,
            sources: 16,
            rows: 256,
            records: 256,
            items: 256,
            bytes: 16 * 1024 * 1024,
            frame_bytes: 65535,
            refresh_micros: 3_600_000_000,
            work_units: 32_000_000,
        }
    }
}
impl Limits {
    pub(super) fn validate(self) -> Result<(), Error> {
        if self.jobs == 0
            || self.sources == 0
            || self.rows == 0
            || self.records == 0
            || self.items == 0
            || self.rows > 4096
            || self.records > 4096
            || self.items > 4096
            || self.frame_bytes < 128
            || self.frame_bytes > 65535
            || self.bytes < 1024
            || self.refresh_micros == 0
            || self.work_units == 0
            || self.work_units > 256_000_000
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
}
/// Required explicit provider; this core creates no resolver, key or transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Provider {
    /// Real NAMESTORE source.
    Namestore,
    /// Existing actual GNS client source; no resolver implementation here.
    Gns,
    /// Explicit credential format/presentation provider, not assumed verified.
    Credential,
    /// Caller OS/CSPRNG entropy port for fresh nonzero32byte identifiers.
    Entropy,
    /// Actual identity public-key derivation port, never a configured guess.
    Identity,
}
pub(super) struct SourceData {
    pub quota: Rc<Quota>,
    pub provider: Provider,
    pub serial: u64,
    pub live: Cell<bool>,
    pub _lease: Lease,
}
impl Drop for SourceData {
    fn drop(&mut self) {
        self.quota
            .sources
            .set(self.quota.sources.get().saturating_sub(1));
    }
}
/// One original actually attached provider source. Only the caller's trusted
/// native/provider owner may mint it after actual attachment/admission readiness.
#[derive(Clone)]
pub struct Source(pub(super) Rc<SourceData>);
impl Source {
    /// Exact provider kind.
    #[must_use]
    pub fn provider(&self) -> Provider {
        self.0.provider
    }
    /// Diagnostic allocation only, never a wire RID.
    #[must_use]
    pub fn allocation(&self) -> u64 {
        self.0.serial
    }
    /// Permanently revoke new use after actual source loss/close. This does not
    /// retire already admitted native jobs; their original receipts remain due.
    pub fn lost(&self) {
        self.0.live.set(false);
    }
    /// Whether this original source still permits new provider admission.
    #[must_use]
    pub fn is_live(&self) -> bool {
        self.0.live.get()
    }
}
impl fmt::Debug for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReclaimSource")
            .field("provider", &self.provider())
            .field("allocation", &self.allocation())
            .finish()
    }
}
pub(super) struct Domain {
    pub _private: u8,
}
/// Exact original prepared provider operation. Private local brand/generation
/// is never serialized or interpreted as proof of a network/crypto outcome.
#[derive(Clone)]
pub struct Effect {
    pub(super) domain: Rc<Domain>,
    pub(super) serial: u64,
}
impl PartialEq for Effect {
    fn eq(&self, o: &Self) -> bool {
        Rc::ptr_eq(&self.domain, &o.domain) && self.serial == o.serial
    }
}
impl Eq for Effect {}
impl fmt::Debug for Effect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ReclaimEffect").field(&self.serial).finish()
    }
}
/// Actual purpose of one original GNS effect; no label/type heuristic or wire field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LookupKind {
    /// Initial mutable ticket authorization capability lookup.
    Authorization,
    /// One actual referenced attribute lookup after original authorization.
    Attribute,
}
/// Original immutable app-output identity, separate from provider success.
#[derive(Clone)]
pub struct Output {
    pub(super) domain: Rc<Domain>,
    pub(super) serial: u64,
}
impl PartialEq for Output {
    fn eq(&self, o: &Self) -> bool {
        Rc::ptr_eq(&self.domain, &o.domain) && self.serial == o.serial
    }
}
impl Eq for Output {}
impl fmt::Debug for Output {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ReclaimOutput").field(&self.serial).finish()
    }
}
/// Actual original native exposure, never a backend result or remote ACK.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Exposure {
    /// No byte exposed.
    Unsent,
    /// Actual immutable prefix.
    Partial {
        /// Actual positive byte count.
        bytes: usize,
    },
    /// Whole immutable original request written locally.
    Written {
        /// Original full request byte count.
        bytes: usize,
    },
}
/// One required real effect. All borrowed key/object bytes are explicit and
/// sensitive; formatting this enum never reveals their contents.
pub enum Action<'a> {
    /// Obtain the actual issuer typed public key from the exact original private key.
    PublicKey {
        /// Original secret borrow.
        key: SecretKeyView<'a>,
    },
    /// Produce a fresh, unpredictable nonzero32byte identifier.
    Identifier,
    /// Start a bounded real NAMESTORE snapshot iterator (all records, maintenance
    /// included). Feed each actual row, then complete only on actual provider END.
    Scan {
        /// Original authority.
        key: SecretKeyView<'a>,
    },
    /// Replace one entire actual NAMESTORE label. Native owner must send one complete
    /// STORE with single_tx=1 and retain the original receipt; no fake transaction.
    Store {
        /// Original authority.
        key: SecretKeyView<'a>,
        /// Exact generated/observed label, without NUL.
        label: &'a [u8],
        /// Whole canonical record set, possibly empty for deletion.
        records: Records<'a>,
    },
    /// Actual scoped GNS lookup using the existing client port.
    Lookup {
        /// Parsed capability issuer.
        zone: ZoneKey,
        /// Exact one-label lookup, without its .ztld suffix.
        label: &'a [u8],
        /// ANY is0; ticket auth requires TXT+refs+presentations.
        record_type: RecordType,
    },
    /// Actual plugin presentation. JWT may simply preserve all original bytes;
    /// selected attributes do not imply selective disclosure or verification.
    Presentation {
        /// Credential from the original real NAMESTORE scan.
        credential: Credential<'a>,
        /// Original issue selection.
        selected: AttributeList<'a>,
    },
}
impl fmt::Debug for Action<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublicKey { .. } => f.write_str("PublicKey([REDACTED])"),
            Self::Identifier => f.write_str("Identifier"),
            Self::Scan { .. } => f.write_str("Scan([REDACTED])"),
            Self::Store { records, .. } => f
                .debug_struct("Store")
                .field("records", &records.count())
                .field("contents", &"[REDACTED]")
                .finish(),
            Self::Lookup { record_type, .. } => f
                .debug_struct("Lookup")
                .field("record_type", record_type)
                .field("name", &"[REDACTED]")
                .finish(),
            Self::Presentation { credential, .. } => f
                .debug_struct("Presentation")
                .field("kind", &credential.kind)
                .field("contents", &"[REDACTED]")
                .finish(),
        }
    }
}
/// Borrow one immutable exact prepared provider action.
#[derive(Debug)]
pub struct Prepared<'a> {
    /// Exact local operation.
    pub effect: &'a Effect,
    /// Original finite absolute caller monotonic deadline.
    pub deadline: u64,
    /// Required actual provider action.
    pub action: Action<'a>,
}
/// One actual provider completion. Trusted adapters must bind this data to the
/// exact admitted native operation/source; raw bytes are not a signature proof.
#[derive(Debug)]
pub enum Completion<'a> {
    /// Actual key-derivation result.
    PublicKey(ZoneKey),
    /// Actual entropy result.
    Identifier(Identifier),
    /// Actual original NAMESTORE scan END.
    ScanEnd,
    /// Original complete scoped GNS result (absence stays absence).
    Records(Records<'a>),
    /// Actual original NAMESTORE status, success only code0.
    Stored(u32),
    /// Actual presentation preserving original credential id/kind.
    Presentation(Presentation<'a>),
    /// Actual definite provider refusal without success.
    Failed(Error),
    /// Provider write outcome is genuinely indeterminate.
    Unknown,
}
/// Local termination/status independent of the official response layout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum End {
    /// Actual completed business operation or natural iterator END.
    Complete,
    /// Actual provider failure.
    Failed(Error),
    /// Caller cancellation; prior provider effects may have committed.
    Cancelled,
    /// Original absolute logical deadline.
    Deadline,
    /// Original provider source lost; no automatic replay.
    SourceLost,
    /// An admitted write is indeterminate.
    Unknown,
}
/// Borrow an immutable official response; expose key/record payload only through
/// its typed checked view, never Debug of a complete secret-containing frame.
pub struct ResponseView<'a> {
    /// Exact original output identity.
    pub output: &'a Output,
    /// Actual response serialized once in zeroizing storage.
    pub bytes: &'a Blob,
}
impl<'a> ResponseView<'a> {
    /// Decode the exact actual prepared official response.
    pub fn response(&self) -> Result<Response<'a>, Error> {
        Response::decode(self.bytes.expose())
    }
}
/// Original progress accounting retained across partial failure/cancellation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Status {
    /// Terminal local/business state, if any.
    pub end: Option<End>,
    /// Actual successful provider writes, never rolled back by cancel.
    pub committed_stores: usize,
    /// One actual native operation still needs physical retirement.
    pub provider_debt: bool,
    /// One app response is prepared/queued/exposed, not remotely consumed.
    pub output_debt: bool,
    /// Last actual original provider exposure, including after its retirement.
    pub exposure: Exposure,
    /// Last actual NAMESTORE status, preserved raw even on failure/late cancel.
    pub provider_code: Option<u32>,
    /// An actual admitted provider outcome was indeterminate, even if a caller
    /// cancellation/deadline was already the first terminal business reason.
    pub outcome_unknown: bool,
}
pub(super) fn request_key<'a>(request: Request<'a>) -> Option<SecretKeyView<'a>> {
    match request {
        Request::StoreAttribute { key, .. }
        | Request::StoreCredential { key, .. }
        | Request::DeleteAttribute { key, .. }
        | Request::DeleteCredential { key, .. }
        | Request::IterateStart { key, .. }
        | Request::IssueTicket { key, .. }
        | Request::RevokeTicket { key, .. } => Some(key),
        _ => None,
    }
}
