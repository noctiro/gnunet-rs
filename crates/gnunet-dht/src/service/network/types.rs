//! Original peer/work capabilities and finite network resource policies.
use super::super::{Brand, ClientId, QueryId};
use crate::routing::Estimate;
use gnunet_block::bloom::NativeEndian;
use gnunet_types::Error;
use gnunet_wire::official::{
    HEADER_LEN, core as core_wire,
    dht::{PUT_FIXED_LEN, RouteOptions},
};

/// An original authenticated underlay source admitted by its native owner.
/// An identity or diagnostic serial cannot reconstruct this token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Peer<'id> {
    pub(super) brand: Brand<'id>,
    pub(super) serial: u64,
}
impl Peer<'_> {
    /// Local diagnostic serial, without connection authority.
    #[must_use]
    pub const fn diagnostic(self) -> u64 {
        self.serial
    }
}
/// One accepted original local PUT not yet handed to any native FIFO.
/// It outlives the submitting client connection; it cannot be reconstructed
/// from a key, public identity, diagnostic serial or a replacement source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PutId<'id> {
    pub(super) brand: Brand<'id>,
    pub(super) serial: u64,
}
impl PutId<'_> {
    /// Original diagnostic serial, without admission or replay authority.
    #[must_use]
    pub const fn diagnostic(self) -> u64 {
        self.serial
    }
}
/// Read-only original unsubmitted PUT metadata. Native owners bind its hard
/// once, using the same anchor captured before local request admission.
#[derive(Clone, Copy, Debug)]
pub struct PutInfo<'id> {
    /// Original accepted intent.
    pub put: PutId<'id>,
    /// Original submitting source, possibly already disconnected.
    pub client: ClientId<'id>,
    /// Original canonical acceptance time, never the latest retry time.
    pub accepted: u64,
    /// Original block expiration, not a newly extended cache lease.
    pub expiration: u64,
    /// Earlier of original retention bound and original expiration.
    pub until: u64,
}
/// One original unsubmitted PUT whose current installed BLOCK validation
/// rejected it. No native submission, successful replication or empty result.
#[derive(Clone, Copy, Debug)]
pub struct PutFailure<'id> {
    /// Original accepted source/intent/time metadata, not recreated authority.
    pub info: PutInfo<'id>,
    /// Actual semantic BLOCK refusal; allocation/provider errors stay errors.
    pub reason: Error,
}
/// Bounded cumulative facts. Submission means actual original native FIFO
/// admission, not writing, remote processing, storage or replication success.
#[derive(Clone, Copy, Debug, Default)]
pub struct PutStats {
    /// Original local PUT intents accepted once.
    pub accepted: u64,
    /// Intents whose first original frame actually entered a native FIFO.
    pub submitted: u64,
    /// Original unsubmitted intents retired at their fixed bound.
    pub expired: u64,
    /// Intents retired after actual current BLOCK validation rejected them.
    pub rejected: u64,
    /// Original unsubmitted intents abandoned by explicit permanent shutdown.
    pub closed: u64,
    /// Current actual original intent count, not completed remote writes.
    pub retained: usize,
    /// Actual retained original payload Vec capacities.
    pub payload_bytes: usize,
}
/// One original outbound frame/signature operation bound to this service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Job<'id> {
    pub(super) brand: Brand<'id>,
    pub(super) serial: u64,
}
impl Job<'_> {
    /// Diagnostic serial, never a substitute for the original job.
    #[must_use]
    pub const fn diagnostic(self) -> u64 {
        self.serial
    }
}
/// Trusted constructor classification of one original P2P job. This metadata
/// neither authenticates a peer nor reconstructs a Job capability from a number.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobKind {
    /// Forwarded lookup request.
    Get,
    /// Forwarded storage request.
    Put,
    /// Locally produced or forwarded response; highest DHT transmission class.
    Result,
}
/// Native handoff, not wire transmission, remote processing or replication ACK.
pub enum Work<'a, 'id> {
    /// Sign exact purpose6 material using the original local PILS identity.
    Sign {
        /// Original job.
        job: Job<'id>,
        /// Original destination source.
        peer: Peer<'id>,
        /// Exact complete original P2P frame length, allowing the host to bind
        /// a suitable actual carrier before it admits this signature.
        frame_bytes: usize,
        /// Exact144-byte purpose header/time/hash/predecessor/successor material.
        material: &'a [u8; crate::path::SIGNED_LEN],
        /// Original finite target; native/canonical gates must precede admission.
        until: u64,
    },
    /// Atomically admit this exact frame to the original underlay FIFO. Calling
    /// `admitted` is allowed only after that native owner retains the full frame.
    Send {
        /// Original job.
        job: Job<'id>,
        /// Original destination source, not a replacement connection.
        peer: Peer<'id>,
        /// Original constructor class, preserved through signing and native
        /// selection without decoding or changing the frame.
        kind: JobKind,
        /// Complete official P2P frame, without a private envelope.
        frame: &'a [u8],
        /// Original finite target, never refreshed by a repeated peek.
        until: u64,
    },
    /// Stop an already issued original signing operation and report its actual
    /// terminal retirement before releasing this job's tombstone.
    Retire {
        /// Original issued job.
        job: Job<'id>,
        /// Original destination, which may already be disconnected.
        peer: Peer<'id>,
    },
}
/// Result of a genuine original signature callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Signed {
    /// Verified signature enabled the same original frame for admission.
    Ready,
    /// Original work was canceled/expired; its actual callback retired the debt.
    Retired,
}
/// Read-only original work metadata for the containing native owner. This is
/// neither a provider admission nor a reconstructed send/retirement receipt.
#[derive(Clone, Copy, Debug)]
pub struct JobInfo<'id> {
    /// Actual original core job capability.
    pub job: Job<'id>,
    /// Actual original peer-source capability.
    pub peer: Peer<'id>,
    /// Original fixed canonical target.
    pub until: u64,
    /// Actual provider admission has been reported for this signing job.
    pub issued: bool,
    /// This original work may only retire, never start a new effect.
    pub retiring: bool,
    /// Original unsubmitted local PUT, if this job belongs to that intent.
    /// After any FIFO admission the intent retires permanently, while already
    /// prepared sibling jobs keep their original native debt independently.
    pub put: Option<PutId<'id>>,
}
/// Maximum complete PUT frame bytes deliverable by the selected underlay.
/// This is a size policy, not source, signing, admission or remote authority.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PutFrameLimit(usize);
impl PutFrameLimit {
    /// Wire representability only; the host must still apply the actual
    /// carrying endpoint limit before admission and every native handoff.
    pub const WIRE: Self = Self(u16::MAX as usize);
    /// Default CORE profile: one `DHT_CORE` header inside one strictly smaller
    /// than `REMOTE_REQUEST_LIMIT` remote session message. Default IPC framing
    /// permits this size; smaller configured IPC bounds are applied separately.
    pub const CORE: Self = Self(core_wire::REMOTE_REQUEST_LIMIT - 1 - HEADER_LEN);
    /// Select a complete underlay PUT-frame bound representable on the wire.
    pub fn new(bytes: usize) -> Result<Self, Error> {
        if !(PUT_FIXED_LEN..=usize::from(u16::MAX)).contains(&bytes) {
            return Err(Error::InvalidInput);
        }
        Ok(Self(bytes))
    }
    /// Derive the actual DHT PUT limit from a native CORE client's individual
    /// IPC-frame bound, not its aggregate queue/source budgets. `CORE_SEND` adds
    /// `SEND_PREFIX`, and its single `DHT_CORE` inner message adds `HEADER_LEN`.
    /// The remote session requires that single inner message to be strictly
    /// smaller than `REMOTE_REQUEST_LIMIT` even though its aggregate may equal it.
    pub fn from_core_frame_bytes(frame_bytes: usize) -> Result<Self, Error> {
        if frame_bytes > usize::from(u16::MAX) {
            return Err(Error::InvalidInput);
        }
        let messages = frame_bytes
            .checked_sub(core_wire::SEND_PREFIX)
            .ok_or(Error::TooLarge)?
            .min(core_wire::MAX_SEND_BYTES)
            .min(core_wire::REMOTE_REQUEST_LIMIT - 1);
        let bytes = messages.checked_sub(HEADER_LEN).ok_or(Error::TooLarge)?;
        if bytes < PUT_FIXED_LEN {
            return Err(Error::TooLarge);
        }
        Self::new(bytes)
    }
    /// Maximum complete original PUT frame, without its DHT_CORE/IPC wrappers.
    #[must_use]
    pub const fn bytes(self) -> usize {
        self.0
    }
}
/// Explicit finite bounded policies; logical query ownership may outlive a retry.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Admitted original peer sources.
    pub peers: usize,
    /// Reverse query routes retained from peers.
    pub routes: usize,
    /// Complete original frames/signing debts, including issued tombstones.
    pub output_frames: usize,
    /// Total bytes of those original complete frames.
    pub output_bytes: usize,
    /// Exact maximum individual PUT frame; path fitting never uses `output_bytes`.
    pub put_frame_limit: PutFrameLimit,
    /// Held original P2P GET/PUT monitor fanouts, including ready output.
    pub monitor_fanouts: usize,
    /// Held recipient frames across those fanouts, separate from local results.
    pub monitor_frames: usize,
    /// Actual held monitor-frame allocation capacities, not per-peer payload copies.
    pub monitor_bytes: usize,
    /// Original accepted PUT intents waiting for their first native admission.
    pub unrouted_puts: usize,
    /// Actual total retained payload capacities of those intents.
    pub unrouted_put_bytes: usize,
    /// Fixed retention from original local acceptance, capped by block expiry.
    pub unrouted_put_lifetime_micros: u64,
    /// Retry spacing only while no frame was submitted; new peers wake it early.
    pub unrouted_put_retry_micros: u64,
    /// Per-route extended query bytes.
    pub extended_query_bytes: usize,
    /// Per-route filter byte bound, including unchanged opaque serialized bytes.
    pub filter_bytes: usize,
    /// Initial filter byte policy when no serialized peer group is supplied.
    pub initial_filter_bytes: usize,
    /// Exact payload hashes per reverse route when its filter codec or the
    /// candidate type is unavailable. Allocated on demand; total hash storage
    /// is bounded by `routes * opaque_seen_hashes * 64` bytes of elements.
    pub opaque_seen_hashes: usize,
    /// Maximum metadata entries in one carried route path.
    pub path_entries: usize,
    /// Total retained cache signed-path Vec capacities, separate from payload
    /// `service::Limits::cache_bytes` and fixed cache entry metadata.
    pub cache_path_bytes: usize,
    /// Original reverse-route retention from initial admission; repeated GETs
    /// merge filters without extending this time.
    pub route_lifetime_micros: u64,
    /// Fixed lifetime of one outbound operation; no poll or clock revision renews it.
    pub operation_lifetime_micros: u64,
    /// Actual local GET retry period, after the prior attempt's handoff.
    pub retry_micros: u64,
    /// Eligible original sources per XOR bucket.
    pub bucket_size: usize,
    /// Explicit native BLOCK group serialization profile.
    pub group_profile: NativeEndian,
    /// Cache validated incoming results as well as ordinary PUT blocks.
    pub cache_results: bool,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            peers: 256,
            routes: 4096,
            output_frames: 256,
            output_bytes: 8 * 1024 * 1024,
            put_frame_limit: PutFrameLimit::CORE,
            monitor_fanouts: 256,
            monitor_frames: 128,
            monitor_bytes: 1024 * 1024,
            unrouted_puts: 1024,
            unrouted_put_bytes: 8 * 1024 * 1024,
            unrouted_put_lifetime_micros: 5 * 60 * 1_000_000,
            unrouted_put_retry_micros: 5_000_000,
            extended_query_bytes: 65535,
            filter_bytes: 32768,
            initial_filter_bytes: 64,
            opaque_seen_hashes: 128,
            path_entries: 512,
            cache_path_bytes: 8 * 1024 * 1024,
            route_lifetime_micros: 5 * 60 * 1_000_000,
            operation_lifetime_micros: 30 * 1_000_000,
            retry_micros: 1_000_000,
            bucket_size: 4,
            group_profile: NativeEndian::native(),
            cache_results: true,
        }
    }
}
impl Limits {
    pub(super) fn validate(self) -> Result<(), Error> {
        if self.peers == 0
            || self.routes == 0
            || self.output_frames == 0
            || self.output_bytes < 208
            || self.monitor_fanouts == 0
            || self.monitor_frames == 0
            || self.monitor_bytes < 88
            || self.unrouted_puts == 0
            || self.unrouted_puts > 65_535
            || self.unrouted_put_bytes == 0
            || self.unrouted_put_lifetime_micros > 5 * 60 * 1_000_000
            || self.unrouted_put_retry_micros > 5_000_000
            || self.filter_bytes > 65531
            || self.initial_filter_bytes > self.filter_bytes
            || self.opaque_seen_hashes == 0
            || self
                .routes
                .checked_mul(self.opaque_seen_hashes)
                .and_then(|n| n.checked_mul(64))
                .is_none_or(|n| n > isize::MAX as usize)
            || self.bucket_size == 0
            || self.path_entries > u16::MAX as usize
            || [
                self.route_lifetime_micros,
                self.operation_lifetime_micros,
                self.retry_micros,
                self.unrouted_put_lifetime_micros,
                self.unrouted_put_retry_micros,
            ]
            .iter()
            .any(|n| *n == 0 || *n == u64::MAX)
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
}
/// Current finite NSE policy. Updating an estimate never recreates a source/job.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    /// Real configured/observed logarithmic network-size estimate.
    pub estimate: Estimate,
}
/// Explicit outcome of one original peer request, not a native send ACK.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// Valid GET was processed under the bounded reverse-route and terminal
    /// result policy; a terminal cache reply does not retain a pending route.
    Get,
    /// An absent concrete type's GET retained its original opaque XQUERY/filter
    /// and reverse route, without semantic query validation or cache matches.
    OpaqueGet,
    /// Valid PUT was processed under storage/forwarding policy.
    Put,
    /// A complete P2P PUT with no installed type handler was processed only
    /// for opaque transit. This asserts no payload validity, cache admission,
    /// local query match, native FIFO handoff or remote replication success.
    OpaquePut,
    /// Valid original RESULT was delivered/routed with all bounded transitions admitted.
    Result,
    /// A valid installed-type RESULT had no live pending query. Independent
    /// monitor observation was retained, with no cache or query delivery.
    /// The native host may still consider a HELLO for discovery.
    UnmatchedResult,
    /// An absent concrete type's RESULT was correlated/routed as opaque bytes
    /// with exact duplicate history. No validity, trusted cache or Last verdict.
    OpaqueResult,
    /// An absent-type RESULT had no live pending query. Only independent
    /// monitor observation was retained; this asserts no payload validity,
    /// trusted cache admission or query delivery.
    OpaqueUnmatchedResult,
    /// Genuine expired block was ignored.
    Expired,
}
/// Bounded current state, never physical underlay quiescence or remote durability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    /// Original peer-source count.
    pub peers: usize,
    /// Live reverse routes.
    pub routes: usize,
    /// Retained original outbound/signature debts.
    pub jobs: usize,
    /// Complete retained frame charge.
    pub bytes: usize,
    /// Actual retained cache path allocation capacities, independently bounded.
    pub cache_path_bytes: usize,
    /// Held original P2P monitor groups, whether unresolved or ready.
    pub monitor_fanouts: usize,
    /// Their held original recipient-frame count.
    pub monitor_frames: usize,
    /// Their actual retained frame allocation capacities.
    pub monitor_bytes: usize,
    /// Original local PUT intents that have not entered any native FIFO.
    pub unrouted_puts: usize,
    /// Their actual retained payload allocation capacities.
    pub unrouted_put_bytes: usize,
    /// Already issued signature jobs requiring real terminal callbacks.
    pub issued: usize,
    /// Permanent stop forbids new work.
    pub closed: bool,
}
pub(super) struct PeerRow<'id> {
    pub token: Peer<'id>,
    pub identity: [u8; 32],
}
pub(super) struct Retry<'id> {
    pub client: ClientId<'id>,
    pub query: QueryId<'id>,
    pub at: u64,
}
pub(super) struct Route<'id> {
    pub peer: Peer<'id>,
    pub key: [u8; 64],
    pub kind: u32,
    pub options: RouteOptions,
    pub xquery: alloc::vec::Vec<u8>,
    pub filter: super::Filter,
    pub until: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PutBlocked {
    pub frames: usize,
    pub bytes: usize,
    pub revision: u64,
}
pub(super) struct UnroutedPut<'id> {
    pub id: PutId<'id>,
    pub client: ClientId<'id>,
    pub accepted: u64,
    pub until: u64,
    pub expiration: u64,
    pub at: u64,
    pub blocked: Option<PutBlocked>,
    pub key: [u8; 64],
    pub kind: u32,
    pub options: RouteOptions,
    pub replication: u32,
    pub payload: alloc::vec::Vec<u8>,
}
impl<'id> UnroutedPut<'id> {
    pub fn info(&self) -> PutInfo<'id> {
        PutInfo {
            put: self.id,
            client: self.client,
            accepted: self.accepted,
            expiration: self.expiration,
            until: self.until,
        }
    }
}
