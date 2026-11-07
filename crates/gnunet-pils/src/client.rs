//! Allocation-free typed PILS client decisions over official IPC1831..1838.
//!
//! The host owns MQ creation, immutable partial-write copies, clock samples and
//! retry timers. It must preserve frame order, call `written` after full writes,
//! and retire an MQ after protocol/announcement validation errors. Output is
//! never a processing/durability acknowledgement. No local token enters the wire.
mod owner;
mod storage;
#[cfg(feature = "alloc")]
pub use storage::HeapBytes;
pub use storage::{ByteStorage, InlineBytes};
/// Optional native storage profile, with bounded metadata and exact-length
/// heap requests/HELLO cache. It shares the same sans-I/O owner and wire rules.
#[cfg(feature = "alloc")]
pub type HeapClient<'a, const O: usize = 32> = Client<'a, O, 65535, 65535, HeapBytes, HeapBytes>;
use crate::{ActiveIdentity, HelloLimits, MasterKey, Profile};
use gnunet_crypto::{EddsaPublicKey, EddsaSignature, hash512};
use gnunet_hello::{Hello, HelloBuilder, SignatureCoverage};
use gnunet_types::Error;
use gnunet_wire::official::{
    AbsoluteTime, Frame, SignaturePurpose, message_type as mt,
    pils::{PeerUpdate, Request, Response},
};
use owner::Brand;
pub use owner::{Epoch, Instance, OperationId, TransmitId};
use zeroize::{Zeroize, Zeroizing};

/// Official request family; FEED has neither request number nor response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationKind {
    /// Sign one exact purpose region.
    Sign,
    /// DHKEM decapsulation.
    Decapsulate,
    /// Legacy hashed ECDH.
    Ecdh,
    /// Unsigned address update, with local submission reporting only.
    Feed,
}
/// Public identity verified under this client's one explicit source profile.
/// Normal Reference029 authenticates metadata only, not its advertised addresses.
/// This is a local ordered-MQ observation, not global authorization or a dial capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Identity<'a> {
    epoch: Epoch<'a>,
    revision: u64,
    peer: EddsaPublicKey,
    peer_hash: [u8; 64],
    address_hash: [u8; 64],
    expiration: AbsoluteTime,
    coverage: SignatureCoverage,
}
impl<'a> Identity<'a> {
    /// Actual HELLO public identity.
    #[must_use]
    pub const fn peer(self) -> EddsaPublicKey {
        self.peer
    }
    /// Official SHA512(public peer identity), distinct from its address context.
    #[must_use]
    pub const fn peer_hash(self) -> [u8; 64] {
        self.peer_hash
    }
    /// Verified address derivation context under the selected source profile.
    #[must_use]
    pub const fn address_hash(self) -> [u8; 64] {
        self.address_hash
    }
    /// HELLO expiration, checked against the caller's UTC at announcement receipt.
    #[must_use]
    pub const fn expiration(self) -> AbsoluteTime {
        self.expiration
    }
    /// Exact authenticated coverage; metadata-only grants no address authority.
    #[must_use]
    pub const fn coverage(self) -> SignatureCoverage {
        self.coverage
    }
    /// Original MQ observation, never a private wire field.
    #[must_use]
    pub const fn epoch(self) -> Epoch<'a> {
        self.epoch
    }
    /// Local announcement revision, not a key identifier on the wire.
    #[must_use]
    pub const fn revision(self) -> u64 {
        self.revision
    }
}
/// Explicit key intent. Crypto requests may be queued while disconnected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyTarget<'a> {
    /// Use the service's key at processing. KEM/DH replies carry no peer field:
    /// their context is the last verified announcement on the same ordered MQ,
    /// not an independently verified cryptographic identity in the result.
    ServiceCurrent,
    /// Bind key identity to this client's current verified announcement.
    /// Pending operations survive reconnect when that same public key returns;
    /// a changed key fails the original operation instead of mislabelling bytes.
    Exact(Identity<'a>),
}
/// Explicit state of optional local private-key access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalKeyStatus {
    /// No local initial key material was supplied.
    Disabled,
    /// Await a verified announcement on the current MQ.
    Waiting,
    /// Derived public identity matches the announced peer.
    Matched,
    /// Supplied master differs; no local key is published. Service requests work.
    Mismatch,
}
/// Owned secret result, erased on drop. No Clone or Debug is implemented.
///
/// ```compile_fail
/// fn print_secret(key: gnunet_pils::client::Secret<32>) { let _ = format!("{key:?}"); }
/// ```
///
/// ```compile_fail
/// fn clone_secret(key: gnunet_pils::client::Secret<32>) { let _copy = key.clone(); }
/// ```
pub struct Secret<const N: usize>(Zeroizing<[u8; N]>);
impl<const N: usize> Secret<N> {
    /// Borrow only while retaining this original secret owner.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }
    /// Explicitly retire the material before dropping a retained result owner.
    pub fn erase(&mut self) {
        self.0.zeroize();
    }
}
/// A completed operation failure. Zero reference crypto results are not success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Failure {
    /// Official service returned its all-zero failure representation.
    CryptoRejected,
    /// Returned signature does not verify the exact retained purpose region.
    InvalidSignature,
    /// The observed/returned key differs from the explicitly requested key.
    KeyChanged,
    /// KEM/DH result has no verified preceding announcement on this MQ.
    IdentityUnavailable,
}
/// One consumed original result. Secret ownership is transferred to this value.
/// No result is cloneable or printable; caller retention lies outside Client's
/// bounded pending-operation storage. Cancellation cannot revoke an old result.
pub enum Completion<'a> {
    /// Independently verified signature, including the actual returned signer.
    Signature {
        /// Original operation.
        operation: OperationId<'a>,
        /// Actual signer, not silently replaced by current identity.
        peer: EddsaPublicKey,
        /// Verified signature over the original exact purpose bytes.
        signature: EddsaSignature,
        /// Present only when the latest announcement matches the signer.
        announced: Option<Identity<'a>>,
    },
    /// Owned DHKEM output; identity is an ordered MQ observation, not a wire tag.
    Decapsulated {
        /// Original operation.
        operation: OperationId<'a>,
        /// Last verified preceding service context.
        identity: Identity<'a>,
        /// Secret erased on drop.
        key: Secret<32>,
    },
    /// Owned legacy SHA512(X25519) output under the observed context.
    Ecdh {
        /// Original operation.
        operation: OperationId<'a>,
        /// Last verified preceding service context.
        identity: Identity<'a>,
        /// Secret erased on drop.
        key: Secret<64>,
    },
    /// One original operation completed without a successful crypto result.
    Failed {
        /// Original operation.
        operation: OperationId<'a>,
        /// Operation's actual family.
        kind: OperationKind,
        /// Explicit refusal.
        reason: Failure,
    },
}
impl<'a> Completion<'a> {
    /// Original typed owner/operation; numeric request numbers are not authority.
    #[must_use]
    pub const fn operation(&self) -> OperationId<'a> {
        match self {
            Self::Signature { operation, .. }
            | Self::Decapsulated { operation, .. }
            | Self::Ecdh { operation, .. }
            | Self::Failed { operation, .. } => *operation,
        }
    }
}
/// One received public update, consumed result or unknown/late response.
pub enum Inbound<'a> {
    /// A fully checked current HELLO and optional local-key decision.
    Identity {
        /// New current observation.
        identity: Identity<'a>,
        /// Whether the actual peer differs from the previous accepted peer.
        identity_changed: bool,
        /// Matching local key is published before this event.
        local_key: LocalKeyStatus,
    },
    /// Exactly one original completion.
    Complete(Completion<'a>),
    /// A structurally valid unknown, duplicate or canceled response was dropped.
    Ignored,
}
/// Immutable frame copied to the host's original output storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Outbound<'a> {
    /// Original logical operation.
    pub operation: OperationId<'a>,
    /// Lease required by `written`; it survives cancellation of the operation.
    pub transmit: TransmitId<'a>,
    /// Complete physical frame length. Host must retain any partial-write cursor.
    pub len: usize,
    /// Actual operation family.
    pub kind: OperationKind,
}
/// Local full-write fact only. FEED has no remote completion message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Written<'a> {
    /// Original operation, possibly already canceled.
    pub operation: OperationId<'a>,
    /// Actual family.
    pub kind: OperationKind,
    /// Whether cancellation already suppressed this operation.
    pub canceled: bool,
}
/// What the host can know about a FEED lost with its original MQ.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeedDisposition {
    /// No frame was copied to a host output lease.
    NotSubmitted,
    /// A copied output lease was lost; application is unknown.
    SubmissionUnknown,
}
/// One non-replayed FEED retired by a connection loss.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LostFeed<'a> {
    /// Original operation.
    pub operation: OperationId<'a>,
    /// Exact known submission boundary.
    pub disposition: FeedDisposition,
}
/// Bounded loss report; pure crypto requests remain retained for reconnect.
pub struct LossReport<'a, const O: usize> {
    feeds: [Option<LostFeed<'a>>; O],
    retained: usize,
}
impl<'a, const O: usize> LossReport<'a, O> {
    /// Only original, uncanceled FEED operations retired on this MQ.
    pub fn feeds(&self) -> impl Iterator<Item = LostFeed<'a>> + '_ {
        self.feeds.iter().flatten().copied()
    }
    /// Crypto operations retained with their exact original request bytes/rids.
    #[must_use]
    pub const fn retained(&self) -> usize {
        self.retained
    }
}
struct Operation<'a, R: ByteStorage> {
    id: OperationId<'a>,
    wire: Option<u32>,
    kind: OperationKind,
    request: R,
    len: usize,
    expected: Option<EddsaPublicKey>,
    written: Option<Epoch<'a>>,
}
#[derive(Clone, Copy)]
struct Lease<'a> {
    token: TransmitId<'a>,
    operation: OperationId<'a>,
    kind: OperationKind,
}
#[derive(Clone, Copy)]
enum Retry {
    Ready,
    At(AbsoluteTime),
    Connected,
    Registration,
    Closed,
}
struct EraseFrame<'a>(&'a mut [u8]);
impl Drop for EraseFrame<'_> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Bounded sans-I/O client owner. O bounds pending operations; F bounds each
/// immutable request; H bounds the public retained PEER_ID announcement.
/// Caller-provided HELLO scratch is public and may change on validation errors.
/// No registry allocator, global owner counter, unsafe code or background task.
pub struct Client<
    'a,
    const O: usize = 8,
    const F: usize = 2048,
    const H: usize = 4096,
    R: ByteStorage = InlineBytes<F>,
    A: ByteStorage = InlineBytes<H>,
> {
    brand: Brand<'a>,
    profile: Profile,
    limits: HelloLimits,
    operations: [Option<Operation<'a, R>>; O],
    next_operation: u64,
    next_wire: u64,
    next_epoch: u64,
    next_transmit: u64,
    next_revision: u64,
    epoch: Option<Epoch<'a>>,
    lease: Option<Lease<'a>>,
    retry: Retry,
    backoff: u64,
    identity: Option<Identity<'a>>,
    last_peer: Option<EddsaPublicKey>,
    announcement: A,
    announcement_len: usize,
    master: Option<MasterKey>,
    local: Option<ActiveIdentity>,
    local_status: LocalKeyStatus,
}
impl<'a, const O: usize, const F: usize, const H: usize, R: ByteStorage, A: ByteStorage>
    Client<'a, O, F, H, R, A>
{
    /// Construct without I/O. Initial connection is immediately ready. A
    /// resource refusal occurs before borrowing identity or admitting work.
    pub fn new(
        instance: &'a mut Instance,
        profile: Profile,
        limits: HelloLimits,
    ) -> Result<Self, Error> {
        if F < 40 || F > u16::MAX as usize || H < 176 || H > u16::MAX as usize {
            return Err(Error::Capacity);
        }
        Ok(Self {
            brand: Brand::new(instance),
            profile,
            limits,
            operations: core::array::from_fn(|_| None),
            next_operation: 0,
            next_wire: 0,
            next_epoch: 0,
            next_transmit: 0,
            next_revision: 0,
            epoch: None,
            lease: None,
            retry: Retry::Ready,
            backoff: 0,
            identity: None,
            last_peer: None,
            announcement: A::zeroed(0)?,
            announcement_len: 0,
            master: None,
            local: None,
            local_status: LocalKeyStatus::Disabled,
        })
    }
    fn open(&self) -> Result<(), Error> {
        if matches!(self.retry, Retry::Closed) {
            Err(Error::Stale)
        } else {
            Ok(())
        }
    }
    fn check_epoch(&self, epoch: Epoch<'a>) -> Result<(), Error> {
        self.open()?;
        if self.epoch == Some(epoch) {
            Ok(())
        } else {
            Err(Error::Stale)
        }
    }
    /// Current physical MQ authority, distinct from native socket attempts.
    #[must_use]
    pub const fn epoch(&self) -> Option<Epoch<'a>> {
        self.epoch
    }
    /// Whether the original reconnect is ready at this caller source time.
    #[must_use]
    pub const fn connection_needed(&self, now: AbsoluteTime) -> bool {
        match self.retry {
            Retry::Ready => true,
            Retry::At(at) => at.as_micros() != u64::MAX && now.as_micros() >= at.as_micros(),
            _ => false,
        }
    }
    /// Immediate ready queue is represented by zero; MAX means FOREVER. A ready
    /// reconnect cannot be delayed by a later source-clock rollback.
    #[must_use]
    pub const fn next_wakeup(&self) -> Option<AbsoluteTime> {
        match self.retry {
            Retry::Ready => Some(AbsoluteTime::from_micros(0)),
            Retry::At(at) => Some(at),
            _ => None,
        }
    }
    /// Attach a newly created original MQ; pending pure requests are replayable.
    pub fn begin_connection(&mut self, now: AbsoluteTime) -> Result<Epoch<'a>, Error> {
        self.open()?;
        if !self.connection_needed(now) {
            return Err(Error::NotReady);
        }
        let serial = self.next_epoch.checked_add(1).ok_or(Error::Overflow)?;
        let epoch = Epoch {
            serial,
            brand: self.brand,
        };
        self.next_epoch = serial;
        self.epoch = Some(epoch);
        self.retry = Retry::Connected;
        Ok(epoch)
    }
    fn schedule_retry(&mut self, now: AbsoluteTime) {
        self.retry = if self.backoff == 0 {
            Retry::Ready
        } else {
            Retry::At(AbsoluteTime::from_micros(
                now.as_micros().saturating_add(self.backoff),
            ))
        };
        self.backoff = if self.backoff == 0 {
            1000
        } else {
            self.backoff.saturating_mul(2).min(900_000_000)
        };
    }
    /// An MQ could not be created. No fictitious epoch or response is generated.
    pub fn connection_unavailable(&mut self, now: AbsoluteTime) -> Result<(), Error> {
        self.prepare_connection_unavailable(now)?;
        self.register_retry(now)
    }
    /// Retain an actual MQ-creation refusal before a separate source-time
    /// registration. No clock refusal may fabricate a physical connection loss.
    pub fn prepare_connection_unavailable(&mut self, now: AbsoluteTime) -> Result<(), Error> {
        self.open()?;
        if self.epoch.is_some() || !self.connection_needed(now) {
            return Err(Error::NotReady);
        }
        self.retry = Retry::Registration;
        Ok(())
    }
    /// Whether the original failure still needs a caller source-time registration.
    #[must_use]
    pub const fn retry_registration_pending(&self) -> bool {
        matches!(self.retry, Retry::Registration)
    }
    /// Register one original PILS retry after its physical retirement/effects.
    /// A host samples its canonical clock only after stopping old I/O; a refused
    /// sample leaves this registration pending and cannot resurrect that MQ.
    pub fn register_retry(&mut self, now: AbsoluteTime) -> Result<(), Error> {
        self.open()?;
        if !self.retry_registration_pending() {
            return Err(Error::NotReady);
        }
        self.schedule_retry(now);
        Ok(())
    }
    /// Retire this exact MQ and capture its already sampled retry time together.
    /// Hosts with fallible clock ports should use prepare_connection_lost then
    /// register_retry, after actually stopping the old attempt/stream/queue.
    pub fn connection_lost(
        &mut self,
        epoch: Epoch<'a>,
        now: AbsoluteTime,
    ) -> Result<LossReport<'a, O>, Error> {
        let report = self.prepare_connection_lost(epoch)?;
        self.register_retry(now)?;
        Ok(report)
    }
    /// Retire current authority and byte lease before any fallible clock sample.
    /// Pure crypto requests keep their original bytes/rids; FEED is not replayed.
    pub fn prepare_connection_lost(
        &mut self,
        epoch: Epoch<'a>,
    ) -> Result<LossReport<'a, O>, Error> {
        self.check_epoch(epoch)?;
        let mut feeds = [None; O];
        let mut retained = 0;
        for (i, slot) in self.operations.iter_mut().enumerate() {
            if let Some(op) = slot {
                if op.kind == OperationKind::Feed {
                    let submitted = self.lease.is_some_and(|lease| lease.operation == op.id);
                    feeds[i] = Some(LostFeed {
                        operation: op.id,
                        disposition: if submitted {
                            FeedDisposition::SubmissionUnknown
                        } else {
                            FeedDisposition::NotSubmitted
                        },
                    });
                    *slot = None;
                } else {
                    op.written = None;
                    retained += 1;
                }
            }
        }
        self.epoch = None;
        self.lease = None;
        self.identity = None;
        self.local = None;
        self.local_status = if self.master.is_some() {
            LocalKeyStatus::Waiting
        } else {
            LocalKeyStatus::Disabled
        };
        self.retry = Retry::Registration;
        Ok(LossReport { feeds, retained })
    }
    fn expected(&self, target: KeyTarget<'a>) -> Result<Option<EddsaPublicKey>, Error> {
        match target {
            KeyTarget::ServiceCurrent => Ok(None),
            KeyTarget::Exact(id) => {
                if self.identity == Some(id) && id.epoch.brand == self.brand {
                    Ok(Some(id.peer))
                } else {
                    Err(Error::Stale)
                }
            }
        }
    }
    fn admit(
        &mut self,
        kind: OperationKind,
        target: KeyTarget<'a>,
        request_len: usize,
        encode: impl FnOnce(Option<u32>, &mut [u8]) -> Result<usize, Error>,
    ) -> Result<OperationId<'a>, Error> {
        self.open()?;
        let expected = self.expected(target)?;
        let index = self
            .operations
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let serial = self.next_operation.checked_add(1).ok_or(Error::Overflow)?;
        let wire = if kind == OperationKind::Feed {
            None
        } else {
            Some(u32::try_from(self.next_wire).map_err(|_| Error::Overflow)?)
        };
        if request_len > F {
            return Err(Error::Capacity);
        }
        let mut request = R::zeroed(request_len)?;
        let len = encode(wire, &mut request)?;
        let id = OperationId {
            serial,
            brand: self.brand,
        };
        self.operations[index] = Some(Operation {
            id,
            wire,
            kind,
            request,
            len,
            expected,
            written: None,
        });
        self.next_operation = serial;
        if wire.is_some() {
            self.next_wire += 1;
        }
        Ok(id)
    }
    /// Original explicit announcement parsing policy.
    #[must_use]
    pub const fn hello_limits(&self) -> HelloLimits {
        self.limits
    }
    /// Actual dynamic request/announcement capacities. Inline backing is already
    /// covered by the fixed Client layout, and is not charged again here.
    pub fn retained_storage_bytes(&self) -> Result<usize, Error> {
        self.operations.iter().flatten().try_fold(
            self.announcement.retained_storage_bytes(),
            |bytes, operation| {
                bytes
                    .checked_add(operation.request.retained_storage_bytes())
                    .ok_or(Error::Overflow)
            },
        )
    }
    /// Queue the exact complete purpose region. Normal service check_sign
    /// rejects a header-only region; no native-endian/truncated length is used.
    pub fn sign(&mut self, region: &[u8], target: KeyTarget<'a>) -> Result<OperationId<'a>, Error> {
        if region.len() <= 8 {
            return Err(Error::InvalidInput);
        }
        self.admit(
            OperationKind::Sign,
            target,
            gnunet_wire::official::pils::sign_request_len(region.len())?,
            |wire, out| {
                Request::Sign {
                    request: wire.ok_or(Error::Malformed)?,
                    region,
                }
                .encode(out)
            },
        )
    }
    /// Queue the exact official purpose7/expiration/profile address hash region.
    pub fn sign_hello(
        &mut self,
        builder: &HelloBuilder<'_>,
        expiration: AbsoluteTime,
        target: KeyTarget<'a>,
    ) -> Result<OperationId<'a>, Error> {
        let hello = builder.with_signature(
            EddsaPublicKey::from_bytes([0; 32]),
            EddsaSignature::from_bytes([0; 64]),
            expiration,
        );
        self.sign(&hello.signed_payload(self.profile.hello())?, target)
    }
    /// Queue an official DHKEM request, retaining it while disconnected.
    pub fn decapsulate(
        &mut self,
        encapsulation: [u8; 32],
        target: KeyTarget<'a>,
    ) -> Result<OperationId<'a>, Error> {
        self.admit(OperationKind::Decapsulate, target, 40, |wire, out| {
            Request::Decapsulate {
                request: wire.ok_or(Error::Malformed)?,
                encapsulation,
            }
            .encode(out)
        })
    }
    /// Queue an official legacy hashed ECDH request.
    pub fn ecdh(
        &mut self,
        public: [u8; 32],
        target: KeyTarget<'a>,
    ) -> Result<OperationId<'a>, Error> {
        self.admit(OperationKind::Ecdh, target, 40, |wire, out| {
            Request::Ecdh {
                request: wire.ok_or(Error::Malformed)?,
                public,
            }
            .encode(out)
        })
    }
    /// Queue unsigned builder addresses on this live MQ. Scratch is public.
    /// Full write completes only local submission; no FEED result exists.
    pub fn feed_addresses(
        &mut self,
        epoch: Epoch<'a>,
        builder: &HelloBuilder<'_>,
        now: AbsoluteTime,
        scratch: &mut [u8],
    ) -> Result<OperationId<'a>, Error> {
        self.check_epoch(epoch)?;
        let hello = builder.with_signature(
            EddsaPublicKey::from_bytes([0; 32]),
            EddsaSignature::from_bytes([0; 64]),
            now,
        );
        let n = hello.encode_block(scratch)?;
        self.admit(
            OperationKind::Feed,
            KeyTarget::ServiceCurrent,
            n.checked_add(8).ok_or(Error::Overflow)?,
            |_, out| {
                Request::Feed {
                    block: &scratch[..n],
                }
                .encode(out)
            },
        )
    }
    /// Suppress exactly this pending operation and future replay. An already
    /// copied frame remains owned by its original TransmitId: finish it or close
    /// that MQ, never splice a partial frame or claim remote cancellation.
    pub fn cancel(&mut self, operation: OperationId<'a>) -> Result<(), Error> {
        self.open()?;
        if operation.brand != self.brand {
            return Err(Error::Stale);
        }
        let index = self
            .operations
            .iter()
            .position(|s| s.as_ref().is_some_and(|o| o.id == operation))
            .ok_or(Error::Stale)?;
        self.operations[index] = None;
        Ok(())
    }
    /// Whether this original operation has neither a logical result owner nor
    /// a copied transmit lease left in this client. Canceling a logical request
    /// alone does not retire an already copied/partial original frame. This can
    /// also be queried after close, which retires all original client work.
    pub fn operation_quiescent(&self, operation: OperationId<'a>) -> Result<bool, Error> {
        if operation.brand != self.brand {
            return Err(Error::Stale);
        }
        Ok(!self
            .operations
            .iter()
            .flatten()
            .any(|pending| pending.id == operation)
            && self.lease.is_none_or(|lease| lease.operation != operation))
    }
    /// Outstanding admitted operations, excluding canceled/completed ones.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.operations.iter().flatten().count()
    }
    /// Exact length of the next unleased original frame. Host may reserve queue
    /// metadata and allocate its final immutable body before taking that lease.
    pub fn next_request_len(&self, epoch: Epoch<'a>) -> Result<Option<usize>, Error> {
        self.check_epoch(epoch)?;
        if self.lease.is_some() {
            return Ok(None);
        }
        Ok(self
            .operations
            .iter()
            .flatten()
            .filter(|o| o.written != Some(epoch))
            .min_by_key(|o| o.id.serial)
            .map(|o| o.len))
    }
    /// Copy one next FIFO frame atomically. One byte lease may remain live;
    /// subsequent requests wait until written or original MQ loss. Caller output
    /// and all scheduling state are unchanged on a short-output refusal.
    pub fn next_request(
        &mut self,
        epoch: Epoch<'a>,
        out: &mut [u8],
    ) -> Result<Option<Outbound<'a>>, Error> {
        self.check_epoch(epoch)?;
        if self.lease.is_some() {
            return Ok(None);
        }
        let Some(op) = self
            .operations
            .iter()
            .flatten()
            .filter(|o| o.written != Some(epoch))
            .min_by_key(|o| o.id.serial)
        else {
            return Ok(None);
        };
        if out.len() < op.len {
            return Err(Error::Capacity);
        }
        let serial = self.next_transmit.checked_add(1).ok_or(Error::Overflow)?;
        let token = TransmitId { serial, epoch };
        let result = Outbound {
            operation: op.id,
            transmit: token,
            len: op.len,
            kind: op.kind,
        };
        out[..op.len].copy_from_slice(&op.request[..op.len]);
        self.lease = Some(Lease {
            token,
            operation: op.id,
            kind: op.kind,
        });
        self.next_transmit = serial;
        Ok(Some(result))
    }
    /// Commit the original complete local write exactly once. FEED is retired
    /// here; crypto operations still await their correctly typed server result.
    pub fn written(
        &mut self,
        epoch: Epoch<'a>,
        transmit: TransmitId<'a>,
    ) -> Result<Written<'a>, Error> {
        self.check_epoch(epoch)?;
        let lease = self
            .lease
            .filter(|l| l.token == transmit)
            .ok_or(Error::Stale)?;
        let slot = self
            .operations
            .iter_mut()
            .find(|s| s.as_ref().is_some_and(|o| o.id == lease.operation));
        let canceled = slot.is_none();
        if let Some(slot) = slot {
            if lease.kind == OperationKind::Feed {
                *slot = None;
            } else if let Some(op) = slot {
                op.written = Some(epoch);
            }
        }
        self.lease = None;
        Ok(Written {
            operation: lease.operation,
            kind: lease.kind,
            canceled,
        })
    }
    /// Current verified observation only after a checked announcement on this MQ.
    /// MQ loss invalidates it; previously returned public snapshots remain data.
    #[must_use]
    pub const fn identity(&self) -> Option<Identity<'a>> {
        self.identity
    }
    /// Last accepted public announcement, retained across MQ loss as cache data.
    /// It is not current identity authority; identity() becomes None on loss.
    #[must_use]
    pub fn last_announcement(&self) -> &[u8] {
        &self.announcement[..self.announcement_len]
    }
    /// Actual local-key status, published atomically with identity updates.
    #[must_use]
    pub const fn local_key_status(&self) -> LocalKeyStatus {
        self.local_status
    }
    /// Borrow a matched current local key. Rust prevents rotation/loss while the
    /// borrow is live; no secret key is exposed for a mismatched master.
    ///
    /// ```compile_fail
    /// use gnunet_pils::client::Client;
    /// fn close_while_borrowed(owner: &mut Client<'_>) {
    ///     let key = owner.local_key();
    ///     owner.close();
    ///     if let Some(key) = key { let _peer = key.public_key(); }
    /// }
    /// ```
    #[must_use]
    pub fn local_key(&self) -> Option<&ActiveIdentity> {
        self.local.as_ref()
    }
    /// Enable local key access from caller-owned persisted IKM, without file I/O.
    /// Mismatch retains service access but publishes no wrong private key.
    pub fn enable_local_key(&mut self, master: MasterKey) -> Result<LocalKeyStatus, Error> {
        self.open()?;
        let (local, status) = self.derive_local(&master, self.identity)?;
        self.master = Some(master);
        self.local = local;
        self.local_status = status;
        Ok(status)
    }
    /// Construct another explicit key owner only from a locally matched current
    /// announcement. Temporary active seed bytes are erased after the callback;
    /// deliberate copies returned by the constructor belong to that caller.
    pub fn with_active_seed<T>(&self, construct: impl FnOnce(&[u8; 32]) -> T) -> Result<T, Error> {
        if self.local_status != LocalKeyStatus::Matched {
            return Err(Error::NotReady);
        }
        let identity = self.identity.ok_or(Error::NotReady)?;
        self.master
            .as_ref()
            .ok_or(Error::NotReady)?
            .with_active_seed(&identity.address_hash, self.profile, construct)
    }
    fn derive_local(
        &self,
        master: &MasterKey,
        identity: Option<Identity<'a>>,
    ) -> Result<(Option<ActiveIdentity>, LocalKeyStatus), Error> {
        let Some(identity) = identity else {
            return Ok((None, LocalKeyStatus::Waiting));
        };
        let local = master.derive(&identity.address_hash, self.profile)?;
        if local.public_key() == identity.peer {
            Ok((Some(local), LocalKeyStatus::Matched))
        } else {
            Ok((None, LocalKeyStatus::Mismatch))
        }
    }
    /// Retire optional local IKM/private-key ownership. Public identity is kept.
    pub fn disable_local_key(&mut self) {
        self.local = None;
        self.master = None;
        self.local_status = LocalKeyStatus::Disabled;
    }
    fn update(
        &mut self,
        epoch: Epoch<'a>,
        update: PeerUpdate<'_>,
        bytes: &[u8],
        scratch: &mut [u8],
        now: AbsoluteTime,
    ) -> Result<Inbound<'a>, Error> {
        if bytes.len() > H {
            return Err(Error::Capacity);
        }
        let hello = Hello::parse_block(update.block, scratch, self.limits)?;
        let verified = hello.verify_at(self.profile.hello(), now)?;
        if hello.address_hash(self.profile.hello()) != update.hash {
            return Err(Error::Authentication);
        }
        let revision = self.next_revision.checked_add(1).ok_or(Error::Overflow)?;
        let identity = Identity {
            epoch,
            revision,
            peer: hello.peer(),
            peer_hash: hash512(hello.peer().as_bytes()),
            address_hash: update.hash,
            expiration: hello.expiration(),
            coverage: verified.coverage(),
        };
        let (local, status) = if let Some(master) = &self.master {
            self.derive_local(master, Some(identity))?
        } else {
            (None, LocalKeyStatus::Disabled)
        };
        let identity_changed = self.last_peer != Some(identity.peer);
        let mut announcement = A::zeroed(bytes.len())?;
        announcement[..bytes.len()].copy_from_slice(bytes);
        self.identity = Some(identity);
        self.last_peer = Some(identity.peer);
        self.next_revision = revision;
        self.local = local;
        self.local_status = status;
        self.announcement = announcement;
        self.announcement_len = bytes.len();
        self.backoff = 0;
        Ok(Inbound::Identity {
            identity,
            identity_changed,
            local_key: status,
        })
    }
    /// Consume an original complete response and erase its entire input frame on
    /// every return path, including malformed, stale, unknown or canceled keys.
    /// Host must preserve MQ frame order and report full write before responses.
    pub fn receive(
        &mut self,
        epoch: Epoch<'a>,
        frame: &mut [u8],
        scratch: &mut [u8],
        now: AbsoluteTime,
    ) -> Result<Inbound<'a>, Error> {
        let guard = EraseFrame(frame);
        self.check_epoch(epoch)?;
        let kind = Frame::decode(guard.0)?.header().message_type();
        // The official MQ ignores well-framed messages without a registered
        // handler. This is distinct from a malformed known response or an
        // unknown/late request number, and does not reset PILS backoff.
        if !matches!(
            kind,
            mt::PILS_PEER_ID | mt::PILS_SIGN_RESULT | mt::PILS_DECAPS_RESULT | mt::PILS_ECDH_RESULT
        ) {
            return Ok(Inbound::Ignored);
        }
        let response = Response::decode(guard.0)?;
        if let Response::PeerUpdate(update) = response {
            return self.update(epoch, update, guard.0, scratch, now);
        }
        self.backoff = 0;
        let (wire, kind) = match &response {
            Response::Signature { request, .. } => (*request, OperationKind::Sign),
            Response::Decapsulation { request, .. } => (*request, OperationKind::Decapsulate),
            Response::Ecdh { request, .. } => (*request, OperationKind::Ecdh),
            Response::PeerUpdate(_) => return Err(Error::Malformed),
        };
        let Some(index) = self
            .operations
            .iter()
            .position(|s| s.as_ref().is_some_and(|o| o.wire == Some(wire)))
        else {
            return Ok(Inbound::Ignored);
        };
        let op = self.operations[index].as_ref().ok_or(Error::Stale)?;
        if op.kind != kind {
            return Err(Error::Malformed);
        }
        if op.written != Some(epoch) {
            return Err(Error::NotReady);
        }
        let failed = |reason| Completion::Failed {
            operation: op.id,
            kind,
            reason,
        };
        let result = match response {
            Response::Signature {
                peer, signature, ..
            } => {
                let peer = EddsaPublicKey::from_bytes(peer);
                let signature = EddsaSignature::from_bytes(signature);
                if signature.as_bytes().iter().all(|b| *b == 0) {
                    failed(Failure::CryptoRejected)
                } else if op.expected.is_some_and(|p| p != peer) {
                    failed(Failure::KeyChanged)
                } else {
                    let region = &op.request[8..op.len];
                    let purpose = SignaturePurpose::decode(&region[..8])?;
                    if peer.verify(purpose.purpose(), region, &signature).is_err() {
                        failed(Failure::InvalidSignature)
                    } else {
                        Completion::Signature {
                            operation: op.id,
                            peer,
                            signature,
                            announced: self.identity.filter(|i| i.peer == peer),
                        }
                    }
                }
            }
            Response::Decapsulation { key, .. } => {
                if key.iter().all(|b| *b == 0) {
                    failed(Failure::CryptoRejected)
                } else if let Some(identity) = self.identity {
                    if op.expected.is_some_and(|p| p != identity.peer) {
                        failed(Failure::KeyChanged)
                    } else {
                        Completion::Decapsulated {
                            operation: op.id,
                            identity,
                            key: Secret(Zeroizing::new(*key)),
                        }
                    }
                } else {
                    failed(Failure::IdentityUnavailable)
                }
            }
            Response::Ecdh { key, .. } => {
                if key.iter().all(|b| *b == 0) {
                    failed(Failure::CryptoRejected)
                } else if let Some(identity) = self.identity {
                    if op.expected.is_some_and(|p| p != identity.peer) {
                        failed(Failure::KeyChanged)
                    } else {
                        Completion::Ecdh {
                            operation: op.id,
                            identity,
                            key: Secret(Zeroizing::new(*key)),
                        }
                    }
                } else {
                    failed(Failure::IdentityUnavailable)
                }
            }
            Response::PeerUpdate(_) => return Err(Error::Malformed),
        };
        self.operations[index] = None;
        Ok(Inbound::Complete(result))
    }
    /// Permanently close this original owner and return all still-admitted IDs.
    /// Request payloads and local secret owners are erased; no completion or
    /// server cancellation is invented. Repeated close yields no new IDs.
    pub fn close(&mut self) -> [Option<OperationId<'a>>; O] {
        let retired = core::array::from_fn(|i| self.operations[i].as_ref().map(|o| o.id));
        self.operations.iter_mut().for_each(|s| *s = None);
        self.epoch = None;
        self.lease = None;
        self.identity = None;
        self.disable_local_key();
        self.retry = Retry::Closed;
        retired
    }
}

#[cfg(test)]
mod exhaustion {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Exercise otherwise unreachable numeric exhaustion without billions of operations"
    )]
    use super::*;
    fn limits() -> HelloLimits {
        HelloLimits {
            maximum_input_bytes: 1024,
            maximum_address_bytes: 1024,
            maximum_addresses: 16,
        }
    }
    #[test]
    fn wire_id_exhaustion_refuses_new_work_without_reusing_or_dropping_old_requests()
    -> Result<(), Error> {
        let mut instance = Instance::new();
        let mut c = Client::<2, 40, 176>::new(&mut instance, Profile::Reference029, limits())?;
        c.next_wire = u64::from(u32::MAX);
        let last = c.ecdh([7; 32], KeyTarget::ServiceCurrent)?;
        assert_eq!(
            c.ecdh([8; 32], KeyTarget::ServiceCurrent),
            Err(Error::Overflow)
        );
        assert_eq!(c.pending(), 1);
        let e = c.begin_connection(AbsoluteTime::from_micros(0))?;
        let mut out = [0; 40];
        let tx = c.next_request(e, &mut out)?.ok_or(Error::NotReady)?;
        assert_eq!(tx.operation, last);
        assert!(matches!(
            Request::decode(&out)?,
            Request::Ecdh {
                request: u32::MAX,
                ..
            }
        ));
        c.written(e, tx.transmit)?;
        c.connection_lost(e, AbsoluteTime::from_micros(0))?;
        let next = c.begin_connection(AbsoluteTime::from_micros(0))?;
        let mut replay = [0; 40];
        let retry = c.next_request(next, &mut replay)?.ok_or(Error::NotReady)?;
        assert_eq!(retry.operation, last);
        assert_eq!(replay, out);
        c.cancel(last)?;
        assert_eq!(
            c.ecdh([9; 32], KeyTarget::ServiceCurrent),
            Err(Error::Overflow)
        );
        assert_eq!(c.pending(), 0);
        Ok(())
    }
    #[test]
    fn local_epoch_operation_and_transmit_exhaustion_is_atomic() -> Result<(), Error> {
        let mut instance = Instance::new();
        let mut c = Client::<2, 40, 176>::new(&mut instance, Profile::Reference029, limits())?;
        c.next_operation = u64::MAX;
        assert_eq!(
            c.ecdh([7; 32], KeyTarget::ServiceCurrent),
            Err(Error::Overflow)
        );
        assert_eq!(c.pending(), 0);
        assert_eq!(c.next_wire, 0);
        c.next_operation = 0;
        c.next_epoch = u64::MAX;
        assert_eq!(
            c.begin_connection(AbsoluteTime::from_micros(0)),
            Err(Error::Overflow)
        );
        assert!(c.epoch().is_none() && c.connection_needed(AbsoluteTime::from_micros(0)));
        c.next_epoch = 0;
        let e = c.begin_connection(AbsoluteTime::from_micros(0))?;
        c.ecdh([7; 32], KeyTarget::ServiceCurrent)?;
        c.next_transmit = u64::MAX;
        let mut out = [0xa5; 40];
        assert_eq!(c.next_request(e, &mut out), Err(Error::Overflow));
        assert_eq!(out, [0xa5; 40]);
        assert!(c.lease.is_none());
        assert_eq!(c.pending(), 1);
        Ok(())
    }
}
