//! Actual native own-address publication. Pure preparation/signature/policy is
//! reused; API-receipt assurance is separate from the managed Journal's durable
//! lifecycle. No Committed/Durable state is set from STORE_RESULT.
use crate::{
    Failure,
    generation::{self, Reservations},
    hello::{self, HelloSink},
    pils::Pils,
    time::Bounds,
    writer::{self, Writer},
};
use gnunet_crypto::{EddsaPublicKey, EddsaSignature};
use gnunet_hello::{AbsoluteTime, Hello, HelloBuilder, Limits as HelloLimits, SignatureProfile};
use gnunet_peerstore_client_host as ps;
use gnunet_pils::client::{Identity, OperationId};
use gnunet_transport::{
    addresses::{AddressLease, PublicationId},
    own::{Authority, Certificate, OfferId, PublicationBounds},
    signing::ValidationId,
};
use gnunet_transport_host::Server;
use gnunet_types::Error as Fault;
use std::time::Duration;
/// Original caller tags on the one actual PILS source.
#[derive(Clone)]
pub enum SignTask {
    /// Original purpose35 engine effect.
    Validation(ValidationId),
    /// Original actual ADD/certificate offer.
    Address {
        /// Original actual communicator ADD lease.
        lease: AddressLease,
        /// Original exact pure certificate/signature offer.
        offer: OfferId,
    },
    /// Actual resource FEED, including an empty set, with its publication id.
    Feed(PublicationId),
}
/// Original exact public STORE effect; no plain wire RID authorizes replacement.
#[derive(Clone)]
pub struct StoreTask {
    lease: AddressLease,
    offer: OfferId,
}
/// Original actual identity/resource revision for one public HELLO add.
pub struct HelloTask<'id> {
    publication: PublicationId,
    identity: Identity<'id>,
    bounds: Bounds,
    cache_expiry: u64,
    refresh_at: u64,
}
struct Row<'id> {
    certificate: Certificate,
    stamp: Option<generation::Request>,
    stamp_intent: Option<Bounds>,
    sign: Option<OperationId<'id>>,
    sign_bounds: Option<Bounds>,
    store: Option<ps::Operation<'id>>,
    store_offer: Option<OfferId>,
    store_bounds: Option<Bounds>,
    stored_by_service: bool,
    refresh: Option<u64>,
    retiring: bool,
}
struct Feed {
    publication: PublicationId,
    uris: Vec<u8>,
    bounds: Bounds,
}
struct HelloIntent<'id> {
    task: HelloTask<'id>,
    frame: Vec<u8>,
    expires: u64,
}
/// Explicit finite material/output policy. Existing pure policy owns forecast,
/// record bytes and refresh calculations; these bounds own native operations.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Actual source-owned ADD metadata slots.
    pub addresses: usize,
    /// Same bounded canonical public HELLO codec limits.
    pub hello: HelloLimits,
    /// The actual source's explicit official signature/address-coverage profile.
    pub signature_profile: SignatureProfile,
    /// Checked complete PILS/PEERSTORE envelope sizes.
    pub output: PublicationBounds,
    /// Original SIGN/STORE/FEED/HELLO operation budget.
    pub operation: Duration,
    /// Original HELLO STOP/suffix grace.
    pub retirement: Duration,
}
/// Actual independent projection of local live resources and native receipts.
pub struct Publications<'id> {
    rows: Vec<Row<'id>>,
    maximum: usize,
    authority: Authority,
    identity: Identity<'id>,
    limits: Limits,
    stamp_owner: Option<AddressLease>,
    feed: Option<Feed>,
    feed_operation: Option<OperationId<'id>>,
    hello: Option<HelloIntent<'id>>,
    hello_running: bool,
    hello_until: Option<u64>,
    hello_publication: Option<PublicationId>,
    refresh_feed: Option<u64>,
    scratch: Vec<u8>,
}
fn allocate(n: usize) -> Result<Vec<u8>, Fault> {
    let mut out = Vec::new();
    out.try_reserve_exact(n).map_err(|_| Fault::Capacity)?;
    out.resize(n, 0);
    Ok(out)
}
fn temporary(e: Fault) -> bool {
    matches!(e, Fault::Capacity | Fault::WouldBlock | Fault::NotReady)
}
impl<'id> Publications<'id> {
    /// Bind only after a real original-source PILS identity observation. This
    /// type loads no key, accesses no private seed and creates no socket/store.
    pub fn new(identity: Identity<'id>, limits: Limits) -> Result<Self, Failure> {
        if limits.addresses == 0 || limits.operation.is_zero() || limits.retirement.is_zero() {
            return Err(Fault::InvalidInput.into());
        }
        let mut rows = Vec::new();
        rows.try_reserve_exact(limits.addresses)
            .map_err(|_| Fault::Capacity)?;
        Ok(Self {
            rows,
            maximum: limits.addresses,
            authority: Authority::from_verified_peer(identity.peer()),
            identity,
            limits,
            stamp_owner: None,
            feed: None,
            feed_operation: None,
            hello: None,
            hello_running: false,
            hello_until: None,
            hello_publication: None,
            refresh_feed: None,
            scratch: allocate(limits.hello.maximum_address_bytes)?,
        })
    }
    /// An announcement on the same physical key authority can renew metadata.
    /// Changing physical source/key requires actual outer epoch retirement;
    /// identical raw peer bytes cannot recreate the former authority brand.
    pub fn identity(&mut self, identity: Identity<'id>) -> Result<(), Fault> {
        if identity.epoch() != self.identity.epoch() || identity.peer() != self.identity.peer() {
            return Err(Fault::StaleGeneration);
        }
        self.identity = identity;
        Ok(())
    }
    /// Match current true resource state, retaining every old native job until
    /// its actual result/retirement. Cache records never create ADD ownership.
    pub fn synchronize(
        &mut self,
        server: &Server,
        pils: &mut Pils<'id, SignTask>,
    ) -> Result<(), Failure> {
        for row in &mut self.rows {
            if !server.owns_local_address(row.certificate.lease()) && !row.retiring {
                row.retiring = true;
                row.certificate.retire();
                if let Some(op) = row.sign {
                    pils.cancel(op)?;
                }
            }
        }
        self.rows.retain(|r| {
            !(r.retiring && r.sign.is_none() && r.store.is_none() && r.stamp.is_none())
        });
        for local in server.local_addresses() {
            if self
                .rows
                .iter()
                .any(|r| r.certificate.lease() == local.lease)
            {
                continue;
            }
            if self.rows.len() >= self.maximum {
                // Actual old native debt retains its slot. The current ADD
                // stays in Server; prepare it after an original slot retires.
                break;
            }
            let prefix = 60usize
                + gnunet_transport::own_wire::SUBSYSTEM.len()
                + 1
                + gnunet_transport::own_wire::KEY.len()
                + 1;
            let maximum = self
                .limits
                .output
                .own_record_bytes
                .checked_sub(prefix)
                .ok_or(Fault::Capacity)?;
            let certificate = Certificate::new(local, self.authority.clone(), maximum)?;
            self.rows.push(Row {
                certificate,
                stamp: None,
                stamp_intent: None,
                sign: None,
                sign_bounds: None,
                store: None,
                store_offer: None,
                store_bounds: None,
                stored_by_service: false,
                refresh: Some(0),
                retiring: false,
            });
        }
        Ok(())
    }
    /// Apply only an actual original matching durable highwater completion.
    pub fn reservation(
        &mut self,
        receipt: generation::CommittedReservation,
        server: &Server,
        now: u64,
    ) -> Result<(), Failure> {
        let lease = self.stamp_owner.take().ok_or(Fault::Stale)?;
        let Some(row) = self
            .rows
            .iter_mut()
            .find(|r| *r.certificate.lease() == lease)
        else {
            return Err(Fault::Stale.into());
        };
        let request = row.stamp.take().ok_or(Fault::Stale)?;
        if &request != receipt.request() {
            return Err(Fault::Stale.into());
        }
        if row.retiring
            || !server.owns_local_address(&lease)
            || now >= request.expires()
            || tokio::time::Instant::now() >= request.hard()
        {
            return Ok(());
        }
        row.certificate.prepare(now, receipt.stamp())?;
        row.sign_bounds = Some(Bounds::after(now, self.limits.operation)?);
        row.refresh = None;
        Ok(())
    }
    /// Exact actual signature/feed event. Validation tags belong to outer Owner.
    pub fn signature(
        &mut self,
        origin: SignTask,
        peer: EddsaPublicKey,
        signature: EddsaSignature,
        server: &Server,
    ) -> Result<(), Failure> {
        let SignTask::Address { lease, offer } = origin else {
            return Err(Fault::Malformed.into());
        };
        let row = self
            .rows
            .iter_mut()
            .find(|r| *r.certificate.lease() == lease)
            .ok_or(Fault::Stale)?;
        row.sign = None;
        if row.certificate.pending_id() != Some(&offer) {
            return Err(Fault::Stale.into());
        }
        if row.retiring || !server.owns_local_address(&lease) {
            let _actual = row.certificate.signed(&offer, peer, signature)?;
            return Ok(());
        }
        if !row.certificate.signed(&offer, peer, signature)? {
            return Err(Fault::Stale.into());
        }
        Ok(())
    }
    /// Original failed/canceled signature never grants Verified or Saved.
    pub fn signature_failed(&mut self, origin: SignTask, now: u64) -> Result<(), Failure> {
        match origin {
            SignTask::Address { lease, offer } => {
                let row = self
                    .rows
                    .iter_mut()
                    .find(|r| *r.certificate.lease() == lease)
                    .ok_or(Fault::Stale)?;
                row.sign = None;
                match row.certificate.signing_retired(&offer, now)? {
                    Ok(at) => row.refresh = Some(at),
                    Err(_) => row.retiring = true,
                }
            }
            SignTask::Feed(_) => {
                self.feed_operation = None;
                self.feed = None;
            }
            SignTask::Validation(_) => return Err(Fault::Malformed.into()),
        }
        Ok(())
    }
    /// A full original FEED write is submission only; it does not acknowledge a
    /// HELLO update, store, address reachability or application by PILS.
    pub fn feed_written(&mut self, origin: SignTask, server: &mut Server) -> Result<(), Failure> {
        let SignTask::Feed(publication) = origin else {
            return Err(Fault::Malformed.into());
        };
        self.feed_operation = None;
        match server.address_publication_written(&publication) {
            Ok(()) | Err(Fault::Stale) => {}
            Err(error) => return Err(error.into()),
        }
        self.feed = None;
        Ok(())
    }
    /// Apply actual STORE result only to the original certificate. Strong pure
    /// commit_finished(Committed) is deliberately never called from this path.
    pub fn stored(&mut self, event: writer::Event<StoreTask>) -> Result<(), Failure> {
        match event {
            writer::Event::StoredByService(task) => {
                let row = self
                    .rows
                    .iter_mut()
                    .find(|r| *r.certificate.lease() == task.lease)
                    .ok_or(Fault::Stale)?;
                if row.store_offer.as_ref() != Some(&task.offer) || row.store.is_none() {
                    return Err(Fault::Stale.into());
                }
                row.store_offer = None;
                row.store = None;
                row.store_bounds = None;
                row.stored_by_service = true;
                if row.retiring {
                    row.refresh = None;
                } else {
                    let (_, refresh) = row.certificate.offer_deadlines(&task.offer)?;
                    row.refresh = Some(refresh);
                }
            }
            writer::Event::Refused { origin, code } => {
                let row = self
                    .rows
                    .iter_mut()
                    .find(|r| *r.certificate.lease() == origin.lease)
                    .ok_or(Fault::Stale)?;
                if row.store_offer.as_ref() != Some(&origin.offer) || row.store.is_none() {
                    return Err(Fault::Stale.into());
                }
                row.store = None;
                row.store_offer = None;
                return Err(
                    format!("TRANSPORT original own-address STORE refused code{code}").into(),
                );
            }
            writer::Event::Ended {
                origin,
                reason,
                submission,
            } => {
                let row = self
                    .rows
                    .iter_mut()
                    .find(|r| *r.certificate.lease() == origin.lease)
                    .ok_or(Fault::Stale)?;
                if row.store_offer.as_ref() != Some(&origin.offer) || row.store.is_none() {
                    return Err(Fault::Stale.into());
                }
                row.store = None;
                row.store_offer = None;
                return Err(format!(
                    "TRANSPORT original own-address STORE ended {reason:?}/{submission:?}"
                )
                .into());
            }
            writer::Event::SourceLost(error) => return Err(error),
            writer::Event::Activity => {}
        }
        Ok(())
    }
    /// Capture a real verified PILS announcement only when its exact identity,
    /// original resource revision and current address list still match. Forward
    /// its unchanged purpose7 signature as an ordinary HELLO frame, not envelope.
    pub fn announcement(&mut self, server: &Server, bytes: &[u8], now: u64) -> Result<(), Failure> {
        if self.hello_running || self.hello.is_some() {
            return Ok(());
        }
        let update = gnunet_wire::official::pils::PeerUpdate::decode(bytes)?;
        let hello = Hello::parse_block(update.block, &mut self.scratch, self.limits.hello)?;
        if hello.peer() != self.identity.peer() || !server.addresses_match(hello) {
            return Ok(());
        }
        let _actual = hello.verify_at(
            self.limits.signature_profile,
            AbsoluteTime::from_micros(now),
        )?;
        if hello.address_count() == 0 {
            return Ok(());
        }
        let id = server.address_snapshot()?.id().clone();
        if self.hello_publication.as_ref() == Some(&id)
            && self.hello_until.is_some_and(|until| until > now)
        {
            return Ok(());
        }
        let length = hello.message_len()?;
        if length.checked_add(95).ok_or(Fault::Overflow)? > self.limits.output.hello_record_bytes {
            return Err(Fault::Capacity.into());
        }
        let mut frame = allocate(length)?;
        hello.encode_message(&mut frame)?;
        let expires = hello.expiration().as_micros();
        let bounds = Bounds::after(now, self.limits.operation)?;
        let refresh_at = expires
            .saturating_sub(gnunet_transport::own::HELLO_TTL)
            .checked_add(gnunet_transport::own::REFRESH_CAP)
            .ok_or(Fault::Overflow)?;
        self.hello = Some(HelloIntent {
            task: HelloTask {
                publication: id,
                identity: self.identity,
                bounds,
                cache_expiry: expires,
                refresh_at,
            },
            frame,
            expires,
        });
        Ok(())
    }
    /// Actual helper outcome: ExistingNewer is observed history, not our store.
    pub fn hello_finished(
        &mut self,
        done: hello::Finished<'id, HelloTask<'id>>,
    ) -> Result<(), Failure> {
        self.hello_running = false;
        let task = done.origin;
        if task.identity.epoch() != self.identity.epoch()
            || task.identity.peer() != self.identity.peer()
        {
            return Err(Fault::StaleGeneration.into());
        }
        match done.result? {
            ps::hello::Completion {
                outcome: ps::hello::AddOutcome::StoreResult(1),
                ..
            }
            | ps::hello::Completion {
                outcome: ps::hello::AddOutcome::ExistingNewer { .. },
                ..
            } => {
                self.hello_publication = Some(task.publication);
                self.hello_until = Some(task.cache_expiry);
                self.refresh_feed = Some(task.refresh_at);
            }
            actual => {
                return Err(
                    format!("TRANSPORT original HELLO add ended: {:?}", actual.outcome).into(),
                );
            }
        }
        Ok(())
    }
    /// Perform actual bounded next production admissions, retaining targets on
    /// capacity refusal. Each return admits at most one actual provider job.
    pub fn advance(
        &mut self,
        server: &mut Server,
        pils: &mut Pils<'id, SignTask>,
        writer: &mut Writer<'id, StoreTask>,
        generation: &mut Reservations,
        hello_sink: &mut HelloSink<'id, HelloTask<'id>>,
        now: u64,
    ) -> Result<bool, Failure> {
        self.synchronize(server, pils)?;
        if self.refresh_feed.is_some_and(|at| at <= now) {
            server.refresh_address_publication()?;
            self.refresh_feed = None;
            self.hello_until = None;
        }
        if self.feed_operation.is_none() {
            if self.feed.is_none()
                && let Some(publication) = server.address_publication()?
            {
                let mut uris = Vec::new();
                uris.try_reserve_exact(self.limits.hello.maximum_address_bytes)
                    .map_err(|_| Fault::Capacity)?;
                for uri in publication.uris() {
                    if uris
                        .len()
                        .checked_add(uri.len())
                        .and_then(|n| n.checked_add(1))
                        .is_none_or(|n| n > self.limits.hello.maximum_address_bytes)
                    {
                        return Err(Fault::Capacity.into());
                    }
                    uris.extend_from_slice(uri);
                    uris.push(0);
                }
                self.feed = Some(Feed {
                    publication: publication.id().clone(),
                    uris,
                    bounds: Bounds::after(now, self.limits.operation)?,
                });
            }
            if let Some(feed) = &self.feed {
                if !feed.bounds.live(now) {
                    return Err(Fault::Deadline.into());
                }
                let mut builder = HelloBuilder::new(&mut self.scratch, self.limits.hello);
                for uri in feed.uris.split(|b| *b == 0).filter(|b| !b.is_empty()) {
                    builder.add_address(uri)?;
                }
                match pils.feed(
                    SignTask::Feed(feed.publication.clone()),
                    &builder,
                    feed.bounds,
                ) {
                    Ok(operation) => {
                        server.claim_address_publication(&feed.publication)?;
                        self.feed_operation = Some(operation);
                        return Ok(true);
                    }
                    Err(rejected) if temporary(rejected.reason) => {}
                    Err(rejected) => return Err(rejected.reason.into()),
                }
            }
        }
        for i in 0..self.rows.len() {
            if self.rows[i].retiring {
                continue;
            }
            if self.rows[i].stored_by_service && self.rows[i].refresh.is_some_and(|at| at <= now) {
                let lease = self.rows[i].certificate.lease().clone();
                let local = server
                    .local_addresses()
                    .find(|a| *a.lease == lease)
                    .ok_or(Fault::Stale)?;
                let prefix = 60
                    + gnunet_transport::own_wire::SUBSYSTEM.len()
                    + 1
                    + gnunet_transport::own_wire::KEY.len()
                    + 1;
                self.rows[i].certificate = Certificate::new(
                    local,
                    self.authority.clone(),
                    self.limits
                        .output
                        .own_record_bytes
                        .checked_sub(prefix)
                        .ok_or(Fault::Capacity)?,
                )?;
                self.rows[i].stored_by_service = false;
                self.rows[i].refresh = Some(0);
            }
            if self.rows[i].stored_by_service {
                continue;
            }
            if self.rows[i].certificate.pending_id().is_none()
                && self.rows[i].stamp.is_none()
                && self.stamp_owner.is_none()
                && self.rows[i].refresh.is_some_and(|at| at <= now)
            {
                if self.rows[i].stamp_intent.is_none() {
                    self.rows[i].stamp_intent = Some(Bounds::after(now, self.limits.operation)?);
                }
                let bounds = self.rows[i].stamp_intent.ok_or(Fault::Stale)?;
                if !bounds.live(now) {
                    return Err(Fault::Deadline.into());
                }
                if !generation.is_idle() {
                    continue;
                }
                let request = generation.request(now, bounds.expires, bounds.hard)?;
                self.rows[i].stamp_intent = None;
                self.stamp_owner = Some(self.rows[i].certificate.lease().clone());
                self.rows[i].stamp = Some(request);
                return Ok(true);
            }
            if self.rows[i].sign.is_none()
                && let Some(offer) = self.rows[i].certificate.signature_offer()
            {
                let bounds = self.rows[i].sign_bounds.ok_or(Fault::Stale)?;
                if !bounds.live(now) {
                    return Err(Fault::Deadline.into());
                }
                let task = SignTask::Address {
                    lease: self.rows[i].certificate.lease().clone(),
                    offer: offer.id.clone(),
                };
                match pils.sign(task, offer.peer, offer.region, bounds) {
                    Ok(operation) => {
                        let id = offer.id.clone();
                        self.rows[i].certificate.signing_admitted(&id)?;
                        self.rows[i].sign = Some(operation);
                        return Ok(true);
                    }
                    Err(rejected) if temporary(rejected.reason) => {}
                    Err(rejected) => return Err(rejected.reason.into()),
                }
            }
            if self.rows[i].store.is_none() && self.rows[i].certificate.record_draft().is_some() {
                if self.rows[i].store_bounds.is_none() {
                    self.rows[i].store_bounds = Some(Bounds::after(now, self.limits.operation)?);
                }
                let record = self.rows[i]
                    .certificate
                    .record_draft()
                    .ok_or(Fault::Stale)?;
                let offer = record.id.clone();
                let task = StoreTask {
                    lease: self.rows[i].certificate.lease().clone(),
                    offer: offer.clone(),
                };
                let bounds = self.rows[i].store_bounds.ok_or(Fault::Stale)?;
                if !bounds.live(now) {
                    return Err(Fault::Deadline.into());
                }
                match writer.store(
                    task,
                    ps::Record {
                        peer: *record.peer.as_bytes(),
                        expiry: record.expiry,
                        subsystem: Some(gnunet_transport::own_wire::SUBSYSTEM),
                        key: Some(gnunet_transport::own_wire::KEY),
                        value: record.value,
                    },
                    0,
                    bounds,
                ) {
                    Ok(operation) => {
                        self.rows[i].store = Some(operation);
                        self.rows[i].store_offer = Some(offer);
                        return Ok(true);
                    }
                    Err(rejected) if temporary(rejected.reason) => {}
                    Err(rejected) => return Err(rejected.reason.into()),
                }
            }
        }
        if hello_sink.idle()
            && let Some(intent) = self.hello.take()
        {
            if !intent.task.bounds.live(now) {
                return Err(Fault::Deadline.into());
            }
            let options = ps::hello::Options {
                profile: self.limits.signature_profile,
                hello: self.limits.hello,
                now: AbsoluteTime::from_micros(now),
                until: intent.task.bounds.expires.min(intent.expires),
                hard: intent.task.bounds.hard,
                grace: self.limits.retirement,
            };
            match hello_sink.start(intent.task, intent.frame, options) {
                Ok(()) => {
                    self.hello_running = true;
                    return Ok(true);
                }
                Err(rejected) => {
                    let (task, frame) = rejected.value;
                    self.hello = Some(HelloIntent {
                        task,
                        frame,
                        expires: intent.expires,
                    });
                    if !temporary(rejected.reason) {
                        return Err(rejected.reason.into());
                    }
                }
            }
        }
        Ok(false)
    }
    /// Actual canonical next refresh only; native provider bounds are separate.
    pub fn next_refresh(&self) -> Option<u64> {
        self.rows
            .iter()
            .filter_map(|r| r.refresh)
            .chain(self.refresh_feed)
            .filter(|n| *n > 0)
            .min()
    }
    /// Physically retiring the old Server precedes this hook. Cancel each old
    /// signature/FEED on the same actual PILS source, retain all native suffixes,
    /// and transfer the one actual stamp origin to the caller's worker drain.
    pub(crate) fn begin_epoch_retirement(
        &mut self,
        pils: &mut Pils<'id, SignTask>,
    ) -> Result<Option<crate::epoch::RetiredStamp<'id>>, Failure> {
        self.retire();
        self.feed = None;
        self.hello = None;
        self.refresh_feed = None;
        if let Some(operation) = self.feed_operation {
            pils.cancel(operation)?;
        }
        for row in &self.rows {
            if let Some(operation) = row.sign {
                pils.cancel(operation)?;
            }
        }
        Ok(self.take_retired_stamp()?)
    }
    /// Transfer only an actually admitted original generation job after the old
    /// Engine's physical sources have been retired. No crypto/receipt is created.
    pub(crate) fn take_retired_stamp(
        &mut self,
    ) -> Result<Option<crate::epoch::RetiredStamp<'id>>, Fault> {
        let original = match self.stamp_owner.take() {
            Some(lease) => {
                let row = self
                    .rows
                    .iter_mut()
                    .find(|r| *r.certificate.lease() == lease)
                    .ok_or(Fault::Stale)?;
                let request = row.stamp.take().ok_or(Fault::Stale)?;
                Some(crate::epoch::RetiredStamp::from_original(
                    self.identity,
                    lease,
                    request,
                ))
            }
            None => None,
        };
        Ok(original)
    }
    /// No original SIGN/FEED/STORE/HELLO work remains owned here. This is not
    /// remote withdrawal; old cache entries retain their actual expirations.
    pub(crate) fn epoch_quiescent(&self) -> bool {
        self.feed_operation.is_none()
            && !self.hello_running
            && self
                .rows
                .iter()
                .all(|r| r.sign.is_none() && r.store.is_none() && r.stamp.is_none())
    }
    /// Settle an original STORE while retiring, preserving its actual outcome
    /// separately for the caller. A failure cannot become new-epoch success.
    pub(crate) fn retire_store(&mut self, event: &writer::Event<StoreTask>) -> Result<(), Fault> {
        let task = match event {
            writer::Event::StoredByService(t) => t,
            writer::Event::Refused { origin, .. } | writer::Event::Ended { origin, .. } => origin,
            writer::Event::Activity => return Ok(()),
            writer::Event::SourceLost(_) => return Err(Fault::Unavailable),
        };
        let row = self
            .rows
            .iter_mut()
            .find(|r| *r.certificate.lease() == task.lease)
            .ok_or(Fault::Stale)?;
        if row.store_offer.as_ref() != Some(&task.offer) || row.store.is_none() {
            return Err(Fault::Stale);
        }
        row.store = None;
        row.store_offer = None;
        row.store_bounds = None;
        row.refresh = None;
        Ok(())
    }
    /// Real old HELLO helper result has returned; caller retains it unchanged.
    pub(crate) fn retire_hello(&mut self, task: &HelloTask<'id>) -> Result<(), Fault> {
        if task.identity.epoch() != self.identity.epoch()
            || task.identity.peer() != self.identity.peer()
        {
            return Err(Fault::Stale);
        }
        self.hello_running = false;
        Ok(())
    }
    /// No new effects after source loss. Original provider debts stay owned by
    /// their real clients until actual completion/close; historical cache is not
    /// advertised as erased or revoked by this local retirement.
    pub fn retire(&mut self) {
        for row in &mut self.rows {
            row.retiring = true;
            row.stamp_intent = None;
            row.certificate.retire();
        }
    }
}
