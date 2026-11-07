//! Actual local NAMESTORE provider. Original native query/epoch/zone and finite
//! room-source leases remain distinct from real AEAD and in-memory key install.
use crate::{clock::Span, types::*, *};
use gnunet_gnsrecord::{RecordData, RecordFlags, RecordType};
use gnunet_namestore_client_host as ns;
use gnunet_types::Error as Fault;
use std::{
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use subtle::ConstantTimeEq;
use wire::records::Record;
/// Native record provider limits. The adapter never starts NAMESTORE or loads a
/// key file; callers supply the same process Resolver/clock and an explicit root.
#[derive(Clone, Copy, Debug)]
pub struct RecordLimits {
    /// Actual original general/monitor native policy; reconnect must be false.
    pub native: ns::Limits,
    /// Maximum retained original requests/inline monitor records.
    pub operations: usize,
    /// Metadata and retained inline ciphertext capacity, outside native budgets.
    pub bytes: usize,
}
impl Default for RecordLimits {
    fn default() -> Self {
        let native = ns::Limits {
            reconnect: false,
            ..ns::Limits::default()
        };
        Self {
            native,
            operations: 32,
            bytes: 256 * 1024,
        }
    }
}
/// Explicit actual private-zone destination for a public room advertisement.
/// Flags/expiration are GNS record fields; code0 is not publication evidence.
#[derive(Clone, Copy, Debug)]
pub struct RecordDestination<'a> {
    /// Explicit owned zone identity, not an inferred private-key hash.
    pub identity: Identity,
    /// Existing NAMESTORE label, excluding NUL.
    pub label: &'a [u8],
    /// Original absolute/relative microsecond expiration, interpreted by flags.
    pub expiration: u64,
    /// Actual GNS storage flags, including optional PRIVATE/RELATIVE_EXPIRATION.
    pub flags: RecordFlags,
}
/// Actual record observation, including its original native result. `installed`
/// counts successful AEAD/state installs only; a STORE code is still interpreted
/// from the original response and is not a disk durability/publication receipt.
pub struct RecordProgress<'a> {
    original: ns::Progress<'a>,
    binding: Option<Binding<'a>>,
    installed: usize,
    refusal: Option<domain::Error>,
    loss: Option<RecordLoss<'a>>,
}
impl<'a> RecordProgress<'a> {
    /// Consume the original observation so callers can retain an actual owned
    /// IO/source error after inspecting binding/install/refusal/loss metadata.
    /// This grants no successful record lookup, store or key-install receipt.
    pub fn into_native(self) -> ns::Progress<'a> {
        self.original
    }
    /// Actual original native operation/epoch/RID/result or local loss.
    pub const fn native(&self) -> &ns::Progress<'a> {
        &self.original
    }
    /// Actual independent physical record-owner stop and original pending jobs.
    pub const fn loss(&self) -> Option<&RecordLoss<'a>> {
        self.loss.as_ref()
    }
    /// Exact original domain record lookup, if this result belongs to one.
    pub const fn binding(&self) -> Option<Binding<'a>> {
        self.binding
    }
    /// Actual authenticated key installs (duplicates do not increase this).
    pub const fn installed(&self) -> usize {
        self.installed
    }
    /// Actual record/state refusal; never converted into an absent/success value.
    pub const fn refusal(&self) -> Option<domain::Error> {
        self.refusal
    }
}
impl std::fmt::Debug for RecordProgress<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessengerRecords([REDACTED])")
            .field("native", &self.original)
            .field("installed", &self.installed)
            .field("refusal", &self.refusal)
            .finish_non_exhaustive()
    }
}
/// Actual physical record-owner stop accounting. Pending original jobs remain
/// identifiable without exporting any private key or ciphertext.
pub struct RecordLoss<'a> {
    general: Option<ns::Loss<'a>>,
    monitor: Option<ns::Loss<'a>>,
    pending: Vec<Pending<'a>>,
}
impl<'a> RecordLoss<'a> {
    /// Transfer both actual stopped source reports while their instance remains
    /// live. Original domain bindings can be observed before consumption.
    pub fn into_sources(self) -> (Option<ns::Loss<'a>>, Option<ns::Loss<'a>>) {
        (self.general, self.monitor)
    }
    /// Actual general source physical-close accounting, if it existed.
    pub const fn general(&self) -> Option<&ns::Loss<'_>> {
        self.general.as_ref()
    }
    /// Actual monitor source physical-close accounting, if it existed.
    pub const fn monitor(&self) -> Option<&ns::Loss<'_>> {
        self.monitor.as_ref()
    }
    /// Original domain bindings retired with the owner, without secret content.
    pub fn bindings(&self) -> impl Iterator<Item = Binding<'a>> + '_ {
        self.pending.iter().filter_map(|p| p.binding)
    }
}
impl std::fmt::Debug for RecordLoss<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordLoss")
            .field("general", &self.general)
            .field("monitor", &self.monitor)
            .field("pending", &self.pending.len())
            .finish()
    }
}
struct Pending<'a> {
    native: Option<ns::Operation<'a>>,
    native_epoch: Option<ns::Epoch<'a>>,
    rid: Option<u32>,
    binding: Option<Binding<'a>>,
    operation: Option<Operation<'a>>,
    room: Room<'a>,
    source: Source<'a>,
    public: PublicKey,
    span: Span,
    label: [u8; 32],
    inline: Option<domain::OwnedBytes>,
    monitor_origin: Option<(ns::Operation<'a>, ns::Epoch<'a>)>,
}
#[derive(Clone, Copy)]
struct WatchRoom<'a> {
    room: Room<'a>,
    source: Source<'a>,
    public: PublicKey,
}
pub(crate) struct Records<'a> {
    instance: &'a ns::Instance,
    baseline: EndpointSource,
    client: ns::Client<'a>,
    root: crypto::records::RecordSecret,
    limits: RecordLimits,
    pending: Vec<Pending<'a>>,
    monitor: Option<ns::Monitor<'a>>,
    monitor_span: Option<Span>,
    monitor_epoch: Option<ns::Epoch<'a>>,
    watch: Vec<WatchRoom<'a>>,
    next_credit: bool,
    stopped: bool,
    poll_monitor: bool,
}
impl<'a> Records<'a> {
    pub(crate) fn source_current(&self, source: ns::Epoch<'a>) -> bool {
        !self.stopped && (self.client.epoch() == Some(source) || self.monitor_epoch == Some(source))
    }
    pub fn uses_public(&self, public: &PublicKey) -> bool {
        self.watch.iter().any(|w| &w.public == public)
            || self.pending.iter().any(|p| &p.public == public)
    }
    pub fn hard(&self) -> Option<tokio::time::Instant> {
        self.pending
            .iter()
            .map(|p| p.span.hard)
            .chain(self.monitor_span.map(|s| s.hard))
            .min()
    }
    pub fn logical(&self) -> Option<u64> {
        self.pending
            .iter()
            .map(|p| p.span.logical)
            .chain(self.monitor_span.map(|s| s.logical))
            .min()
    }
    pub fn expired(&self, now: Option<u64>) -> bool {
        self.pending.iter().any(|p| p.span.expired(now))
            || self.monitor_span.is_some_and(|s| s.expired(now))
    }
    pub fn close(&mut self) -> RecordLoss<'a> {
        let general = self.client.close();
        let monitor = self.monitor.as_mut().and_then(ns::Monitor::close);
        self.monitor = None;
        self.monitor_span = None;
        self.monitor_epoch = None;
        self.watch.clear();
        self.next_credit = false;
        self.stopped = true;
        RecordLoss {
            general,
            monitor,
            pending: core::mem::take(&mut self.pending),
        }
    }
}
fn prefix_base32(bytes: &[u8], out: &mut [u8]) -> Result<(), Fault> {
    let mut encoded = [0; 103];
    let n = gnunet_gnsrecord::encode_base32(bytes, &mut encoded)?;
    if n < out.len() {
        return Err(Fault::Truncated);
    }
    for (to, from) in out.iter_mut().zip(encoded) {
        *to = from.to_ascii_lowercase();
    }
    Ok(())
}
fn epoch_label(room: &Hash, epoch: &Hash, id: &ShortHash) -> Result<[u8; 32], Fault> {
    let mut out = [0; 32];
    out[..10].copy_from_slice(b"epoch_key_");
    prefix_base32(room, &mut out[10..18])?;
    prefix_base32(epoch, &mut out[18..26])?;
    prefix_base32(id, &mut out[26..])?;
    Ok(out)
}
fn encryption_label(record: Record<'_>) -> Result<[u8; 31], Fault> {
    let Record::EncryptionKey {
        room_key,
        encrypted_private_data,
        ..
    } = record
    else {
        return Err(Fault::InvalidInput);
    };
    let mut out = [0; 31];
    out[..15].copy_from_slice(b"encryption_key_");
    prefix_base32(room_key, &mut out[15..23])?;
    // Only the official ciphertext516 is hashed. No private key identifier.
    prefix_base32(
        &gnunet_crypto::hash512(encrypted_private_data),
        &mut out[23..],
    )?;
    Ok(out)
}
impl<'a, E: crypto::Entropy, const N: usize> Api<'a, E, N> {
    /// Install an actual local record port using the SAME shared process clock.
    /// The explicit caller RecordSecret is unrelated to IDENTITY private hashes.
    /// This opens no socket, starts no service and does not fabricate a snapshot.
    pub fn enable_records(
        &mut self,
        instance: &'a ns::Instance,
        endpoint: EndpointSource,
        root: crypto::records::RecordSecret,
        limits: RecordLimits,
    ) -> Result<(), Error> {
        if self.records.is_some() || limits.operations == 0 || limits.native.reconnect {
            return Err(Fault::InvalidInput.into());
        }
        if !Arc::ptr_eq(&endpoint.clock(), &self.clock.source) {
            return Err(Fault::Conflict.into());
        }
        let size = limits
            .operations
            .checked_mul(core::mem::size_of::<Pending<'a>>() + wire::records::EPOCH_KEY_LEN)
            .and_then(|b| {
                b.checked_add(
                    self.limits
                        .core
                        .rooms
                        .checked_mul(core::mem::size_of::<WatchRoom<'a>>())?,
                )
            })
            .ok_or(Fault::Overflow)?;
        if size > limits.bytes {
            return Err(Fault::Capacity.into());
        }
        let baseline = endpoint.duplicate()?;
        let client = ns::Client::new(instance, endpoint, limits.native)?;
        let mut pending = Vec::new();
        pending
            .try_reserve_exact(limits.operations)
            .map_err(|_| Fault::Capacity)?;
        let mut watch = Vec::new();
        watch
            .try_reserve_exact(self.limits.core.rooms)
            .map_err(|_| Fault::Capacity)?;
        self.records = Some(Records {
            instance,
            baseline,
            client,
            root,
            limits,
            pending,
            monitor: None,
            monitor_span: None,
            monitor_epoch: None,
            watch,
            next_credit: false,
            stopped: false,
            poll_monitor: false,
        });
        Ok(())
    }
    /// Explicitly replace a stopped record MQ after its original loss was
    /// observed. No old lookup/STORE/monitor/ciphertext is replayed or relabelled.
    pub fn reconnect_records(&mut self) -> Result<(), Error> {
        let r = self.records.as_mut().ok_or(Fault::NotReady)?;
        if !r.stopped {
            return Err(Fault::NotReady.into());
        }
        let client = ns::Client::new(r.instance, r.baseline.duplicate()?, r.limits.native)?;
        let mut pending = Vec::new();
        pending
            .try_reserve_exact(r.limits.operations)
            .map_err(|_| Fault::Capacity)?;
        r.client = client;
        r.pending = pending;
        r.monitor = None;
        r.monitor_span = None;
        r.monitor_epoch = None;
        r.next_credit = false;
        r.stopped = false;
        self.record_blocked = false;
        self.wake_domain();
        Ok(())
    }
    /// Physically stop the original monitor. Pending inline results keep their
    /// original origin and fail rather than being adopted by a later monitor.
    pub fn stop_record_watch(&mut self) -> Option<ns::Loss<'a>> {
        let r = self.records.as_mut()?;
        let loss = r.monitor.as_mut().and_then(ns::Monitor::close);
        r.monitor = None;
        r.monitor_epoch = None;
        r.monitor_span = None;
        r.watch.clear();
        r.next_credit = false;
        self.record_blocked = false;
        self.wake_domain();
        loss
    }
    /// Explicit finite whole-zone monitor for the current actual room leases.
    /// Newly opened/reopened rooms require a fresh explicit monitor; old replies
    /// cannot acquire a new room/source generation or a changed signing identity.
    pub fn watch_records(&mut self, timeout: Duration) -> Result<ns::Operation<'a>, Error> {
        let (_, span) = self.admission(timeout)?;
        let identity = self.selected;
        let signer = self.signer(identity)?;
        let public = self.signers[signer].public;
        let r = self.records.as_mut().ok_or(Fault::NotReady)?;
        if r.monitor.is_some() || r.stopped {
            return Err(Fault::NotReady.into());
        }
        r.watch.clear();
        for room in &self.rooms {
            if let Some(source) = room.source
                && room.signer == identity
            {
                r.watch.push(WatchRoom {
                    room: room.room,
                    source,
                    public,
                });
            }
        }
        let monitor = ns::Monitor::new(
            r.instance,
            r.baseline.duplicate()?,
            Some(&self.signers[signer].secret),
            true,
            0,
            span.logical,
            r.limits.native,
        )?;
        let operation = monitor.operation();
        r.monitor = Some(monitor);
        r.monitor_span = Some(span);
        r.monitor_epoch = None;
        r.next_credit = false;
        Ok(operation)
    }
    /// Request a genuine historical/current epoch record with its original
    /// Core binding. A missing label becomes ProviderFailed(NotFound), never a
    /// generated replacement key or a renewed deadline.
    pub fn load_epoch_record(
        &mut self,
        room: Room<'a>,
        epoch: Hash,
        id: ShortHash,
        timeout: Duration,
    ) -> Result<Operation<'a>, Error> {
        let (now, span) = self.admission(timeout)?;
        let (_, source, native_epoch, member) = self.sending(room)?;
        let r = self.records.as_ref().ok_or(Fault::NotReady)?;
        if r.stopped || r.pending.len() == r.limits.operations {
            return Err(Fault::WouldBlock.into());
        }
        let operation =
            self.core
                .request_epoch_record(source, member, epoch, id, now, span.logical)?;
        self.record_job(room, source, native_epoch, operation, span, Intent::User)?;
        Ok(operation)
    }
    pub(crate) fn start_record_lookup(
        &mut self,
        binding: Binding<'a>,
        public: PublicKey,
        span: Span,
    ) -> Result<(), Error> {
        let now = self.sample()?;
        let room = self
            .leases
            .iter()
            .find(|l| l.operation == binding.operation())
            .ok_or(Fault::StaleGeneration)?
            .room;
        let signer = self
            .signers
            .iter()
            .position(|s| s.public == public)
            .ok_or(Fault::Authentication)?;
        let r = self.records.as_mut().ok_or(Fault::NotReady)?;
        if r.stopped || span.expired(Some(now)) {
            return Err(Fault::NotReady.into());
        }
        if let Some(i) = r
            .pending
            .iter()
            .position(|p| p.operation == Some(binding.operation()) && p.inline.is_some())
        {
            let p = r.pending.remove(i);
            if p.source != binding.source()
                || p.public != public
                || p.room != room
                || p.span.expired(Some(now))
            {
                return Err(Fault::StaleGeneration.into());
            }
            if p.monitor_origin.is_none_or(|(op, epoch)| {
                r.monitor.as_ref().is_none_or(|m| m.operation() != op)
                    || r.monitor_epoch != Some(epoch)
            }) {
                return Err(Fault::StaleGeneration.into());
            }
            let bytes = p.inline.ok_or(Fault::Conflict)?;
            let record = Record::decode(
                RecordType::MESSENGER_ROOM_EPOCH_KEY,
                bytes.expose(),
                self.profiles
                    .record_profile(
                        &public,
                        RecordType::MESSENGER_ROOM_EPOCH_KEY,
                        bytes.expose(),
                    )
                    .ok_or(Fault::Unavailable)?,
            )?;
            self.core
                .complete_epoch_record(binding, &r.root, record, now)?;
            self.reset_decryption();
            return Ok(());
        }
        if r.pending.len() == r.limits.operations {
            return Err(Fault::WouldBlock.into());
        }
        let label = epoch_label(
            self.core.room_key(room)?,
            binding.epoch(),
            binding.identifier(),
        )?;
        let operation = r
            .client
            .lookup(&self.signers[signer].secret, &label, 0, span.logical)?;
        let rid = r.client.request_id(operation)?;
        r.pending.push(Pending {
            native: Some(operation),
            native_epoch: None,
            rid,
            binding: Some(binding),
            operation: Some(binding.operation()),
            room,
            source: binding.source(),
            public,
            span,
            label,
            inline: None,
            monitor_origin: None,
        });
        Ok(())
    }
    /// Actually seal and submit the current/retained epoch key to its private
    /// local zone. The returned native job settles only from the real STORE code.
    pub fn store_epoch_record(
        &mut self,
        room: Room<'a>,
        epoch: Hash,
        id: ShortHash,
        timeout: Duration,
    ) -> Result<ns::Operation<'a>, Error> {
        let (_, span) = self.admission(timeout)?;
        let (i, source, _) = self.live_source(room)?;
        let signer = self.signer(self.rooms[i].signer)?;
        let r = self.records.as_mut().ok_or(Fault::NotReady)?;
        if r.stopped || r.pending.len() == r.limits.operations {
            return Err(Fault::WouldBlock.into());
        }
        let sealed = self
            .core
            .seal_epoch_record(room, &epoch, &id, &r.root, &mut self.entropy)?;
        let label = epoch_label(self.core.room_key(room)?, &epoch, &id)?;
        let native = store_one(
            &mut r.client,
            StoreZone {
                secret: &self.signers[signer].secret,
                public: self.signers[signer].public,
                profiles: &mut self.profiles,
            },
            &label,
            sealed.record(),
            self.core.local_profile(),
            span,
            StoreMetadata {
                flags: RecordFlags::PRIVATE,
                expiration: u64::MAX,
            },
        )?;
        r.pending.push(Pending {
            native: Some(native),
            native_epoch: None,
            rid: r.client.request_id(native)?,
            binding: None,
            operation: None,
            room,
            source,
            public: self.signers[signer].public,
            span,
            label,
            inline: None,
            monitor_origin: None,
        });
        Ok(native)
    }
    /// Store an actual official room-entry record in an explicitly owned zone.
    /// This prepares real NAMESTORE work; it claims neither GNS publication nor
    /// remote CADET reachability or an accepted invitation.
    pub fn store_room_entry(
        &mut self,
        room: Room<'a>,
        door: [u8; 32],
        destination: RecordDestination<'_>,
        timeout: Duration,
    ) -> Result<ns::Operation<'a>, Error> {
        let (_, span) = self.admission(timeout)?;
        let key = *self.core.room_key(room)?;
        self.store_room_record(
            room,
            Record::RoomEntry {
                door: &door,
                room_key: &key,
            },
            destination,
            span,
        )
    }
    /// Store exact official fixed-name256/native-flags room details. The caller
    /// may use the shared record_text codec; no private alternate text is added.
    pub fn store_room_details(
        &mut self,
        room: Room<'a>,
        name: &[u8; 256],
        flags: u32,
        destination: RecordDestination<'_>,
        timeout: Duration,
    ) -> Result<ns::Operation<'a>, Error> {
        let (_, span) = self.admission(timeout)?;
        self.store_room_record(room, Record::RoomDetails { name, flags }, destination, span)
    }
    fn store_room_record(
        &mut self,
        room: Room<'a>,
        record: Record<'_>,
        destination: RecordDestination<'_>,
        span: Span,
    ) -> Result<ns::Operation<'a>, Error> {
        let (_, source, _) = self.live_source(room)?;
        let signer = self.signer(destination.identity)?;
        let r = self.records.as_mut().ok_or(Fault::NotReady)?;
        if r.stopped || r.pending.len() == r.limits.operations {
            return Err(Fault::WouldBlock.into());
        }
        let operation = store_one(
            &mut r.client,
            StoreZone {
                secret: &self.signers[signer].secret,
                public: self.signers[signer].public,
                profiles: &mut self.profiles,
            },
            destination.label,
            record,
            self.core.local_profile(),
            span,
            StoreMetadata {
                flags: destination.flags,
                expiration: destination.expiration,
            },
        )?;
        r.pending.push(Pending {
            native: Some(operation),
            native_epoch: None,
            rid: r.client.request_id(operation)?,
            binding: None,
            operation: None,
            room,
            source,
            public: self.signers[signer].public,
            span,
            label: [0; 32],
            inline: None,
            monitor_origin: None,
        });
        Ok(operation)
    }
    pub(crate) fn store_recipient(
        &mut self,
        room: Room<'a>,
        source: Source<'a>,
        identity: Identity,
        key: &crypto::EcdheSecret,
        span: Span,
    ) -> Result<(), Error> {
        let Some(r) = self.records.as_ref() else {
            return Ok(());
        };
        if r.stopped {
            return Err(Fault::NotReady.into());
        }
        let signer = self.signer(identity)?;
        let room_key = *self.core.room_key(room)?;
        let r = self.records.as_mut().ok_or(Fault::NotReady)?;
        if r.pending.len() == r.limits.operations {
            return Err(Fault::WouldBlock.into());
        }
        let sealed =
            crypto::records::EncryptionRecord::seal(&r.root, &room_key, key, &mut self.entropy)?;
        let short = encryption_label(sealed.record())?;
        let mut label = [0; 32];
        label[..31].copy_from_slice(&short);
        let native = store_one(
            &mut r.client,
            StoreZone {
                secret: &self.signers[signer].secret,
                public: self.signers[signer].public,
                profiles: &mut self.profiles,
            },
            &short,
            sealed.record(),
            self.core.local_profile(),
            span,
            StoreMetadata {
                flags: RecordFlags::PRIVATE,
                expiration: u64::MAX,
            },
        )?;
        r.pending.push(Pending {
            native: Some(native),
            native_epoch: None,
            rid: r.client.request_id(native)?,
            binding: None,
            operation: None,
            room,
            source,
            public: self.signers[signer].public,
            span,
            label,
            inline: None,
            monitor_origin: None,
        });
        Ok(())
    }
    fn apply_record_set(
        &mut self,
        watch: WatchRoom<'a>,
        records: ns::ipc::Records<'_>,
        span: Span,
    ) -> Result<usize, domain::Error> {
        let i = self
            .room_index(watch.room)
            .map_err(|_| Fault::StaleGeneration)?;
        if self.rooms[i].source != Some(watch.source)
            || self
                .core
                .local_member(watch.room)?
                .is_some_and(|m| self.core.member_public(m).is_ok_and(|p| *p != watch.public))
        {
            return Err(Fault::StaleGeneration.into());
        }
        let now = match self.clock.sample() {
            Ok(now) => now,
            Err(error) => {
                self.capture_stop(StopCause::Clock(error), false, None);
                return Err(error.into());
            }
        };
        if span.expired(Some(now)) {
            return Err(Fault::Timeout.into());
        }
        let mut installed = 0;
        for data in records.records().iter() {
            let data = data?;
            // NAMESTORE is the actual local record/expiration authority. Keep
            // its original metadata in RecordProgress; do not infer a new TTL
            // or treat expiry metadata itself as cryptographic authorization.
            if !data.flags.contains(RecordFlags::PRIVATE) {
                continue;
            }
            match data.record_type {
                RecordType::MESSENGER_ENCRYPTION_KEY => {
                    let record = Record::decode(
                        data.record_type,
                        data.data,
                        self.profiles
                            .record_profile(&watch.public, data.record_type, data.data)
                            .ok_or(Fault::Unavailable)?,
                    )?;
                    let Record::EncryptionKey { room_key, .. } = record else {
                        continue;
                    };
                    if room_key != self.core.room_key(watch.room)? {
                        continue;
                    }
                    let r = self.records.as_ref().ok_or(Fault::NotReady)?;
                    installed += usize::from(self.core.recover_encryption_record(
                        watch.source,
                        watch.public,
                        &r.root,
                        record,
                    )?);
                }
                RecordType::MESSENGER_ROOM_EPOCH_KEY => {
                    let record = Record::decode(
                        data.record_type,
                        data.data,
                        self.profiles
                            .record_profile(&watch.public, data.record_type, data.data)
                            .ok_or(Fault::Unavailable)?,
                    )?;
                    let Record::EpochKey {
                        room_key,
                        epoch,
                        identifier,
                        ..
                    } = record
                    else {
                        continue;
                    };
                    if room_key != self.core.room_key(watch.room)? {
                        continue;
                    }
                    if self.free_jobs() == 0 {
                        return Err(Fault::WouldBlock.into());
                    }
                    let Some(member) = self.core.local_member(watch.room)? else {
                        continue;
                    };
                    if *self.core.member_public(member)? != watch.public {
                        return Err(Fault::StaleGeneration.into());
                    }
                    let r = self.records.as_ref().ok_or(Fault::NotReady)?;
                    if r.pending.len() == r.limits.operations {
                        return Err(Fault::WouldBlock.into());
                    }
                    let original = domain::OwnedBytes::copy_from(data.data)?;
                    let label = epoch_label(room_key, epoch, identifier)?;
                    self.next_job.checked_add(1).ok_or(Fault::Overflow)?;
                    let epoch_native = self.rooms[i].epoch.ok_or(Fault::StaleGeneration)?;
                    let order = self
                        .core
                        .group_identifier_order(watch.room, identifier)?
                        .or_else(|| self.profiles.identifier_origin(room_key, epoch, identifier))
                        .or_else(|| self.profiles.common_identifier_order());
                    if order.is_none() {
                        return Err(Fault::Unavailable.into());
                    }
                    let operation = self.core.request_epoch_record_profiled(
                        watch.source,
                        member,
                        domain::EpochRecordTarget {
                            epoch: *epoch,
                            identifier: *identifier,
                            identifier_order: order,
                        },
                        now,
                        span.logical,
                    )?;
                    self.record_job(
                        watch.room,
                        watch.source,
                        epoch_native,
                        operation,
                        span,
                        Intent::Epoch,
                    )
                    .map_err(|_| Fault::Capacity)?;
                    let monitor_origin = self.records.as_ref().and_then(|r| {
                        r.monitor
                            .as_ref()
                            .zip(r.monitor_epoch)
                            .map(|(m, e)| (m.operation(), e))
                    });
                    self.records
                        .as_mut()
                        .ok_or(Fault::NotReady)?
                        .pending
                        .push(Pending {
                            native: None,
                            native_epoch: None,
                            rid: None,
                            binding: None,
                            operation: Some(operation),
                            room: watch.room,
                            source: watch.source,
                            public: watch.public,
                            span,
                            label,
                            inline: Some(original),
                            monitor_origin,
                        });
                }
                _ => {}
            }
        }
        if installed > 0 {
            self.reset_decryption();
            self.wake_domain();
        }
        Ok(installed)
    }
    /// Poll real record IO before canonical clock coherence. Each call consumes
    /// at most one original native event; callbacks cannot manufacture receipts.
    pub(crate) fn poll_records(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<RecordProgress<'a>, Error>> {
        let Some(r) = self.records.as_mut() else {
            return Poll::Pending;
        };
        if r.stopped {
            return Poll::Pending;
        }
        if r.next_credit
            && let (Some(m), Some(span)) = (r.monitor.as_mut(), r.monitor_span)
        {
            match m.next(1, span.logical) {
                Ok(_) => r.next_credit = false,
                Err(ns::Error::Protocol(Fault::WouldBlock)) => {}
                Err(e) => return Poll::Ready(Err(e.into())),
            }
        }
        let hard = r.hard();
        let mut from_monitor = if r.monitor.is_some() {
            r.poll_monitor = !r.poll_monitor;
            r.poll_monitor
        } else {
            false
        };
        let mut event = if from_monitor {
            r.monitor
                .as_mut()
                .map(|m| m.poll(cx, r.monitor_span.map(|s| s.hard)))
                .unwrap_or(Poll::Pending)
        } else {
            r.client.poll(cx, hard)
        };
        if event.is_pending() {
            from_monitor = !from_monitor;
            event = if from_monitor {
                r.monitor
                    .as_mut()
                    .map(|m| m.poll(cx, r.monitor_span.map(|s| s.hard)))
                    .unwrap_or(Poll::Pending)
            } else {
                r.client.poll(cx, hard)
            };
        }
        let event = match event {
            Poll::Ready(Ok(v)) => v,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
            Poll::Pending => return Poll::Pending,
        };
        self.record_blocked = false;
        self.wake_domain();
        let mut binding = None;
        let mut installed = 0;
        let mut refusal = None;
        let mut loss = None;
        let result = (|| -> Result<(), Error> {
            match &event {
                ns::Progress::Connected(epoch) => {
                    if from_monitor {
                        self.records.as_mut().ok_or(Fault::Conflict)?.monitor_epoch = Some(*epoch);
                    }
                }
                ns::Progress::Queued {
                    epoch,
                    operation,
                    request_id,
                }
                | ns::Progress::Written {
                    epoch,
                    operation,
                    request_id,
                } => {
                    if let Some(p) = self
                        .records
                        .as_mut()
                        .ok_or(Fault::Conflict)?
                        .pending
                        .iter_mut()
                        .find(|p| p.native == Some(*operation))
                    {
                        if p.native_epoch.is_some_and(|old| old != *epoch) || p.rid != *request_id {
                            return Err(Fault::StaleGeneration.into());
                        }
                        p.native_epoch = Some(*epoch);
                    }
                }
                ns::Progress::Completed(completion) => {
                    let r = self.records.as_mut().ok_or(Fault::Conflict)?;
                    if let Some(i) = r
                        .pending
                        .iter()
                        .position(|p| p.native == Some(completion.operation))
                    {
                        let p = r.pending.remove(i);
                        binding = p.binding;
                        if p.native_epoch != completion.epoch
                            || p.rid != completion.request_id
                            || p.span.expired(None)
                        {
                            return Err(Fault::StaleGeneration.into());
                        }
                        if let Some(b) = p.binding {
                            let now = self.sample()?;
                            let outcome = (|| -> Result<(), domain::Error> {
                                if p.span.expired(Some(now))
                                    || self.rooms[self
                                        .room_index(p.room)
                                        .map_err(|_| Fault::StaleGeneration)?]
                                    .source
                                        != Some(p.source)
                                {
                                    return Err(Fault::StaleGeneration.into());
                                }
                                let ns::Outcome::Reply(reply) = &completion.outcome else {
                                    return Err(Fault::Closed.into());
                                };
                                let ns::ipc::Response::Lookup {
                                    zone,
                                    label,
                                    found,
                                    records,
                                    ..
                                } = reply.view()?
                                else {
                                    return Err(Fault::Conflict.into());
                                };
                                let signer = self
                                    .signers
                                    .iter()
                                    .position(|s| s.public == p.public)
                                    .ok_or(Fault::StaleGeneration)?;
                                if !key_matches(&self.signers[signer].secret, zone)
                                    || label.bytes() != p.label
                                {
                                    return Err(Fault::Authentication.into());
                                }
                                if found != 1 {
                                    return Err(if found == 0 {
                                        Fault::NotFound
                                    } else {
                                        Fault::Io
                                    }
                                    .into());
                                }
                                let mut chosen = None;
                                for data in records.records().iter() {
                                    let data = data?;
                                    if data.record_type != RecordType::MESSENGER_ROOM_EPOCH_KEY
                                        || !data.flags.contains(RecordFlags::PRIVATE)
                                    {
                                        continue;
                                    }
                                    let rec = Record::decode(
                                        data.record_type,
                                        data.data,
                                        self.profiles
                                            .record_profile(&p.public, data.record_type, data.data)
                                            .ok_or(Fault::Unavailable)?,
                                    )?;
                                    if let Record::EpochKey {
                                        room_key,
                                        epoch,
                                        identifier,
                                        ..
                                    } = rec
                                        && room_key == self.core.room_key(p.room)?
                                        && epoch == b.epoch()
                                        && identifier == b.identifier()
                                    {
                                        if chosen.is_some() {
                                            return Err(Fault::Conflict.into());
                                        }
                                        chosen = Some(rec);
                                    }
                                }
                                let r = self.records.as_ref().ok_or(Fault::NotReady)?;
                                self.core.complete_epoch_record(
                                    b,
                                    &r.root,
                                    chosen.ok_or(Fault::NotFound)?,
                                    now,
                                )?;
                                installed = 1;
                                Ok(())
                            })();
                            if let Err(e) = outcome {
                                self.core.provider_failed(b, e)?;
                                refusal = Some(e);
                            } else {
                                self.reset_decryption();
                                self.wake_domain();
                            }
                        }
                    }
                }
                ns::Progress::Record {
                    epoch,
                    operation,
                    reply,
                } => {
                    let r = self.records.as_ref().ok_or(Fault::Conflict)?;
                    let monitor = r.monitor.as_ref().ok_or(Fault::StaleGeneration)?;
                    if monitor.operation() != *operation || r.monitor_epoch != Some(*epoch) {
                        return Err(Fault::StaleGeneration.into());
                    }
                    let span = r.monitor_span.ok_or(Fault::Conflict)?;
                    let ns::ipc::Response::Records { zone, records, .. } = reply.view()? else {
                        return Err(Fault::Conflict.into());
                    };
                    let public = self
                        .signers
                        .iter()
                        .find(|s| key_matches(&s.secret, zone))
                        .map(|s| s.public)
                        .ok_or(Fault::Authentication)?;
                    // A monitor is bound to its original room/source snapshot.
                    for i in 0..self.records.as_ref().ok_or(Fault::Conflict)?.watch.len() {
                        let watch = self.records.as_ref().ok_or(Fault::Conflict)?.watch[i];
                        if watch.public != public {
                            continue;
                        }
                        match self.apply_record_set(watch, records, span) {
                            Ok(n) => installed += n,
                            Err(e) => refusal = Some(e),
                        }
                    }
                    self.records.as_mut().ok_or(Fault::Conflict)?.next_credit = true;
                }
                ns::Progress::Lost { .. } | ns::Progress::Unavailable(_) => {
                    let r = self.records.as_mut().ok_or(Fault::Conflict)?;
                    let stopped = r.close();
                    for p in &stopped.pending {
                        if let Some(b) = p.binding {
                            self.core.provider_failed(b, Fault::Closed.into())?;
                        }
                    }
                    loss = Some(stopped);
                    self.wake_domain();
                }
                _ => {}
            }
            Ok(())
        })();
        if let Err(e) = result {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(RecordProgress {
            original: event,
            binding,
            installed,
            refusal,
            loss,
        }))
    }
}
struct StoreMetadata {
    flags: RecordFlags,
    expiration: u64,
}
struct StoreZone<'s> {
    secret: &'s gnunet_identity::SecretKey,
    public: PublicKey,
    profiles: &'s mut Profiles,
}
fn store_one<'a>(
    client: &mut ns::Client<'a>,
    zone: StoreZone<'_>,
    label: &[u8],
    record: Record<'_>,
    profile: wire::profile::Profile,
    span: Span,
    metadata: StoreMetadata,
) -> Result<ns::Operation<'a>, Error> {
    if span.expired(None) {
        return Err(Fault::Timeout.into());
    }
    let mut payload = zeroize::Zeroizing::new([0; wire::records::ENCRYPTION_KEY_LEN]);
    let n = record.encode(profile, payload.as_mut())?;
    zone.profiles
        .produced_record(zone.public, record.record_type(), &payload[..n], profile)?;
    let data = RecordData {
        expiration_time: metadata.expiration,
        record_type: record.record_type(),
        flags: metadata.flags,
        data: &payload[..n],
    };
    let mut encoded = zeroize::Zeroizing::new([0; 1024]);
    let n = gnunet_gnsrecord::serialize(&[data], encoded.as_mut())?;
    let records = ns::ipc::Records::new(&encoded[..n], 1)?;
    let set = ns::ipc::StoreSet {
        label: ns::ipc::CString::new(label)?,
        records,
        reserved: 0,
    };
    let stored = client.store_batch(zone.secret, &[set], true, span.logical)?;
    if stored.sets_sent != 1 {
        return Err(Fault::Conflict.into());
    }
    Ok(stored.operation)
}

fn key_matches(
    key: &gnunet_identity::SecretKey,
    view: gnunet_wire::official::identity::SecretKeyView<'_>,
) -> bool {
    bool::from(key.expose_serialized()[..].ct_eq(&view.expose_serialized()[..]))
}
