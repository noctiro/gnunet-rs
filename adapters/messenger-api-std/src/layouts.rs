//! Finite explicit original-producer facts and original held-notification needs.
//! This is local configuration, not wire negotiation or a signature/provider ACK.
use crate::{types::*, *};
use domain::{ClientLayout, OriginalSigner};
use gnunet_types::Error as Fault;
use wire::{
    body::Body,
    envelope::Envelope,
    profile::{Endian, Profile},
};
#[derive(Clone, Copy)]
struct Sender {
    hash: Hash,
    layout: ClientLayout,
}
#[derive(Clone, Copy)]
struct Message {
    room: Hash,
    hash: Hash,
    layout: ClientLayout,
}
#[derive(Clone, Copy)]
struct Identifier {
    room: Hash,
    epoch: Hash,
    id: ShortHash,
    order: Endian,
}
#[derive(Clone, Copy)]
struct RoomProfile {
    key: Hash,
    profile: Profile,
}
#[derive(Clone, Copy)]
struct RecordProfile {
    zone: PublicKey,
    kind: gnunet_gnsrecord::RecordType,
    hash: Option<Hash>,
    profile: Profile,
}
/// Bounded original body/short, identifier, room-capability and record producers.
/// None defaults make absent facts explicit rather than infer the current daemon
/// originated every forwarded message or every historical private-zone record.
pub struct Profiles {
    maximum: usize,
    local: Profile,
    default: Option<ClientLayout>,
    default_room: Option<Profile>,
    default_record: Option<Profile>,
    senders: Vec<Sender>,
    messages: Vec<Message>,
    identifiers: Vec<Identifier>,
    rooms: Vec<RoomProfile>,
    records: Vec<RecordProfile>,
}
fn reserve<T>(n: usize) -> Result<Vec<T>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Fault::Capacity)?;
    Ok(v)
}
impl Profiles {
    /// Explicit homogeneous producer contract used by Api::new's existing one-
    /// profile interface; mixed callers use new_profiled with independent facts.
    pub fn same(profile: Profile) -> Result<Self, Error> {
        Self::new(
            0,
            profile,
            Some(ClientLayout::same(profile)),
            Some(profile),
            Some(profile),
        )
    }
    /// Reserve fixed metadata before original IO. No key, crypto or IO is used.
    pub fn new(
        maximum: usize,
        local: Profile,
        default: Option<ClientLayout>,
        default_room: Option<Profile>,
        default_record: Option<Profile>,
    ) -> Result<Self, Error> {
        local.validate()?;
        if let Some(x) = default {
            x.validate()?;
        }
        for p in [default_room, default_record].into_iter().flatten() {
            p.validate()?;
        }
        Ok(Self {
            maximum,
            local,
            default,
            default_room,
            default_record,
            senders: reserve(maximum)?,
            messages: reserve(maximum)?,
            identifiers: reserve(maximum)?,
            rooms: reserve(maximum)?,
            records: reserve(maximum)?,
        })
    }
    /// Actual local Rust signed-body/short encoder, independent from the
    /// connected daemon's native IPC reset-field profile.
    pub const fn local_profile(&self) -> Profile {
        self.local
    }
    pub(crate) fn common_record_profile(&self) -> Option<Profile> {
        self.default_record
    }
    /// Actual allocated configuration capacities, charged to Api's own budget.
    pub fn bytes(&self) -> Result<usize, Error> {
        [
            (self.senders.capacity(), std::mem::size_of::<Sender>()),
            (self.messages.capacity(), std::mem::size_of::<Message>()),
            (
                self.identifiers.capacity(),
                std::mem::size_of::<Identifier>(),
            ),
            (self.rooms.capacity(), std::mem::size_of::<RoomProfile>()),
            (
                self.records.capacity(),
                std::mem::size_of::<RecordProfile>(),
            ),
        ]
        .into_iter()
        .try_fold(0usize, |n, (a, b)| {
            n.checked_add(a.checked_mul(b).ok_or(Fault::Overflow)?)
                .ok_or_else(|| Fault::Overflow.into())
        })
    }
    /// Exact attributed sender hash. Core still verifies its actual public-key
    /// hash/signature; a daemon's carried sender field is not trusted as proof.
    pub fn sender(&mut self, hash: Hash, layout: ClientLayout) -> Result<(), Error> {
        layout.validate()?;
        if self.senders.len() == self.maximum {
            return Err(Fault::Capacity.into());
        }
        if self.senders.iter().any(|s| s.hash == hash) {
            return Err(Fault::Conflict.into());
        }
        self.senders.push(Sender { hash, layout });
        Ok(())
    }
    /// Declare a real original member/peer public identity and its exact grammar.
    /// Only public bytes are hashed; no secret identity is accepted by this API.
    pub fn signer(
        &mut self,
        signer: OriginalSigner,
        mut layout: ClientLayout,
    ) -> Result<(), Error> {
        layout.original.signer = Some(signer);
        let hash = match signer {
            OriginalSigner::Member(p) => {
                wire::PublicKey::new(&p)?;
                gnunet_crypto::hash512(&p)
            }
            OriginalSigner::Peer(p) => gnunet_crypto::hash512(&p),
        };
        self.sender(hash, layout)
    }
    /// Exact original room/message override; useful when one key has produced
    /// different layouts. It never rewrites or retags the original byte string.
    pub fn message(&mut self, room: Hash, hash: Hash, layout: ClientLayout) -> Result<(), Error> {
        layout.validate()?;
        if self.messages.len() == self.maximum {
            return Err(Fault::Capacity.into());
        }
        if self
            .messages
            .iter()
            .any(|r| r.room == room && r.hash == hash)
        {
            return Err(Fault::Conflict.into());
        }
        self.messages.push(Message { room, hash, layout });
        Ok(())
    }
    /// Original raw identifier creator. A later sender's ABI is independent.
    pub fn identifier(
        &mut self,
        room: Hash,
        epoch: Hash,
        id: ShortHash,
        order: Endian,
    ) -> Result<(), Error> {
        if self.identifiers.len() == self.maximum {
            return Err(Fault::Capacity.into());
        }
        if self
            .identifiers
            .iter()
            .any(|r| r.room == room && r.epoch == epoch && r.id == id)
        {
            return Err(Fault::Conflict.into());
        }
        self.identifiers.push(Identifier {
            room,
            epoch,
            id,
            order,
        });
        Ok(())
    }
    /// Explicit room-capability creator, independent from IPC/body producers.
    pub fn room(&mut self, key: Hash, profile: Profile) -> Result<(), Error> {
        profile.validate()?;
        if self.rooms.len() == self.maximum {
            return Err(Fault::Capacity.into());
        }
        if self.rooms.iter().any(|r| r.key == key) {
            return Err(Fault::Conflict.into());
        }
        self.rooms.push(RoomProfile { key, profile });
        Ok(())
    }
    /// Private-zone record producer, selected before typed flags/length parsing.
    /// Exact data hash wins over the zone/type default; this hashes ciphertext
    /// record bytes only, never any private key/secret serialization.
    pub fn record(
        &mut self,
        zone: PublicKey,
        kind: gnunet_gnsrecord::RecordType,
        hash: Option<Hash>,
        profile: Profile,
    ) -> Result<(), Error> {
        profile.validate()?;
        wire::PublicKey::new(&zone)?;
        if self.records.len() == self.maximum {
            return Err(Fault::Capacity.into());
        }
        if self
            .records
            .iter()
            .any(|r| r.zone == zone && r.kind == kind && r.hash == hash)
        {
            return Err(Fault::Conflict.into());
        }
        self.records.push(RecordProfile {
            zone,
            kind,
            hash,
            profile,
        });
        Ok(())
    }
    pub(crate) fn body(&self, room: &Hash, hash: &Hash, sender: &Hash) -> Option<ClientLayout> {
        self.messages
            .iter()
            .find(|r| r.room == *room && r.hash == *hash)
            .map(|r| r.layout)
            .or_else(|| {
                self.senders
                    .iter()
                    .find(|r| r.hash == *sender)
                    .map(|r| r.layout)
            })
    }
    pub(crate) fn room_profile(&self, key: &Hash) -> Option<Profile> {
        self.rooms
            .iter()
            .find(|r| r.key == *key)
            .map(|r| r.profile)
            .or(self.default_room)
    }
    pub(crate) fn common_identifier_order(&self) -> Option<Endian> {
        self.default.and_then(|layout| layout.identifier_order)
    }
    pub(crate) fn identifier_origin(
        &self,
        room: &Hash,
        epoch: &Hash,
        id: &ShortHash,
    ) -> Option<Endian> {
        self.identifiers
            .iter()
            .find(|r| r.room == *room && r.epoch == *epoch && r.id == *id)
            .map(|r| r.order)
    }
    pub(crate) fn produced_record(
        &mut self,
        zone: PublicKey,
        kind: gnunet_gnsrecord::RecordType,
        raw: &[u8],
        profile: Profile,
    ) -> Result<(), Error> {
        if self
            .record_profile(&zone, kind, raw)
            .is_some_and(|known| known.endian == profile.endian)
        {
            return Ok(());
        }
        self.record(zone, kind, Some(gnunet_crypto::hash512(raw)), profile)
    }
    pub(crate) fn record_profile(
        &self,
        zone: &PublicKey,
        kind: gnunet_gnsrecord::RecordType,
        raw: &[u8],
    ) -> Option<Profile> {
        if self.records.is_empty() {
            return self.default_record;
        }
        let hash = gnunet_crypto::hash512(raw);
        self.records
            .iter()
            .find(|r| r.zone == *zone && r.kind == kind && r.hash == Some(hash))
            .map(|r| r.profile)
            .or_else(|| {
                self.records
                    .iter()
                    .find(|r| r.zone == *zone && r.kind == kind && r.hash.is_none())
                    .map(|r| r.profile)
            })
            .or(self.default_record)
    }
}
pub(crate) enum Selection {
    Ready(ClientLayout),
    Need {
        requirement: LayoutRequirement,
        identifier: Option<(Hash, ShortHash)>,
    },
}
/// An actual original notification needs an explicit local decoding fact.
/// Carried sender/hash/id metadata is not an authentication assertion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LayoutRequirement {
    /// Original signed-body/plaintext producer.
    Producer,
    /// Creator order of a new exact raw group identifier.
    Identifier,
}
/// Original held notification scope. Private construction binds this need to
/// one owner/actual epoch/notification serial; no fake RID or new timeout exists.
#[derive(Clone, Copy)]
pub struct LayoutNeed<'a> {
    pub(crate) owner: u64,
    pub(crate) epoch: native::Epoch<'a>,
    pub(crate) serial: u64,
    pub(crate) room: Room<'a>,
    pub(crate) hash: Hash,
    pub(crate) sender: Hash,
    pub(crate) identifier: Option<(Hash, ShortHash)>,
    pub(crate) requirement: LayoutRequirement,
}
impl std::fmt::Debug for LayoutNeed<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessengerLayoutNeed([REDACTED], not authenticated)")
            .field("requirement", &self.requirement)
            .finish_non_exhaustive()
    }
}
impl<'a> LayoutNeed<'a> {
    /// Original actual source epoch, not producer-origin identity.
    pub const fn epoch(&self) -> native::Epoch<'a> {
        self.epoch
    }
    /// Exact original room generation.
    pub const fn room(&self) -> Room<'a> {
        self.room
    }
    /// Carried original message hash awaiting actual Core checking.
    pub const fn message(&self) -> &Hash {
        &self.hash
    }
    /// Carried attributed-sender hash awaiting actual signature/public-key checks.
    pub const fn sender(&self) -> &Hash {
        &self.sender
    }
    /// Exact raw epoch/identifier when its creator order is missing.
    pub const fn identifier(&self) -> Option<(&Hash, &ShortHash)> {
        match &self.identifier {
            Some((epoch, id)) => Some((epoch, id)),
            None => None,
        }
    }
    /// Exact missing local fact; never a successful provider completion.
    pub const fn requirement(&self) -> LayoutRequirement {
        self.requirement
    }
}
impl<'a, E: crypto::Entropy, const N: usize> Api<'a, E, N> {
    /// Fulfill only the exact still-held original input. This supplies grammar
    /// facts, not authenticated data; Core still verifies source/hash/signature,
    /// AEAD and the original carried short digest. No original deadline extends.
    pub fn provide_layout(
        &mut self,
        need: LayoutNeed<'a>,
        layout: ClientLayout,
    ) -> Result<(), Error> {
        layout.validate()?;
        let valid = self.held_notification.as_ref().is_some_and(|held| {
            need.owner == self.owner
                && self.epoch == Some(need.epoch)
                && held.epoch == need.epoch
                && held.serial == need.serial
                && !held.applied
                && held.need.is_some_and(|original| {
                    original.serial == need.serial
                        && original.room == need.room
                        && original.hash == need.hash
                        && original.requirement == need.requirement
                })
        });
        if !valid {
            return Err(Fault::StaleGeneration.into());
        }
        let now = self.sample()?;
        if self
            .held_notification
            .as_ref()
            .is_none_or(|held| held.span.expired(Some(now)))
        {
            self.capture_stop(StopCause::Initialization, false, None);
            return Err(Fault::Timeout.into());
        }
        let held = self
            .held_notification
            .as_mut()
            .ok_or(Fault::StaleGeneration)?;
        held.layout = Some(layout);
        held.need = None;
        held.need_reported = false;
        self.wake_domain();
        Ok(())
    }
    /// Add a record-layout fact only while its original actual NAMESTORE source
    /// remains current. Old source tokens cannot retag a replacement MQ. This
    /// does not replay an old lookup/STORE or complete its failed result.
    pub fn declare_record_layout(
        &mut self,
        source: gnunet_namestore_client_host::Epoch<'a>,
        zone: PublicKey,
        kind: gnunet_gnsrecord::RecordType,
        hash: Option<Hash>,
        profile: Profile,
    ) -> Result<(), Error> {
        if self
            .records
            .as_ref()
            .is_none_or(|r| !r.source_current(source))
        {
            return Err(Fault::StaleGeneration.into());
        }
        self.profiles.record(zone, kind, hash, profile)
    }
    /// Supply an identifier creator for records from the exact still-current
    /// original NAMESTORE source. It cannot retag another MQ or authorize a key.
    pub fn declare_record_identifier(
        &mut self,
        source: gnunet_namestore_client_host::Epoch<'a>,
        room: Room<'a>,
        epoch: Hash,
        id: ShortHash,
        order: Endian,
    ) -> Result<(), Error> {
        if self
            .records
            .as_ref()
            .is_none_or(|r| !r.source_current(source))
        {
            return Err(Fault::StaleGeneration.into());
        }
        let key = *self.core.room_key(room)?;
        self.profiles.identifier(key, epoch, id, order)
    }
    pub(crate) fn layout_progress(&mut self) -> Option<Progress<'a>> {
        let held = self.held_notification.as_mut()?;
        if held.need_reported {
            return None;
        }
        let need = held.need?;
        held.need_reported = true;
        Some(Progress::LayoutNeeded(need))
    }
    pub(crate) fn original_layout(
        &self,
        index: usize,
        source: Source<'a>,
        response: wire::Response<'_>,
        override_layout: Option<ClientLayout>,
    ) -> Result<Selection, Error> {
        let wire::Response::Receive {
            key,
            sender,
            hash,
            epoch,
            message,
            ..
        } = response
        else {
            return Ok(Selection::Ready(ClientLayout::same(
                self.core.local_profile(),
            )));
        };
        let room = self.rooms[index].room;
        let retained = self.core.message(room, hash).ok().and_then(|m| {
            m.cipher_layout().map(|plaintext| ClientLayout {
                original: m.layout(),
                plaintext,
                transcript: m.transcript_layout().unwrap_or(plaintext),
                identifier_order: None,
            })
        });
        let local = self.leases.iter().find_map(|l| {
            (l.source == source
                && self.epoch == Some(l.epoch)
                && l.kind == Some(native::Kind::Send)
                && l.binding.is_some_and(|b| b.message() == hash))
            .then_some(
                l.layout
                    .unwrap_or(ClientLayout::same(self.core.local_profile())),
            )
        });
        let Some(mut layout) = local
            .or(override_layout)
            .or_else(|| self.profiles.body(key, hash, sender))
            .or(retained)
            .or(self.profiles.default)
        else {
            return Ok(Selection::Need {
                requirement: LayoutRequirement::Producer,
                identifier: None,
            });
        };
        layout.validate()?;
        let kind = Envelope::decode(message.expose())?.header()?.kind;
        let parsed = wire::message::Message::decode_with_profiles(
            message.expose(),
            layout.original.body_profile(kind)?,
            layout.original.padding,
            wire::padding::Decode::Absent,
        )?;
        let id = match parsed.body() {
            Body::Announcement { identifier, .. }
            | Body::Group { identifier, .. }
            | Body::Revolution { identifier, .. } => Some(*identifier),
            _ => None,
        };
        if let Some(id) = id {
            layout.identifier_order = self
                .core
                .group_identifier_order(room, &id)?
                .or_else(|| self.profiles.identifier_origin(key, epoch, &id))
                .or(layout.identifier_order);
            if layout.identifier_order.is_none() {
                return Ok(Selection::Need {
                    requirement: LayoutRequirement::Identifier,
                    identifier: Some((*epoch, id)),
                });
            }
        }
        Ok(Selection::Ready(layout))
    }
}
