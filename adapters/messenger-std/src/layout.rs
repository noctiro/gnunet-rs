//! Explicit bounded producer policy. Packed padding belongs to its immediate
//! encoder; signed body/profile attribution belongs to its original signer/hash.
//! This module never falls back by trying host byte orders or modifies signatures.
use crate::core::{
    self, BodyLayout, OriginalLayout, OriginalSigner,
    wire::{self, padding, profile::Profile},
};
use gnunet_types::Error as Fault;
use wire::{
    body::Body,
    envelope::{Envelope, Kind},
};
/// One immutable explicitly configured original-message override.
#[derive(Clone, Copy)]
pub enum Selector {
    /// Exact original room/message and original signing principal.
    Message {
        /// Actual room capability key.
        room: [u8; 64],
        /// Exact canonical signed-message hash, excluding outer padding.
        hash: [u8; 64],
        /// Expected original cryptographic principal.
        signer: OriginalSigner,
    },
    /// Original member signing key; independent from a forwarding connection.
    Member([u8; 36]),
    /// Original peer-control signing key; independent from a forwarding connection.
    Peer([u8; 32]),
}
impl std::fmt::Debug for Selector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProducerSelector([REDACTED])")
    }
}
struct Rule {
    selector: Selector,
    body: BodyLayout,
}
/// Explicit per-peer transport contract. The pinned C endpoints encode AND
/// decode padding in their own host order, so cross-layout Rust adaptation may
/// need independent incoming/outgoing declarations; there is no wire negotiation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Transport {
    /// Remote daemon's native word layout for room port hashing.
    pub port: Profile,
    /// Encoder layout of actual incoming outer padding.
    pub incoming_padding: Profile,
    /// Layout required by that actual remote decoder for outgoing outer padding.
    pub outgoing_padding: Profile,
}
impl Transport {
    /// One explicitly declared unchanged C daemon ABI.
    pub const fn c_abi(profile: Profile) -> Self {
        Self {
            port: profile,
            incoming_padding: profile,
            outgoing_padding: profile,
        }
    }
    fn validate(self) -> Result<(), core::Error> {
        self.port.validate()?;
        self.incoming_padding.validate()?;
        self.outgoing_padding.validate()?;
        Ok(())
    }
}
/// Bounded explicit peer encoding/room encoding/original signer/message policy.
/// Portable denotes the mathematically profile-independent non-FILE SERVICE
/// grammar, not a claim that the original producer shared the local machine.
pub struct Policy {
    maximum: usize,
    rules: Vec<Rule>,
    relays: Vec<([u8; 32], Transport)>,
    rooms: Vec<([u8; 64], Profile)>,
    default_relay: Transport,
    default_room: Profile,
    common_file: Option<Profile>,
}
impl Policy {
    /// Configure source defaults explicitly. common_file declares the allowed
    /// FILE NAME_MAX for otherwise unspecified producers; None rejects unknown FILE
    /// layouts. No wire bytes or connection are used to guess this constraint.
    pub fn new(
        maximum: usize,
        default_relay: Profile,
        default_room: Profile,
        common_file: Option<Profile>,
    ) -> Result<Self, core::Error> {
        if maximum == 0 {
            return Err(Fault::Capacity.into());
        }
        default_relay.validate()?;
        default_room.validate()?;
        if let Some(p) = common_file {
            p.validate()?
        }
        let mut rules = Vec::new();
        let mut relays = Vec::new();
        let mut rooms = Vec::new();
        rules
            .try_reserve_exact(maximum)
            .map_err(|_| Fault::Capacity)?;
        relays
            .try_reserve_exact(maximum)
            .map_err(|_| Fault::Capacity)?;
        rooms
            .try_reserve_exact(maximum)
            .map_err(|_| Fault::Capacity)?;
        Ok(Self {
            maximum,
            rules,
            relays,
            rooms,
            default_relay: Transport::c_abi(default_relay),
            default_room,
            common_file,
        })
    }
    /// Bind an exact original producer policy; duplicate selectors are refused.
    pub fn insert(&mut self, selector: Selector, body: BodyLayout) -> Result<(), core::Error> {
        if let BodyLayout::Explicit(p) = body {
            p.validate()?
        }
        if self.rules.len() == self.maximum {
            return Err(Fault::Capacity.into());
        }
        let same = |a: Selector, b: Selector| match (a, b) {
            (
                Selector::Message {
                    room: a, hash: x, ..
                },
                Selector::Message {
                    room: b, hash: y, ..
                },
            ) => a == b && x == y,
            (Selector::Member(a), Selector::Member(b)) => a == b,
            (Selector::Peer(a), Selector::Peer(b)) => a == b,
            _ => false,
        };
        if self.rules.iter().any(|r| same(r.selector, selector)) {
            return Err(Fault::Conflict.into());
        }
        if let Selector::Member(public) = selector {
            wire::PublicKey::new(&public)?;
        }
        self.rules.push(Rule { selector, body });
        Ok(())
    }
    /// Explicit current relay daemon profile, used only for its port/padding.
    pub fn insert_relay(&mut self, peer: [u8; 32], profile: Profile) -> Result<(), core::Error> {
        self.insert_transport(peer, Transport::c_abi(profile))
    }
    /// Explicit independent transport profiles, for Rust/Rust or adapted endpoints.
    pub fn insert_transport(
        &mut self,
        peer: [u8; 32],
        transport: Transport,
    ) -> Result<(), core::Error> {
        transport.validate()?;
        if self.relays.len() == self.maximum {
            return Err(Fault::Capacity.into());
        }
        if self.relays.iter().any(|(p, _)| *p == peer) {
            return Err(Fault::Conflict.into());
        }
        self.relays.push((peer, transport));
        Ok(())
    }
    /// Explicit capability creator profile, used only for room flag interpretation.
    pub fn insert_room(&mut self, key: [u8; 64], profile: Profile) -> Result<(), core::Error> {
        profile.validate()?;
        if self.rooms.len() == self.maximum {
            return Err(Fault::Capacity.into());
        }
        if self.rooms.iter().any(|(k, _)| *k == key) {
            return Err(Fault::Conflict.into());
        }
        self.rooms.push((key, profile));
        Ok(())
    }
    /// Exact configured current relay profile; not an original signer assertion.
    pub fn relay(&self, peer: &[u8; 32]) -> Profile {
        self.transport(peer).port
    }
    /// Exact configured actual padding encoder/decoder profiles.
    pub fn transport(&self, peer: &[u8; 32]) -> Transport {
        self.relays
            .iter()
            .find(|(p, _)| p == peer)
            .map_or(self.default_relay, |(_, p)| *p)
    }
    /// Exact configured capability-creator profile, independent from a relay.
    pub fn room(&self, key: &[u8; 64]) -> Profile {
        self.rooms
            .iter()
            .find(|(k, _)| k == key)
            .map_or(self.default_room, |(_, p)| *p)
    }
    fn default_body(&self, kind: Kind) -> Result<BodyLayout, core::Error> {
        if !kind.is_known() {
            return Err(Fault::Unsupported.into());
        }
        if kind == Kind::FILE {
            self.common_file
                .map(BodyLayout::Explicit)
                .ok_or_else(|| Fault::Unavailable.into())
        } else {
            Ok(BodyLayout::Portable)
        }
    }
    fn subject(&self, signer: OriginalSigner, kind: Kind) -> Result<BodyLayout, core::Error> {
        self.rules
            .iter()
            .find_map(|r| match (r.selector, signer) {
                (Selector::Member(a), OriginalSigner::Member(b)) if a == b => Some(r.body),
                (Selector::Peer(a), OriginalSigner::Peer(b)) if a == b => Some(r.body),
                _ => None,
            })
            .map_or_else(|| self.default_body(kind), Ok)
    }
    /// Select a real accepted app's signed body from its actually bound OPEN
    /// principal. IPC SEND is unpadded. This does not authenticate that principal
    /// or relax Core's exact actual app public-key/assigned-ID signature checks.
    pub fn application(
        &self,
        core: &core::Core<'_>,
        source: core::Source<'_>,
        raw: &[u8],
    ) -> Result<OriginalLayout, core::Error> {
        let (public, _) = core.service_client(source)?;
        let header = Envelope::decode(raw)?.header()?;
        let digest = gnunet_crypto::hash512(raw.get(68..).ok_or(Fault::Truncated)?);
        let room = core.source_room(source)?;
        let key = core.room_key(room)?;
        let signer = OriginalSigner::Member(public);
        let rule = self.rules.iter().find(
            |r| matches!(r.selector,Selector::Message{room:r,hash,..}if r==*key&&hash==digest),
        );
        let body = if let Some(rule) = rule {
            if !matches!(rule.selector,Selector::Message{signer:expected,..}if expected==signer) {
                return Err(Fault::Authentication.into());
            }
            rule.body
        } else {
            self.subject(signer, header.kind)?
        };
        Ok(OriginalLayout {
            body,
            padding: self.default_room,
            signer: Some(signer),
        })
    }
    /// Select explicit original body provenance. Signature-specific ambiguity is
    /// resolved only by actual verification under configured known principals;
    /// the Core independently checks source generation, signature and membership.
    pub fn incoming(
        &self,
        core: &core::Core<'_>,
        room: core::Room<'_>,
        raw: &[u8],
        relay: [u8; 32],
        mode: padding::Decode,
    ) -> Result<OriginalLayout, core::Error> {
        let transport = self.transport(&relay).incoming_padding;
        let env = Envelope::decode(raw)?;
        let header = env.header()?;
        let split = padding::split(env.raw_body(), transport, mode)?;
        let end = raw
            .len()
            .checked_sub(split.padding.len())
            .ok_or(Fault::Malformed)?;
        let digest = gnunet_crypto::hash512(raw.get(68..end).ok_or(Fault::Truncated)?);
        let key = core.room_key(room)?;
        if let Some(rule) = self.rules.iter().find(
            |r| matches!(r.selector,Selector::Message{room:r,hash,..}if r==*key&&hash==digest),
        ) {
            let Selector::Message { signer, .. } = rule.selector else {
                return Err(Fault::Conflict.into());
            };
            return Ok(OriginalLayout {
                body: rule.body,
                padding: transport,
                signer: Some(signer),
            });
        }
        if let Ok(message) = core.message(room, &digest)
            && let Some(signer) = message.original_signer()
        {
            return Ok(OriginalLayout {
                body: message.layout().body,
                padding: transport,
                signer: Some(signer),
            });
        }
        if matches!(
            header.kind,
            Kind::INFO | Kind::PEER | Kind::MISS | Kind::MERGE | Kind::CONNECTION
        ) {
            let signer = OriginalSigner::Peer(*header.sender_id);
            return Ok(OriginalLayout {
                body: self.subject(signer, header.kind)?,
                padding: transport,
                signer: Some(signer),
            });
        }
        if header.kind == Kind::JOIN {
            let message = wire::message::Message::decode_with_profiles(
                raw,
                Profile::LITTLE_255,
                transport,
                mode,
            )?;
            let Body::Join { public_key, .. } = message.body() else {
                return Err(Fault::Malformed.into());
            };
            let signer = OriginalSigner::Member(*public_key.as_bytes());
            return Ok(OriginalLayout {
                body: self.subject(signer, header.kind)?,
                padding: transport,
                signer: Some(signer),
            });
        }
        let mut candidates = Vec::new();
        candidates
            .try_reserve(core.members(room)?.count())
            .map_err(|_| Fault::Capacity)?;
        for (member, _, id, _) in core.members(room)? {
            if id != *header.sender_id {
                continue;
            }
            let public = *core.member_public(member)?;
            if !candidates.iter().any(|(p, _)| *p == public) {
                let signer = OriginalSigner::Member(public);
                candidates.push((public, self.subject(signer, header.kind)?));
            }
        }
        if candidates.is_empty() {
            return Ok(OriginalLayout {
                body: self.default_body(header.kind)?,
                padding: transport,
                signer: None,
            });
        }
        if candidates.iter().all(|(_, p)| *p == candidates[0].1) {
            return Ok(OriginalLayout {
                body: candidates[0].1,
                padding: transport,
                signer: if candidates.len() == 1 {
                    Some(OriginalSigner::Member(candidates[0].0))
                } else {
                    None
                },
            });
        }
        let mut selected = None;
        for (public, body) in candidates {
            let layout = OriginalLayout {
                body,
                padding: transport,
                signer: Some(OriginalSigner::Member(public)),
            };
            let parsed = wire::message::Message::decode_with_profiles(
                raw,
                layout.body_profile(header.kind)?,
                transport,
                mode,
            );
            if let Ok(message) = parsed
                && core::crypto::signature::verify_member(message, wire::PublicKey::new(&public)?)
                    .is_ok()
            {
                if selected.is_some() {
                    return Err(Fault::Conflict.into());
                }
                selected = Some(layout)
            }
        }
        selected.ok_or_else(|| Fault::Authentication.into())
    }
}
