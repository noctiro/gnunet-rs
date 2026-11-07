//! Actual inline CORE effect sink and bounded peer/application coordination.
use super::loose::{Loose, Waiting};
use super::observations::ChannelObservations;
use super::types::{ChannelBuffers, Error, Limits, Refusal, Report, Signing};
use crate::{connection as bridge, server};
use gnunet_cadet::{
    connection::{self, Book, Frame, Outcome, Reset},
    peer::{self, ChannelOwner},
    service as app,
    tunnel::{
        context,
        controller::{self, Controller, QueuedControl},
        identity_dh,
    },
};
use gnunet_crypto::Entropy;
use gnunet_types::{Error as ProtocolError, MonoInstant};
use gnunet_wire::official::cadet_peer::{ChannelMessage, PathPeers, PeerMessage};
use std::time::Duration;
use tokio::time::Instant;

pub(super) struct Tunnel<'node, 'store, 'book> {
    pub(super) peer: Option<[u8; 32]>,
    pub(super) owner: Option<Controller<'node, 'store, 'book>>,
    pub(super) free: Option<controller::Stores<'store>>,
    numbers: Option<peer::Numbers>,
    route: Option<connection::Route<'book>>,
    used: MonoInstant,
    ratchet_generation: Option<controller::Generation<'node>>,
    ratchet_at: MonoInstant,
    pub(super) closing: bool,
}
pub(super) struct Channel<'app, 'node, 'store, 'bytes> {
    pub(super) owner: Option<ChannelOwner<'node, 'store, 'bytes>>,
    observations: Option<ChannelObservations>,
    free: Option<ChannelBuffers<'store, 'bytes>>,
    tunnel: usize,
    open: Option<(app::Open<'app>, MonoInstant)>,
    open_hard: Option<Instant>,
    binding: Option<app::Binding<'app, 'node>>,
    admitted: [Option<app::Admitted<'app, 'node>>; 4],
    delivery: Option<app::PeerDelivery<'app, 'node>>,
    close: Option<app::Close<'app>>,
    closing: bool,
    lost: bool,
}
#[derive(Clone, Copy)]
pub(super) enum Effect<'node, 'book> {
    Control {
        tunnel: usize,
        queued: QueuedControl<'node, 'book>,
    },
    Channel {
        slot: usize,
        attempt: peer::Attempt<'node>,
        frame: Frame<'book>,
        route: connection::Route<'book>,
    },
    Rejection {
        tunnel: usize,
        channel: u32,
        frame: Frame<'book>,
    },
}
impl<'book> Effect<'_, 'book> {
    pub(super) fn frame(self) -> Frame<'book> {
        match self {
            Self::Control { queued, .. } => queued.frame(),
            Self::Channel { frame, .. } | Self::Rejection { frame, .. } => frame,
        }
    }
}
#[derive(Clone, Copy)]
pub(super) struct Pending<'node, 'book> {
    effect: Effect<'node, 'book>,
    started: bool,
}
#[derive(Clone, Copy)]
struct Held<'book> {
    tunnel: usize,
    allocation: u64,
    route: connection::Route<'book>,
    length: usize,
}
#[derive(Clone, Copy)]
struct Used {
    tunnel: u64,
    channel: u32,
}

pub(super) struct State<'node, 'book, 'server, 'app, 'appstore, 'appbytes, 'store, 'bytes, E> {
    pub(super) server: &'server mut server::Server<'app, 'appstore, 'appbytes>,
    contexts: context::Registry<'node>,
    channel_domain: &'node peer::Instance,
    pub(super) tunnels: Vec<Tunnel<'node, 'store, 'book>>,
    channels: Vec<Channel<'app, 'node, 'store, 'bytes>>,
    pending: Vec<Option<Pending<'node, 'book>>>,
    used: Vec<Option<Used>>,
    loose: Loose<'node>,
    loose_cursor: usize,
    pub(super) signs: Vec<Option<Signing<'book>>>,
    pub(super) monotime: Option<crate::signing::monotime::Range>,
    pub(super) monotime_notice: bool,
    pub(super) monotime_needed: bool,
    plaintext: &'store mut [u8],
    ciphertext: &'store mut [u8],
    held: Option<Held<'book>>,
    pub(super) entropy: E,
    pub(super) source: identity_dh::Source<'node>,
    pub(super) limits: Limits,
    pub(super) report: Report,
    pub(super) refusal: Option<Refusal>,
    pub(super) error: Option<ProtocolError>,
    pub(super) closing: bool,
    cursor: usize,
    class: u8,
    next_tick: MonoInstant,
}
fn fixed<T>(size: usize, make: impl FnMut() -> T) -> Result<Vec<T>, ProtocolError> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(size)
        .map_err(|_| ProtocolError::Capacity)?;
    result.resize_with(size, make);
    Ok(result)
}
impl<'node, 'book, 'server, 'app, 'appstore, 'appbytes, 'store, 'bytes, E: Entropy>
    State<'node, 'book, 'server, 'app, 'appstore, 'appbytes, 'store, 'bytes, E>
{
    pub(super) fn new(
        server: &'server mut server::Server<'app, 'appstore, 'appbytes>,
        storage: super::Storage<'node, 'store, 'bytes>,
        source: identity_dh::Source<'node>,
        limits: Limits,
        entropy: E,
        now: MonoInstant,
    ) -> Result<Self, Error> {
        let mut tunnels = Vec::new();
        tunnels
            .try_reserve_exact(storage.tunnels.len())
            .map_err(|_| ProtocolError::Capacity)?;
        for free in storage.tunnels {
            tunnels.push(Tunnel {
                peer: None,
                owner: None,
                free: Some(free),
                numbers: None,
                route: None,
                used: now,
                ratchet_generation: None,
                ratchet_at: now,
                closing: false,
            });
        }
        let mut channels = Vec::new();
        channels
            .try_reserve_exact(storage.channels.len())
            .map_err(|_| ProtocolError::Capacity)?;
        for free in storage.channels {
            channels.push(Channel {
                owner: None,
                observations: None,
                free: Some(free),
                tunnel: 0,
                open: None,
                open_hard: None,
                binding: None,
                admitted: [None; 4],
                delivery: None,
                close: None,
                closing: false,
                lost: false,
            });
        }
        Ok(Self {
            server,
            contexts: storage.contexts,
            channel_domain: storage.channel_domain,
            tunnels,
            channels,
            pending: fixed(limits.pending_frames, || None)?,
            used: fixed(limits.used_channels, || None)?,
            loose: Loose::new(limits.used_channels)?,
            loose_cursor: 0,
            signs: fixed(limits.pending_frames, || None)?,
            monotime: None,
            monotime_notice: false,
            monotime_needed: false,
            plaintext: storage.plaintext,
            ciphertext: storage.ciphertext,
            held: None,
            entropy,
            source,
            limits,
            report: Report::default(),
            refusal: None,
            error: None,
            closing: false,
            cursor: 0,
            class: 0,
            next_tick: now,
        })
    }
    pub(super) fn peer_statistics(&self) -> gnunet_cadet::statistics::Snapshot {
        let mut snapshot = self.contexts.statistics();
        snapshot.merge(&self.channel_domain.statistics());
        snapshot
    }
    pub(super) fn channel_observations(&self) -> impl Iterator<Item = &ChannelObservations> + '_ {
        self.channels
            .iter()
            .filter_map(|channel| channel.observations.as_ref())
    }
    fn fail(&mut self, peer: [u8; 32], channel: Option<u32>, reason: ProtocolError) {
        self.report.dropped = self.report.dropped.saturating_add(1);
        if self.refusal.is_none() {
            self.refusal = Some(Refusal {
                peer,
                channel,
                reason,
            });
        }
    }
    fn fault(&mut self, error: ProtocolError) {
        if self.error.is_none() {
            self.error = Some(error);
        }
    }
    fn tunnel_index(&self, peer: [u8; 32]) -> Option<usize> {
        self.tunnels
            .iter()
            .position(|t| t.peer == Some(peer) && t.owner.is_some() && !t.closing)
    }
    fn ensure_tunnel<const P: usize>(
        &mut self,
        peer: [u8; 32],
        book: &Book<'book, '_, '_, P>,
        now: MonoInstant,
    ) -> Result<usize, ProtocolError> {
        if let Some(index) = self.tunnel_index(peer) {
            self.tunnels[index].used = now;
            return Ok(index);
        }
        if self.closing {
            return Err(ProtocolError::Closed);
        }
        if self.tunnels.iter().any(|t| t.peer == Some(peer)) {
            return Err(ProtocolError::WouldBlock);
        }
        let index = self
            .tunnels
            .iter()
            .position(|t| t.peer.is_none() && t.free.is_some())
            .ok_or(ProtocolError::Capacity)?;
        let context = self.contexts.allocate(self.server.local_peer(), peer)?;
        let stores = self.tunnels[index]
            .free
            .take()
            .ok_or(ProtocolError::Capacity)?;
        // Stores were prevalidated by Node construction; no IO or secret callback
        // occurs between reserve and this actual constructor.
        let owner = Controller::new_external_identity(
            context,
            self.source,
            book.reset_authority(),
            stores,
            self.limits.tunnel,
            now,
        )?;
        self.tunnels[index].numbers = Some(peer::Numbers::new(&self.server.local_peer(), &peer)?);
        self.tunnels[index].owner = Some(owner);
        self.tunnels[index].peer = Some(peer);
        self.tunnels[index].used = now;
        self.tunnels[index].closing = false;
        self.tunnels[index].ratchet_generation = None;
        self.tunnels[index].ratchet_at = now;
        self.report.tunnels = self.report.tunnels.saturating_add(1);
        Ok(index)
    }
    fn ensure_route<const P: usize>(
        &mut self,
        index: usize,
        book: &mut Book<'book, '_, '_, P>,
        now: MonoInstant,
    ) -> Result<bool, ProtocolError> {
        let peer = self.tunnels[index]
            .peer
            .ok_or(ProtocolError::StaleGeneration)?;
        if book.select(peer).is_some() {
            return Ok(true);
        }
        if self.tunnels[index].route.is_some_and(|route| {
            book.route_info(route)
                .is_ok_and(|info| info.phase != connection::Phase::Retired)
        }) {
            return Ok(false);
        }
        if book.current_neighbor(peer).is_none() {
            return Ok(false);
        }
        let path = [self.server.local_peer(), peer];
        self.ensure_path(index, book, &path, now)
    }
    fn ensure_path<const P: usize>(
        &mut self,
        index: usize,
        book: &mut Book<'book, '_, '_, P>,
        path: &[[u8; 32]],
        now: MonoInstant,
    ) -> Result<bool, ProtocolError> {
        let peer = self.tunnels[index]
            .peer
            .ok_or(ProtocolError::StaleGeneration)?;
        if book.select(peer).is_some() {
            return Ok(true);
        }
        if self.tunnels[index].route.is_some_and(|r| {
            book.route_info(r)
                .is_ok_and(|i| i.phase != connection::Phase::Retired)
        }) {
            return Ok(false);
        }
        let owner = self.tunnels[index]
            .owner
            .as_ref()
            .ok_or(ProtocolError::StaleGeneration)?;
        let reset = owner.scope().local() > peer && owner.snapshot().confirmed.is_none();
        let sign_slot = if reset {
            Some(
                self.signs
                    .iter()
                    .position(Option::is_none)
                    .ok_or(ProtocolError::Capacity)?,
            )
        } else {
            None
        };
        let authentication = if reset {
            let Some(range) = self.monotime.as_mut() else {
                if !self.monotime_needed {
                    self.monotime_notice = true;
                    self.monotime_needed = true;
                }
                return Ok(false);
            };
            match range.take_next() {
                Ok(value) => connection::Authentication::Monotime(value),
                Err(_) => {
                    self.monotime = None;
                    if !self.monotime_needed {
                        self.monotime_notice = true;
                        self.monotime_needed = true;
                    }
                    return Ok(false);
                }
            }
        } else {
            connection::Authentication::Unsigned
        };
        let cid = connection::fresh_connection(&mut self.entropy)?;
        let opened = book.open(PathPeers::new(path), cid, authentication, now)?;
        self.tunnels[index].route = Some(opened.route);
        if let (Some(slot), Some(request)) = (sign_slot, opened.sign) {
            self.signs[slot] = Some(Signing {
                request,
                expires: MonoInstant(
                    now.0
                        .checked_add(self.limits.opening_micros)
                        .ok_or(ProtocolError::Overflow)?,
                ),
            });
        }
        Ok(false)
    }
    fn drive_initial(&mut self, index: usize, now: MonoInstant) -> Result<(), ProtocolError> {
        let owner = self.tunnels[index]
            .owner
            .as_mut()
            .ok_or(ProtocolError::StaleGeneration)?;
        let snapshot = owner.snapshot();
        if !snapshot.closed
            && snapshot.candidate.is_none()
            && (snapshot.confirmed.is_none() || snapshot.traffic_paused)
        {
            let _event = owner.request(owner.scope(), now, &mut self.entropy)?;
        }
        Ok(())
    }
    fn channel_index(&self, tunnel: usize, wire: u32) -> Option<usize> {
        self.channels.iter().position(|c| {
            c.tunnel == tunnel
                && c.owner
                    .as_ref()
                    .is_some_and(|o| o.scope().wire_id() == wire)
        })
    }
    fn app_index(&self, channel: app::Channel<'app>) -> Option<usize> {
        self.channels.iter().position(|c| {
            c.binding.is_some_and(|b| b.channel() == channel)
                || c.open.is_some_and(|(o, _)| o.channel() == channel)
        })
    }
    fn prepare_ratchet(
        &mut self,
        index: usize,
        now: MonoInstant,
    ) -> Result<MonoInstant, ProtocolError> {
        let next = MonoInstant(
            now.0
                .checked_add(self.limits.ratchet_micros)
                .ok_or(ProtocolError::Overflow)?,
        );
        let tunnel = &mut self.tunnels[index];
        let owner = tunnel.owner.as_mut().ok_or(ProtocolError::NotReady)?;
        let Some(generation) = owner.snapshot().confirmed else {
            return Ok(next);
        };
        if tunnel.ratchet_generation != Some(generation) {
            tunnel.ratchet_generation = Some(generation);
            tunnel.ratchet_at = next;
        }
        if let Some(snapshot) = owner.crypto_snapshot()
            && snapshot.ratchet_allowed
            && !snapshot.ratchet_pending
            && (snapshot.sent.saturating_add(1) >= self.limits.ratchet_messages
                || now >= tunnel.ratchet_at)
        {
            owner.request_ratchet(owner.scope())?;
        }
        Ok(next)
    }
    fn ratchet_sealed(&mut self, index: usize, was_pending: bool, next: MonoInstant) {
        if was_pending
            && self.tunnels[index]
                .owner
                .as_ref()
                .and_then(|o| o.crypto_snapshot())
                .is_some_and(|s| !s.ratchet_pending)
        {
            self.tunnels[index].ratchet_at = next;
        }
    }
    fn queue_rejection<const P: usize>(
        &mut self,
        tunnel: usize,
        channel: u32,
        book: &mut Book<'book, '_, '_, P>,
        now: MonoInstant,
    ) -> Result<(), ProtocolError> {
        let slot = self
            .pending
            .iter()
            .position(Option::is_none)
            .ok_or(ProtocolError::Capacity)?;
        let next_ratchet = self.prepare_ratchet(tunnel, now)?;
        let owner = self.tunnels[tunnel]
            .owner
            .as_mut()
            .ok_or(ProtocolError::StaleGeneration)?;
        let ratchet = owner.crypto_snapshot().is_some_and(|s| s.ratchet_pending);
        let sealed = owner.reject_channel(
            owner.scope(),
            channel,
            book,
            self.ciphertext,
            &mut self.entropy,
        )?;
        let frame =
            book.queue_payload(sealed.route(), PeerMessage::decode(sealed.bytes())?, now)?;
        self.ratchet_sealed(tunnel, ratchet, next_ratchet);
        self.pending[slot] = Some(Pending {
            effect: Effect::Rejection {
                tunnel,
                channel,
                frame,
            },
            started: false,
        });
        Ok(())
    }
    fn incoming<const P: usize>(
        &mut self,
        tunnel: usize,
        channel: u32,
        challenge: [u8; 64],
        book: &mut Book<'book, '_, '_, P>,
        now: MonoInstant,
    ) -> Result<(), ProtocolError> {
        let owner = self.tunnels[tunnel]
            .owner
            .as_ref()
            .ok_or(ProtocolError::StaleGeneration)?;
        let scope = owner.scope();
        let allocation = scope.allocation();
        let remote = scope.peer();
        let expected_side = if remote > self.server.local_peer() {
            peer::NUMBER_SIDE_BIT
        } else {
            0
        };
        if channel & !(peer::NUMBER_SIDE_BIT - 1) != expected_side {
            return Err(ProtocolError::Malformed);
        }
        if let Some(index) = self.loose.position(scope, channel) {
            let original = self.loose.rows[index].ok_or(ProtocolError::StaleGeneration)?;
            if original.expired(now) {
                self.report.loose_expired = self.report.loose_expired.saturating_add(1);
                self.remove_loose(index);
            } else {
                // Duplicate OPEN cannot replace the original h_port or renew
                // either first wait bound, even if its new bytes differ.
                return Ok(());
            }
        }
        if self
            .used
            .iter()
            .flatten()
            .any(|u| u.tunnel == allocation && u.channel == channel)
            || self.channel_effect_pending(tunnel, channel)
        {
            return self.queue_rejection(tunnel, channel, book, now);
        }
        let used = self
            .used
            .iter()
            .position(Option::is_none)
            .ok_or(ProtocolError::Capacity)?;
        let Some(port) = self.server.resolve_port_challenge(&challenge) else {
            // The authenticated original OPEN waits for an actual listener.
            // Fixed metadata admission precedes its shared CTN lease; there is
            // no payload owner, OPEN_ACK or negative wire frame yet.
            self.loose
                .admit(Waiting::new(tunnel, scope, channel, challenge, now)?)?;
            self.report.loose_retained = self.report.loose_retained.saturating_add(1);
            self.used[used] = Some(Used {
                tunnel: allocation,
                channel,
            });
            self.tunnels[tunnel].used = now;
            return Ok(());
        };
        self.bind_incoming(tunnel, channel, challenge, port, now, None)?;
        self.used[used] = Some(Used {
            tunnel: allocation,
            channel,
        });
        Ok(())
    }
    fn bind_incoming(
        &mut self,
        tunnel: usize,
        channel: u32,
        challenge: [u8; 64],
        port: [u8; 64],
        now: MonoInstant,
        bound: Option<(MonoInstant, Instant)>,
    ) -> Result<(), ProtocolError> {
        if bound.is_some_and(|(expires, hard)| now >= expires || Instant::now() >= hard) {
            return Err(ProtocolError::Deadline);
        }
        let scope = self.tunnels[tunnel]
            .owner
            .as_ref()
            .ok_or(ProtocolError::StaleGeneration)?
            .scope();
        let allocation = scope.allocation();
        let remote = scope.peer();
        let slot = self
            .channels
            .iter()
            .position(|c| c.owner.is_none() && c.free.is_some())
            .ok_or(ProtocolError::Capacity)?;
        let buffers = self.channels[slot]
            .free
            .take()
            .ok_or(ProtocolError::Capacity)?;
        let address = peer::Address {
            channel,
            local_peer: self.server.local_peer(),
            remote_peer: remote,
            port,
        };
        let mut peer = match ChannelOwner::allocate(
            self.channel_domain,
            address,
            buffers,
            Some(challenge),
            now,
            self.limits.channel,
        ) {
            Ok(owner) => owner,
            Err(r) => {
                self.channels[slot].free = Some(r.value);
                return Err(r.reason);
            }
        };
        if bound.is_some_and(|(expires, hard)| now >= expires || Instant::now() >= hard) {
            peer.retire()?;
            self.channels[slot].free = Some(peer.into_buffers().map_err(|r| r.reason)?);
            return Err(ProtocolError::Deadline);
        }
        let binding = match self.server.accept_peer(&mut peer) {
            Ok(binding) => binding,
            Err(reason) => {
                peer.retire()?;
                self.channels[slot].free = Some(peer.into_buffers().map_err(|r| r.reason)?);
                return Err(reason);
            }
        };
        let record = &mut self.channels[slot];
        record.owner = Some(peer);
        record.observations = Some(ChannelObservations::new(address, allocation));
        record.tunnel = tunnel;
        record.binding = Some(binding);
        record.closing = false;
        record.lost = false;
        self.tunnels[tunnel].used = now;
        self.report.channels = self.report.channels.saturating_add(1);
        Ok(())
    }
    fn channel_effect_pending(&self, tunnel: usize, channel: u32) -> bool {
        self.pending
            .iter()
            .flatten()
            .any(|pending| match pending.effect {
                Effect::Channel { slot, attempt, .. } => {
                    self.channels[slot].tunnel == tunnel && attempt.scope().wire_id() == channel
                }
                Effect::Rejection {
                    tunnel: original,
                    channel: ctn,
                    ..
                } => original == tunnel && ctn == channel,
                Effect::Control { .. } => false,
            })
    }
    fn release_used_if_idle(&mut self, tunnel: usize, channel: u32) {
        let Some(allocation) = self.tunnels[tunnel]
            .owner
            .as_ref()
            .map(|owner| owner.scope().allocation())
        else {
            return;
        };
        // Retiring owners remain authoritative until their actual native,
        // receive/send and application lifetimes have fully drained. Pending
        // negative responses similarly keep their original CTN reserved.
        if self.channel_index(tunnel, channel).is_some()
            || self.tunnels[tunnel]
                .owner
                .as_ref()
                .is_some_and(|owner| self.loose.position(owner.scope(), channel).is_some())
            || self.channel_effect_pending(tunnel, channel)
        {
            return;
        }
        for used in &mut self.used {
            if used.is_some_and(|original| {
                original.tunnel == allocation && original.channel == channel
            }) {
                *used = None;
            }
        }
    }
    fn remove_loose(&mut self, index: usize) {
        let Some(original) = self.loose.rows[index].take() else {
            return;
        };
        if self.tunnels[original.tunnel]
            .owner
            .as_ref()
            .is_some_and(|owner| owner.scope() == original.scope)
        {
            self.release_used_if_idle(original.tunnel, original.channel);
        } else {
            // A retired context cannot authorize work on a replacement slot.
            // Its old allocation is disjoint from every current CTN claim.
            for used in &mut self.used {
                if used.is_some_and(|used| {
                    used.tunnel == original.scope.allocation() && used.channel == original.channel
                }) {
                    *used = None;
                }
            }
        }
    }
    fn service_loose(&mut self, now: MonoInstant) -> Result<bool, ProtocolError> {
        let count = self.loose.rows.len();
        for offset in 0..count {
            let index = (self.loose_cursor + offset) % count;
            let Some(original) = self.loose.rows[index] else {
                continue;
            };
            let current = self.tunnels[original.tunnel]
                .owner
                .as_ref()
                .is_some_and(|owner| {
                    owner.scope() == original.scope
                        && original.scope.is_live()
                        && !owner.snapshot().closed
                        && !self.tunnels[original.tunnel].closing
                });
            if self.closing || !current || original.expired(now) {
                if original.expired(now) {
                    self.report.loose_expired = self.report.loose_expired.saturating_add(1);
                }
                // Official closed-port timeout is local removal, not DESTROY.
                self.remove_loose(index);
                self.loose_cursor = (index + 1) % count;
                return Ok(true);
            }
            let Some(port) = self.server.resolve_port_challenge(&original.challenge) else {
                continue;
            };
            match self.bind_incoming(
                original.tunnel,
                original.channel,
                original.challenge,
                port,
                now,
                Some((original.expires, original.hard)),
            ) {
                Ok(()) => {
                    // The same CTN lease now belongs to the actual peer owner.
                    self.report.loose_bound = self.report.loose_bound.saturating_add(1);
                    self.loose.rows[index] = None;
                    self.loose_cursor = (index + 1) % count;
                    return Ok(true);
                }
                Err(ProtocolError::Capacity | ProtocolError::WouldBlock) => {}
                Err(ProtocolError::Deadline) => {
                    self.report.loose_expired = self.report.loose_expired.saturating_add(1);
                    self.remove_loose(index);
                    self.loose_cursor = (index + 1) % count;
                    return Ok(true);
                }
                Err(reason) => return Err(reason),
            }
        }
        self.loose_cursor = (self.loose_cursor + 1) % count;
        Ok(false)
    }
    fn consume_held<const P: usize>(
        &mut self,
        book: &mut Book<'book, '_, '_, P>,
        now: MonoInstant,
    ) -> Result<bool, ProtocolError> {
        let Some(held) = self.held else {
            return Ok(false);
        };
        let Some(tunnel) = self.tunnels.get(held.tunnel).and_then(|t| t.owner.as_ref()) else {
            self.clear_held();
            return Ok(true);
        };
        let remote = tunnel.scope().peer();
        if tunnel.scope().allocation() != held.allocation || tunnel.snapshot().closed {
            self.clear_held();
            return Ok(true);
        }
        let message = match ChannelMessage::decode(&self.plaintext[..held.length]) {
            Ok(message) => message,
            Err(reason) => {
                self.fail(remote, None, reason);
                self.clear_held();
                return Ok(true);
            }
        };
        let channel = match message {
            ChannelMessage::Open { channel, .. }
            | ChannelMessage::OpenAck { channel, .. }
            | ChannelMessage::Destroy { channel, .. }
            | ChannelMessage::Data { channel, .. }
            | ChannelMessage::DataAck { channel, .. } => channel,
            ChannelMessage::KeepAlive => {
                self.clear_held();
                return Ok(true);
            }
        };
        if !matches!(message, ChannelMessage::Open { .. })
            && let Some(index) = self.loose.position(tunnel.scope(), channel)
        {
            let original = self.loose.rows[index].ok_or(ProtocolError::StaleGeneration)?;
            if original.expired(now) {
                // This original wait is gone. The current new input receives
                // the ordinary unknown-channel disposition, without retaining
                // a payload borrow across metadata/source mutation.
                let reject = !matches!(
                    message,
                    ChannelMessage::Destroy { .. } | ChannelMessage::DataAck { .. }
                );
                self.report.loose_expired = self.report.loose_expired.saturating_add(1);
                self.remove_loose(index);
                if reject && let Err(reason) = self.queue_rejection(held.tunnel, channel, book, now)
                {
                    self.fail(remote, Some(channel), reason);
                }
            } else if matches!(message, ChannelMessage::Destroy { .. }) {
                self.report.loose_destroyed = self.report.loose_destroyed.saturating_add(1);
                self.remove_loose(index);
            }
            // No listener means no application payload owner or flow ACK.
            self.clear_held();
            return Ok(true);
        }
        if let Some(index) = self.channel_index(held.tunnel, channel) {
            let record = &mut self.channels[index];
            let owner = record
                .owner
                .as_mut()
                .ok_or(ProtocolError::StaleGeneration)?;
            let expected = (owner.ack().0, owner.phase());
            let before = owner.available_send();
            let result = owner.receive(owner.scope(), message, held.route.connection(), now);
            if let Some(observations) = &mut record.observations {
                observations.input(
                    message,
                    expected,
                    (before, owner.available_send()),
                    owner.phase(),
                    &result,
                    now,
                );
            }
            match result {
                Ok(_) => {
                    self.tunnels[held.tunnel].used = now;
                    self.clear_held();
                    Ok(true)
                }
                Err(reason @ (ProtocolError::Capacity | ProtocolError::WouldBlock)) => {
                    owner.discarded_receive_capacity(owner.scope(), message);
                    self.fail(remote, Some(channel), reason);
                    self.clear_held();
                    Ok(true)
                }
                Err(reason) => {
                    self.channels[index].closing = true;
                    self.fail(remote, Some(channel), reason);
                    self.clear_held();
                    Ok(true)
                }
            }
        } else if let ChannelMessage::Open { h_port, .. } = message {
            match self.incoming(held.tunnel, channel, h_port, book, now) {
                Ok(()) => {
                    self.clear_held();
                    Ok(true)
                }
                // CORE is a packet port: capacity loss is consumable, with no
                // invented ACK/proof. Reliable OPEN retries can be admitted later.
                Err(reason) => {
                    let peer = self.tunnels[held.tunnel]
                        .peer
                        .ok_or(ProtocolError::StaleGeneration)?;
                    self.fail(peer, Some(channel), reason);
                    self.clear_held();
                    Ok(true)
                }
            }
        } else {
            let peer = self.tunnels[held.tunnel]
                .peer
                .ok_or(ProtocolError::StaleGeneration)?;
            if !matches!(
                message,
                ChannelMessage::Destroy { .. } | ChannelMessage::DataAck { .. }
            ) && let Err(reason) = self.queue_rejection(held.tunnel, channel, book, now)
            {
                self.fail(peer, Some(channel), reason);
            }
            self.clear_held();
            Ok(true)
        }
    }
    fn clear_held(&mut self) {
        if let Some(h) = self.held.take() {
            self.plaintext[..h.length].fill(0)
        }
    }
    fn outgoing<const P: usize>(
        &mut self,
        book: &mut Book<'book, '_, '_, P>,
        now: MonoInstant,
    ) -> Result<bool, ProtocolError> {
        if self.closing {
            return Ok(false);
        }
        let hard = Instant::now()
            .checked_add(Duration::from_micros(self.limits.opening_micros))
            .ok_or(ProtocolError::Overflow)?;
        let Some(open) = self.server.next_open() else {
            return Ok(false);
        };
        let info = self.server.channel_info(open.channel())?;
        let tunnel = match self.ensure_tunnel(info.peer, book, now) {
            Ok(t) => t,
            Err(reason) => {
                self.server.open_failed(open)?;
                self.report.failed_opens = self.report.failed_opens.saturating_add(1);
                self.fail(info.peer, None, reason);
                return Ok(true);
            }
        };
        let Some(slot) = self
            .channels
            .iter()
            .position(|c| c.owner.is_none() && c.free.is_some())
        else {
            self.server.open_failed(open)?;
            self.report.failed_opens = self.report.failed_opens.saturating_add(1);
            self.fail(info.peer, None, ProtocolError::Capacity);
            return Ok(true);
        };
        let wire = self.tunnels[tunnel]
            .numbers
            .as_mut()
            .ok_or(ProtocolError::NotReady)?
            .allocate()?;
        let buffers = self.channels[slot]
            .free
            .take()
            .ok_or(ProtocolError::Capacity)?;
        let owner = match ChannelOwner::allocate(
            self.channel_domain,
            peer::Address {
                channel: wire,
                local_peer: self.server.local_peer(),
                remote_peer: info.peer,
                port: info.port,
            },
            buffers,
            None,
            now,
            self.limits.channel,
        ) {
            Ok(o) => o,
            Err(r) => {
                self.channels[slot].free = Some(r.value);
                self.server.open_failed(open)?;
                self.fail(info.peer, Some(wire), r.reason);
                return Ok(true);
            }
        };
        let observations = self.tunnels[tunnel]
            .owner
            .as_ref()
            .map(|tunnel| ChannelObservations::new(owner.address(), tunnel.scope().allocation()));
        let c = &mut self.channels[slot];
        c.tunnel = tunnel;
        c.owner = Some(owner);
        c.observations = observations;
        c.open = Some((
            open,
            MonoInstant(
                now.0
                    .checked_add(self.limits.opening_micros)
                    .ok_or(ProtocolError::Overflow)?,
            ),
        ));
        c.open_hard = Some(hard);
        c.closing = false;
        c.lost = false;
        self.report.channels = self.report.channels.saturating_add(1);
        let _ready = self.ensure_route(tunnel, book, now)?;
        self.drive_initial(tunnel, now)?;
        Ok(true)
    }
    fn application(&mut self, now: MonoInstant) -> Result<bool, ProtocolError> {
        if let Some(open) = self.server.canceling_open() {
            if let Some(index) = self.app_index(open.channel()) {
                self.channels[index].closing = true;
            } else {
                self.server.open_failed(open)?;
                return Ok(true);
            }
        }
        if let Some(effect) = self.server.next_close() {
            let index = self
                .app_index(effect.channel())
                .ok_or(ProtocolError::StaleGeneration)?;
            self.channels[index].close = Some(effect);
            self.channels[index].closing = true;
            return Ok(true);
        }
        if let Some(effect) = self.server.next_receive_done() {
            let index = self
                .app_index(effect.channel())
                .ok_or(ProtocolError::StaleGeneration)?;
            let c = &mut self.channels[index];
            let delivery = c.delivery.ok_or(ProtocolError::StaleGeneration)?;
            self.server.peer_receive_done(
                effect,
                delivery,
                c.owner.as_mut().ok_or(ProtocolError::StaleGeneration)?,
            )?;
            c.delivery = None;
            self.report.receive_done = self.report.receive_done.saturating_add(1);
            return Ok(true);
        }
        if let Some(sending) = self.server.next_send_where(|sending| {
            let Some(index) = self.app_index(sending.effect.channel()) else {
                return false;
            };
            let channel = &self.channels[index];
            !channel.closing
                && !channel.lost
                && channel
                    .binding
                    .is_some_and(|binding| binding.channel() == sending.effect.channel())
                && channel.admitted.iter().any(Option::is_none)
                && channel.owner.as_ref().is_some_and(|owner| {
                    owner.phase() == peer::Phase::Ready && owner.available_send() != 0
                })
        }) {
            let Some(index) = self.app_index(sending.effect.channel()) else {
                return Err(ProtocolError::StaleGeneration);
            };
            let c = &mut self.channels[index];
            if c.closing {
                return Ok(false);
            }
            let binding = c.binding.ok_or(ProtocolError::NotReady)?;
            let slot = c
                .admitted
                .iter()
                .position(Option::is_none)
                .ok_or(ProtocolError::Capacity)?;
            let owner = c.owner.as_mut().ok_or(ProtocolError::NotReady)?;
            if owner.available_send() == 0 {
                return Ok(false);
            }
            let effect = sending.effect;
            let send = owner.queue_send(sending.payload, now)?;
            let admitted = self.server.send_admitted(effect, binding, owner, send)?;
            c.admitted[slot] = Some(admitted);
            self.report.admitted = self.report.admitted.saturating_add(1);
            return Ok(true);
        }
        Ok(false)
    }
    fn service_channel(&mut self, index: usize, now: MonoInstant) -> Result<bool, ProtocolError> {
        let c = &mut self.channels[index];
        if c.owner.is_none() {
            return Ok(false);
        }
        // Native expiry/source detach may already have retired the exact pure
        // application endpoint before this class gets its next turn. Do not
        // misapply a subsequently observed peer completion as fresh local credit.
        if c.binding.is_some_and(|binding| {
            self.server
                .channel_info(binding.channel())
                .is_ok_and(|info| info.phase == app::Phase::Closing)
        }) {
            c.closing = true;
        }
        if c.open.is_some_and(|(_, deadline)| now >= deadline)
            || c.open.is_some() && c.open_hard.is_some_and(|hard| Instant::now() >= hard)
        {
            c.closing = true;
        }
        if c.open.is_some_and(|(open, _)| {
            !self
                .server
                .channel_info(open.channel())
                .is_ok_and(|info| info.phase == app::Phase::Opening)
        }) {
            c.closing = true;
        }
        if c.owner
            .as_ref()
            .is_some_and(|o| o.phase() == peer::Phase::Closed)
        {
            c.closing = true;
            c.lost = true;
        }
        let owner = c.owner.as_mut().ok_or(ProtocolError::NotReady)?;
        if !c.closing && c.binding.is_none() && owner.phase() == peer::Phase::Ready {
            let (open, _) = c.open.ok_or(ProtocolError::StaleGeneration)?;
            if !self
                .server
                .channel_info(open.channel())
                .is_ok_and(|info| info.phase == app::Phase::Opening)
            {
                c.closing = true;
                return Ok(true);
            }
            c.binding = Some(self.server.peer_opened(open, owner)?);
            c.open = None;
            c.open_hard = None;
            return Ok(true);
        }
        for slot in 0..c.admitted.len() {
            if let Some(admitted) = c.admitted[slot]
                && owner.completion_for(admitted.send()).is_ok()
            {
                if !c.closing {
                    let outcome = self.server.send_completed(admitted, owner)?;
                    if outcome == peer::Outcome::PeerAccepted {
                        self.report.peer_accepted = self.report.peer_accepted.saturating_add(1);
                    } else {
                        c.closing = true;
                        c.lost = true;
                    }
                }
                owner.release_send(admitted.send())?;
                c.admitted[slot] = None;
                return Ok(true);
            }
        }
        if c.closing {
            if owner.pending().is_some() {
                return Ok(false);
            }
            if owner.phase() != peer::Phase::Closed {
                if self.closing
                    || c.lost
                    || (owner.phase() == peer::Phase::Opening
                        && self.tunnels[c.tunnel]
                            .owner
                            .as_ref()
                            .is_none_or(|t| t.snapshot().confirmed.is_none()))
                {
                    owner.retire()?;
                    return Ok(true);
                }
                if owner.phase() != peer::Phase::Closing {
                    owner.close()?;
                    return Ok(true);
                }
                return Ok(false);
            }
            if let Some(done) = owner.completion() {
                owner.release_send(done.send)?;
                return Ok(true);
            }
            if c.admitted.iter().any(Option::is_some) {
                return Ok(false);
            }
            if let Some((open, _)) = c.open.take() {
                c.open_hard = None;
                self.server.open_failed(open)?;
                self.report.failed_opens = self.report.failed_opens.saturating_add(1);
                return Ok(true);
            }
            if let Some(binding) = c.binding {
                if c.close.is_none() {
                    // Actual peer/tunnel loss precedes the local close effect.
                    self.server.peer_lost(binding, owner)?;
                    return Ok(true);
                }
                let effect = c.close.ok_or(ProtocolError::NotReady)?;
                self.server.peer_closed(effect, binding, owner)?;
                c.binding = None;
                c.close = None;
                c.delivery = None;
                return Ok(true);
            }
            let owner = c.owner.take().ok_or(ProtocolError::NotReady)?;
            let tunnel = c.tunnel;
            let channel = owner.scope().wire_id();
            c.free = Some(owner.into_buffers().map_err(|r| r.reason)?);
            if let Some(observations) = &mut c.observations {
                observations.owner_returned = true;
            }
            c.closing = false;
            c.lost = false;
            c.delivery = None;
            // This old owner is actually gone, not merely Closing or locally
            // detached. A subsequent authenticated OPEN may reuse its CTN.
            self.release_used_if_idle(tunnel, channel);
            return Ok(true);
        }
        if c.delivery.is_none() && owner.peek_delivery().is_some() {
            let binding = c.binding.ok_or(ProtocolError::NotReady)?;
            match self.server.receive_peer(binding, owner) {
                Ok(delivery) => {
                    c.delivery = Some(delivery);
                    return Ok(true);
                }
                Err(ProtocolError::Capacity | ProtocolError::WouldBlock) => {}
                Err(ProtocolError::Closed | ProtocolError::TooLarge | ProtocolError::Malformed) => {
                    c.closing = true;
                    return Ok(true);
                }
                Err(e) => return Err(e),
            }
        }
        Ok(false)
    }
    fn output_channel<const P: usize>(
        &mut self,
        index: usize,
        book: &mut Book<'book, '_, '_, P>,
        now: MonoInstant,
    ) -> Result<bool, ProtocolError> {
        let Some(owner) = self.channels[index].owner.as_ref() else {
            return Ok(false);
        };
        if owner.pending().is_some()
            || (self.channels[index].closing && owner.phase() == peer::Phase::Closed)
        {
            return Ok(false);
        }
        let tunnel = self.channels[index].tunnel;
        let remote = owner.address().remote_peer;
        let Some(route) = book.select(remote) else {
            return Ok(false);
        };
        if self.tunnels[tunnel]
            .owner
            .as_ref()
            .is_none_or(|t| t.snapshot().confirmed.is_none() || t.snapshot().traffic_paused)
        {
            return Ok(false);
        }
        if !book.payload_capacity(
            route,
            self.limits
                .channel
                .payload_bytes
                .checked_add(124)
                .ok_or(ProtocolError::Overflow)?,
        )? {
            return Ok(false);
        }
        let Some(slot) = self.pending.iter().position(Option::is_none) else {
            return Ok(false);
        };
        let next_ratchet = self.prepare_ratchet(tunnel, now)?;
        let application = self.channels[index]
            .binding
            .map(|b| b.channel())
            .or_else(|| self.channels[index].open.map(|(o, _)| o.channel()));
        let owner = self.channels[index]
            .owner
            .as_mut()
            .ok_or(ProtocolError::NotReady)?;
        // Plaintext staging is independent of retained inbound plaintext.
        // Full DATA can exceed the small control stack buffer. Encode directly
        // into the caller ciphertext staging suffix before separate AEAD output.
        let needed = self
            .limits
            .channel
            .payload_bytes
            .checked_add(12)
            .ok_or(ProtocolError::Overflow)?;
        if self.ciphertext.len()
            < needed
                .checked_add(needed + 112)
                .ok_or(ProtocolError::Overflow)?
        {
            return Err(ProtocolError::Capacity);
        }
        let (plain, encrypted) = self.ciphertext.split_at_mut(needed);
        let Some(prepared) = owner.prepare_next(now, plain)? else {
            return Ok(false);
        };
        let attempt = prepared.attempt();
        let kind = prepared.bytes().get(2..4).ok_or(ProtocolError::Malformed)?;
        if let Some(application) = application
            && self
                .server
                .consume_peer_drop(application, [kind[0], kind[1]])?
        {
            // No cipher/nonce, Book frame, CORE prefix or peer ACK exists.
            // Consume this original attempt only; reliable DATA/OPEN retains
            // its existing payload/MID and bounded retry clock.
            owner.settle(attempt, peer::Emission::Dropped, now)?;
            plain.fill(0);
            self.report.diagnostic_drops = self.report.diagnostic_drops.saturating_add(1);
            return Ok(true);
        }
        let controller = self.tunnels[tunnel]
            .owner
            .as_mut()
            .ok_or(ProtocolError::NotReady)?;
        let ratchet = controller
            .crypto_snapshot()
            .is_some_and(|s| s.ratchet_pending);
        let sealed = match controller.seal_channel(
            controller.scope(),
            owner,
            prepared,
            book,
            encrypted,
            &mut self.entropy,
        ) {
            Ok(s) => s,
            Err(r) => {
                owner.discard_attempt(r.prepared.attempt())?;
                return if matches!(
                    r.reason,
                    ProtocolError::NotReady | ProtocolError::WouldBlock
                ) {
                    Ok(false)
                } else {
                    Err(r.reason)
                };
            }
        };
        let actual_route = sealed.route();
        let frame =
            match book.queue_payload(actual_route, PeerMessage::decode(sealed.bytes())?, now) {
                Ok(frame) => frame,
                Err(reason) => {
                    owner.discard_attempt(attempt)?;
                    return Err(reason);
                }
            };
        plain.fill(0);
        self.ratchet_sealed(tunnel, ratchet, next_ratchet);
        self.pending[slot] = Some(Pending {
            effect: Effect::Channel {
                slot: index,
                attempt,
                frame,
                route: actual_route,
            },
            started: false,
        });
        Ok(true)
    }
    fn output_control<const P: usize>(
        &mut self,
        index: usize,
        book: &mut Book<'book, '_, '_, P>,
        now: MonoInstant,
    ) -> Result<bool, ProtocolError> {
        let Some(slot) = self.pending.iter().position(Option::is_none) else {
            return Ok(false);
        };
        let Some(owner) = self.tunnels[index].owner.as_mut() else {
            return Ok(false);
        };
        if owner.snapshot().closed {
            return Ok(false);
        }
        let Some(route) = book.select(owner.scope().peer()) else {
            return Ok(false);
        };
        if !book.payload_capacity(route, 168)? {
            return Ok(false);
        }
        let next_ratchet = self.prepare_ratchet(index, now)?;
        let owner = self.tunnels[index]
            .owner
            .as_mut()
            .ok_or(ProtocolError::NotReady)?;
        let ratchet = owner.crypto_snapshot().is_some_and(|s| s.ratchet_pending);
        let Some(prepared) =
            owner.prepare(owner.scope(), book, now, self.ciphertext, &mut self.entropy)?
        else {
            return Ok(false);
        };
        let frame = match book.queue_payload(
            prepared.attempt().route(),
            PeerMessage::decode(prepared.bytes())?,
            now,
        ) {
            Ok(f) => f,
            Err(reason) => {
                owner.reject_prepared(prepared)?;
                return Err(reason);
            }
        };
        let queued = match owner.queue_control(prepared, book, frame) {
            Ok(q) => q,
            Err(r) => {
                let reason = r.reason;
                owner.reject_prepared(r.prepared)?;
                book.cancel_frame(frame)?;
                return Err(reason);
            }
        };
        self.ratchet_sealed(index, ratchet, next_ratchet);
        self.pending[slot] = Some(Pending {
            effect: Effect::Control {
                tunnel: index,
                queued,
            },
            started: false,
        });
        Ok(true)
    }
    pub(super) fn management_snapshot<const P: usize>(
        &self,
        book: &Book<'book, '_, '_, P>,
        kind: crate::management::Kind,
    ) -> Result<crate::management::Snapshot, ProtocolError> {
        let mut directory =
            crate::management::Directory::new(self.server.local_peer(), self.limits.management)?;
        for peer in book.known_neighbors() {
            directory.path(&[peer])?;
        }
        for route in book.retained_routes() {
            let info = book.route_info(route)?;
            if info.phase == connection::Phase::Retired {
                continue;
            }
            let path = book.route_peers(route)?;
            if info.position > 0 {
                let mut oriented = Vec::new();
                oriented
                    .try_reserve_exact(info.position)
                    .map_err(|_| ProtocolError::Capacity)?;
                oriented.extend(path[..info.position].iter().rev().copied());
                directory.path(&oriented)?;
            }
            if info.position + 1 < path.len() {
                directory.path(&path[info.position + 1..])?;
            }
            if let Some(peer) = info.expected_peer {
                directory.connection(peer)?;
            }
        }
        for (index, tunnel) in self.tunnels.iter().enumerate() {
            if let Some(owner) = tunnel.owner.as_ref() {
                let channels = self
                    .channels
                    .iter()
                    .filter(|c| c.tunnel == index && c.owner.is_some())
                    .count()
                    + self
                        .loose
                        .rows
                        .iter()
                        .flatten()
                        .filter(|row| row.scope == owner.scope())
                        .count();
                directory.tunnel(
                    owner.scope().peer(),
                    u32::try_from(channels).map_err(|_| ProtocolError::Overflow)?,
                    owner.management_state(),
                )?;
            }
        }
        directory.snapshot(kind)
    }
    pub(super) fn native_deferred(&mut self, frame: Frame<'book>) {
        if let Some(p) = self
            .pending
            .iter_mut()
            .flatten()
            .find(|p| p.effect.frame() == frame)
        {
            p.started = true;
        }
    }
    pub(super) fn begin_close(&mut self) {
        self.closing = true;
        for index in 0..self.loose.rows.len() {
            self.remove_loose(index);
        }
        self.clear_held();
        self.plaintext.fill(0);
        self.ciphertext.fill(0);
        for c in &mut self.channels {
            if c.owner.is_some() {
                c.closing = true;
                c.lost = true;
            }
        }
        for t in &mut self.tunnels {
            if let Some(o) = t.owner.as_mut() {
                if !o.snapshot().closed
                    && let Err(e) = o.close(o.scope())
                    && self.error.is_none()
                {
                    self.error = Some(e)
                }
                t.closing = true;
            }
        }
    }
    pub(super) fn quiescent(&self) -> bool {
        self.pending.iter().all(Option::is_none)
            && self.channels.iter().all(|c| c.owner.is_none())
            && self.tunnels.iter().all(|t| t.owner.is_none())
            && self.signs.iter().all(Option::is_none)
            && self.held.is_none()
            && self.loose.rows.iter().all(Option::is_none)
    }
    pub(super) fn transport_after(
        &self,
        cursor: usize,
    ) -> Option<(usize, super::TransportDemand<'node, 'app>)> {
        if self.closing {
            return None;
        }
        for index in cursor..self.channels.len() {
            let c = &self.channels[index];
            let tunnel = &self.tunnels[c.tunnel];
            if c.closing || tunnel.closing || c.owner.is_none() {
                continue;
            }
            let Some(tunnel_owner) = tunnel.owner.as_ref() else {
                continue;
            };
            let scope = tunnel_owner.scope();
            let (channel, opening) = if let Some((open, expires)) = c.open {
                let Some(hard) = c.open_hard else {
                    continue;
                };
                (
                    open.channel(),
                    Some((
                        super::Discovery {
                            open,
                            peer: scope.peer(),
                            expires,
                        },
                        hard.into_std(),
                    )),
                )
            } else if let Some(binding) = c.binding {
                (binding.channel(), None)
            } else {
                continue;
            };
            if self
                .server
                .channel_info(channel)
                .is_ok_and(|info| matches!(info.phase, app::Phase::Opening | app::Phase::Ready))
            {
                return Some((
                    index + 1,
                    super::TransportDemand {
                        scope,
                        channel: Some(channel),
                        opening,
                    },
                ));
            }
        }
        // A confirmed original tunnel independently retains demand, including
        // while its last app channel drains real terminal debt and through the
        // existing finite idle policy. An unqualified opening placeholder cannot
        // acquire that lifetime after its original app was cancelled.
        let start = cursor.saturating_sub(self.channels.len());
        for index in start..self.tunnels.len() {
            let tunnel = &self.tunnels[index];
            let Some(owner) = &tunnel.owner else {
                continue;
            };
            if tunnel.closing || owner.snapshot().confirmed.is_none() {
                continue;
            }
            return Some((
                self.channels.len() + index + 1,
                super::TransportDemand {
                    scope: owner.scope(),
                    channel: None,
                    opening: None,
                },
            ));
        }
        None
    }
    fn discovery_index(&self, wanted: super::Discovery<'app>) -> Option<usize> {
        self.channels.iter().position(|c| {
            !c.closing
                && c.open == Some((wanted.open, wanted.expires))
                && c.owner
                    .as_ref()
                    .is_some_and(|o| o.address().remote_peer == wanted.peer)
                && self
                    .server
                    .channel_info(wanted.open.channel())
                    .is_ok_and(|info| info.phase == app::Phase::Opening)
        })
    }
    pub(super) fn discovery_hard(&self, wanted: super::Discovery<'app>) -> Option<Instant> {
        self.channels[self.discovery_index(wanted)?].open_hard
    }
    pub(super) fn discovery_needed<const P: usize>(
        &self,
        book: &Book<'book, '_, '_, P>,
        after: Option<app::Open<'app>>,
    ) -> Option<super::Discovery<'app>> {
        let start = match after {
            None => 0,
            Some(open) => {
                self.channels
                    .iter()
                    .position(|c| c.open.is_some_and(|(o, _)| o == open))?
                    + 1
            }
        };
        self.channels[start..].iter().find_map(|c| {
            let (open, expires) = c.open?;
            // The actual application MQ can retire this original open before
            // service_channel gets its next fair turn to mark c.closing. Keep
            // this projection consistent with discovery_index/discovery_hard;
            // a completed GET stop must not make that old open look new again.
            if !self
                .server
                .channel_info(open.channel())
                .is_ok_and(|info| info.phase == app::Phase::Opening)
            {
                return None;
            }
            let owner = c.owner.as_ref()?;
            let peer = owner.address().remote_peer;
            let routing = self.tunnels[c.tunnel].route.is_some_and(|r| {
                book.route_info(r)
                    .is_ok_and(|i| i.phase != connection::Phase::Retired)
            });
            (!c.closing
                && !routing
                && book.select(peer).is_none()
                && book.current_neighbor(peer).is_none())
            .then_some(super::Discovery {
                open,
                peer,
                expires,
            })
        })
    }
    pub(super) fn expire_discovery(
        &mut self,
        wanted: super::Discovery<'app>,
    ) -> Result<(), ProtocolError> {
        let i = self
            .discovery_index(wanted)
            .ok_or(ProtocolError::StaleGeneration)?;
        self.channels[i].closing = true;
        self.fail(wanted.peer, None, ProtocolError::Deadline);
        Ok(())
    }
    pub(super) fn admit_discovery<const P: usize>(
        &mut self,
        wanted: super::Discovery<'app>,
        path: &[[u8; 32]],
        book: &mut Book<'book, '_, '_, P>,
        now: MonoInstant,
    ) -> Result<bool, ProtocolError> {
        let i = self
            .discovery_index(wanted)
            .ok_or(ProtocolError::StaleGeneration)?;
        if self.closing
            || now >= wanted.expires
            || self.channels[i]
                .open_hard
                .is_none_or(|hard| Instant::now() >= hard)
        {
            return Err(ProtocolError::Deadline);
        }
        if path.len() < 2
            || path.len() > P
            || path.first() != Some(&self.server.local_peer())
            || path.last() != Some(&wanted.peer)
            || path.iter().enumerate().any(|(i, p)| path[..i].contains(p))
        {
            return Err(ProtocolError::InvalidInput);
        }
        if book.current_neighbor(path[1]).is_none() {
            return Err(ProtocolError::NotReady);
        }
        let tunnel = self.channels[i].tunnel;
        let ready = self.ensure_path(tunnel, book, path, now)?;
        let admitted = ready
            || self.tunnels[tunnel].route.is_some_and(|r| {
                book.route_info(r)
                    .is_ok_and(|info| info.phase != connection::Phase::Retired)
            });
        if admitted {
            self.drive_initial(tunnel, now)?;
        }
        Ok(admitted)
    }
    pub(super) fn native_deadline(&self) -> Option<Instant> {
        self.loose.native_deadline()
    }
    pub(super) fn next_deadline(&self) -> Option<MonoInstant> {
        let mut result = Some(
            self.loose
                .next_deadline()
                .map_or(self.next_tick, |at| at.min(self.next_tick)),
        );
        for t in &self.tunnels {
            if let Some(o) = &t.owner
                && let Some(at) = o.next_deadline()
            {
                result = Some(result.map_or(at, |r| r.min(at)));
            }
        }
        for c in &self.channels {
            if !c.closing
                && let Some((_, at)) = c.open
            {
                result = Some(result.map_or(at, |r| r.min(at)));
            }
            if let Some(at) = c.owner.as_ref().and_then(|o| o.next_wakeup()) {
                result = Some(result.map_or(at, |r| r.min(at)));
            }
        }
        result
    }
    pub(super) fn maintain<const P: usize>(
        &mut self,
        book: &mut Book<'book, '_, '_, P>,
        now: MonoInstant,
    ) -> Result<bool, ProtocolError> {
        // One actionable original wait precedes continuously ready route ticks
        // or authenticated input. Admission into this table happens only below,
        // so at most its fixed occupancy can delay those other classes.
        if self.service_loose(now)? {
            return Ok(true);
        }
        if now >= self.next_tick {
            self.next_tick = MonoInstant(
                now.0
                    .checked_add(self.limits.route_tick_micros)
                    .ok_or(ProtocolError::Overflow)?,
            );
            match book.tick(now) {
                Ok(_) | Err(ProtocolError::Capacity) => {}
                Err(e) => return Err(e),
            }
            return Ok(true);
        }
        for slot in 0..self.pending.len() {
            if let Some(p) = self.pending[slot]
                && !p.started
            {
                let cancel = match p.effect {
                    Effect::Control { tunnel, queued } => self.tunnels[tunnel]
                        .owner
                        .as_ref()
                        .is_none_or(|o| !o.queued_needed(queued)),
                    Effect::Channel { slot, .. } => self.closing || self.channels[slot].lost,
                    Effect::Rejection { tunnel, .. } => {
                        self.closing || self.tunnels[tunnel].closing
                    }
                };
                if cancel {
                    match book.cancel_frame(p.effect.frame()) {
                        Ok(()) => return Ok(true),
                        Err(ProtocolError::WouldBlock) => {}
                        Err(e) => return Err(e),
                    }
                }
            }
        }
        if self.consume_held(book, now)? {
            return Ok(true);
        }
        for offset in 0..4 {
            let class = (self.class + offset) % 4;
            let worked = match class {
                0 => self.application(now)?,
                1 => self.outgoing(book, now)?,
                2 => {
                    let mut worked = false;
                    for n in 0..self.channels.len() {
                        let i = (self.cursor + n) % self.channels.len();
                        if self.service_channel(i, now)? || self.output_channel(i, book, now)? {
                            self.cursor = (i + 1) % self.channels.len();
                            worked = true;
                            break;
                        }
                    }
                    worked
                }
                _ => {
                    let mut worked = false;
                    for i in 0..self.tunnels.len() {
                        let Some(owner) = self.tunnels[i].owner.as_ref() else {
                            continue;
                        };
                        let scope = owner.scope();
                        let snapshot = owner.snapshot();
                        let no_dh = owner.pending_identity_dh().is_none();
                        let no_channels = !self
                            .channels
                            .iter()
                            .any(|c| c.owner.is_some() && c.tunnel == i)
                            && !self.loose.contains(scope);
                        if !self.tunnels[i].closing
                            && no_channels
                            && now.0.saturating_sub(self.tunnels[i].used.0)
                                >= self.limits.idle_micros
                        {
                            self.tunnels[i]
                                .owner
                                .as_mut()
                                .ok_or(ProtocolError::NotReady)?
                                .close(scope)?;
                            self.tunnels[i].closing = true;
                            worked = true;
                            break;
                        }
                        if self.tunnels[i].closing {
                            let peer =
                                self.tunnels[i].peer.ok_or(ProtocolError::StaleGeneration)?;
                            if book.close_peer(peer)? != 0 {
                                worked = true;
                                break;
                            }
                            if let Some(route) = self.tunnels[i].route.take() {
                                match book.close_route(route) {
                                    Ok(())
                                    | Err(ProtocolError::Closed | ProtocolError::StaleGeneration) =>
                                        {}
                                    Err(e) => return Err(e),
                                }
                                worked = true;
                                break;
                            }
                            if no_channels
                                && !book.peer_has_work(peer)
                                && !self.pending.iter().flatten().any(|p| match p.effect {
                                    Effect::Control { tunnel, .. }
                                    | Effect::Rejection { tunnel, .. } => tunnel == i,
                                    Effect::Channel { slot, .. } => self.channels[slot].tunnel == i,
                                })
                                && snapshot.pending.is_none()
                                && no_dh
                            {
                                let owner = self.tunnels[i]
                                    .owner
                                    .take()
                                    .ok_or(ProtocolError::NotReady)?;
                                self.tunnels[i].free =
                                    Some(owner.into_stores().map_err(|r| r.reason)?);
                                self.tunnels[i].peer = None;
                                self.tunnels[i].numbers = None;
                                for u in &mut self.used {
                                    if u.is_some_and(|u| u.tunnel == scope.allocation()) {
                                        *u = None;
                                    }
                                }
                                worked = true;
                                break;
                            }
                            continue;
                        }
                        let _event = self.tunnels[i]
                            .owner
                            .as_mut()
                            .ok_or(ProtocolError::NotReady)?
                            .tick(scope, now)?;
                        if self
                            .channels
                            .iter()
                            .any(|c| c.owner.is_some() && c.tunnel == i)
                        {
                            let _ready = self.ensure_route(i, book, now)?;
                            self.drive_initial(i, now)?;
                        }
                        if self.output_control(i, book, now)? {
                            worked = true;
                            break;
                        }
                        if let Some(route) = book.keepalive_due(now)
                            && book.route_info(route)?.expected_peer == self.tunnels[i].peer
                        {
                            match self.tunnels[i]
                                .owner
                                .as_mut()
                                .ok_or(ProtocolError::NotReady)?
                                .keepalive(scope, route, book, now)
                            {
                                Ok(()) => {
                                    worked = true;
                                    break;
                                }
                                Err(ProtocolError::NotReady) => {}
                                Err(e) => return Err(e),
                            }
                        }
                    }
                    worked
                }
            };
            if worked {
                self.class = (class + 1) % 4;
                return Ok(true);
            }
        }
        if let Some(route) = book.retired_route() {
            match book.release_route(route) {
                Ok(()) => return Ok(true),
                Err(ProtocolError::WouldBlock) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(false)
    }
}

impl<
    'node,
    'book,
    'server,
    'app,
    'appstore,
    'appbytes,
    'store,
    'bytes,
    'core,
    E: Entropy,
    const P: usize,
> bridge::Observer<'core, 'book, P>
    for State<'node, 'book, 'server, 'app, 'appstore, 'appbytes, 'store, 'bytes, E>
{
    fn neighbor(
        &mut self,
        source: bridge::Source<'core, 'book>,
        book: &mut Book<'book, '_, '_, P>,
        now: MonoInstant,
    ) {
        // The actual Book already owns this original neighbor proof; no raw PID
        // reminting is needed. Existing demand will use only current_neighbor.
        if book.current_neighbor(source.peer().identity().0) != Some(source.neighbor()) {
            self.fault(ProtocolError::StaleGeneration);
            return;
        }
        if let Some(index) = self.tunnel_index(source.peer().identity().0) {
            self.tunnels[index].used = now;
        }
    }
    fn retired(
        &mut self,
        source: bridge::Source<'core, 'book>,
        _routes: usize,
        _book: &mut Book<'book, '_, '_, P>,
        _now: MonoInstant,
    ) {
        if let Some(index) = self.tunnel_index(source.peer().identity().0) {
            self.tunnels[index].route = None;
        }
        // Working keys and Numbers survive path loss; original sends were
        // settled by Bridge callbacks before this retirement notification.
    }
    fn input<'message>(
        &mut self,
        _source: bridge::Source<'core, 'book>,
        event: connection::Event<'book, 'message>,
        wire: &'message [u8],
        book: &mut Book<'book, '_, '_, P>,
        now: MonoInstant,
    ) {
        let mut subject = _source.peer().identity().0;
        let result = (|| -> Result<(), ProtocolError> {
            match event {
                connection::Event::Created { route, reset }
                | connection::Event::Duplicate { route, reset } => {
                    if let Some(peer) = book.route_info(route)?.expected_peer {
                        subject = peer;
                        let i = self.ensure_tunnel(peer, book, now)?;
                        if let Reset::Fresh(proof) = reset {
                            let owner = self.tunnels[i]
                                .owner
                                .as_mut()
                                .ok_or(ProtocolError::NotReady)?;
                            owner.peer_reset(owner.scope(), proof, now)?;
                        }
                        self.drive_initial(i, now)?;
                    }
                }
                connection::Event::Ready(route) => {
                    if let Some(peer) = book.route_info(route)?.expected_peer {
                        subject = peer;
                        let i = self.ensure_tunnel(peer, book, now)?;
                        self.drive_initial(i, now)?;
                    }
                }
                connection::Event::Endpoint(input) => {
                    let peer = input.expected_peer();
                    subject = peer;
                    let index = self.ensure_tunnel(peer, book, now)?;
                    let owner = self.tunnels[index]
                        .owner
                        .as_mut()
                        .ok_or(ProtocolError::NotReady)?;
                    owner.tick(owner.scope(), now)?;
                    match input.message() {
                        PeerMessage::KeyExchange { .. } | PeerMessage::KeyExchangeAuth { .. } => {
                            owner.control(owner.scope(), input, now, &mut self.entropy)?;
                        }
                        PeerMessage::Encrypted { .. } => {
                            if self.held.is_some() {
                                self.fail(peer, None, ProtocolError::Capacity);
                                return Ok(());
                            }
                            let received =
                                owner.open(owner.scope(), input, wire, self.plaintext)?;
                            let length = received.opened.bytes().len();
                            let allocation = received.opened.scope().allocation();
                            self.held = Some(Held {
                                tunnel: index,
                                allocation,
                                route: input.route(),
                                length,
                            });
                            self.report.authenticated = self.report.authenticated.saturating_add(1);
                        }
                        _ => return Err(ProtocolError::Unsupported),
                    }
                }
                connection::Event::Retired(_)
                | connection::Event::Forwarded { .. }
                | connection::Event::Rejected { .. }
                | connection::Event::Ignored => {}
            }
            Ok(())
        })();
        if let Err(reason) = result {
            match reason {
                ProtocolError::Authentication
                | ProtocolError::Replay
                | ProtocolError::Malformed
                | ProtocolError::Capacity
                | ProtocolError::WouldBlock
                | ProtocolError::TooLarge
                | ProtocolError::NotReady => self.fail(subject, None, reason),
                other => self.fault(other),
            }
        }
    }
    fn started(
        &mut self,
        binding: bridge::Binding<'core, 'book>,
        book: &mut Book<'book, '_, '_, P>,
        _now: MonoInstant,
    ) {
        let Some(index) = self
            .pending
            .iter()
            .position(|p| p.is_some_and(|p| p.effect.frame() == binding.frame()))
        else {
            return;
        };
        let Some(mut pending) = self.pending[index] else {
            return;
        };
        let result = match pending.effect {
            Effect::Control { tunnel, queued } => self.tunnels[tunnel]
                .owner
                .as_mut()
                .ok_or(ProtocolError::StaleGeneration)
                .and_then(|o| o.bind_queued(queued, book, binding.attempt())),
            _ => Ok(()),
        };
        pending.started = true;
        self.pending[index] = Some(pending);
        if let Err(e) = result {
            self.fault(e)
        }
    }
    fn exposed(
        &mut self,
        binding: bridge::Binding<'core, 'book>,
        _state: gnunet_core_client_host::PayloadState<'core>,
        _book: &mut Book<'book, '_, '_, P>,
        _now: MonoInstant,
    ) {
        if let Some(effect) = self
            .pending
            .iter()
            .flatten()
            .find(|p| p.effect.frame() == binding.frame())
            .map(|p| p.effect)
            && let Effect::Channel { slot, attempt, .. } = effect
        {
            let result = self.channels[slot]
                .owner
                .as_mut()
                .ok_or(ProtocolError::StaleGeneration)
                .and_then(|o| o.exposed(attempt));
            if let Err(e) = result {
                self.fault(e)
            }
        }
    }
    fn completed(
        &mut self,
        completion: connection::Completion<'book>,
        _binding: Option<bridge::Binding<'core, 'book>>,
        _state: Option<gnunet_core_client_host::PayloadState<'core>>,
        book: &mut Book<'book, '_, '_, P>,
        now: MonoInstant,
    ) {
        let Some(index) = self
            .pending
            .iter()
            .position(|p| p.is_some_and(|p| p.effect.frame() == completion.frame))
        else {
            return;
        };
        let Some(pending) = self.pending[index] else {
            return;
        };
        let result = match pending.effect {
            Effect::Control { tunnel, queued } => self.tunnels[tunnel]
                .owner
                .as_mut()
                .ok_or(ProtocolError::StaleGeneration)
                .and_then(|o| o.complete_queued(queued, book, completion, now).map(|_| ())),
            Effect::Channel {
                slot,
                attempt,
                route,
                ..
            } => self.channels[slot]
                .owner
                .as_mut()
                .ok_or(ProtocolError::StaleGeneration)
                .and_then(|o| {
                    if completion.route != Some(route) {
                        return Err(ProtocolError::StaleGeneration);
                    }
                    let emission = if completion.outcome == Outcome::Written {
                        peer::Emission::Sent {
                            connection: route.connection(),
                        }
                    } else {
                        peer::Emission::Failed
                    };
                    o.settle(attempt, emission, now).map(|_| ())
                }),
            Effect::Rejection { .. } => Ok(()),
        };
        if let Err(e) = result {
            self.fault(e)
        } else {
            self.pending[index] = None;
            if let Effect::Rejection {
                tunnel, channel, ..
            } = pending.effect
            {
                // An actual terminal Book/native callback, including failure,
                // retires only this original response. Other pending originals
                // or a still-owned channel keep the CTN reserved.
                self.release_used_if_idle(tunnel, channel);
            }
        }
    }
}
