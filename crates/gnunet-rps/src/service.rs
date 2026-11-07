use crate::sampler::{add, bytes, copied, reserve, shuffled};
use crate::{Group, Peer, Random, Rank, Sampler};
use alloc::vec::Vec;
use core::{fmt, mem::size_of};
use gnunet_types::Error;
use gnunet_wire::official::rps::{ClientRequest, ClientResponse, PeerMessage};
const MAX_PULL_PEERS: usize = (gnunet_wire::official::cadet::MAX_APPLICATION_MESSAGE_SIZE - 8) / 32;

/// An external non-movable lifetime brand for one service.
#[derive(Debug, Default)]
pub struct Instance {
    _private: u8,
}
impl Instance {
    /// Create an unused brand. Keep it outside the service owner.
    #[must_use]
    pub const fn new() -> Self {
        Self { _private: 0 }
    }
}
macro_rules! id {
    ($name:ident, $doc:literal) => {
        #[doc=$doc]
        #[derive(Clone, Copy)]
        pub struct $name<'i> {
            brand: &'i Instance,
            serial: u64,
        }
        impl PartialEq for $name<'_> {
            fn eq(&self, other: &Self) -> bool {
                core::ptr::eq(self.brand, other.brand) && self.serial == other.serial
            }
        }
        impl Eq for $name<'_> {}
        impl fmt::Debug for $name<'_> {
            fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
                out.debug_tuple(stringify!($name))
                    .field(&self.serial)
                    .finish()
            }
        }
    };
}
id!(
    GroupId,
    "Original instance-branded group generation; never a wire hash."
);
id!(Client, "Original local IPC client generation.");
id!(
    EffectId,
    "Once-only original effect token retained until actual completion."
);

/// Actual protocol sizes and round timing; microseconds use a monotonic clock.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// Initial desired Brahms view size.
    pub view_size: usize,
    /// Independent history sampler elements.
    pub sampler_size: usize,
    /// Mean round interval; actual rounds jitter from one half to three halves.
    pub round_interval: u64,
    /// Original discovery probe lifetime, never renewed by partial writes.
    pub probe_timeout: u64,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            view_size: 10,
            sampler_size: 10,
            round_interval: 30_000_000,
            probe_timeout: 30_000_000,
        }
    }
}
/// Explicit independent resource ceilings, not eager allocation sizes.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Main plus simultaneously selected subgroup instances.
    pub groups: usize,
    /// Attached native service clients.
    pub clients: usize,
    /// Known/probing peers in each group.
    pub peers_per_group: usize,
    /// Largest requested view target and peer-list response.
    pub view: usize,
    /// Largest independent history sampler size.
    pub sampler: usize,
    /// Original queued and admitted effects together.
    pub effects: usize,
    /// Actual retained capacities including original in-flight payloads/staging.
    pub retained_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            groups: 16,
            clients: 64,
            peers_per_group: 4096,
            view: 1024,
            sampler: 1024,
            effects: 8192,
            retained_bytes: 32 * 1024 * 1024,
        }
    }
}
impl Limits {
    /// Validate pure resource/timing settings before host I/O or entropy use.
    pub fn validate(self, config: Config) -> Result<(), Error> {
        if self.groups == 0
            || self.clients == 0
            || self.peers_per_group == 0
            || self.view == 0
            || self.sampler == 0
            || self.effects < self.groups
            || self.retained_bytes == 0
            || self.sampler > Sampler::MAX_SLOTS
            || self.groups > 65_536
            || self.clients > 65_536
            || self.peers_per_group > 1_048_576
            || self.view > 2047
            || self.effects > 1_048_576
            || config.view_size == 0
            || config.view_size > self.view
            || config.sampler_size == 0
            || config.sampler_size > self.sampler
            || config.round_interval < 2
            || config.round_interval == u64::MAX
            || config.probe_timeout == 0
            || config.probe_timeout == u64::MAX
        {
            return Err(Error::InvalidInput);
        }
        config
            .round_interval
            .checked_add(config.round_interval / 2)
            .ok_or(Error::Overflow)?;
        let minimum = add(
            Sampler::minimum_bytes(config.sampler_size)?,
            add(size_of::<State<'_>>(), size_of::<Effect<'_>>())?,
        )?;
        if minimum > self.retained_bytes {
            return Err(Error::Capacity);
        }
        Ok(())
    }
}

/// Owned original peer message; encoding borrows this exact immutable payload.
#[derive(Debug)]
pub enum PeerOutput {
    /// Real header-only probe; no application ACK exists.
    CheckLive,
    /// Brahms push carrying the authenticated sender implicitly.
    Push,
    /// Original outstanding request for this group's current view.
    PullRequest,
    /// Snapshot of the actual view at request handling time.
    PullReply {
        /// Public identities only.
        peers: Vec<Peer>,
    },
}
impl PeerOutput {
    /// Borrow the official wire representation without reinterpreting ownership.
    #[must_use]
    pub fn as_wire(&self) -> PeerMessage<'_> {
        match self {
            Self::CheckLive => PeerMessage::CheckLive,
            Self::Push => PeerMessage::Push,
            Self::PullRequest => PeerMessage::PullRequest,
            Self::PullReply { peers } => PeerMessage::PullReply { peers },
        }
    }
    fn bytes(&self) -> Result<usize, Error> {
        match self {
            Self::PullReply { peers } => bytes(peers),
            _ => Ok(0),
        }
    }
}
/// A concrete original external action; success is never a remote semantic ACK.
#[derive(Debug)]
pub enum Action<'i> {
    /// Bind the exact CADET group port.
    OpenPort {
        /// Original group generation.
        group: GroupId<'i>,
        /// Exact public port hash.
        hash: Group,
    },
    /// Close the actual port and its remaining channel ownership.
    ClosePort {
        /// Original group generation.
        group: GroupId<'i>,
        /// Original public hash.
        hash: Group,
    },
    /// Start or reuse an actual CADET channel; local Written is not online.
    Connect {
        /// Original group generation.
        group: GroupId<'i>,
        /// Authenticated destination.
        peer: Peer,
    },
    /// Retire the actual channel, including original outstanding sends.
    ClosePeer {
        /// Original group generation.
        group: GroupId<'i>,
        /// Original peer.
        peer: Peer,
    },
    /// Send exact original bytes on the original channel generation.
    PeerSend {
        /// Original group generation.
        group: GroupId<'i>,
        /// Destination, never supplied by peer payload.
        peer: Peer,
        /// Immutable original message.
        message: PeerOutput,
    },
    /// Emit a view snapshot to one original IPC client.
    ClientView {
        /// Original client generation.
        client: Client<'i>,
        /// Raw official debug ID, normally zero.
        id: [u8; 4],
        /// Snapshot, not a late borrow of the mutable view.
        peers: Vec<Peer>,
    },
    /// Emit newly accepted biased-stream members to one original client.
    ClientStream {
        /// Original client generation.
        client: Client<'i>,
        /// Actual selected-group observations.
        peers: Vec<Peer>,
    },
}
impl Action<'_> {
    /// Borrow an official client reply; no response exists for other actions.
    #[must_use]
    pub fn client_response(&self) -> Option<ClientResponse<'_>> {
        match self {
            Self::ClientView { id, peers, .. } => Some(ClientResponse::View { id: *id, peers }),
            Self::ClientStream { peers, .. } => Some(ClientResponse::Stream { peers }),
            _ => None,
        }
    }
    fn bytes(&self) -> Result<usize, Error> {
        match self {
            Self::ClientView { peers, .. } | Self::ClientStream { peers, .. } => bytes(peers),
            Self::PeerSend { message, .. } => message.bytes(),
            _ => Ok(0),
        }
    }
    fn group(&self) -> Option<GroupId<'_>> {
        match self {
            Self::OpenPort { group, .. }
            | Self::ClosePort { group, .. }
            | Self::Connect { group, .. }
            | Self::ClosePeer { group, .. }
            | Self::PeerSend { group, .. } => Some(*group),
            _ => None,
        }
    }
}
/// Original effect still owned by the core until a real host terminal event.
#[derive(Debug)]
pub struct Effect<'i> {
    /// Once-only original action token.
    pub id: EffectId<'i>,
    /// Immutable bytes and original destinations for this action.
    pub action: Action<'i>,
    admitted: bool,
}
impl Effect<'_> {
    /// Whether the host has already accepted this exact original action.
    #[must_use]
    pub const fn is_admitted(&self) -> bool {
        self.admitted
    }
}
/// Actual host terminal disposition; no fake ACK or implicit replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Completion {
    /// The original action was actually written/locally applied.
    Written,
    /// The original action provably did not enter its external sink.
    Unsent(Error),
    /// Exposure/processing is uncertain; this original is never replayed.
    Lost(Error),
}
/// Original owned terminal work returned to the host for cause retention.
#[derive(Debug)]
pub struct Terminal<'i> {
    /// Exact original action, including immutable snapshot and IDs.
    pub effect: Effect<'i>,
    /// The real completion supplied by the host.
    pub completion: Completion,
}

#[derive(Clone, Copy)]
struct PeerState<'i> {
    peer: Peer,
    online: bool,
    seeded: bool,
    seed_pending: bool,
    pull_discovered: bool,
    probing_until: Option<u64>,
    pull: Option<(EffectId<'i>, bool)>,
    pull_until: Option<u64>,
}
struct State<'i> {
    id: GroupId<'i>,
    hash: Group,
    config: Config,
    next_round: u64,
    peers: Vec<PeerState<'i>>,
    view: Vec<Peer>,
    pushes: Vec<Peer>,
    pulls: Vec<Peer>,
    sampler: Sampler,
}
impl State<'_> {
    fn copy(&self) -> Result<Self, Error> {
        Ok(Self {
            id: self.id,
            hash: self.hash,
            config: self.config,
            next_round: self.next_round,
            peers: copied(&self.peers)?,
            view: copied(&self.view)?,
            pushes: copied(&self.pushes)?,
            pulls: copied(&self.pulls)?,
            sampler: self.sampler.copy()?,
        })
    }
    fn bytes(&self) -> Result<usize, Error> {
        add(
            add(
                add(bytes(&self.peers)?, bytes(&self.view)?)?,
                add(bytes(&self.pushes)?, bytes(&self.pulls)?)?,
            )?,
            self.sampler.retained_bytes()?,
        )
    }
    fn copy_bound(&self) -> Result<usize, Error> {
        add(
            add(
                self.peers
                    .len()
                    .checked_mul(size_of::<PeerState<'_>>())
                    .ok_or(Error::Overflow)?,
                add(self.view.len(), add(self.pushes.len(), self.pulls.len())?)?
                    .checked_mul(size_of::<Peer>())
                    .ok_or(Error::Overflow)?,
            )?,
            self.sampler.retained_bytes()?,
        )
    }
}
#[derive(Clone, Copy)]
struct ClientState<'i> {
    id: Client<'i>,
    group: GroupId<'i>,
    stream: bool,
    view: Option<u32>,
}
struct Stage<'i> {
    brand: &'i Instance,
    next: u64,
    effects: Vec<Effect<'i>>,
    views: Vec<(Client<'i>, Option<u32>)>,
    max_effects: usize,
    max_bytes: usize,
    temporary: usize,
}
impl<'i> Stage<'i> {
    fn push(&mut self, action: Action<'i>) -> Result<EffectId<'i>, Error> {
        if self.effects.len() >= self.max_effects {
            return Err(Error::Capacity);
        }
        let serial = self.next;
        self.next = serial.checked_add(1).ok_or(Error::Overflow)?;
        reserve(&mut self.effects, 1)?;
        let id = EffectId {
            brand: self.brand,
            serial,
        };
        self.effects.push(Effect {
            id,
            action,
            admitted: false,
        });
        if self.bytes()? > self.max_bytes {
            return Err(Error::Capacity);
        }
        Ok(id)
    }
    fn peer_closing(&self, group: GroupId<'i>, peer: Peer) -> bool {
        self.effects.iter().any(|effect|matches!(effect.action,Action::ClosePeer { group:g,peer:p } if g == group && p == peer))
    }
    fn copy_peers(&self, peers: &[Peer]) -> Result<Vec<Peer>, Error> {
        let minimum = peers
            .len()
            .checked_mul(size_of::<Peer>())
            .ok_or(Error::Overflow)?;
        if add(add(self.bytes()?, minimum)?, size_of::<Effect<'i>>())? > self.max_bytes {
            return Err(Error::Capacity);
        }
        let out = copied(peers)?;
        if add(add(self.bytes()?, bytes(&out)?)?, size_of::<Effect<'i>>())? > self.max_bytes {
            return Err(Error::Capacity);
        }
        Ok(out)
    }
    fn bytes(&self) -> Result<usize, Error> {
        self.effects.iter().try_fold(
            add(bytes(&self.effects)?, bytes(&self.views)?)?,
            |sum, effect| add(sum, effect.action.bytes()?),
        )
    }
}

/// Actual no_std protocol owner. The host owns transport, clocks and entropy.
pub struct Service<'i> {
    brand: &'i Instance,
    local: Peer,
    main: GroupId<'i>,
    config: Config,
    limits: Limits,
    next: u64,
    now: u64,
    closed: bool,
    groups: Vec<State<'i>>,
    clients: Vec<ClientState<'i>>,
    effects: Vec<Effect<'i>>,
}
impl<'i> Service<'i> {
    /// Construct the main group and retain its actual OpenPort action.
    pub fn new(
        brand: &'i mut Instance,
        local: Peer,
        main_hash: Group,
        config: Config,
        limits: Limits,
        now: u64,
        random: &mut impl Random,
    ) -> Result<Self, Error> {
        limits.validate(config)?;
        let minimum = add(
            Sampler::minimum_bytes(config.sampler_size)?,
            add(size_of::<State<'i>>(), size_of::<Effect<'i>>())?,
        )?;
        if minimum > limits.retained_bytes {
            return Err(Error::Capacity);
        }
        let main = GroupId { brand, serial: 1 };
        let state = Self::new_state(main, main_hash, config, now, random)?;
        let mut groups = Vec::new();
        reserve(&mut groups, 1)?;
        groups.push(state);
        let mut effects = Vec::new();
        reserve(&mut effects, 1)?;
        effects.push(Effect {
            id: EffectId { brand, serial: 2 },
            action: Action::OpenPort {
                group: main,
                hash: main_hash,
            },
            admitted: false,
        });
        let service = Self {
            brand,
            local,
            main,
            config,
            limits,
            next: 3,
            now,
            closed: false,
            groups,
            clients: Vec::new(),
            effects,
        };
        service.budget(0)?;
        Ok(service)
    }
    fn new_state(
        id: GroupId<'i>,
        hash: Group,
        config: Config,
        now: u64,
        random: &mut impl Random,
    ) -> Result<State<'i>, Error> {
        Ok(State {
            id,
            hash,
            config,
            next_round: jitter(now, config.round_interval, random)?,
            peers: Vec::new(),
            view: Vec::new(),
            pushes: Vec::new(),
            pulls: Vec::new(),
            sampler: Sampler::new(config.sampler_size, random)?,
        })
    }
    fn guard(&self, now: u64) -> Result<(), Error> {
        if self.closed {
            Err(Error::Closed)
        } else if now < self.now {
            Err(Error::TimeUncertain)
        } else {
            Ok(())
        }
    }
    fn group_index(&self, id: GroupId<'i>) -> Result<usize, Error> {
        if !core::ptr::eq(self.brand, id.brand) {
            return Err(Error::StaleGeneration);
        }
        self.groups
            .iter()
            .position(|group| group.id == id)
            .ok_or(Error::StaleGeneration)
    }
    fn client_index(&self, id: Client<'i>) -> Result<usize, Error> {
        self.clients
            .iter()
            .position(|client| client.id == id)
            .ok_or(Error::StaleGeneration)
    }
    fn stage(&self) -> Stage<'i> {
        Stage {
            brand: self.brand,
            next: self.next,
            effects: Vec::new(),
            views: Vec::new(),
            max_effects: self.limits.effects - self.effects.len(),
            temporary: 0,
            max_bytes: self
                .limits
                .retained_bytes
                .saturating_sub(self.retained_bytes().unwrap_or(usize::MAX)),
        }
    }
    fn stage_for(&self, state: &State<'i>, temporary: usize) -> Result<Stage<'i>, Error> {
        let extra = add(state.bytes()?, temporary)?;
        self.budget(extra)?;
        let mut stage = self.stage();
        stage.temporary = temporary;
        stage.max_bytes = stage.max_bytes.checked_sub(extra).ok_or(Error::Capacity)?;
        Ok(stage)
    }
    fn sync_stage(&self, state: &State<'i>, stage: &mut Stage<'i>) -> Result<(), Error> {
        self.budget(add(add(state.bytes()?, stage.bytes()?)?, stage.temporary)?)?;
        stage.max_bytes = self
            .limits
            .retained_bytes
            .checked_sub(add(
                add(self.retained_bytes()?, state.bytes()?)?,
                stage.temporary,
            )?)
            .ok_or(Error::Capacity)?;
        Ok(())
    }
    fn budget(&self, extra: usize) -> Result<(), Error> {
        if add(self.retained_bytes()?, extra)? > self.limits.retained_bytes {
            Err(Error::Capacity)
        } else {
            Ok(())
        }
    }
    /// Whether admission has stopped; original host effects can remain live.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.closed
    }
    /// A stopped owner is quiescent only after every real terminal disposition.
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        self.closed && self.groups.is_empty() && self.effects.is_empty()
    }
    /// Queued and admitted original effects that still need terminal ownership.
    #[must_use]
    pub fn pending_effects(&self) -> usize {
        self.effects.len()
    }
    /// Actual retained capacities including in-flight original snapshots.
    pub fn retained_bytes(&self) -> Result<usize, Error> {
        let mut total = add(
            add(bytes(&self.groups)?, bytes(&self.clients)?)?,
            bytes(&self.effects)?,
        )?;
        for group in &self.groups {
            total = add(total, group.bytes()?)?;
        }
        for effect in &self.effects {
            total = add(total, effect.action.bytes()?)?;
        }
        Ok(total)
    }
    fn copy_group(&self, index: usize) -> Result<State<'i>, Error> {
        self.budget(self.groups[index].copy_bound()?)?;
        let copy = self.groups[index].copy()?;
        self.budget(copy.bytes()?)?;
        Ok(copy)
    }
    fn prepare(
        &self,
        stage: &Stage<'i>,
        transient: usize,
    ) -> Result<Option<Vec<Effect<'i>>>, Error> {
        let required = add(self.effects.len(), stage.effects.len())?;
        if required > self.limits.effects {
            return Err(Error::Capacity);
        }
        let extra = add(stage.bytes()?, transient)?;
        self.budget(extra)?;
        if required <= self.effects.capacity() {
            return Ok(None);
        }
        // Old immutable originals remain owned while a new metadata table is
        // reserved. No allocation error can strand a grown live table.
        self.budget(add(
            extra,
            required
                .checked_mul(size_of::<Effect<'i>>())
                .ok_or(Error::Overflow)?,
        )?)?;
        let mut queue = Vec::new();
        reserve(&mut queue, required)?;
        self.budget(add(extra, bytes(&queue)?)?)?;
        Ok(Some(queue))
    }
    fn append(&mut self, stage: Stage<'i>, queue: Option<Vec<Effect<'i>>>) {
        self.next = stage.next;
        for (client, view) in stage.views {
            if let Some(state) = self.clients.iter_mut().find(|state| state.id == client) {
                state.view = view;
            }
        }
        if let Some(mut queue) = queue {
            queue.append(&mut self.effects);
            queue.extend(stage.effects);
            self.effects = queue;
        } else {
            self.effects.extend(stage.effects);
        }
    }
    fn commit_group(
        &mut self,
        index: usize,
        state: State<'i>,
        stage: Stage<'i>,
        now: u64,
    ) -> Result<(), Error> {
        let queue = self.prepare(&stage, state.bytes()?)?;
        self.groups[index] = state;
        self.append(stage, queue);
        self.now = now;
        Ok(())
    }
    /// Stable main generation, independent of its wire hash.
    #[must_use]
    pub const fn main_group(&self) -> GroupId<'i> {
        self.main
    }
    /// Exact hash for a currently live original group generation.
    pub fn group_hash(&self, group: GroupId<'i>) -> Result<Group, Error> {
        Ok(self.groups[self.group_index(group)?].hash)
    }
    /// An original ClosePeer still owns all old channel/input/send retirement.
    /// The host may remove this barrier only after physically retiring those
    /// owners and completing that original ClosePeer effect. Stale groups are
    /// checked separately by group_hash/actual input admission.
    #[must_use]
    pub fn peer_closing(&self, group: GroupId<'i>, peer: Peer) -> bool {
        self.effects.iter().any(|effect| matches!(effect.action,Action::ClosePeer { group:g,peer:p } if g == group && p == peer))
    }
    /// Current selected group of an original native client.
    pub fn client_group(&self, client: Client<'i>) -> Result<GroupId<'i>, Error> {
        Ok(self.clients[self.client_index(client)?].group)
    }
    /// Attach one real IPC client without inventing any wire acknowledgement.
    pub fn attach_client(&mut self) -> Result<Client<'i>, Error> {
        self.guard(self.now)?;
        if self.clients.len() >= self.limits.clients {
            return Err(Error::Capacity);
        }
        let next = self.next.checked_add(1).ok_or(Error::Overflow)?;
        self.budget(size_of::<ClientState<'i>>())?;
        let mut replacement = if self.clients.len() == self.clients.capacity() {
            let count = add(self.clients.len(), 1)?;
            self.budget(
                count
                    .checked_mul(size_of::<ClientState<'i>>())
                    .ok_or(Error::Overflow)?,
            )?;
            let mut values = Vec::new();
            reserve(&mut values, count)?;
            self.budget(bytes(&values)?)?;
            Some(values)
        } else {
            None
        };
        let id = Client {
            brand: self.brand,
            serial: self.next,
        };
        if let Some(mut values) = replacement.take() {
            values.append(&mut self.clients);
            self.clients = values;
        }
        self.clients.push(ClientState {
            id,
            group: self.main,
            stream: false,
            view: None,
        });
        self.next = next;
        Ok(id)
    }
    /// Oldest unadmitted original action; admitting it never marks a peer live.
    #[must_use]
    pub fn effect(&self) -> Option<&Effect<'i>> {
        self.effects.iter().find(|effect| !effect.admitted)
    }
    /// Transfer the exact original effect to the actual host sink once.
    pub fn admit_effect(&mut self, id: EffectId<'i>) -> Result<(), Error> {
        let effect = self
            .effects
            .iter_mut()
            .find(|effect| effect.id == id)
            .ok_or(Error::StaleGeneration)?;
        if effect.admitted {
            return Err(Error::Replay);
        }
        effect.admitted = true;
        Ok(())
    }
    /// Retire an unadmitted effect with a provably unsent cause.
    pub fn reject_effect(
        &mut self,
        id: EffectId<'i>,
        reason: Error,
    ) -> Result<Terminal<'i>, Error> {
        let index = self
            .effects
            .iter()
            .position(|effect| effect.id == id)
            .ok_or(Error::StaleGeneration)?;
        if self.effects[index].admitted {
            return Err(Error::Conflict);
        }
        self.finish(index, Completion::Unsent(reason))
    }
    /// Apply the actual original terminal disposition, never a peer ACK.
    pub fn complete_effect(
        &mut self,
        id: EffectId<'i>,
        completion: Completion,
    ) -> Result<Terminal<'i>, Error> {
        let index = self
            .effects
            .iter()
            .position(|effect| effect.id == id)
            .ok_or(Error::StaleGeneration)?;
        if !self.effects[index].admitted {
            return Err(Error::NotReady);
        }
        self.finish(index, completion)
    }
    fn finish(&mut self, index: usize, completion: Completion) -> Result<Terminal<'i>, Error> {
        let effect = self.effects.remove(index);
        if let Action::PeerSend {
            group,
            peer,
            message: PeerOutput::PullRequest,
        } = &effect.action
            && let Ok(group_index) = self.group_index(*group)
            && let Some(state) = self.groups[group_index]
                .peers
                .iter_mut()
                .find(|state| state.peer == *peer)
            && state.pull.is_some_and(|(id, _)| id == effect.id)
        {
            if completion != Completion::Written {
                state.pull_until = None;
            }
            state.pull = if completion == Completion::Written {
                Some((effect.id, true))
            } else {
                None
            };
        }
        Ok(Terminal { effect, completion })
    }
    fn notify_view(&self, state: &State<'i>, stage: &mut Stage<'i>) -> Result<(), Error> {
        self.sync_stage(state, stage)?;
        for client in &self.clients {
            if client.group != state.id {
                continue;
            }
            let Some(updates) = client.view else {
                continue;
            };
            stage.push(Action::ClientView {
                client: client.id,
                id: [0; 4],
                peers: stage.copy_peers(&state.view)?,
            })?;
            if updates > 0 {
                reserve(&mut stage.views, 1)?;
                stage.views.push((
                    client.id,
                    if updates == 1 {
                        None
                    } else {
                        Some(updates - 1)
                    },
                ));
            }
        }
        Ok(())
    }
    fn notify_stream(
        &self,
        group: GroupId<'i>,
        peer: Peer,
        stage: &mut Stage<'i>,
    ) -> Result<(), Error> {
        for client in &self.clients {
            if client.group == group && client.stream {
                stage.push(Action::ClientStream {
                    client: client.id,
                    peers: stage.copy_peers(&[peer])?,
                })?;
            }
        }
        Ok(())
    }
    fn insert_view(
        &self,
        state: &mut State<'i>,
        peer: Peer,
        stage: &mut Stage<'i>,
    ) -> Result<bool, Error> {
        if state.view.contains(&peer) || state.view.len() >= state.config.view_size {
            return Ok(false);
        }
        self.budget(add(
            add(state.bytes()?, stage.bytes()?)?,
            size_of::<Peer>(),
        )?)?;
        reserve(&mut state.view, 1)?;
        state.view.push(peer);
        self.sync_stage(state, stage)?;
        self.notify_stream(state.id, peer, stage)?;
        Ok(true)
    }
    fn qualify(
        &self,
        state: &mut State<'i>,
        peer: Peer,
        stage: &mut Stage<'i>,
        rank: &mut impl Rank,
    ) -> Result<bool, Error> {
        if peer == self.local {
            return Ok(false);
        }
        self.budget(add(
            add(state.bytes()?, stage.bytes()?)?,
            size_of::<PeerState<'i>>(),
        )?)?;
        let index = peer_index(state, peer, self.limits.peers_per_group)?;
        self.sync_stage(state, stage)?;
        let was_online = state.peers[index].online;
        state.peers[index].online = true;
        state.peers[index].probing_until = None;
        if state.peers[index].pull_discovered {
            unique(&mut state.pulls, peer, self.limits.peers_per_group)?;
            state.peers[index].pull_discovered = false;
        }
        if state.peers[index].seed_pending && !state.peers[index].seeded {
            state.sampler.observe(peer, rank)?;
            state.peers[index].seeded = true;
            state.peers[index].seed_pending = false;
            if self.insert_view(state, peer, stage)? {
                self.notify_view(state, stage)?;
            }
        }
        Ok(!was_online)
    }
    fn discover_in(
        &self,
        state: &mut State<'i>,
        peer: Peer,
        now: u64,
        stage: &mut Stage<'i>,
        seed: bool,
        from_pull: bool,
    ) -> Result<(), Error> {
        if peer == self.local {
            return Ok(());
        }
        self.budget(add(
            add(state.bytes()?, stage.bytes()?)?,
            size_of::<PeerState<'i>>(),
        )?)?;
        if self.peer_closing(state.id, peer) || stage.peer_closing(state.id, peer) {
            return Err(Error::WouldBlock);
        }
        let index = peer_index(state, peer, self.limits.peers_per_group)?;
        self.sync_stage(state, stage)?;
        state.peers[index].seed_pending |= seed && !state.peers[index].seeded;
        state.peers[index].pull_discovered |= from_pull;
        if state.peers[index].online || state.peers[index].probing_until.is_some() {
            return Ok(());
        }
        let until = now
            .checked_add(state.config.probe_timeout)
            .ok_or(Error::Overflow)?;
        stage.push(Action::Connect {
            group: state.id,
            peer,
        })?;
        stage.push(Action::PeerSend {
            group: state.id,
            peer,
            message: PeerOutput::CheckLive,
        })?;
        let pull = stage.push(Action::PeerSend {
            group: state.id,
            peer,
            message: PeerOutput::PullRequest,
        })?;
        state.peers[index].probing_until = Some(until);
        state.peers[index].pull = Some((pull, false));
        state.peers[index].pull_until = Some(until);
        Ok(())
    }
    /// Seed one real public candidate, with bounded real PULL probing.
    pub fn discover(
        &mut self,
        group: GroupId<'i>,
        peer: Peer,
        now: u64,
        _random: &mut impl Random,
        rank: &mut impl Rank,
    ) -> Result<(), Error> {
        self.guard(now)?;
        let index = self.group_index(group)?;
        if self.peer_closing(group, peer) {
            return Err(Error::WouldBlock);
        }
        if peer == self.local
            || self.groups[index]
                .peers
                .iter()
                .any(|entry| entry.peer == peer && entry.seeded)
        {
            self.now = now;
            return Ok(());
        }
        let mut state = self.copy_group(index)?;
        let mut stage = self.stage_for(&state, 0)?;
        self.discover_in(&mut state, peer, now, &mut stage, true, false)?;
        if state
            .peers
            .iter()
            .any(|entry| entry.peer == peer && entry.online)
        {
            self.qualify(&mut state, peer, &mut stage, rank)?;
        }
        self.commit_group(index, state, stage, now)
    }
    /// Grant online qualification only after actual authenticated remote evidence.
    pub fn peer_connected(
        &mut self,
        group: GroupId<'i>,
        peer: Peer,
        now: u64,
        _random: &mut impl Random,
        rank: &mut impl Rank,
    ) -> Result<(), Error> {
        self.guard(now)?;
        let index = self.group_index(group)?;
        if self.peer_closing(group, peer) {
            return Err(Error::WouldBlock);
        }
        let mut state = self.copy_group(index)?;
        let mut stage = self.stage_for(&state, 0)?;
        self.qualify(&mut state, peer, &mut stage, rank)?;
        self.commit_group(index, state, stage, now)
    }
    /// Handle an already framed authenticated same-group peer message.
    ///
    /// Return success before the host releases its actual receive delivery.
    /// An unsolicited/old pull reply grants neither online nor sampler credit.
    pub fn peer_message(
        &mut self,
        group: GroupId<'i>,
        peer: Peer,
        message: PeerMessage<'_>,
        now: u64,
        random: &mut impl Random,
        rank: &mut impl Rank,
    ) -> Result<(), Error> {
        self.guard(now)?;
        if peer == self.local {
            return Err(Error::InvalidInput);
        }
        let index = self.group_index(group)?;
        if self.peer_closing(group, peer) {
            return Err(Error::WouldBlock);
        }
        if let PeerMessage::PullReply { peers } = message {
            self.validate_pull_reply(index, peer, peers)?;
        }
        let mut state = self.copy_group(index)?;
        let mut stage = self.stage_for(&state, 0)?;
        self.qualify(&mut state, peer, &mut stage, rank)?;
        match message {
            PeerMessage::CheckLive => {}
            PeerMessage::Push => {
                unique(&mut state.pushes, peer, self.limits.peers_per_group)?;
            }
            PeerMessage::PullRequest => {
                let mut peers = stage.copy_peers(&state.view)?;
                if peers.len() > MAX_PULL_PEERS {
                    crate::sampler::shuffle(&mut peers, random)?;
                }
                peers.truncate(MAX_PULL_PEERS);
                stage.push(Action::PeerSend {
                    group,
                    peer,
                    message: PeerOutput::PullReply { peers },
                })?;
            }
            PeerMessage::PullReply { peers } => {
                self.consume_pull_reply(&mut state, peer, peers, now, &mut stage, false)?;
            }
        }
        self.commit_group(index, state, stage, now)
    }
    fn validate_pull_reply(&self, index: usize, peer: Peer, peers: &[Peer]) -> Result<(), Error> {
        if peers.len() > self.limits.view || peers.len() > MAX_PULL_PEERS {
            return Err(Error::TooLarge);
        }
        if !self.groups[index]
            .peers
            .iter()
            .any(|entry| entry.peer == peer && entry.pull.is_some_and(|(_, written)| written))
        {
            return Err(Error::Replay);
        }
        Ok(())
    }
    fn consume_pull_reply(
        &self,
        state: &mut State<'i>,
        peer: Peer,
        peers: &[Peer],
        now: u64,
        stage: &mut Stage<'i>,
        sender_gone: bool,
    ) -> Result<(), Error> {
        let sender = state
            .peers
            .iter_mut()
            .find(|entry| entry.peer == peer)
            .ok_or(Error::StaleGeneration)?;
        sender.pull = None;
        sender.pull_until = None;
        for candidate in peers {
            if *candidate == self.local
                || (sender_gone && *candidate == peer)
                || self.peer_closing(state.id, *candidate)
                || stage.peer_closing(state.id, *candidate)
            {
                continue;
            }
            let existing = state
                .peers
                .iter()
                .find(|entry| entry.peer == *candidate)
                .is_some_and(|entry| entry.online);
            if existing {
                unique(&mut state.pulls, *candidate, self.limits.peers_per_group)?;
            } else {
                self.discover_in(state, *candidate, now, stage, false, true)?;
            }
        }
        Ok(())
    }
    fn remove_peer_state(
        &self,
        state: &mut State<'i>,
        peer: Peer,
        stage: &mut Stage<'i>,
    ) -> Result<(), Error> {
        state.peers.retain(|entry| entry.peer != peer);
        state.pushes.retain(|entry| *entry != peer);
        state.pulls.retain(|entry| *entry != peer);
        let old_len = state.view.len();
        state.view.retain(|entry| *entry != peer);
        if state.view.len() != old_len {
            self.notify_view(state, stage)?;
        }
        Ok(())
    }
    fn commit_peer_removal(
        &mut self,
        index: usize,
        state: State<'i>,
        stage: Stage<'i>,
        peer: Peer,
    ) -> Result<(), Error> {
        let group = state.id;
        let queue = self.prepare(&stage, state.bytes()?)?;
        // Admitted original sends remain until the host supplies their terminal.
        self.effects.retain(|effect| effect.admitted || !matches!(&effect.action, Action::Connect { group: g, peer: p } | Action::PeerSend { group: g, peer: p, .. } if *g == group && *p == peer));
        self.groups[index] = state;
        self.append(stage, queue);
        Ok(())
    }
    /// Consume an already authenticated original PULL reply after the last
    /// same-group peer channel actually closed. The original PULL must have
    /// really written; only third-party hints survive, with ordinary probes.
    /// The gone sender gains no online, stream or sampler qualification.
    pub fn peer_pull_reply_after_close(
        &mut self,
        group: GroupId<'i>,
        peer: Peer,
        peers: &[Peer],
        now: u64,
    ) -> Result<(), Error> {
        self.guard(now)?;
        if peer == self.local {
            return Err(Error::InvalidInput);
        }
        let index = self.group_index(group)?;
        if self.peer_closing(group, peer) {
            return Err(Error::WouldBlock);
        }
        self.validate_pull_reply(index, peer, peers)?;
        let mut state = self.copy_group(index)?;
        let mut stage = self.stage_for(&state, 0)?;
        self.consume_pull_reply(&mut state, peer, peers, now, &mut stage, true)?;
        self.remove_peer_state(&mut state, peer, &mut stage)?;
        self.commit_peer_removal(index, state, stage, peer)?;
        self.now = now;
        Ok(())
    }
    /// Retire one original channel's qualification and original outstanding pull.
    pub fn peer_lost(&mut self, group: GroupId<'i>, peer: Peer) -> Result<(), Error> {
        let index = self.group_index(group)?;
        let mut state = self.copy_group(index)?;
        let mut stage = self.stage_for(&state, 0)?;
        self.remove_peer_state(&mut state, peer, &mut stage)?;
        self.commit_peer_removal(index, state, stage, peer)
    }
    /// Apply one actual IPC request. There is no fictitious per-request wire ACK.
    pub fn client_request(
        &mut self,
        client: Client<'i>,
        request: ClientRequest<'_>,
        now: u64,
        random: &mut impl Random,
        rank: &mut impl Rank,
    ) -> Result<(), Error> {
        self.guard(now)?;
        let index = self.client_index(client)?;
        match request {
            ClientRequest::Seed { peers } => {
                if peers.len() > self.limits.peers_per_group {
                    return Err(Error::TooLarge);
                }
                let selected = self.clients[index].group;
                // Each idempotent public seed is separately admitted. An error
                // retains its real accepted prefix; it is not a STORE receipt.
                for peer in peers {
                    self.discover(self.main, *peer, now, random, rank)?;
                    if selected != self.main {
                        self.discover(selected, *peer, now, random, rank)?;
                    }
                }
            }
            ClientRequest::SubStart {
                round_interval,
                group,
                ..
            } => self.select_group(client, group, round_interval.as_micros(), now, random)?,
            ClientRequest::SubStop { group } => {
                let selected = self.clients[index].group;
                if selected == self.main || self.group_hash(selected)? != group {
                    return Err(Error::InvalidInput);
                }
                self.select_group(
                    client,
                    self.group_hash(self.main)?,
                    self.config.round_interval,
                    now,
                    random,
                )?;
            }
            ClientRequest::ViewRequest { updates } => {
                let group = self.group_index(self.clients[index].group)?;
                let mut stage = self.stage();
                stage.push(Action::ClientView {
                    client,
                    id: [0; 4],
                    peers: stage.copy_peers(&self.groups[group].view)?,
                })?;
                let queue = self.prepare(&stage, 0)?;
                self.effects.retain(|effect| effect.admitted || !matches!(&effect.action, Action::ClientView { client: c, .. } if *c == client));
                self.clients[index].view = if updates == 1 {
                    None
                } else {
                    Some(updates.saturating_sub(1))
                };
                self.append(stage, queue);
            }
            ClientRequest::ViewCancel => {
                self.clients[index].view = None;
                self.effects.retain(|effect| effect.admitted || !matches!(&effect.action, Action::ClientView { client: c, .. } if *c == client));
            }
            ClientRequest::StreamRequest => self.clients[index].stream = true,
            ClientRequest::StreamCancel => {
                self.clients[index].stream = false;
                self.effects.retain(|effect| effect.admitted || !matches!(&effect.action, Action::ClientStream { client: c, .. } if *c == client));
            }
        }
        self.now = now;
        Ok(())
    }
    fn selected_elsewhere(&self, group: GroupId<'i>, except: Client<'i>) -> bool {
        group == self.main
            || self
                .clients
                .iter()
                .any(|client| client.id != except && client.group == group)
    }
    fn close_group_actions(&self, group: GroupId<'i>, stage: &mut Stage<'i>) -> Result<(), Error> {
        let state = &self.groups[self.group_index(group)?];
        // The port owns all of its actual channels. One aggregate retirement
        // must fit independently of the number of merely known public peers.
        stage.push(Action::ClosePort {
            group,
            hash: state.hash,
        })?;
        Ok(())
    }
    fn select_group(
        &mut self,
        client: Client<'i>,
        hash: Group,
        interval: u64,
        now: u64,
        random: &mut impl Random,
    ) -> Result<(), Error> {
        if interval < 2 || interval == u64::MAX {
            return Err(Error::InvalidInput);
        }
        let client_index = self.client_index(client)?;
        let old = self.clients[client_index].group;
        if self.group_hash(old)? == hash {
            // An existing shared port has one coherent round interval.
            if self.groups[self.group_index(old)?].config.round_interval != interval {
                return Err(Error::Conflict);
            }
            return Ok(());
        }
        let mut stage = self.stage();
        let mut fresh = None;
        let selected = if let Some(group) = self.groups.iter().find(|group| group.hash == hash) {
            if group.config.round_interval != interval {
                return Err(Error::Conflict);
            }
            group.id
        } else {
            let retire_old = !self.selected_elsewhere(old, client);
            if self.groups.len() >= self.limits.groups && !retire_old {
                return Err(Error::Capacity);
            }
            let serial = stage.next;
            stage.next = serial.checked_add(1).ok_or(Error::Overflow)?;
            let id = GroupId {
                brand: self.brand,
                serial,
            };
            let config = Config {
                round_interval: interval,
                ..self.config
            };
            self.budget(Sampler::minimum_bytes(config.sampler_size)?)?;
            let state = Self::new_state(id, hash, config, now, random)?;
            self.budget(state.bytes()?)?;
            stage.push(Action::OpenPort { group: id, hash })?;
            fresh = Some(state);
            id
        };
        let retire_old = !self.selected_elsewhere(old, client);
        if retire_old {
            self.close_group_actions(old, &mut stage)?;
        }
        let transient = fresh.as_ref().map_or(Ok(0), State::bytes)?;
        let queue = self.prepare(&stage, transient)?;
        let queue_bytes = queue.as_ref().map_or(Ok(0), bytes)?;
        let group_transient = add(transient, queue_bytes)?;
        let group_table =
            if fresh.is_some() && !retire_old && self.groups.len() == self.groups.capacity() {
                let count = add(self.groups.len(), 1)?;
                self.budget(add(
                    add(stage.bytes()?, group_transient)?,
                    count
                        .checked_mul(size_of::<State<'i>>())
                        .ok_or(Error::Overflow)?,
                )?)?;
                let mut values = Vec::new();
                reserve(&mut values, count)?;
                self.budget(add(add(stage.bytes()?, group_transient)?, bytes(&values)?)?)?;
                Some(values)
            } else {
                None
            };
        // Original admitted writes retain their old client/group identity.
        self.effects.retain(|effect| effect.admitted || (!matches!(&effect.action, Action::ClientView { client: c, .. } | Action::ClientStream { client: c, .. } if *c == client) && !(retire_old && effect.action.group() == Some(old))));
        if retire_old {
            self.groups.retain(|group| group.id != old);
        }
        if let Some(mut values) = group_table {
            values.append(&mut self.groups);
            self.groups = values;
        }
        if let Some(group) = fresh {
            self.groups.push(group);
        }
        self.clients[client_index].group = selected;
        self.append(stage, queue);
        self.now = now;
        Ok(())
    }
    /// Retire the real original IPC client and its last-selected subgroup.
    /// Admitted original effects still accept only their own terminal outcome.
    pub fn detach_client(&mut self, client: Client<'i>) -> Result<(), Error> {
        let index = self.client_index(client)?;
        let group = self.clients[index].group;
        let retire = !self.selected_elsewhere(group, client);
        let mut stage = self.stage();
        if retire {
            self.close_group_actions(group, &mut stage)?;
        }
        let queue = self.prepare(&stage, 0)?;
        self.effects.retain(|effect| effect.admitted || (!matches!(&effect.action, Action::ClientView { client: c, .. } | Action::ClientStream { client: c, .. } if *c == client) && !(retire && effect.action.group() == Some(group))));
        self.clients.remove(index);
        if retire {
            self.groups.retain(|state| state.id != group);
        }
        self.append(stage, queue);
        Ok(())
    }
    /// Adapt this group's bounded view/history targets using actual NSE input.
    pub fn resize(
        &mut self,
        group: GroupId<'i>,
        view_size: usize,
        sampler_size: usize,
        now: u64,
        random: &mut impl Random,
    ) -> Result<(), Error> {
        self.guard(now)?;
        if view_size == 0
            || view_size > self.limits.view
            || sampler_size == 0
            || sampler_size > self.limits.sampler
        {
            return Err(Error::InvalidInput);
        }
        let index = self.group_index(group)?;
        let mut state = self.copy_group(index)?;
        let mut stage = self.stage_for(&state, 0)?;
        if sampler_size > state.sampler.len() {
            self.budget(add(state.bytes()?, Sampler::minimum_bytes(sampler_size)?)?)?;
        }
        state.sampler.resize(sampler_size, random)?;
        state.config.view_size = view_size;
        state.config.sampler_size = sampler_size;
        if state.view.len() > view_size {
            state.view = shuffled(&state.view, random)?;
            state.view.truncate(view_size);
            self.notify_view(&state, &mut stage)?;
        }
        self.commit_group(index, state, stage, now)
    }
    /// Adapt every active group and the initial sizes of future subgroups.
    pub fn resize_all(
        &mut self,
        view_size: usize,
        sampler_size: usize,
        now: u64,
        random: &mut impl Random,
    ) -> Result<(), Error> {
        self.guard(now)?;
        for index in 0..self.groups.len() {
            let group = self.groups[index].id;
            self.resize(group, view_size, sampler_size, now, random)?;
        }
        self.config.view_size = view_size;
        self.config.sampler_size = sampler_size;
        Ok(())
    }
    /// Earliest original round or live discovery deadline.
    #[must_use]
    pub fn next_deadline(&self) -> Option<u64> {
        if self.closed {
            return None;
        }
        self.groups
            .iter()
            .flat_map(|state| {
                core::iter::once(state.next_round)
                    .chain(state.peers.iter().filter_map(|peer| deadline(peer)))
            })
            .min()
    }
    /// Process due original timers without assigning a new deadline to old work.
    pub fn round_due(
        &mut self,
        now: u64,
        random: &mut impl Random,
        rank: &mut impl Rank,
    ) -> Result<(), Error> {
        self.guard(now)?;
        // IDs are copied one at a time; a round does not create/destroy groups.
        for index in 0..self.groups.len() {
            let group = self.groups[index].id;
            if self.groups[index].next_round <= now
                || self.groups[index]
                    .peers
                    .iter()
                    .any(|peer| deadline(peer).is_some_and(|until| until <= now))
            {
                self.round(group, now, random, rank)?;
            }
        }
        self.now = now;
        Ok(())
    }
    /// Run one Brahms round, preserving its push/pull/history and flooding bound.
    pub fn round(
        &mut self,
        group: GroupId<'i>,
        now: u64,
        random: &mut impl Random,
        rank: &mut impl Rank,
    ) -> Result<(), Error> {
        self.guard(now)?;
        let index = self.group_index(group)?;
        let mut state = self.copy_group(index)?;
        let temporary = add(
            state.peers.len(),
            add(
                state.view.len().checked_mul(2).ok_or(Error::Overflow)?,
                add(state.pushes.len(), state.pulls.len())?,
            )?,
        )?
        .checked_mul(size_of::<Peer>())
        .ok_or(Error::Overflow)?;
        let mut stage = self.stage_for(&state, temporary)?;
        let mut expired = Vec::new();
        for peer in &state.peers {
            if deadline(peer).is_some_and(|until| until <= now) {
                reserve(&mut expired, 1)?;
                expired.push(peer.peer);
                stage.push(Action::ClosePeer {
                    group,
                    peer: peer.peer,
                })?;
            }
        }
        state.peers.retain(|peer| !expired.contains(&peer.peer));
        state.pushes.retain(|peer| !expired.contains(peer));
        state.pulls.retain(|peer| !expired.contains(peer));
        let previous = copied(&state.view)?;
        state.view.retain(|peer| !expired.contains(peer));
        if state.next_round <= now {
            let permutation = shuffled(&state.view, random)?;
            let push_count = fraction_ceil(permutation.len(), 45)?;
            let pull_count = fraction_ceil(permutation.len(), 45)?;
            for peer in permutation.iter().take(push_count) {
                stage.push(Action::PeerSend {
                    group,
                    peer: *peer,
                    message: PeerOutput::Push,
                })?;
            }
            let pull_start = push_count.min(permutation.len().saturating_sub(pull_count));
            for peer in permutation.iter().skip(pull_start).take(pull_count) {
                let Some(peer_state) = state.peers.iter_mut().find(|entry| entry.peer == *peer)
                else {
                    continue;
                };
                if peer_state.pull.is_none() {
                    let id = stage.push(Action::PeerSend {
                        group,
                        peer: *peer,
                        message: PeerOutput::PullRequest,
                    })?;
                    peer_state.pull = Some((id, false));
                    peer_state.pull_until = Some(
                        now.checked_add(state.config.probe_timeout)
                            .ok_or(Error::Overflow)?,
                    );
                }
            }
            // Reject push flooding before admitting a new view. Qualification
            // alone never inserts an unsolicited PUSH sender into the view.
            let push_threshold = state
                .config
                .view_size
                .checked_mul(45)
                .ok_or(Error::Overflow)?;
            if !state.pushes.is_empty()
                && state.pushes.len().checked_mul(100).ok_or(Error::Overflow)? <= push_threshold
                && !state.pulls.is_empty()
            {
                let push = shuffled(&state.pushes, random)?;
                let pull = shuffled(&state.pulls, random)?;
                state.view.clear();
                let push_target = fraction_ceil(state.config.view_size, 45)?;
                let pull_target = state
                    .config
                    .view_size
                    .checked_mul(45)
                    .ok_or(Error::Overflow)?
                    / 100;
                for peer in push
                    .iter()
                    .take(push_target)
                    .chain(pull.iter().take(pull_target))
                {
                    self.insert_view(&mut state, *peer, &mut stage)?;
                }
                let history_target = fraction_ceil(state.config.view_size, 10)?;
                for _ in 0..history_target {
                    if let Some(peer) = state.sampler.sample(random)? {
                        if state
                            .peers
                            .iter()
                            .any(|entry| entry.peer == peer && entry.online)
                        {
                            self.insert_view(&mut state, peer, &mut stage)?;
                        } else if !self.peer_closing(group, peer)
                            && !stage.peer_closing(group, peer)
                        {
                            self.discover_in(&mut state, peer, now, &mut stage, true, false)?;
                        }
                    }
                }
            }
            // Feed both unique streams even when flooding blocks view update.
            for peer in state.pushes.iter().chain(&state.pulls) {
                state.sampler.observe(*peer, rank)?;
            }
            state.pushes.clear();
            state.pulls.clear();
            state.next_round = jitter(now, state.config.round_interval, random)?;
        }
        if previous != state.view {
            self.notify_view(&state, &mut stage)?;
        }
        let queue = self.prepare(
            &stage,
            add(state.bytes()?, add(bytes(&expired)?, bytes(&previous)?)?)?,
        )?;
        // Timer expiry retires unsent probes. Admitted originals are never
        // recycled as new probes; the host closes and returns each actual fact.
        self.effects.retain(|effect| effect.admitted || !matches!(&effect.action, Action::Connect { group: g, peer } | Action::PeerSend { group: g, peer, .. } if *g == group && expired.contains(peer)));
        self.groups[index] = state;
        self.append(stage, queue);
        self.now = now;
        Ok(())
    }
    /// Stop admission and retain concrete close actions for every real group.
    /// Existing admitted originals still require their real terminal events.
    pub fn shutdown(&mut self) -> Result<(), Error> {
        if self.closed && self.groups.is_empty() {
            return Ok(());
        }
        // Stop admission and suppress ordinary work before calculating closing
        // slots. Preserve original admitted work and an earlier retired group's
        // unadmitted ClosePort, whose actual resource still needs retirement.
        self.closed = true;
        self.clients.clear();
        self.effects
            .retain(|effect| effect.admitted || matches!(effect.action, Action::ClosePort { .. }));
        let mut stage = self.stage();
        for state in &self.groups {
            self.close_group_actions(state.id, &mut stage)?;
        }
        let queue = self.prepare(&stage, 0)?;
        self.groups.clear();
        self.append(stage, queue);
        self.closed = true;
        Ok(())
    }
}

fn peer_index<'i>(state: &mut State<'i>, peer: Peer, maximum: usize) -> Result<usize, Error> {
    if let Some(index) = state.peers.iter().position(|entry| entry.peer == peer) {
        return Ok(index);
    }
    if state.peers.len() >= maximum {
        return Err(Error::Capacity);
    }
    reserve(&mut state.peers, 1)?;
    let index = state.peers.len();
    state.peers.push(PeerState {
        peer,
        online: false,
        seeded: false,
        seed_pending: false,
        pull_discovered: false,
        probing_until: None,
        pull: None,
        pull_until: None,
    });
    Ok(index)
}
fn unique(values: &mut Vec<Peer>, peer: Peer, maximum: usize) -> Result<(), Error> {
    if values.contains(&peer) {
        return Ok(());
    }
    if values.len() >= maximum {
        return Err(Error::Capacity);
    }
    reserve(values, 1)?;
    values.push(peer);
    Ok(())
}
fn fraction_ceil(value: usize, percent: usize) -> Result<usize, Error> {
    value
        .checked_mul(percent)
        .and_then(|n| n.checked_add(99))
        .map(|n| n / 100)
        .ok_or(Error::Overflow)
}
fn jitter(now: u64, interval: u64, random: &mut impl Random) -> Result<u64, Error> {
    let extra = crate::sampler::uniform_u64(random, interval)?;
    now.checked_add(interval / 2)
        .and_then(|n| n.checked_add(extra))
        .ok_or(Error::Overflow)
}

fn deadline(peer: &PeerState<'_>) -> Option<u64> {
    match (peer.probing_until, peer.pull_until) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "test assertions report failed protocol invariants"
)]
mod tests {
    use super::*;
    struct Entropy(u8);
    impl Random for Entropy {
        fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
            for byte in out {
                self.0 = self.0.wrapping_add(1);
                *byte = self.0;
            }
            Ok(())
        }
    }
    struct TestRank(bool);
    impl Rank for TestRank {
        fn rank(&mut self, key: &[u8; 64], peer: &Peer) -> Result<[u8; 64], Error> {
            if self.0 {
                return Err(Error::Io);
            }
            let mut out = *key;
            out[..32].copy_from_slice(peer);
            Ok(out)
        }
    }
    fn written(service: &mut Service<'_>) -> Result<(), Error> {
        while let Some(effect) = service.effect() {
            let id = effect.id;
            service.admit_effect(id)?;
            let terminal = service.complete_effect(id, Completion::Written)?;
            assert_eq!(terminal.completion, Completion::Written);
        }
        Ok(())
    }
    #[test]
    fn local_written_is_not_remote_live_and_unsolicited_reply_is_rejected() -> Result<(), Error> {
        let mut brand = Instance::new();
        let mut random = Entropy(0);
        let mut rank = TestRank(false);
        let mut service = Service::new(
            &mut brand,
            [1; 32],
            [2; 64],
            Config::default(),
            Limits::default(),
            0,
            &mut random,
        )?;
        written(&mut service)?;
        let group = service.main_group();
        service.discover(group, [3; 32], 0, &mut random, &mut rank)?;
        assert_eq!(
            service.peer_message(
                group,
                [3; 32],
                PeerMessage::PullReply { peers: &[] },
                0,
                &mut random,
                &mut rank
            ),
            Err(Error::Replay)
        );
        written(&mut service)?;
        assert!(service.groups[0].view.is_empty());
        assert!(!service.groups[0].peers[0].online);
        service.peer_message(
            group,
            [3; 32],
            PeerMessage::PullReply { peers: &[] },
            1,
            &mut random,
            &mut rank,
        )?;
        assert_eq!(service.groups[0].view, alloc::vec![[3; 32]]);
        assert_eq!(
            service.peer_message(
                group,
                [3; 32],
                PeerMessage::PullReply { peers: &[] },
                1,
                &mut random,
                &mut rank
            ),
            Err(Error::Replay)
        );
        Ok(())
    }
    #[test]
    fn subgroup_recreation_rejects_old_group_and_original_effects_still_retire() -> Result<(), Error>
    {
        let mut brand = Instance::new();
        let mut random = Entropy(3);
        let mut rank = TestRank(false);
        let mut service = Service::new(
            &mut brand,
            [1; 32],
            [2; 64],
            Config::default(),
            Limits::default(),
            0,
            &mut random,
        )?;
        let client = service.attach_client()?;
        let start = ClientRequest::SubStart {
            reserved: [0; 4],
            round_interval: gnunet_wire::official::RelativeTime::from_micros(30_000_000),
            group: [4; 64],
        };
        service.client_request(client, start, 0, &mut random, &mut rank)?;
        let old = service.client_group(client)?;
        let old_open = service
            .effects
            .iter()
            .find(|effect| matches!(effect.action,Action::OpenPort { group,.. } if group == old))
            .map(|effect| effect.id)
            .ok_or(Error::NotFound)?;
        service.admit_effect(old_open)?;
        service.client_request(
            client,
            ClientRequest::SubStop { group: [4; 64] },
            0,
            &mut random,
            &mut rank,
        )?;
        service.client_request(client, start, 0, &mut random, &mut rank)?;
        let current = service.client_group(client)?;
        assert_ne!(old, current);
        assert_eq!(
            service.peer_connected(old, [3; 32], 0, &mut random, &mut rank),
            Err(Error::StaleGeneration)
        );
        let terminal = service.complete_effect(old_open, Completion::Lost(Error::Io))?;
        assert_eq!(terminal.effect.id, old_open);
        assert_eq!(terminal.completion, Completion::Lost(Error::Io));
        assert!(service.group_hash(current).is_ok());
        Ok(())
    }
    #[test]
    fn rank_failure_does_not_commit_online_view_sampler_or_notifications() -> Result<(), Error> {
        let mut brand = Instance::new();
        let mut random = Entropy(9);
        let mut rank = TestRank(false);
        let mut service = Service::new(
            &mut brand,
            [1; 32],
            [2; 64],
            Config::default(),
            Limits::default(),
            0,
            &mut random,
        )?;
        let group = service.main_group();
        service.discover(group, [3; 32], 0, &mut random, &mut rank)?;
        let pending = service.pending_effects();
        rank.0 = true;
        assert_eq!(
            service.peer_message(
                group,
                [3; 32],
                PeerMessage::CheckLive,
                0,
                &mut random,
                &mut rank
            ),
            Err(Error::Io)
        );
        assert!(!service.groups[0].peers[0].online);
        assert!(service.groups[0].view.is_empty());
        assert_eq!(service.pending_effects(), pending);
        Ok(())
    }
    #[test]
    fn group_close_uses_one_original_port_action_not_one_per_known_peer() -> Result<(), Error> {
        let mut brand = Instance::new();
        let mut random = Entropy(7);
        let mut rank = TestRank(false);
        let limits = Limits {
            groups: 2,
            effects: 2,
            peers_per_group: 64,
            ..Limits::default()
        };
        let mut service = Service::new(
            &mut brand,
            [1; 32],
            [2; 64],
            Config::default(),
            limits,
            0,
            &mut random,
        )?;
        let client = service.attach_client()?;
        service.client_request(
            client,
            ClientRequest::SubStart {
                reserved: [0; 4],
                round_interval: gnunet_wire::official::RelativeTime::from_micros(30_000_000),
                group: [4; 64],
            },
            0,
            &mut random,
            &mut rank,
        )?;
        written(&mut service)?;
        for state in &mut service.groups {
            for value in 0..64 {
                let mut peer = [0; 32];
                peer[0] = value;
                peer_index(state, peer, 64)?;
            }
        }
        service.shutdown()?;
        assert_eq!(service.pending_effects(), 2);
        assert!(
            service
                .effects
                .iter()
                .all(|effect| matches!(effect.action, Action::ClosePort { .. }))
        );
        assert!(!service.is_quiescent());
        written(&mut service)?;
        assert!(service.is_quiescent());
        Ok(())
    }
    #[test]
    fn shutdown_cancels_unadmitted_ordinary_work_before_close_admission() -> Result<(), Error> {
        let mut brand = Instance::new();
        let mut random = Entropy(11);
        let mut rank = TestRank(false);
        let limits = Limits {
            groups: 2,
            effects: 2,
            ..Limits::default()
        };
        let mut service = Service::new(
            &mut brand,
            [1; 32],
            [2; 64],
            Config::default(),
            limits,
            0,
            &mut random,
        )?;
        let client = service.attach_client()?;
        service.client_request(
            client,
            ClientRequest::SubStart {
                reserved: [0; 4],
                round_interval: gnunet_wire::official::RelativeTime::from_micros(30_000_000),
                group: [4; 64],
            },
            0,
            &mut random,
            &mut rank,
        )?;
        assert_eq!(service.pending_effects(), 2);
        service.shutdown()?;
        assert!(
            service
                .effects
                .iter()
                .all(|effect| matches!(effect.action, Action::ClosePort { .. }))
        );
        assert_eq!(service.pending_effects(), 2);
        written(&mut service)?;
        assert!(service.is_quiescent());
        Ok(())
    }
    #[test]
    fn shutdown_retries_after_original_admitted_terminal_without_false_quiescence()
    -> Result<(), Error> {
        let mut brand = Instance::new();
        let mut random = Entropy(17);
        let limits = Limits {
            groups: 1,
            effects: 1,
            ..Limits::default()
        };
        let mut service = Service::new(
            &mut brand,
            [1; 32],
            [2; 64],
            Config::default(),
            limits,
            0,
            &mut random,
        )?;
        let original = service.effect().ok_or(Error::NotFound)?.id;
        service.admit_effect(original)?;
        assert_eq!(service.shutdown(), Err(Error::Capacity));
        assert!(service.is_closed());
        assert!(!service.is_quiescent());
        let terminal = service.complete_effect(original, Completion::Lost(Error::Io))?;
        assert_eq!(terminal.effect.id, original);
        service.shutdown()?;
        assert!(!service.is_quiescent());
        written(&mut service)?;
        assert!(service.is_quiescent());
        Ok(())
    }
    #[test]
    fn original_close_peer_blocks_same_peer_recreation_until_actual_terminal() -> Result<(), Error>
    {
        let mut brand = Instance::new();
        let mut random = Entropy(29);
        let mut rank = TestRank(false);
        let mut service = Service::new(
            &mut brand,
            [1; 32],
            [2; 64],
            Config::default(),
            Limits::default(),
            0,
            &mut random,
        )?;
        written(&mut service)?;
        let group = service.main_group();
        let peer = [3; 32];
        service.discover(group, peer, 0, &mut random, &mut rank)?;
        written(&mut service)?;
        service.round(group, 30_000_000, &mut random, &mut rank)?;
        assert!(service.peer_closing(group, peer));
        assert_eq!(
            service.discover(group, peer, 30_000_000, &mut random, &mut rank),
            Err(Error::WouldBlock)
        );
        assert_eq!(
            service.peer_message(
                group,
                peer,
                PeerMessage::CheckLive,
                30_000_000,
                &mut random,
                &mut rank
            ),
            Err(Error::WouldBlock)
        );
        assert_eq!(
            service.peer_connected(group, peer, 30_000_000, &mut random, &mut rank),
            Err(Error::WouldBlock)
        );
        service.peer_lost(group, peer)?;
        assert!(
            service.groups[0]
                .peers
                .iter()
                .all(|state| state.peer != peer)
        );
        written(&mut service)?;
        assert!(!service.peer_closing(group, peer));
        service.discover(group, peer, 30_000_000, &mut random, &mut rank)?;
        assert_eq!(service.groups[0].peers.len(), 1);
        assert!(!service.groups[0].peers[0].online);
        Ok(())
    }
}
