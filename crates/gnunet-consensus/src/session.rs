//! Original session state and real generic SET task scheduling; no native IO.
use crate::{
    state::{self, Ballot, Change, Members, Pool},
    wire::{Block, Join, RoundContext},
    *,
};
use alloc::vec::Vec;
use core::mem::size_of;
use gnunet_wire::official::set::Abi;
mod effects;
mod gradecast;
mod preface;
mod results;
mod retirement;
mod round;
mod source;
use round::{Round, Schedule};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    Collect,
    WaitStart,
    Setup,
    Run,
    InitRep,
    Gradecast,
    Apply,
    Finish,
    Closing,
    Stopped,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TaskState {
    Planned,
    Starting,
    Active,
    Done,
    Failed,
    Cancel,
}
struct Task<'id> {
    id: TaskId<'id>,
    key: RoundContext,
    peer: usize,
    set: SetId<'id>,
    deadline: u64,
    state: TaskState,
    failure: Option<Error>,
    own_contested: bool,
    remote_marker: bool,
    own_marker_missing: bool,
    remote_context_contested: bool,
    staged: Members,
    inventory: Option<u64>,
}
struct Set<'id> {
    id: SetId<'id>,
    deadline: u64,
    members: Members,
    ready: bool,
    closed: bool,
    close_requested: bool,
    // Publishing PrepareSet transfers a real preparation/retirement obligation
    // to the host. Before publication this is only a local immutable snapshot.
    preparation_issued: bool,
    // A trusted host has physically retired this exact native source. Its
    // logical CloseSet debt remains until that original effect settles.
    retired: Option<Error>,
    kind: Round,
    repetition: i16,
    leader: i16,
}
struct Offer<'id> {
    id: OfferId<'id>,
    key: RoundContext,
    peer: usize,
    deadline: u64,
    claimed: bool,
    reject_requested: bool,
    retire: bool,
}
impl Offer<'_> {
    fn available(&self, now: u64) -> bool {
        !self.claimed && !self.reject_requested && !self.retire && now < self.deadline
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LeaderStage {
    Setup(Round),
    Run(Round),
    EchoGrade,
    ConfirmGrade,
    Done,
}
struct Leader<'id> {
    proposal: Members,
    echo: Members,
    echo_ballot: Ballot,
    confirm_ballot: Ballot,
    contested: bool,
    confidence: u8,
    confirm_worst: usize,
    stage: LeaderStage,
    source: Option<SetId<'id>>,
    cursor: usize,
}
/// One original session and its actual native/public obligations. No source is
/// replaced implicitly and no local SET write is treated as peer acceptance.
pub struct Session<'id> {
    brand: &'id Instance,
    session: u64,
    next: Option<u64>,
    limits: Limits,
    abi: Abi,
    peers: Vec<[u8; 32]>,
    local: usize,
    global: [u8; 64],
    schedule: Schedule,
    now: u64,
    pool: Pool,
    current: Members,
    local_values: Members,
    leaders: Vec<Leader<'id>>,
    round_ballot: Option<Ballot>,
    tasks: Vec<Task<'id>>,
    staged_bytes: usize,
    sets: Vec<Set<'id>>,
    offers: Vec<Offer<'id>>,
    inputs: Vec<SetId<'id>>,
    stage: Stage,
    kind: Round,
    rep: usize,
    setup_cursor: usize,
    work_leader: usize,
    work_cursor: usize,
    pending: Option<Effect<'id>>,
    listener: bool,
    concluded: bool,
    first_size: u64,
    blacklisted: Vec<u8>,
    early: u8,
    output_cursor: usize,
    outcome: Outcome,
    first_task_context: Option<TaskFailureContext>,
    failure_context: Option<FailureContext>,
    failed_tasks: u64,
    cancelling: bool,
    client_close_requested: bool,
    run_cursor: usize,
    run_blocked: bool,
    unfinished: usize,
    apply_worst: usize,
    close_cursor: usize,
    leader_scan: usize,
    task_scan: usize,
    gradecast_task_turn: bool,
}
impl<'id> Session<'id> {
    /// Canonicalize the actual participant set and create the original listener
    /// intent. Start/deadline remain their original absolute public values.
    pub fn new(
        brand: &'id Instance,
        local: [u8; 32],
        join: Join<'_>,
        limits: Limits,
        abi: Abi,
        now: u64,
    ) -> Result<Self, Error> {
        limits.validate()?;
        abi.validate()?;
        if now == u64::MAX || join.start >= join.deadline || now >= join.deadline {
            return Err(Error::Deadline);
        }
        let has_local = join.peers.contains(&local);
        let count = join
            .peers
            .len()
            .checked_add(usize::from(!has_local))
            .ok_or(Error::Overflow)?;
        if count > limits.peers {
            return Err(Error::Capacity);
        }
        let peer_bytes = size_of::<[u8; 32]>() + size_of::<u8>();
        let minimum = size_of::<Self>()
            .checked_add(count.checked_mul(peer_bytes).ok_or(Error::Overflow)?)
            .ok_or(Error::Overflow)?;
        if minimum > limits.retained_bytes {
            return Err(Error::Capacity);
        }
        let mut peers = Vec::new();
        peers
            .try_reserve_exact(count)
            .map_err(|_| Error::Capacity)?;
        peers.extend_from_slice(join.peers);
        if !has_local {
            peers.push(local);
        }
        peers.sort_unstable();
        if peers.windows(2).any(|p| p[0] == p[1]) {
            return Err(Error::Conflict);
        }
        let at = peers
            .binary_search(&local)
            .map_err(|_| Error::Authentication)?;
        let mut global = [0; 64];
        gnunet_crypto::hkdf_gnunet(
            b"gnunet-service-consensus/session_id",
            peers.as_flattened(),
            &[&join.session],
            &mut global,
        )?;
        let mut free = limits
            .retained_bytes
            .checked_sub(size_of::<Self>())
            .and_then(|n| state::charge(&peers).ok().and_then(|m| n.checked_sub(m)))
            .ok_or(Error::Capacity)?;
        let blacklisted = state::bytes(count, &mut free)?;
        let mut this = Self {
            brand,
            session: brand.allocate()?,
            next: Some(1),
            limits,
            abi,
            peers,
            local: at,
            global,
            schedule: Schedule::new(join.start, join.deadline, count)?,
            now,
            pool: Pool::new(),
            current: Members::new(),
            local_values: Members::new(),
            leaders: Vec::new(),
            round_ballot: None,
            tasks: Vec::new(),
            staged_bytes: 0,
            sets: Vec::new(),
            offers: Vec::new(),
            inputs: Vec::new(),
            stage: Stage::Collect,
            kind: Round::Union,
            rep: 0,
            setup_cursor: 0,
            work_leader: 0,
            work_cursor: 0,
            pending: None,
            listener: false,
            concluded: false,
            first_size: 0,
            blacklisted,
            early: 0,
            output_cursor: 0,
            outcome: Outcome::default(),
            first_task_context: None,
            failure_context: None,
            failed_tasks: 0,
            cancelling: false,
            client_close_requested: false,
            run_cursor: 0,
            run_blocked: false,
            unfinished: 0,
            apply_worst: usize::MAX,
            close_cursor: 0,
            leader_scan: 0,
            task_scan: 0,
            gradecast_task_turn: false,
        };
        this.publish(Action::Listen { global_id: global })?;
        Ok(this)
    }
    fn serial(&mut self) -> Result<u64, Error> {
        let n = self.next.ok_or(Error::Overflow)?;
        self.next = n.checked_add(1);
        Ok(n)
    }
    /// Canonical derived standard SET application hash.
    #[must_use]
    pub const fn global_id(&self) -> [u8; 64] {
        self.global
    }
    /// Sorted original participants, including the actual local identity.
    #[must_use]
    pub fn peers(&self) -> &[[u8; 32]] {
        &self.peers
    }
    /// Actual local index in that original list.
    #[must_use]
    pub const fn local_index(&self) -> usize {
        self.local
    }
    fn retained(&self) -> Result<usize, Error> {
        let mut n = size_of::<Self>()
            .checked_add(self.pool.charged()?)
            .and_then(|n| n.checked_add(self.current.charged().ok()?))
            .and_then(|n| n.checked_add(self.local_values.charged().ok()?))
            .ok_or(Error::Overflow)?;
        for charge in [
            state::charge(&self.peers)?,
            state::charge(&self.leaders)?,
            state::charge(&self.tasks)?,
            self.staged_bytes,
            state::charge(&self.sets)?,
            state::charge(&self.offers)?,
            state::charge(&self.inputs)?,
            self.blacklisted.capacity(),
        ] {
            n = n.checked_add(charge).ok_or(Error::Overflow)?;
        }
        for set in &self.sets {
            n = n
                .checked_add(set.members.charged()?)
                .ok_or(Error::Overflow)?;
        }
        for l in &self.leaders {
            for v in [
                l.proposal.charged()?,
                l.echo.charged()?,
                l.echo_ballot.charged()?,
                l.confirm_ballot.charged()?,
            ] {
                n = n.checked_add(v).ok_or(Error::Overflow)?;
            }
        }
        if let Some(b) = &self.round_ballot {
            n = n.checked_add(b.charged()?).ok_or(Error::Overflow)?;
        }
        if let Some(Effect {
            action: Action::ClientElement { data, .. },
            ..
        }) = &self.pending
        {
            n = n.checked_add(data.capacity()).ok_or(Error::Overflow)?;
        }
        Ok(n)
    }
    fn available(&self) -> Result<usize, Error> {
        self.limits
            .retained_bytes
            .checked_sub(self.retained()?)
            .ok_or(Error::Capacity)
    }
    fn set_at(&self, id: SetId<'id>) -> Result<usize, Error> {
        self.sets
            .iter()
            .position(|s| s.id == id)
            .ok_or(Error::StaleGeneration)
    }
    fn task_at(&self, id: TaskId<'id>) -> Result<usize, Error> {
        self.tasks
            .binary_search_by_key(&id.serial, |t| t.id.serial)
            .ok()
            .filter(|i| self.tasks[*i].id == id)
            .ok_or(Error::StaleGeneration)
    }
    fn offer_at(&self, id: OfferId<'id>) -> Result<usize, Error> {
        self.offers
            .iter()
            .position(|o| o.id == id)
            .ok_or(Error::StaleGeneration)
    }
    fn allowed(&self) -> Result<(), Error> {
        if self.cancelling
            || self.outcome.failure.is_some()
            || matches!(self.stage, Stage::Closing | Stage::Stopped)
        {
            Err(Error::Closed)
        } else {
            Ok(())
        }
    }
    /// Insert an original opaque application element before conclude. User labels
    /// are not implicitly a BLOCK namespace; the actual selected policy is explicit.
    pub fn insert(
        &mut self,
        payload_type: u16,
        data: &[u8],
        now: u64,
        validator: &mut impl Validator,
    ) -> Result<(), Error> {
        self.allowed()?;
        if self.concluded {
            return Err(Error::Closed);
        }
        if payload_type > wire::USER_TYPE_MAX || data.len() > self.limits.element_bytes {
            return Err(Error::TooLarge);
        }
        self.now = self.now.max(now);
        if self.now >= self.schedule.deadline() {
            return Err(Error::Deadline);
        }
        let mut free = self.available()?;
        let mut raw = state::bytes(data.len().checked_add(3).ok_or(Error::Overflow)?, &mut free)?;
        Block {
            payload_type,
            marker: 0,
            data,
        }
        .encode(&mut raw)?;
        let _fact = validator.check(payload_type, data, self.now)?;
        let mut free = self
            .available()?
            .checked_sub(raw.capacity())
            .ok_or(Error::Capacity)?;
        let id = self
            .pool
            .intern_owned(raw, self.abi, self.limits, &mut free)?;
        let mut free = self.available()?;
        let current = self.current.prepare_add(id, self.limits, &mut free)?;
        let local = self.local_values.prepare_add(id, self.limits, &mut free)?;
        self.current.commit_add(id, current);
        self.local_values.commit_add(id, local);
        Ok(())
    }

    /// Freeze insertion and schedule the original public start/deadline.
    pub fn conclude(&mut self, now: u64) -> Result<(), Error> {
        self.allowed()?;
        if self.concluded {
            return Err(Error::Conflict);
        }
        self.now = self.now.max(now);
        if self.now >= self.schedule.deadline() {
            return Err(Error::Deadline);
        }
        self.concluded = true;
        self.stage = Stage::WaitStart;
        Ok(())
    }
    fn key_eq(a: RoundContext, b: RoundContext) -> bool {
        a.kind == b.kind
            && a.peer1 == b.peer1
            && a.peer2 == b.peer2
            && a.repetition == b.repetition
            && a.leader == b.leader
    }
    fn arrange(a: usize, b: usize, n: usize) -> (i16, i16) {
        let (lo, hi) = (a.min(b), a.max(b));
        if (hi - lo) % n <= n / 2 {
            (lo as i16, hi as i16)
        } else {
            (hi as i16, lo as i16)
        }
    }
    /// Retain the actual incoming SET offer and its real peer/task context. Future
    /// phase offers are bounded; malformed roles never authorize a replacement MQ.
    pub fn offer(
        &mut self,
        peer: [u8; 32],
        context: RoundContext,
        now: u64,
    ) -> Result<OfferId<'id>, Error> {
        self.allowed()?;
        self.now = self.now.max(now);
        if self.now >= self.schedule.deadline() {
            return Err(Error::Deadline);
        }
        let p = self
            .peers
            .binary_search(&peer)
            .map_err(|_| Error::Authentication)?;
        let (p1, p2) = Self::arrange(self.local, p, self.peers.len());
        let kind = Round::from_wire(context.kind)?;
        if p == self.local
            || context.peer1 != p1
            || context.peer2 != p2
            || p2 as usize != self.local
        {
            return Err(Error::Authentication);
        }
        if kind.preface() {
            if context.repetition != -1 || context.leader != -1 {
                return Err(Error::Malformed);
            }
        } else if context.repetition < 0
            || context.repetition as usize >= self.schedule.repetitions()
            || context.leader < 0
            || context.leader as usize >= self.peers.len()
        {
            return Err(Error::Malformed);
        }
        let repetition = if kind.preface() {
            0
        } else {
            context.repetition as usize
        };
        let deadline = self.window_deadline(kind, repetition);
        if self.now >= deadline {
            return Err(Error::Deadline);
        }
        if self.sets.iter().any(|set| {
            set.retired.is_some()
                && set.kind == kind
                && set.repetition == context.repetition
                && set.leader == context.leader
        }) {
            return Err(Error::Closed);
        }
        if !matches!(self.stage, Stage::Collect | Stage::WaitStart) {
            let stale = if kind.preface() {
                self.kind > kind || matches!(self.stage, Stage::Finish)
            } else if context.repetition as usize != self.rep {
                (context.repetition as usize) < self.rep
            } else if matches!(self.stage, Stage::Apply | Stage::Finish) {
                true
            } else if let Some(leader) = self.leaders.get(context.leader as usize) {
                match leader.stage {
                    LeaderStage::Setup(round) | LeaderStage::Run(round) => kind < round,
                    LeaderStage::EchoGrade => kind < Round::Confirm,
                    LeaderStage::ConfirmGrade | LeaderStage::Done => true,
                }
            } else {
                false
            };
            if stale
                || self
                    .tasks
                    .iter()
                    .any(|t| Self::key_eq(t.key, context) && t.state != TaskState::Planned)
            {
                return Err(Error::StaleGeneration);
            }
        }
        let senders = (0..self.peers.len())
            .filter(|i| {
                *i != self.local
                    && Self::arrange(self.local, *i, self.peers.len()).1 as usize == self.local
            })
            .count()
            .max(1);
        let quota = self.limits.offers.div_ceil(senders);
        if context.kind == 2
            && context.leader as usize != self.local
            && context.leader as usize != p
        {
            return Err(Error::Authentication);
        }
        if self.offers.iter().filter(|o| o.peer == p).count() >= quota {
            return Err(Error::Capacity);
        }
        if self.offers.iter().any(|o| Self::key_eq(o.key, context)) {
            return Err(Error::Replay);
        }
        let mut free = self.available()?;
        state::reserve(&mut self.offers, 1, self.limits.offers, &mut free)?;
        let id = OfferId {
            brand: self.brand,
            session: self.session,
            serial: self.serial()?,
        };
        if let Some(t) = self
            .tasks
            .iter()
            .position(|t| t.state == TaskState::Planned && Self::key_eq(t.key, context))
        {
            self.run_cursor = self.run_cursor.min(t);
            self.run_blocked = false;
        }
        self.offers.push(Offer {
            id,
            key: context,
            peer: p,
            deadline,
            claimed: false,
            reject_requested: false,
            retire: false,
        });
        self.wake_gradecast();
        Ok(id)
    }
    /// Original immutable native SET population length.
    pub fn set_len(&self, id: SetId<'id>) -> Result<usize, Error> {
        self.allowed()?;
        let s = self.set_at(id)?;
        if self.sets[s].closed || self.sets[s].retired.is_some() {
            return Err(Error::Closed);
        }
        Ok(self.sets[s].members.ids.len())
    }
    /// Original immutable type25 body by index; no live view or coefficient copy.
    pub fn set_element(
        &self,
        id: SetId<'id>,
        index: usize,
    ) -> Result<Option<gnunet_wire::official::set::Element<'_>>, Error> {
        self.allowed()?;
        let s = self.set_at(id)?;
        if self.sets[s].closed || self.sets[s].retired.is_some() {
            return Err(Error::Closed);
        }
        Ok(self.sets[s]
            .members
            .ids
            .get(index)
            .map(|i| gnunet_wire::official::set::Element {
                element_type: 25,
                data: &self.pool.elements[*i as usize].raw,
            }))
    }
    fn window_deadline(&self, kind: Round, rep: usize) -> u64 {
        self.schedule.window(kind, rep)
    }
    fn phase_deadline(&self) -> u64 {
        self.window_deadline(self.kind, self.rep)
    }
    fn wake_gradecast(&mut self) {
        self.leader_scan = self.leaders.len();
        self.task_scan = self.tasks.len();
    }
    fn begin(&mut self, kind: Round) -> Result<(), Error> {
        self.kind = kind;
        self.stage = Stage::Setup;
        self.setup_cursor = 0;
        self.work_cursor = 0;
        self.inputs.clear();
        self.tasks.clear();
        self.staged_bytes = 0;
        self.run_cursor = 0;
        self.run_blocked = false;
        self.unfinished = 0;
        Ok(())
    }
    fn start_phase_set(
        &mut self,
        kind: Round,
        leader: usize,
        input: bool,
    ) -> Result<SetId<'id>, Error> {
        // Split-borrow source membership without cloning its payloads. It is
        // copied only once into the original immutable SET population snapshot.
        let mut free = self.available()?;
        let mut members = match kind {
            Round::Union | Round::Inventory | Round::Lead => self.current.copy(&mut free)?,
            Round::Echo => self.leaders[leader].proposal.copy(&mut free)?,
            Round::Confirm => self.leaders[leader].echo.copy(&mut free)?,
        };
        if kind == Round::Inventory
            && let Ok(sender) = u8::try_from(self.local)
        {
            let mut raw = [0; 12];
            raw[2] = 2;
            raw[3..11].copy_from_slice(&self.first_size.to_be_bytes());
            raw[11] = sender;
            let id = self.pool.intern(&raw, self.abi, self.limits, &mut free)?;
            members.add(id, self.limits, &mut free)?;
        }
        if kind == Round::Confirm && self.leaders[leader].contested {
            let id = self
                .pool
                .intern(&[0, 0, 1], self.abi, self.limits, &mut free)?;
            members.add(id, self.limits, &mut free)?;
        }
        state::reserve(&mut self.sets, 1, self.limits.sets, &mut free)?;
        if input {
            state::reserve(&mut self.inputs, 1, self.limits.sets, &mut free)?;
        }
        let id = SetId {
            brand: self.brand,
            session: self.session,
            serial: self.serial()?,
        };
        self.sets.push(Set {
            id,
            deadline: self.window_deadline(kind, self.rep),
            members,
            ready: false,
            closed: false,
            close_requested: false,
            preparation_issued: false,
            retired: None,
            kind,
            repetition: if kind.preface() { -1 } else { self.rep as i16 },
            leader: if kind.preface() { -1 } else { leader as i16 },
        });
        if input {
            self.inputs.push(id);
        }
        Ok(id)
    }
    fn plan_task(
        &mut self,
        kind: Round,
        leader: Option<usize>,
        other: usize,
        set: SetId<'id>,
    ) -> Result<(), Error> {
        let (p1, p2) = Self::arrange(self.local, other, self.peers.len());
        let key = RoundContext {
            kind: kind.wire(),
            peer1: p1,
            peer2: p2,
            repetition: if kind.preface() { -1 } else { self.rep as i16 },
            leader: leader.map_or(-1, |n| n as i16),
            contested: u16::from(
                kind == Round::Confirm && self.leaders[leader.ok_or(Error::Conflict)?].contested,
            ),
        };
        let original = &self.sets[self.set_at(set)?];
        if original.kind != kind
            || original.repetition != key.repetition
            || original.leader != key.leader
        {
            return Err(Error::Conflict);
        }
        let deadline = original.deadline;
        let mut free = self.available()?;
        state::reserve(&mut self.tasks, 1, self.limits.tasks, &mut free)?;
        let id = TaskId {
            brand: self.brand,
            session: self.session,
            serial: self.serial()?,
        };
        if other != self.local {
            self.unfinished = self.unfinished.checked_add(1).ok_or(Error::Overflow)?;
        }
        self.tasks.push(Task {
            id,
            key,
            peer: other,
            set,
            deadline,
            state: if other == self.local {
                TaskState::Done
            } else {
                TaskState::Planned
            },
            failure: None,
            own_contested: key.contested != 0,
            remote_marker: false,
            own_marker_missing: false,
            remote_context_contested: false,
            staged: Members::new(),
            inventory: None,
        });
        if other != self.local
            && let Some(cause) = self.sets[self.set_at(set)?].retired
        {
            self.task_failed(self.tasks.len() - 1, cause, false)?;
        }
        Ok(())
    }
    /// Finite CPU/scheduling work, at most64 explicit units per call. True means
    /// genuine state/cursor work, never a physical SET write or peer response.
    pub fn step(&mut self, now: u64, budget: usize) -> Result<bool, Error> {
        if budget == 0 {
            return Err(Error::InvalidInput);
        }
        self.now = self.now.max(now);
        // Other real callbacks may already have observed this time. Revisit
        // actionable expired work, not merely a first crossing of self.now.
        // Each exact task leaves Planned/Active once cancellation is issued.
        if self.stage == Stage::Gradecast
            && (self.tasks.iter().any(|task| {
                matches!(task.state, TaskState::Planned | TaskState::Active)
                    && self.now >= task.deadline
            }) || self.leaders.iter().any(|leader| {
                if let LeaderStage::Setup(kind) = leader.stage {
                    self.now >= self.window_deadline(kind, self.rep)
                } else {
                    false
                }
            }))
        {
            self.wake_gradecast();
        }
        if self.now >= self.schedule.deadline()
            && !matches!(self.stage, Stage::Closing | Stage::Stopped)
        {
            self.cancel(Error::Deadline)?;
        }
        if self
            .pending
            .as_ref()
            .is_some_and(|e| e.deadline.is_some_and(|end| self.now >= end))
            && !self.cancelling
            && self.pending.as_ref().is_none_or(|e| {
                !matches!(
                    e.action,
                    Action::PrepareSet { .. } | Action::Reconcile { .. }
                )
            })
        {
            self.cancel(Error::Deadline)?;
        }
        if self.pending.is_some() {
            return Ok(false);
        }
        let mut changed = false;
        for _ in 0..budget.min(64) {
            if !self.cancelling
                && let Some(offer) = self.offers.iter().find(|offer| {
                    !offer.claimed
                        && !offer.reject_requested
                        && (offer.retire || self.now >= offer.deadline)
                })
            {
                let offer = offer.id;
                self.publish(Action::RejectOffer { offer })?;
                let at = self.offer_at(offer)?;
                self.offers[at].reject_requested = true;
                return Ok(true);
            }
            let result = match self.stage {
                Stage::Collect => Ok(false),
                Stage::WaitStart => {
                    if self.now < self.schedule.start() || !self.listener {
                        Ok(false)
                    } else {
                        self.begin(Round::Union).map(|()| true)
                    }
                }
                Stage::Setup => self.setup_step(),
                Stage::Run => self.run_step(),
                Stage::InitRep => self.init_rep_step(),
                Stage::Gradecast => self.gradecast_step(),
                Stage::Apply => self.apply_step(),
                Stage::Finish => self.finish_step(),
                Stage::Closing => self.closing_step(),
                Stage::Stopped => Ok(false),
            };
            match result {
                Ok(false) => break,
                Ok(true) => changed = true,
                Err(Error::WouldBlock | Error::NotReady) => break,
                Err(cause) => {
                    self.cancel(cause)?;
                    return Err(cause);
                }
            }
            if self.pending.is_some() {
                break;
            }
        }
        Ok(changed)
    }
    /// Original next start/phase/session deadline; no retry creates a new bound.
    #[must_use]
    pub fn next_deadline(&self) -> Option<u64> {
        let phase = match self.stage {
            Stage::Stopped | Stage::Closing => None,
            Stage::Collect => Some(self.schedule.deadline()),
            Stage::WaitStart if self.now < self.schedule.start() => Some(self.schedule.start()),
            Stage::Gradecast => {
                let mut next = self.schedule.deadline();
                for task in &self.tasks {
                    if matches!(
                        task.state,
                        TaskState::Planned | TaskState::Starting | TaskState::Active
                    ) {
                        let end = task.deadline;
                        if end > self.now {
                            next = next.min(end);
                        }
                    }
                }
                for leader in &self.leaders {
                    if let LeaderStage::Setup(kind) | LeaderStage::Run(kind) = leader.stage {
                        let end = self.window_deadline(kind, self.rep);
                        if end > self.now {
                            next = next.min(end);
                        }
                    }
                }
                Some(next)
            }
            Stage::Setup => Some(self.phase_deadline().min(self.schedule.deadline())),
            Stage::Run if self.phase_deadline() > self.now => {
                Some(self.phase_deadline().min(self.schedule.deadline()))
            }
            Stage::Run if self.schedule.deadline() > self.now => Some(self.schedule.deadline()),
            Stage::Run => None,
            _ => Some(self.schedule.deadline()),
        };
        // Future requests are accepted while the caller is still collecting
        // inputs. A delayed CONCLUDE cannot extend their original windows.
        // A pending effect already owns the slot required to publish a
        // rejection, so its actual receipt must wake this owner first.
        if self.pending.is_some() {
            return phase;
        }
        phase.map(|original| {
            self.offers
                .iter()
                .filter(|offer| !offer.claimed && !offer.reject_requested)
                .map(|offer| offer.deadline)
                .fold(original, u64::min)
        })
    }
    /// Whether the original operation may still receive ordinary native results.
    /// The host also validates its actual source/epoch and original native bound.
    #[must_use]
    pub fn task_live(&self, id: TaskId<'id>) -> bool {
        !self.cancelling
            && self.task_at(id).is_ok_and(|i| {
                matches!(self.tasks[i].state, TaskState::Starting | TaskState::Active)
            })
    }
    /// Whether the original immutable SET remains an active normal source.
    #[must_use]
    pub fn set_live(&self, id: SetId<'id>) -> bool {
        !self.cancelling
            && self.set_at(id).is_ok_and(|i| {
                !self.sets[i].closed
                    && !self.sets[i].close_requested
                    && self.sets[i].retired.is_none()
            })
    }
    /// Whether the original unclaimed offer still permits acceptance, never an
    /// authenticated-peer assertion from raw bytes alone.
    #[must_use]
    pub fn offer_live(&self, id: OfferId<'id>) -> bool {
        !self.cancelling
            && self
                .offer_at(id)
                .is_ok_and(|i| self.offers[i].available(self.now))
    }
    /// Whether original listener IO remains useful. A qualified final result
    /// stops new offers before the actual listener retirement action is settled.
    #[must_use]
    pub fn listener_live(&self) -> bool {
        self.listener
            && !self.cancelling
            && !matches!(self.stage, Stage::Finish | Stage::Closing | Stage::Stopped)
    }
    /// Actual independent outcome and client terminal write fact.
    #[must_use]
    pub const fn outcome(&self) -> Outcome {
        self.outcome
    }
    /// First real task failure and count; this is a bounded summary, not an
    /// exhaustive audit log. Native callers retain each original source cause.
    #[must_use]
    pub const fn task_failures(&self) -> (Option<Error>, u64) {
        let first = match self.first_task_context {
            Some(context) => Some(context.cause),
            None => None,
        };
        (first, self.failed_tasks)
    }
    fn failure_stage(&self) -> FailureStage {
        match self.stage {
            Stage::Collect => FailureStage::Collect,
            Stage::WaitStart => FailureStage::WaitStart,
            Stage::Setup => FailureStage::Setup,
            Stage::Run => FailureStage::Run,
            Stage::InitRep => FailureStage::InitRep,
            Stage::Gradecast => FailureStage::Gradecast,
            Stage::Apply => FailureStage::Apply,
            Stage::Finish => FailureStage::Finish,
            Stage::Closing => FailureStage::Closing,
            Stage::Stopped => FailureStage::Stopped,
        }
    }
    fn snapshot_failure(&self, cause: Error) -> FailureContext {
        let mut grades = LeaderGrades::default();
        for leader in &self.leaders {
            match (leader.stage, leader.confidence) {
                (LeaderStage::Done, 0) => grades.zero += 1,
                (LeaderStage::Done, 1) => grades.one += 1,
                (LeaderStage::Done, 2) => grades.two += 1,
                _ => grades.pending += 1,
            }
        }
        let mut tasks = TasksByKind::default();
        for task in self.tasks.iter().filter(|task| task.peer != self.local) {
            let counts = match task.key.kind {
                0 => &mut tasks.initial,
                1 => &mut tasks.size,
                2 => &mut tasks.lead,
                3 => &mut tasks.echo,
                5 => &mut tasks.confirm,
                _ => continue,
            };
            match task.state {
                TaskState::Done => counts.done += 1,
                TaskState::Failed => counts.failed += 1,
                _ => counts.unfinished += 1,
            }
        }
        FailureContext {
            cause,
            stage: self.failure_stage(),
            kind: matches!(self.stage, Stage::Setup | Stage::Run).then_some(self.kind.wire()),
            repetition: matches!(
                self.stage,
                Stage::InitRep | Stage::Gradecast | Stage::Apply | Stage::Finish
            )
            .then_some(self.rep),
            participants: self.peers.len(),
            strong: self.strong(),
            positive_leaders: self.round_ballot.as_ref().map_or(0, Ballot::count),
            grades,
            tasks,
            first_task: self.first_task_context,
            observed_canonical: self.now,
        }
    }
    /// Original first business-failure metadata, stable across source retirement
    /// and later cleanup. None after successful525 followed only by teardown.
    /// This readonly copy supplies no source/task authority or new clock sample.
    #[must_use]
    pub const fn failure_context(&self) -> Option<FailureContext> {
        self.failure_context
    }
    /// Quiescent only after every original native source/operation/effect retired.
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        self.stage == Stage::Stopped && self.pending.is_none() && !self.listener
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
