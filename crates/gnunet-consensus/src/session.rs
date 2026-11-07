//! Original session state and real generic SET task scheduling; no native IO.
use crate::{
    state::{self, Ballot, Change, Members, Pool},
    wire::{Block, Join, RoundContext},
    *,
};
use alloc::vec::Vec;
use core::mem::size_of;
use gnunet_wire::official::set::Abi;
mod source;
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
    state: TaskState,
    failure: Option<Error>,
    own_contested: bool,
    remote_marker: bool,
    own_marker_missing: bool,
    remote_context_contested: bool,
}
struct Set<'id> {
    id: SetId<'id>,
    deadline: u64,
    members: Members,
    ready: bool,
    closed: bool,
    close_requested: bool,
    // A trusted host has physically retired this exact native source. Its
    // logical CloseSet debt remains until that original effect settles.
    retired: Option<Error>,
    kind: u16,
    repetition: i16,
    leader: i16,
}
struct Offer<'id> {
    id: OfferId<'id>,
    key: RoundContext,
    peer: usize,
    claimed: bool,
    reject_requested: bool,
    retire: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LeaderStage {
    Setup(u16),
    Run(u16),
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
    start: u64,
    deadline: u64,
    now: u64,
    pool: Pool,
    current: Members,
    local_values: Members,
    leaders: Vec<Leader<'id>>,
    round_ballot: Option<Ballot>,
    tasks: Vec<Task<'id>>,
    sets: Vec<Set<'id>>,
    offers: Vec<Offer<'id>>,
    inputs: Vec<SetId<'id>>,
    stage: Stage,
    kind: u16,
    rep: usize,
    repetitions: usize,
    setup_cursor: usize,
    work_leader: usize,
    work_cursor: usize,
    pending: Option<Effect<'id>>,
    listener: bool,
    concluded: bool,
    lower_bound: u8,
    sizes: Vec<u64>,
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
        let minimum = size_of::<Self>()
            .checked_add(count.checked_mul(41).ok_or(Error::Overflow)?)
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
        let sizes_bytes = count.checked_mul(size_of::<u64>()).ok_or(Error::Overflow)?;
        let mut sizes = Vec::new();
        sizes
            .try_reserve_exact(count)
            .map_err(|_| Error::Capacity)?;
        let actual = state::charge(&sizes)?;
        if actual > free || actual < sizes_bytes {
            return Err(Error::Capacity);
        }
        free -= actual;
        sizes.resize(count, 0);
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
            start: join.start,
            deadline: join.deadline,
            now,
            pool: Pool::new(),
            current: Members::new(),
            local_values: Members::new(),
            leaders: Vec::new(),
            round_ballot: None,
            tasks: Vec::new(),
            sets: Vec::new(),
            offers: Vec::new(),
            inputs: Vec::new(),
            stage: Stage::Collect,
            kind: 0,
            rep: 0,
            repetitions: count / 3 + 1,
            setup_cursor: 0,
            work_leader: 0,
            work_cursor: 0,
            pending: None,
            listener: false,
            concluded: false,
            lower_bound: 0,
            sizes,
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
    fn publish(&mut self, action: Action<'id>) -> Result<(), Error> {
        if self.pending.is_some() {
            return Err(Error::WouldBlock);
        }
        let source = match &action {
            Action::PrepareSet { set } | Action::Reconcile { set, .. } => Some(*set),
            _ => None,
        };
        if let Some(source) = source {
            let source = &self.sets[self.set_at(source)?];
            if source.closed || source.retired.is_some() {
                return Err(Error::Closed);
            }
        }
        let deadline = match &action {
            Action::PrepareSet { set } => Some(self.sets[self.set_at(*set)?].deadline),
            Action::Reconcile { task, .. } => {
                Some(self.task_deadline(self.tasks[self.task_at(*task)?].key))
            }
            a if a.cleanup() => None,
            _ => Some(self.deadline),
        };
        let serial = self.serial()?;
        self.pending = Some(Effect {
            id: EffectId {
                brand: self.brand,
                session: self.session,
                serial,
            },
            action,
            admitted: false,
            deadline,
        });
        Ok(())
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
            state::charge(&self.sets)?,
            state::charge(&self.offers)?,
            state::charge(&self.inputs)?,
            state::charge(&self.sizes)?,
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
    fn payload(
        &mut self,
        raw: &[u8],
        now: u64,
        validator: &mut impl Validator,
    ) -> Result<u32, Error> {
        if raw.len()
            > self
                .limits
                .element_bytes
                .checked_add(3)
                .ok_or(Error::Overflow)?
        {
            return Err(Error::TooLarge);
        }
        let block = Block::decode(raw)?;
        if block.marker == 0 {
            if block.payload_type > wire::USER_TYPE_MAX {
                return Err(Error::InvalidInput);
            }
            // Opaque is a real public policy outcome, not authenticated success.
            let _fact = validator.check(block.payload_type, block.data, self.now.max(now))?;
        } else if block.marker == 2 {
            block.size_marker()?;
        }
        let mut free = self.available()?;
        self.pool.intern(raw, self.abi, self.limits, &mut free)
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
        if self.now >= self.deadline {
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
        if self.now >= self.deadline {
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
        if self.now >= self.deadline {
            return Err(Error::Deadline);
        }
        let p = self
            .peers
            .binary_search(&peer)
            .map_err(|_| Error::Authentication)?;
        let (p1, p2) = Self::arrange(self.local, p, self.peers.len());
        if p == self.local
            || context.peer1 != p1
            || context.peer2 != p2
            || p2 as usize != self.local
            || !matches!(context.kind, 0 | 1 | 2 | 3 | 5)
        {
            return Err(Error::Authentication);
        }
        if context.kind <= 1 {
            if context.repetition != -1 || context.leader != -1 {
                return Err(Error::Malformed);
            }
        } else if context.repetition < 0
            || context.repetition as usize >= self.repetitions
            || context.leader < 0
            || context.leader as usize >= self.peers.len()
        {
            return Err(Error::Malformed);
        }
        if self.sets.iter().any(|set| {
            set.retired.is_some()
                && set.kind == context.kind
                && set.repetition == context.repetition
                && set.leader == context.leader
        }) {
            return Err(Error::Closed);
        }
        if !matches!(self.stage, Stage::Collect | Stage::WaitStart) {
            let stale = if context.kind <= 1 {
                self.kind > context.kind || matches!(self.stage, Stage::Finish)
            } else if context.repetition as usize != self.rep {
                (context.repetition as usize) < self.rep
            } else if matches!(self.stage, Stage::Apply | Stage::Finish) {
                true
            } else if let Some(leader) = self.leaders.get(context.leader as usize) {
                let floor = match leader.stage {
                    LeaderStage::Setup(kind) | LeaderStage::Run(kind) => Self::grade_rank(kind),
                    LeaderStage::EchoGrade => 2,
                    LeaderStage::ConfirmGrade | LeaderStage::Done => 3,
                };
                Self::grade_rank(context.kind) < floor
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
    fn grade_rank(kind: u16) -> usize {
        match kind {
            2 => 0,
            3 => 1,
            _ => 2,
        }
    }
    fn window_deadline(&self, kind: u16, rep: usize) -> u64 {
        let round = match kind {
            0 => 0,
            1 => 1,
            2 => 2 + 3 * rep,
            3 => 3 + 3 * rep,
            5 => 4 + 3 * rep,
            _ => 0,
        };
        let periods = 3 + 3 * self.repetitions;
        let width = u128::from(self.deadline - self.start);
        self.start
            .saturating_add(((width * (round + 1) as u128) / periods as u128) as u64)
            .min(self.deadline)
    }
    fn phase_deadline(&self) -> u64 {
        self.window_deadline(self.kind, self.rep)
    }
    fn task_deadline(&self, key: RoundContext) -> u64 {
        self.window_deadline(key.kind, key.repetition.max(0) as usize)
    }
    fn wake_gradecast(&mut self) {
        self.leader_scan = self.leaders.len();
        self.task_scan = self.tasks.len();
    }
    fn begin(&mut self, kind: u16) -> Result<(), Error> {
        self.kind = kind;
        self.stage = Stage::Setup;
        self.setup_cursor = 0;
        self.work_cursor = 0;
        self.inputs.clear();
        self.tasks.clear();
        self.run_cursor = 0;
        self.run_blocked = false;
        self.unfinished = 0;
        Ok(())
    }
    fn start_phase_set(
        &mut self,
        kind: u16,
        leader: usize,
        input: bool,
    ) -> Result<SetId<'id>, Error> {
        // Split-borrow source membership without cloning its payloads. It is
        // copied only once into the original immutable SET population snapshot.
        let mut free = self.available()?;
        let mut members = match kind {
            0..=2 => self.current.copy(&mut free)?,
            3 => self.leaders[leader].proposal.copy(&mut free)?,
            5 => self.leaders[leader].echo.copy(&mut free)?,
            _ => return Err(Error::Conflict),
        };
        if kind == 1 {
            let mut raw = [0; 12];
            raw[2] = 2;
            raw[3..11].copy_from_slice(&self.first_size.to_be_bytes());
            raw[11] = self.local as u8;
            let id = self.pool.intern(&raw, self.abi, self.limits, &mut free)?;
            members.add(id, self.limits, &mut free)?;
        }
        if kind == 5 && self.leaders[leader].contested {
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
            retired: None,
            kind,
            repetition: if kind <= 1 { -1 } else { self.rep as i16 },
            leader: if kind <= 1 { -1 } else { leader as i16 },
        });
        if input {
            self.inputs.push(id);
        }
        Ok(id)
    }
    fn total_tasks(&self) -> Result<usize, Error> {
        if self.kind <= 1 {
            Ok(self.peers.len())
        } else {
            Err(Error::Conflict)
        }
    }
    fn plan_task(
        &mut self,
        kind: u16,
        leader: Option<usize>,
        other: usize,
        set: SetId<'id>,
    ) -> Result<(), Error> {
        let (p1, p2) = Self::arrange(self.local, other, self.peers.len());
        let key = RoundContext {
            kind,
            peer1: p1,
            peer2: p2,
            repetition: if kind <= 1 { -1 } else { self.rep as i16 },
            leader: leader.map_or(-1, |n| n as i16),
            contested: u16::from(
                kind == 5 && self.leaders[leader.ok_or(Error::Conflict)?].contested,
            ),
        };
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
        });
        if other != self.local
            && let Some(cause) = self.sets[self.set_at(set)?].retired
        {
            self.task_failed(self.tasks.len() - 1, cause, false)?;
        }
        Ok(())
    }
    fn setup_step(&mut self) -> Result<bool, Error> {
        let retired = self.inputs.iter().any(|id| {
            self.set_at(*id)
                .is_ok_and(|at| self.sets[at].retired.is_some())
        });
        if self.now >= self.phase_deadline() && !retired {
            return Err(Error::Deadline);
        }

        if self.total_tasks()? > self.limits.tasks {
            return Err(Error::Capacity);
        }
        let sets = if matches!(self.kind, 3 | 5) {
            self.peers.len()
        } else {
            1
        };
        if self.inputs.len() < sets {
            self.start_phase_set(self.kind, self.inputs.len(), true)?;
            return Ok(true);
        }
        for id in &self.inputs {
            let at = self.set_at(*id)?;
            if !self.sets[at].ready && self.sets[at].retired.is_none() {
                let set = *id;
                self.publish(Action::PrepareSet { set })?;
                return Ok(true);
            }
        }
        if self.setup_cursor < self.total_tasks()? {
            let set = *self.inputs.first().ok_or(Error::NotReady)?;
            self.plan_task(self.kind, None, self.setup_cursor, set)?;
            self.setup_cursor += 1;
            return Ok(true);
        }
        self.stage = Stage::Run;
        Ok(true)
    }
    fn task_failed(&mut self, index: usize, cause: Error, cancel: bool) -> Result<(), Error> {
        if self.tasks[index].failure.is_none() {
            if self.first_task_context.is_none() {
                let task = &self.tasks[index];
                let state = match task.state {
                    TaskState::Planned => FailureTaskState::Planned,
                    TaskState::Starting => FailureTaskState::Starting,
                    TaskState::Active => FailureTaskState::Active,
                    TaskState::Done => FailureTaskState::Done,
                    TaskState::Failed => FailureTaskState::Failed,
                    TaskState::Cancel => FailureTaskState::Cancel,
                };
                self.first_task_context = Some(TaskFailureContext {
                    cause,
                    stage: self.failure_stage(),
                    task_serial: task.id.serial,
                    set_serial: task.set.serial,
                    round: task.key,
                    peer_index: task.peer,
                    state,
                    observed_canonical: self.now,
                });
            }
            self.tasks[index].failure = Some(cause);
            self.failed_tasks = self.failed_tasks.checked_add(1).ok_or(Error::Overflow)?;
        }
        if !cancel && !matches!(self.tasks[index].state, TaskState::Done | TaskState::Failed) {
            self.unfinished = self.unfinished.checked_sub(1).ok_or(Error::Conflict)?;
        }
        self.run_blocked = false;
        self.run_cursor = self.run_cursor.min(index);
        self.tasks[index].state = if cancel {
            TaskState::Cancel
        } else {
            TaskState::Failed
        };
        self.wake_gradecast();
        Ok(())
    }
    fn record_result(&mut self, t: usize, change: Change, id: u32) -> Result<(), Error> {
        let task = &self.tasks[t];
        let kind = task.key.kind;
        let leader = task.key.leader;
        let peer = task.peer;
        let base = self.set_at(task.set)?;
        if self.sets[base].members.contains(id) != (change == Change::Remove) {
            return Err(Error::Authentication);
        }
        if self.blacklisted[peer] != 0 {
            return Ok(());
        }
        let mut free = self.available()?;
        match kind {
            0 | 1 => {
                if change == Change::Add {
                    self.current.add(id, self.limits, &mut free)?;
                }
            }
            2 => {
                let l = usize::try_from(leader).map_err(|_| Error::Malformed)?;
                if l != self.local {
                    match change {
                        Change::Add => self.leaders[l].proposal.add(id, self.limits, &mut free)?,
                        Change::Remove => self.leaders[l].proposal.remove(id),
                        Change::Stay => {}
                    }
                }
            }
            3 => {
                let l = leader as usize;
                self.leaders[l]
                    .echo_ballot
                    .record(id, change, peer, self.limits, &mut free)?;
            }
            5 => {
                let l = leader as usize;
                self.leaders[l]
                    .confirm_ballot
                    .record(id, change, peer, self.limits, &mut free)?;
            }
            _ => return Err(Error::Malformed),
        }
        Ok(())
    }
    /// Apply only one actual matching original SET operation result. A selected
    /// application policy may accept opaque data without calling it authenticated.
    pub fn set_result(
        &mut self,
        id: TaskId<'id>,
        peer: [u8; 32],
        event: SetEvent<'_>,
        now: u64,
        validator: &mut impl Validator,
    ) -> Result<(), Error> {
        self.now = self.now.max(now);
        let t = self.task_at(id)?;
        if self.now >= self.deadline && !self.cancelling {
            self.cancel(Error::Deadline)?;
        }

        if self.peers[self.tasks[t].peer] != peer {
            return Err(Error::Authentication);
        }
        if !self.cancelling
            && self.tasks[t].state == TaskState::Active
            && self.now >= self.task_deadline(self.tasks[t].key)
        {
            self.task_failed(t, Error::Deadline, true)?;
        }
        if self.cancelling || self.tasks[t].state == TaskState::Cancel {
            if matches!(event, SetEvent::Done { .. } | SetEvent::Failure(_))
                && matches!(self.tasks[t].state, TaskState::Active | TaskState::Cancel)
            {
                let cause = self.tasks[t]
                    .failure
                    .unwrap_or_else(|| self.outcome.failure.map_or(Error::Cancelled, |f| f.cause));
                self.task_failed(t, cause, false)?;
                return Ok(());
            }
            return Err(Error::Closed);
        }
        let result = self.apply_result(id, peer, event, now, validator);
        if let Err(cause) = result
            && self.tasks[t].state == TaskState::Active
            && !matches!(cause, Error::WouldBlock | Error::NotReady)
        {
            self.task_failed(t, cause, true)?;
        }
        result
    }
    fn apply_result(
        &mut self,
        id: TaskId<'id>,
        peer: [u8; 32],
        event: SetEvent<'_>,
        now: u64,
        validator: &mut impl Validator,
    ) -> Result<(), Error> {
        self.allowed()?;
        self.now = self.now.max(now);
        let t = self.task_at(id)?;
        if self.tasks[t].state != TaskState::Active || self.peers[self.tasks[t].peer] != peer {
            return Err(Error::StaleGeneration);
        }
        match event {
            SetEvent::Failure(cause) => self.task_failed(t, cause, false),
            SetEvent::Done { current_size } => {
                let key = self.tasks[t].key;
                let p = self.tasks[t].peer;
                if key.kind == 0 {
                    self.first_size = self.first_size.max(current_size);
                }
                if key.kind == 3 {
                    self.leaders[key.leader as usize].echo_ballot.commit(p)?;
                }
                if key.kind == 5 {
                    let remote = self.tasks[t].remote_marker
                        || self.tasks[t].remote_context_contested
                        || (self.tasks[t].own_contested && !self.tasks[t].own_marker_missing);
                    if remote {
                        self.leaders[key.leader as usize]
                            .confirm_ballot
                            .contest(p)?;
                    }
                    self.leaders[key.leader as usize].confirm_ballot.commit(p)?;
                }
                self.run_blocked = false;
                self.tasks[t].state = TaskState::Done;
                self.unfinished = self.unfinished.checked_sub(1).ok_or(Error::Conflict)?;
                self.wake_gradecast();
                Ok(())
            }
            SetEvent::AddLocal { element_type, data }
            | SetEvent::AddRemote { element_type, data } => {
                if element_type != 25 {
                    return Err(Error::Malformed);
                }
                let block = Block::decode(data)?;
                if block.marker != 0 {
                    if block.marker == 1 && self.tasks[t].key.kind == 5 {
                        if matches!(event, SetEvent::AddLocal { .. }) {
                            self.tasks[t].remote_marker = true;
                        } else if self.tasks[t].own_contested && data == [0, 0, 1] {
                            self.tasks[t].own_marker_missing = true;
                        } else {
                            return Err(Error::Authentication);
                        }
                    }
                    if block.marker == 2 {
                        let (size, sender) = block.size_marker()?;
                        let p = self.tasks[t].peer;
                        if usize::from(sender) == p {
                            self.sizes[p] = size;
                        }
                    }
                    return Ok(());
                }
                let element = self.payload(data, now, validator)?;
                self.record_result(
                    t,
                    if matches!(event, SetEvent::AddLocal { .. }) {
                        Change::Add
                    } else {
                        Change::Remove
                    },
                    element,
                )
            }
        }
    }
    fn run_step(&mut self) -> Result<bool, Error> {
        if self.run_blocked {
            if self.now < self.phase_deadline() {
                return Ok(false);
            }
            self.run_blocked = false;
            self.run_cursor = 0;
        }

        if self.run_cursor < self.tasks.len() {
            let i = self.run_cursor;
            self.run_cursor += 1;
            let task = &self.tasks[i];
            if task.state == TaskState::Cancel {
                let task = task.id;
                self.publish(Action::CancelTask { task })?;
                return Ok(true);
            }
            if task.state == TaskState::Active && self.now >= self.phase_deadline() {
                self.task_failed(i, Error::Deadline, true)?;
                return Ok(true);
            }
            if task.state != TaskState::Planned {
                return Ok(true);
            }
            if self.blacklisted[task.peer] != 0 {
                self.task_failed(i, Error::Authentication, false)?;
                return Ok(true);
            }
            if self.now >= self.phase_deadline() {
                self.task_failed(i, Error::Deadline, false)?;
                return Ok(true);
            }
            let incoming = if task.key.peer2 as usize == self.local {
                self.offers
                    .iter()
                    .find(|o| !o.claimed && o.peer == task.peer && Self::key_eq(o.key, task.key))
                    .map(|o| o.id)
            } else {
                None
            };
            if task.key.peer2 as usize == self.local && incoming.is_none() {
                return Ok(true);
            }
            let action = Action::Reconcile {
                task: task.id,
                set: task.set,
                peer: self.peers[task.peer],
                context: task.key,
                incoming,
                lower_bound: self.lower_bound,
            };
            self.publish(action)?;
            self.tasks[i].state = TaskState::Starting;
            if let Some(offer) = incoming {
                let at = self.offer_at(offer)?;
                self.offers[at].claimed = true;
                self.tasks[i].remote_context_contested = self.offers[at].key.contested != 0;
            }
            return Ok(true);
        }
        if self.unfinished != 0 {
            self.run_blocked = true;
            return Ok(false);
        }
        // Every original task is semantically or physically terminal before its
        // original input source is retired. Close debts are actual, not counted away.
        if let Some(s) = self.sets.iter().find(|s| !s.closed && !s.close_requested) {
            let set = s.id;
            self.publish(Action::CloseSet { set })?;
            let at = self.set_at(set)?;
            self.sets[at].close_requested = true;
            return Ok(true);
        }
        if self.sets.iter().any(|s| !s.closed) {
            return Ok(false);
        }
        self.sets.clear();
        self.inputs.clear();
        // Every original preface source was physically retired above. Its
        // terminal native tasks no longer consume the next repetition's pool.
        self.tasks.clear();
        match self.kind {
            0 => {
                self.first_size = self.current.ids.len() as u64;
                self.begin(1)?;
            }
            1 => {
                let mut sorted = Vec::new();
                let mut free = self.available()?;
                state::reserve(&mut sorted, self.sizes.len(), self.limits.peers, &mut free)?;
                sorted.extend_from_slice(&self.sizes);
                sorted.sort_unstable();
                let at = (self.peers.len() / 3 + 1).min(sorted.len() - 1);
                self.lower_bound = sorted[at].min(u64::from(u8::MAX)) as u8;
                self.kind = 2;
                self.rep = 0;
                self.work_leader = 0;
                self.stage = Stage::InitRep;
                self.work_cursor = 0;
            }
            _ => return Err(Error::Conflict),
        }
        Ok(true)
    }
    fn leader_setup(&mut self, l: usize, kind: u16) -> Result<bool, Error> {
        let retired = self.leaders[l]
            .source
            .and_then(|id| self.set_at(id).ok())
            .is_some_and(|at| self.sets[at].retired.is_some());
        if self.now >= self.window_deadline(kind, self.rep) && !retired {
            return Err(Error::Deadline);
        }
        let Some(source) = self.leaders[l].source else {
            let source = self.start_phase_set(kind, l, false)?;
            self.leaders[l].source = Some(source);
            return Ok(true);
        };
        let at = self.set_at(source)?;
        if !self.sets[at].ready && self.sets[at].retired.is_none() {
            self.publish(Action::PrepareSet { set: source })?;
            return Ok(true);
        }
        let total = if kind == 2 && l != self.local {
            1
        } else {
            self.peers.len()
        };
        let cursor = self.leaders[l].cursor;
        if cursor < total {
            let other = if kind == 2 && l != self.local {
                l
            } else {
                cursor
            };
            self.plan_task(kind, Some(l), other, source)?;
            self.leaders[l].cursor += 1;
            return Ok(true);
        }
        self.leaders[l].stage = LeaderStage::Run(kind);
        self.leaders[l].cursor = 0;
        Ok(true)
    }
    fn leader_run(&mut self, l: usize, kind: u16) -> Result<bool, Error> {
        let source = self.leaders[l].source.ok_or(Error::Conflict)?;
        if self.tasks.iter().any(|task| {
            task.set == source && !matches!(task.state, TaskState::Done | TaskState::Failed)
        }) {
            return Ok(false);
        }
        let at = self.set_at(source)?;
        if !self.sets[at].close_requested {
            self.publish(Action::CloseSet { set: source })?;
            self.sets[at].close_requested = true;
            return Ok(true);
        }
        if !self.sets[at].closed {
            return Ok(false);
        }
        // CloseSet has physically retired this exact source and its original
        // native task rows. Stable retain preserves serial order for task_at;
        // fresh IDs never relabel callbacks or keep a whole past phase alive.
        self.tasks.retain(|task| task.set != source);
        self.sets.retain(|set| set.id != source);
        self.leaders[l].source = None;
        self.leaders[l].cursor = 0;
        self.leaders[l].stage = match kind {
            2 => LeaderStage::Setup(3),
            3 => LeaderStage::EchoGrade,
            5 => LeaderStage::ConfirmGrade,
            _ => return Err(Error::Conflict),
        };
        Ok(true)
    }
    fn gradecast_task(&mut self, i: usize) -> Result<bool, Error> {
        let task = &self.tasks[i];
        if task.state == TaskState::Cancel {
            let task = task.id;
            self.publish(Action::CancelTask { task })?;
            return Ok(true);
        }
        let expired = self.now >= self.task_deadline(task.key);
        if task.state == TaskState::Active && expired {
            self.task_failed(i, Error::Deadline, true)?;
            return Ok(true);
        }
        if task.state != TaskState::Planned {
            return Ok(false);
        }
        if self.blacklisted[task.peer] != 0 {
            self.task_failed(i, Error::Authentication, false)?;
            return Ok(true);
        }
        if expired {
            self.task_failed(i, Error::Deadline, false)?;
            return Ok(true);
        }
        let incoming = if task.key.peer2 as usize == self.local {
            self.offers
                .iter()
                .find(|o| !o.claimed && o.peer == task.peer && Self::key_eq(o.key, task.key))
                .map(|o| o.id)
        } else {
            None
        };
        if task.key.peer2 as usize == self.local && incoming.is_none() {
            return Ok(false);
        }
        let action = Action::Reconcile {
            task: task.id,
            set: task.set,
            peer: self.peers[task.peer],
            context: task.key,
            incoming,
            lower_bound: self.lower_bound,
        };
        self.publish(action)?;
        self.tasks[i].state = TaskState::Starting;
        if let Some(offer) = incoming {
            let at = self.offer_at(offer)?;
            self.offers[at].claimed = true;
            self.tasks[i].remote_context_contested = self.offers[at].key.contested != 0;
        }
        Ok(true)
    }
    fn gradecast_step(&mut self) -> Result<bool, Error> {
        if self
            .leaders
            .iter()
            .all(|leader| leader.stage == LeaderStage::Done)
        {
            if self.unfinished != 0 || !self.tasks.is_empty() || !self.sets.is_empty() {
                return Err(Error::Conflict);
            }
            // The previous phase-wide scheduler applied these exclusions only
            // after every confirmation was terminal. Keep that same boundary:
            // a fast leader cannot change another live leader's electorate.
            for (index, leader) in self.leaders.iter().enumerate() {
                if leader.confidence <= 1 {
                    self.blacklisted[index] = 1;
                }
            }
            self.stage = Stage::Apply;
            self.work_cursor = 0;
            self.apply_worst = usize::MAX;
            return Ok(true);
        }
        self.gradecast_task_turn = !self.gradecast_task_turn;
        if self.task_scan != 0 && (self.gradecast_task_turn || self.leader_scan == 0) {
            self.run_cursor %= self.tasks.len();
            let at = self.run_cursor;
            self.run_cursor += 1;
            self.task_scan -= 1;
            let changed = self.gradecast_task(at)?;
            if changed {
                self.leader_scan = self.leaders.len();
            }
            return Ok(changed || self.task_scan != 0 || self.leader_scan != 0);
        }
        if self.leader_scan != 0 {
            self.work_leader %= self.leaders.len();
            let l = self.work_leader;
            self.work_leader += 1;
            self.leader_scan -= 1;
            let changed = match self.leaders[l].stage {
                LeaderStage::Setup(kind) => self.leader_setup(l, kind)?,
                LeaderStage::Run(kind) => self.leader_run(l, kind)?,
                LeaderStage::EchoGrade => self.echo_grade_step(l)?,
                LeaderStage::ConfirmGrade => self.confirm_grade_step(l)?,
                LeaderStage::Done => false,
            };
            if changed {
                self.wake_gradecast();
            }
            return Ok(changed || self.task_scan != 0 || self.leader_scan != 0);
        }
        Ok(false)
    }
    fn faults(&self) -> usize {
        self.peers.len().saturating_sub(1) / 3
    }
    fn strong(&self) -> usize {
        self.peers.len() - self.faults()
    }
    fn init_rep_step(&mut self) -> Result<bool, Error> {
        let n = self.peers.len();
        if n.checked_mul(n).ok_or(Error::Overflow)? > self.limits.tasks || n > self.limits.sets {
            return Err(Error::Capacity);
        }
        if self.leaders.len() < self.peers.len() {
            let mut free = self.available()?;
            let proposal = self.current.copy(&mut free)?;
            let echo = Members::new();
            let echo_ballot = Ballot::new(self.peers.len(), self.local, &mut free)?;
            let confirm_ballot = Ballot::new(self.peers.len(), self.local, &mut free)?;
            state::reserve(&mut self.leaders, 1, self.limits.peers, &mut free)?;
            self.leaders.push(Leader {
                proposal,
                echo,
                echo_ballot,
                confirm_ballot,
                contested: false,
                confidence: 0,
                confirm_worst: usize::MAX,
                stage: LeaderStage::Setup(2),
                source: None,
                cursor: 0,
            });
            return Ok(true);
        }
        let mut free = self.available()?;
        let mut ballot = Ballot::new(self.peers.len(), self.local, &mut free)?;
        ballot.uncommit(self.local)?;
        self.round_ballot = Some(ballot);
        self.kind = 2;
        self.stage = Stage::Gradecast;
        self.work_leader = 0;
        self.run_cursor = 0;
        self.wake_gradecast();
        Ok(true)
    }
    fn echo_grade_step(&mut self, l: usize) -> Result<bool, Error> {
        if self.leaders[l].cursor == 0 && self.leaders[l].echo.ids.is_empty() {
            let mut free = self.available()?;
            self.leaders[l].echo = self.leaders[l].proposal.copy(&mut free)?;
        }
        let count = self.leaders[l].echo_ballot.votes.len();
        if self.leaders[l].cursor < count {
            let vote = &self.leaders[l].echo_ballot.votes[self.leaders[l].cursor];
            let element = vote.element;
            let (change, majority) = self.leaders[l].echo_ballot.majority(vote);
            if majority < self.strong() {
                self.leaders[l].contested = true;
            }
            let mut free = self.available()?;
            match change {
                Change::Add => self.leaders[l].echo.add(element, self.limits, &mut free)?,
                Change::Remove => self.leaders[l].echo.remove(element),
                Change::Stay => {}
            }
            self.leaders[l].cursor += 1;
            return Ok(true);
        }
        if self.leaders[l].echo_ballot.count() < self.strong() {
            self.leaders[l].contested = true;
        }
        if self.leaders[l].contested {
            self.leaders[l].confirm_ballot.contest(self.local)?;
        }
        self.leaders[l].stage = LeaderStage::Setup(5);
        self.leaders[l].cursor = 0;
        Ok(true)
    }
    fn confirm_grade_step(&mut self, l: usize) -> Result<bool, Error> {
        let votes = self.leaders[l].confirm_ballot.votes.len();
        if self.leaders[l].cursor < votes {
            let vote = &self.leaders[l].confirm_ballot.votes[self.leaders[l].cursor];
            let element = vote.element;
            let (change, majority) = self.leaders[l].confirm_ballot.confirmation_majority(vote);
            self.leaders[l].confirm_worst = self.leaders[l].confirm_worst.min(majority);
            let mut free = self.available()?;
            match change {
                Change::Add => self.leaders[l].echo.add(element, self.limits, &mut free)?,
                Change::Remove => self.leaders[l].echo.remove(element),
                Change::Stay => {}
            }
            self.leaders[l].cursor += 1;
            return Ok(true);
        }
        if self.leaders[l].cursor == votes {
            let ballot = &self.leaders[l].confirm_ballot;
            let noncontested = ballot.noncontested();
            let worst = if self.leaders[l].confirm_worst == usize::MAX {
                noncontested
            } else {
                self.leaders[l].confirm_worst
            };
            // A failed direct LEAD does not invalidate actual t+1 matching
            // CONFIRMs. Their original completed SET operations supply the
            // grade; requiring our LEAD to succeed would permit grades 0 and 2
            // at two correct receivers of the same Byzantine leader.
            let confidence = if noncontested >= self.strong() && worst >= self.strong() {
                2
            } else if noncontested > self.faults() && worst > self.faults() {
                1
            } else {
                0
            };
            self.leaders[l].confidence = confidence;
            if confidence > 0 {
                self.round_ballot
                    .as_mut()
                    .ok_or(Error::Conflict)?
                    .commit(l)?;
                self.leaders[l].cursor += 1;
            } else {
                self.leaders[l].stage = LeaderStage::Done;
                self.leaders[l].cursor = 0;
            }
            return Ok(true);
        }
        let index = self.leaders[l].cursor - votes - 1;
        if index < self.pool.elements.len() {
            if self.leaders[l].confidence > 0 {
                let id = u32::try_from(index).map_err(|_| Error::Overflow)?;
                let current = self.current.contains(id);
                let proposed = self.leaders[l].echo.contains(id);
                if current != proposed {
                    let mut free = self.available()?;
                    self.round_ballot.as_mut().ok_or(Error::Conflict)?.record(
                        id,
                        if proposed {
                            Change::Add
                        } else {
                            Change::Remove
                        },
                        l,
                        self.limits,
                        &mut free,
                    )?;
                }
            }
            self.leaders[l].cursor += 1;
            return Ok(true);
        }
        self.leaders[l].stage = LeaderStage::Done;
        self.leaders[l].cursor = 0;
        Ok(true)
    }
    fn apply_step(&mut self) -> Result<bool, Error> {
        let ballot = self.round_ballot.as_ref().ok_or(Error::Conflict)?;
        if ballot.count() < self.strong() {
            return Err(Error::Unavailable);
        }
        if let Some(vote) = ballot.votes.get(self.work_cursor) {
            let id = vote.element;
            let (change, count) = ballot.union_majority(vote);
            self.apply_worst = self.apply_worst.min(count);
            let mut free = self.available()?;
            match change {
                Change::Add => self.current.add(id, self.limits, &mut free)?,
                Change::Remove => self.current.remove(id),
                Change::Stay => {}
            }
            self.work_cursor += 1;
            return Ok(true);
        }
        // The construction permits early stopping only after an n-f majority,
        // with the same original fault bound used by grade and round admission.
        let adequate = self.apply_worst >= self.strong();
        if adequate {
            self.early = self.early.saturating_add(1);
        } else if self.early != 0 {
            return Err(Error::Authentication);
        }
        self.round_ballot = None;
        self.leaders.clear();
        if self.early >= 2 || self.rep + 1 == self.repetitions {
            self.stage = Stage::Finish;
            self.output_cursor = 0;
        } else {
            self.rep += 1;
            self.stage = Stage::InitRep;
            self.work_leader = 0;
            self.work_cursor = 0;
        }
        Ok(true)
    }
    fn finish_step(&mut self) -> Result<bool, Error> {
        // Installed secretsharing starts a second session with the same public
        // hash immediately from525. Retire the old real listener/offer source
        // before publishing the public terminal, never merely clear a counter.
        if self.listener {
            self.publish(Action::CloseListener)?;
            return Ok(true);
        }

        if let Some(id) = self.current.ids.get(self.output_cursor).copied() {
            self.output_cursor += 1;
            if self.local_values.contains(id) {
                return Ok(true);
            }
            let block = Block::decode(&self.pool.elements[id as usize].raw)?;
            if block.marker != 0 {
                return Ok(true);
            }
            let element_type = block.payload_type;
            let mut free = self.available()?;
            let mut data = state::bytes(block.data.len(), &mut free)?;
            data.copy_from_slice(block.data);
            self.publish(Action::ClientElement { element_type, data })?;
            return Ok(true);
        }
        self.publish(Action::ClientDone)?;
        Ok(true)
    }
    fn closing_step(&mut self) -> Result<bool, Error> {
        if self.close_cursor < self.tasks.len() {
            let i = self.close_cursor;
            self.close_cursor += 1;
            if matches!(self.tasks[i].state, TaskState::Active | TaskState::Cancel) {
                let task = self.tasks[i].id;
                self.tasks[i].state = TaskState::Cancel;
                self.publish(Action::CancelTask { task })?;
            }
            return Ok(true);
        }
        if self.unfinished != 0 {
            self.close_cursor = 0;
            return Ok(false);
        }
        // The original listener physically owns all remaining unaccepted offers;
        // its actual retirement closes them as one retained source generation.
        if self.listener {
            self.publish(Action::CloseListener)?;
            return Ok(true);
        }
        if let Some(offer) = self.offers.iter().find(|o| !o.reject_requested) {
            let id = offer.id;
            self.publish(Action::RejectOffer { offer: id })?;
            let at = self.offer_at(id)?;
            self.offers[at].reject_requested = true;
            return Ok(true);
        }
        if let Some(set) = self.sets.iter().find(|s| !s.closed && !s.close_requested) {
            let id = set.id;
            self.publish(Action::CloseSet { set: id })?;
            let at = self.set_at(id)?;
            self.sets[at].close_requested = true;
            return Ok(true);
        }
        if self.listener {
            self.publish(Action::CloseListener)?;
            return Ok(true);
        }
        if self.cancelling && !self.client_close_requested {
            let cause = self.outcome.failure.map_or(Error::Cancelled, |f| f.cause);
            self.publish(Action::CloseClient { cause })?;
            self.client_close_requested = true;
            return Ok(true);
        }
        if self
            .tasks
            .iter()
            .all(|t| matches!(t.state, TaskState::Done | TaskState::Failed))
            && self.sets.iter().all(|s| s.closed)
            && self.offers.is_empty()
        {
            self.stage = Stage::Stopped;
            return Ok(true);
        }
        Ok(false)
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
                    && self.now >= self.task_deadline(task.key)
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
        if self.now >= self.deadline && !matches!(self.stage, Stage::Closing | Stage::Stopped) {
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
                && let Some(offer) = self.offers.iter().find(|o| o.retire && !o.reject_requested)
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
                    if self.now < self.start || !self.listener {
                        Ok(false)
                    } else {
                        self.begin(0).map(|()| true)
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
    /// Closing-only progress requiring no clock read, synthetic timestamp or
    /// entropy. Admitted original IO still waits for its real terminal receipt.
    pub fn retire_step(&mut self) -> Result<bool, Error> {
        if self.stage == Stage::Stopped {
            return Ok(false);
        }
        if self.stage != Stage::Closing {
            return Err(Error::NotReady);
        }
        if self.pending.is_some() {
            return Ok(false);
        }
        self.closing_step()
    }
    /// Original next start/phase/session deadline; no retry creates a new bound.
    #[must_use]
    pub fn next_deadline(&self) -> Option<u64> {
        match self.stage {
            Stage::Stopped | Stage::Closing => None,
            Stage::Collect => Some(self.deadline),
            Stage::WaitStart if self.now < self.start => Some(self.start),
            Stage::Gradecast => {
                let mut next = self.deadline;
                for task in &self.tasks {
                    if matches!(
                        task.state,
                        TaskState::Planned | TaskState::Starting | TaskState::Active
                    ) {
                        let end = self.task_deadline(task.key);
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
            Stage::Run if self.phase_deadline() > self.now => {
                Some(self.phase_deadline().min(self.deadline))
            }
            Stage::Run if self.deadline > self.now => Some(self.deadline),
            Stage::Run => None,
            _ => Some(self.deadline),
        }
    }
    /// Borrow the single original immutable effect; None is not completion.
    #[must_use]
    pub fn effect(&self) -> Option<&Effect<'id>> {
        self.pending.as_ref()
    }
    /// Native admission of exactly this original effect, once.
    pub fn admit_effect(&mut self, id: EffectId<'id>) -> Result<(), Error> {
        let effect = self.pending.as_mut().ok_or(Error::NotFound)?;
        if effect.id != id {
            return Err(Error::StaleGeneration);
        }
        if effect.admitted {
            return Err(Error::Conflict);
        }
        effect.admitted = true;
        Ok(())
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
            && self.offer_at(id).is_ok_and(|i| {
                !self.offers[i].claimed
                    && !self.offers[i].retire
                    && !self.offers[i].reject_requested
            })
    }
    /// Whether original listener IO remains useful. A qualified final result
    /// stops new offers before the actual listener retirement action is settled.
    #[must_use]
    pub fn listener_live(&self) -> bool {
        self.listener
            && !self.cancelling
            && !matches!(self.stage, Stage::Finish | Stage::Closing | Stage::Stopped)
    }
    /// Metadata gate for the same original normal effect. This uses only the last
    /// observed canonical time; it does not replace a real native hard guard.
    #[must_use]
    pub fn effect_io_allowed(&self, id: EffectId<'id>) -> bool {
        !self.cancelling
            && self.pending.as_ref().is_some_and(|e| {
                e.id == id && !e.action.cleanup() && e.deadline.is_none_or(|end| self.now < end)
            })
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
            kind: matches!(self.stage, Stage::Setup | Stage::Run).then_some(self.kind),
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
    /// Cancel without clock or entropy. An admitted original action remains
    /// until its real native disposition; future work is never silently replayed.
    pub fn cancel(&mut self, cause: Error) -> Result<(), Error> {
        if self.stage == Stage::Stopped {
            return Err(Error::Closed);
        }
        // The ordinary C client destroys its MQ immediately after525. Once
        // that exact original write is known, source teardown is cleanup only.
        if self.outcome.client_done_written {
            if !matches!(cause, Error::Closed | Error::Cancelled) {
                self.outcome.cleanup_failure.get_or_insert(cause);
            }
            if self.stage != Stage::Closing {
                self.close_cursor = 0;
            }
            self.stage = Stage::Closing;
            return Ok(());
        }
        if self.outcome.failure.is_none() {
            self.failure_context = Some(self.snapshot_failure(cause));
        }
        self.outcome.failure.get_or_insert(Failure {
            cause,
            cancelled: cause == Error::Cancelled,
        });
        self.cancelling = true;
        if self.stage != Stage::Closing {
            self.close_cursor = 0;
        }
        self.stage = Stage::Closing;
        if self
            .pending
            .as_ref()
            .is_some_and(|e| !e.admitted && !e.action.cleanup())
        {
            let effect = self.pending.take().ok_or(Error::Conflict)?;
            match effect.action {
                Action::PrepareSet { set } => {
                    let at = self.set_at(set)?;
                    self.sets[at].closed = true;
                }
                Action::Reconcile { task, incoming, .. } => {
                    let at = self.task_at(task)?;
                    self.task_failed(at, cause, false)?;
                    if let Some(o) = incoming {
                        let i = self.offer_at(o)?;
                        self.offers[i].claimed = false;
                    }
                }
                Action::Listen { .. } => {}
                _ => {}
            }
        }
        for i in 0..self.tasks.len() {
            if self.tasks[i].state == TaskState::Planned {
                self.task_failed(i, cause, false)?;
            }
        }
        Ok(())
    }
    /// Settle one original native effect. Cleanup receipts require actual
    /// physical retirement; queue admission or timeout alone is not Retired.
    pub fn complete_effect(
        &mut self,
        id: EffectId<'id>,
        completion: Completion,
    ) -> Result<Terminal<'id>, Error> {
        self.complete_effect_inner(id, completion, None, None)
    }
    fn complete_effect_inner(
        &mut self,
        id: EffectId<'id>,
        completion: Completion,
        retired_source: Option<SetId<'id>>,
        uncommitted_offer: Option<OfferId<'id>>,
    ) -> Result<Terminal<'id>, Error> {
        let effect = self.pending.as_ref().ok_or(Error::NotFound)?;
        if effect.id != id {
            return Err(Error::StaleGeneration);
        }
        if !effect.admitted && !matches!(completion, Completion::Unsent(_)) {
            return Err(Error::Conflict);
        }
        if completion == Completion::Retired && !effect.action.cleanup() {
            return Err(Error::InvalidInput);
        }
        let effect = self.pending.take().ok_or(Error::Conflict)?;
        let cause = match completion {
            Completion::Unsent(e) | Completion::Lost(e) => Some(e),
            _ => None,
        };
        if effect.action.cleanup() {
            if let Some(e) = cause {
                self.outcome.cleanup_failure.get_or_insert(e);
            }
            match effect.action {
                Action::RejectOffer { offer } => {
                    let o = self.offer_at(offer)?;
                    self.offers.swap_remove(o);
                }
                Action::CancelTask { task } => {
                    let t = self.task_at(task)?;
                    self.task_failed(t, self.tasks[t].failure.unwrap_or(Error::Cancelled), false)?;
                }
                Action::CloseSet { set } => {
                    let s = self.set_at(set)?;
                    self.sets[s].closed = true;
                }
                Action::CloseListener => {
                    self.listener = false;
                    self.offers.clear();
                }
                Action::CloseClient { .. } => {}
                _ => return Err(Error::Conflict),
            }
        } else if let Some(e) = cause {
            if self.outcome.failure.is_some() {
                self.outcome.cleanup_failure.get_or_insert(e);
            }
            match effect.action {
                Action::PrepareSet { set } => {
                    let s = self.set_at(set)?;
                    if retired_source != Some(set) {
                        self.sets[s].closed = true;
                    }
                }
                Action::Reconcile { task, incoming, .. } => {
                    let t = self.task_at(task)?;
                    self.task_failed(t, e, false)?;
                    if let Some(o) = incoming {
                        let at = self.offer_at(o)?;
                        if uncommitted_offer == Some(o) {
                            self.offers[at].claimed = false;
                            self.offers[at].retire = true;
                        } else {
                            self.offers.swap_remove(at);
                        }
                    }
                }
                Action::Listen { .. } => {}
                _ => {}
            }
            if retired_source.is_none() {
                self.cancel(e)?;
            }
        } else {
            match &effect.action {
                Action::Listen { .. } => self.listener = true,
                Action::PrepareSet { set } => {
                    let s = self.set_at(*set)?;
                    self.sets[s].ready = true;
                }
                Action::Reconcile { task, incoming, .. } => {
                    let t = self.task_at(*task)?;
                    if self.cancelling {
                        self.tasks[t].state = TaskState::Cancel;
                    } else {
                        self.tasks[t].state = TaskState::Active;
                    }
                    if let Some(o) = incoming {
                        let at = self.offer_at(*o)?;
                        self.offers.swap_remove(at);
                    }
                }
                Action::ClientElement { .. } => {}
                Action::ClientDone => {
                    self.outcome.client_done_written = true;
                    self.stage = Stage::Closing;
                    self.close_cursor = 0;
                }
                _ => return Err(Error::Conflict),
            }
        }
        self.run_blocked = false;
        self.wake_gradecast();
        Ok(Terminal { effect, completion })
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
