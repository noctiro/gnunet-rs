//! Actual bounded announcement/search state. Host ports own only original IO.
use crate::types::{Brand, Key};
use crate::{
    Admission, ClientId, Error, JobId, Limits, Metrics, OutputId, Reply, StateBlock, Times, Work,
};
use alloc::{sync::Arc, vec::Vec};
use gnunet_regex::{
    Automaton, Hash,
    accept::{AcceptBlock, AcceptMaterial},
};
use gnunet_wire::official::regex::{Request, SearchResult};
const HOUR: u64 = 3_600_000_000;
const DAY: u64 = 24 * HOUR;
fn bytes(input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(input.len())
        .map_err(|_| Error::Capacity)?;
    v.extend_from_slice(input);
    Ok(v)
}
fn paths(input: &[[u8; 32]]) -> Result<Vec<[u8; 32]>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(input.len())
        .map_err(|_| Error::Capacity)?;
    v.extend_from_slice(input);
    Ok(v)
}
struct Ann {
    dfa: Automaton,
    frequency: u64,
    cycle: u64,
    cursor: usize,
    stage: Stage,
    active: bool,
    due: Option<u64>,
    charge: usize,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Stage {
    State,
    Sign,
}
struct Search {
    input: Vec<u8>,
    branches: usize,
}
struct Client {
    id: ClientId,
    closing: bool,
    close_requested: bool,
    ann: Option<Ann>,
    search: Option<Search>,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Status {
    Planned,
    Issued,
    Active,
    Stopping,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum AnnStep {
    State,
    Sign,
    Accept,
}
#[derive(Clone, Copy)]
enum Role {
    Ann {
        cycle: u64,
        record: usize,
        step: AnnStep,
    },
    Search {
        position: usize,
        kind: u32,
    },
    Retire,
}
enum Kind {
    Put {
        key: Hash,
        kind: u32,
        expires: u64,
        body: Vec<u8>,
        counted: bool,
    },
    Get {
        key: Hash,
        kind: u32,
        xquery: Vec<u8>,
        traversal: bool,
        counted: bool,
    },
    Sign {
        peer: [u8; 32],
        generation: u64,
        material: AcceptMaterial,
    },
    Retire {
        target: JobId,
    },
}
struct Job {
    id: JobId,
    client: ClientId,
    status: Status,
    role: Role,
    kind: Kind,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Delivery {
    Ready,
    Queued,
    Exposed,
}
struct Output {
    id: OutputId,
    client: ClientId,
    peer: [u8; 32],
    get: Vec<[u8; 32]>,
    put: Vec<[u8; 32]>,
    state: Delivery,
}
struct Seen {
    job: u64,
    hash: Hash,
}
/// Single original service allocation. Native source/expiry/IO ports are external.
pub struct Core {
    brand: Arc<Brand>,
    next: u64,
    clients: Vec<Client>,
    jobs: Vec<Job>,
    outputs: Vec<Output>,
    seen: Vec<Seen>,
    limits: Limits,
    now: Option<Times>,
    identity: Option<[u8; 32]>,
    identity_generation: u64,
    retained: usize,
    credits: usize,
    metrics: Metrics,
}
impl Core {
    /// Reserve all bounded row tables, without starting any backend or source.
    pub fn new(limits: Limits) -> Result<Self, Error> {
        if limits.seen_results == 0
            || limits.seen_results > 1_000_000
            || limits.clients == 0
            || limits.clients > 4096
            || limits.jobs == 0
            || limits.jobs > 65536
            || limits.branches == 0
            || limits.outputs == 0
            || limits.output_paths > 2046
            || limits.input_bytes > 65530
            || limits.block_bytes >= gnunet_regex::MAX_BLOCK_BYTES
            || limits.block_bytes < 176
            || limits.retained_bytes == 0
            || limits.announcement_bytes == 0
        {
            return Err(Error::Protocol(gnunet_types::Error::InvalidInput));
        }
        let mut clients = Vec::new();
        clients
            .try_reserve_exact(limits.clients)
            .map_err(|_| Error::Capacity)?;
        let mut jobs = Vec::new();
        jobs.try_reserve_exact(limits.jobs.checked_mul(2).ok_or(Error::Capacity)?)
            .map_err(|_| Error::Capacity)?;
        let mut outputs = Vec::new();
        outputs
            .try_reserve_exact(limits.outputs)
            .map_err(|_| Error::Capacity)?;
        let mut seen = Vec::new();
        seen.try_reserve_exact(limits.seen_results)
            .map_err(|_| Error::Capacity)?;
        Ok(Self {
            brand: Arc::new(Brand),
            next: 1,
            clients,
            jobs,
            outputs,
            seen,
            limits,
            now: None,
            identity: None,
            identity_generation: 0,
            retained: 0,
            credits: 0,
            metrics: Metrics::default(),
        })
    }
    /// Cumulative nonpersistent diagnostics for this original Core allocation.
    /// Values saturate and cannot grant job/IPC/backend authority.
    #[must_use]
    pub fn metrics(&self) -> Metrics {
        self.metrics
    }
    fn normal_jobs(&self) -> usize {
        self.credits
    }
    fn key(&mut self) -> Result<Key, Error> {
        let sequence = self.next;
        self.next = sequence
            .checked_add(1)
            .ok_or(Error::Protocol(gnunet_types::Error::Overflow))?;
        Ok(Key {
            brand: Arc::clone(&self.brand),
            sequence,
        })
    }
    fn index(&self, id: &ClientId) -> Result<usize, Error> {
        if !Arc::ptr_eq(&id.0.brand, &self.brand) {
            return Err(Error::Stale);
        }
        self.clients
            .iter()
            .position(|c| c.id == *id)
            .ok_or(Error::Stale)
    }
    fn ji(&self, id: &JobId) -> Result<usize, Error> {
        if !Arc::ptr_eq(&id.0.brand, &self.brand) {
            return Err(Error::Stale);
        }
        self.jobs
            .iter()
            .position(|j| j.id == *id)
            .ok_or(Error::Stale)
    }
    fn oi(&self, id: &OutputId) -> Result<usize, Error> {
        if !Arc::ptr_eq(&id.0.brand, &self.brand) {
            return Err(Error::Stale);
        }
        self.outputs
            .iter()
            .position(|o| o.id == *id)
            .ok_or(Error::Stale)
    }
    fn room(&self, amount: usize) -> Result<(), Error> {
        if self
            .retained
            .checked_add(amount)
            .is_none_or(|n| n > self.limits.retained_bytes)
        {
            Err(Error::Capacity)
        } else {
            Ok(())
        }
    }
    fn charge(&mut self, amount: usize) -> Result<(), Error> {
        self.room(amount)?;
        self.retained += amount;
        Ok(())
    }
    fn time(&mut self, now: Times) -> Result<(), Error> {
        if self.now.is_some_and(|old| now.monotonic < old.monotonic) {
            return Err(Error::Clock);
        }
        self.now = Some(now);
        Ok(())
    }
    /// Bind one actually accepted original MQ. Tokens never survive another Core.
    pub fn attach(&mut self) -> Result<ClientId, Error> {
        if self.clients.len() == self.limits.clients {
            return Err(Error::Capacity);
        }
        let id = ClientId(self.key()?);
        self.clients.push(Client {
            id: id.clone(),
            closing: false,
            close_requested: false,
            ann: None,
            search: None,
        });
        Ok(id)
    }
    /// Admit the actual original request. At most one of EACH type per MQ.
    /// An error authorizes no ACK; the host physically closes that source.
    pub fn handle(
        &mut self,
        id: &ClientId,
        request: Request<'_>,
        now: Times,
    ) -> Result<Admission, Error> {
        self.time(now)?;
        let ci = self.index(id)?;
        if self.clients[ci].closing || self.clients[ci].close_requested {
            return Err(Error::Closing);
        }
        match request {
            Request::Announce {
                regex,
                compression,
                refresh_delay,
                ..
            } => {
                if self.clients[ci].ann.is_some() {
                    return Err(Error::Duplicate);
                }
                if regex.bytes().len() > self.limits.input_bytes {
                    return Err(Error::Capacity);
                }
                let dfa = Automaton::compile(regex.bytes(), compression, self.limits.compiler)?;
                let mut charge = 0usize;
                for state in dfa.states() {
                    charge = charge
                        .checked_add(state.record().encoded_len()?)
                        .and_then(|n| n.checked_add(128))
                        .ok_or(Error::Capacity)?;
                }
                for index in 0..dfa.initial_count() {
                    charge = charge
                        .checked_add(dfa.initial(index).ok_or(Error::Order)?.encoded_len()?)
                        .and_then(|n| n.checked_add(128))
                        .ok_or(Error::Capacity)?;
                }
                charge = charge
                    .checked_mul(2)
                    .and_then(|n| n.checked_add(dfa.language_expression().len()))
                    .ok_or(Error::Capacity)?;
                if charge > self.limits.announcement_bytes {
                    return Err(Error::Capacity);
                }
                self.charge(charge)?;
                self.clients[ci].ann = Some(Ann {
                    dfa,
                    frequency: refresh_delay.as_micros(),
                    cycle: 0,
                    cursor: 0,
                    stage: Stage::State,
                    active: false,
                    due: Some(now.monotonic),
                    charge,
                });
                Ok(Admission::Announce)
            }
            Request::Search { string } => {
                if self.clients[ci].search.is_some() {
                    return Err(Error::Duplicate);
                }
                if string.bytes().len() > self.limits.input_bytes {
                    return Err(Error::Capacity);
                }
                let input = bytes(string.bytes())?;
                let (position, key) = gnunet_regex::first_key(&input);
                let mut xquery = bytes(&input[position..])?;
                xquery.try_reserve_exact(1).map_err(|_| Error::Capacity)?;
                xquery.push(0);
                self.room(
                    input
                        .len()
                        .checked_add(xquery.len())
                        .ok_or(Error::Capacity)?,
                )?;
                if self.normal_jobs() == self.limits.jobs {
                    return Err(Error::Capacity);
                }
                let job = JobId(self.key()?);
                self.retained += input.len() + xquery.len();
                self.clients[ci].search = Some(Search { input, branches: 1 });
                self.credits += 1;
                self.jobs.push(Job {
                    id: job,
                    client: id.clone(),
                    status: Status::Planned,
                    role: Role::Search { position, kind: 22 },
                    kind: Kind::Get {
                        key,
                        kind: 22,
                        xquery,
                        traversal: false,
                        counted: false,
                    },
                });
                Ok(Admission::Search)
            }
        }
    }
    /// Actual new PILS identity/epoch event, including reconnect with the same key.
    /// Calls are events, not polling: every call advances the signer generation.
    pub fn set_identity(&mut self, peer: Option<[u8; 32]>, now: Times) -> Result<(), Error> {
        self.time(now)?;
        self.identity_generation = self
            .identity_generation
            .checked_add(1)
            .ok_or(Error::Order)?;
        self.identity = peer;
        for i in 0..self.clients.len() {
            if let Some(ann) = &mut self.clients[i].ann {
                ann.active = false;
                ann.cursor = 0;
                ann.stage = Stage::State;
                ann.due = Some(now.monotonic);
            }
        }
        self.stop_where(|j| matches!(j.role, Role::Ann { .. }))?;
        Ok(())
    }
    /// Advance actual refresh cursors fairly by at most one new work per client.
    /// Zero refresh is immediately due again after completion, never one-shot.
    pub fn tick(&mut self, now: Times) -> Result<(), Error> {
        self.time(now)?;
        self.plan_retirements()?;
        for ci in 0..self.clients.len() {
            self.pump(ci, now)?;
        }
        Ok(())
    }
    /// Earliest original refresh or ready same-cycle continuation target. Actual
    /// backend/credit backpressure never becomes a zero-delay busy timer.
    #[must_use]
    pub fn next_wakeup(&self) -> Option<u64> {
        if self.identity.is_none() || self.credits == self.limits.jobs {
            return None;
        }
        self.clients
            .iter()
            .filter(|c| {
                !c.closing
                    && !c.close_requested
                    && !self.jobs.iter().any(|j| {
                        j.client == c.id && matches!(j.role, Role::Ann { .. } | Role::Retire)
                    })
            })
            .filter_map(|c| {
                c.ann.as_ref().and_then(|a| {
                    if a.active {
                        self.now.map(|t| t.monotonic)
                    } else {
                        a.due
                    }
                })
            })
            .min()
    }
    fn record(ann: &Ann, index: usize) -> Result<gnunet_regex::Record<'_>, Error> {
        if index < ann.dfa.states().len() {
            Ok(ann.dfa.states()[index].record())
        } else {
            ann.dfa
                .initial(index - ann.dfa.states().len())
                .ok_or(Error::Order)
        }
    }
    fn pump(&mut self, ci: usize, now: Times) -> Result<(), Error> {
        if self.identity.is_none() || self.clients[ci].closing || self.clients[ci].close_requested {
            return Ok(());
        }
        let client = self.clients[ci].id.clone();
        if self
            .jobs
            .iter()
            .any(|j| j.client == client && matches!(j.role, Role::Ann { .. } | Role::Retire))
        {
            return Ok(());
        }
        let Some(ann) = &mut self.clients[ci].ann else {
            return Ok(());
        };
        if !ann.active {
            if ann.due.is_none_or(|due| due > now.monotonic) {
                return Ok(());
            }
            ann.cycle = ann.cycle.checked_add(1).ok_or(Error::Order)?;
            ann.cursor = 0;
            ann.stage = Stage::State;
            ann.active = true;
            ann.due = if ann.frequency == u64::MAX {
                None
            } else {
                now.monotonic.checked_add(ann.frequency)
            };
        }
        if ann.cursor == ann.dfa.states().len() + ann.dfa.initial_count() {
            ann.active = false;
            return Ok(());
        }
        if self.credits == self.limits.jobs {
            return Ok(());
        }
        let record = Self::record(ann, ann.cursor)?;
        let (kind, step, charge) = match ann.stage {
            Stage::State => {
                let size = record.encoded_len()?;
                if size > self.limits.block_bytes {
                    return Err(Error::Capacity);
                }
                let mut body = Vec::new();
                body.try_reserve_exact(size).map_err(|_| Error::Capacity)?;
                body.resize(size, 0);
                record.encode(&mut body)?;
                (
                    Kind::Put {
                        key: record.key,
                        kind: 22,
                        expires: now.absolute.checked_add(HOUR).ok_or(Error::Order)?,
                        body,
                        counted: false,
                    },
                    AnnStep::State,
                    size,
                )
            }
            Stage::Sign => {
                let material = AcceptMaterial::new(
                    record.key,
                    now.absolute.checked_add(DAY).ok_or(Error::Order)?,
                );
                (
                    Kind::Sign {
                        peer: self.identity.ok_or(Error::Order)?,
                        generation: self.identity_generation,
                        material,
                    },
                    AnnStep::Sign,
                    0,
                )
            }
        };
        let role = Role::Ann {
            cycle: ann.cycle,
            record: ann.cursor,
            step,
        };
        self.room(charge)?;
        let id = JobId(self.key()?);
        self.retained += charge;
        self.credits += 1;
        self.jobs.push(Job {
            id,
            client,
            status: Status::Planned,
            role,
            kind,
        });
        Ok(())
    }
    /// Borrow the next original work ONCE. The host must keep its actual backend
    /// source/operation/bounds until a matching terminal or quiescent retire.
    pub fn next_work(&mut self) -> Result<Option<Work<'_>>, Error> {
        self.next_work_with_sign(true)
    }
    /// Skip unleased signature work while the actual signer is full; retire and
    /// DHT progress remain available. No material is copied or separate job made.
    pub fn next_work_with_sign(&mut self, sign_ready: bool) -> Result<Option<Work<'_>>, Error> {
        self.plan_retirements()?;
        let selected = self
            .jobs
            .iter()
            .position(|j| j.status == Status::Planned && matches!(j.kind, Kind::Retire { .. }))
            .or_else(|| {
                self.jobs.iter().position(|j| {
                    j.status == Status::Planned
                        && (sign_ready || !matches!(j.kind, Kind::Sign { .. }))
                })
            });
        let Some(index) = selected else {
            return Ok(None);
        };
        self.jobs[index].status = Status::Issued;
        let j = &self.jobs[index];
        Ok(Some(match &j.kind {
            Kind::Put {
                key,
                kind,
                expires,
                body,
                ..
            } => Work::Put {
                job: j.id.clone(),
                client: j.client.clone(),
                key: *key,
                kind: *kind,
                options: if *kind == 23 { 3 } else { 1 },
                replication: 5,
                expires: *expires,
                block: body,
            },
            Kind::Get {
                key, kind, xquery, ..
            } => Work::Get {
                job: j.id.clone(),
                client: j.client.clone(),
                key: *key,
                kind: *kind,
                options: if *kind == 23 { 3 } else { 1 },
                replication: 5,
                xquery,
            },
            Kind::Sign { peer, material, .. } => Work::Sign {
                job: j.id.clone(),
                client: j.client.clone(),
                peer: *peer,
                material: material.view(),
            },
            Kind::Retire { target } => Work::Retire {
                job: j.id.clone(),
                client: j.client.clone(),
                target: target.clone(),
            },
        }))
    }
    /// Observe actual local provider PUT admission for this SAME issued job.
    /// Returns true only when its diagnostic counter was added once. False is a
    /// diagnostic no-op (stale/wrong-kind/phase/duplicate), never a business
    /// failure or permission to retry a native mutation. Work leasing and the
    /// later local terminal do not count as admission or remote storage.
    pub fn put_admitted(&mut self, id: &JobId) -> bool {
        let Ok(i) = self.ji(id) else {
            return false;
        };
        if self.jobs[i].status != Status::Issued {
            return false;
        }
        let Kind::Put {
            kind,
            body,
            counted,
            ..
        } = &mut self.jobs[i].kind
        else {
            return false;
        };
        if *counted || !matches!(*kind, 22 | 23) {
            return false;
        }
        *counted = true;
        self.metrics.put_admitted(*kind, body.len());
        true
    }
    /// Only the actual original GET admission: it is not a result or completion.
    pub fn get_started(&mut self, id: &JobId) -> Result<(), Error> {
        let i = self.ji(id)?;
        if !matches!(self.jobs[i].kind, Kind::Get { .. }) {
            return Err(Error::Order);
        }
        match self.jobs[i].status {
            Status::Issued => self.jobs[i].status = Status::Active,
            Status::Stopping => {}
            _ => return Err(Error::Order),
        }
        if let Kind::Get {
            traversal, counted, ..
        } = &mut self.jobs[i].kind
            && !*counted
        {
            *counted = true;
            if *traversal {
                self.metrics.node_admitted();
            }
        }
        Ok(())
    }
    fn remove_job(&mut self, index: usize) -> Job {
        let release = match &self.jobs[index].kind {
            Kind::Retire { target } => !self.jobs.iter().any(|j| j.id == *target),
            _ => !self
                .jobs
                .iter()
                .any(|j| matches!(&j.kind,Kind::Retire{target} if *target==self.jobs[index].id)),
        };
        if release {
            self.credits -= 1;
        }
        let job = self.jobs.swap_remove(index);
        let size = match &job.kind {
            Kind::Put { body, .. } => body.len(),
            Kind::Get { xquery, .. } => xquery.len(),
            _ => 0,
        };
        self.retained -= size;
        self.seen.retain(|s| s.job != job.id.0.sequence);
        job
    }
    fn finish(&mut self, index: usize) -> Result<(), Error> {
        let job = &self.jobs[index];
        if job.status == Status::Stopping {
            self.remove_job(index);
            return Ok(());
        }
        let transition = if let Role::Ann {
            cycle,
            record,
            step,
        } = job.role
        {
            let ci = self.index(&job.client)?;
            if self.clients[ci].closing {
                None
            } else {
                let ann = self.clients[ci].ann.as_ref().ok_or(Error::Order)?;
                if ann.cycle != cycle || ann.cursor != record {
                    return Err(Error::Stale);
                }
                let accepting = match step {
                    AnnStep::State => Self::record(ann, record)?.accepting,
                    AnnStep::Accept => false,
                    AnnStep::Sign => return Err(Error::Order),
                };
                Some((ci, step, accepting))
            }
        } else {
            None
        };
        // Everything which can reject this original terminal is checked BEFORE
        // consuming its row. No native terminal can become an untracked orphan.
        if let Some((ci, step, accepting)) = transition {
            let ann = self.clients[ci].ann.as_mut().ok_or(Error::Order)?;
            if step == AnnStep::State && accepting {
                ann.stage = Stage::Sign;
            } else {
                ann.cursor += 1;
                ann.stage = Stage::State;
            }
        }
        self.remove_job(index);
        Ok(())
    }
    /// Actual original local PUT transfer/API terminal only. There is no invented
    /// remote ACK, replication, disk-sync or reachability assertion.
    pub fn put_complete(&mut self, id: &JobId) -> Result<(), Error> {
        let i = self.ji(id)?;
        if !matches!(self.jobs[i].kind, Kind::Put { .. }) || self.jobs[i].status == Status::Planned
        {
            return Err(Error::Order);
        }
        self.finish(i)
    }
    /// Actual PILS operation is quiescent. Verify original peer/generation,
    /// material and signature before producing a NEW accepting PUT job.
    pub fn complete_signature(
        &mut self,
        id: &JobId,
        peer: [u8; 32],
        signature: [u8; 64],
        now: Times,
    ) -> Result<(), Error> {
        self.time(now)?;
        let i = self.ji(id)?;
        let Kind::Sign {
            peer: original,
            generation,
            material,
        } = &self.jobs[i].kind
        else {
            return Err(Error::Order);
        };
        if self.jobs[i].status == Status::Planned {
            return Err(Error::Order);
        }
        if self.jobs[i].status == Status::Stopping {
            self.remove_job(i);
            return Ok(());
        }
        if *original != peer
            || *generation != self.identity_generation
            || self.identity != Some(peer)
        {
            return Err(Error::Stale);
        }
        let encoded = material.finish(peer, signature);
        AcceptBlock::decode(&encoded)?.verify(now.absolute, &material.key())?;
        self.room(encoded.len())?;
        let body = bytes(&encoded)?;
        let key = material.key();
        let role = match self.jobs[i].role {
            Role::Ann {
                cycle,
                record,
                step: AnnStep::Sign,
            } => Role::Ann {
                cycle,
                record,
                step: AnnStep::Accept,
            },
            _ => return Err(Error::Order),
        };
        let client = self.jobs[i].client.clone();
        let next = JobId(self.key()?);
        let expires = now.absolute.checked_add(HOUR).ok_or(Error::Order)?;
        self.remove_job(i);
        self.retained += body.len();
        self.credits += 1;
        self.jobs.push(Job {
            id: next,
            client,
            status: Status::Planned,
            role,
            kind: Kind::Put {
                key,
                kind: 23,
                expires,
                body,
                counted: false,
            },
        });
        Ok(())
    }
    /// Original backend failed AND is physically quiescent. Its client must close;
    /// this does not fabricate a wire error, search DONE or mutation success.
    pub fn backend_failed(&mut self, id: &JobId) -> Result<(), Error> {
        let i = self.ji(id)?;
        if matches!(self.jobs[i].kind, Kind::Retire { .. })
            || self.jobs[i].status == Status::Planned
        {
            return Err(Error::Order);
        }
        let ci = self.index(&self.jobs[i].client)?;
        if self.jobs[i].status != Status::Stopping {
            self.clients[ci].close_requested = true;
        }
        self.remove_job(i);
        Ok(())
    }
    /// Actual repeated GET result from that SAME admitted original query.
    pub fn receive(&mut self, id: &JobId, reply: Reply<'_>, now: Times) -> Result<(), Error> {
        self.time(now)?;
        let ji = self.ji(id)?;
        let job = &self.jobs[ji];
        if job.status == Status::Stopping {
            return Err(Error::Closing);
        }
        if job.status != Status::Active {
            return Err(Error::Order);
        }
        let Kind::Get { key, kind, .. } = &job.kind else {
            return Err(Error::Order);
        };
        if *key != reply.key || *kind != reply.kind {
            return Err(Error::Protocol(gnunet_types::Error::Malformed));
        }
        if reply.expires < now.absolute {
            return Err(Error::Expired);
        }
        let ci = self.index(&job.client)?;
        if self.clients[ci].closing || self.clients[ci].close_requested {
            return Err(Error::Closing);
        }
        let client = job.client.clone();
        let Role::Search { position, .. } = job.role else {
            return Err(Error::Order);
        };
        let key = *key;
        let kind = *kind;
        if reply.block.len() > self.limits.block_bytes {
            return Err(Error::Capacity);
        }
        let digest = gnunet_crypto::hash512(reply.block);
        if self
            .seen
            .iter()
            .any(|s| s.job == id.0.sequence && s.hash == digest)
        {
            return Ok(());
        }
        if self.seen.len() == self.limits.seen_results {
            return Err(Error::Capacity);
        }
        if kind == 22 {
            let state = StateBlock::decode(reply.block)?;
            if state.key() != key {
                return Err(Error::Protocol(gnunet_types::Error::Authentication));
            }
            let search = self.clients[ci].search.as_ref().ok_or(Error::Order)?;
            let next = if position == search.input.len() {
                if state.accepting() {
                    Some((key, position, 23))
                } else {
                    None
                }
            } else {
                let found = state.longest(&search.input[position..])?;
                // longest checked every edge of this actual validated state.
                // Count the work even if later branch admission is refused.
                self.metrics.edges_inspected(state.edge_count());
                found.map(|e| (e.destination, position + e.label.len(), 22))
            };
            if let Some((key, position, kind)) = next {
                self.branch(ci, key, position, kind)?;
            }
        } else {
            if reply
                .get_path
                .len()
                .checked_add(reply.put_path.len())
                .is_none_or(|n| n > self.limits.output_paths)
            {
                return Err(Error::Capacity);
            }
            if self.outputs.len() == self.limits.outputs {
                return Err(Error::Capacity);
            }
            let checked = AcceptBlock::decode(reply.block)?.verify(now.absolute, &key)?;
            let charge = reply
                .get_path
                .len()
                .checked_add(reply.put_path.len())
                .and_then(|n| n.checked_mul(32))
                .ok_or(Error::Capacity)?;
            self.room(charge)?;
            let get = paths(reply.get_path)?;
            let put = paths(reply.put_path)?;
            let output = OutputId(self.key()?);
            self.retained += charge;
            self.outputs.push(Output {
                id: output,
                client,
                peer: checked.peer(),
                get,
                put,
                state: Delivery::Ready,
            });
            // Count a genuine checked result successfully retained by this
            // original query; duplicate/failing input grants no found result.
            self.metrics.accepting_found(reply.block.len());
        }
        self.seen.push(Seen {
            job: id.0.sequence,
            hash: digest,
        });
        Ok(())
    }
    fn branch(&mut self, ci: usize, key: Hash, position: usize, kind: u32) -> Result<(), Error> {
        let client = self.clients[ci].id.clone();
        if self.jobs.iter().any(|j|j.client==client&&matches!((&j.kind,j.role),(Kind::Get{key:k,..},Role::Search{position:p,kind:t})if *k==key&&p==position&&t==kind)){return Ok(());}
        let search = self.clients[ci].search.as_ref().ok_or(Error::Order)?;
        if search.branches == self.limits.branches || self.normal_jobs() == self.limits.jobs {
            return Err(Error::Capacity);
        }
        let mut xquery = if kind == 22 {
            bytes(search.input.get(position..).ok_or(Error::Order)?)?
        } else {
            Vec::new()
        };
        if kind == 22 {
            xquery.try_reserve_exact(1).map_err(|_| Error::Capacity)?;
            xquery.push(0);
        }
        self.room(xquery.len())?;
        let id = JobId(self.key()?);
        self.retained += xquery.len();
        self.clients[ci]
            .search
            .as_mut()
            .ok_or(Error::Order)?
            .branches += 1;
        self.credits += 1;
        self.jobs.push(Job {
            id,
            client,
            status: Status::Planned,
            role: Role::Search { position, kind },
            kind: Kind::Get {
                key,
                kind,
                xquery,
                traversal: kind == 22,
                counted: false,
            },
        });
        Ok(())
    }
    /// Backend/source failure requires physical client retirement by the host.
    pub fn needs_close(&self, id: &ClientId) -> Result<bool, Error> {
        Ok(self.clients[self.index(id)?].close_requested)
    }
    /// Called AFTER physical original MQ retirement. Never emits a wire CANCEL.
    /// Ready output is known unqueued; Queued/Exposed output debt stays retained.
    pub fn disconnect(&mut self, id: &ClientId) -> Result<(), Error> {
        let ci = self.index(id)?;
        self.clients[ci].closing = true;
        self.stop_where(|j| j.client == *id && !matches!(j.kind, Kind::Retire { .. }))?;
        let mut i = 0;
        while i < self.outputs.len() {
            if self.outputs[i].client == *id && self.outputs[i].state == Delivery::Ready {
                self.remove_output(i);
            } else {
                i += 1;
            }
        }
        Ok(())
    }
    fn stop_where(&mut self, mut choose: impl FnMut(&Job) -> bool) -> Result<(), Error> {
        let mut i = 0;
        while i < self.jobs.len() {
            if choose(&self.jobs[i]) {
                if self.jobs[i].status == Status::Planned {
                    self.remove_job(i);
                    continue;
                }
                self.jobs[i].status = Status::Stopping;
            }
            i += 1;
        }
        self.plan_retirements()
    }
    fn plan_retirements(&mut self) -> Result<(), Error> {
        let mut i = 0;
        while i < self.jobs.len() {
            if self.jobs.len() == self.limits.jobs * 2 {
                break;
            }
            let target = &self.jobs[i];
            if target.status == Status::Stopping
                && !self
                    .jobs
                    .iter()
                    .any(|j| matches!(&j.kind,Kind::Retire{target:t}if *t==target.id))
            {
                let target_id = target.id.clone();
                let client = target.client.clone();
                let id = JobId(self.key()?);
                self.jobs.push(Job {
                    id,
                    client,
                    status: Status::Planned,
                    role: Role::Retire,
                    kind: Kind::Retire { target: target_id },
                });
            }
            i += 1;
        }
        Ok(())
    }
    /// The EXACT original retire operation is actually quiescent. Admission of a
    /// cancel command or closing only its caller's future is insufficient.
    pub fn retired(&mut self, id: &JobId) -> Result<(), Error> {
        let i = self.ji(id)?;
        if self.jobs[i].status != Status::Issued {
            return Err(Error::Order);
        }
        let Kind::Retire { target } = &self.jobs[i].kind else {
            return Err(Error::Order);
        };
        let target = target.clone();
        if let Ok(target_index) = self.ji(&target)
            && self.jobs[target_index].status != Status::Stopping
        {
            return Err(Error::Order);
        }
        self.remove_job(i);
        if let Ok(i) = self.ji(&target) {
            self.remove_job(i);
        }
        Ok(())
    }
    /// Original oldest unqueued result. Repeated borrowing returns the SAME id.
    pub fn next_output(&self, id: &ClientId) -> Result<Option<OutputId>, Error> {
        let ci = self.index(id)?;
        if self.clients[ci].closing || self.clients[ci].close_requested {
            return Ok(None);
        }
        Ok(self
            .outputs
            .iter()
            .find(|o| o.client == *id && o.state == Delivery::Ready)
            .map(|o| o.id.clone()))
    }
    /// Borrow only a genuinely checked accepting result and original route paths.
    pub fn output(&self, id: &OutputId) -> Result<SearchResult<'_>, Error> {
        let o = &self.outputs[self.oi(id)?];
        Ok(SearchResult {
            peer: o.peer,
            get_path: &o.get,
            put_path: &o.put,
        })
    }
    /// Actual standard response enqueue on the original client MQ, not a write.
    pub fn queued(&mut self, id: &OutputId) -> Result<(), Error> {
        let i = self.oi(id)?;
        if self.outputs[i].state != Delivery::Ready
            || self.clients[self.index(&self.outputs[i].client)?].closing
            || self.clients[self.index(&self.outputs[i].client)?].close_requested
        {
            return Err(Error::Order);
        }
        self.outputs[i].state = Delivery::Queued;
        Ok(())
    }
    /// Actual positive partial-write exposure; repeating it cannot mint a result.
    pub fn exposed(&mut self, id: &OutputId) -> Result<(), Error> {
        let i = self.oi(id)?;
        if self.outputs[i].state == Delivery::Ready {
            return Err(Error::Order);
        }
        self.outputs[i].state = Delivery::Exposed;
        Ok(())
    }
    fn remove_output(&mut self, index: usize) {
        let o = self.outputs.remove(index);
        self.retained -= (o.get.len() + o.put.len()) * 32;
    }
    /// Actual whole write on the same original MQ, never a remote application ACK.
    pub fn written(&mut self, id: &OutputId) -> Result<(), Error> {
        let i = self.oi(id)?;
        if self.outputs[i].state == Delivery::Ready {
            return Err(Error::Order);
        }
        self.remove_output(i);
        Ok(())
    }
    /// Called only after disconnect/actual Framed retirement for original queued debt.
    pub fn aborted(&mut self, id: &OutputId) -> Result<(), Error> {
        let i = self.oi(id)?;
        if !self.clients[self.index(&self.outputs[i].client)?].closing
            || self.outputs[i].state == Delivery::Ready
        {
            return Err(Error::Order);
        }
        self.remove_output(i);
        Ok(())
    }
    /// Number of original normal and retirement rows still retained. A number
    /// alone is diagnostic; it is not a backend quiescence receipt.
    #[must_use]
    pub fn pending_jobs(&self) -> usize {
        self.jobs.len()
    }
    /// All actual clients have been physically retired/released, every backend
    /// target/cancel row has a matching terminal, and no output debt remains.
    #[must_use]
    pub fn quiescent(&self) -> bool {
        self.clients.is_empty() && self.jobs.is_empty() && self.outputs.is_empty()
    }
    /// True removes a physically disconnected client with NO original backend or
    /// output debt. False means caller must retain the SAME id and keep draining.
    pub fn release(&mut self, id: &ClientId) -> Result<bool, Error> {
        let ci = self.index(id)?;
        if !self.clients[ci].closing {
            return Err(Error::Order);
        }
        if self.jobs.iter().any(|j| j.client == *id) || self.outputs.iter().any(|o| o.client == *id)
        {
            return Ok(false);
        }
        let client = self.clients.swap_remove(ci);
        if let Some(ann) = client.ann {
            self.retained -= ann.charge;
        }
        if let Some(search) = client.search {
            self.retained -= search.input.len();
        }
        Ok(true)
    }
}
