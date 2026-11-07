use super::*;
use gnunet_types::MonoInstant;
#[path = "runtime/admission.rs"]
mod admission;
#[path = "runtime/cancellation.rs"]
mod cancellation;
#[path = "runtime/forward.rs"]
mod forward;
#[path = "runtime/output_completion.rs"]
mod output_completion;
/// One bounded actual source, reusable material caches, original frame owners,
/// PILS client and durable worker. No hidden task or per-neighbour MQ is created.
/// `Source`/fixed plaintext loans live in caller storage, avoiding self-reference.
#[must_use = "close native source and drain/join original durable worker explicitly"]
pub struct Runtime<'id, 'source, 'pils, 'slots, 'out, J, const N: usize = 32> {
    instance: &'id Instance,
    source: &'source Source<'id>,
    guard: Task<'source, 'id>,
    // Immutable source/material anchor, not the latest Exact-admission token.
    identity: Identity<'pils>,
    client: Client<'pils, N>,
    provider: store::Provider<'id>,
    routes: dv::routes::Routes<'id, 'slots>,
    send: material::SendMaterials<'slots, 'source, 'id>,
    receive: material::ReceiveMaterials<'slots, 'source, 'id>,
    replay: replay::Replay<'slots, 'source, 'id>,
    buffers: Vec<&'out mut [u8]>,
    scratch: &'slots mut [u8],
    neighbours: Vec<Neighbour<'id>>,
    inputs: Vec<InputRow<'source, 'id, 'pils, 'out, J>>,
    outputs: Vec<OutputRow<'source, 'id, 'pils, J>>,
    retiring: Vec<Retiring<OperationId<'pils>>>,
    probes: Vec<ProbeTrack<'id>>,
    probe_capacity: usize,
    clock: Arc<dyn RuntimeClock>,
    clock_revision: u64,
    limits: Limits,
    input_scan: InputScan,
    closed: bool,
    shutdown_complete: bool,
    anchor: std::time::Instant,
    source_hard: Instant,
    partial: Option<Instant>,
    alarm: Option<Pin<Box<Sleep>>>,
    cleanup: Option<Error>,
}
/// Debt for the one input row loop whose work is clipped by Runtime quantum.
/// Counts and cursor are inline metadata, independent of protocol/native bounds.
#[derive(Default)]
struct InputScan {
    next: usize,
    count: usize,
    remaining: usize,
}
impl InputScan {
    fn changed(&mut self, count: usize) {
        self.count = count;
        self.remaining = count;
        self.next = if count == 0 { 0 } else { self.next % count };
    }
    fn begin(&mut self, count: usize) {
        if self.count != count {
            self.changed(count);
        }
    }
    fn take(&mut self) -> Option<usize> {
        if self.count == 0 {
            return None;
        }
        let index = self.next;
        self.next = (self.next + 1) % self.count;
        // Later external polls retain the original bounded expiry/readiness
        // checks, but a completed idle pass cannot create fresh self-wake debt.
        self.remaining = self.remaining.saturating_sub(1);
        Some(index)
    }
    fn pending(&self) -> bool {
        self.remaining != 0
    }
    fn stop(&mut self) {
        self.next = 0;
        self.count = 0;
        self.remaining = 0;
    }
}

/// Observe both the original registered alarm and a newly earlier target.
/// Returning Ready is consumed by the caller once, even if both polls observe
/// it. An unfinished registration can be narrowed, never pushed into the future.
fn poll_input_alarm(
    alarm: &mut Option<Pin<Box<Sleep>>>,
    cx: &mut Context<'_>,
    target: Instant,
) -> bool {
    let old_ready = alarm
        .as_mut()
        .is_some_and(|timer| timer.as_mut().poll(cx).is_ready());
    let timer = alarm.get_or_insert_with(|| Box::pin(tokio::time::sleep_until(target)));
    if old_ready || target < timer.deadline() {
        timer.as_mut().reset(target);
    }
    let new_ready = timer.as_mut().poll(cx).is_ready();
    old_ready || new_ready
}
fn runnable_input_scan(debt: bool, closed: bool, awaiting_physical: bool) -> bool {
    debt && !closed && !awaiting_physical
}
fn clock_adjusted(previous: &mut u64, observed: u64) -> bool {
    if *previous == observed {
        false
    } else {
        *previous = observed;
        true
    }
}

impl<'id, 'source, 'pils, 'slots, 'out, J, const N: usize>
    Runtime<'id, 'source, 'pils, 'slots, 'out, J, N>
{
    /// Adopt the ALREADY physically attached/verified real PILS client and its
    /// caller-minted source for this exact local identity/epoch. Does not inspect
    /// keys, open files, connect MQs or create a worker. Provider was explicitly
    /// opened by caller in its independent marked TransportDv namespace.
    #[expect(
        clippy::too_many_arguments,
        reason = "Explicit independent caller resource owners; no hidden constructor effects"
    )]
    pub fn new(
        instance: &'id Instance,
        source: &'source Source<'id>,
        route_instance: &'id dv::routes::Instance,
        client: Client<'pils, N>,
        provider: store::Provider<'id>,
        clock: Arc<dyn RuntimeClock>,
        storage: Storage<'slots, 'source, 'id, 'out>,
        limits: Limits,
    ) -> Result<Self, Error> {
        let mut provider = Some(provider);
        Self::try_new(
            instance,
            source,
            route_instance,
            client,
            &mut provider,
            clock,
            storage,
            limits,
        )
    }
    /// Fallible native adoption with worker ownership retained on failure. Only
    /// a fully prepared runtime takes the original Provider from this Option.
    #[expect(
        clippy::too_many_arguments,
        reason = "Independent explicit original resource owners"
    )]
    pub fn try_new(
        instance: &'id Instance,
        source: &'source Source<'id>,
        route_instance: &'id dv::routes::Instance,
        client: Client<'pils, N>,
        provider: &mut Option<store::Provider<'id>>,
        clock: Arc<dyn RuntimeClock>,
        storage: Storage<'slots, 'source, 'id, 'out>,
        limits: Limits,
    ) -> Result<Self, Error> {
        if provider.is_none() {
            return Err(Protocol::NotReady.into());
        }
        if limits.inputs == 0
            || limits.outputs == 0
            || limits.neighbours == 0
            || limits.quantum == 0
            || limits.bytes == 0
            || limits.frame_bytes < dv::BOX_PREFIX + dv::PAYLOAD_PREFIX + 4
            || limits.frame_bytes > u16::MAX as usize
            || limits.operation.0 == 0
            || limits.native_operation.is_zero()
            || limits.source.is_zero()
            || limits.retirement_grace.is_zero()
            || limits.input.is_zero()
            || limits.material_lifetime.as_micros() == 0
            || u64::try_from(limits.material_lifetime.as_micros()).is_err()
            || limits.material_messages == 0
            || N == 0
            || storage.send.is_empty()
            || storage.receive.is_empty()
            || storage.plaintext.is_empty()
            || storage.scratch.len() < limits.frame_bytes
            || storage.plaintext.iter().any(|s| s.len() < 4)
            || !storage
                .plaintext
                .iter()
                .any(|s| s.len() >= limits.frame_bytes - dv::BOX_PREFIX - dv::PAYLOAD_PREFIX)
        {
            return Err(Protocol::InvalidInput.into());
        }
        if !client.is_idle() || !Arc::ptr_eq(&clock, &client.clock()) {
            return Err(Protocol::Conflict.into());
        }
        let identity = client.identity().ok_or(Protocol::NotReady)?;
        if client.epoch() != Some(identity.epoch())
            || identity.peer().as_bytes() != &source.local().0
        {
            return Err(Protocol::Stale.into());
        }
        let sample = clock.sample()?;
        let now = sample.now.as_micros();
        let guard = source.task(0, now, identity.expiration().as_micros())?;
        let source_remaining = std::time::Duration::from_micros(
            guard.until().checked_sub(now).ok_or(Protocol::Deadline)?,
        );
        let source_hard = Instant::now()
            .checked_add(limits.source.min(source_remaining))
            .ok_or(Protocol::Overflow)?;
        let probe_capacity = storage.probes.len();
        let mut probes = Vec::new();
        probes
            .try_reserve_exact(probe_capacity)
            .map_err(|_| Protocol::Capacity)?;
        let routes = dv::routes::Routes::new(
            route_instance,
            source.local(),
            storage.routes,
            storage.probes,
            storage.sources,
            limits.routes,
        )?;
        let send = material::SendMaterials::new(storage.send)?;
        let receive = material::ReceiveMaterials::new(storage.receive)?;
        let replay = replay::Replay::new(
            source,
            storage.replay_peers,
            storage.replay_nonces,
            limits.replay,
        )?;
        let mut neighbours = Vec::new();
        neighbours
            .try_reserve_exact(limits.neighbours)
            .map_err(|_| Protocol::Capacity)?;
        let mut inputs = Vec::new();
        inputs
            .try_reserve_exact(limits.inputs)
            .map_err(|_| Protocol::Capacity)?;
        let mut outputs = Vec::new();
        outputs
            .try_reserve_exact(limits.outputs)
            .map_err(|_| Protocol::Capacity)?;
        let mut retiring = Vec::new();
        retiring
            .try_reserve_exact(N)
            .map_err(|_| Protocol::Capacity)?;
        let provider = provider.take().ok_or(Protocol::NotReady)?;
        Ok(Self {
            instance,
            source,
            guard,
            identity,
            client,
            provider,
            routes,
            send,
            receive,
            replay,
            buffers: storage.plaintext,
            scratch: storage.scratch,
            neighbours,
            inputs,
            outputs,
            retiring,
            probes,
            probe_capacity,
            clock,
            clock_revision: sample.revision,
            limits,
            input_scan: InputScan::default(),
            closed: false,
            shutdown_complete: false,
            anchor: std::time::Instant::now(),
            source_hard,
            partial: None,
            alarm: None,
            cleanup: None,
        })
    }
    fn inputs_changed(&mut self) {
        if self.closed {
            self.input_scan.stop();
        } else {
            self.input_scan.changed(self.inputs.len());
        }
    }
    fn token(&self) -> Result<Token<'id>, Protocol> {
        Ok(Token {
            domain: self.instance,
            serial: self.instance.next()?,
        })
    }
    fn now(&mut self) -> Result<u64, Error> {
        if Instant::now() >= self.source_hard {
            self.close();
            return Err(Protocol::Deadline.into());
        }
        let checked = self.clock.sample().map_err(Error::from).and_then(|sample| {
            if Instant::now() >= self.source_hard {
                return Err(Protocol::Deadline.into());
            }
            self.guard.check(sample.now.as_micros())?;
            // Existing Client/Bounds subscriptions supply adjustment wakes.
            // The shared sample revision identifies the real change once;
            // ordinary elapsed microseconds do not manufacture another pass.
            if clock_adjusted(&mut self.clock_revision, sample.revision) {
                self.inputs_changed();
            }
            Ok(sample.now.as_micros())
        });
        if checked.is_err() {
            self.close();
        }
        checked
    }
    fn bound(&self, now: u64) -> Result<Bound, Protocol> {
        let mut b = Bound::new(now, self.identity.expiration().as_micros(), self.limits)?;
        b.until = b.until.min(self.guard.until());
        b.hard = b.hard.min(self.source_hard);
        Ok(b)
    }
    fn material_lease(&self, now: u64) -> Result<MaterialLease, Protocol> {
        MaterialLease::capture(
            now,
            Instant::now(),
            self.guard.until(),
            self.identity.expiration().as_micros(),
            self.source_hard,
            self.limits.material_lifetime,
        )
    }
    fn failure_source(&self) -> Budget {
        Budget {
            until: gnunet_wire::official::AbsoluteTime::from_micros(self.guard.until()),
            hard: self.source_hard,
        }
    }
    fn input_failure(
        &self,
        index: usize,
        native: Instant,
        absolute: Option<u64>,
    ) -> FailureContext<'id> {
        self.inputs[index].failure(
            &self.outputs,
            self.failure_source(),
            self.identity.expiration(),
            native,
            absolute.map(gnunet_wire::official::AbsoluteTime::from_micros),
        )
    }
    fn output_failure(
        &self,
        index: usize,
        native: Instant,
        absolute: Option<u64>,
    ) -> FailureContext<'id> {
        self.outputs[index].failure(
            self.failure_source(),
            self.identity.expiration(),
            native,
            absolute.map(gnunet_wire::official::AbsoluteTime::from_micros),
        )
    }
    /// Original verified local public source; no key bytes or signing power.
    pub const fn identity(&self) -> Identity<'pils> {
        self.identity
    }
    /// Negative local lifecycle fact, not remote quiescence or a signing proof.
    /// The original shared PILS owner has been physically closed when true.
    pub const fn is_closed(&self) -> bool {
        self.closed
    }
    /// Exact original shared process clock; cloning adds no subscription or IO.
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.clock.clone()
    }
    /// Original native input targets for bounded external forwarding policy.
    pub fn input_budget(&self, id: Token<'id>) -> Result<Budget, Error> {
        let r = &self.inputs[self.input_index(id)?];
        Ok(Budget {
            until: gnunet_wire::official::AbsoluteTime::from_micros(r.bounds.until),
            hard: r.bounds.hard,
        })
    }
    /// Original verified LEARNs whose forwarding policy remains unplanned.
    pub fn learn_ready_tokens(&self) -> impl Iterator<Item = Token<'id>> + '_ {
        self.inputs
            .iter()
            .filter(|r| r.planning && matches!(r.state, InputState::LearnReady))
            .map(|r| r.token)
    }
    /// Read only a real retained local physical output fact. This never consumes
    /// the native bridge's original OutputFinished/Origin receipt.
    pub fn output_outcome(&self, id: Token<'id>) -> Result<Option<WriteOutcome>, Error> {
        Ok(self.outputs[self.output_index(id)?].state.outcome())
    }
    /// Probe observation survives output-row recycling; no fresh deadline is
    /// minted and sent never means receipt by a remote peer/application.
    pub fn probe_status(&self, id: Token<'id>) -> Result<ProbeStatus, Error> {
        let p = self
            .probes
            .iter()
            .find(|p| p.token == id)
            .ok_or(Protocol::Stale)?;
        Ok(ProbeStatus {
            budget: p.budget,
            sent: p.sent,
            retired: p.probe.is_none(),
            outcome: p.outcome,
        })
    }
    fn retire_probe_book(&mut self, id: Token<'id>) -> Result<(), Error> {
        let p = self
            .probes
            .iter()
            .position(|p| p.token == id)
            .ok_or(Protocol::Stale)?;
        if let Some(probe) = self.probes[p].probe {
            // Keep the exact book identity when its original retirement refuses.
            self.routes.retire_probe(probe)?;
            self.probes[p].probe = None;
            self.inputs_changed();
        }
        if let Ok(o) = self.output_index(id) {
            self.outputs[o].probe = None;
        }
        Ok(())
    }
    /// End only this original probe/learning lease and cancel its still pending
    /// output interest. Queued native frames still require real original settle.
    pub fn retire_probe(&mut self, id: Token<'id>) -> Result<(), Error> {
        let mut errors = cancellation::Errors::default();
        errors.record(self.retire_probe_book(id));
        if let Ok(o) = self.output_index(id)
            && self.outputs[o].state.outcome().is_none()
        {
            errors.record(self.cancel_output_index(o, WriteOutcome::Unsent));
        }
        errors.finish(&mut self.cleanup)
    }
    /// Release a retired original probe metadata slot only AFTER its real
    /// physical output has terminated. Never steal a bridge completion receipt.
    pub fn release_probe(&mut self, id: Token<'id>) -> Result<(), Error> {
        let i = self
            .probes
            .iter()
            .position(|p| p.token == id)
            .ok_or(Protocol::Stale)?;
        if self.probes[i].probe.is_some() || self.probes[i].outcome.is_none() {
            return Err(Protocol::NotReady.into());
        }
        self.probes.swap_remove(i);
        self.inputs_changed();
        Ok(())
    }
    fn monotonic(&self) -> Result<MonoInstant, Protocol> {
        Ok(MonoInstant(
            u64::try_from(self.anchor.elapsed().as_micros()).map_err(|_| Protocol::Overflow)?,
        ))
    }
    fn live(&self) -> Result<(), Protocol> {
        if self.closed {
            Err(Protocol::Closed)
        } else {
            Ok(())
        }
    }
    fn admission_identity(&self, now: u64) -> Result<Identity<'pils>, Protocol> {
        self.live()?;
        let actual = self.client.identity().ok_or(Protocol::Stale)?;
        if self.client.epoch() != Some(self.identity.epoch())
            || actual.epoch() != self.identity.epoch()
            || actual.peer() != self.identity.peer()
            || actual.address_hash() != self.identity.address_hash()
            || actual.coverage() != self.identity.coverage()
        {
            return Err(Protocol::Stale);
        }
        if self.identity.expiration().as_micros() <= now || actual.expiration().as_micros() <= now {
            return Err(Protocol::NotReady);
        }
        Ok(actual)
    }
    fn input_index(&self, id: Token<'id>) -> Result<usize, Protocol> {
        self.inputs
            .iter()
            .position(|r| r.token == id)
            .ok_or(Protocol::Stale)
    }
    fn output_index(&self, id: Token<'id>) -> Result<usize, Protocol> {
        self.outputs
            .iter()
            .position(|r| r.token == id)
            .ok_or(Protocol::Stale)
    }
    fn eligible(&self, n: &Neighbour<'id>) -> bool {
        self.neighbours.contains(n)
    }
    fn neighbour(&self, peer: PeerId) -> Option<&Neighbour<'id>> {
        self.neighbours.iter().find(|n| n.peer == peer)
    }
    fn used(&self) -> usize {
        retained_packet_bytes(&self.inputs, &self.outputs)
    }
    fn capacity(&self, n: usize, output: bool) -> Result<(), Protocol> {
        if (output && self.outputs.len() >= self.limits.outputs)
            || (!output && self.inputs.len() >= self.limits.inputs)
            || self
                .used()
                .checked_add(n)
                .is_none_or(|n| n > self.limits.bytes)
        {
            Err(Protocol::Capacity)
        } else {
            Ok(())
        }
    }
    /// Register only a real current direct queue from the caller's native port.
    /// A same peer/number after detach receives a distinct private lease.
    pub fn attach(
        &mut self,
        client: gnunet_transport::ClientId,
        peer: PeerId,
        queue: u32,
        reverse_link: bool,
    ) -> Result<Neighbour<'id>, Error> {
        self.live()?;
        self.now()?;
        if peer == self.source.local() {
            return Err(Protocol::InvalidInput.into());
        }
        if self
            .neighbours
            .iter()
            .any(|n| n.client == client && n.queue == queue)
        {
            return Err(Protocol::Conflict.into());
        }
        if self.neighbours.len() == self.limits.neighbours {
            return Err(Protocol::Capacity.into());
        }
        let n = Neighbour {
            token: self.token()?,
            client,
            peer,
            queue,
            reverse: reverse_link,
        };
        self.neighbours.push(n.clone());
        self.inputs_changed();
        Ok(n)
    }
    /// Revoke this exact original queue lease and paths, cancel matching retained
    /// inputs/outputs. New same-peer queues do not inherit old callbacks.
    pub fn detach(&mut self, n: &Neighbour<'id>) -> Result<(), Error> {
        let i = self
            .neighbours
            .iter()
            .position(|a| a == n)
            .ok_or(Protocol::Stale)?;
        self.neighbours.swap_remove(i);
        for p in 0..self.probes.len() {
            if &self.probes[p].neighbour == n && self.probes[p].probe.is_some() {
                let id = self.probes[p].token;
                self.retire_probe(id)?;
            }
        }
        if !self.neighbours.iter().any(|known| known.peer == n.peer) {
            self.routes.neighbour_lost(n.peer);
        }
        for i in 0..self.inputs.len() {
            if &self.inputs[i].neighbour == n {
                self.cancel_input_index(i)?;
            }
        }
        for i in 0..self.outputs.len() {
            if &self.outputs[i].neighbour == n {
                self.cancel_output_index(i, WriteOutcome::Lost(None))?;
            }
        }
        Ok(())
    }
    /// Accept exactly one physical original DV frame after fallible bounded copy.
    /// `origin` stays with this row until explicitly taken; no FC/CORE callback is
    /// sent here. Only actual direct queue identity is used for LEARN source checks.
    /// Refusal handling comes from its actual admission stage, never an error list.
    pub fn receive(
        &mut self,
        n: &Neighbour<'id>,
        origin: J,
        bytes: &[u8],
    ) -> Result<Token<'id>, InputRefused<J>> {
        self.receive_inner(n, origin, bytes, None)
    }
    /// Actual bridge entry when original Engine/native admission predates this
    /// actor call. Capacity retry keeps these SAME original two targets.
    pub fn receive_with_budget(
        &mut self,
        n: &Neighbour<'id>,
        origin: J,
        bytes: &[u8],
        original: Budget,
    ) -> Result<Token<'id>, InputRefused<J>> {
        self.receive_inner(n, origin, bytes, Some(original))
    }
    fn receive_inner(
        &mut self,
        n: &Neighbour<'id>,
        origin: J,
        bytes: &[u8],
        original: Option<Budget>,
    ) -> Result<Token<'id>, InputRefused<J>> {
        let admission: Result<_, admission::Failure> = (|| {
            self.live().map_err(admission::Failure::source)?;
            if let Some(original) = original {
                original
                    .check_native()
                    .map_err(|_| admission::Failure::expired())?;
            }
            if !self.eligible(n) {
                return Err(admission::Failure::rejected(Protocol::Stale));
            }
            if bytes.len() > self.limits.frame_bytes {
                return Err(admission::Failure::rejected(Protocol::TooLarge));
            }
            self.capacity(bytes.len(), false)
                .map_err(admission::Failure::deferred)?;
            let state = match admission::inspect(bytes, self.source.local(), n.peer)? {
                admission::Shape::Learn => InputState::Learn,
                admission::Shape::Box => InputState::Box,
            };
            // A Clock can return the same numeric error as a remote decoder or
            // a capacity refusal. Its failure still belongs to this Actor source.
            let now = self.now().map_err(admission::Failure::source)?;
            self.admission_identity(now)
                .map_err(admission::Failure::source)?;
            let mut bounds = self.bound(now).map_err(admission::Failure::source)?;
            if let Some(original) = original {
                bounds.until = bounds.until.min(original.until.as_micros());
                bounds.hard = bounds.hard.min(original.hard);
            }
            admission::check_bounds(&bounds, original, now)?;
            let bytes = copy(bytes).map_err(admission::Failure::deferred)?;
            // Exact reservations may still expose excess Vec capacity. Admit
            // only its actual retained allocation, before accepting the origin.
            self.capacity(bytes.capacity(), false)
                .map_err(admission::Failure::deferred)?;
            let token = self.token().map_err(admission::Failure::source)?;
            Ok((state, bounds, bytes, token))
        })();
        match admission {
            Err(failure) => Err(failure.with_origin(origin)),
            Ok((state, bounds, bytes, token)) => {
                self.inputs.push(InputRow {
                    token,
                    neighbour: n.clone(),
                    origin: Some(origin),
                    bytes,
                    received: std::time::Instant::now(),
                    bounds,
                    state,
                    forwards: 0,
                    planning: true,
                    disposition: Disposition::Dropped,
                    debt: None,
                });
                self.inputs_changed();
                Ok(token)
            }
        }
    }
    /// Register that caller has finished selecting LEARN forwards. A processed
    /// input remains retained until all its original selected outputs terminate.
    pub fn finish_learning(&mut self, id: Token<'id>) -> Result<(), Error> {
        let i = self.input_index(id)?;
        if !matches!(self.inputs[i].state, InputState::LearnReady) {
            return Err(Protocol::NotReady.into());
        }
        self.inputs[i].planning = false;
        self.maybe_finish(i);
        Ok(())
    }
    fn maybe_finish(&mut self, i: usize) {
        if !self.inputs[i].planning
            && self.inputs[i].forwards == 0
            && matches!(self.inputs[i].state, InputState::LearnReady)
        {
            self.inputs[i].state = InputState::Finished;
            self.inputs[i].disposition = Disposition::Learned;
            self.inputs_changed();
        }
    }
    /// Original actual grant, never an arbitrary parsed inner frame. Borrowing
    /// this does not complete Engine admission or its original outer FC debt.
    pub fn delivery(
        &mut self,
        id: Token<'id>,
    ) -> Result<&box_admission::Granted<'source, 'id, 'out>, Error> {
        let logical = self.now()?;
        let i = self.input_index(id)?;
        self.inputs[i]
            .bounds
            .check(logical)
            .map_err(|_| Error::TaskBudgetExpired)?;
        let checked = match &self.inputs[i].state {
            InputState::Granted(g) => g.message().map(|_| ()).map_err(Error::Box),
            _ => return Err(Protocol::NotReady.into()),
        };
        if let Err(error) = checked {
            if matches!(&error, Error::Box(box_admission::Reason::Deadline)) {
                return Err(Error::TaskBudgetExpired);
            }
            if matches!(&error, Error::Box(box_admission::Reason::Clock(_))) {
                self.close();
            }
            return Err(error);
        }
        match &self.inputs[i].state {
            InputState::Granted(g) => Ok(g),
            _ => Err(Protocol::Conflict.into()),
        }
    }
    /// Called only after the external actual Engine accepted this SAME grant's
    /// immutable inner bytes. Consumes grant, recycles buffer, retains original
    /// input attribution for the native FC owner; no private ACK is generated.
    pub fn delivered(&mut self, id: Token<'id>) -> Result<(), Error> {
        let i = self.input_index(id)?;
        if !matches!(self.inputs[i].state, InputState::Granted(_)) {
            return Err(Protocol::NotReady.into());
        }
        let InputState::Granted(g) =
            core::mem::replace(&mut self.inputs[i].state, InputState::Finished)
        else {
            return Err(Protocol::Conflict.into());
        };
        let (buffer, _, _, _) = g.recycle().into_parts();
        self.buffers.push(buffer);
        self.inputs[i].disposition = Disposition::Delivered;
        self.inputs_changed();
        Ok(())
    }
    /// Borrow original immutable frame while source, deadline and selected queue
    /// are still live. No local/remote write progress is implied.
    pub fn output(&mut self, id: Token<'id>) -> Result<Output<'_, 'id>, Error> {
        self.live()?;
        let logical = self.now()?;
        let r = &self.outputs[self.output_index(id)?];
        r.bounds
            .check(logical)
            .map_err(|_| Error::TaskBudgetExpired)?;
        if !self.eligible(&r.neighbour)
            || !matches!(r.state, OutputState::Ready)
            || ordered_predecessor(&self.outputs, r)
        {
            return Err(Protocol::NotReady.into());
        }
        Ok(Output {
            token: id,
            neighbour: &r.neighbour,
            bytes: &r.bytes,
            without_fc: r.without_fc,
            hard: r.bounds.hard,
            until: gnunet_wire::official::AbsoluteTime::from_micros(r.bounds.until),
        })
    }
    /// Actual native immutable-frame queue admission, separate from first byte.
    /// Call synchronously after the real enqueue following output() preflight;
    /// no await/owner teardown may intervene. This completion samples no clock.
    pub fn queued(&mut self, id: Token<'id>) -> Result<(), Error> {
        let i = self.output_index(id)?;
        if !matches!(self.outputs[i].state, OutputState::Ready) || self.outputs[i].queued {
            return Err(Protocol::Conflict.into());
        }
        if ordered_predecessor(&self.outputs, &self.outputs[i]) {
            return Err(Protocol::NotReady.into());
        }
        self.outputs[i].queued = true;
        Ok(())
    }
    /// Actual positive byte write for this original frame. Never remote receipt.
    pub fn exposed(&mut self, id: Token<'id>) -> Result<(), Error> {
        let i = self.output_index(id)?;
        if !self.outputs[i].queued || self.outputs[i].state.outcome().is_some() {
            return Err(Protocol::Conflict.into());
        }
        self.outputs[i].exposed = true;
        Ok(())
    }
    /// Original actual physical completion. A written probe starts its real RTT
    /// clock here. The original encoded frame is never resealed on partial retry.
    pub fn written(&mut self, id: Token<'id>) -> Result<(), Error> {
        let i = self.output_index(id)?;
        if !self.outputs[i].queued || self.outputs[i].state.outcome().is_some() {
            return Err(Protocol::Conflict.into());
        }
        self.outputs[i].exposed = true;
        // Record the actual whole local write before fallible RTT, clock or
        // probe bookkeeping. No observation failure can revoke this callback.
        self.finish_output(i, WriteOutcome::Written);
        let mut errors = cancellation::Errors::default();
        if self
            .probes
            .iter()
            .any(|p| p.token == id && Instant::now() >= p.budget.hard)
        {
            errors.record(self.retire_probe_book(id));
        }
        if let Some(probe) = self.outputs[i].probe {
            let observation = self
                .monotonic()
                .and_then(|at| self.routes.probe_written(probe, at))
                .map_err(Error::from);
            if let Err(error) = observation {
                // Expired RTT interest is independent of the written packet.
                if !matches!(error, Error::Protocol(Protocol::Deadline)) {
                    errors.record(Err(error));
                }
                errors.record(self.retire_probe_book(id));
            }
        }
        errors.finish(&mut self.cleanup)
    }
    /// Caller reports that the original physical output owner actually ended,
    /// preserving unknown exposure. This includes source loss and an incomplete
    /// logical output whose actual chunks all ended; it does not assert that
    /// the shared source closed. Canceling a wait future must NOT call this.
    pub fn output_lost(&mut self, id: Token<'id>, exposed: Option<bool>) -> Result<(), Error> {
        let i = self.output_index(id)?;
        if self.outputs[i].state.outcome().is_some() {
            return Err(Protocol::Stale.into());
        }
        if self.outputs[i].exposed && exposed == Some(false) {
            return Err(Protocol::Conflict.into());
        }
        let exposed = if self.outputs[i].exposed {
            Some(true)
        } else {
            exposed
        };
        let cleanup = self.cancel_output_index(i, WriteOutcome::Lost(exposed));
        if self.outputs[i].state.outcome().is_none() {
            self.finish_output(i, WriteOutcome::Lost(exposed));
        }
        // The external physical owner already ended. Its one real callback
        // cannot be consumed without the terminal fact when cleanup refuses.
        cleanup
    }
    fn finish_output(&mut self, i: usize, outcome: WriteOutcome) {
        // A child completion can release an input, a replay reservation or
        // shared plaintext capacity that an earlier row could not acquire.
        self.inputs_changed();
        let id = self.outputs[i].token;
        if let Some(p) = self.probes.iter_mut().find(|p| p.token == id) {
            p.outcome = Some(outcome);
            if outcome == WriteOutcome::Written {
                p.sent = true;
            }
        }
        self.outputs[i].state = OutputState::Finished(outcome);
        if let Some(parent) = self.outputs[i].parent
            && let Ok(p) = self.input_index(parent)
            && self.inputs[p].child_finished(outcome)
        {
            self.maybe_finish(p)
        }
    }
    /// Take only terminated original input metadata; returned disk debt still
    /// belongs to Provider until its actual event/join, never a fake rollback.
    pub fn take_finished(&mut self, id: Token<'id>) -> Result<Finished<'id, J>, Error> {
        let i = self.input_index(id)?;
        if !matches!(self.inputs[i].state, InputState::Finished) || self.inputs[i].forwards != 0 {
            return Err(Protocol::NotReady.into());
        }
        let r = self.inputs.swap_remove(i);
        self.inputs_changed();
        Ok(Finished {
            origin: r.origin.ok_or(Protocol::Conflict)?,
            disposition: r.disposition,
            disk_debt: r.debt,
        })
    }
    /// Synchronously hand off only this terminated output's external origin.
    /// The original row, neighbour, outcome, bytes and bounds stay in this slot
    /// until the handoff succeeds. A refusal must return the SAME origin; it is
    /// restored without changing row order, scan debt or any physical fact.
    /// The closure cannot reenter this Runtime or await native work.
    pub fn try_take_output_finished<E>(
        &mut self,
        id: Token<'id>,
        handoff: impl FnOnce(Option<J>) -> Result<Option<J>, (E, Option<J>)>,
    ) -> Result<Result<OutputFinished<'id, J>, E>, Error> {
        let i = self.output_index(id)?;
        let result = output_completion::try_take(&mut self.outputs, i, handoff)?;
        if result.is_ok() {
            self.inputs_changed();
        }
        Ok(result)
    }
    /// Take exact terminated original local output fact without retagging it.
    /// Validate its outcome before removing the original non-clone owner.
    pub fn take_output_finished(
        &mut self,
        id: Token<'id>,
    ) -> Result<OutputFinished<'id, J>, Error> {
        match self.try_take_output_finished(id, |origin| {
            Ok::<_, (core::convert::Infallible, Option<J>)>(origin)
        })? {
            Ok(output) => Ok(output),
            Err(never) => match never {},
        }
    }
    /// Actually sign a fresh purpose37 probe to one eligible direct queue. Stamp
    /// comes from caller's real reservation authority; raw u64 is NOT described
    /// as durable evidence. Fresh challenge comes only from explicit entropy.
    pub fn probe(
        &mut self,
        n: &Neighbour<'id>,
        stamp: u64,
        entropy: &mut impl Entropy,
    ) -> Result<Token<'id>, Error> {
        self.probe_inner(n, stamp, entropy, None)
    }
    /// Use the SAME original scheduler/worker budget; check native hard before
    /// any clock sample, entropy, key operation or PILS request admission.
    pub fn probe_with_budget(
        &mut self,
        n: &Neighbour<'id>,
        stamp: u64,
        entropy: &mut impl Entropy,
        original: Budget,
    ) -> Result<Token<'id>, Error> {
        self.probe_inner(n, stamp, entropy, Some(original))
    }
    fn probe_inner(
        &mut self,
        n: &Neighbour<'id>,
        stamp: u64,
        entropy: &mut impl Entropy,
        original: Option<Budget>,
    ) -> Result<Token<'id>, Error> {
        if let Some(original) = original {
            original.check_native()?;
        }
        self.live()?;
        if self.probes.len() == self.probe_capacity {
            return Err(Protocol::Capacity.into());
        }
        if !self.eligible(n) {
            return Err(Protocol::Stale.into());
        }
        self.capacity(dv::LEARN_PREFIX, true)?;
        let logical = self.now()?;
        let mut bounds = self.bound(logical)?;
        if let Some(original) = original {
            bounds.until = bounds.until.min(original.until.as_micros());
            bounds.hard = bounds.hard.min(original.hard);
        }
        bounds.check(logical)?;
        let target = self.admission_identity(logical)?;
        let task = self.source.task(stamp, logical, bounds.until)?;
        let mut challenge = [0; 32];
        entropy
            .fill(&mut challenge)
            .map_err(|_| Protocol::Entropy)?;
        let bytes = sized(dv::LEARN_PREFIX)?;
        self.capacity(bytes.capacity(), true)?;
        let token = self.token()?;
        let probe = self
            .routes
            .begin_probe(challenge, stamp, self.monotonic()?)?;
        let operation = match self.client.sign(
            &dv::init_region(stamp, &challenge),
            KeyTarget::Exact(target),
        ) {
            Ok(op) => op,
            Err(e) => {
                if let Err(cleanup) = self.routes.retire_probe(probe) {
                    self.remember(cleanup.into());
                }
                return Err(e.into());
            }
        };
        self.probes.push(ProbeTrack {
            token,
            neighbour: n.clone(),
            probe: Some(probe),
            budget: Budget {
                until: gnunet_wire::official::AbsoluteTime::from_micros(bounds.until),
                hard: bounds.hard,
            },
            sent: false,
            outcome: None,
        });
        self.outputs.push(OutputRow {
            token,
            neighbour: n.clone(),
            origin: None,
            parent: None,
            bounds,
            state: OutputState::Probe {
                task,
                operation,
                challenge,
            },
            bytes,
            without_fc: true,
            ordered_target: None,
            exposed: false,
            queued: false,
            probe: Some(probe),
        });
        Ok(token)
    }
    /// Actually admit purpose36 for this signature-verified original LEARN and
    /// chosen actual successor. Every fork has independent bounded original
    /// output/PILS ownership; immutable input remains held until all terminate.
    pub fn forward_learn(
        &mut self,
        input: Token<'id>,
        next: &Neighbour<'id>,
        reverse: bool,
    ) -> Result<Token<'id>, Error> {
        self.live()?;
        if !self.eligible(next) {
            return Err(Protocol::Stale.into());
        }
        let i = self.input_index(input)?;
        if !matches!(self.inputs[i].state, InputState::LearnReady) || !self.inputs[i].planning {
            return Err(Protocol::NotReady.into());
        }
        let verified = dv::Learn::decode(&self.inputs[i].bytes)?
            .verify(self.source.local(), self.inputs[i].neighbour.peer)?;
        let packet = verified.packet();
        if next.peer == self.inputs[i].neighbour.peer || packet.hop_count() == dv::MAX_HOPS {
            return Err(Protocol::InvalidInput.into());
        }
        for h in 0..packet.hop_count() {
            if packet.hop(h)?.peer == next.peer {
                return Err(Protocol::Malformed.into());
            }
        }
        // Returning to the original initiator is a real probe completion path.
        let len = self.inputs[i]
            .bytes
            .len()
            .checked_add(dv::HOP_BYTES)
            .ok_or(Protocol::Overflow)?;
        if len > self.limits.frame_bytes {
            return Err(Protocol::TooLarge.into());
        }
        let stamp = packet.stamp()?;
        let challenge = packet.challenge()?;
        self.capacity(len, true)?;
        let logical = self.now()?;
        self.inputs[i]
            .bounds
            .check(logical)
            .map_err(|_| Error::TaskBudgetExpired)?;
        let target = self.admission_identity(logical)?;
        let task = self
            .source
            .task(stamp, logical, self.inputs[i].bounds.until)?;
        let bytes = sized(len)?;
        self.capacity(bytes.capacity(), true)?;
        let token = self.token()?;
        let operation = self.client.sign(
            &dv::hop_region(self.inputs[i].neighbour.peer, next.peer, &challenge),
            KeyTarget::Exact(target),
        )?;
        self.inputs[i].forwards = self.inputs[i]
            .forwards
            .checked_add(1)
            .ok_or(Protocol::Overflow)?;
        self.outputs.push(OutputRow {
            token,
            neighbour: next.clone(),
            origin: None,
            parent: Some(input),
            bounds: Bound {
                until: self.inputs[i].bounds.until,
                hard: self.inputs[i].bounds.hard,
            },
            state: OutputState::Forward {
                task,
                operation,
                reverse,
            },
            bytes,
            without_fc: true,
            ordered_target: None,
            exposed: false,
            queued: false,
            probe: None,
        });
        Ok(token)
    }
    /// Whether this source still owns a certification job for this exact target.
    /// Readonly metadata for fair admission selection; it samples no clock and
    /// grants no source liveness, completed signature or native send admission.
    pub fn send_material_pending(&self, target: PeerId) -> bool {
        self.outputs.iter().any(|output| {
            matches!(&output.state, OutputState::Seal { job, .. } if job.target() == target)
        })
    }
    /// Real eligible-route selection -> fixed material lookup/PILS purpose30 ->
    /// AEAD official BOX. Clear input is retained only until actual seal. No raw
    /// LEARN/BOX nesting is accepted; partial writes never trigger another seal.
    pub fn send(
        &mut self,
        target: PeerId,
        origin: J,
        message: &[u8],
        stamp: u64,
        entropy: &mut impl Entropy,
    ) -> Result<Token<'id>, Refused<J>> {
        self.send_inner(
            SendOptions {
                target,
                stamp,
                without_fc: false,
                original: None,
                policy: SendPolicy::Bidirectional,
                route: None,
            },
            origin,
            message,
            entropy,
        )
    }
    /// Preserve original actual CORE/Engine job targets across route/cache/PILS
    /// waiting. Earlier waits never become a fresh actor-relative lifetime.
    pub fn send_with_budget(
        &mut self,
        target: PeerId,
        origin: J,
        message: &[u8],
        stamp: u64,
        entropy: &mut impl Entropy,
        original: Budget,
    ) -> Result<Token<'id>, Refused<J>> {
        self.send_inner(
            SendOptions {
                target,
                stamp,
                without_fc: false,
                original: Some(original),
                policy: SendPolicy::Bidirectional,
                route: None,
            },
            origin,
            message,
            entropy,
        )
    }
    /// Admit a real original Engine packet, preserving control flags, original
    /// budgets, explicit evidence policy and optional exact eligible route.
    pub fn send_with_options(
        &mut self,
        options: SendOptions<'id>,
        origin: J,
        message: &[u8],
        entropy: &mut impl Entropy,
    ) -> Result<Token<'id>, Refused<J>> {
        self.send_inner(options, origin, message, entropy)
    }
    fn send_inner(
        &mut self,
        options: SendOptions<'id>,
        origin: J,
        message: &[u8],
        entropy: &mut impl Entropy,
    ) -> Result<Token<'id>, Refused<J>> {
        let SendOptions {
            target,
            stamp,
            without_fc,
            original,
            policy,
            route: expected_route,
        } = options;
        let admission: Result<_, Error> = (|| {
            self.live()?;
            if let Some(original) = original {
                original.check_native()?;
            }
            let frame = Frame::decode(message)?;
            if matches!(
                frame.header().message_type().value(),
                dv::LEARN_TYPE | dv::BOX_TYPE
            ) {
                return Err(Protocol::Malformed.into());
            }
            let neighbours = &self.neighbours;
            let now = self.monotonic()?;
            let route = match expected_route {
                Some(expected) => self
                    .routes
                    .select_id(expected, target, policy, now, |p| {
                        neighbours.iter().any(|n| n.peer == p)
                    })
                    .map_err(|error| match error {
                        Protocol::StaleGeneration => Protocol::Stale,
                        other => other,
                    })?,
                None => self
                    .routes
                    .select(target, policy, now, |p| {
                        neighbours.iter().any(|n| n.peer == p)
                    })?
                    .ok_or(Protocol::NotReady)?,
            };
            if route.path.is_empty() {
                return Err(Protocol::Conflict.into());
            }
            let first = route.path[0];
            let route_hard = Instant::from_std(self.anchor)
                .checked_add(std::time::Duration::from_micros(route.until.0))
                .ok_or(Protocol::Overflow)?
                .min(self.source_hard);
            if Instant::now() >= route_hard {
                return Err(Protocol::Deadline.into());
            }
            let mut path = Vec::new();
            path.try_reserve_exact(route.path.len() - 1)
                .map_err(|_| Protocol::Capacity)?;
            path.extend_from_slice(&route.path[1..]);
            let n = self.neighbour(first).ok_or(Protocol::Stale)?.clone();
            let size = dv::BOX_PREFIX
                .checked_add(path.len() * 32)
                .and_then(|v| v.checked_add(dv::PAYLOAD_PREFIX + message.len()))
                .ok_or(Protocol::Overflow)?;
            if size > self.limits.frame_bytes {
                return Err(Protocol::TooLarge.into());
            }
            // Cache hits retain only the output allocation. A real miss
            // charges its copied plaintext separately before job admission.
            self.capacity(size, true)?;
            let logical = self.now()?;
            let mut bounds = self.bound(logical)?;
            bounds.hard = bounds.hard.min(route_hard);
            if let Some(original) = original {
                bounds.until = bounds.until.min(original.until.as_micros());
                bounds.hard = bounds.hard.min(original.hard);
            }
            bounds.check(logical)?;
            let candidate = self.send.find(self.source, target, logical)?;
            // One original certification per target may be in flight. A
            // second command keeps its original Engine packet/budget until
            // this job completes or retires; no output buffer or competing
            // certificate is allocated for this zero-admission refusal.
            if candidate.is_none() && self.send_material_pending(target) {
                return Err(Protocol::WouldBlock.into());
            }
            let token = self.token()?;
            let mut bytes = sized(size)?;
            self.capacity(bytes.capacity(), true)?;
            // Allocation can take time after lookup. Recheck the original
            // epoch at actual use; expiration is a real miss, never a shorter
            // packet lifetime or a replacement of its original budget.
            bounds.check(logical)?;
            let sealed = if let Some(hit) = candidate {
                let task = self.source.task(hit.stamp(), logical, bounds.until)?;
                self.send.seal(
                    hit,
                    task,
                    logical,
                    cache::Packet {
                        route: &path,
                        without_fc,
                        message,
                    },
                    self.scratch,
                    &mut bytes,
                )?
            } else {
                None
            };
            let state = if sealed.is_some() {
                OutputState::Ready
            } else {
                let lease = self.material_lease(logical)?;
                let task = self.source.task(stamp, logical, lease.until)?;
                self.capacity(
                    bytes
                        .capacity()
                        .checked_add(message.len())
                        .ok_or(Protocol::Overflow)?,
                    true,
                )?;
                let message = Zeroizing::new(copy(message)?);
                self.capacity(
                    bytes
                        .capacity()
                        .checked_add(message.capacity())
                        .ok_or(Protocol::Overflow)?,
                    true,
                )?;
                let prepared = task.prepare_seal(target, logical, entropy)?;
                lease.check(logical)?;
                let job = SealJob::begin(
                    prepared,
                    &mut self.client,
                    self.identity,
                    logical,
                    bounds.operation(),
                )?;
                OutputState::Seal {
                    job: Box::new(job),
                    lease,
                    message,
                    route: path,
                }
            };
            Ok((token, n, bounds, state, bytes))
        })();
        match admission {
            Err(error) => Err(Refused { origin, error }),
            Ok((token, neighbour, bounds, state, bytes)) => {
                self.outputs.push(OutputRow {
                    token,
                    neighbour,
                    origin: Some(origin),
                    parent: None,
                    bounds,
                    state,
                    bytes,
                    without_fc,
                    ordered_target: (!without_fc).then_some(target),
                    exposed: false,
                    queued: false,
                    probe: None,
                });
                Ok(token)
            }
        }
    }
    fn accept_learn(&mut self, i: usize, now: MonoInstant) -> Result<Option<Step<'id>>, Error> {
        let verified = dv::Learn::decode(&self.inputs[i].bytes)?
            .verify(self.source.local(), self.inputs[i].neighbour.peer)?;
        match self
            .routes
            .accept(verified, self.inputs[i].neighbour.reverse, now)?
        {
            dv::routes::Admission::Routes { changed, freshness } => {
                self.inputs[i].state = InputState::LearnReady;
                Ok(Some(Step::LearnReady {
                    input: self.inputs[i].token,
                    changed,
                    freshness,
                }))
            }
            dv::routes::Admission::Pending => Ok(None),
            dv::routes::Admission::Source(work) => {
                self.inputs[i].state = InputState::LearnWork(work);
                Ok(Some(Step::Activity))
            }
        }
    }
    fn source_work(
        &mut self,
        i: usize,
        work: dv::routes::SourceWork<'id>,
    ) -> Result<Option<Step<'id>>, Error> {
        match work {
            dv::routes::SourceWork::Load { .. } => match self.provider.load(work.into()) {
                Ok(loaded) => {
                    loaded.apply_learn(&mut self.routes)?;
                    self.inputs[i].state = InputState::Learn;
                    Ok(Some(Step::Activity))
                }
                Err(e) if matches!(&e.cause, store::Cause::Protocol(Protocol::WouldBlock)) => {
                    Ok(None)
                }
                Err(e) => Err(e.into()),
            },
            dv::routes::SourceWork::Store { .. } => match self.provider.store(work.into()) {
                Ok(store::Admission::Known(actual)) => {
                    actual.apply_learn(&mut self.routes)?;
                    self.inputs[i].state = InputState::Learn;
                    Ok(Some(Step::Activity))
                }
                Ok(store::Admission::Queued { operation, .. }) => {
                    self.inputs[i].state = InputState::LearnStore(operation);
                    Ok(Some(Step::Activity))
                }
                Err(e) if matches!(&e.cause, store::Cause::Protocol(Protocol::WouldBlock)) => {
                    Ok(None)
                }
                Err(e) => Err(e.into()),
            },
        }
    }
    fn start_box(&mut self, i: usize, now: u64) -> Result<Option<Step<'id>>, Error> {
        let packet = dv::BoxPacket::decode(&self.inputs[i].bytes)?;
        if packet.hop_count() > 0 {
            forward::start(
                &mut self.inputs[i],
                &mut self.outputs,
                &self.neighbours,
                self.instance,
                self.source.local(),
                now,
                self.limits.outputs,
            )
            .map(|token| token.map(Step::OutputReady))
            .map_err(Error::from)
        } else {
            let encapsulation = packet.encapsulation()?;
            self.inputs[i].bounds.check(now)?;
            let candidate = self.receive.find(self.source, &encapsulation, now)?;
            if let Some(material) = candidate {
                self.inputs[i].state = InputState::Material(material);
            } else {
                let lease = self.material_lease(now)?;
                let task = self.source.task(0, now, lease.until)?;
                let job = ReceiveJob::begin(
                    task,
                    encapsulation,
                    &mut self.client,
                    self.identity,
                    now,
                    self.inputs[i].bounds.operation(),
                )?;
                self.inputs[i].state = InputState::Decapsulating { job, lease };
            }
            Ok(Some(Step::Activity))
        }
    }
    fn authenticate_box(
        &mut self,
        i: usize,
        material: cache::ReceiveId<'id>,
        now: u64,
    ) -> Result<Option<Step<'id>>, Error> {
        self.inputs[i].bounds.check(now)?;
        if !self.receive.live(material, now)? {
            self.inputs[i].state = InputState::Box;
            return Ok(Some(Step::Activity));
        }
        let packet = dv::BoxPacket::decode(&self.inputs[i].bytes)?;
        let used = packet
            .ciphertext()
            .len()
            .checked_sub(dv::PAYLOAD_PREFIX)
            .ok_or(Protocol::Truncated)?;
        let Some(b) = self.buffers.iter().position(|b| b.len() >= used) else {
            return Ok(None);
        };
        // Bounds subscription is reserved BEFORE consuming the caller loan.
        let bounds = box_admission::Bounds::new(self.clock.clone(), self.inputs[i].bounds.hard)
            .map_err(Error::Box)?;
        let task = self.source.task(0, now, self.inputs[i].bounds.until)?;
        let request = task.prepare_open(packet, now)?;
        self.inputs[i].bounds.check(now)?;
        let buffer = self.buffers.swap_remove(b);
        let opened = match self
            .receive
            .open(material, request, now, self.scratch, buffer)
        {
            material::ReceiveUse::Opened(opened) => opened,
            material::ReceiveUse::Miss(buffer) => {
                self.buffers.push(buffer);
                self.inputs[i].state = InputState::Box;
                return Ok(Some(Step::Activity));
            }
            material::ReceiveUse::Failed { error, buffer } => {
                self.buffers.push(buffer);
                return Err(error.into());
            }
        };
        self.inputs[i].state = match box_admission::start(&mut self.provider, opened, bounds) {
            box_admission::Start::Ready(r) => InputState::Ready(r),
            box_admission::Start::Waiting(w) => InputState::Waiting(w),
            box_admission::Start::Refused(r) => InputState::Refused(r),
        };
        Ok(Some(Step::Activity))
    }
    fn promote(&mut self, i: usize) -> Result<Option<Step<'id>>, Error> {
        let state = core::mem::replace(&mut self.inputs[i].state, InputState::Finished);
        match state {
            InputState::Ready(ready) => match ready.grant(&mut self.provider, &mut self.replay) {
                box_admission::Grant::Admitted(g) => {
                    self.inputs[i].state = InputState::Granted(g);
                    Ok(Some(Step::DeliveryReady(self.inputs[i].token)))
                }
                box_admission::Grant::Refused { ready, .. } => {
                    self.inputs[i].state = InputState::Ready(ready);
                    Ok(None)
                }
                box_admission::Grant::Rejected(r) => {
                    self.inputs[i].state = InputState::Refused(r);
                    Ok(Some(Step::Activity))
                }
                box_admission::Grant::Closed(recycled) => {
                    let (buffer, _, reason, debt) = recycled.into_parts();
                    self.buffers.push(buffer);
                    self.inputs[i].debt = debt;
                    Err(Error::Box(
                        reason.unwrap_or(box_admission::Reason::Canceled),
                    ))
                }
            },
            InputState::Refused(r) => {
                let retry = matches!(r.reason(),box_admission::Reason::Store(e) if matches!(e.cause,store::Cause::Protocol(Protocol::WouldBlock)))
                    && r.debt().is_none();
                if retry {
                    self.inputs[i].state = match r.retry(&mut self.provider) {
                        box_admission::Start::Ready(r) => InputState::Ready(r),
                        box_admission::Start::Waiting(w) => InputState::Waiting(w),
                        box_admission::Start::Refused(r) => InputState::Refused(r),
                    };
                    Ok(None)
                } else {
                    let (buffer, _, reason, debt) = r.recycle().into_parts();
                    self.buffers.push(buffer);
                    self.inputs[i].debt = debt;
                    Err(Error::Box(
                        reason.unwrap_or(box_admission::Reason::Canceled),
                    ))
                }
            }
            other => {
                self.inputs[i].state = other;
                Err(Protocol::Conflict.into())
            }
        }
    }
    fn completion(&mut self, result: &Completion<'pils>, logical: u64) -> Result<Step<'id>, Error> {
        let op = result.operation();
        if let Some(i) = self.inputs.iter().position(
            |r| matches!(&r.state,InputState::Decapsulating { job, .. } if job.operation()==op),
        ) {
            let context = self.input_failure(i, Instant::now(), Some(logical));
            let state = core::mem::replace(&mut self.inputs[i].state, InputState::Finished);
            self.inputs_changed();
            let InputState::Decapsulating { job, lease } = state else {
                return Err(Protocol::Conflict.into());
            };
            let token = self.inputs[i].token;
            let completed = (|| {
                // Completion of a longer-lived material Task does not authorize
                // installation for an expired original packet operation.
                material::check_install(&self.inputs[i].bounds, lease, logical)?;
                let material = job.complete(result, logical)?;
                material::check_install(&self.inputs[i].bounds, lease, logical)?;
                Ok::<_, Error>(material)
            })();
            let material = match completed {
                Ok(material) => material,
                Err(error) => {
                    self.inputs[i].planning = false;
                    return Ok(Step::Failed {
                        token,
                        error,
                        context,
                    });
                }
            };
            let id = match self
                .receive
                .install(material, lease, &self.inputs[i].bounds, logical)
            {
                Ok(id) => id,
                Err(error) => {
                    self.inputs[i].planning = false;
                    return Ok(Step::Failed {
                        token,
                        error: error.into(),
                        context,
                    });
                }
            };
            self.inputs[i].state = InputState::Material(id);
            return Ok(Step::Activity);
        }
        if let Some(i) = self.outputs.iter().position(|r| match &r.state {
            OutputState::Probe { operation, .. } | OutputState::Forward { operation, .. } => {
                *operation == op
            }
            OutputState::Seal { job, .. } => job.operation() == op,
            _ => false,
        }) {
            let token = self.outputs[i].token;
            let context = self.output_failure(i, Instant::now(), Some(logical));
            let state = core::mem::replace(&mut self.outputs[i].state, OutputState::Ready);
            self.inputs_changed();
            let completed = (|| {
                self.outputs[i].bounds.check(logical)?;
                match state {
                    OutputState::Probe {
                        task,
                        operation,
                        challenge,
                    } => {
                        task.check(logical)?;
                        let sig = signature(
                            result,
                            operation,
                            self.identity,
                            self.source.local(),
                            logical,
                        )?;
                        EddsaPublicKey::from_bytes(self.source.local().0).verify(
                            dv::INIT_PURPOSE,
                            &dv::init_region(task.stamp(), &challenge),
                            sig,
                        )?;
                        self.outputs[i].bytes.copy_from_slice(&dv::initiate(
                            self.source.local(),
                            task.stamp(),
                            &challenge,
                            sig.as_bytes(),
                        ));
                    }
                    OutputState::Forward {
                        task,
                        operation,
                        reverse,
                    } => {
                        task.check(logical)?;
                        let parent = self.outputs[i].parent.ok_or(Protocol::Conflict)?;
                        let p = self.input_index(parent)?;
                        self.inputs[p].bounds.check(logical)?;
                        let packet = dv::Learn::decode(&self.inputs[p].bytes)?
                            .verify(self.source.local(), self.inputs[p].neighbour.peer)?
                            .packet();
                        let sig = signature(
                            result,
                            operation,
                            self.identity,
                            self.source.local(),
                            logical,
                        )?;
                        let region = dv::hop_region(
                            self.inputs[p].neighbour.peer,
                            self.outputs[i].neighbour.peer,
                            &packet.challenge()?,
                        );
                        EddsaPublicKey::from_bytes(self.source.local().0).verify(
                            dv::HOP_PURPOSE,
                            &region,
                            sig,
                        )?;
                        let elapsed = self.inputs[p].received.elapsed().as_micros();
                        let delay = u64::try_from(elapsed).map_err(|_| Protocol::Overflow)?;
                        packet.forward(
                            dv::Hop {
                                peer: self.source.local(),
                                signature: *sig.as_bytes(),
                            },
                            reverse,
                            delay,
                            &mut self.outputs[i].bytes,
                        )?;
                    }
                    OutputState::Seal {
                        job,
                        lease,
                        message,
                        route,
                    } => {
                        material::check_install(&self.outputs[i].bounds, lease, logical)?;
                        let material =
                            (*job).certify(result, logical, self.limits.material_messages)?;
                        material::check_install(&self.outputs[i].bounds, lease, logical)?;
                        let hit =
                            self.send
                                .install(material, lease, &self.outputs[i].bounds, logical)?;
                        let task =
                            self.source
                                .task(hit.stamp(), logical, self.outputs[i].bounds.until)?;
                        self.send
                            .seal(
                                hit,
                                task,
                                logical,
                                cache::Packet {
                                    route: &route,
                                    without_fc: self.outputs[i].without_fc,
                                    message: &message,
                                },
                                self.scratch,
                                &mut self.outputs[i].bytes,
                            )?
                            .ok_or(Protocol::NotReady)?;
                    }
                    _ => return Err(Error::Protocol(Protocol::Conflict)),
                };
                Ok(())
            })();
            match completed {
                Ok(()) => {
                    self.outputs[i].state = OutputState::Ready;
                    return Ok(Step::OutputReady(token));
                }
                Err(error) => {
                    if self.outputs[i].probe.is_some()
                        && let Err(cleanup) = self.retire_probe_book(token)
                    {
                        self.remember(cleanup)
                    }
                    self.finish_output(i, WriteOutcome::Unsent);
                    return Ok(Step::Failed {
                        token,
                        error,
                        context,
                    });
                }
            }
        }
        // The existing native owner independently consumed a canceled/late result.
        Ok(Step::Activity)
    }
    fn store_event(&mut self, event: &store::Event<'id>) -> Result<(), Error> {
        for i in 0..self.inputs.len() {
            if let InputState::LearnStore(op) = &self.inputs[i].state {
                let matches = match event {
                    store::Event::Committed(p) => p.operation() == op,
                    store::Event::Failed {
                        operation: Some(actual),
                        ..
                    } => actual == op,
                    store::Event::Ended => true,
                    _ => false,
                };
                if matches {
                    match event {
                        store::Event::Committed(p) => {
                            p.apply_learn(&mut self.routes)?;
                            self.inputs[i].state = InputState::Learn
                        }
                        _ => {
                            if let store::Owner::Learn(source) = op.request().owner() {
                                self.routes.source_lost(source)?;
                            }
                            self.inputs[i].state = InputState::Finished;
                            self.inputs[i].planning = false;
                        }
                    }
                }
            }
            let state = core::mem::replace(&mut self.inputs[i].state, InputState::Finished);
            self.inputs[i].state = match state {
                InputState::Waiting(waiting) => match waiting.observe(&mut self.provider, event) {
                    box_admission::Observation::Unrelated(w) => InputState::Waiting(w),
                    box_admission::Observation::Ready(r) => InputState::Ready(r),
                    box_admission::Observation::Refused(r) => InputState::Refused(r),
                    box_admission::Observation::Closed => InputState::Finished,
                },
                other => other,
            };
        }
        Ok(())
    }
    fn retain_cancel(
        &mut self,
        operation: OperationId<'pils>,
        original: Instant,
    ) -> Result<(), Error> {
        if self.closed {
            // The same original native Client was already physically closed.
            return Ok(());
        }
        let canceled = self.client.cancel(operation).map_err(Error::from);
        self.finish_pils_cancel(operation, original, canceled)
    }
    fn finish_pils_cancel(
        &mut self,
        operation: OperationId<'pils>,
        original: Instant,
        canceled: Result<(), Error>,
    ) -> Result<(), Error> {
        // Cancellation and native quiescence are independent observations.
        // Even a refused cancellation cannot bypass the original copied frame.
        let quiescent = self
            .client
            .operation_quiescent(operation)
            .map_err(Error::from);
        let actual = cancellation::retain(
            &mut self.retiring,
            operation,
            original,
            self.limits.retirement_grace,
            N,
            canceled,
            quiescent,
        );
        if actual.fence {
            // No ledger room or trustworthy quiescence: physically retire this
            // original PILS source. External TRANSPORT writes stay independent.
            self.stop_native();
        }
        actual.errors.finish(&mut self.cleanup)
    }
    fn cancel_input_index(&mut self, i: usize) -> Result<(), Error> {
        if matches!(self.inputs[i].state, InputState::Finished) {
            return Ok(());
        }
        let was_closed = self.closed;
        let mut errors = cancellation::Errors::default();
        let state = core::mem::replace(&mut self.inputs[i].state, InputState::Finished);
        self.inputs_changed();
        self.inputs[i].planning = false;
        self.inputs[i].disposition = Disposition::Dropped;
        match state {
            InputState::Decapsulating { job, .. } => {
                let op = job.operation();
                let until = self.inputs[i].bounds.hard;
                if !self.closed {
                    // The original operation survives consumption/refusal of
                    // its wrapper until actually quiescent or source-fenced.
                    let canceled = job
                        .cancel(&mut self.client)
                        .map(|_| ())
                        .map_err(Error::from);
                    errors.record(self.finish_pils_cancel(op, until, canceled));
                }
            }
            InputState::LearnStore(op) => {
                // Provider keeps this exact Operation + native worker Job even
                // if callback cancellation refuses; shutdown still drains it.
                errors.record(self.provider.cancel(&op).map(|_| ()).map_err(Error::from));
                if let store::Owner::Learn(source) = op.request().owner() {
                    errors.record(self.routes.source_lost(source).map_err(Error::from));
                }
            }
            InputState::LearnWork(work) => {
                let source = match work {
                    dv::routes::SourceWork::Load { source, .. }
                    | dv::routes::SourceWork::Store { source, .. } => source,
                };
                errors.record(self.routes.source_lost(source).map_err(Error::from));
            }
            InputState::Waiting(w) => {
                if let Some(recycled) = w.recycle(&mut self.provider) {
                    let (buffer, _, _, debt) = recycled.into_parts();
                    self.buffers.push(buffer);
                    self.inputs[i].debt = debt;
                }
            }
            InputState::Ready(r) => {
                let (buffer, _, _, debt) = r.recycle().into_parts();
                self.buffers.push(buffer);
                self.inputs[i].debt = debt;
            }
            InputState::Refused(r) => {
                let (buffer, _, _, debt) = r.recycle().into_parts();
                self.buffers.push(buffer);
                self.inputs[i].debt = debt;
            }
            InputState::Granted(g) => {
                let (buffer, _, _, debt) = g.recycle().into_parts();
                self.buffers.push(buffer);
                self.inputs[i].debt = debt;
            }
            _ => {}
        }
        let parent = self.inputs[i].token;
        for o in 0..self.outputs.len() {
            if self.outputs[o].parent == Some(parent)
                && !matches!(self.outputs[o].state, OutputState::Finished(_))
            {
                let outcome = if self.outputs[o].queued {
                    WriteOutcome::Lost(Some(self.outputs[o].exposed))
                } else {
                    WriteOutcome::Unsent
                };
                // Every original child is visited even if another cleanup
                // failed. Actual queued outputs still need physical facts.
                errors.record(self.cancel_output_index(o, outcome));
            }
        }
        if !was_closed && self.closed {
            // The current row and all its children now have safe owners. Finish
            // all other local rows after the new physical source fence too.
            self.close();
        }
        errors.finish(&mut self.cleanup)
    }
    fn cancel_output_index(&mut self, i: usize, outcome: WriteOutcome) -> Result<(), Error> {
        if matches!(
            self.outputs[i].state,
            OutputState::Finished(_) | OutputState::AwaitPhysical
        ) {
            return Ok(());
        }
        let was_closed = self.closed;
        let mut errors = cancellation::Errors::default();
        // No terminal result is used as a temporary take hole. This complete
        // synchronous transition always stores its real final phase below.
        let state = core::mem::replace(&mut self.outputs[i].state, OutputState::Ready);
        self.inputs_changed();
        let operation = match state {
            OutputState::Probe { operation, .. } | OutputState::Forward { operation, .. } => {
                Some(operation)
            }
            OutputState::Seal { job, .. } => Some(job.operation()),
            _ => None,
        };
        if let Some(op) = operation {
            errors.record(self.retain_cancel(op, self.outputs[i].bounds.hard));
        }
        if self.outputs[i].probe.is_some() {
            errors.record(self.retire_probe_book(self.outputs[i].token));
        }
        if self.outputs[i].queued {
            self.outputs[i].state = OutputState::AwaitPhysical;
        } else {
            self.finish_output(i, outcome);
        }
        if !was_closed && self.closed {
            self.close();
        }
        errors.finish(&mut self.cleanup)
    }
    /// Cancel original processing interest only. Native/disk admitted work keeps
    /// its original ownership and is actually drained or physically closed.
    pub fn cancel(&mut self, id: Token<'id>) -> Result<(), Error> {
        if let Ok(i) = self.input_index(id) {
            self.cancel_input_index(i)
        } else {
            let i = self.output_index(id)?;
            self.cancel_output_index(
                i,
                if self.outputs[i].queued {
                    WriteOutcome::Lost(Some(self.outputs[i].exposed))
                } else {
                    WriteOutcome::Unsent
                },
            )
        }
    }
    fn stop_native(&mut self) {
        // Physical close always precedes pure source/task/cache invalidation.
        let _actual = self.client.close();
        self.source.retire();
        self.closed = true;
        self.input_scan.stop();
        self.partial = None;
        self.send.close();
        self.receive.close();
    }
    fn remember(&mut self, error: Error) {
        if self.cleanup.is_none() {
            self.cleanup = Some(error)
        }
    }
    /// Immediate independent native cleanup needs NO logical clock. Original
    /// Provider worker is only asked to stop here and must still be joined.
    pub fn close(&mut self) {
        self.stop_native();
        for i in 0..self.probes.len() {
            let id = self.probes[i].token;
            if self.probes[i].probe.is_some()
                && let Err(error) = self.retire_probe_book(id)
            {
                self.remember(error)
            }
        }
        for i in 0..self.inputs.len() {
            if let Err(error) = self.cancel_input_index(i) {
                self.remember(error)
            }
        }
        for i in 0..self.outputs.len() {
            if !matches!(self.outputs[i].state, OutputState::Finished(_)) {
                let outcome = if self.outputs[i].queued {
                    WriteOutcome::Lost(Some(self.outputs[i].exposed))
                } else {
                    WriteOutcome::Unsent
                };
                // Native close already retired all actual PILS operations. Do not
                // re-admit/cancel under another MQ or pretend they were unsent.
                if self.outputs[i].queued {
                    self.outputs[i].state = OutputState::AwaitPhysical;
                } else {
                    self.finish_output(i, outcome);
                }
            }
        }
        self.retiring.clear();
        if let Err(e) = self.replay.retire() {
            self.remember(e.into())
        }
        self.provider.request_stop();
        self.scratch.zeroize();
        for b in &mut self.buffers {
            b.zeroize()
        }
        self.input_scan.stop();
    }
    /// First independent cleanup error is retained, not substituted for the
    /// original poll/I/O error that initiated cleanup.
    pub fn take_cleanup_error(&mut self) -> Option<Error> {
        self.cleanup.take()
    }
    /// Actual durable source drain and worker join. fsync/rename can block in OS;
    /// socket cancellation is never represented as a bounded disk interruption.
    pub async fn shutdown(&mut self, observe: impl FnMut(store::Event<'id>)) -> store::Shutdown {
        self.close();
        let actual = self.provider.shutdown(observe).await;
        self.shutdown_complete = true;
        actual
    }
    /// Check an already captured actual task/source budget before any native
    /// retry. Native hard runs first, then the same actual clock/source guard.
    /// A failed original target cannot be treated as permission to refresh it.
    pub fn check_budget(&mut self, original: Budget) -> Result<(), Error> {
        original
            .check_native()
            .map_err(|_| Error::TaskBudgetExpired)?;
        self.live()?;
        let now = self.now()?;
        if now >= original.until.as_micros() {
            return Err(Error::TaskBudgetExpired);
        }
        original
            .check_native()
            .map_err(|_| Error::TaskBudgetExpired)?;
        Ok(())
    }
    /// Original actual startup/source hard limit, only narrowed. A past target
    /// closes the original source before any canonical clock sample or work.
    pub fn restrict_source_hard(&mut self, original: Instant) -> Result<(), Error> {
        self.source_hard = self.source_hard.min(original);
        if Instant::now() >= self.source_hard {
            self.close();
            return Err(Protocol::Deadline.into());
        }
        Ok(())
    }
    /// Set only after actual Provider shutdown/drain/join returned, including
    /// its real failure report. It does not convert Unknown into committed.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown_complete
    }
    /// Original actor/source/worker and all caller-returnable rows settled.
    /// Pure probe metadata is not external native debt and grants no fresh work.
    pub fn is_quiescent(&self) -> bool {
        self.closed
            && self.shutdown_complete
            && self.inputs.is_empty()
            && self.outputs.is_empty()
            && self.retiring.is_empty()
    }
    /// Borrow actual route metadata; it adds no Engine membership or CORE peer.
    pub fn route(
        &mut self,
        target: PeerId,
        confirmed: bool,
    ) -> Result<Option<dv::routes::Route<'id, '_>>, Error> {
        self.live()?;
        self.now()?;
        let now = self.monotonic()?;
        let neighbours = &self.neighbours;
        Ok(self.routes.best(target, confirmed, now, |p| {
            neighbours.iter().any(|n| n.peer == p)
        })?)
    }
    /// Retained candidate targets only; send_path still checks actual current
    /// eligible route/source/expiry before any Engine membership is installed.
    pub fn route_targets(&self) -> impl Iterator<Item = PeerId> + '_ {
        self.routes.targets()
    }
    /// Actual usable path, including current signature-verified bidirectional
    /// inverse routes. Passive freshness and unknown RTT remain unchanged.
    pub fn send_path(&mut self, target: PeerId) -> Result<Option<SendPath<'id>>, Error> {
        self.send_path_with_policy(target, SendPolicy::Bidirectional)
    }
    /// Select using explicit evidence requirements. The resulting native target
    /// is fixed to its original route/source expiry, never another clock epoch.
    pub fn send_path_with_policy(
        &mut self,
        target: PeerId,
        policy: SendPolicy,
    ) -> Result<Option<SendPath<'id>>, Error> {
        self.live()?;
        self.now()?;
        let now = self.monotonic()?;
        let neighbours = &self.neighbours;
        let Some(route) = self.routes.select(target, policy, now, |p| {
            neighbours.iter().any(|n| n.peer == p)
        })?
        else {
            return Ok(None);
        };
        let hops = route.path.len().checked_sub(1).ok_or(Protocol::Malformed)?;
        let overhead = dv::BOX_PREFIX
            .checked_add(dv::PAYLOAD_PREFIX)
            .and_then(|v| v.checked_add(hops * 32))
            .ok_or(Protocol::Overflow)?;
        let max_plaintext = self
            .limits
            .frame_bytes
            .checked_sub(overhead)
            .filter(|n| *n >= 4)
            .ok_or(Protocol::TooLarge)?;
        let hard = Instant::from_std(self.anchor)
            .checked_add(std::time::Duration::from_micros(route.until.0))
            .ok_or(Protocol::Overflow)?
            .min(self.source_hard);
        if Instant::now() >= hard {
            return Ok(None);
        }
        Ok(Some(SendPath {
            policy,
            life: RouteLife {
                route: route.id,
                hard,
                freshness: route.freshness,
            },
            max_plaintext,
            rtt: route.rtt,
        }))
    }
    /// Convert original route expiration to fixed native time for a bridge with
    /// an independent Engine monotonic epoch. No bare integer epoch cast occurs.
    pub fn route_life(
        &mut self,
        target: PeerId,
        confirmed: bool,
    ) -> Result<Option<RouteLife<'id>>, Error> {
        self.live()?;
        self.now()?;
        let now = self.monotonic()?;
        let neighbours = &self.neighbours;
        let Some(route) = self.routes.best(target, confirmed, now, |p| {
            neighbours.iter().any(|n| n.peer == p)
        })?
        else {
            return Ok(None);
        };
        let hard = Instant::from_std(self.anchor)
            .checked_add(std::time::Duration::from_micros(route.until.0))
            .ok_or(Protocol::Overflow)?;
        Ok(Some(RouteLife {
            route: route.id,
            hard,
            freshness: route.freshness,
        }))
    }
    /// Convenience bounded remaining lifetime. The actual bridge should retain
    /// route_life's fixed native target and call remaining at Engine admission.
    pub fn route_remaining(
        &mut self,
        target: PeerId,
        confirmed: bool,
    ) -> Result<Option<Duration>, Error> {
        self.route_life(target, confirmed)?
            .map(|r| r.remaining().map_err(Error::from))
            .transpose()
    }
    fn arm(&mut self, cx: &mut Context<'_>) {
        let mut hard = self
            .source_hard
            .min(Instant::now() + std::time::Duration::from_millis(50));
        for r in &self.inputs {
            if !matches!(r.state, InputState::Finished) {
                hard = hard.min(r.bounds.hard)
            }
        }
        for r in &self.outputs {
            if !matches!(
                r.state,
                OutputState::Finished(_) | OutputState::AwaitPhysical
            ) {
                hard = hard.min(r.bounds.hard)
            }
        }
        for r in &self.retiring {
            hard = hard.min(r.hard)
        }
        for p in &self.probes {
            if p.probe.is_some() {
                hard = hard.min(p.budget.hard)
            }
        }
        if let Some(p) = self.partial {
            hard = hard.min(p)
        }
        if poll_input_alarm(&mut self.alarm, cx, hard) {
            self.inputs_changed();
        }
    }
    fn native_guard(&mut self, cx: &mut Context<'_>) -> Result<Option<Step<'id>>, Error> {
        if self.closed {
            return Ok(None);
        }
        self.arm(cx);
        let native = Instant::now();
        if native >= self.source_hard
            || self.partial.is_some_and(|hard| native >= hard)
            || self.retiring.iter().any(|r| native >= r.hard)
        {
            self.close();
            return Ok(Some(Step::Stopped));
        }
        for p in 0..self.probes.len() {
            if self.probes[p].probe.is_some() && native >= self.probes[p].budget.hard {
                let id = self.probes[p].token;
                self.retire_probe(id)?;
                return Ok(Some(Step::Activity));
            }
        }
        let mut i = 0;
        while i < self.retiring.len() {
            if self
                .client
                .operation_quiescent(self.retiring[i].operation)?
            {
                self.retiring.swap_remove(i);
            } else {
                i += 1;
            }
        }
        for i in 0..self.inputs.len() {
            if !matches!(self.inputs[i].state, InputState::Finished)
                && native >= self.inputs[i].bounds.hard
            {
                let token = self.inputs[i].token;
                let context = self.input_failure(i, native, None);
                if let Err(cleanup) = self.cancel_input_index(i) {
                    self.remember(cleanup);
                }
                return Ok(Some(Step::Failed {
                    token,
                    error: Protocol::Deadline.into(),
                    context,
                }));
            }
        }
        for i in 0..self.outputs.len() {
            if !matches!(
                self.outputs[i].state,
                OutputState::Finished(_) | OutputState::AwaitPhysical
            ) && native >= self.outputs[i].bounds.hard
            {
                let token = self.outputs[i].token;
                let context = self.output_failure(i, native, None);
                if let Err(cleanup) = self.cancel_output_index(i, WriteOutcome::Unsent) {
                    self.remember(cleanup);
                }
                return Ok(Some(Step::Failed {
                    token,
                    error: Protocol::Deadline.into(),
                    context,
                }));
            }
        }
        Ok(None)
    }
    /// Fair bounded actual poll. Native alarms/retirement run before a logical
    /// clock sample, so canonical clock failure/wait cannot hide original hard
    /// deadlines. Polling this owner creates no autonomous task/thread.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Step<'id>, Error>> {
        // Actual worker outcomes remain observable even after MQ/source close.
        if let Some(step) = match self.native_guard(cx) {
            Ok(s) => s,
            Err(e) => {
                self.close();
                return Poll::Ready(Err(e));
            }
        } {
            return Poll::Ready(Ok(step));
        }
        match self.provider.poll(cx) {
            Poll::Ready(Ok(Some(event))) => {
                if let Err(error) = self.store_event(&event) {
                    self.close();
                    return Poll::Ready(Err(error));
                }
                // A consumed provider event can release its bounded capacity
                // even when its original input has already retired.
                if !self.closed {
                    self.inputs_changed();
                }
                return Poll::Ready(Ok(Step::Store(event)));
            }
            Poll::Ready(Err(error)) => {
                self.close();
                return Poll::Ready(Err(error.into()));
            }
            _ => {}
        }
        if let Some(output) = self
            .outputs
            .iter()
            .find(|r| matches!(r.state, OutputState::AwaitPhysical))
        {
            return Poll::Ready(Ok(Step::RetireOutput(output.token)));
        }
        if self.closed {
            return Poll::Ready(Ok(Step::Stopped));
        }
        let logical = match self.now() {
            Ok(n) => n,
            Err(error) => {
                self.close();
                return Poll::Ready(Err(error));
            }
        };
        for p in 0..self.probes.len() {
            if self.probes[p].probe.is_some() && logical >= self.probes[p].budget.until.as_micros()
            {
                let id = self.probes[p].token;
                if let Err(error) = self.retire_probe(id) {
                    return Poll::Ready(Err(error));
                }
                return Poll::Ready(Ok(Step::Activity));
            }
        }
        let complete = {
            // This is the actual existing native Client future; dropping a
            // pending wait preserves its real Framed input/output cursors.
            let wait = self.client.drive(None);
            let mut wait = core::pin::pin!(wait);
            wait.as_mut().poll(cx)
        };
        match complete {
            Poll::Ready(Err(error)) => {
                self.close();
                return Poll::Ready(Err(error.into()));
            }
            Poll::Ready(Ok(progress)) => {
                let result = match progress {
                    Progress::Inbound(Inbound::Complete(result)) => {
                        self.partial = None;
                        self.completion(&result, logical)
                    }
                    Progress::Inbound(Inbound::Identity { identity, .. }) => {
                        self.partial = None;
                        if identity.epoch() != self.identity.epoch()
                            || identity.peer() != self.identity.peer()
                        {
                            self.close();
                            Ok(Step::Stopped)
                        } else {
                            Ok(Step::Activity)
                        }
                    }
                    Progress::Inbound(Inbound::Ignored) => {
                        self.partial = None;
                        Ok(Step::Activity)
                    }
                    Progress::Activity { read_bytes, .. } => {
                        if read_bytes > 0 && self.partial.is_none() {
                            self.partial = Instant::now().checked_add(self.limits.input);
                        }
                        Ok(Step::Activity)
                    }
                    Progress::Written(_) | Progress::WaitDeadline => Ok(Step::Activity),
                    Progress::Lost { cause, report, .. } => {
                        let retained = report.retained();
                        self.close();
                        Err(Error::Source { cause, retained })
                    }
                    Progress::ConnectRetry { error, .. } => {
                        let retained = self.client.pending();
                        self.close();
                        Err(Error::Source {
                            cause: gnunet_pils_host::client::LossCause::Io(error),
                            retained,
                        })
                    }
                    Progress::Unavailable(error) => {
                        self.close();
                        Err(error.into())
                    }
                    Progress::Closed | Progress::Connected(_) => {
                        // Constructor adopted a ready original epoch. Any fresh
                        // connection/retry is a different source, never replay.
                        self.close();
                        Ok(Step::Stopped)
                    }
                };
                return Poll::Ready(result);
            }
            Poll::Pending => {}
        }
        let now = match self.monotonic() {
            Ok(now) => now,
            Err(e) => {
                self.close();
                return Poll::Ready(Err(e.into()));
            }
        };
        match self.routes.expired_probe(now) {
            Ok(Some(probe)) => {
                if let Some(track) = self.probes.iter().find(|p| p.probe == Some(probe)) {
                    let id = track.token;
                    if let Err(error) = self.retire_probe(id) {
                        return Poll::Ready(Err(error));
                    }
                } else if let Err(error) = self.routes.retire_probe(probe) {
                    return Poll::Ready(Err(error.into()));
                }
                self.inputs_changed();
                return Poll::Ready(Ok(Step::Activity));
            }
            Err(error) => return Poll::Ready(Err(error.into())),
            _ => {}
        }
        self.input_scan.begin(self.inputs.len());
        for _ in 0..self.limits.quantum.min(self.inputs.len()) {
            let Some(i) = self.input_scan.take() else {
                break;
            };
            if matches!(self.inputs[i].state, InputState::Finished) {
                continue;
            }
            if let Err(e) = self.inputs[i].bounds.check(logical) {
                let token = self.inputs[i].token;
                let context = self.input_failure(i, Instant::now(), Some(logical));
                if let Err(cleanup) = self.cancel_input_index(i) {
                    self.remember(cleanup)
                }
                return Poll::Ready(Ok(Step::Failed {
                    token,
                    error: e.into(),
                    context,
                }));
            }
            // Expire borrowed admission/grant before waiting for other work.
            let expired = match &mut self.inputs[i].state {
                InputState::Waiting(w) => match w.poll_expired(cx, &mut self.provider) {
                    Poll::Ready(Some(r)) => Some(InputState::Refused(r)),
                    _ => None,
                },
                InputState::Ready(r) => {
                    if r.poll_expired(cx).is_ready() {
                        Some(InputState::Finished)
                    } else {
                        None
                    }
                }
                InputState::Granted(g) => {
                    if g.poll_expired(cx).is_ready() {
                        Some(InputState::Finished)
                    } else {
                        None
                    }
                }
                _ => None,
            };
            if let Some(expired) = expired {
                if matches!(expired, InputState::Finished) {
                    if let Err(cleanup) = self.cancel_input_index(i) {
                        self.remember(cleanup)
                    }
                } else {
                    self.inputs[i].state = expired;
                    self.inputs_changed();
                }
                return Poll::Ready(Ok(Step::Activity));
            }
            // Forwarding advances only through its original output/native
            // result. Both deadline guards above still apply; an idle input
            // turn must not scan child diagnostics that it cannot consume.
            if matches!(self.inputs[i].state, InputState::Forwarding) {
                continue;
            }
            let context = self.input_failure(i, Instant::now(), Some(logical));
            let phase = self.inputs[i].state.phase();
            let result = match self.inputs[i].state {
                InputState::Learn => self.accept_learn(i, now),
                InputState::LearnWork(work) => self.source_work(i, work),
                InputState::Box => self.start_box(i, logical),
                InputState::Material(material) => self.authenticate_box(i, material, logical),
                InputState::Ready(_) | InputState::Refused(_) => self.promote(i),
                _ => Ok(None),
            };
            if self.inputs[i].state.phase() != phase {
                self.inputs_changed();
            }
            match result {
                Ok(Some(step)) => return Poll::Ready(Ok(step)),
                Ok(None) => {}
                Err(error) => {
                    let token = self.inputs[i].token;
                    if let Err(cleanup) = self.cancel_input_index(i) {
                        self.remember(cleanup)
                    }
                    return Poll::Ready(Ok(Step::Failed {
                        token,
                        error,
                        context,
                    }));
                }
            }
        }
        // This turn may have narrowed an original row/retirement target.
        // Keep its actual earlier alarm registered before any pending/terminal
        // query return, without postponing the registration made on entry.
        self.arm(cx);
        if self.input_scan.pending() {
            // Wake only for the unvisited suffix of this bounded input pass.
            // Repeated terminal hints below do not restart the pass.
            cx.waker().wake_by_ref();
        }
        if let Some(r) = self
            .inputs
            .iter()
            .find(|r| matches!(r.state, InputState::Finished) && r.forwards == 0)
        {
            return Poll::Ready(Ok(Step::InputFinished(r.token)));
        }
        if let Some(r) = self
            .outputs
            .iter()
            .find(|r| matches!(r.state, OutputState::Finished(_)))
        {
            return Poll::Ready(Ok(Step::OutputFinished(r.token)));
        }
        Poll::Pending
    }
    /// Original external physical output still requiring retirement. This view
    /// samples no clock and works during source/clock failure cleanup.
    pub fn retirement(&self, id: Token<'id>) -> Result<Retirement<'_, 'id>, Error> {
        let r = &self.outputs[self.output_index(id)?];
        if !matches!(r.state, OutputState::AwaitPhysical) {
            return Err(Protocol::NotReady.into());
        }
        Ok(Retirement {
            token: id,
            neighbour: &r.neighbour,
            exposed: r.exposed.then_some(true),
            hard: r.bounds.hard,
        })
    }
    /// Registered direct-queue metadata, not inferred peer authentication.
    pub fn neighbours(&self) -> impl Iterator<Item = &Neighbour<'id>> {
        self.neighbours.iter()
    }
    /// Borrow exact original external input attribution before delivery. No
    /// ownership transfer, mutation, source retag or FC completion occurs.
    pub fn input_origin(&self, id: Token<'id>) -> Result<&J, Error> {
        self.inputs[self.input_index(id)?]
            .origin
            .as_ref()
            .ok_or_else(|| Protocol::Conflict.into())
    }
    /// Borrow the exact original output attribution without sampling any clock.
    /// This grants no send/write fact and preserves non-Clone ownership in row.
    pub fn output_origin(&self, id: Token<'id>) -> Result<Option<&J>, Error> {
        Ok(self.outputs[self.output_index(id)?].origin.as_ref())
    }
    /// Original accepted physical queue attribution; this does not authorize a
    /// current same-peer queue after the original lease is detached.
    pub fn input_neighbour(&self, id: Token<'id>) -> Result<&Neighbour<'id>, Error> {
        Ok(&self.inputs[self.input_index(id)?].neighbour)
    }
    /// Recheck the original immutable authenticated LEARN for explicit bounded
    /// caller forwarding policy. No raw PID/source string can construct this.
    pub fn learn(&mut self, id: Token<'id>) -> Result<dv::VerifiedLearn<'_>, Error> {
        let logical = self.now()?;
        let r = &self.inputs[self.input_index(id)?];
        r.bounds
            .check(logical)
            .map_err(|_| Error::TaskBudgetExpired)?;
        if !matches!(r.state, InputState::LearnReady) {
            return Err(Protocol::NotReady.into());
        }
        Ok(dv::Learn::decode(&r.bytes)?.verify(self.source.local(), r.neighbour.peer)?)
    }
    /// True only after original external queued outputs have real physical
    /// completions too; closing PILS does not close the caller's transport MQ.
    /// Exact actual local readiness. Clock failure/closure does not erase it or
    /// require reconstructing a fresh canonical sample for original cleanup.
    pub fn input_state(&self, token: Token<'id>) -> Result<InputProgress, Protocol> {
        Ok(Self::input_progress(&self.inputs[self.input_index(token)?]))
    }
    fn input_progress(row: &InputRow<'source, 'id, 'pils, 'out, J>) -> InputProgress {
        match &row.state {
            InputState::LearnReady => InputProgress::LearnReady,
            InputState::Granted(_) => InputProgress::DeliveryReady,
            InputState::Finished if row.forwards == 0 => InputProgress::Finished,
            InputState::Finished => InputProgress::Retiring,
            _ => InputProgress::Working,
        }
    }
    /// Read original input identities and readiness in one metadata traversal.
    /// No clock, proof, payload copy or admission is supplied. Positions are
    /// ephemeral; only the returned original token identifies later work.
    pub fn input_states(&self) -> impl ExactSizeIterator<Item = (Token<'id>, InputProgress)> + '_ {
        self.inputs
            .iter()
            .map(|row| (row.token, Self::input_progress(row)))
    }
    /// Local bounded input metadata still needs inspection after a clipped
    /// poll. This is only scheduling debt, never IO, authentication or delivery.
    /// A composing owner must retain it even if nested wakeups are coalesced.
    pub fn input_scan_pending(&self) -> bool {
        // poll() gives original external retirement priority over input work.
        // Keep the debt parked while that same physical barrier exists; real
        // settlement changes the row/capacity and restores a complete pass.
        runnable_input_scan(
            self.input_scan.pending(),
            self.closed,
            self.outputs
                .iter()
                .any(|row| matches!(row.state, OutputState::AwaitPhysical)),
        )
    }
    /// Exact actual readiness, never a synthetic queue/write acknowledgement.
    pub fn output_state(&self, token: Token<'id>) -> Result<OutputProgress, Protocol> {
        Ok(self.outputs[self.output_index(token)?].progress())
    }
    /// Iterate original output identities and their current metadata states in
    /// one bounded pass. This shares output_state() classification, samples no
    /// clock and grants no native admission or completion acknowledgement.
    pub fn output_states(&self) -> impl Iterator<Item = (Token<'id>, OutputProgress)> + '_ {
        self.outputs
            .iter()
            .map(|output| (output.token, output.progress()))
    }
    /// Actual retained original input tokens, also after closure. Enumeration
    /// grants no success; take_finished still checks the original terminal state.
    pub fn input_tokens(&self) -> impl Iterator<Item = Token<'id>> + '_ {
        self.inputs.iter().map(|r| r.token)
    }
    /// Ready outputs that may be newly staged without overtaking an earlier
    /// ordinary local BOX for the same ultimate target on this actor source.
    /// Controls, forwarded packets and other targets remain independently ready.
    ///
    /// This is a bounded metadata scan, not a clock/source/native-write receipt.
    /// The caller still performs output() preflight. A predecessor remains a
    /// barrier through queueing, partial writes and physical cancellation until
    /// its actual Written/Lost/Unsent terminal outcome; retiring its metadata is
    /// not required. Original tokens, rather than Vec positions, own the order.
    pub fn admissible_output_tokens(&self) -> impl Iterator<Item = Token<'id>> + '_ {
        self.outputs
            .iter()
            .filter(|output| admissible_output(&self.outputs, output))
            .map(|output| output.token)
    }
    /// Actual retained output tokens, including AwaitPhysical after closure.
    /// Physical debt must still settle before take_output_finished succeeds.
    pub fn output_tokens(&self) -> impl Iterator<Item = Token<'id>> + '_ {
        self.outputs.iter().map(|r| r.token)
    }
    /// Actual original externally queued outputs still lacking physical result.
    pub fn native_outputs_pending(&self) -> usize {
        self.outputs
            .iter()
            .filter(|r| r.queued && r.state.outcome().is_none())
            .count()
    }
    /// Return all remaining erased caller loans after actual source close.
    /// The worker still requires explicit shutdown/join independently.
    pub fn take_buffers(&mut self) -> Result<Vec<&'out mut [u8]>, Error> {
        if !self.closed {
            return Err(Protocol::NotReady.into());
        }
        Ok(core::mem::take(&mut self.buffers))
    }
    /// Drive original physical/disk owners. Canceling only this future cancels
    /// no operation and loses no original cursor/receipt.
    pub async fn drive(&mut self) -> Result<Step<'id>, Error> {
        std::future::poll_fn(|cx| self.poll(cx)).await
    }
}
impl<J, const N: usize> Drop for Runtime<'_, '_, '_, '_, '_, J, N> {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
#[path = "runtime/input_scan_tests.rs"]
mod input_scan_tests;
