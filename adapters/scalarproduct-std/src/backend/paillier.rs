//! Original Paillier lifecycle translated to the shared native action view.
//! No socket, native ACK, retry epoch or successful result is fabricated here.
use super::{
    Action, Completion, Effect, EffectId, Failure, InputId, IntersectionId, Outcome,
    PaillierOutcome, PeerKind, PeerOutput, PeerSource,
};
use crate::{Error, Role};
use gnunet_scalarproduct_paillier as p;
use gnunet_types::Error as Fault;
use gnunet_wire::official::scalarproduct::{ClientResponse, PeerMessage, ResponseStatus};
use std::{mem::size_of, rc::Rc};

pub(super) fn classify(error: p::Error) -> Fault {
    match error {
        p::Error::Core(cause) => cause,
        p::Error::Primitive(gnunet_paillier::Error::Entropy(cause)) => cause,
        p::Error::Primitive(gnunet_paillier::Error::Capacity) => Fault::Capacity,
        p::Error::Primitive(gnunet_paillier::Error::NotReady) => Fault::NotReady,
        p::Error::Primitive(gnunet_paillier::Error::Cancelled) | p::Error::Cancelled => {
            Fault::Cancelled
        }
        p::Error::Primitive(gnunet_paillier::Error::Finished) | p::Error::Finished => {
            Fault::StaleGeneration
        }
        p::Error::Deadline => Fault::Deadline,
        p::Error::Clock => Fault::TimeUncertain,
        _ => Fault::Malformed,
    }
}
enum Kind<'i> {
    Listen,
    Start,
    Port,
    Connect,
    Frame {
        frame: p::Frame<'i>,
        kind: PeerKind,
    },
    Release {
        input: InputId<'i>,
        delivery: u64,
        source: PeerSource,
    },
    Client {
        status: ResponseStatus,
        range: i32,
        product: Option<p::Mpi>,
    },
    CloseIntersection,
    ClosePeer(PeerSource),
    ClosePort,
}
struct Pending<'i> {
    id: EffectId<'i>,
    kind: Kind<'i>,
    admitted: bool,
}
#[derive(Clone, Copy)]
struct Input<'i> {
    id: InputId<'i>,
    delivery: u64,
    source: PeerSource,
}

pub(super) struct Computation<'i> {
    alice: Vec<p::Alice<'i>>,
    bob: Vec<p::Bob<'i>>,
    binding: p::Binding<'i>,
    role: Role,
    session: [u8; 64],
    expected: Option<[u8; 32]>,
    source: Option<PeerSource>,
    next: Option<u64>,
    pending: Option<Pending<'i>>,
    input: Option<Input<'i>>,
    delivery: u64,
    setup: bool,
    intersection_open: bool,
    intersection_done: bool,
    matched: usize,
    port_open: bool,
    connect_written: bool,
    cancelled: bool,
    closing: bool,
    want_reply: bool,
    client_written: bool,
    client_terminal: bool,
    result: Option<(i32, p::Mpi)>,
    failure: Option<Failure>,
    cleanup_failure: Option<Fault>,
    first_error: Option<p::Error>,
    facts: PaillierOutcome,
}
impl<'i> Computation<'i> {
    #[expect(
        clippy::too_many_arguments,
        reason = "original profile, vector, peer, key, native origin and retained quota are explicit"
    )]
    pub fn new(
        instance: &'i p::Instance,
        role: Role,
        session: [u8; 64],
        expected: Option<[u8; 32]>,
        vector: p::MatchedVector,
        policy: p::Limits,
        key: Option<Rc<gnunet_paillier::KeyPair>>,
        origin: u64,
        outside: usize,
    ) -> Result<Self, Error> {
        let matched = vector.initial_rows();
        let mut alice = Vec::new();
        let mut bob = Vec::new();
        let binding = match role {
            Role::Alice => {
                if expected.is_none() {
                    return Err(Fault::Malformed.into());
                }
                alice.try_reserve_exact(1).map_err(|_| Fault::Capacity)?;
                let mut core = p::Alice::new(
                    instance,
                    session,
                    key.ok_or(Fault::NotReady)?,
                    vector,
                    policy,
                    origin,
                )
                .map_err(Error::Paillier)?;
                let charge = outside
                    .checked_add(
                        alice
                            .capacity()
                            .checked_mul(size_of::<p::Alice<'i>>())
                            .ok_or(Fault::Overflow)?,
                    )
                    .ok_or(Fault::Overflow)?;
                core.set_external_retained_bytes(charge)
                    .map_err(Error::Paillier)?;
                let binding = core.binding();
                alice.push(core);
                binding
            }
            Role::Bob => {
                bob.try_reserve_exact(1).map_err(|_| Fault::Capacity)?;
                let mut core = p::Bob::new(instance, session, vector, policy, origin)
                    .map_err(Error::Paillier)?;
                let charge = outside
                    .checked_add(
                        bob.capacity()
                            .checked_mul(size_of::<p::Bob<'i>>())
                            .ok_or(Fault::Overflow)?,
                    )
                    .ok_or(Fault::Overflow)?;
                core.set_external_retained_bytes(charge)
                    .map_err(Error::Paillier)?;
                let binding = core.binding();
                bob.push(core);
                binding
            }
        };
        Ok(Self {
            alice,
            bob,
            binding,
            role,
            session,
            expected,
            source: None,
            next: Some(1),
            pending: None,
            input: None,
            delivery: 0,
            setup: false,
            intersection_open: false,
            intersection_done: false,
            matched,
            port_open: false,
            connect_written: false,
            cancelled: false,
            closing: false,
            want_reply: false,
            client_written: false,
            client_terminal: false,
            result: None,
            failure: None,
            cleanup_failure: None,
            first_error: None,
            facts: PaillierOutcome::default(),
        })
    }
    fn id(&self) -> IntersectionId<'i> {
        IntersectionId::Paillier(self.binding)
    }
    fn validate(&self, id: IntersectionId<'i>, peer: Option<[u8; 32]>) -> Result<(), Fault> {
        if id != self.id()
            || peer.is_some_and(|peer| self.source.is_none_or(|source| source.peer != peer))
        {
            return Err(Fault::StaleGeneration);
        }
        Ok(())
    }
    fn publish(&mut self, kind: Kind<'i>) -> Result<(), Fault> {
        if self.pending.is_some() {
            return Err(Fault::WouldBlock);
        }
        let serial = self.next.ok_or(Fault::Overflow)?;
        self.next = serial.checked_add(1);
        self.pending = Some(Pending {
            id: EffectId::Paillier(self.binding, serial),
            kind,
            admitted: false,
        });
        Ok(())
    }
    pub fn effect(&self) -> Option<Effect<'_, 'i>> {
        let pending = self.pending.as_ref()?;
        let action = match &pending.kind {
            Kind::Listen => Action::ListenIntersection {
                id: self.id(),
                app: self.session,
                peer: self.expected?,
            },
            Kind::Start => Action::StartIntersection {
                id: self.id(),
                app: self.session,
                peer: self.source?.peer,
            },
            Kind::Port => Action::OpenPort { port: self.session },
            Kind::Connect => Action::Connect {
                peer: self.expected?,
                port: self.session,
            },
            Kind::Frame { frame, kind } => Action::PeerSend {
                source: self.source?,
                payload: PeerOutput::Paillier(frame, *kind),
            },
            Kind::Release {
                input,
                delivery,
                source,
            } => Action::ReceiveDone {
                source: *source,
                input: *input,
                delivery: *delivery,
            },
            Kind::Client {
                status,
                range,
                product,
            } => Action::ClientResult {
                response: ClientResponse {
                    status: *status,
                    range: *range,
                    product: product.as_ref().map_or(&[], p::Mpi::as_bytes),
                },
            },
            Kind::CloseIntersection => Action::CloseIntersection { id: self.id() },
            Kind::ClosePeer(source) => Action::ClosePeer { source: *source },
            Kind::ClosePort => Action::ClosePort { port: self.session },
        };
        Some(Effect {
            id: pending.id,
            action,
            admitted: pending.admitted,
        })
    }
    pub fn admit_effect(&mut self, id: EffectId<'i>) -> Result<(), Fault> {
        let pending = self.pending.as_mut().ok_or(Fault::Stale)?;
        if pending.id != id || pending.admitted {
            return Err(Fault::StaleGeneration);
        }
        pending.admitted = true;
        match pending.kind {
            Kind::Listen | Kind::Start => self.intersection_open = true,
            Kind::Port => self.port_open = true,
            _ => {}
        }
        Ok(())
    }
    pub fn complete_effect(
        &mut self,
        id: EffectId<'i>,
        completion: Completion,
    ) -> Result<(), Fault> {
        let pending = self.pending.as_ref().ok_or(Fault::Stale)?;
        if pending.id != id || !pending.admitted {
            return Err(Fault::StaleGeneration);
        }
        let legal = matches!(
            (&pending.kind, completion),
            (
                Kind::Release { .. },
                Completion::Written | Completion::Processed
            ) | (
                Kind::CloseIntersection | Kind::ClosePeer(_) | Kind::ClosePort,
                Completion::Written | Completion::Retired
            ) | (
                _,
                Completion::Written | Completion::Unsent(_) | Completion::Lost(_)
            )
        );
        if !legal {
            return Err(Fault::Conflict);
        }
        let pending = self.pending.take().ok_or(Fault::Stale)?;
        let failed = match completion {
            Completion::Lost(error) | Completion::Unsent(error) => Some(error),
            _ => None,
        };
        match pending.kind {
            Kind::Frame { frame, kind } => {
                let terminal = match completion {
                    Completion::Written => p::Terminal::Written,
                    Completion::Unsent(error) => p::Terminal::Unsent(p::Error::Core(error)),
                    Completion::Lost(error) => p::Terminal::Lost(p::Error::Core(error)),
                    _ => return Err(Fault::Conflict),
                };
                let result = if let Some(core) = self.alice.first_mut() {
                    core.complete_output(frame, terminal)
                } else {
                    self.bob
                        .first_mut()
                        .ok_or(Fault::Stale)?
                        .complete_output(frame, terminal)
                };
                if let Err(rejected) = result {
                    let error = rejected.error();
                    self.pending = Some(Pending {
                        id,
                        kind: Kind::Frame {
                            frame: rejected.into_frame(),
                            kind,
                        },
                        admitted: true,
                    });
                    self.first_error.get_or_insert(error);
                    return Err(classify(error));
                }
            }
            Kind::Listen if failed.is_none() => self.setup = true,
            Kind::Start if failed.is_none() => self.setup = true,
            Kind::Port => {}
            Kind::Connect if failed.is_none() => {
                self.connect_written = true;
                if !self.cancelled && self.failure.is_none() {
                    let result = self
                        .alice
                        .first_mut()
                        .ok_or(Fault::Stale)?
                        .activate(self.binding);
                    if let Err(error) = result {
                        self.record(error);
                    }
                }
            }
            Kind::Release { .. } => self.input = None,
            Kind::Client { .. } => {
                self.want_reply = false;
                self.client_terminal = true;
                if failed.is_none() {
                    self.client_written = true;
                }
                self.result = None;
                self.closing = true;
            }
            Kind::CloseIntersection => self.intersection_open = false,
            Kind::ClosePeer(_) => {
                self.source = None;
                self.input = None;
            }
            Kind::ClosePort => self.port_open = false,
            _ => {}
        }
        if let Some(cause) = failed {
            self.record(p::Error::Core(cause));
        }
        self.synchronize();
        Ok(())
    }
    pub fn pump(&mut self) -> Result<bool, Fault> {
        self.synchronize();
        if self.pending.is_some() {
            return Ok(false);
        }
        if self.closing {
            if self.want_reply && !self.cancelled {
                let (range, product) = if self.failure.is_some() {
                    (0, None)
                } else {
                    self.result
                        .take()
                        .map_or((0, None), |(range, product)| (range, Some(product)))
                };
                self.publish(Kind::Client {
                    status: if self.failure.is_some() {
                        ResponseStatus::FAILURE
                    } else {
                        ResponseStatus::SUCCESS
                    },
                    range,
                    product,
                })?;
                return Ok(true);
            }
            let kind = if self.intersection_open {
                Some(Kind::CloseIntersection)
            } else if let Some(source) = self.source {
                Some(Kind::ClosePeer(source))
            } else if self.port_open {
                Some(Kind::ClosePort)
            } else {
                None
            };
            if let Some(kind) = kind {
                self.publish(kind)?;
                return Ok(true);
            }
            return Ok(false);
        }
        if let Some(input) = self.input {
            if self.role == Role::Bob && !self.intersection_done {
                if !self.setup {
                    self.publish(Kind::Start)?;
                    return Ok(true);
                }
                return Ok(false);
            }
            self.publish(Kind::Release {
                input: input.id,
                delivery: input.delivery,
                source: input.source,
            })?;
            return Ok(true);
        }
        match self.role {
            Role::Alice if !self.setup => {
                self.publish(Kind::Listen)?;
                return Ok(true);
            }
            Role::Alice if !self.connect_written => {
                self.publish(Kind::Connect)?;
                return Ok(true);
            }
            Role::Bob if !self.port_open => {
                self.publish(Kind::Port)?;
                return Ok(true);
            }
            _ => {}
        }
        let id = if let Some(core) = self.alice.first() {
            core.output()
        } else {
            self.bob.first().and_then(p::Bob::output)
        };
        if let Some(id) = id {
            // Reserve the local publication serial before moving the actual
            // pure Frame owner. No later error may silently drop that debt.
            let serial = self.next.ok_or(Fault::Overflow)?;
            let frame = if let Some(core) = self.alice.first_mut() {
                core.admit_output(id)
            } else {
                self.bob.first_mut().ok_or(Fault::Stale)?.admit_output(id)
            };
            let frame = match frame {
                Ok(frame) => frame,
                Err(error) => {
                    self.record(error);
                    return Err(classify(error));
                }
            };
            self.next = serial.checked_add(1);
            self.pending = Some(Pending {
                id: EffectId::Paillier(self.binding, serial),
                kind: Kind::Frame {
                    frame,
                    kind: PeerKind::Bob,
                },
                admitted: false,
            });
            let kind = match &self.pending.as_ref().ok_or(Fault::Stale)?.kind {
                Kind::Frame { frame, .. } => {
                    PeerMessage::decode(frame.bytes()).and_then(|message| match message {
                        PeerMessage::PaillierSession { .. } => Ok(PeerKind::Session),
                        PeerMessage::PaillierAlice { values } => Ok(PeerKind::Alice(values.len())),
                        PeerMessage::PaillierBob { .. } | PeerMessage::PaillierBobPart { .. } => {
                            Ok(PeerKind::Bob)
                        }
                        _ => Err(Fault::Malformed),
                    })
                }
                _ => Err(Fault::Conflict),
            };
            match kind {
                Ok(kind) => {
                    if let Kind::Frame { kind: stored, .. } =
                        &mut self.pending.as_mut().ok_or(Fault::Stale)?.kind
                    {
                        *stored = kind;
                    }
                }
                Err(cause) => {
                    self.record(p::Error::Core(cause));
                    return Err(cause);
                }
            }
            return Ok(true);
        }
        Ok(false)
    }
    pub fn attach_peer(&mut self, source: PeerSource) -> Result<(), Fault> {
        if self.closing
            || self.source.is_some()
            || source.epoch == 0
            || source.channel == 0
            || self.expected.is_some_and(|peer| peer != source.peer)
        {
            return Err(Fault::Authentication);
        }
        if self.role == Role::Bob {
            let result = self
                .bob
                .first_mut()
                .ok_or(Fault::Stale)?
                .activate(self.binding);
            if let Err(error) = result {
                self.record(error);
                return Err(classify(error));
            }
        }
        self.source = Some(source);
        Ok(())
    }
    pub fn intersection_key(
        &self,
        id: IntersectionId<'i>,
        cursor: usize,
    ) -> Result<Option<&[u8; 64]>, Fault> {
        self.validate(id, None)?;
        Ok(if let Some(core) = self.alice.first() {
            core.intersection_key(cursor)
        } else {
            self.bob
                .first()
                .and_then(|core| core.intersection_key(cursor))
        })
    }
    pub fn intersection_removed(
        &mut self,
        id: IntersectionId<'i>,
        peer: [u8; 32],
        key: &[u8; 64],
        now: u64,
    ) -> Result<(), Fault> {
        self.validate(id, Some(peer))?;
        let count = self.matched.checked_sub(1).ok_or(Fault::Malformed)?;
        let result = if let Some(core) = self.alice.first_mut() {
            core.intersection_removed(self.binding, key, now)
        } else {
            self.bob
                .first_mut()
                .ok_or(Fault::Stale)?
                .intersection_removed(self.binding, key, now)
        };
        match result {
            Ok(()) => {
                self.matched = count;
                Ok(())
            }
            Err(error) => {
                self.record(error);
                Err(classify(error))
            }
        }
    }
    pub fn intersection_done(
        &mut self,
        id: IntersectionId<'i>,
        peer: [u8; 32],
        now: u64,
    ) -> Result<(), Fault> {
        self.validate(id, Some(peer))?;
        // C's SETI DONE leaves current_size unset. The authoritative final size
        // is the original nonzero keys minus actual original DEL_LOCAL events.
        let count = u64::try_from(self.matched).map_err(|_| Fault::Overflow)?;
        let result = if let Some(core) = self.alice.first_mut() {
            core.intersection_done(self.binding, count, now)
        } else {
            self.bob
                .first_mut()
                .ok_or(Fault::Stale)?
                .intersection_done(self.binding, count, now)
        };
        match result {
            Ok(()) => {
                self.intersection_done = true;
                Ok(())
            }
            Err(error) => {
                self.record(error);
                Err(classify(error))
            }
        }
    }
    pub fn intersection_failed(
        &mut self,
        id: IntersectionId<'i>,
        cause: Fault,
    ) -> Result<(), Fault> {
        self.validate(id, None)?;
        self.record(p::Error::Core(cause));
        Ok(())
    }
    pub fn receive(
        &mut self,
        source: PeerSource,
        delivery: u64,
        message: PeerMessage<'_>,
        now: u64,
    ) -> Result<InputId<'i>, Fault> {
        if self.source != Some(source) || delivery == 0 || delivery <= self.delivery {
            return Err(Fault::StaleGeneration);
        }
        if self.input.is_some() || self.pending.is_some() {
            return Err(Fault::WouldBlock);
        }
        if self.closing {
            return Err(Fault::Closed);
        }
        let result = if let Some(core) = self.alice.first_mut() {
            core.receive(self.binding, message, now)
        } else {
            self.bob
                .first_mut()
                .ok_or(Fault::Stale)?
                .receive(self.binding, message, now)
        };
        match result {
            Ok(()) => {
                let id = InputId::Paillier(self.binding, delivery);
                self.delivery = delivery;
                self.input = Some(Input {
                    id,
                    source,
                    delivery,
                });
                Ok(id)
            }
            Err(p::Error::Core(Fault::WouldBlock | Fault::NotReady)) => Err(Fault::WouldBlock),
            Err(error) => {
                self.record(error);
                Err(classify(error))
            }
        }
    }
    pub fn step(
        &mut self,
        entropy: &mut impl gnunet_crypto::Entropy,
        units: usize,
        now: u64,
    ) -> Result<bool, Fault> {
        if self.pending.is_some() || self.closing {
            return Ok(false);
        }
        let units = u16::try_from(units).map_err(|_| Fault::InvalidInput)?;
        let result = if let Some(core) = self.alice.first_mut() {
            core.progress(now, entropy, units)
        } else {
            self.bob
                .first_mut()
                .ok_or(Fault::Stale)?
                .progress(now, entropy, units)
        };
        match result {
            Ok(progress) => {
                let mut progressed = progress;
                self.synchronize();
                if self.facts.product_computed && self.result.is_none() && !self.closing {
                    let product = self.alice.first_mut().ok_or(Fault::Stale)?.take_product();
                    match product {
                        Ok(product) => {
                            self.result = Some((product.range(), product.mpi()));
                            self.want_reply = true;
                            self.closing = true;
                            progressed = true;
                        }
                        Err(error) => {
                            self.record(error);
                            return Err(classify(error));
                        }
                    }
                }
                if self.facts.reply_handed_off && self.failure.is_none() {
                    self.want_reply = true;
                    self.closing = true;
                    progressed = true;
                }
                Ok(progressed)
            }
            Err(error) => {
                self.record(error);
                Err(classify(error))
            }
        }
    }
    pub fn peer_lost(&mut self, source: PeerSource, cause: Fault) -> Result<(), Fault> {
        if self.source != Some(source) {
            return Err(Fault::StaleGeneration);
        }
        let result = if let Some(core) = self.alice.first_mut() {
            core.peer_lost(self.binding, p::Error::Core(cause))
        } else {
            self.bob
                .first_mut()
                .ok_or(Fault::Stale)?
                .peer_lost(self.binding, p::Error::Core(cause))
        };
        if let Err(error) = result {
            self.first_error.get_or_insert(error);
        }
        self.record(p::Error::Core(cause));
        self.synchronize();
        Ok(())
    }
    pub fn cancel(&mut self) -> Result<(), Fault> {
        self.cancelled = true;
        self.want_reply = false;
        self.record(p::Error::Cancelled);
        Ok(())
    }
    fn record(&mut self, error: p::Error) {
        if self.client_written {
            let cause = classify(error);
            if !matches!(cause, Fault::Closed | Fault::Cancelled) {
                self.cleanup_failure.get_or_insert(cause);
            }
            self.closing = true;
            self.want_reply = false;
            return;
        }
        self.first_error.get_or_insert(error);
        self.failure.get_or_insert(Failure {
            cause: classify(error),
        });
        self.closing = true;
        self.want_reply = !self.cancelled && !self.client_terminal;
        if let Some(core) = self.alice.first_mut() {
            core.cancel();
        }
        if let Some(core) = self.bob.first_mut() {
            core.cancel();
        }
        self.result = None;
        self.synchronize();
    }
    fn synchronize(&mut self) {
        if let Some(core) = self.alice.first() {
            self.facts.product_computed |= core.product_computed();
            self.facts.peer_failure = self.facts.peer_failure.or(core.peer_failure());
            if self.first_error.is_none() {
                self.first_error = core.failure();
            }
        }
        if let Some(core) = self.bob.first() {
            self.facts.reply_handed_off |= core.reply_handed_off();
            self.facts.peer_failure = self.facts.peer_failure.or(core.peer_failure());
            if self.first_error.is_none() {
                self.first_error = core.failure();
            }
        }
        self.facts.failure = self.first_error;
        if let Some(error) = self.first_error {
            self.failure.get_or_insert(Failure {
                cause: classify(error),
            });
        }
    }
    pub fn outcome(&self) -> Outcome {
        Outcome {
            ecc: None,
            paillier: Some(self.facts),
            failure: self.failure,
            client_written: self.client_written,
            cleanup_failure: self.cleanup_failure,
        }
    }
    pub fn peer_source(&self) -> Option<PeerSource> {
        self.source
    }
    pub fn can_finish_locally(&self) -> bool {
        self.failure.is_none()
            && !self.cancelled
            && self.intersection_done
            && (self.alice.first().is_some_and(p::Alice::can_finish_locally)
                || self.bob.first().is_some_and(p::Bob::can_finish_locally))
    }
    /// The shared native owner may drain only this source's already held
    /// reply continuation after a real channel close. Fresh IO and success
    /// remain forbidden; the ordinary receive/math/final-tail gates still run.
    pub fn can_drain_peer_input(&self, source: PeerSource) -> bool {
        self.source == Some(source)
            && self.role == Role::Alice
            && self.failure.is_none()
            && !self.cancelled
            && !self.closing
            && self.intersection_done
            && self
                .alice
                .first()
                .is_some_and(p::Alice::can_drain_peer_input)
    }
    pub fn retire_peer_for_local_work(
        &mut self,
        source: PeerSource,
        cause: Fault,
        receipt: Option<(EffectId<'i>, Completion)>,
    ) -> Result<(), Fault> {
        if self.source != Some(source) || !self.can_finish_locally() {
            return Err(Fault::NotReady);
        }
        match (&self.pending, receipt) {
            (
                Some(Pending {
                    id,
                    kind:
                        Kind::Release {
                            source: original, ..
                        },
                    admitted: true,
                }),
                Some((received, Completion::Written | Completion::Lost(_) | Completion::Unsent(_))),
            ) if *id == received && *original == source => {}
            (
                Some(Pending {
                    kind: Kind::Client { .. },
                    ..
                }),
                None,
            )
            | (None, None) => {}
            _ => return Err(Fault::StaleGeneration),
        }
        let result = if let Some(core) = self.alice.first_mut() {
            core.retire_peer_for_local_work(self.binding, p::Error::Core(cause))
        } else {
            self.bob
                .first_mut()
                .ok_or(Fault::Stale)?
                .retire_peer_for_local_work(self.binding, p::Error::Core(cause))
        };
        result.map_err(classify)?;
        if receipt.is_some() {
            self.pending = None;
        }
        self.input = None;
        self.source = None;
        self.cleanup_failure.get_or_insert(cause);
        self.synchronize();
        Ok(())
    }
    pub fn error(&self) -> Option<p::Error> {
        self.first_error
    }
    pub fn is_quiescent(&self) -> bool {
        self.closing
            && !self.want_reply
            && self.pending.is_none()
            && !self.intersection_open
            && self.source.is_none()
            && !self.port_open
            && self.alice.first().is_none_or(p::Alice::is_quiescent)
            && self.bob.first().is_none_or(p::Bob::is_quiescent)
    }
}
