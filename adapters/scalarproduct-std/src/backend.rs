//! One private action view for the existing physical SETI/CADET/IPC reactor.
//! Original algorithm tokens/Frame allocations are retained, never re-minted.
mod paillier;
use crate::{Error, Limits, Profile, Role};
pub(crate) use ecc::{Completion, PeerSource};
use gnunet_scalarproduct as ecc;
use gnunet_scalarproduct_paillier as p;
use gnunet_types::Error as Fault;
use gnunet_wire::official::scalarproduct::{ClientResponse, PeerMessage};
use std::{mem::size_of, rc::Rc};
pub(crate) fn classify_paillier(error: p::Error) -> Fault {
    paillier::classify(error)
}

pub(crate) struct Instance {
    ecc: ecc::Instance,
    paillier: p::Instance,
}
impl Instance {
    pub fn new() -> Self {
        Self {
            ecc: ecc::Instance::new(),
            paillier: p::Instance::new(),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EffectId<'i> {
    Ecc(ecc::EffectId<'i>),
    Paillier(p::Binding<'i>, u64),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InputId<'i> {
    Ecc(ecc::InputId<'i>),
    Paillier(p::Binding<'i>, u64),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IntersectionId<'i> {
    Ecc(ecc::IntersectionId<'i>),
    Paillier(p::Binding<'i>),
}

#[derive(Clone, Copy)]
pub(crate) enum PeerKind {
    Session,
    Alice(usize),
    Bob,
}
pub(crate) enum PeerOutput<'a, 'i> {
    Ecc(&'a ecc::PeerOutput),
    Paillier(&'a p::Frame<'i>, PeerKind),
}
impl PeerOutput<'_, '_> {
    pub fn kind(&self) -> PeerKind {
        match self {
            Self::Ecc(ecc::PeerOutput::Session { .. }) => PeerKind::Session,
            Self::Ecc(ecc::PeerOutput::Alice { pairs }) => PeerKind::Alice(pairs.len()),
            Self::Ecc(_) => PeerKind::Bob,
            Self::Paillier(_, kind) => *kind,
        }
    }
    pub fn encoded_len(&self) -> Result<usize, Fault> {
        match self {
            Self::Ecc(payload) => payload.wire().encoded_len(),
            Self::Paillier(frame, _) => Ok(frame.bytes().len()),
        }
    }
    pub fn encode(&self, output: &mut [u8]) -> Result<usize, Fault> {
        match self {
            Self::Ecc(payload) => payload.wire().encode(output),
            Self::Paillier(frame, _) => {
                if output.len() < frame.bytes().len() {
                    return Err(Fault::Truncated);
                }
                output[..frame.bytes().len()].copy_from_slice(frame.bytes());
                Ok(frame.bytes().len())
            }
        }
    }
}
pub(crate) enum Action<'a, 'i> {
    ListenIntersection {
        id: IntersectionId<'i>,
        app: [u8; 64],
        peer: [u8; 32],
    },
    StartIntersection {
        id: IntersectionId<'i>,
        app: [u8; 64],
        peer: [u8; 32],
    },
    OpenPort {
        port: [u8; 64],
    },
    Connect {
        peer: [u8; 32],
        port: [u8; 64],
    },
    PeerSend {
        source: PeerSource,
        payload: PeerOutput<'a, 'i>,
    },
    ReceiveDone {
        source: PeerSource,
        input: InputId<'i>,
        delivery: u64,
    },
    ClientResult {
        response: ClientResponse<'a>,
    },
    CloseIntersection {
        id: IntersectionId<'i>,
    },
    ClosePeer {
        source: PeerSource,
    },
    ClosePort {
        port: [u8; 64],
    },
}
impl Action<'_, '_> {
    pub fn client_response(&self) -> Option<ClientResponse<'_>> {
        match self {
            Self::ClientResult { response } => Some(*response),
            _ => None,
        }
    }
}
pub(crate) struct Effect<'a, 'i> {
    pub id: EffectId<'i>,
    pub action: Action<'a, 'i>,
    pub admitted: bool,
}
impl Effect<'_, '_> {
    pub fn is_admitted(&self) -> bool {
        self.admitted
    }
}

/// One bounded original source classification. Full native causes stay in the
/// original SessionReport; algorithm-specific facts stay in the selected branch.
#[derive(Clone, Copy, Debug)]
pub struct Failure {
    /// Original error classification.
    pub cause: Fault,
}
/// Original Paillier observations without secret coefficients or MPI contents.
#[derive(Clone, Copy, Debug, Default)]
pub struct PaillierOutcome {
    /// Actual arithmetic completed, not a local client write.
    pub product_computed: bool,
    /// Bob's original last complete local MQ write, not Alice's result/ACK.
    pub reply_handed_off: bool,
    /// First original primitive/computation failure, without replacing IO causes.
    pub failure: Option<p::Error>,
    /// Independent original peer loss after/before arithmetic completion.
    pub peer_failure: Option<p::Error>,
}
/// Typed results of either actual installed profile. Paillier magnitudes never
/// pass through the ECC bounded-i32 result type.
#[derive(Clone, Copy, Debug, Default)]
pub struct Outcome {
    /// Exact existing ECC facts when ECC was explicitly selected.
    pub ecc: Option<ecc::Outcome>,
    /// Exact Paillier progress/failure facts when Paillier was selected.
    pub paillier: Option<PaillierOutcome>,
    /// Common original classified failure.
    pub failure: Option<Failure>,
    /// Original whole local client result write.
    pub client_written: bool,
    /// Independent error retiring an already written original client result.
    pub cleanup_failure: Option<Fault>,
}
impl Outcome {
    /// Existing ECC small-value convenience. Large Paillier values remain
    /// private owned MPI results and are deliberately not reduced to i32.
    #[must_use]
    pub fn known_value(self) -> Option<i32> {
        self.ecc.and_then(ecc::Outcome::known_value)
    }
}

pub(crate) struct Computation<'i> {
    ecc: Vec<ecc::Computation<'i>>,
    paillier: Vec<paillier::Computation<'i>>,
}
impl<'i> Computation<'i> {
    #[expect(
        clippy::too_many_arguments,
        reason = "selected original profile, brand, vector, key and admission origin are explicit"
    )]
    pub fn new(
        brand: &'i Instance,
        profile: Profile,
        role: Role,
        session: [u8; 64],
        peer: Option<[u8; 32]>,
        values: Vec<ecc::Value>,
        limits: Limits,
        key: Option<Rc<gnunet_paillier::KeyPair>>,
        origin: u64,
        entropy: &mut impl gnunet_crypto::Entropy,
    ) -> Result<Self, Error> {
        let mut this = Self {
            ecc: Vec::new(),
            paillier: Vec::new(),
        };
        match profile {
            Profile::Ecc => {
                let vector = ecc::Vector::new(
                    values,
                    limits.hash_order,
                    limits.max_rows,
                    limits.core.max_retained_bytes,
                )?;
                let core = match role {
                    Role::Alice => ecc::Computation::alice(
                        &brand.ecc,
                        session,
                        peer.ok_or(Fault::Malformed)?,
                        vector,
                        limits.core,
                        entropy,
                    )?,
                    Role::Bob => ecc::Computation::bob(&brand.ecc, session, vector, limits.core)?,
                };
                this.ecc.try_reserve_exact(1).map_err(|_| Fault::Capacity)?;
                if this
                    .ecc
                    .capacity()
                    .checked_mul(size_of::<ecc::Computation<'i>>())
                    .ok_or(Fault::Overflow)?
                    > limits.session_bytes
                {
                    return Err(Fault::Capacity.into());
                }
                this.ecc.push(core);
            }
            Profile::Paillier(policy) => {
                let vector = p::MatchedVector::new(
                    values,
                    limits.hash_order,
                    limits.max_rows,
                    policy.max_retained_bytes,
                )
                .map_err(Error::Paillier)?;
                this.paillier
                    .try_reserve_exact(1)
                    .map_err(|_| Fault::Capacity)?;
                let bytes = this
                    .paillier
                    .capacity()
                    .checked_mul(size_of::<paillier::Computation<'i>>())
                    .ok_or(Fault::Overflow)?;
                let allowance = limits.native_allowance()?;
                let outside = bytes
                    .checked_add(size_of::<Self>())
                    .and_then(|n| n.checked_add(allowance))
                    .ok_or(Fault::Overflow)?;
                let core = paillier::Computation::new(
                    &brand.paillier,
                    role,
                    session,
                    peer,
                    vector,
                    policy,
                    key,
                    origin,
                    outside,
                )?;
                this.paillier.push(core);
            }
        }
        Ok(this)
    }
    pub fn effect(&self) -> Option<Effect<'_, 'i>> {
        if let Some(core) = self.ecc.first() {
            let effect = core.effect()?;
            let action = match &effect.action {
                ecc::Action::ListenIntersection { id, app, peer } => Action::ListenIntersection {
                    id: IntersectionId::Ecc(*id),
                    app: *app,
                    peer: *peer,
                },
                ecc::Action::StartIntersection { id, app, peer } => Action::StartIntersection {
                    id: IntersectionId::Ecc(*id),
                    app: *app,
                    peer: *peer,
                },
                ecc::Action::OpenPort { port } => Action::OpenPort { port: *port },
                ecc::Action::Connect { peer, port } => Action::Connect {
                    peer: *peer,
                    port: *port,
                },
                ecc::Action::PeerSend { source, payload } => Action::PeerSend {
                    source: *source,
                    payload: PeerOutput::Ecc(payload),
                },
                ecc::Action::ReceiveDone {
                    source,
                    input,
                    delivery,
                } => Action::ReceiveDone {
                    source: *source,
                    input: InputId::Ecc(*input),
                    delivery: *delivery,
                },
                action @ ecc::Action::ClientResult { .. } => Action::ClientResult {
                    response: action.client_response()?,
                },
                ecc::Action::CloseIntersection { id } => Action::CloseIntersection {
                    id: IntersectionId::Ecc(*id),
                },
                ecc::Action::ClosePeer { source } => Action::ClosePeer { source: *source },
                ecc::Action::ClosePort { port } => Action::ClosePort { port: *port },
            };
            return Some(Effect {
                id: EffectId::Ecc(effect.id),
                action,
                admitted: effect.is_admitted(),
            });
        }
        self.paillier.first()?.effect()
    }
    pub fn admit_effect(&mut self, id: EffectId<'i>) -> Result<(), Fault> {
        match id {
            EffectId::Ecc(id) => self
                .ecc
                .first_mut()
                .ok_or(Fault::StaleGeneration)?
                .admit_effect(id),
            EffectId::Paillier(..) => self
                .paillier
                .first_mut()
                .ok_or(Fault::StaleGeneration)?
                .admit_effect(id),
        }
    }
    pub fn complete_effect(
        &mut self,
        id: EffectId<'i>,
        completion: Completion,
    ) -> Result<(), Fault> {
        match id {
            EffectId::Ecc(id) => self
                .ecc
                .first_mut()
                .ok_or(Fault::StaleGeneration)?
                .complete_effect(id, completion),
            EffectId::Paillier(..) => self
                .paillier
                .first_mut()
                .ok_or(Fault::StaleGeneration)?
                .complete_effect(id, completion),
        }
    }
    pub fn outcome(&self) -> Outcome {
        if let Some(core) = self.ecc.first() {
            let outcome = core.outcome();
            Outcome {
                ecc: Some(outcome),
                paillier: None,
                failure: outcome.failure.map(|f| Failure { cause: f.cause }),
                client_written: outcome.client_written,
                cleanup_failure: outcome.cleanup_failure,
            }
        } else {
            self.paillier
                .first()
                .map_or_else(Outcome::default, paillier::Computation::outcome)
        }
    }
    pub fn peer_source(&self) -> Option<PeerSource> {
        self.ecc
            .first()
            .and_then(ecc::Computation::peer_source)
            .or_else(|| {
                self.paillier
                    .first()
                    .and_then(paillier::Computation::peer_source)
            })
    }
    pub fn is_quiescent(&self) -> bool {
        self.ecc.first().is_none_or(ecc::Computation::is_quiescent)
            && self
                .paillier
                .first()
                .is_none_or(paillier::Computation::is_quiescent)
    }
    pub fn autonomous_work(&self) -> bool {
        !self.paillier.is_empty()
    }
    pub fn pump(&mut self) -> Result<bool, Fault> {
        if let Some(core) = self.paillier.first_mut() {
            core.pump()
        } else {
            Ok(false)
        }
    }
    pub fn attach_peer(&mut self, source: PeerSource) -> Result<(), Fault> {
        if let Some(core) = self.ecc.first_mut() {
            core.attach_peer(source)
        } else {
            self.paillier
                .first_mut()
                .ok_or(Fault::Stale)?
                .attach_peer(source)
        }
    }
    pub fn intersection_key(
        &self,
        id: IntersectionId<'i>,
        cursor: usize,
    ) -> Result<Option<&[u8; 64]>, Fault> {
        match id {
            IntersectionId::Ecc(id) => self
                .ecc
                .first()
                .ok_or(Fault::StaleGeneration)?
                .intersection_key(id, cursor),
            IntersectionId::Paillier(_) => self
                .paillier
                .first()
                .ok_or(Fault::StaleGeneration)?
                .intersection_key(id, cursor),
        }
    }
    pub fn intersection_removed(
        &mut self,
        id: IntersectionId<'i>,
        peer: [u8; 32],
        key: &[u8; 64],
        now: u64,
    ) -> Result<(), Fault> {
        match id {
            IntersectionId::Ecc(id) => self
                .ecc
                .first_mut()
                .ok_or(Fault::StaleGeneration)?
                .intersection_removed(id, peer, key),
            IntersectionId::Paillier(_) => self
                .paillier
                .first_mut()
                .ok_or(Fault::StaleGeneration)?
                .intersection_removed(id, peer, key, now),
        }
    }
    pub fn intersection_done(
        &mut self,
        id: IntersectionId<'i>,
        peer: [u8; 32],
        now: u64,
    ) -> Result<(), Fault> {
        match id {
            IntersectionId::Ecc(id) => self
                .ecc
                .first_mut()
                .ok_or(Fault::StaleGeneration)?
                .intersection_done(id, peer),
            IntersectionId::Paillier(_) => self
                .paillier
                .first_mut()
                .ok_or(Fault::StaleGeneration)?
                .intersection_done(id, peer, now),
        }
    }
    pub fn intersection_failed(
        &mut self,
        id: IntersectionId<'i>,
        cause: Fault,
    ) -> Result<(), Fault> {
        match id {
            IntersectionId::Ecc(id) => self
                .ecc
                .first_mut()
                .ok_or(Fault::StaleGeneration)?
                .intersection_failed(id, cause),
            IntersectionId::Paillier(_) => self
                .paillier
                .first_mut()
                .ok_or(Fault::StaleGeneration)?
                .intersection_failed(id, cause),
        }
    }
    pub fn receive(
        &mut self,
        source: PeerSource,
        delivery: u64,
        message: PeerMessage<'_>,
        now: u64,
    ) -> Result<InputId<'i>, Fault> {
        if let Some(core) = self.ecc.first_mut() {
            core.receive(source, delivery, message).map(InputId::Ecc)
        } else {
            self.paillier
                .first_mut()
                .ok_or(Fault::Stale)?
                .receive(source, delivery, message, now)
        }
    }
    pub fn step(
        &mut self,
        entropy: &mut impl gnunet_crypto::Entropy,
        units: usize,
        now: u64,
    ) -> Result<bool, Fault> {
        if let Some(core) = self.ecc.first_mut() {
            core.step(entropy, units).map(|()| true)
        } else {
            self.paillier
                .first_mut()
                .ok_or(Fault::Stale)?
                .step(entropy, units, now)
        }
    }
    pub fn peer_lost(&mut self, source: PeerSource, cause: Fault) -> Result<(), Fault> {
        if let Some(core) = self.ecc.first_mut() {
            core.peer_lost(source, cause)
        } else {
            self.paillier
                .first_mut()
                .ok_or(Fault::Stale)?
                .peer_lost(source, cause)
        }
    }
    pub fn cancel(&mut self) -> Result<(), Fault> {
        if let Some(core) = self.ecc.first_mut() {
            core.cancel()
        } else {
            self.paillier.first_mut().ok_or(Fault::Stale)?.cancel()
        }
    }
    pub fn paillier_error(&self) -> Option<p::Error> {
        self.paillier.first().and_then(paillier::Computation::error)
    }
    /// Only a Paillier Alice continuation already received on this exact source
    /// may wait for preceding local chunk work after actual channel destruction.
    /// ECC copies its single final point pair synchronously and needs no such gate.
    pub fn can_drain_peer_input(&self, source: PeerSource) -> bool {
        self.paillier
            .first()
            .is_some_and(|core| core.can_drain_peer_input(source))
    }
    pub fn can_finish_locally(&self) -> bool {
        if let Some(core) = self.ecc.first() {
            core.can_finish_locally()
        } else {
            self.paillier
                .first()
                .is_some_and(paillier::Computation::can_finish_locally)
        }
    }
    pub fn retire_peer_for_local_work(
        &mut self,
        source: PeerSource,
        cause: Fault,
        receipt: Option<(EffectId<'i>, Completion)>,
    ) -> Result<(), Fault> {
        if let Some(core) = self.ecc.first_mut() {
            let receipt = match receipt {
                Some((EffectId::Ecc(id), completion)) => Some((id, completion)),
                None => None,
                _ => return Err(Fault::StaleGeneration),
            };
            core.retire_peer_for_local_work(source, cause, receipt)
        } else {
            self.paillier
                .first_mut()
                .ok_or(Fault::Stale)?
                .retire_peer_for_local_work(source, cause, receipt)
        }
    }
}
