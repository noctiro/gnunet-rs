//! CAKE peer handshake, retransmission, record and liveness state. The transport
//! host retains every returned frame and owns its actual send/receive credit.
use crate::{
    record::{ReceiveError, Receiver, Sender},
    wire::{
        self, ACK, DONE_PREFIX, INITIATOR_PAYLOAD, INITIATOR_PREFIX, RESPONDER_PAYLOAD,
        RESPONDER_PREFIX, WordOrder,
    },
};
use gnunet_crypto::{EddsaPrivateKey, EddsaPublicKey, Entropy, hash512};
use gnunet_session_crypto::{
    Prk,
    exchange::{self, EcdhePublic, EcdheSecret},
    session::{self as crypto, Role},
    transcript::Hash512State,
};
use gnunet_types::Error;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

const SECOND: u64 = 1_000_000;
const PROBE: u64 = 30 * SECOND;
const IDLE: u64 = 5 * 60 * SECOND;

/// A peer's public identity and private KEM conversion, erased at owner drop.
/// Multiple sessions may borrow it without exporting or cloning secret keys.
pub struct Identity {
    public: EddsaPublicKey,
    kem: EcdheSecret,
}
impl Identity {
    /// Import an official Ed25519 seed and erase the local input copy.
    #[must_use]
    pub fn from_seed(mut seed: [u8; 32]) -> Self {
        let public = EddsaPrivateKey::from_seed(seed).public_key();
        let kem = EcdheSecret::from_eddsa_seed(seed);
        seed.zeroize();
        Self { public, kem }
    }
    /// Exact public peer bytes; this grants no session authentication.
    #[must_use]
    pub const fn public_key(&self) -> EddsaPublicKey {
        self.public
    }
}

/// Public handshake progress, independent of any old established association.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// The selected initiator must start a fresh exchange.
    Ready,
    /// The selected responder is waiting for InitiatorHello.
    AwaitInitiator,
    /// The InitiatorHello flight is retained for retransmission.
    InitiatorHelloSent,
    /// A proposed responder association awaits verified InitiatorDone.
    ResponderHelloSent,
    /// The initiator has keys but still needs authenticated explicit confirmation.
    InitiatorDoneSent,
    /// A fully confirmed association is available for application traffic.
    Established,
}
/// An actual core transition. Encoded bytes are not a transport acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    /// No application delivery or outgoing frame was produced.
    None,
    /// Send exactly this many newly encoded or original retransmitted bytes.
    Send(usize),
    /// Confirmation completed; also send the indicated reply bytes when nonzero.
    Established(usize),
    /// Deliver this many authenticated application bytes from caller scratch.
    Payload(usize),
    /// The old confirmed association expired; no success is implied for its work.
    Lost,
}

enum Handshake {
    Idle,
    Initiator {
        ephemeral: EcdheSecret,
        early: Prk,
        transcript: Hash512State,
    },
    Responder {
        ihts: Prk,
        master: Prk,
        traffic: Prk,
        transcript: Hash512State,
        peer_class: u16,
    },
    Confirming,
}
struct Association {
    sender: Sender,
    receiver: Receiver,
    confirmed: bool,
    peer_class: u16,
}

/// Allocation-free CORE peer owner. `F` bounds retained handshake bytes, not the
/// official protocol's frame limit. A host can choose up to the full u16 profile.
/// No native runtime, socket, hidden RNG, self-reference or C backend is used.
pub struct Session<'a, const F: usize = 1024> {
    identity: &'a Identity,
    peer: EddsaPublicKey,
    order: WordOrder,
    local_info: &'a [u8],
    local_class: u16,
    initiator: bool,
    phase: Phase,
    handshake: Handshake,
    association: Option<Association>,
    flight: [u8; F],
    flight_len: usize,
    peer_flight: Option<[u8; 64]>,
    retransmit_at: u64,
    retransmit_delay: u64,
    retransmits: u8,
    idle_at: u64,
    probe_at: u64,
    unanswered: u8,
}
impl<'a, const F: usize> Session<'a, F> {
    /// Select the official hash-order role for one transport-bound peer identity.
    /// `local_info` is the exact optional services-info byte string, without a NUL.
    pub fn new(
        identity: &'a Identity,
        peer: EddsaPublicKey,
        order: WordOrder,
        local_info: &'a [u8],
    ) -> Result<Self, Error> {
        Self::with_class(identity, peer, order, local_info, 0)
    }
    /// Select the advertised peer class. It is authenticated by the handshake;
    /// the default constructor retains the current reference UNKNOWN class.
    pub fn with_class(
        identity: &'a Identity,
        peer: EddsaPublicKey,
        order: WordOrder,
        local_info: &'a [u8],
        local_class: u16,
    ) -> Result<Self, Error> {
        if identity.public == peer || local_info.contains(&0) {
            return Err(Error::InvalidInput);
        }
        let minimum = INITIATOR_PREFIX + INITIATOR_PAYLOAD + 16;
        if F < minimum || local_info.len() > F - minimum {
            return Err(Error::Capacity);
        }
        let initiator = wire::is_initiator(identity.public.as_bytes(), peer.as_bytes(), order);
        Ok(Self {
            identity,
            peer,
            order,
            local_info,
            local_class,
            initiator,
            phase: if initiator {
                Phase::Ready
            } else {
                Phase::AwaitInitiator
            },
            handshake: Handshake::Idle,
            association: None,
            flight: [0; F],
            flight_len: 0,
            peer_flight: None,
            retransmit_at: u64::MAX,
            retransmit_delay: SECOND,
            retransmits: 0,
            idle_at: u64::MAX,
            probe_at: u64::MAX,
            unanswered: 0,
        })
    }
    /// Current handshake state; an old authenticated association can coexist.
    #[must_use]
    pub const fn phase(&self) -> Phase {
        self.phase
    }
    /// Whether application delivery is currently authorized.
    #[must_use]
    pub fn established(&self) -> bool {
        self.association.as_ref().is_some_and(|a| a.confirmed)
    }
    /// Authenticated class of the currently confirmed association. A proposed
    /// re-handshake never replaces old public metadata before Finished succeeds.
    #[must_use]
    pub fn peer_class(&self) -> Option<u16> {
        self.association
            .as_ref()
            .filter(|a| a.confirmed)
            .map(|a| a.peer_class)
    }
    /// Original logical target for the next host wake, including retransmission.
    #[must_use]
    pub fn next_deadline(&self) -> u64 {
        self.retransmit_at.min(self.probe_at).min(self.idle_at)
    }
    /// Encode application messages only after explicit peer confirmation.
    pub fn send(&mut self, now: u64, messages: &[u8], output: &mut [u8]) -> Result<usize, Error> {
        let association = self
            .association
            .as_mut()
            .filter(|a| a.confirmed)
            .ok_or(Error::NotReady)?;
        association.sender.seal(now, messages, output)
    }
    fn capacity(&self, output: &[u8], size: usize) -> Result<(), Error> {
        if size > F || size > usize::from(u16::MAX) || output.len() < size {
            Err(Error::Capacity)
        } else {
            Ok(())
        }
    }
    fn remember(&mut self, now: u64, output: &[u8], size: usize) {
        self.flight[..size].copy_from_slice(&output[..size]);
        self.flight_len = size;
        self.retransmits = 0;
        self.retransmit_delay = SECOND;
        self.retransmit_at = now.saturating_add(SECOND);
    }
    fn repeat(&self, output: &mut [u8]) -> Result<Event, Error> {
        if output.len() < self.flight_len {
            return Err(Error::Capacity);
        }
        output[..self.flight_len].copy_from_slice(&self.flight[..self.flight_len]);
        Ok(Event::Send(self.flight_len))
    }
    fn activity(&mut self, now: u64) {
        self.idle_at = now.saturating_add(IDLE);
        self.probe_at = now.saturating_add(PROBE);
        self.unanswered = 0;
    }
    fn forget_flight(&mut self) {
        self.flight[..self.flight_len].zeroize();
        self.flight_len = 0;
        self.retransmit_at = u64::MAX;
        self.handshake = Handshake::Idle;
    }
    /// Drive the original retained logical deadlines. Retransmission is byte
    /// identical; native scheduling and transport admission stay with the host.
    pub fn tick(
        &mut self,
        now: u64,
        entropy: &mut impl Entropy,
        output: &mut [u8],
    ) -> Result<Event, Error> {
        if self.association.is_some()
            && ((self.idle_at != u64::MAX && now >= self.idle_at)
                || (self.probe_at != u64::MAX && now >= self.probe_at && self.unanswered >= 3))
        {
            let was_confirmed = self.established();
            self.association = None;
            self.forget_flight();
            self.idle_at = u64::MAX;
            self.probe_at = u64::MAX;
            self.phase = if self.initiator {
                Phase::Ready
            } else {
                Phase::AwaitInitiator
            };
            if was_confirmed {
                return Ok(Event::Lost);
            }
        }
        if self.phase == Phase::Ready {
            return self.initiate(now, entropy, output);
        }
        if self.flight_len != 0 && self.retransmit_at != u64::MAX && now >= self.retransmit_at {
            if self.retransmits == 5 {
                // These keys belonged to an exchange that never received its
                // explicit confirmation. Once that exchange is abandoned, a
                // late ACK must not confirm or erase the next handshake flight.
                // An older confirmed association during responder re-handshake
                // remains usable until the new Finished or its own idle timeout.
                if self.association.as_ref().is_some_and(|a| !a.confirmed) {
                    self.association = None;
                    self.idle_at = u64::MAX;
                    self.probe_at = u64::MAX;
                    self.unanswered = 0;
                }
                self.forget_flight();
                self.phase = if self.established() {
                    Phase::Established
                } else if self.initiator {
                    Phase::Ready
                } else {
                    Phase::AwaitInitiator
                };
                if self.phase == Phase::Ready {
                    return self.initiate(now, entropy, output);
                }
            } else {
                let event = self.repeat(output)?;
                self.retransmits += 1;
                self.retransmit_delay = self.retransmit_delay.saturating_mul(2).min(60 * SECOND);
                self.retransmit_at = now.saturating_add(self.retransmit_delay);
                return Ok(event);
            }
        }
        if self.association.is_some() && self.probe_at != u64::MAX && now >= self.probe_at {
            if output.len() < 44 {
                return Err(Error::Capacity);
            }
            let heartbeat = [0, 8, 0, 84, 0, 0, 0, 0];
            let size = self
                .association
                .as_mut()
                .ok_or(Error::NotReady)?
                .sender
                .seal(now, &heartbeat, output)?;
            self.unanswered += 1;
            self.probe_at = now.saturating_add(PROBE);
            return Ok(Event::Send(size));
        }
        Ok(Event::None)
    }
    fn initiate(
        &mut self,
        now: u64,
        entropy: &mut impl Entropy,
        output: &mut [u8],
    ) -> Result<Event, Error> {
        let size = INITIATOR_PREFIX + INITIATOR_PAYLOAD + self.local_info.len() + 16;
        self.capacity(output, size)?;
        let recipient = EcdhePublic::from_edwards(self.peer.as_bytes())?;
        let (encapsulation, shared) = exchange::kem_encapsulate_random(recipient, entropy)?;
        let ephemeral = EcdheSecret::generate(entropy)?;
        output[..size].fill(0);
        wire::header(output, size, 80)?;
        entropy
            .fill(&mut output[8..16])
            .map_err(|_| Error::Entropy)?;
        output[16..48].copy_from_slice(ephemeral.public_key().as_bytes());
        output[48..80].copy_from_slice(encapsulation.as_bytes());
        output[80..144].copy_from_slice(&hash512(self.peer.as_bytes()));
        let mut transcript = Hash512State::new();
        transcript.update(&output[..INITIATOR_PREFIX]);
        let (early, traffic) = crypto::early(&shared, &snapshot(&transcript))?;
        output[144..176].copy_from_slice(self.identity.public.as_bytes());
        output[176..178].copy_from_slice(&self.local_class.to_be_bytes());
        output[178..size - 16].copy_from_slice(self.local_info);
        seal_part(&traffic, 0, &mut output[INITIATOR_PREFIX..size])?;
        transcript.update(&output[INITIATOR_PREFIX..size]);
        self.handshake = Handshake::Initiator {
            ephemeral,
            early,
            transcript,
        };
        self.phase = Phase::InitiatorHelloSent;
        self.peer_flight = None;
        self.remember(now, output, size);
        Ok(Event::Send(size))
    }
    /// Consume one complete peer frame. Scratch contains plaintext only after
    /// successful authentication. Invalid frames do not refresh peer liveness.
    pub fn receive(
        &mut self,
        now: u64,
        input: &[u8],
        entropy: &mut impl Entropy,
        output: &mut [u8],
        scratch: &mut [u8],
    ) -> Result<Event, Error> {
        self.receive_classified(now, input, entropy, output, scratch)
            .map_err(ReceiveError::cause)
    }
    /// Consume the same original input with precise record-rejection provenance.
    /// Only a public epoch-policy rejection is `RejectedEpoch`; handshake,
    /// local resource and crypto errors retain their original `Failed` cause.
    /// Rejected records do not refresh activity or mutate replay/session state.
    pub fn receive_classified(
        &mut self,
        now: u64,
        input: &[u8],
        entropy: &mut impl Entropy,
        output: &mut [u8],
        scratch: &mut [u8],
    ) -> Result<Event, ReceiveError> {
        match wire::kind(input)? {
            80 if !self.initiator => self
                .initiator_hello(now, input, entropy, output, scratch)
                .map_err(ReceiveError::Failed),
            81 if self.initiator => self
                .responder_hello(now, input, output, scratch)
                .map_err(ReceiveError::Failed),
            82 if !self.initiator => self
                .initiator_done(now, input, output)
                .map_err(ReceiveError::Failed),
            83 => self.record(now, input, output, scratch),
            _ => Ok(Event::None),
        }
    }
    fn initiator_hello(
        &mut self,
        now: u64,
        input: &[u8],
        entropy: &mut impl Entropy,
        output: &mut [u8],
        scratch: &mut [u8],
    ) -> Result<Event, Error> {
        if input.len() < INITIATOR_PREFIX + INITIATOR_PAYLOAD + 16 {
            return Err(Error::Truncated);
        }
        let hash = hash512(input);
        if self.peer_flight == Some(hash) {
            return if self.phase == Phase::ResponderHelloSent {
                self.repeat(output)
            } else {
                Ok(Event::None)
            };
        }
        if !bool::from(input[80..144].ct_eq(&hash512(self.identity.public.as_bytes()))) {
            return Err(Error::Authentication);
        }
        let size = RESPONDER_PREFIX + RESPONDER_PAYLOAD + self.local_info.len() + 96;
        self.capacity(output, size)?;
        let shared = exchange::kem_decapsulate(
            &self.identity.kem,
            EcdhePublic::from_bytes(wire::array(input, 48)?),
        )?;
        let mut transcript = Hash512State::new();
        transcript.update(&input[..INITIATOR_PREFIX]);
        let (early, traffic) = crypto::early(&shared, &snapshot(&transcript))?;
        let plain = open_part(&traffic, 0, &input[INITIATOR_PREFIX..], scratch)?;
        if plain < INITIATOR_PAYLOAD || !bool::from(scratch[..32].ct_eq(self.peer.as_bytes())) {
            return Err(Error::Authentication);
        }
        let peer_class = u16::from_be_bytes(wire::array(scratch, 32)?);
        transcript.update(&input[INITIATOR_PREFIX..]);
        let (ephemeral, ephemeral_shared) = exchange::kem_encapsulate_random(
            EcdhePublic::from_bytes(wire::array(input, 16)?),
            entropy,
        )?;
        let (challenge, identity_shared) = exchange::kem_encapsulate_random(
            EcdhePublic::from_edwards(self.peer.as_bytes())?,
            entropy,
        )?;
        let handshake = crypto::handshake(&early, &ephemeral_shared)?;
        let master = crypto::master(&handshake, &identity_shared)?;
        output[..size].fill(0);
        wire::header(output, size, 81)?;
        entropy
            .fill(&mut output[8..16])
            .map_err(|_| Error::Entropy)?;
        output[16..48].copy_from_slice(ephemeral.as_bytes());
        transcript.update(&output[..RESPONDER_PREFIX]);
        let rhts = crypto::handshake_traffic(&handshake, &snapshot(&transcript), Role::Responder)?;
        let ihts = crypto::handshake_traffic(&handshake, &snapshot(&transcript), Role::Initiator)?;
        let first_end = size - 80;
        output[48..80].copy_from_slice(challenge.as_bytes());
        output[80..82].copy_from_slice(&self.local_class.to_be_bytes());
        output[82..first_end - 16].copy_from_slice(self.local_info);
        seal_part(&rhts, 0, &mut output[RESPONDER_PREFIX..first_end])?;
        transcript.update(&output[RESPONDER_PREFIX..first_end]);
        let finished = Zeroizing::new(crypto::finished(
            &master,
            &snapshot(&transcript),
            Role::Responder,
        )?);
        output[first_end..first_end + 64].copy_from_slice(finished.as_ref());
        seal_part(&rhts, 1, &mut output[first_end..size])?;
        transcript.update(&output[first_end..size]);
        let traffic =
            crypto::application_traffic(&master, &snapshot(&transcript), Role::Responder)?;
        self.handshake = Handshake::Responder {
            ihts,
            master,
            traffic,
            transcript,
            peer_class,
        };
        self.phase = Phase::ResponderHelloSent;
        self.peer_flight = Some(hash);
        self.remember(now, output, size);
        Ok(Event::Send(size))
    }
    fn responder_hello(
        &mut self,
        now: u64,
        input: &[u8],
        output: &mut [u8],
        scratch: &mut [u8],
    ) -> Result<Event, Error> {
        if input.len() < RESPONDER_PREFIX + RESPONDER_PAYLOAD + 96 {
            return Err(Error::Truncated);
        }
        let hash = hash512(input);
        if self.phase == Phase::InitiatorDoneSent && self.peer_flight == Some(hash) {
            return self.repeat(output);
        }
        let Handshake::Initiator {
            ephemeral,
            early,
            transcript,
        } = &self.handshake
        else {
            return Ok(Event::None);
        };
        self.capacity(output, 104)?;
        let shared =
            exchange::kem_decapsulate(ephemeral, EcdhePublic::from_bytes(wire::array(input, 16)?))?;
        let handshake = crypto::handshake(early, &shared)?;
        let mut transcript = transcript.clone();
        transcript.update(&input[..RESPONDER_PREFIX]);
        let rhts = crypto::handshake_traffic(&handshake, &snapshot(&transcript), Role::Responder)?;
        let ihts = crypto::handshake_traffic(&handshake, &snapshot(&transcript), Role::Initiator)?;
        let first_end = input.len() - 80;
        open_part(&rhts, 0, &input[RESPONDER_PREFIX..first_end], scratch)?;
        let peer_class = u16::from_be_bytes(wire::array(scratch, 32)?);
        let identity_shared = exchange::kem_decapsulate(
            &self.identity.kem,
            EcdhePublic::from_bytes(wire::array(scratch, 0)?),
        )?;
        let master = crypto::master(&handshake, &identity_shared)?;
        transcript.update(&input[RESPONDER_PREFIX..first_end]);
        let mut finished = Zeroizing::new([0; 64]);
        open_part(&rhts, 1, &input[first_end..], finished.as_mut())?;
        if !bool::from(finished.ct_eq(&crypto::finished(
            &master,
            &snapshot(&transcript),
            Role::Responder,
        )?)) {
            return Err(Error::Authentication);
        }
        transcript.update(&input[first_end..]);
        let peer_traffic =
            crypto::application_traffic(&master, &snapshot(&transcript), Role::Responder)?;
        let finished = Zeroizing::new(crypto::finished(
            &master,
            &snapshot(&transcript),
            Role::Initiator,
        )?);
        output[..104].fill(0);
        wire::header(output, 104, 82)?;
        output[4..68].copy_from_slice(finished.as_ref());
        seal_part(&ihts, 0, &mut output[4..DONE_PREFIX])?;
        transcript.update(&output[4..DONE_PREFIX]);
        let traffic =
            crypto::application_traffic(&master, &snapshot(&transcript), Role::Initiator)?;
        output[84..88].copy_from_slice(&ACK);
        seal_part(&traffic, 0, &mut output[84..104])?;
        let receiver = Receiver::new(peer_traffic, true, false)?;
        self.association = Some(Association {
            sender: Sender::new(traffic, 1, now),
            receiver,
            confirmed: false,
            peer_class,
        });
        self.activity(now);
        self.handshake = Handshake::Confirming;
        self.phase = Phase::InitiatorDoneSent;
        self.peer_flight = Some(hash);
        self.remember(now, output, 104);
        Ok(Event::Send(104))
    }
    fn initiator_done(
        &mut self,
        now: u64,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<Event, Error> {
        if input.len() < 104 {
            return Err(Error::Truncated);
        }
        if self.phase == Phase::Established {
            return Ok(Event::Send(
                self.association
                    .as_mut()
                    .ok_or(Error::NotReady)?
                    .sender
                    .seal(now, &ACK, output)?,
            ));
        }
        let Handshake::Responder {
            ihts,
            master,
            traffic,
            transcript,
            ..
        } = &self.handshake
        else {
            return Ok(Event::None);
        };
        self.capacity(output, 40)?;
        let mut finished = Zeroizing::new([0; 64]);
        open_part(ihts, 0, &input[4..84], finished.as_mut())?;
        if !bool::from(finished.ct_eq(&crypto::finished(
            master,
            &snapshot(transcript),
            Role::Initiator,
        )?)) {
            return Err(Error::Authentication);
        }
        let mut transcript = transcript.clone();
        transcript.update(&input[4..84]);
        let peer_traffic =
            crypto::application_traffic(master, &snapshot(&transcript), Role::Initiator)?;
        let mut ack = [0; 4];
        open_part(&peer_traffic, 0, &input[84..104], &mut ack)?;
        if ack != ACK {
            return Err(Error::Authentication);
        }
        let receiver = Receiver::new(peer_traffic, false, true)?;
        output[36..40].copy_from_slice(&ACK);
        let (tag, sequence) = crypto::seal_record(traffic, 1, &mut output[36..40])?;
        wire::header(output, 40, 83)?;
        output[4..12].copy_from_slice(&0_u64.to_be_bytes());
        output[12..20].copy_from_slice(&sequence);
        output[20..36].copy_from_slice(&tag);
        let Handshake::Responder {
            traffic,
            peer_class,
            ..
        } = core::mem::replace(&mut self.handshake, Handshake::Idle)
        else {
            return Err(Error::NotReady);
        };
        self.association = Some(Association {
            sender: Sender::new(traffic, 2, now),
            receiver,
            confirmed: true,
            peer_class,
        });
        self.forget_flight();
        self.phase = Phase::Established;
        self.activity(now);
        Ok(Event::Established(40))
    }
    fn record(
        &mut self,
        now: u64,
        input: &[u8],
        output: &mut [u8],
        scratch: &mut [u8],
    ) -> Result<Event, ReceiveError> {
        // Reserve the largest control response before consuming any record/credit.
        if output.len() < 40 {
            return Err(Error::Capacity.into());
        }
        let Some(association) = &mut self.association else {
            return Ok(Event::None);
        };
        let (_, size) = association.receiver.open_classified(input, scratch)?;
        self.activity(now);
        let kind = u16::from_be_bytes([scratch[2], scratch[3]]);
        let declared = usize::from(u16::from_be_bytes([scratch[0], scratch[1]]));
        let control = (kind == 85 && declared == 4) || (kind == 84 && declared == 8 && size >= 8);
        if control {
            let was_confirmed = self.established();
            let association = self.association.as_mut().ok_or(Error::NotReady)?;
            if kind == 84 {
                let flags = wire::array(scratch, 4)?;
                let flags = match self.order {
                    WordOrder::Little => u32::from_le_bytes(flags),
                    WordOrder::Big => u32::from_be_bytes(flags),
                };
                if flags & 1 != 0 {
                    association.sender.update(now)?;
                }
            }
            let reply = if kind == 84 {
                association.sender.seal(now, &ACK, output)?
            } else {
                0
            };
            association.confirmed = true;
            if !was_confirmed {
                self.forget_flight();
                self.phase = Phase::Established;
                return Ok(Event::Established(reply));
            }
            return Ok(if reply == 0 {
                Event::None
            } else {
                Event::Send(reply)
            });
        }
        if !self.established() {
            return Ok(Event::None);
        }
        wire::messages(&scratch[..size])?;
        Ok(Event::Payload(size))
    }
}
fn snapshot(transcript: &Hash512State) -> [u8; 64] {
    transcript.clone().finish()
}
fn seal_part(key: &Prk, sequence: u64, bytes: &mut [u8]) -> Result<(), Error> {
    let split = bytes.len().checked_sub(16).ok_or(Error::Truncated)?;
    let (plaintext, tag) = bytes.split_at_mut(split);
    tag.copy_from_slice(&crypto::record_material(key, sequence)?.seal(&[], plaintext)?);
    Ok(())
}
fn open_part(key: &Prk, sequence: u64, bytes: &[u8], output: &mut [u8]) -> Result<usize, Error> {
    let size = bytes.len().checked_sub(16).ok_or(Error::Truncated)?;
    if output.len() < size {
        return Err(Error::Capacity);
    }
    let tag = wire::array(bytes, size)?;
    output[..size].copy_from_slice(&bytes[..size]);
    crypto::record_material(key, sequence)?.open(&[], &mut output[..size], &tag)?;
    Ok(size)
}
