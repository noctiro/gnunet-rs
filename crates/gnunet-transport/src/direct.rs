//! One allocation-free TRANSPORT link over an authenticated reliable carrier.
//!
//! The embedding attaches this owner to the original TCP session, supplies
//! actual BOX admission and receive events, and drives CORE independently.
//! Direct TNG controls and CORE payloads share the same original carrier.
//! A replacement carrier gets a new link and scope.
use crate::{
    direct_flow::DirectFlow,
    direct_fragment::{REASSEMBLY_LIFETIME, Reassembly},
    direct_fragment_send::Sender,
    direct_validation::DirectValidation,
    dv::{BoxPacket, Learn},
    p2p::{self, Challenge, Fragment, Validation},
};
use core::num::{NonZeroU16, NonZeroU64};
use gnunet_crypto::{EddsaPrivateKey, EddsaPublicKey, Entropy};
use gnunet_types::{Error, MonoInstant, Rejected, RelativeTime};
use gnunet_wire::official::{Frame, MessageType, message_type as mt};

pub use crate::direct_flow::{Delivery, Scope};
pub use crate::direct_validation::Status;
pub use crate::{
    direct_fragment::FragmentLane,
    direct_fragment_send::{Progress as SendProgress, Span as SendSpan},
};

const FLOW_SIZE: usize = 60;

/// Scratch capacity sufficient for every control offered by this profile.
pub const MAX_CONTROL_SIZE: usize = 120;

/// Default number of concurrent input originals on a direct link.
pub const DEFAULT_REASSEMBLIES: usize = 4;

/// Local bounds and offered reachability of this authenticated carrier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Actual capacity for one complete CORE or DV frame.
    pub max_payload: NonZeroU16,
    /// Largest BOX payload used for outbound data, including fragment framing.
    pub max_box: NonZeroU16,
    /// Finite lifetime of an original pending validation challenge.
    pub response_timeout: RelativeTime,
    /// Local carrier validity advertised in responses, capped by the protocol.
    pub offered_validity: RelativeTime,
}

/// Exclusive fragment storage supplied for the lifetime of one carrier.
pub struct FragmentBuffers<'a, const N: usize = DEFAULT_REASSEMBLIES> {
    /// Independent originals. At least one lane must fit `Limits::max_payload`.
    pub receive: [FragmentLane<'a>; N],
    /// One encoded outbound fragment, bounded by the selected BOX limit.
    pub transmit: &'a mut [u8],
}

/// The outcome of one original authenticated TCP BOX input.
#[derive(Debug)]
#[must_use]
pub enum Received<'wire, 'scope> {
    /// The link consumed this official control.
    Control,
    /// A CORE frame and the exclusive receipt for its original byte charge.
    Payload {
        /// The original plaintext frame borrowed from the carrier input.
        frame: &'wire [u8],
        /// Return this after the original consumer releases the frame.
        delivery: Delivery<'scope>,
    },
    /// A DV frame attributed to this authenticated and validated carrier.
    Routed {
        /// The original structurally valid DV envelope.
        frame: RoutingFrame<'wire>,
        /// Release the charged data BOX after use. Control envelopes carry no charge.
        delivery: Option<Delivery<'scope>>,
    },
}

/// Official DV packet accepted from a validated carrier. End-to-end
/// signatures, ciphertext authentication and replay still belong to DV.
#[derive(Clone, Copy, Debug)]
pub enum RoutingFrame<'a> {
    /// A signed learning path.
    Learn(Learn<'a>),
    /// An encrypted DV envelope.
    Box(BoxPacket<'a>),
}

impl<'a> RoutingFrame<'a> {
    /// Check the extent and type of an official DV frame.
    ///
    /// # Errors
    /// Rejects non-DV types, malformed sizes and invalid hop counts.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        Self::decode_kind(Frame::decode(input)?.header().message_type(), input)
    }

    fn decode_kind(kind: MessageType, input: &'a [u8]) -> Result<Self, Error> {
        match kind {
            mt::TRANSPORT_DV_LEARN => Learn::decode(input).map(Self::Learn),
            mt::TRANSPORT_DV_BOX => BoxPacket::decode(input).map(Self::Box),
            _ => Err(Error::Unsupported),
        }
    }

    /// The exact encoded official frame.
    #[must_use]
    pub const fn bytes(self) -> &'a [u8] {
        match self {
            Self::Learn(learn) => learn.bytes(),
            Self::Box(packet) => packet.bytes(),
        }
    }

    fn uses_flow(self) -> Result<bool, Error> {
        match self {
            Self::Learn(_) => Ok(false),
            Self::Box(packet) => Ok(packet.without_fc()? != 1),
        }
    }
}

/// One complete original reassembled on the direct carrier.
#[derive(Clone, Copy, Debug)]
pub enum Reassembled<'a> {
    /// A CORE handshake or encrypted data frame.
    Core(&'a [u8]),
    /// An official DV envelope requiring separate routing.
    Routed(RoutingFrame<'a>),
}

/// Direct address validation, FLOW and original control output for one carrier.
pub struct Link<'scope, const N: usize = DEFAULT_REASSEMBLIES> {
    validation: DirectValidation,
    flow: DirectFlow<'scope>,
    response: Option<Validation>,
    reassembly: Reassembly<'scope, N>,
    fragments: Sender,
    fragment_output: &'scope mut [u8],
    limits: Limits,
}

impl<'scope, const N: usize> Link<'scope, N> {
    /// Bind the original reliable carrier and the identities it authenticated.
    ///
    /// The caller owns the exclusive carrier scope for this link's lifetime.
    ///
    /// # Errors
    /// Rejects invalid capacity, timeout, identity or zero offered validity.
    pub fn new(
        scope: &'scope mut Scope,
        local: EddsaPublicKey,
        remote: EddsaPublicKey,
        limits: Limits,
        buffers: FragmentBuffers<'scope, N>,
    ) -> Result<Self, Error> {
        if limits.offered_validity == RelativeTime::ZERO
            || limits.max_box > limits.max_payload
            || (limits.max_box < limits.max_payload
                && usize::from(limits.max_box.get()) <= p2p::FRAGMENT_HEADER_LEN)
        {
            return Err(Error::InvalidInput);
        }
        let size = usize::from(limits.max_payload.get());
        let output = buffers
            .transmit
            .get_mut(..usize::from(limits.max_box.get()))
            .ok_or(Error::Capacity)?;
        Ok(Self {
            validation: DirectValidation::new(local, remote, limits.response_timeout)?,
            flow: DirectFlow::new(scope, limits.max_payload)?,
            response: None,
            reassembly: Reassembly::new(size, buffers.receive)?,
            fragments: Sender::new(
                limits.max_box,
                RelativeTime::from_micros(REASSEMBLY_LIFETIME.0),
            )?,
            fragment_output: output,
            limits,
        })
    }

    /// Dispatch one authenticated plaintext BOX from the original carrier.
    ///
    /// A challenge retains at most one signed immutable response. A repeat
    /// of that challenge shares the existing response. CORE input requires a
    /// current validation proof and the one original delivery slot.
    ///
    /// # Errors
    /// `WouldBlock` leaves ownership of the original input at the carrier for
    /// retry. `NotReady` rejects premature CORE input; later validation
    /// controls must still be read. Unsupported message types never become
    /// payloads for CORE. Malformed or invalid controls fail independently.
    pub fn receive<'wire>(
        &mut self,
        now: MonoInstant,
        input: &'wire [u8],
        signer: &EddsaPrivateKey,
    ) -> Result<Received<'wire, 'scope>, Error> {
        let status = self.live_status(now)?;
        match Frame::decode(input)?.header().message_type() {
            mt::TRANSPORT_ADDRESS_VALIDATION_CHALLENGE => {
                let challenge = Challenge::decode(input)?;
                if let Some(response) = self.response {
                    if challenge.nonce != response.nonce || challenge.origin != response.origin {
                        return Err(Error::WouldBlock);
                    }
                } else {
                    self.response = Some(self.validation.answer(
                        challenge,
                        signer,
                        self.limits.offered_validity,
                    )?);
                }
            }
            mt::TRANSPORT_ADDRESS_VALIDATION_RESPONSE => {
                self.validation
                    .receive_response(now, Validation::decode(input)?)?;
                self.flow.request_announcement();
            }
            mt::TRANSPORT_FLOW_CONTROL => self.flow.receive_flow(input)?,
            mt::TRANSPORT_FRAGMENT => {
                if status == Status::Unvalidated {
                    return Err(Error::NotReady);
                }
                self.reassembly
                    .receive(now, Fragment::decode(input)?, |frame, bytes| {
                        let kind = frame.header().message_type();
                        if core_frame(kind) {
                            Ok(())
                        } else {
                            RoutingFrame::decode_kind(kind, bytes).map(|_| ())
                        }
                    })?;
            }
            mt::TRANSPORT_RELIABILITY_ACK => {
                // On a reliable carrier LOCAL BOX admission settles each
                // span. Remote receipts never grant CORE delivery credit.
                let _entries = p2p::acknowledgements(input)?;
            }
            kind if core_frame(kind) => {
                if status == Status::Unvalidated {
                    return Err(Error::NotReady);
                }
                if self.reassembly.frame().is_some() {
                    return Err(Error::WouldBlock);
                }
                return Ok(Received::Payload {
                    frame: input,
                    delivery: self.flow.admit_inbound(input)?,
                });
            }
            mt::TRANSPORT_DV_LEARN | mt::TRANSPORT_DV_BOX => {
                if status == Status::Unvalidated {
                    return Err(Error::NotReady);
                }
                if input.len() > usize::from(self.limits.max_payload.get()) {
                    return Err(Error::TooLarge);
                }
                let frame = RoutingFrame::decode(input)?;
                let delivery = if frame.uses_flow()? {
                    if self.reassembly.frame().is_some() {
                        return Err(Error::WouldBlock);
                    }
                    Some(self.flow.admit_classified(input.len())?)
                } else {
                    None
                };
                return Ok(Received::Routed { frame, delivery });
            }
            _ => return Err(Error::Unsupported),
        }
        Ok(Received::Control)
    }

    /// Whether an original completed by TRANSPORT is ready for a consumer.
    #[must_use]
    pub fn has_reassembled(&self) -> bool {
        self.reassembly.frame().is_some()
    }

    /// Consume a completed original in place. Pending earlier direct delivery
    /// can retain it until that delivery releases its exclusive byte charge.
    ///
    /// # Errors
    /// Refuses a conflicting earlier delivery. Once called, the consumer's
    /// result is returned after the complete original and its credit retire.
    pub fn deliver_reassembled<T>(
        &mut self,
        consume: impl FnOnce(Reassembled<'_>) -> Result<T, Error>,
    ) -> Result<Option<T>, Error> {
        let Some(frame) = self.reassembly.frame() else {
            return Ok(None);
        };
        let kind = Frame::decode(frame)?.header().message_type();
        let packet = if core_frame(kind) {
            Ok(Reassembled::Core(frame))
        } else {
            RoutingFrame::decode_kind(kind, frame).map(Reassembled::Routed)
        };
        let receipt = match &packet {
            Ok(Reassembled::Core(_)) => Some(self.flow.admit_inbound(frame)?),
            Ok(Reassembled::Routed(packet)) if packet.uses_flow()? => {
                Some(self.flow.admit_classified(frame.len())?)
            }
            _ => None,
        };
        let result = packet.and_then(consume);
        self.reassembly.clear_completed();
        if let Some(receipt) = receipt {
            self.flow
                .release_inbound(receipt)
                .map_err(|error| error.reason)?;
        }
        result.map(Some)
    }

    /// Admit at most one response, challenge or due FLOW on the original carrier.
    ///
    /// The callback receives the entire encoded frame in caller scratch. It
    /// returns success only when the TCP owner has admitted that original
    /// BOX. No control is marked sent before admission. A FLOW attempt may
    /// consume a durable stamp before a refusal. The carrier supplies its
    /// output readiness separately from protocol timer readiness.
    ///
    /// # Errors
    /// Returns capacity, local clock, entropy, stamp and original admission
    /// failures. `Ok(None)` means no control was offered to the callback.
    pub fn send_control<T>(
        &mut self,
        now: MonoInstant,
        scratch: &mut [u8],
        entropy: &mut impl Entropy,
        issue_stamp: impl FnOnce() -> Result<NonZeroU64, Error>,
        admit: impl FnOnce(&[u8]) -> Result<T, Error>,
    ) -> Result<Option<T>, Error> {
        self.live_status(now)?;
        if let Some(response) = self.response {
            let admitted = submit(scratch, &response.encode(), admit)?;
            self.response = None;
            return Ok(Some(admitted));
        }
        if let Some(challenge) = self.validation.poll_challenge(now, entropy)? {
            let admitted = submit(scratch, &challenge.encode(), admit)?;
            self.validation.challenge_admitted(now, challenge)?;
            return Ok(Some(admitted));
        }
        let mut admit = Some(admit);
        if let Some(accepted) = self.reassembly.poll_ack(now, scratch, |frame| {
            admit.take().ok_or(Error::Conflict)?(frame)
        })? {
            return Ok(Some(accepted));
        }
        if now < self.flow.next_flow_at()? {
            return Ok(None);
        }
        if scratch.len() < FLOW_SIZE {
            return Err(Error::Capacity);
        }
        self.flow.send_flow(now, issue_stamp, |frame| {
            submit(scratch, frame, admit.take().ok_or(Error::Conflict)?)
        })
    }

    /// Submit one complete CORE frame or its next original fragment.
    ///
    /// The caller retains its frame across a known refusal. The admission
    /// callback must report an error only for a BOX that was not admitted.
    ///
    /// # Errors
    /// Refuses unvalidated links, malformed or unsupported frames, and
    /// insufficient current grant or carrier capacity.
    pub fn send_payload<T>(
        &mut self,
        now: MonoInstant,
        input: &[u8],
        entropy: &mut impl Entropy,
        admit: impl FnOnce(&[u8]) -> Result<T, Error>,
    ) -> Result<SendProgress<T>, Error> {
        self.require_validated(now)?;
        if !core_frame(Frame::decode(input)?.header().message_type()) {
            return Err(Error::Unsupported);
        }
        self.send_frame(now, input, true, entropy, |bytes, _span| admit(bytes))
    }

    /// Submit official DV control or forwarding data on this validated link.
    /// Control traffic bypasses FLOW. Data BOXes use the current grant.
    /// The admission callback sees whether this BOX completes its original.
    ///
    /// # Errors
    /// Refuses an unvalidated link, oversized frame or unavailable admission.
    pub fn send_routing<T>(
        &mut self,
        now: MonoInstant,
        frame: RoutingFrame<'_>,
        entropy: &mut impl Entropy,
        admit: impl FnOnce(&[u8], SendSpan) -> Result<T, Error>,
    ) -> Result<SendProgress<T>, Error> {
        self.require_validated(now)?;
        self.send_frame(now, frame.bytes(), frame.uses_flow()?, entropy, admit)
    }

    fn send_frame<T>(
        &mut self,
        now: MonoInstant,
        input: &[u8],
        uses_flow: bool,
        entropy: &mut impl Entropy,
        admit: impl FnOnce(&[u8], SendSpan) -> Result<T, Error>,
    ) -> Result<SendProgress<T>, Error> {
        if input.len() > usize::from(self.limits.max_payload.get()) {
            return Err(Error::TooLarge);
        }
        if !self.fragments.is_active() && input.len() <= usize::from(self.limits.max_box.get()) {
            let admit = |bytes: &[u8]| admit(bytes, SendSpan::Final);
            return if uses_flow {
                self.flow.send_classified(input, admit)
            } else {
                admit(input)
            }
            .map(SendProgress::Complete);
        }
        self.fragments
            .send(now, input, self.fragment_output, entropy, |frame, span| {
                let admit = |bytes: &[u8]| admit(bytes, span);
                if uses_flow {
                    self.flow.send_fragment(frame, admit)
                } else {
                    admit(frame)
                }
            })
    }

    /// Return the original byte charge after the consumer releases its frame.
    ///
    /// # Errors
    /// A foreign or retired original receipt remains with the caller.
    pub fn release(
        &mut self,
        delivery: Delivery<'scope>,
    ) -> Result<(), Rejected<Delivery<'scope>>> {
        self.flow.release_inbound(delivery)
    }

    /// Observe unused outbound grant once validation currently holds.
    ///
    /// # Errors
    /// Refuses a closed, unvalidated or invalid-clock link.
    pub fn outbound_credit(&mut self, now: MonoInstant) -> Result<u64, Error> {
        self.require_validated(now)?;
        self.flow.outbound_credit()
    }

    /// An original frame still owns a fragment sequence on this carrier.
    #[must_use]
    pub fn fragmented_send_pending(&self) -> bool {
        self.fragments.is_active()
    }

    /// Advance the local reachability lease and observe its current status.
    ///
    /// # Errors
    /// Rejects a non-finite or regressing local clock while live.
    pub fn status(&mut self, now: MonoInstant) -> Result<Status, Error> {
        let status = self.validation.status(now)?;
        if matches!(status, Status::Ready(_)) {
            self.reassembly.expire(now);
            if self
                .fragments
                .deadline()
                .is_some_and(|deadline| now >= deadline)
            {
                return Err(Error::Deadline);
            }
        } else {
            self.reassembly.clear();
            self.fragments.cancel();
        }
        Ok(status)
    }

    /// Last verified response and the current renewal target.
    #[must_use]
    pub fn observe_validation(
        &self,
    ) -> (
        Option<crate::direct_validation::ValidationObservation>,
        Option<MonoInstant>,
    ) {
        (
            self.validation.observation(),
            self.validation.scheduled_validation(),
        )
    }

    /// Original direct FLOW owner's accounting, without granting credit.
    #[must_use]
    pub fn observe_flow(&self) -> crate::direct_flow::Observation {
        self.flow.observation()
    }

    /// Next expiry, including work that must run while output is blocked.
    #[must_use]
    pub fn maintenance_deadline(&self) -> Option<MonoInstant> {
        [
            self.validation.expires_at(),
            self.reassembly.expiry(),
            self.fragments.deadline(),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Next control timer. A zero instant represents an available response.
    ///
    /// # Errors
    /// A deadline that cannot be represented never becomes a forever timer.
    pub fn next_deadline(&self) -> Result<Option<MonoInstant>, Error> {
        let Some(validation) = self.validation.next_deadline() else {
            return Ok(None);
        };
        if self.response.is_some() {
            return Ok(Some(MonoInstant(0)));
        }
        Ok([
            Some(validation),
            Some(self.flow.next_flow_at()?),
            self.maintenance_deadline(),
            self.reassembly.ack_deadline(),
        ]
        .into_iter()
        .flatten()
        .min())
    }

    /// Fence every original receive receipt and discard pending link controls.
    pub fn cancel(&mut self) {
        self.response = None;
        self.validation.cancel();
        self.flow.cancel();
        self.reassembly.clear();
        self.fragments.cancel();
    }

    fn live_status(&mut self, now: MonoInstant) -> Result<Status, Error> {
        match self.status(now)? {
            Status::Closed => Err(Error::Closed),
            status => Ok(status),
        }
    }

    fn require_validated(&mut self, now: MonoInstant) -> Result<(), Error> {
        match self.status(now)? {
            Status::Ready(_) => Ok(()),
            Status::Unvalidated => Err(Error::NotReady),
            Status::Closed => Err(Error::Closed),
        }
    }
}

fn core_frame(kind: MessageType) -> bool {
    matches!(
        kind,
        mt::CORE_INITIATOR_HELLO
            | mt::CORE_RESPONDER_HELLO
            | mt::CORE_INITIATOR_DONE
            | mt::CORE_ENCRYPTED_MESSAGE_CAKE
    )
}

fn submit<T>(
    scratch: &mut [u8],
    frame: &[u8],
    admit: impl FnOnce(&[u8]) -> Result<T, Error>,
) -> Result<T, Error> {
    let output = scratch.get_mut(..frame.len()).ok_or(Error::Capacity)?;
    output.copy_from_slice(frame);
    admit(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PeerId, dv};

    struct EntropyFixture;

    impl Entropy for EntropyFixture {
        fn fill(&mut self, output: &mut [u8]) -> Result<(), Error> {
            output.fill(42);
            Ok(())
        }
    }

    #[test]
    fn validated_carriers_separate_core_and_fragmented_dv_delivery() -> Result<(), Error> {
        let left = EddsaPrivateKey::from_seed([1; 32]);
        let right = EddsaPrivateKey::from_seed([2; 32]);
        let mut left_scope = Scope::new();
        let mut right_scope = Scope::new();
        let limits = Limits {
            max_payload: NonZeroU16::new(1200).ok_or(Error::InvalidInput)?,
            max_box: NonZeroU16::new(128).ok_or(Error::InvalidInput)?,
            response_timeout: RelativeTime::from_micros(5_000_000),
            offered_validity: RelativeTime::from_micros(30_000_000),
        };
        let (mut left_body, mut left_map, mut left_box) = ([0; 1200], [0; 150], [0; 128]);
        let (mut right_body, mut right_map, mut right_box) = ([0; 1200], [0; 150], [0; 128]);
        let mut sender = Link::<1>::new(
            &mut left_scope,
            left.public_key(),
            right.public_key(),
            limits,
            FragmentBuffers {
                receive: [FragmentLane::new(&mut left_body, &mut left_map)?],
                transmit: &mut left_box,
            },
        )?;
        let mut peer = Link::<1>::new(
            &mut right_scope,
            right.public_key(),
            left.public_key(),
            limits,
            FragmentBuffers {
                receive: [FragmentLane::new(&mut right_body, &mut right_map)?],
                transmit: &mut right_box,
            },
        )?;
        let now = MonoInstant(1);
        let mut scratch = [0; MAX_CONTROL_SIZE];
        let mut entropy = EntropyFixture;
        let cake_frame = [0, 4, 0, 83];
        let reliability = [0, 4, 4, 192];
        let challenge = [17; 32];
        let initiator = PeerId(*left.public_key().as_bytes());
        let signed = left.sign(dv::INIT_PURPOSE, &dv::init_region(1, &challenge))?;
        let learn = dv::initiate(initiator, 1, &challenge, signed.as_bytes());
        if sender.receive(now, &cake_frame, &left).err() != Some(Error::NotReady)
            || peer.receive(now, &learn, &right).err() != Some(Error::NotReady)
            || sender.receive(now, &reliability, &left).err() != Some(Error::Unsupported)
        {
            return Err(Error::InvalidInput);
        }
        let challenge_size = sender
            .send_control(
                now,
                &mut scratch,
                &mut entropy,
                || Err(Error::Entropy),
                |frame| {
                    Challenge::decode(frame)?;
                    Ok(frame.len())
                },
            )?
            .ok_or(Error::NotReady)?;
        if !matches!(
            peer.receive(now, &scratch[..challenge_size], &right)?,
            Received::Control
        ) {
            return Err(Error::InvalidInput);
        }

        let refused = peer.send_control(
            now,
            &mut scratch,
            &mut entropy,
            || Err(Error::Entropy),
            |_| Err::<(), _>(Error::WouldBlock),
        );
        if refused != Err(Error::WouldBlock) {
            return Err(Error::InvalidInput);
        }
        let frozen = scratch;
        let response_size = peer
            .send_control(
                now,
                &mut scratch,
                &mut entropy,
                || Err(Error::Entropy),
                |frame| {
                    Validation::decode(frame)?;
                    Ok(frame.len())
                },
            )?
            .ok_or(Error::NotReady)?;
        if scratch != frozen
            || !matches!(
                sender.receive(now, &scratch[..response_size], &left)?,
                Received::Control
            )
            || !matches!(sender.status(now)?, Status::Ready(_))
            || peer.status(now)? != Status::Unvalidated
        {
            return Err(Error::InvalidInput);
        }
        let Received::Payload { frame, delivery } = sender.receive(now, &cake_frame, &left)? else {
            return Err(Error::InvalidInput);
        };
        if !core::ptr::eq(frame, &cake_frame[..]) {
            return Err(Error::InvalidInput);
        }
        sender
            .release(delivery)
            .map_err(|rejected| rejected.reason)?;

        peer.send_control(
            now,
            &mut scratch,
            &mut entropy,
            || Err(Error::Entropy),
            |message| {
                let _received = sender.receive(now, message, &left)?;
                Ok(())
            },
        )?
        .ok_or(Error::NotReady)?;
        sender
            .send_control(
                now,
                &mut scratch,
                &mut entropy,
                || Err(Error::Entropy),
                |message| {
                    let _received = peer.receive(now, message, &right)?;
                    Ok(())
                },
            )?
            .ok_or(Error::NotReady)?;

        let credit = sender.outbound_credit(now)?;
        let routed = RoutingFrame::decode(&learn)?;
        let mut submit = |message: &[u8], span| {
            let fragment = Fragment::decode(message)?;
            let expected = if usize::from(fragment.offset) + fragment.body.len()
                == usize::from(fragment.total)
            {
                SendSpan::Final
            } else {
                SendSpan::Partial
            };
            if span != expected {
                return Err(Error::Conflict);
            }
            let _received = peer.receive(now, message, &right)?;
            Ok(())
        };
        if !matches!(
            sender.send_routing(now, routed, &mut entropy, &mut submit)?,
            SendProgress::Partial(())
        ) || !matches!(
            sender.send_routing(now, routed, &mut entropy, submit)?,
            SendProgress::Complete(())
        ) || sender.outbound_credit(now)? != credit
        {
            return Err(Error::Conflict);
        }
        peer.deliver_reassembled(|packet| {
            let Reassembled::Routed(RoutingFrame::Learn(received)) = packet else {
                return Err(Error::Conflict);
            };
            if received.bytes() != learn {
                return Err(Error::Conflict);
            }
            received.verify(PeerId(*right.public_key().as_bytes()), initiator)?;
            Ok(())
        })?
        .ok_or(Error::NotReady)?;
        Ok(())
    }
}
