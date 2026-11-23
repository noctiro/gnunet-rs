//! Bounded CORE driving over one reliable, validated TRANSPORT carrier.
use crate::{
    record::ReceiveError,
    session::{Event, Identity, Monitor, Phase, Session},
    wire::{INITIATOR_PAYLOAD, INITIATOR_PREFIX, RESPONDER_PAYLOAD, WordOrder},
};
use core::num::NonZeroUsize;
use gnunet_crypto::{EddsaPublicKey, Entropy};
use gnunet_types::Error;
use gnunet_wire::official::Frame;
use zeroize::Zeroize;

/// Local identity and handshake policy for a direct CORE peer.
pub struct Local<'a> {
    /// The original local CORE identity.
    pub identity: &'a Identity,
    /// The chosen reference-native word-order profile.
    pub order: WordOrder,
    /// The optional services-info suffix without a NUL.
    pub services: &'a [u8],
    /// The advertised authenticated class of this local peer.
    pub class: u16,
}

/// Progress of admitting the original encoded frame to a lower carrier.
pub enum Submission<T> {
    /// More of the original frame remains to be submitted.
    Pending,
    /// The entire frame was admitted.
    Complete(T),
}

/// One CORE association and one caller-owned admission slot for encoded output.
///
/// TRANSPORT owns validation and every original carrier completion. Inbound
/// plaintext is lent synchronously. The slot retains exact outbound bytes until
/// the original lower owner accepts them or the carrier is retired.
pub struct Peer<'identity, 'buffers, const F: usize = 1024> {
    local: Local<'identity>,
    session: Option<Session<'identity, F>>,
    outbound: &'buffers mut [u8],
    plaintext: &'buffers mut [u8],
    pending: Option<NonZeroUsize>,
}

impl<'identity, 'buffers, const F: usize> Peer<'identity, 'buffers, F> {
    /// Reserve buffers before exposing a peer to the direct path.
    /// Bound `outbound` to the largest frame the selected carrier can admit.
    ///
    /// # Errors
    /// Refuses local services-info with a NUL or insufficient capacity for its
    /// handshake. Larger frames still require enough capacity at admission.
    pub fn new(
        local: Local<'identity>,
        outbound: &'buffers mut [u8],
        plaintext: &'buffers mut [u8],
    ) -> Result<Self, Error> {
        let flight = (INITIATOR_PREFIX + INITIATOR_PAYLOAD + 16)
            .checked_add(local.services.len())
            .ok_or(Error::Capacity)?;
        if local.services.contains(&0) {
            return Err(Error::InvalidInput);
        }
        if flight > F.min(outbound.len()).min(usize::from(u16::MAX))
            || plaintext.len() < INITIATOR_PAYLOAD.max(RESPONDER_PAYLOAD)
        {
            return Err(Error::Capacity);
        }
        Ok(Self {
            local,
            session: None,
            outbound,
            plaintext,
            pending: None,
        })
    }

    /// Start a new association for the identity proven on this exact carrier.
    /// The embedding calls this only after its TRANSPORT validation succeeds.
    ///
    /// # Errors
    /// Refuses replacement of a live carrier or association with the local peer.
    pub fn activate_validated(&mut self, peer: EddsaPublicKey) -> Result<(), Error> {
        if self.session.is_some() {
            return Err(Error::Conflict);
        }
        self.session = Some(Session::with_class(
            self.local.identity,
            peer,
            self.local.order,
            self.local.services,
            self.local.class,
        )?);
        Ok(())
    }

    /// Drop the original association and disarm every staged frame on loss.
    pub fn carrier_lost(&mut self) {
        self.session = None;
        self.clear_pending();
    }

    /// Whether the original session has explicitly confirmed its association.
    #[must_use]
    pub fn established(&self) -> bool {
        self.session.as_ref().is_some_and(Session::established)
    }

    /// Authenticated class of the currently confirmed CORE association.
    #[must_use]
    pub fn peer_class(&self) -> Option<u16> {
        self.session.as_ref()?.peer_class()
    }

    /// Observe the active original CAKE session, including unconfirmed phases.
    #[must_use]
    pub fn monitor(&self) -> Option<Monitor> {
        self.session.as_ref().map(Session::monitor)
    }

    /// Whether an encoded frame still owns the original output slot.
    #[must_use]
    pub const fn has_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// Association expiry independent of the original output slot.
    #[must_use]
    pub fn association_expiry(&self) -> Option<u64> {
        self.session.as_ref()?.association_expiry()
    }

    /// Retire an expired association and any staged bytes from its old keys.
    /// Returns whether any association was retired.
    pub fn expire_association(&mut self, now: u64) -> bool {
        if self
            .session
            .as_mut()
            .and_then(|session| session.expire_association(now))
            .is_none()
        {
            return false;
        }
        self.clear_pending();
        true
    }

    /// Schedule a CORE tick while the output slot can accept its result.
    /// A ready initiator can run immediately. A retained frame waits for lower
    /// admission or carrier retirement before the next CORE timer turn.
    #[must_use]
    pub fn next_deadline(&self) -> Option<u64> {
        if self.has_pending() {
            return None;
        }
        let session = self.session.as_ref()?;
        if session.phase() == Phase::Ready {
            return Some(0);
        }
        let deadline = session.next_deadline();
        (deadline != u64::MAX).then_some(deadline)
    }

    /// Advance the handshake, retransmission or liveness state once.
    /// A tick leaves an occupied output slot intact.
    ///
    /// # Errors
    /// Propagates the original session's crypto, entropy or capacity error.
    pub fn tick(&mut self, now: u64, entropy: &mut impl Entropy) -> Result<Event, Error> {
        if self.has_pending() {
            return Ok(Event::None);
        }
        let Some(session) = &mut self.session else {
            return Ok(Event::None);
        };
        let event = session.tick(now, entropy, self.outbound)?;
        self.retain(event);
        Ok(event)
    }

    /// Encode complete local messages once after association confirmation.
    ///
    /// # Errors
    /// An occupied slot returns `WouldBlock` before mutating the session.
    /// Unconfirmed sends or invalid messages retain the session's original error.
    pub fn send(&mut self, now: u64, messages: &[u8]) -> Result<(), Error> {
        self.require_empty()?;
        let session = self.session.as_mut().ok_or(Error::NotReady)?;
        let encoded = session.send(now, messages, self.outbound)?;
        self.pending = NonZeroUsize::new(encoded);
        Ok(())
    }

    /// Consume one original complete CORE frame from the validated peer.
    /// Lend each authenticated application message in wire order to `deliver`.
    /// The callback consumes or drops each borrow during its invocation.
    ///
    /// # Errors
    /// `Failed(WouldBlock)` leaves the input unconsumed while a prior response
    /// owns the output slot. Other errors retain session rejection provenance.
    pub fn receive(
        &mut self,
        now: u64,
        frame: &[u8],
        entropy: &mut impl Entropy,
        mut deliver: impl FnMut(&[u8]),
    ) -> Result<Event, ReceiveError> {
        self.require_empty()?;
        let session = self.session.as_mut().ok_or(Error::NotReady)?;
        let used = frame.len().min(self.plaintext.len());
        let result = session
            .receive_classified(now, frame, entropy, self.outbound, self.plaintext)
            .and_then(|event| {
                if let Event::Payload(size) = event {
                    let mut messages = &self.plaintext[..size];
                    while !messages.is_empty() {
                        let (message, remainder) = Frame::decode_prefix(messages)?;
                        deliver(&messages[..message.encoded_len()]);
                        messages = remainder;
                    }
                }
                Ok(event)
            });
        self.plaintext[..used].zeroize();
        let event = result?;
        self.retain(event);
        Ok(event)
    }

    /// Lend the exact prepared frame to one synchronous lower admission.
    /// Successful admission clears the slot. A refusal leaves its exact bytes
    /// present for a later actual attempt.
    ///
    /// # Errors
    /// Propagates the lower admission error. `OutcomeUnknown` retires CORE on
    /// this carrier because the frame could already have entered its stream.
    /// The embedding then retires that original carrier.
    pub fn submit<T>(
        &mut self,
        admit: impl FnOnce(&[u8]) -> Result<T, Error>,
    ) -> Result<Option<T>, Error> {
        self.submit_progress(|frame| admit(frame).map(Submission::Complete))
    }

    /// Lend the prepared frame without clearing it while an original lower
    /// fragment sequence remains incomplete.
    ///
    /// # Errors
    /// A refusal retains the same original bytes. An uncertain admission
    /// retires the carrier before those bytes can be offered again.
    pub fn submit_progress<T>(
        &mut self,
        admit: impl FnOnce(&[u8]) -> Result<Submission<T>, Error>,
    ) -> Result<Option<T>, Error> {
        let Some(size) = self.pending else {
            return Ok(None);
        };
        match admit(&self.outbound[..size.get()]) {
            Ok(Submission::Complete(value)) => {
                self.clear_pending();
                Ok(Some(value))
            }
            Ok(Submission::Pending) => Ok(None),
            Err(Error::OutcomeUnknown) => {
                self.carrier_lost();
                Err(Error::OutcomeUnknown)
            }
            Err(error) => Err(error),
        }
    }

    fn require_empty(&self) -> Result<(), Error> {
        if self.has_pending() {
            return Err(Error::WouldBlock);
        }
        Ok(())
    }

    fn retain(&mut self, event: Event) {
        if let Event::Send(size) | Event::Established(size) = event {
            self.pending = NonZeroUsize::new(size);
        }
    }

    fn clear_pending(&mut self) {
        if let Some(size) = self.pending.take() {
            self.outbound[..size.get()].zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::MonitorState;

    struct Random(u64);
    impl Entropy for Random {
        fn fill(&mut self, output: &mut [u8]) -> Result<(), Error> {
            for byte in output {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                *byte = self.0 as u8;
            }
            Ok(())
        }
    }

    fn local(identity: &Identity) -> Local<'_> {
        Local {
            identity,
            order: WordOrder::Little,
            services: b"",
            class: 0,
        }
    }

    fn admit<const F: usize>(
        peer: &mut Peer<'_, '_, F>,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        peer.submit(|frame| {
            output
                .get_mut(..frame.len())
                .ok_or(Error::Capacity)?
                .copy_from_slice(frame);
            Ok(frame.len())
        })?
        .ok_or(Error::NotReady)
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "check real CORE session and admission transitions"
    )]
    fn retains_receive_responses_and_local_records_until_admission() -> Result<(), Error> {
        const APP: [u8; 9] = [0, 4, 2, 0, 0, 5, 2, 1, 0xab];
        let first = Identity::from_seed([1; 32]);
        let second = Identity::from_seed([2; 32]);
        let order = WordOrder::Little;
        let (i, r) = if crate::wire::is_initiator(
            first.public_key().as_bytes(),
            second.public_key().as_bytes(),
            order,
        ) {
            (&first, &second)
        } else {
            (&second, &first)
        };
        let (mut itx, mut irx, mut rtx, mut rrx) = ([0; 256], [0; 256], [0; 256], [0; 256]);
        let mut initiator = Peer::<256>::new(local(i), &mut itx, &mut irx)?;
        let mut responder = Peer::<256>::new(local(r), &mut rtx, &mut rrx)?;
        let mut entropy = Random(7);
        let mut wire = [0; 256];
        let mut refused = [0; 256];

        assert_eq!(initiator.tick(0, &mut entropy)?, Event::None);
        assert_eq!(initiator.send(0, &APP), Err(Error::NotReady));
        initiator.activate_validated(r.public_key())?;
        responder.activate_validated(i.public_key())?;
        assert_eq!(initiator.next_deadline(), Some(0));
        assert_eq!(
            initiator.monitor().map(|value| value.state),
            Some(MonitorState::Down)
        );
        assert_eq!(
            responder.monitor().map(|value| value.state),
            Some(MonitorState::AwaitInitiation)
        );

        assert!(matches!(initiator.tick(1, &mut entropy)?, Event::Send(_)));
        let size = admit(&mut initiator, &mut wire)?;
        assert!(matches!(
            responder
                .receive(2, &wire[..size], &mut entropy, |_| {})
                .map_err(ReceiveError::cause)?,
            Event::Send(_)
        ));
        let mut refused_size = 0;
        assert_eq!(
            responder.submit::<()>(|frame| {
                refused_size = frame.len();
                refused[..refused_size].copy_from_slice(frame);
                Err(Error::WouldBlock)
            }),
            Err(Error::WouldBlock)
        );
        assert_eq!(responder.tick(4_000_000, &mut entropy)?, Event::None);
        assert_eq!(
            responder.receive(3, &wire[..size], &mut entropy, |_| {}),
            Err(ReceiveError::Failed(Error::WouldBlock))
        );
        let size = admit(&mut responder, &mut wire)?;
        assert_eq!(&wire[..size], &refused[..refused_size]);

        assert!(matches!(
            initiator
                .receive(4, &wire[..size], &mut entropy, |_| {})
                .map_err(ReceiveError::cause)?,
            Event::Send(_)
        ));
        let size = admit(&mut initiator, &mut wire)?;
        assert!(matches!(
            responder
                .receive(5, &wire[..size], &mut entropy, |_| {})
                .map_err(ReceiveError::cause)?,
            Event::Established(_)
        ));
        assert_eq!(responder.send(5, &APP), Err(Error::WouldBlock));
        let size = admit(&mut responder, &mut wire)?;
        assert_eq!(
            initiator
                .receive(6, &wire[..size], &mut entropy, |_| {})
                .map_err(ReceiveError::cause)?,
            Event::Established(0)
        );

        initiator.send(7, &APP)?;
        assert_eq!(
            initiator.submit::<()>(|frame| {
                refused_size = frame.len();
                refused[..refused_size].copy_from_slice(frame);
                Err(Error::WouldBlock)
            }),
            Err(Error::WouldBlock)
        );
        assert_eq!(initiator.send(8, &APP), Err(Error::WouldBlock));
        let size = admit(&mut initiator, &mut wire)?;
        assert_eq!(&wire[..size], &refused[..refused_size]);
        let mut offset = 0;
        let mut deliveries = 0;
        assert_eq!(
            responder
                .receive(9, &wire[..size], &mut entropy, |message| {
                    assert_eq!(message, &APP[offset..offset + message.len()]);
                    offset += message.len();
                    deliveries += 1;
                })
                .map_err(ReceiveError::cause)?,
            Event::Payload(APP.len())
        );
        assert_eq!((offset, deliveries), (APP.len(), 2));
        assert_eq!(
            initiator.monitor().map(|value| value.state),
            Some(MonitorState::InitiatorConnected)
        );
        let monitored = responder.monitor().ok_or(Error::NotReady)?;
        assert_eq!(monitored.state, MonitorState::ResponderConnected);
        assert_eq!(monitored.timeout.as_micros(), 300_000_009);
        assert!(monitored.timeout.as_micros() > responder.next_deadline().ok_or(Error::NotReady)?);
        assert!(responder.expire_association(monitored.timeout.as_micros()));
        let still_registered = responder.monitor().ok_or(Error::NotReady)?;
        assert_eq!(still_registered.state, MonitorState::AwaitInitiation);
        assert_eq!(still_registered.timeout.as_micros(), 0);
        assert_eq!(still_registered.class, None);

        initiator.send(11, &APP)?;
        initiator.carrier_lost();
        assert!(!initiator.established());
        assert_eq!(initiator.monitor(), None);
        assert!(!initiator.has_pending());
        assert_eq!(initiator.submit::<()>(|_| Err(Error::Conflict)), Ok(None));
        Ok(())
    }
}
