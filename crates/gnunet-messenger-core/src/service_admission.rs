//! Native service admission for official room OPEN, ENTRY and SEND requests.

mod local;
pub use local::{
    LocalEntry, LocalRequest, LocalRoomAdmission, LocalRoomCommand, LocalRoomRequest, LocalSend,
    ScopedLocalRoomRequest,
};

use crate::{
    Hash, ShortHash, carrier,
    wire::{envelope::Kind, message::Message, profile::Endian},
};
use gnunet_types::Error;

/// Room capability bits interpreted in the creator's declared bitfield order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoomCapabilities(u8);

impl RoomCapabilities {
    /// Read the three official room flags without inspecting other key bytes.
    #[must_use]
    pub const fn decode(key: &Hash, order: Endian) -> Self {
        let bits = match order {
            Endian::Little => key[0],
            Endian::Big => key[0].reverse_bits(),
        };
        Self(bits & 7)
    }

    /// Whether the room is public.
    pub const fn is_public(self) -> bool {
        self.0 & 1 != 0
    }

    /// Whether the room carries group traffic.
    pub const fn is_group(self) -> bool {
        self.0 & 2 != 0
    }

    /// Whether the room carries a feed.
    pub const fn is_feed(self) -> bool {
        self.0 & 4 != 0
    }

    /// A personal feed accepts ENTRY but cannot register a port through OPEN.
    pub const fn allows_open(self) -> bool {
        !self.is_feed() || self.is_group()
    }
}

/// A door classified as remote at ENTRY admission.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RemoteDoor(ShortHash);

impl core::fmt::Debug for RemoteDoor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RemoteDoor([REDACTED])")
    }
}

impl RemoteDoor {
    /// Original peer that must be reached by the native CADET channel.
    pub const fn peer(self) -> ShortHash {
        self.0
    }
}

/// Door selected against the service identity observed for the original request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryTarget {
    /// Zero and the current local peer both enter without a CADET channel.
    Local,
    /// A CADET connection to this original remote peer is required.
    Remote(RemoteDoor),
}

impl EntryTarget {
    /// Classify the original wire door using an observed local service identity.
    #[must_use]
    pub fn resolve(requested: ShortHash, local: ShortHash) -> Self {
        if requested == [0; 32] || requested == local {
            Self::Local
        } else {
            Self::Remote(RemoteDoor(requested))
        }
    }
}

/// One ENTRY's route. A bound request stays with its original channel generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntryRoute<C>(EntryStep<C>);

/// Observation of work still owned by the native service for an ENTRY.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryStep<C> {
    /// Respond with the local identity once it is available.
    Local,
    /// Register or find a native channel to this door for the original room.
    Connect(RemoteDoor),
    /// Wait for credit and compatible authenticated INFO on this exact channel.
    Observe {
        /// Original remote door.
        door: RemoteDoor,
        /// Native channel identity including its generation.
        channel: C,
    },
}

impl<C: Copy> EntryRoute<C> {
    /// Start from the original classified door, before any native admission.
    #[must_use]
    pub const fn new(target: EntryTarget) -> Self {
        Self(match target {
            EntryTarget::Local => EntryStep::Local,
            EntryTarget::Remote(door) => EntryStep::Connect(door),
        })
    }

    /// Read the retained step without advancing a native operation.
    #[must_use]
    pub const fn step(self) -> EntryStep<C> {
        self.0
    }

    /// Record the actual native channel for this door. The adapter must have
    /// verified that the channel belongs to the original room and peer.
    ///
    /// # Errors
    /// Returns [`Error::Conflict`] for a local or already bound route.
    pub fn bind(&mut self, channel: C) -> Result<(), Error> {
        let EntryStep::Connect(door) = self.0 else {
            return Err(Error::Conflict);
        };
        self.0 = EntryStep::Observe { door, channel };
        Ok(())
    }
}

/// Original channel readiness. A used send credit remains evidence that the
/// service opened the channel; it does not grant another send.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PeerHandshake(HandshakeState);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum HandshakeState {
    #[default]
    Waiting,
    Credit,
    Info,
    Ready,
}

impl PeerHandshake {
    /// Observe an actual send-credit notification from this CADET channel.
    pub fn observe_credit(&mut self) {
        self.0 = match self.0 {
            HandshakeState::Waiting | HandshakeState::Credit => HandshakeState::Credit,
            HandshakeState::Info | HandshakeState::Ready => HandshakeState::Ready,
        };
    }

    /// Observe the original peer's verified, compatible INFO on this channel.
    pub fn observe_info(&mut self) {
        self.0 = match self.0 {
            HandshakeState::Waiting | HandshakeState::Info => HandshakeState::Info,
            HandshakeState::Credit | HandshakeState::Ready => HandshakeState::Ready,
        };
    }

    /// Whether both independent observations were made on this generation.
    #[must_use]
    pub const fn is_ready(self) -> bool {
        matches!(self.0, HandshakeState::Ready)
    }
}

/// An unpadded signed body of a kind accepted from the local Messenger IPC.
/// The original bytes remain borrowed. The caller must still authenticate the
/// signed body against the exact room and client before accepting it.
#[derive(Clone, Copy, Debug)]
pub struct ClientSend<'message>(Message<'message>);

impl<'message> ClientSend<'message> {
    /// Check an original SEND body decoded with its declared producer profile.
    ///
    /// # Errors
    /// Returns [`Error::PermissionDenied`] for an unknown or peer-control kind,
    /// or [`Error::Malformed`] if the decoded message carried outer padding.
    pub fn new(message: Message<'message>) -> Result<Self, Error> {
        let kind = message.header().kind;
        if !kind.is_known()
            || matches!(
                kind,
                Kind::INFO | Kind::PEER | Kind::MISS | Kind::MERGE | Kind::CONNECTION
            )
        {
            return Err(Error::PermissionDenied);
        }
        if !message.padding().is_empty() {
            return Err(Error::Malformed);
        }
        Ok(Self(message))
    }

    /// Original kind, for any additional local policy gates.
    #[must_use]
    pub const fn kind(self) -> Kind {
        self.0.header().kind
    }

    /// Return the original unmodified message if it can be relayed in one
    /// complete CADET application frame, including the carrier header and
    /// smallest permitted outer padding. `frame_limit` is the local carrier's
    /// bound and may be stricter than the protocol limit.
    ///
    /// # Errors
    /// Returns [`Error::TooLarge`] if the message cannot fit.
    pub fn for_carrier(self, frame_limit: usize) -> Result<Message<'message>, Error> {
        if carrier::minimum_frame_len(self.0) > frame_limit.min(carrier::MAX_FRAME_BYTES) {
            return Err(Error::TooLarge);
        }
        Ok(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_waits_for_both_observations_on_the_bound_channel() {
        let target = EntryTarget::resolve([7; 32], [8; 32]);
        let mut route = EntryRoute::new(target);
        assert_eq!(route.bind(1), Ok(()));
        assert_eq!(route.bind(2), Err(Error::Conflict));
        assert!(matches!(
            route.step(),
            EntryStep::Observe { channel: 1, .. }
        ));

        let mut original = PeerHandshake::default();
        let mut replacement = PeerHandshake::default();
        original.observe_info();
        replacement.observe_credit();
        assert!(!original.is_ready());
        assert!(!replacement.is_ready());
        original.observe_credit();
        replacement.observe_info();
        assert!(original.is_ready());
        assert!(replacement.is_ready());
    }

    fn encode(kind: Kind, body: &[u8], output: &mut [u8]) -> Result<usize, Error> {
        use crate::wire::{
            KeyType, SensitiveBytes,
            envelope::{self, Header, SIGNATURE_LEN, Signature},
        };
        use gnunet_types::AbsoluteTime;

        let mut tagged = [0; SIGNATURE_LEN];
        tagged[..4].copy_from_slice(&KeyType::Eddsa.value().to_be_bytes());
        envelope::encode(
            Header {
                signature: Signature::new(&tagged)?,
                timestamp: AbsoluteTime::UNIX_EPOCH,
                sender_id: &[1; 32],
                previous: &[2; 64],
                kind,
            },
            SensitiveBytes::new(body),
            output,
        )
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "check the exact SEND body and its smallest carrier size"
    )]
    fn client_send_respects_the_actual_carrier_budget() -> Result<(), Error> {
        use crate::wire::{padding, profile::Profile};

        let mut raw = [0; 256];
        let len = encode(Kind::TEXT, b"unchanged", &mut raw)?;
        let message = Message::decode(&raw[..len], Profile::LITTLE_255, padding::Decode::Absent)?;
        let send = ClientSend::new(message)?;
        let minimum = gnunet_wire::official::HEADER_LEN + len + padding::MIN_PADDING;
        assert_eq!(send.kind(), Kind::TEXT);
        assert!(matches!(
            send.for_carrier(minimum - 1),
            Err(Error::TooLarge)
        ));
        assert_eq!(
            send.for_carrier(minimum)?.original().expose_encoded(),
            &raw[..len]
        );
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "check peer control and unsigned padding refusals independently"
    )]
    fn client_send_rejects_peer_control_and_outer_padding() -> Result<(), Error> {
        use crate::wire::{padding, profile::Profile};

        let profile = Profile::LITTLE_255;
        let mut raw = [0; 256];
        let len = encode(Kind::PEER, &[5; 32], &mut raw)?;
        let peer = Message::decode(&raw[..len], profile, padding::Decode::Absent)?;
        assert!(matches!(
            ClientSend::new(peer),
            Err(Error::PermissionDenied)
        ));

        let len = encode(Kind::TEXT, b"unchanged", &mut raw)?;
        let padded = padding::write(
            len,
            padding::Encode::ToLength {
                total: len + padding::MIN_PADDING,
                noise: crate::wire::SensitiveBytes::new(&[]),
            },
            profile,
            &mut raw,
        )?;
        let relay = Message::decode(&raw[..padded], profile, padding::Decode::Required)?;
        assert!(matches!(ClientSend::new(relay), Err(Error::Malformed)));
        Ok(())
    }
}
