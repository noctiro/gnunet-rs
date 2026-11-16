//! TRANSPORT input admission, peer ownership and explicit failure scope.
use crate::{Host, HostError, Peer, PeerLossOrigin, Random, inc};
use gnunet_client::transport::{self as tr, Request, Response};
use gnunet_core::{record::ReceiveError, session::Session};
use gnunet_crypto::EddsaPublicKey;
use gnunet_types::Error;
use gnunet_wire::official::core::PeerId;
use std::{collections::VecDeque, fmt};

/// Both outcomes consume the input; admission refusal creates no peer state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Outcome {
    Consumed,
    PeerRefused,
}

/// Only source failures retire the physical MQ and all its peer generations.
#[derive(Debug)]
pub(super) enum Failure {
    Source(Error),
    Host(HostError),
}
impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        Self::Source(error)
    }
}
impl From<HostError> for Failure {
    fn from(error: HostError) -> Self {
        Self::Host(error)
    }
}
impl fmt::Display for Failure {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(error) => write!(output, "CORE TRANSPORT input: {error}"),
            Self::Host(error) => error.fmt(output),
        }
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match self {
            Self::Source(error) => error,
            Self::Host(error) => error,
        })
    }
}

impl Host<'_> {
    pub(super) fn transport_frame(&mut self, bytes: &[u8], now: u64) -> Result<Outcome, Failure> {
        match Response::decode(bytes)? {
            Response::Connected(tr::PeerId(id)) => {
                let id = PeerId(id);
                if id == self.identity() || self.peers.contains_key(&id) {
                    return Err(Error::Malformed.into());
                }
                if self.peers.len() >= self.limits.max_peers {
                    inc(&mut self.report.peer_refusals);
                    return Ok(Outcome::PeerRefused);
                }
                let session = Session::with_class(
                    self.identity,
                    EddsaPublicKey::from_bytes(id.0),
                    self.order,
                    self.info,
                    self.class.0 as u16,
                )
                .map_err(HostError::from)?;
                self.peers.insert(
                    id,
                    Peer {
                        session,
                        credits: tr::SEND_WINDOW,
                        ciphertexts: VecDeque::new(),
                        bytes: 0,
                        state: u32::MAX,
                        timeout: 0,
                    },
                );
                self.peer_state(id);
            }
            Response::Disconnected(tr::PeerId(id)) => self.disconnect_peer(PeerId(id), now)?,
            Response::SendCredit(tr::PeerId(id)) => self.returned_send_credit(PeerId(id))?,
            Response::Received {
                peer: tr::PeerId(id),
                message,
            } => self.received(PeerId(id), message, now)?,
        }
        Ok(Outcome::Consumed)
    }

    fn disconnect_peer(&mut self, id: PeerId, now: u64) -> Result<(), Failure> {
        if let Some(peer) = self.peers.get(&id)
            && peer.session.established()
        {
            self.peer_loss(peer.loss(id, PeerLossOrigin::TransportDisconnected, now));
        }
        self.applications.remove_peer(id);
        let Some(peer) = self.peers.remove(&id) else {
            return Ok(());
        };
        let cancelled = self.transport.as_mut().map_or(0, |link| {
            link.cancel_unwritten(|bytes| {
                matches!(Request::decode(bytes), Ok(Request::Send { peer, .. }) if peer.0 == id.0)
            })
        });
        let owed = tr::SEND_WINDOW
            .checked_sub(peer.credits)
            .and_then(|n| n.checked_sub(u32::try_from(cancelled).ok()?))
            .ok_or(Error::Malformed)?;
        if owed > 0 {
            if !self.retired_credits.contains_key(&id)
                && self.retired_credits.len() >= self.limits.max_pending_frames
            {
                return Err(Error::Capacity.into());
            }
            let debt = self.retired_credits.entry(id).or_default();
            *debt = debt.checked_add(owed).ok_or(Error::Capacity)?;
        }
        Ok(())
    }

    fn returned_send_credit(&mut self, id: PeerId) -> Result<(), Failure> {
        if let Some(debt) = self.retired_credits.get_mut(&id) {
            *debt -= 1;
            if *debt == 0 {
                self.retired_credits.remove(&id);
            }
            inc(&mut self.report.late_send_credits);
            return Ok(());
        }
        let Some(peer) = self.peers.get_mut(&id) else {
            inc(&mut self.report.late_send_credits);
            return Ok(());
        };
        if peer.credits >= tr::SEND_WINDOW {
            return Err(Error::Malformed.into());
        }
        peer.credits += 1;
        Ok(())
    }

    fn received(&mut self, id: PeerId, message: &[u8], now: u64) -> Result<(), Failure> {
        if id == self.identity() {
            return Err(Error::Malformed.into());
        }
        // Every consumed RECV owes one real credit, including a peer declined
        // locally. Preflight its complete storage before changing crypto state.
        // Exhausted mandatory control storage still retires the source instead
        // of blocking RECV ahead of its own later SEND_OK credits.
        if self
            .peers
            .get(&id)
            .is_some_and(|peer| !peer.control_capacity(self.limits))
            || !self
                .transport
                .as_ref()
                .is_some_and(|link| link.control_capacity(tr::FIXED_LEN))
        {
            return Err(Error::Capacity.into());
        }
        self.transport
            .as_mut()
            .ok_or(Error::Closed)?
            .reserve(tr::FIXED_LEN, true)?;
        let mut credit = Vec::new();
        credit
            .try_reserve_exact(tr::FIXED_LEN)
            .map_err(|_| Failure::Host(Error::Capacity.into()))?;
        credit.resize(tr::FIXED_LEN, 0);
        Request::ReceiveContinue {
            peer: tr::PeerId(id.0),
            increase: 1,
        }
        .encode(&mut credit)?;

        if let Some(peer) = self.peers.get_mut(&id) {
            match peer.session.receive_classified(
                now,
                message,
                &mut Random,
                &mut self.output,
                &mut self.plain,
            ) {
                Ok(event) => self.crypto_event(id, event)?,
                // Record rejection is isolated to this input. Unexpected
                // local failures retain their cause for the owning foreground.
                Err(ReceiveError::RejectedEpoch(_)) => {
                    inc(&mut self.report.rejected_records);
                    inc(&mut self.report.rejected_epoch);
                }
                Err(ReceiveError::Failed(error)) => {
                    let counter = match error {
                        Error::Authentication => &mut self.report.rejected_authentication,
                        Error::Replay => &mut self.report.rejected_replay,
                        Error::Truncated => &mut self.report.rejected_truncated,
                        Error::Malformed => &mut self.report.rejected_malformed,
                        Error::InvalidInput => &mut self.report.rejected_invalid_input,
                        Error::Unsupported => &mut self.report.rejected_unsupported,
                        _ => return Err(Failure::Host(error.into())),
                    };
                    inc(&mut self.report.rejected_records);
                    inc(counter);
                }
            }
        } else {
            // The MQ can keep delivering a locally refused peer. No unbounded
            // rejection registry or session is needed to discard and credit it.
            inc(&mut self.report.unadmitted_records);
        }
        self.plain.fill(0);
        self.transport
            .as_mut()
            .ok_or(Error::Closed)?
            .enqueue_control(credit)?;
        inc(&mut self.report.receive_credits);
        Ok(())
    }
}
