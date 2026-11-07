//! Synchronous generation retirement; process sockets and backing stay owned.
use super::*;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Phase {
    Active,
    Retired,
}

/// Actual canceled local generation, without replacement or remote authority.
#[derive(Clone, Copy, Debug)]
pub struct Retirement {
    /// Original local peer whose keys/queues are now unavailable.
    pub peer: PeerId,
    /// Actual incoming authenticated peer owners retired.
    pub incoming: usize,
    /// Actual outgoing endpoint owners retired.
    pub outgoing: usize,
    /// Physical TRANSPORT source for the original callbacks/publications.
    pub transport_generation: u64,
    /// This cut itself retired that still-attached physical MQ.
    pub transport_was_attached: bool,
}
impl Communicator<'_> {
    /// Retire original IO/callback authority before admitting another identity.
    /// This performs no new send, receive, signature, journal write or callback.
    /// Old exposed MQ effects retain their exact loss metadata; they are not
    /// drained successfully or replayed onto a replacement. The native owner has
    /// no background socket task, so cancellation settles its real packet slots.
    pub fn retire_identity(&mut self) -> Result<Retirement, Failure> {
        if self.closed || self.closing || self.identity_phase != Phase::Active {
            return Err(Error::Closed.into());
        }
        let report = Retirement {
            peer: self.configuration.local,
            incoming: self.peers(),
            outgoing: self.endpoints(),
            transport_generation: self.transport_generation(),
            transport_was_attached: self.transport_attached,
        };
        if self.transport_attached {
            // Uses the same bounded original-source ledger as real source loss.
            // A bookkeeping refusal retains the initiating failure and closes
            // everything; no partially certified replacement can be admitted.
            if let Err(error) = self.retire_transport() {
                self.close();
                return Err(error.into());
            }
        }
        self.cancel_burst();
        for peer in self.peers.iter_mut().flatten() {
            peer.receiver.close();
        }
        for endpoint in self.endpoints.iter_mut().flatten() {
            endpoint.sender.close();
        }
        self.peers.iter_mut().for_each(|v| *v = None);
        self.endpoints.iter_mut().for_each(|v| *v = None);
        self.index.clear();
        self.ack = None;
        for (index, socket) in self.sockets.iter_mut().enumerate() {
            if index < self.defaults {
                socket.retire_packets();
            } else {
                socket.close();
            }
        }
        if let Some(state) = &mut self.discovery {
            state.pending = [None, None];
            state.hint = None;
            for row in &mut state.rows {
                row.packet = None;
            }
        }
        self.identity_phase = Phase::Retired;
        Ok(report)
    }
    /// Actual local debt barrier; this grants no private key or new source.
    #[must_use]
    pub fn identity_retired(&self) -> bool {
        self.identity_phase == Phase::Retired
            && !self.closed
            && !self.closing
            && !self.transport_attached
            && self.effects.is_empty()
            && self.pending_mq.is_none()
            && self.io.queued_frames() == 0
            && self.peers.iter().all(Option::is_none)
            && self.endpoints.iter().all(Option::is_none)
            && self.completions.iter().all(Option::is_none)
            && self.ack.is_none()
            && self.sockets.iter().all(DatagramSocket::is_quiescent)
    }
    /// Select a fresh matched key/journal only after actual retirement. All
    /// queue/token serials, socket receipts and native time remain monotonic.
    /// A new TRANSPORT source still requires explicit original-loss observation
    /// and real reconnect; no old command, packet or callback is replayed.
    pub fn resume_identity(
        &mut self,
        identity: &Identity,
        journal: &Journal,
    ) -> Result<(), Failure> {
        if !self.identity_retired() {
            return Err(Error::NotReady.into());
        }
        if journal.local_peer() != identity.peer() {
            return Err(Error::Authentication.into());
        }
        if !journal.quiescent()? {
            return Err(Error::OutcomeUnknown.into());
        }
        self.configuration.local = identity.peer();
        self.identity_phase = Phase::Active;
        Ok(())
    }
}
