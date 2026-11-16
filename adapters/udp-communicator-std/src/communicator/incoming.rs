//! Datagram authentication, endpoint preflight and receive admission.
use super::*;

impl Communicator<'_> {
    fn classification_refused(
        &mut self,
        socket: usize,
        receipt: Receipt,
        peer: PeerId,
        operation: AddressUse,
        error: io::Error,
    ) -> Result<Option<Activity>, Failure> {
        self.sockets[socket].consume(receipt)?;
        Ok(Some(Activity::ClassificationFailed {
            peer,
            target: receipt.address(),
            operation,
            error,
        }))
    }
    fn discarded(
        &mut self,
        socket: usize,
        receipt: Receipt,
        error: Error,
    ) -> Result<Option<Activity>, Failure> {
        self.sockets[socket].consume(receipt)?;
        Ok(Some(Activity::Discarded(error)))
    }
    pub(super) fn incoming(
        &mut self,
        socket: usize,
        identity: &Identity,
        journal: &mut Journal,
        receipt: Receipt,
        now: u64,
        classify: &mut impl FnMut(SocketAddr) -> io::Result<u32>,
    ) -> Result<Option<Activity>, Failure> {
        match self.burst_probe(socket, receipt) {
            Ok(burst::Probe::Selected) => return Ok(Some(Activity::Burst)),
            Ok(burst::Probe::Pending) => return Ok(None),
            Ok(burst::Probe::Unrelated) => {}
            Err(error) => {
                self.close();
                return Err(error);
            }
        }
        if receipt.len() == gnunet_nat_burst_host::wire::MESSAGE_BYTES
            && socket < self.defaults
            && self.burst.is_some()
        {
            let order = self.burst.as_ref().ok_or(Error::Stale)?.policy.remote_order;
            let probe = gnunet_nat_burst_host::wire::BurstMessage::decode(
                self.sockets[socket].bytes(receipt)?,
                order,
            )?;
            if probe.local_port != 0 || probe.peer == self.configuration.local {
                return self.discarded(socket, receipt, Error::InvalidInput);
            }
            if !self.room(1, 256) {
                return Ok(None);
            }
            match self.prepare_endpoint_on(probe.peer, receipt.address(), socket, now, classify) {
                Ok(EndpointAdmission::New(plan)) => self.commit_endpoint(plan)?,
                Ok(EndpointAdmission::Live) => {}
                Ok(EndpointAdmission::Retiring) => {
                    return self.discarded(socket, receipt, Error::NotReady);
                }
                Err(EndpointPlanError::Protocol(error)) => {
                    return self.discarded(socket, receipt, error);
                }
                Err(EndpointPlanError::Classification(error)) => {
                    return self.classification_refused(
                        socket,
                        receipt,
                        probe.peer,
                        AddressUse::Probe,
                        error,
                    );
                }
            }
            self.sockets[socket].consume(receipt)?;
            return Ok(Some(Activity::Burst));
        }
        if self.ack.is_some() {
            return Ok(None);
        }
        let incoming_bound = receipt
            .len()
            .saturating_sub(48)
            .checked_add(88)
            .ok_or(Error::Overflow)?;
        if incoming_bound > 65535 {
            return self.discarded(socket, receipt, Error::TooLarge);
        }
        let bytes = incoming_bound.checked_add(512).ok_or(Error::Overflow)?;
        if 4 > self.configuration.capacity.frames || bytes > self.configuration.capacity.bytes {
            return self.discarded(socket, receipt, Error::Capacity);
        }
        if !self.room(4, bytes) {
            return Ok(None);
        }
        // Move, never clone, the one original scratch allocation during this
        // synchronous borrow so the authenticated guard can outlive table lookup.
        let mut scratch = std::mem::replace(&mut self.scratch, Zeroizing::new(Vec::new()));
        let result = self.incoming_staged(
            socket,
            identity,
            journal,
            receipt,
            now,
            classify,
            &mut scratch,
            incoming_bound,
        );
        self.scratch = scratch;
        match result {
            Err(Failure::Core(
                error @ (Error::Authentication
                | Error::Replay
                | Error::Malformed
                | Error::Truncated
                | Error::InvalidInput
                | Error::Unsupported
                | Error::NotFound
                | Error::TooLarge
                | Error::Capacity),
            )) => self.discarded(socket, receipt, error),
            result => result,
        }
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "One original receipt, scratch and independently owned admission ports remain explicit before replay commit"
    )]
    fn incoming_staged(
        &mut self,
        socket: usize,
        identity: &Identity,
        journal: &mut Journal,
        receipt: Receipt,
        now: u64,
        classify: &mut impl FnMut(SocketAddr) -> io::Result<u32>,
        scratch: &mut [u8],
        incoming_bound: usize,
    ) -> Result<Option<Activity>, Failure> {
        let ack_buffers = [buffer(116)?, buffer(116)?];
        let message_buffer = buffer(incoming_bound)?;
        self.index
            .try_reserve_exact(MAX_NEW_KEY_IDS)
            .map_err(|_| Error::Capacity)?;
        let watermark = self.endpoint_serial;
        let packet = self.sockets[socket].bytes(receipt)?;
        let mut matched = false;
        let mut replay = false;
        let mut retiring_candidate = false;
        let mut received = None;
        if let Some(prefix) = packet.get(..32) {
            let kid = <[u8; 32]>::try_from(prefix).map_err(|_| Error::Truncated)?;
            let start = self.index.partition_point(|entry| entry.value < kid);
            let end = self.index.partition_point(|entry| entry.value <= kid);
            let mut previous = None;
            for at in start..end {
                let candidate = self.index[at];
                if previous == Some((candidate.peer, candidate.generation)) {
                    continue;
                }
                previous = Some((candidate.peer, candidate.generation));
                let Some(peer) = self.peers[candidate.peer]
                    .as_ref()
                    .filter(|peer| peer.generation == candidate.generation)
                else {
                    continue;
                };
                let sender = peer.id;
                // Move this one original owner out during a synchronous admission
                // transaction. The prepared BOX exclusively borrows its receiver;
                // endpoint preparation can inspect the other communicator tables.
                // Restore the same owner on every Result path, before handling it.
                let packet = self.sockets[socket].bytes(receipt)?;
                let mut peer = self.peers[candidate.peer].take().ok_or(Error::Stale)?;
                let admission = (|| {
                    let prepared = peer.receiver.prepare_boxed(identity, packet, scratch)?;
                    let endpoint = match self.prepare_endpoint_on(
                        sender,
                        receipt.address(),
                        socket,
                        now,
                        classify,
                    )? {
                        EndpointAdmission::New(plan) => Some(plan),
                        EndpointAdmission::Live => None,
                        EndpointAdmission::Retiring => return Ok(None),
                    };
                    Ok::<_, EndpointPlanError>(Some((prepared.commit(), endpoint)))
                })();
                self.peers[candidate.peer] = Some(peer);
                match admission {
                    Ok(Some((value, endpoint))) => {
                        received = Some((candidate.peer, sender, true, value, endpoint));
                        break;
                    }
                    Ok(None) => retiring_candidate = true,
                    Err(EndpointPlanError::Protocol(Error::NotFound)) => {}
                    Err(EndpointPlanError::Protocol(Error::Replay)) => {
                        matched = true;
                        replay = true;
                    }
                    Err(EndpointPlanError::Protocol(Error::Authentication)) => matched = true,
                    Err(EndpointPlanError::Protocol(error)) => return Err(error.into()),
                    Err(EndpointPlanError::Classification(error)) => {
                        return self.classification_refused(
                            socket,
                            receipt,
                            sender,
                            AddressUse::Boxed,
                            error,
                        );
                    }
                }
            }
        }
        if received.is_none() && matched {
            return self.discarded(
                socket,
                receipt,
                if replay {
                    Error::Replay
                } else {
                    Error::Authentication
                },
            );
        }
        if received.is_none() && retiring_candidate {
            return self.discarded(socket, receipt, Error::NotReady);
        }
        if received.is_none() && receipt.len() == 96 && self.discovery.is_some() {
            let sender = match discovery::verify(
                self.sockets[socket].bytes(receipt)?,
                receipt.address(),
                self.configuration.local,
            ) {
                Ok(Some(sender)) => sender,
                Ok(None) => return self.discarded(socket, receipt, Error::NotFound),
                Err(error) => return self.discarded(socket, receipt, error),
            };
            let state = self.discovery.as_ref().ok_or(Error::Stale)?;
            if state.hint.is_some() {
                return self.discarded(socket, receipt, Error::Capacity);
            }
            let network = match classify(receipt.address()) {
                Ok(network) => network,
                Err(error) => {
                    return self.classification_refused(
                        socket,
                        receipt,
                        sender,
                        AddressUse::Discovery,
                        error,
                    );
                }
            };
            let state = self.discovery.as_mut().ok_or(Error::Stale)?;
            state.hint = Some(Discovered {
                peer: sender,
                source: receipt.address(),
                network,
            });
            self.sockets[socket].consume(receipt)?;
            return Ok(Some(Activity::Discovered));
        }
        let (peer_index, sender, boxed, value, endpoint) = if let Some(received) = received {
            received
        } else {
            let opened =
                match handshake::open(identity, self.sockets[socket].bytes(receipt)?, scratch) {
                    Ok(opened) => opened,
                    Err(error) => return self.discarded(socket, receipt, error),
                };
            let sender = opened.sender();
            let existing = self.peer_index(sender);
            let index = existing
                .or_else(|| self.peers.iter().position(Option::is_none))
                .ok_or(Error::Capacity)?;
            let endpoint =
                match self.prepare_endpoint_on(sender, receipt.address(), socket, now, classify) {
                    Ok(EndpointAdmission::New(plan)) => Some(plan),
                    Ok(EndpointAdmission::Live) => None,
                    Ok(EndpointAdmission::Retiring) => {
                        return self.discarded(socket, receipt, Error::NotReady);
                    }
                    Err(EndpointPlanError::Classification(error)) => {
                        return self.classification_refused(
                            socket,
                            receipt,
                            sender,
                            AddressUse::Initial,
                            error,
                        );
                    }
                    Err(EndpointPlanError::Protocol(error)) => return Err(error.into()),
                };
            if existing.is_some() {
                let peer = self.peers[index].as_mut().ok_or(Error::Stale)?;
                let value = peer.receiver.initial_opened(identity, opened, journal);
                let value = self.received_or_history(value, journal)?;
                (index, sender, false, value, endpoint)
            } else {
                let generation = self.peer_serial.checked_add(1).ok_or(Error::Overflow)?;
                let mut receiver = Receiver::new(
                    self.configuration.local,
                    sender,
                    RxPolicy {
                        secrets: self.configuration.transmit.secrets,
                        maximum_secret_bytes: self.configuration.transmit.maximum_secret_bytes,
                    },
                )?;
                let value = receiver.initial_opened(identity, opened, journal);
                let value = self.received_or_history(value, journal)?;
                self.peers[index] = Some(Peer {
                    id: sender,
                    generation,
                    receiver,
                    last_rx: now,
                });
                self.peer_serial = generation;
                (index, sender, false, value, endpoint)
            }
        };
        // Every buffer, endpoint and selector-index capacity was reserved before
        // the original Receiver consumed a KID or made its durable replay commit.
        let mut staged: [Option<OwnedFrame>; 3] = [None, None, None];
        for (index, (ack, bytes)) in value
            .acknowledgements
            .into_iter()
            .zip(ack_buffers)
            .enumerate()
        {
            if let Some(ack) = ack {
                staged[index] = Some(freeze(bytes, |out| transport::notify(sender, ack, out))?);
            }
        }
        if let Some(message) = value.message() {
            staged[2] = Some(freeze(message_buffer, |out| {
                transport::incoming(sender, message, out)
            })?);
        }
        if let Some(plan) = endpoint {
            self.commit_endpoint(plan)?;
        }
        if let Some(peer) = self.peers[peer_index].as_mut() {
            peer.last_rx = now;
        }
        self.index_peer(peer_index);
        if let Some(ack) = value.incoming_ack {
            self.ack = Some(AckWork {
                peer: sender,
                ack,
                cursor: 0,
                watermark,
                release_input: false,
            });
        }
        for frame in staged.into_iter().flatten() {
            self.push(frame, Origin::Effect)?;
        }
        self.sockets[socket].consume(receipt)?;
        Ok(Some(Activity::Incoming {
            peer: sender,
            source: receipt.address(),
            boxed,
            bytes: receipt.len(),
        }))
    }
    fn received_or_history(
        &self,
        result: Result<Received, Error>,
        journal: &mut Journal,
    ) -> Result<Received, Failure> {
        match result {
            Ok(value) => Ok(value),
            Err(Error::Storage | Error::OutcomeUnknown) => {
                if let Some(failure) = journal.take_failure() {
                    Err(Failure::History(JournalError::Native(failure)))
                } else {
                    Err(Error::OutcomeUnknown.into())
                }
            }
            Err(error) => Err(error.into()),
        }
    }
}
