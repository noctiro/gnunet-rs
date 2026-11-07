//! Physical endpoint ownership beneath one logical DHT peer and job graph.
use super::*;
impl<'id> Server<'id> {
    pub(super) fn connect_native(&mut self, native: NativePeer<'id>) -> Result<(), Error> {
        if self.peers.iter().any(|peer| peer.native == native) {
            return Ok(());
        }
        let identity = native.identity().0;
        if self.routing_identity == Some(identity) {
            // A real PILS update may turn a formerly remote PID into self.
            // Keep native retirement/send debt separate from logical peers.
            return Ok(());
        }
        let existing = self
            .peers
            .iter()
            .find(|peer| peer.native.identity().0 == identity)
            .map(|peer| peer.token);
        let token = match existing {
            Some(token) => token,
            None => {
                let token = self
                    .owner
                    .as_mut()
                    .ok_or(Fault::NotReady)?
                    .connect_peer(identity)?;
                let local =
                    gnunet_dht::routing::peer_key(&self.routing_identity.ok_or(Fault::NotReady)?);
                let bucket =
                    gnunet_dht::routing::bucket(&local, &gnunet_dht::routing::peer_key(&identity));
                let before = self
                    .peers
                    .iter()
                    .enumerate()
                    .filter(|(i, peer)| {
                        !self.peers[..*i].iter().any(|old| old.token == peer.token)
                            && gnunet_dht::routing::bucket(
                                &local,
                                &gnunet_dht::routing::peer_key(&peer.native.identity().0),
                            ) == bucket
                    })
                    .count();
                self.neighbours.connected(
                    self.peers.is_empty(),
                    before < self.limits.network.bucket_size,
                );
                token
            }
        };
        if self.peers.len() == self.peers.capacity() {
            if existing.is_none() {
                self.owner
                    .as_mut()
                    .ok_or(Fault::NotReady)?
                    .disconnect_peer(token)?;
            }
            return Err(Fault::Capacity.into());
        }
        self.peers.push(Peer {
            native,
            token,
            hello_pending: true,
            ip_preferred: false,
        });
        Ok(())
    }
    pub(super) fn disconnect_native(&mut self, native: NativePeer<'id>) -> Result<(), Error> {
        let Some(index) = self.peers.iter().position(|peer| peer.native == native) else {
            return Ok(());
        };
        let peer = self.peers.remove(index);
        if self.closing {
            return Ok(());
        }
        // No replacement endpoint inherits this original unadmitted job choice.
        for job in &mut self.jobs {
            if job.target == Some(native) && !job.cancelled {
                self.owner
                    .as_mut()
                    .ok_or(Fault::NotReady)?
                    .cancel_job(job.job)?;
                job.cancelled = true;
            }
        }
        if !self.peers.iter().any(|other| other.token == peer.token) {
            self.owner
                .as_mut()
                .ok_or(Fault::NotReady)?
                .disconnect_peer(peer.token)?;
        }
        // The actual TRANSPORT epoch retains its own admitted registrations.
        // Removing a desired CORE peer never transfers a cancel to another MQ.
        if self.peers.is_empty() {
            self.neighbours.empty();
        } else {
            self.neighbours.resume();
        }
        Ok(())
    }
    pub(super) fn disconnect_core_peers(&mut self) -> Result<(), Error> {
        while let Some(native) = self
            .peers
            .iter()
            .find_map(|peer| matches!(peer.native, NativePeer::Core(_)).then_some(peer.native))
        {
            self.disconnect_native(native)?;
        }
        Ok(())
    }
    pub(super) fn update_estimate(&mut self) -> Result<(), Error> {
        let ip = self
            .ip
            .as_ref()
            .map(|source| (source.network_size() as f64).max(2.0f64.sqrt()).log2());
        let log2 = match (self.core_estimate, ip) {
            (Some(core), Some(ip)) => {
                let maximum = core.max(ip);
                maximum + (2.0f64.powf(core - maximum) + 2.0f64.powf(ip - maximum)).log2()
            }
            (Some(core), None) => core,
            (None, Some(ip)) => ip,
            (None, None) => 0.5,
        };
        if let Some(owner) = self.owner.as_mut() {
            owner.set_policy(network::Policy {
                estimate: gnunet_dht::routing::Estimate::new(log2)?,
            });
            self.neighbours.resume();
        }
        Ok(())
    }
    pub(super) fn ingest_native(
        &mut self,
        native: NativePeer<'id>,
        wire: &[u8],
        anchor: Anchor,
        entropy: &mut impl Entropy,
    ) -> Result<(), Error> {
        if identity::tracked(wire)? && !self.native_identity_matches(native) {
            // Frame-level refusal: a valid old-local recipient signature cannot
            // be extended under the current PILS signer. The carrier stays live.
            return Err(Error(Arc::new(Cause::Identity)));
        }
        let token = self
            .peers
            .iter()
            .find(|peer| peer.native == native)
            .ok_or(Fault::Stale)?
            .token;
        if Frame::decode(wire)?.header().message_type() == mt::DHT_P2P_HELLO {
            self.discovery
                .observe(wire, Some(native.identity().0), anchor.now, true)?;
            self.report.hello_observations = self.report.hello_observations.saturating_add(1);
        } else {
            let mut blocks = BuiltinBlocks {
                context: BlockContext::new(&self.blocks.plugins, self.blocks.group_profile),
                work: BlockWork {
                    hello: &mut self.hello_scratch,
                    hello_limits: self.limits.hello,
                    hello_profile: self.blocks.hello_profile,
                    pow: &mut self.pow,
                },
            };
            let outcome = self.owner.as_mut().ok_or(Fault::NotReady)?.ingest_peer(
                token,
                wire,
                anchor.now,
                &mut blocks,
                entropy,
            )?;
            self.sync_jobs(anchor)?;
            let hello = match outcome {
                network::Outcome::Put => {
                    let actual = gnunet_wire::official::dht::PutMessage::decode(wire)?;
                    (actual.block_type == 13).then_some(actual.payload)
                }
                network::Outcome::Result | network::Outcome::UnmatchedResult => {
                    let actual = gnunet_wire::official::dht::ResultMessage::decode(wire)?;
                    (actual.block_type == 13).then_some(actual.payload)
                }
                _ => None,
            };
            if let Some(payload) = hello {
                if self.limits.try_connect {
                    self.discovery.observe_block(payload, anchor.now)?;
                }
                self.report.hello_observations = self.report.hello_observations.saturating_add(1);
            }
        }
        Ok(())
    }
    pub(super) fn target_for(
        &self,
        job: Job<'id>,
        peer: network::Peer<'id>,
        length: usize,
        tracked: bool,
    ) -> Result<Option<NativePeer<'id>>, Error> {
        let original = &self.jobs[native_job_index(&self.jobs, job)?];
        if let Some(target) = original.target {
            return if self
                .peers
                .iter()
                .any(|row| row.token == peer && row.native == target)
            {
                Ok((!tracked || self.native_identity_matches(target)).then_some(target))
            } else {
                Err(Fault::Stale.into())
            };
        }
        Ok(self
            .peers
            .iter()
            .find(|row| {
                row.token == peer
                    && (!tracked || self.native_identity_matches(row.native))
                    && match row.native {
                        NativePeer::Core(_) => network::PutFrameLimit::from_core_frame_bytes(
                            self.limits.core.frame_bytes,
                        )
                        .is_ok_and(|limit| length <= limit.bytes()),
                        NativePeer::Ip(peer) => length <= peer.frame_limit(),
                    }
            })
            .map(|row| row.native))
    }
    pub(super) fn request_available(
        &self,
        native: NativePeer<'id>,
        frame: usize,
    ) -> Result<bool, Error> {
        outgoing::request_available(self.core.as_ref(), self.ip.as_ref(), native, frame)
    }
    pub(super) fn send_limit(&self) -> usize {
        self.limits.native_sends
    }
    pub(super) fn cancel_sign_target(
        &mut self,
        target: signer::Target<'id>,
        retired: bool,
    ) -> Result<(), Error> {
        match target {
            signer::Target::Path(job) => {
                let owner = self.owner.as_mut().ok_or(Fault::NotReady)?;
                if !retired {
                    owner.cancel_job(job)?;
                } else {
                    owner.retired(job)?;
                    self.jobs.retain(|native| native.job != job);
                }
            }
            signer::Target::OwnHello(revision) => {
                if retired {
                    self.own_hello.abandon(revision)?;
                }
            }
        }
        Ok(())
    }
    pub(super) fn refresh_own_hello(&mut self, now: u64) -> Result<bool, Error> {
        let Some(ip) = self.ip.as_ref() else {
            return Ok(false);
        };
        if !ip.addresses_current() {
            return Ok(false);
        }
        let Some(identity) = self.signer.identity() else {
            return Ok(false);
        };
        let Some(announcement) = self.signer.announcement() else {
            return Ok(false);
        };
        self.own_hello
            .refresh(
                announcement,
                identity,
                ip.addresses().iter().map(|address| address.url()),
                AbsoluteTime::from_micros(now),
            )
            .map_err(Into::into)
    }
}

pub(super) fn hint<'id>(
    ip: &mut Option<crate::ip::Client<'id>>,
    transport: &mut Option<Application>,
    report: &mut Report,
    peer: [u8; 32],
    address: &[u8],
    bound: Bound,
) -> Result<bool, Error> {
    if address.starts_with(b"ip+udp://") {
        if let Some(ip) = ip {
            match ip.try_connect(peer, address) {
                Ok(_) => return Ok(true),
                Err(crate::ip::Error::Protocol(
                    Fault::WouldBlock | Fault::Capacity | Fault::NotReady | Fault::Closed,
                )) => return Ok(false),
                Err(
                    error @ crate::ip::Error::Protocol(
                        Fault::InvalidInput
                        | Fault::Malformed
                        | Fault::Unsupported
                        | Fault::TooLarge,
                    ),
                ) => {
                    report.record(Cause::Ip(error));
                    return Ok(true);
                }
                Err(error) => return Err(error.into()),
            }
        }
        return Ok(true);
    }
    if let Some(transport) = transport {
        if !transport.idle() {
            return Ok(false);
        }
        transport.hint(peer, address, transport_bounds(bound))?;
    }
    Ok(true)
}

impl<'id> Server<'id> {
    pub(super) fn ip_event(&mut self, event: crate::ip::Event<'id>) -> Result<Event, Error> {
        match event {
            crate::ip::Event::Connected(peer) => {
                if !self.closing {
                    self.connect_native(NativePeer::Ip(peer))?;
                }
                Ok(Event::Activity(Provider::Ip))
            }
            crate::ip::Event::Disconnected { peer, .. } => {
                self.disconnect_native(NativePeer::Ip(peer))?;
                Ok(Event::Activity(Provider::Ip))
            }
            crate::ip::Event::Message(packet) => {
                if !self.closing {
                    if self.ip_input.is_some() {
                        return Err(Fault::Capacity.into());
                    }
                    self.ip_input = Some(packet);
                }
                Ok(Event::Activity(Provider::Ip))
            }
            crate::ip::Event::Finished {
                send,
                peer,
                outcome,
                written,
                frame_bytes,
            } => {
                let index = self
                    .sends
                    .iter()
                    .position(|original| {
                        original.id == NativeSend::Ip(send) && original.peer == NativePeer::Ip(peer)
                    })
                    .ok_or(Fault::Stale)?;
                let original = self.sends.remove(index);
                if matches!(outcome, crate::ip::Outcome::Written) {
                    self.report.ip_written = self.report.ip_written.saturating_add(1);
                }
                if let crate::ip::Outcome::Failed(error) = &outcome {
                    self.report.record(Cause::IpIo(error.clone()));
                }
                Ok(Event::Send(SendFact {
                    job: original.job.map_or(0, Job::diagnostic),
                    peer: peer.identity().0,
                    provider: Provider::Ip,
                    outcome: crate::SendOutcome::Ip(outcome),
                    written,
                    frame_bytes: frame_bytes.checked_add(32).ok_or(Fault::Overflow)?,
                }))
            }
            crate::ip::Event::AddressesChanged { .. } => {
                self.hello_refresh = true;
                self.own_hello_pending = true;
                Ok(Event::Activity(Provider::Ip))
            }
            crate::ip::Event::AddressRefreshFailed(error) => {
                Ok(self.error(Provider::Ip, Cause::Io(error)))
            }
            crate::ip::Event::ReceiveError { local, error } => {
                Ok(self.error(Provider::Ip, Cause::IpReceive { local, error }))
            }
            crate::ip::Event::Discarded { reason, .. } => {
                Ok(self.error(Provider::Ip, Cause::Protocol(reason)))
            }
            crate::ip::Event::Closed => {
                self.ip_input = None;
                self.ip = None;
                self.update_estimate()?;
                if !self.closing && self.core.is_none() {
                    return Err(Fault::Closed.into());
                }
                Ok(Event::Activity(Provider::Ip))
            }
        }
    }
    pub(super) fn ip_close_event(
        &mut self,
        event: crate::ip::Event<'id>,
    ) -> Result<Option<Event>, Error> {
        self.ip_event(event).map(Some)
    }
    pub(super) fn poll_ip(
        &mut self,
        cx: &mut Context<'_>,
        anchor: Anchor,
        entropy: &mut impl Entropy,
    ) -> Poll<Result<Event, Error>> {
        if let Some(packet) = self.ip_input.take() {
            let peer = NativePeer::Ip(packet.peer());
            let result = self.ingest_native(peer, packet.frame(), anchor, entropy);
            self.report.ip_received = self.report.ip_received.saturating_add(1);
            drop(packet); // Returns this original receive-buffer loan and credit.
            return Poll::Ready(Ok(match result {
                Ok(()) => Event::Activity(Provider::Ip),
                Err(error) => Event::Error {
                    provider: Provider::Ip,
                    cause: self.record_error(error),
                },
            }));
        }
        let Some(ip) = self.ip.as_mut() else {
            return Poll::Pending;
        };
        match ip.poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(event)) => Poll::Ready(self.ip_event(event)),
            Poll::Ready(Err(error)) => {
                ip.close();
                if self.core.is_none() {
                    return Poll::Ready(Err(error.into()));
                }
                Poll::Ready(Ok(self.error(Provider::Ip, Cause::Ip(error))))
            }
        }
    }
}

impl Server<'_> {
    pub(super) fn prepare_ip_addresses(&mut self, now: u64) -> Result<(), Error> {
        let Some(ip) = self.ip.as_ref() else {
            return Ok(());
        };
        let actual = (ip.address_revision(), ip.addresses_current());
        if self.ip_addresses_observed != Some(actual) {
            self.ip_addresses_observed = Some(actual);
            self.hello_refresh = true;
        }
        if self.hello_refresh && actual.1 {
            self.refresh_own_hello(now)?;
            self.hello_refresh = false;
            self.own_hello_pending = true;
        }
        Ok(())
    }
    pub(super) fn disable_core(&mut self) -> Result<(), Error> {
        if let Some(source) = self.core.as_mut() {
            source.retire();
        }
        self.disconnect_core_peers()?;
        self.core_estimate = None;
        self.update_estimate()?;
        if let Some(mut nse) = self.nse.take() {
            let actual = nse.close();
            self.report.nse_start_bytes = actual.start_bytes;
            self.report.nse_start_written = actual.start_written;
        }
        if let Some(mut transport) = self.transport.take() {
            let actual = transport.close();
            if let Err(error) = self.transport_retired(actual) {
                let cause = self.record_error(error);
                self.events.push_back(Event::Error {
                    provider: Provider::Transport,
                    cause,
                });
            }
        }
        for result in self.discovery.close() {
            match result {
                Ok(Some(event)) => {
                    let event = self.ps_event(event);
                    self.events.push_back(event);
                }
                Ok(None) => {}
                Err(error) => {
                    let event = self.error(Provider::Peerstore, Cause::Port(error));
                    self.events.push_back(event);
                }
            }
        }
        if let Some(core) = self.core.as_mut()
            && let Some(event) = core.client.close()?
        {
            self.close_core_event(event);
        }
        Ok(())
    }
}

impl Server<'_> {
    pub(super) fn frame_fits(&self, native: NativePeer<'_>, length: usize) -> Result<bool, Error> {
        Ok(match native {
            NativePeer::Core(_) => {
                length
                    <= network::PutFrameLimit::from_core_frame_bytes(self.limits.core.frame_bytes)?
                        .bytes()
            }
            NativePeer::Ip(peer) => length <= peer.frame_limit(),
        })
    }
}
