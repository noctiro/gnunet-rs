use super::*;
impl<'id, 'store, 'bytes, 'cadet, 'cstore, 'policy>
    Coordinator<'id, 'store, 'bytes, 'cadet, 'cstore, 'policy>
{
    pub(super) fn pending(
        &mut self,
        tx: cadet::Transmit<'cadet>,
        action: Action<'id>,
    ) -> Result<(), Error> {
        if self.native.is_some() {
            return Err(Fault::Conflict.into());
        }
        self.native = Some(Pending {
            transmit: tx,
            action,
            until: Self::deadline(self.limits.cadet_send_timeout)?,
        });
        Ok(())
    }
    fn mark_exposed(&mut self, observe: &mut impl FnMut(Event<'id, 'cadet>)) -> Result<(), Error> {
        if let Some(p) = self.native.as_ref()
            && let Action::Data {
                link,
                effect,
                retired,
            } = p.action
        {
            if retired {
                // Keep actual positive-prefix facts while the original pure
                // source is retained for held input; never revive a lost source.
                if self.links[link].as_ref().is_some_and(|l| l.peer.is_some()) {
                    self.server.engine_mut().exposed(effect)?;
                }
                observe(Event::RetiredWrite {
                    transmit: p.transmit,
                    effect,
                    complete: false,
                });
            } else {
                self.server.engine_mut().exposed(effect)?;
            }
        }
        Ok(())
    }
    fn written(
        &mut self,
        tx: cadet::Transmit<'cadet>,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<(), Error> {
        let p = self.native.take().ok_or(Fault::StaleGeneration)?;
        if p.transmit != tx {
            self.native = Some(p);
            return Err(Fault::StaleGeneration.into());
        }
        match p.action {
            Action::Open(i) => {
                if let Some(l) = self.links[i].as_mut() {
                    l.create_written = true;
                }
            }
            Action::Data {
                link,
                effect,
                retired,
            } => {
                if retired {
                    if self.links[link].as_ref().is_some_and(|l| l.peer.is_some()) {
                        self.server.engine_mut().exposed(effect)?;
                    }
                    observe(Event::RetiredWrite {
                        transmit: tx,
                        effect,
                        complete: true,
                    });
                } else {
                    self.server.engine_mut().exposed(effect)?;
                    self.server.engine_mut().written(effect)?;
                    self.report.peer_written = self.report.peer_written.saturating_add(1);
                    observe(Event::PeerWritten {
                        transmit: tx,
                        effect,
                    });
                }
            }
            Action::Ack(_) => {}
            Action::Destroy(i) => {
                self.lost_link(i, Fault::Closed, observe)?;
            }
            Action::Auxiliary => {}
        }
        Ok(())
    }
    fn lost_link(
        &mut self,
        i: usize,
        reason: Fault,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<(), Error> {
        let Some(l) = self.links.get_mut(i).and_then(Option::as_mut) else {
            return Err(Fault::StaleGeneration.into());
        };
        let peer = l.peer.take();
        let open = l.open.take();
        l.channel = None;
        l.open_until = None;
        l.input = None;
        if let Some(peer) = peer {
            let loss = self.server.engine_mut().peer_lost(peer, reason)?;
            observe(Event::PeerLost(loss));
        } else if let Some(open) = open {
            self.server.engine_mut().open_failed(open, reason)?;
        } else {
            self.server.engine_mut().close_flow(l.flow, reason)?;
        }
        if let Some(p) = self.native.as_mut()
            && let Action::Data { link, retired, .. } = &mut p.action
            && *link == i
        {
            *retired = true;
        }
        Ok(())
    }
    fn remote_closed(&mut self, i: usize) -> Result<(), Error> {
        let l = self.links[i].as_ref().ok_or(Fault::StaleGeneration)?;
        let flow = l.flow;
        let discard = self.stopping.is_some()
            || l.peer.is_none()
            || self.server.engine().flow_info(flow)?.phase == core::Phase::Closing;
        self.server.engine_mut().peer_ended(flow)?;
        let l = self.links[i].as_mut().ok_or(Fault::StaleGeneration)?;
        l.remote_closed = true;
        if discard {
            l.input = None;
        }
        if let Some(p) = self.native.as_mut()
            && let Action::Data { link, retired, .. } = &mut p.action
            && *link == i
        {
            *retired = true;
        }
        Ok(())
    }
    pub(super) fn backend_lost(
        &mut self,
        report: cadet::Loss<'cadet>,
        reason: Fault,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<(), Error> {
        if report.pending.is_some_and(|r| {
            r.exposed
                && self
                    .native
                    .as_ref()
                    .is_some_and(|p| p.transmit == r.transmit)
        }) {
            self.mark_exposed(observe)?;
        }
        // The native owner detached its original MQ before minting this report.
        for i in 0..self.links.len() {
            if self.links[i]
                .as_ref()
                .is_some_and(|l| l.channel.is_some() || l.open.is_some() || l.peer.is_some())
            {
                self.lost_link(i, reason, observe)?;
            }
        }
        self.native = None;
        self.report.cadet_losses = self.report.cadet_losses.saturating_add(1);
        Ok(())
    }
    fn restart_backend(
        &mut self,
        reason: Fault,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<(), Error> {
        match self.cadet.reconnect()? {
            cadet::Step::Lost {
                report,
                cause,
                retry_after: _,
            } => {
                self.backend_lost(report, reason, observe)?;
                observe(Event::BackendLost { report, cause });
            }
            cadet::Step::Closed => return Err(Fault::Closed.into()),
            _ => return Err(Fault::Conflict.into()),
        }
        Ok(())
    }
    pub(super) fn poll_backend(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<bool, Error> {
        if self
            .native
            .as_ref()
            .is_some_and(|p| Instant::now() >= p.until)
        {
            self.restart_backend(Fault::Deadline, observe)?;
            return Ok(true);
        }
        let step = match self.cadet.poll(cx, None) {
            Poll::Pending => return Ok(false),
            Poll::Ready(r) => r?,
        };
        match step {
            cadet::Step::Connected(epoch) => observe(Event::BackendConnected(epoch)),
            cadet::Step::Written(w) => self.written(w.transmit, observe)?,
            cadet::Step::Credit { channel, .. } => {
                if self.find(channel).is_none() {
                    return Err(Fault::StaleGeneration.into());
                }
            }
            cadet::Step::Data(frame) => {
                let Some(i) = self.find(frame.channel()) else {
                    return Err(Fault::StaleGeneration.into());
                };
                let l = self.links[i].as_mut().ok_or(Fault::StaleGeneration)?;
                if l.remote_closed
                    || self.stopping.is_some()
                    || self.server.engine().flow_info(l.flow)?.phase == core::Phase::Closing
                {
                    l.input = None;
                    return Ok(true);
                }
                if l.input.is_some() {
                    return Err(Fault::Conflict.into());
                }
                l.input = Some(Input {
                    frame,
                    offset: 0,
                    processing: None,
                    until: Self::deadline(self.limits.input_timeout)?,
                });
            }
            cadet::Step::Destroyed(channel) => {
                if let Some(i) = self.find(channel) {
                    self.remote_closed(i)?;
                }
            }
            cadet::Step::Lost { report, cause, .. } => {
                self.backend_lost(report, Fault::Closed, observe)?;
                observe(Event::BackendLost { report, cause });
            }
            cadet::Step::ConnectRetry { error, retry_after } => {
                observe(Event::BackendRetry { error, retry_after })
            }
            cadet::Step::RejectedIncoming { transmit, .. } => {
                self.pending(transmit, Action::Auxiliary)?
            }
            cadet::Step::Incoming { .. } => {
                self.restart_backend(Fault::PermissionDenied, observe)?
            }
            cadet::Step::Blocked { reason, .. } => self.restart_backend(reason, observe)?,
            cadet::Step::Unavailable(e) => return Err(e.into()),
            cadet::Step::Activity { written_bytes, .. } => {
                if written_bytes > 0 {
                    self.mark_exposed(observe)?;
                }
            }
            cadet::Step::Ignored { .. } => {}
            cadet::Step::WaitDeadline => return Ok(false),
            cadet::Step::Closed => {
                if self.stopping.is_none() {
                    return Err(Fault::Closed.into());
                }
                return Ok(false);
            }
        }
        Ok(true)
    }
    fn offer_discovery(
        &mut self,
        i: usize,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<bool, Error> {
        let l = self.links[i].as_ref().ok_or(Fault::StaleGeneration)?;
        if l.discovery.is_some() {
            return Ok(false);
        }
        let d = self.server.engine_mut().discovery_request(l.flow)?;
        self.links[i]
            .as_mut()
            .ok_or(Fault::StaleGeneration)?
            .discovery = Some(Discovery {
            request: d,
            queued: false,
        });
        match self.limits.discovery {
            DiscoveryMode::External => observe(Event::Discovery(d)),
            DiscoveryMode::Configured => {
                self.server.engine_mut().can_queue_discovery(d.discovery)?;
                // This provider is the caller-authorized finite policy slice;
                // no automatic network discovery result is fabricated.
                let selected = self
                    .policies
                    .iter()
                    .find(|p| {
                        p.network.is_none_or(|n| n.matches(d.destination))
                            && p.protocol.is_none_or(|p| p == d.protocol)
                            && (p.ports.0..=p.ports.1).contains(&d.port)
                    })
                    .copied();
                self.server.engine_mut().discovery_queued(d.discovery)?;
                if let Some(p) = selected {
                    self.server.engine_mut().select_exit(d.discovery, p.peer)?;
                    self.links[i].as_mut().ok_or(Fault::StaleGeneration)?.af = p.af;
                    self.report.configured = self.report.configured.saturating_add(1);
                } else {
                    self.server
                        .engine_mut()
                        .discovery_failed(d.discovery, Fault::Unavailable)?;
                }
                self.server.engine_mut().retire_discovery(d.discovery)?;
                self.links[i]
                    .as_mut()
                    .ok_or(Fault::StaleGeneration)?
                    .discovery = None;
            }
        }
        Ok(true)
    }
    fn open_link(&mut self, i: usize) -> Result<bool, Error> {
        if self.native.is_some() || self.cadet.epoch().is_none() {
            return Ok(false);
        }
        let l = self.links[i].as_ref().ok_or(Fault::StaleGeneration)?;
        if l.remote_closed || l.channel.is_some() || l.open.is_some() {
            return Ok(false);
        }
        let request = self.server.engine_mut().open_request(l.flow)?;
        self.server.engine_mut().can_queue_open(request.open)?;
        match self.cadet.open(request.peer, request.port) {
            Ok(channel) => {
                let tx = self.cadet.pending_transmit().ok_or(Fault::NotReady)?;
                self.server.engine_mut().open_queued(request.open)?;
                let l = self.links[i].as_mut().ok_or(Fault::StaleGeneration)?;
                l.open = Some(request.open);
                l.channel = Some(channel);
                l.create_written = false;
                l.open_until = Some(Self::deadline(self.limits.cadet_send_timeout)?);
                self.pending(tx, Action::Open(i))?;
                Ok(true)
            }
            Err(cadet::Error::Protocol(Fault::WouldBlock | Fault::NotReady)) => {
                self.server.engine_mut().reject_open(request.open)?;
                Ok(false)
            }
            Err(e) => {
                self.server
                    .engine_mut()
                    .open_failed(request.open, Fault::Closed)?;
                Err(e.into())
            }
        }
    }
    fn bind_link(&mut self, i: usize) -> Result<bool, Error> {
        let l = self.links[i].as_ref().ok_or(Fault::StaleGeneration)?;
        let (Some(channel), Some(open)) = (l.channel, l.open) else {
            return Ok(false);
        };
        if l.remote_closed || !l.create_written {
            return Ok(false);
        }
        let info = self.cadet.channel_info(channel)?;
        if info.closing || info.send_credit == 0 {
            return Ok(false);
        }
        // This current actual service source granted real credit for this exact
        // requested endpoint. No plaintext/CID field or queued CREATE binds it.
        let peer = self.server.engine_mut().bind_peer(open, info.peer, l.af)?;
        let l = self.links[i].as_mut().ok_or(Fault::StaleGeneration)?;
        l.open = None;
        l.open_until = None;
        l.peer = Some(peer);
        Ok(true)
    }
    fn send_link(&mut self, i: usize) -> Result<bool, Error> {
        if self.native.is_some() {
            return Ok(false);
        }
        let l = self.links[i].as_ref().ok_or(Fault::StaleGeneration)?;
        if l.remote_closed {
            return Ok(false);
        }
        let (Some(peer), Some(channel)) = (l.peer, l.channel) else {
            return Ok(false);
        };
        if self.cadet.channel_info(channel)?.send_credit == 0 {
            return Ok(false);
        }
        let Some(prepared) = self.server.engine_mut().prepare_peer(peer)? else {
            return Ok(false);
        };
        let effect = prepared.effect;
        let result = self.cadet.send(channel, 0, prepared.bytes);
        match result {
            Ok(tx) => {
                self.server.engine_mut().queued(effect)?;
                self.pending(
                    tx,
                    Action::Data {
                        link: i,
                        effect,
                        retired: false,
                    },
                )?;
                Ok(true)
            }
            Err(cadet::Error::Protocol(Fault::WouldBlock | Fault::NotReady)) => {
                self.server.engine_mut().reject_prepared(effect)?;
                Ok(false)
            }
            Err(e) => {
                self.server.engine_mut().reject_prepared(effect)?;
                self.fail_flow(i, Fault::Closed)?;
                Err(e.into())
            }
        }
    }
    fn close_link(&mut self, i: usize) -> Result<bool, Error> {
        if self.native.is_some() {
            return Ok(false);
        }
        let l = self.links[i].as_ref().ok_or(Fault::StaleGeneration)?;
        if let Some(channel) = l.channel {
            let tx = self.cadet.destroy(channel)?;
            self.pending(tx, Action::Destroy(i))?;
            Ok(true)
        } else if let Some(open) = l.open {
            self.server.engine_mut().open_failed(open, Fault::Closed)?;
            self.links[i].as_mut().ok_or(Fault::StaleGeneration)?.open = None;
            Ok(true)
        } else if let Some(d) = l.discovery {
            if !d.queued {
                self.server
                    .engine_mut()
                    .retire_discovery(d.request.discovery)?;
                self.links[i]
                    .as_mut()
                    .ok_or(Fault::StaleGeneration)?
                    .discovery = None;
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            Ok(false)
        }
    }
    pub(super) fn work(
        &mut self,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<bool, Error> {
        for _ in 0..self.links.len() {
            let i = self.cursor;
            self.cursor = (self.cursor + 1) % self.links.len();
            let Some(l) = self.links[i].as_ref() else {
                continue;
            };
            let phase = self.server.engine().flow_info(l.flow)?.phase;
            if self.stopping.is_some() && phase != core::Phase::Closing {
                self.fail_flow(i, Fault::Closed)?;
                return Ok(true);
            }
            if l.open_until.is_some_and(|at| Instant::now() >= at) {
                self.links[i]
                    .as_mut()
                    .ok_or(Fault::StaleGeneration)?
                    .open_until = None;
                self.fail_flow(i, Fault::Deadline)?;
                return Ok(true);
            }
            if l.remote_closed && (l.channel.is_some() || l.open.is_some() || l.peer.is_some()) {
                if phase == core::Phase::Closing {
                    self.links[i].as_mut().ok_or(Fault::StaleGeneration)?.input = None;
                }
                if self.links[i].as_ref().is_some_and(|l| l.input.is_some())
                    || self
                        .native
                        .as_ref()
                        .is_some_and(|p| p.action.link() == Some(i))
                {
                    continue;
                }
                self.lost_link(i, Fault::Closed, observe)?;
                return Ok(true);
            }
            let progressed = match phase {
                core::Phase::Discovering => self.offer_discovery(i, observe)?,
                core::Phase::NeedOpen => self.open_link(i)?,
                core::Phase::Opening => self.bind_link(i)?,
                core::Phase::Ready => self.send_link(i)?,
                core::Phase::Closing => self.close_link(i)?,
            };
            if progressed {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
