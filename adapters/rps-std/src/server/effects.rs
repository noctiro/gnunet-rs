//! Retained core effects transferred once into actual original native owners.
use super::*;
impl<'id, 'slots> Server<'id, 'slots> {
    pub(super) fn pending(
        &mut self,
        transmit: cadet::Transmit<'id>,
        effect: Option<EffectId<'id>>,
        kind: PendingKind<'id>,
        hard: Instant,
    ) -> Result<(), Error> {
        if self.pending.is_some() {
            return Err(Fault::Conflict.into());
        }
        self.pending = Some(Pending {
            transmit,
            effect,
            admitted: false,
            kind,
            hard,
            completion: None,
        });
        if let Some(effect) = effect {
            self.core.admit_effect(effect)?;
        }
        self.pending.as_mut().ok_or(Fault::Stale)?.admitted = true;
        Ok(())
    }
    pub(super) fn effect(&mut self, observe: &mut impl FnMut(Event<'id>)) -> Result<bool, Error> {
        let Some(effect) = self.core.effect() else {
            return Ok(false);
        };
        let id = effect.id;
        match &effect.action {
            Action::ClientView { client, .. } | Action::ClientStream { client, .. } => {
                let client = *client;
                let reply = effect.action.client_response().ok_or(Fault::Conflict)?;
                let size = reply.encoded_len()?;
                if size > self.limits.frame_bytes {
                    if let Some(i) = self
                        .apps
                        .iter()
                        .position(|a| a.as_ref().is_some_and(|a| a.client == client))
                    {
                        self.stop_app(i, CloseCause::Fault(Fault::TooLarge.into()), observe)?;
                    } else {
                        self.reject(id, Fault::Closed, observe)?;
                    }
                    return Ok(true);
                }
                let mut bytes = buffer(size)?;
                reply.encode(&mut bytes, self.limits.reply_profile)?;
                let charge = bytes.capacity();
                self.queue_client(id, client, OwnedFrame::new(bytes), charge, observe)
            }
            Action::OpenPort { group, hash } => {
                let (group, hash) = (*group, *hash);
                if self.core.group_hash(group)? != hash {
                    return Err(Fault::Authentication.into());
                }
                if self.ports.iter().flatten().any(|p| p.group == group) {
                    self.reject(id, Fault::Conflict, observe)?;
                    return Ok(true);
                }
                // Recreated same-hash groups have different GroupIds. The old
                // branded port must actually retire before the new bind; never
                // adopt it or turn a normal delayed close into a fatal conflict.
                if self.ports.iter().flatten().any(|p| p.hash == hash) {
                    return Ok(false);
                }
                let Some(index) = self.ports.iter().position(Option::is_none) else {
                    self.reject(id, Fault::Capacity, observe)?;
                    return Ok(true);
                };
                if self.cadet.pending_transmit().is_some() || self.cadet.epoch().is_none() {
                    return Ok(false);
                }
                let hard = self.hard()?;
                match self.cadet.listen(hash) {
                    Ok(port) => {
                        self.ports[index] = Some(Bound {
                            group,
                            hash,
                            port,
                            close: None,
                            closing: false,
                            hard: None,
                        });
                        let transmit = self.cadet.pending_transmit().ok_or(Fault::Conflict)?;
                        self.pending(transmit, Some(id), PendingKind::OpenPort(group), hard)?;
                        Ok(true)
                    }
                    Err(error) if retry(&error) => Ok(false),
                    Err(error) => Err(error.into()),
                }
            }
            Action::ClosePort { group, .. } => {
                let group = *group;
                let Some(index) = self
                    .ports
                    .iter()
                    .position(|p| p.as_ref().is_some_and(|p| p.group == group))
                else {
                    self.reject(id, Fault::Closed, observe)?;
                    return Ok(true);
                };
                if self.ports[index]
                    .as_ref()
                    .is_some_and(|p| p.close.is_some())
                {
                    self.reject(id, Fault::Conflict, observe)?;
                    return Ok(true);
                }
                let hard = self.hard()?;
                self.core.admit_effect(id)?;
                let port = self.ports[index].as_mut().ok_or(Fault::Stale)?;
                port.close = Some(id);
                port.closing = true;
                port.hard = Some(hard);
                for peer in self
                    .channels
                    .iter_mut()
                    .flatten()
                    .filter(|p| p.group == group)
                {
                    peer.closing = true;
                    peer.hard.get_or_insert(hard);
                }
                Ok(true)
            }
            Action::Connect { group, peer } => {
                let (group, peer) = (*group, *peer);
                let hash = self.core.group_hash(group)?;
                if self.peer_channel(group, peer).is_some() {
                    self.reject(id, Fault::Conflict, observe)?;
                    return Ok(true);
                }
                let Some(index) = self.channels.iter().position(Option::is_none) else {
                    self.reject(id, Fault::Capacity, observe)?;
                    return Ok(true);
                };
                if self.cadet.pending_transmit().is_some() || self.cadet.epoch().is_none() {
                    return Ok(false);
                }
                let hard = self.hard()?;
                match self.cadet.open(peer, hash) {
                    Ok(channel) => {
                        self.channels[index] = Some(Channel {
                            group,
                            peer,
                            channel,
                            opening: true,
                            closing: false,
                            remote_closed: false,
                            qualification_retired: false,
                            input: None,
                            hard: None,
                        });
                        let transmit = self.cadet.pending_transmit().ok_or(Fault::Conflict)?;
                        self.pending(transmit, Some(id), PendingKind::Open(channel), hard)?;
                        Ok(true)
                    }
                    Err(error) if retry(&error) => Ok(false),
                    Err(error) => Err(error.into()),
                }
            }
            Action::ClosePeer { group, peer } => {
                let (group, peer) = (*group, *peer);
                if !self
                    .channels
                    .iter()
                    .flatten()
                    .any(|p| p.group == group && p.peer == peer)
                {
                    self.reject(id, Fault::Closed, observe)?;
                    return Ok(true);
                }
                if self
                    .closing
                    .iter()
                    .any(|c| c.group == group && c.peer == peer)
                {
                    self.reject(id, Fault::Conflict, observe)?;
                    return Ok(true);
                }
                if self.closing.len() == self.limits.channels {
                    self.reject(id, Fault::Capacity, observe)?;
                    return Ok(true);
                }
                let hard = self.hard()?;
                self.core.admit_effect(id)?;
                self.closing.push(Closing {
                    id,
                    group,
                    peer,
                    written: false,
                    outcome: None,
                });
                for channel in self
                    .channels
                    .iter_mut()
                    .flatten()
                    .filter(|p| p.group == group && p.peer == peer)
                {
                    channel.closing = true;
                    channel.hard.get_or_insert(hard);
                }
                Ok(true)
            }
            Action::PeerSend {
                group,
                peer,
                message,
            } => {
                let (group, peer) = (*group, *peer);
                let Some(index) = self.peer_channel(group, peer) else {
                    self.reject(id, Fault::NotReady, observe)?;
                    return Ok(true);
                };
                let channel = self.channels[index].as_ref().ok_or(Fault::Stale)?.channel;
                let wire = message.as_wire();
                let length = wire.encoded_len()?;
                if length > gnunet_wire::official::cadet::MAX_APPLICATION_MESSAGE_SIZE {
                    self.reject(id, Fault::TooLarge, observe)?;
                    return Ok(true);
                }
                if self.sends.len() == self.limits.peer_frames {
                    self.reject(id, Fault::Capacity, observe)?;
                    return Ok(true);
                }
                let mut bytes = buffer(length)?;
                wire.encode(&mut bytes)?;
                let charge = bytes.capacity();
                let retained = self.sends.iter().try_fold(0usize, |sum, s| {
                    sum.checked_add(s.charge).ok_or(Fault::Overflow)
                })?;
                if retained
                    .checked_add(charge)
                    .is_none_or(|n| n > self.limits.peer_bytes)
                {
                    self.reject(id, Fault::Capacity, observe)?;
                    return Ok(true);
                }
                let hard = self.hard()?;
                self.core.admit_effect(id)?;
                self.sends.push_back(Send {
                    id,
                    channel,
                    frame: OwnedFrame::new(bytes),
                    charge,
                    hard,
                });
                Ok(true)
            }
        }
    }
    pub(super) fn settle_pending(
        &mut self,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Error> {
        let Some(pending) = self.pending.as_ref() else {
            return Ok(false);
        };
        let Some(completion) = pending.completion else {
            return Ok(false);
        };
        let (kind, effect, admitted) = (pending.kind, pending.effect, pending.admitted);
        if let Some(id) = effect {
            self.terminal(id, completion, admitted, observe)?;
            self.pending.as_mut().ok_or(Fault::Stale)?.effect = None;
        }
        match kind {
            PendingKind::Open(channel) => {
                if let Some(i) = self.channel_index(channel) {
                    self.channels[i].as_mut().ok_or(Fault::Stale)?.opening = false;
                }
            }
            PendingKind::Send(_) => {
                if completion == Completion::Written {
                    self.report.peer_frames = self.report.peer_frames.saturating_add(1);
                }
            }
            PendingKind::Destroy(channel) => {
                if let Some(i) = self.channel_index(channel) {
                    let peer = self.channels[i].as_ref().ok_or(Fault::Stale)?;
                    if completion == Completion::Written {
                        for c in &mut self.closing {
                            if c.group == peer.group && c.peer == peer.peer {
                                c.written = true;
                            }
                        }
                    }
                    self.finish_channel(i, observe)?;
                }
            }
            PendingKind::ClosePort(group) => {
                if let Some(i) = self
                    .ports
                    .iter()
                    .position(|p| p.as_ref().is_some_and(|p| p.group == group))
                {
                    let port = self.ports[i].as_ref().ok_or(Fault::Stale)?.port;
                    if completion != Completion::Written
                        && self.cadet.port_hash(port).is_ok()
                        && !self.stopped
                    {
                        match self.cadet.close_port(port) {
                            Ok(None) => {}
                            Ok(Some(_)) => return Err(Fault::Conflict.into()),
                            Err(cadet::Error::Protocol(Fault::Closed)) => {}
                            Err(error) => return Err(error.into()),
                        }
                    }
                    self.ports[i] = None;
                }
            }
            PendingKind::Ack(_) => {
                if completion == Completion::Written {
                    self.report.receive_done = self.report.receive_done.saturating_add(1);
                }
            }
            PendingKind::OpenPort(_) => {
                if completion == Completion::Written {
                    self.seed_cursor = Some(0);
                }
            }
            PendingKind::Internal => {}
        }
        self.pending = None;
        Ok(true)
    }
    pub(super) fn reseed(&mut self) -> Result<bool, Error> {
        if self.cadet.epoch().is_none() || self.shutdown.is_some() {
            return Ok(false);
        }
        let Some(index) = self.seed_cursor else {
            return Ok(false);
        };
        if index >= self.seeds.len() {
            self.seed_cursor = None;
            return Ok(false);
        }
        let seed = self.seeds[index];
        if self.core.group_hash(seed.group).is_err() {
            self.seeds.remove(index);
            return Ok(true);
        }
        if !self.ports.iter().flatten().any(|p| {
            p.group == seed.group
                && !p.closing
                && self.cadet.port_announced(p.port).unwrap_or(false)
        }) {
            self.seed_cursor = Some(index + 1);
            return Ok(true);
        }
        let now = self.now()?;
        let result =
            self.core
                .discover(seed.group, seed.peer, now, &mut self.random, &mut self.rank);
        match self.core_result(result) {
            Ok(()) => {
                self.seed_cursor = Some(index + 1);
                Ok(true)
            }
            Err(Error::Protocol(Fault::Capacity | Fault::WouldBlock)) => Ok(false),
            Err(error) => Err(error),
        }
    }
}
