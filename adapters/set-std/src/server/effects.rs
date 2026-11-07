//! Once-only transfers of immutable core actions to their actual native owners.
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
        if let Some(id) = effect {
            self.core.admit_effect(id)?;
        }
        self.pending.as_mut().ok_or(Fault::Stale)?.admitted = true;
        Ok(())
    }
    // A real local adoption or physical client close has already happened. Its
    // original Written fact is retained until the pure owner accepts completion.
    pub(super) fn settle_adopt(
        &mut self,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Error> {
        let Some(applied) = &self.adopted else {
            return Ok(false);
        };
        let id = applied.id;
        self.terminal(id, Completion::Written, true, observe)?;
        self.adopted = None;
        Ok(true)
    }
    pub(super) fn effect(&mut self, observe: &mut impl FnMut(Event<'id>)) -> Result<bool, Error> {
        let mut scanned = false;
        let applied = self.effect_attempt(observe, &mut scanned)?;
        // Advancing the finite selector is CPU activity, never an admission,
        // write or delivery acknowledgement. The poll class then rotates.
        Ok(applied || scanned)
    }
    fn effect_attempt(
        &mut self,
        observe: &mut impl FnMut(Event<'id>),
        scanned: &mut bool,
    ) -> Result<bool, Error> {
        if self.adopted.is_some() {
            return Ok(false);
        }
        let effect = match self.core.scan_effect(&mut self.effect_scan, 64) {
            EffectScanStep::Ready(effect) => {
                *scanned = true;
                effect
            }
            EffectScanStep::Pending => return Ok(true),
            EffectScanStep::End => {
                // A full blocked pass waits on actual IO or pure progress.
                // Never auto-wrap inside this native poll and spin forever.
                self.effect_scan.reset();
                return Ok(false);
            }
        };
        let id = effect.id;
        match &effect.action {
            Action::ClientFrame { client, bytes, .. } => {
                let client = *client;
                if bytes.len() > self.limits.frame_bytes {
                    // This configured native profile cannot represent the real
                    // result. Close the real source rather than truncate it.
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
                if let Some(app) = self
                    .apps
                    .iter()
                    .flatten()
                    .find(|a| a.client == client && a.io.is_some())
                {
                    let retained = app.writes.iter().try_fold(0usize, |sum, w| {
                        sum.checked_add(w.charge).ok_or(Fault::Overflow)
                    })?;
                    if app.writes.len() == self.limits.output_frames
                        || retained
                            .checked_add(bytes.len())
                            .is_none_or(|n| n > self.limits.output_bytes)
                    {
                        return Ok(false);
                    }
                }
                let mut copy = buffer(bytes.len())?;
                copy.copy_from_slice(bytes);
                let charge = copy.capacity();
                self.queue_client(id, client, OwnedFrame::new(copy), charge, observe)
            }
            Action::OpenPort {
                listener, app_id, ..
            } => {
                let (listener, hash) = (*listener, *app_id);
                if !self.core.client_live(listener) {
                    self.reject(id, Fault::Closed, observe)?;
                    return Ok(true);
                }
                if self.ports.iter().flatten().any(|p| p.listener == listener) {
                    self.reject(id, Fault::Conflict, observe)?;
                    return Ok(true);
                }
                // Same public application, different original listener: wait for
                // actual old port retirement, never reuse a branded old handle.
                if let Some(old) = self.ports.iter().flatten().find(|p| p.hash == hash) {
                    if !old.closing && self.core.client_live(old.listener) {
                        // Two currently live listeners cannot both own one real
                        // CADET port. Refuse the new action, rather than blocking
                        // unrelated core effects behind a permanently live bind.
                        self.reject(id, Fault::Conflict, observe)?;
                        return Ok(true);
                    }
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
                            listener,
                            hash,
                            port,
                            close: None,
                            closing: false,
                            hard: None,
                        });
                        let transmit = self.cadet.pending_transmit().ok_or(Fault::Conflict)?;
                        self.pending(transmit, Some(id), PendingKind::OpenPort(listener), hard)?;
                        Ok(true)
                    }
                    Err(error) if retry(&error) => Ok(false),
                    Err(error) => Err(error.into()),
                }
            }
            Action::ClosePort { listener, app_id } => {
                let (listener, hash) = (*listener, *app_id);
                let Some(index) = self.ports.iter().position(|p| {
                    p.as_ref()
                        .is_some_and(|p| p.listener == listener && p.hash == hash)
                }) else {
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
                port.hard.get_or_insert(hard);
                // Actual Adopt clears listener only after the same-channel local
                // transfer. Accepted operation channels survive listener close.
                for channel in self
                    .channels
                    .iter_mut()
                    .flatten()
                    .filter(|c| c.listener == Some(listener))
                {
                    channel.mark_closing(hard);
                }
                Ok(true)
            }
            Action::OpenPeer {
                operation,
                peer,
                app_id,
            } => {
                let (owner, peer, app_id) = (PeerOwner::Operation(*operation), *peer, *app_id);
                if !self.core.peer_owner_live(owner) {
                    self.reject(id, Fault::Closed, observe)?;
                    return Ok(true);
                }
                if self.owner_channel(owner).is_some() {
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
                match self.cadet.open(peer, app_id) {
                    Ok(channel) => {
                        self.channels[index] = Some(Channel {
                            listener: None,
                            app_id,
                            owner: Some(owner),
                            peer,
                            channel,
                            opening: true,
                            closing: false,
                            local_closing: false,
                            remote_closed: false,
                            retire_reason: Fault::Closed,
                            first: None,
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
            Action::AdoptPeer {
                incoming,
                operation,
            } => {
                let (incoming, operation) = (*incoming, *operation);
                let Some(index) = self.owner_channel(PeerOwner::Incoming(incoming)) else {
                    self.reject(id, Fault::Closed, observe)?;
                    return Ok(true);
                };
                let channel = self.channels[index].as_ref().ok_or(Fault::Stale)?;
                if channel.closing || channel.remote_closed {
                    self.reject(id, Fault::Closed, observe)?;
                    return Ok(true);
                }
                if channel
                    .input
                    .as_ref()
                    .is_some_and(|input| input.at != input.packet.messages().len())
                    || self.sends.iter().any(|s| s.channel == channel.channel)
                    || self.pending.as_ref().is_some_and(
                        |p| matches!(p.kind, PendingKind::Send(c) if c == channel.channel),
                    )
                {
                    return Ok(false);
                }
                let actual = channel.channel;
                let ack_hard = self.hard()?;
                self.core.admit_effect(id)?;
                self.adopted = Some(Adopt {
                    id,
                    channel: Some(actual),
                });
                let channel = self.channels[index].as_mut().ok_or(Fault::Stale)?;
                channel.owner = Some(PeerOwner::Operation(operation));
                channel.listener = None;
                if let Some(input) = &mut channel.input {
                    // Start the actual receive-credit release phase after local
                    // acceptance; the preceding complete request was waiting on
                    // its original core accept deadline, not partial-input IO.
                    input.hard = Some(ack_hard);
                }
                self.settle_adopt(observe)?;
                Ok(true)
            }
            Action::PeerSend { owner, bytes } => {
                let owner = *owner;
                let Some(index) = self.owner_channel(owner) else {
                    self.reject(id, Fault::Closed, observe)?;
                    return Ok(true);
                };
                let source = self.channels[index].as_ref().ok_or(Fault::Stale)?;
                if source.closing {
                    self.reject(id, Fault::Closed, observe)?;
                    return Ok(true);
                }
                let channel = source.channel;
                if bytes.len() > gnunet_wire::official::cadet::MAX_APPLICATION_MESSAGE_SIZE {
                    self.reject(id, Fault::TooLarge, observe)?;
                    return Ok(true);
                }
                if self.sends.len() == self.limits.peer_frames {
                    return Ok(false);
                }
                let retained = self.sends.iter().try_fold(0usize, |sum, s| {
                    sum.checked_add(s.charge).ok_or(Fault::Overflow)
                })?;
                if retained
                    .checked_add(bytes.len())
                    .is_none_or(|n| n > self.limits.peer_bytes)
                {
                    return Ok(false);
                }
                let mut copy = buffer(bytes.len())?;
                copy.copy_from_slice(bytes);
                let charge = copy.capacity();
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
                    frame: OwnedFrame::new(copy),
                    charge,
                    hard,
                });
                Ok(true)
            }
            Action::ClosePeer { owner } => {
                let owner = *owner;
                let Some(index) = self.owner_channel(owner) else {
                    self.reject(id, Fault::Closed, observe)?;
                    return Ok(true);
                };
                if self.closing.iter().any(|c| c.owner == owner) {
                    self.reject(id, Fault::Conflict, observe)?;
                    return Ok(true);
                }
                if self.closing.len() == self.limits.channels {
                    return Ok(false);
                }
                let hard = self.hard()?;
                self.core.admit_effect(id)?;
                self.closing.push(Closing {
                    id,
                    owner,
                    written: false,
                    outcome: None,
                });
                let channel = self.channels[index].as_mut().ok_or(Fault::Stale)?;
                channel.mark_closing(hard);
                Ok(true)
            }
            Action::CloseClient { client, reason } => {
                let (client, reason) = (*client, *reason);
                let Some(index) = self.apps.iter().position(|a| {
                    a.as_ref()
                        .is_some_and(|a| a.client == client && a.io.is_some())
                }) else {
                    self.reject(id, Fault::Closed, observe)?;
                    return Ok(true);
                };
                self.core.admit_effect(id)?;
                self.adopted = Some(Adopt { id, channel: None });
                // This retained local Written fact survives an error settling
                // older output or pure detach after actual physical closure.
                self.stop_app(index, CloseCause::Fault(reason.into()), observe)?;
                self.settle_adopt(observe)?;
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
        let (kind, effect, admitted, original_hard) =
            (pending.kind, pending.effect, pending.admitted, pending.hard);
        if let Some(id) = effect {
            self.terminal(id, completion, admitted, observe)?;
            self.pending.as_mut().ok_or(Fault::Stale)?.effect = None;
        }
        match kind {
            PendingKind::Open(channel) => {
                if let Some(i) = self.channel_index(channel) {
                    let source = self.channels[i].as_mut().ok_or(Fault::Stale)?;
                    source.opening = false;
                    if completion != Completion::Written {
                        source.mark_closing(original_hard);
                        source.remote_closed = true;
                    }
                }
            }
            PendingKind::Send(_) => {
                if completion == Completion::Written {
                    self.report.peer_frames = self.report.peer_frames.saturating_add(1);
                }
            }
            PendingKind::Destroy(channel) => {
                if let Some(i) = self.channel_index(channel) {
                    let owner = self.channels[i].as_ref().ok_or(Fault::Stale)?.owner;
                    if completion == Completion::Written {
                        // Whole local cleanup is independent of the original
                        // business refusal/deadline. Preserve that reason for
                        // unsent payloads and core peer retirement below.
                        for close in &mut self.closing {
                            if Some(close.owner) == owner {
                                close.written = true;
                                close.outcome = Some(Completion::Written);
                            }
                        }
                    }
                    self.finish_channel(i, observe)?;
                }
            }
            PendingKind::ClosePort(listener) => {
                if let Some(i) = self
                    .ports
                    .iter()
                    .position(|p| p.as_ref().is_some_and(|p| p.listener == listener))
                {
                    let port = self.ports[i].as_ref().ok_or(Fault::Stale)?.port;
                    if completion != Completion::Written && self.cadet.port_hash(port).is_ok() {
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
            PendingKind::OpenPort(_) | PendingKind::Internal => {}
        }
        self.pending = None;
        Ok(true)
    }
}
