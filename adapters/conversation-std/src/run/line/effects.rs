use super::{
    Action, ClientOrigin, Completion, EffectScanStep, Error, Fault, NativeKind, PendingClient,
    PendingNative, State, cadet,
};
use gnunet_service_runtime::framing::{Class, OwnedFrame};
fn blocked(error: &cadet::Error) -> bool {
    matches!(
        error,
        cadet::Error::Protocol(Fault::WouldBlock | Fault::NotReady | Fault::Capacity)
    )
}
impl<'s, 'p, 'c, 'slots> State<'s, 'p, 'c, 'slots> {
    fn reject_step(&mut self) -> Result<bool, Error> {
        if self.pending_native.is_some() {
            return Ok(false);
        }
        let Some(index) = self.rejects.iter().position(|r| !r.queued) else {
            return Ok(false);
        };
        let reject = &self.rejects[index];
        let channel = reject.channel;
        let bound = reject.bound;
        let transmit = match self.cadet.destroy(channel) {
            Ok(tx) => tx,
            Err(error) if blocked(&error) => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        self.rejects[index].queued = true;
        let call = self
            .calls
            .iter()
            .flatten()
            .find(|c| c.channel == Some(channel))
            .map(|c| c.id);
        self.pending_native = Some(PendingNative {
            call,
            ack: None,
            transmit,
            kind: NativeKind::Reject(channel),
            attempted: false,
            exposed: false,
            known_written: false,
            closing: true,
            bound,
        });
        self.mark();
        Ok(true)
    }
    pub(super) fn effect_step(&mut self) -> Result<bool, Error> {
        if self.reject_step()? {
            return Ok(true);
        }
        if self.scan_end {
            if !self.dirty {
                return Ok(false);
            }
            self.scan.reset();
            self.scan_end = false;
            self.dirty = false;
        }
        let current = self.selected()?;
        let now = self.now()?;
        let effect = match self
            .session
            .core()
            .ok_or(Fault::NotReady)?
            .scan_effect(&mut self.scan, self.limits.work_units)?
        {
            EffectScanStep::Pending => return Ok(true),
            EffectScanStep::End => {
                self.scan_end = true;
                return Ok(self.dirty);
            }
            EffectScanStep::Ready(effect) => effect,
        };
        let id = effect.id();
        let deadline = effect.deadline();
        let cancelled = effect.cancelled();
        if cancelled
            || !self
                .session
                .core()
                .ok_or(Fault::NotReady)?
                .effect_io_allowed(id, &current, now)?
        {
            let reason = if cancelled {
                Fault::Cancelled
            } else {
                Fault::Deadline
            };
            self.settle(id, Completion::Unsent(reason))?;
            return Ok(true);
        }
        let bound = self.origin.at(deadline)?;
        match effect.action() {
            Action::OpenPort { port } => {
                if self.pending_native.is_some() || self.source.is_none() {
                    return Ok(true);
                }
                if self.port.is_some() {
                    return Err(Fault::Conflict.into());
                }
                let hash = *port;
                let source = self.source.ok_or(Fault::NotReady)?;
                let native = match self.cadet.listen(hash) {
                    Ok(port) => port,
                    Err(error) if blocked(&error) => return Ok(true),
                    Err(error) => return Err(error.into()),
                };
                self.port = Some(native);
                self.port_hash = Some(hash);
                let transmit = self.cadet.pending_transmit().ok_or(Fault::Conflict)?;
                self.pending_native = Some(PendingNative {
                    call: None,
                    ack: None,
                    transmit,
                    kind: NativeKind::Effect(id),
                    attempted: false,
                    exposed: false,
                    known_written: false,
                    closing: false,
                    bound,
                });
                self.session
                    .core_mut()
                    .ok_or(Fault::NotReady)?
                    .attach_port(source)?;
                self.session
                    .core_mut()
                    .ok_or(Fault::NotReady)?
                    .admit_effect(id)?;
            }
            Action::OpenChannel { call, target, port } => {
                if self.pending_native.is_some() || self.source.is_none() {
                    return Ok(true);
                }
                let call = *call;
                let target = *target;
                let port = *port;
                let index = self
                    .calls
                    .iter()
                    .position(|row| row.as_ref().is_some_and(|c| c.id == call))
                    .ok_or(Fault::StaleGeneration)?;
                if self.calls[index]
                    .as_ref()
                    .is_none_or(|c| c.channel.is_some() || c.gone)
                {
                    return Err(Fault::Conflict.into());
                }
                let channel = match self.cadet.open(target, port) {
                    Ok(channel) => channel,
                    Err(error) if blocked(&error) => return Ok(true),
                    Err(error) => return Err(error.into()),
                };
                let source = self.source.ok_or(Fault::NotReady)?;
                let entry = self.calls[index].as_mut().ok_or(Fault::Stale)?;
                entry.channel = Some(channel);
                entry.source = Some(source);
                let transmit = self.cadet.pending_transmit().ok_or(Fault::Conflict)?;
                self.pending_native = Some(PendingNative {
                    call: Some(call),
                    ack: None,
                    transmit,
                    kind: NativeKind::Effect(id),
                    attempted: false,
                    exposed: false,
                    known_written: false,
                    closing: false,
                    bound,
                });
                self.session
                    .core_mut()
                    .ok_or(Fault::NotReady)?
                    .attach_channel(call, source)?;
                self.session
                    .core_mut()
                    .ok_or(Fault::NotReady)?
                    .admit_effect(id)?;
            }
            Action::PeerFrame { call, frame } => {
                if self.pending_native.is_some() {
                    return Ok(true);
                }
                let call = *call;
                let entry = self
                    .calls
                    .iter()
                    .flatten()
                    .find(|c| c.id == call)
                    .ok_or(Fault::StaleGeneration)?;
                if entry.gone || entry.retiring.is_some() {
                    let reason = entry.retiring.unwrap_or(Fault::Closed);
                    self.settle(id, Completion::Unsent(reason))?;
                    return Ok(true);
                }
                let Some(channel) = entry.channel else {
                    return Ok(true);
                };
                let transmit = match self.cadet.send(channel, 0, frame) {
                    Ok(tx) => tx,
                    Err(error) if blocked(&error) => return Ok(true),
                    Err(error) => return Err(error.into()),
                };
                self.pending_native = Some(PendingNative {
                    call: Some(call),
                    ack: None,
                    transmit,
                    kind: NativeKind::Effect(id),
                    attempted: false,
                    exposed: false,
                    known_written: false,
                    closing: false,
                    bound,
                });
                self.session
                    .core_mut()
                    .ok_or(Fault::NotReady)?
                    .admit_effect(id)?;
            }
            Action::ClientFrame { frame, .. } => {
                if self.pending_client.is_some() {
                    return Ok(true);
                }
                if !self.io.capacity(frame.len(), Class::Ordinary) {
                    return Ok(true);
                }
                let copy = OwnedFrame::copy_from(frame)?;
                self.io
                    .enqueue_owned(copy, ClientOrigin(id.value()), Class::Ordinary)
                    .map_err(|rejected| Error::from(rejected.reason))?;
                self.pending_client = Some(PendingClient {
                    effect: id,
                    written: 0,
                    attempted: false,
                    known_written: false,
                    bound,
                });
                self.session
                    .core_mut()
                    .ok_or(Fault::NotReady)?
                    .admit_effect(id)?;
            }
            Action::ReceiveDone { call, delivery } => {
                let call = *call;
                let serial = *delivery;
                let index = self
                    .calls
                    .iter()
                    .position(|row| row.as_ref().is_some_and(|c| c.id == call))
                    .ok_or(Fault::StaleGeneration)?;
                let entry = self.calls[index].as_ref().ok_or(Fault::Stale)?;
                let input = entry.input.as_ref().ok_or(Fault::StaleGeneration)?;
                if input.waiting != Some(serial)
                    || entry.channel != Some(input.received.channel())
                    || entry.source != self.source
                    || !input.validated
                {
                    return Err(Fault::StaleGeneration.into());
                }
                if input.offset < input.received.messages().len() {
                    self.settle(id, Completion::Processed)?;
                    self.calls[index]
                        .as_mut()
                        .and_then(|c| c.input.as_mut())
                        .ok_or(Fault::Stale)?
                        .waiting = None;
                    return Ok(true);
                }
                if input.offset != input.received.messages().len() {
                    return Err(Fault::Malformed.into());
                }
                if self.pending_native.is_some() {
                    return Ok(true);
                }
                let delivery = input.received.delivery();
                let transmit = match self.cadet.receive_done(delivery) {
                    Ok(tx) => tx,
                    Err(error) if blocked(&error) => return Ok(true),
                    Err(error) => return Err(error.into()),
                };
                self.pending_native = Some(PendingNative {
                    call: Some(call),
                    ack: Some((call, serial)),
                    transmit,
                    kind: NativeKind::Effect(id),
                    attempted: false,
                    exposed: false,
                    known_written: false,
                    closing: false,
                    bound,
                });
                self.session
                    .core_mut()
                    .ok_or(Fault::NotReady)?
                    .admit_effect(id)?;
            }
            Action::CloseChannel { call } => {
                let call = *call;
                let index = self
                    .calls
                    .iter()
                    .position(|row| row.as_ref().is_some_and(|c| c.id == call))
                    .ok_or(Fault::StaleGeneration)?;
                let entry = self.calls[index].as_ref().ok_or(Fault::Stale)?;
                if entry.gone || entry.channel.is_none() {
                    self.settle(id, Completion::Unsent(Fault::Closed))?;
                    return Ok(true);
                }
                if self.pending_native.is_some()
                    || self
                        .rejects
                        .iter()
                        .any(|r| Some(r.channel) == entry.channel)
                {
                    return Ok(true);
                }
                let channel = entry.channel.ok_or(Fault::NotReady)?;
                let transmit = match self.cadet.destroy(channel) {
                    Ok(tx) => tx,
                    Err(error) if blocked(&error) => return Ok(true),
                    Err(error) => return Err(error.into()),
                };
                self.pending_native = Some(PendingNative {
                    call: Some(call),
                    ack: None,
                    transmit,
                    kind: NativeKind::Effect(id),
                    attempted: false,
                    exposed: false,
                    known_written: false,
                    closing: true,
                    bound,
                });
                self.session
                    .core_mut()
                    .ok_or(Fault::NotReady)?
                    .admit_effect(id)?;
            }
            Action::ClosePort { .. } => {
                if self.pending_native.is_some() {
                    return Ok(true);
                }
                let Some(port) = self.port else {
                    self.settle(id, Completion::Unsent(Fault::Closed))?;
                    return Ok(true);
                };
                let transmit = match self.cadet.close_port(port) {
                    Ok(Some(tx)) => tx,
                    Ok(None) => return Err(Fault::Cancelled.into()),
                    Err(error) if blocked(&error) => return Ok(true),
                    Err(error) => return Err(error.into()),
                };
                self.pending_native = Some(PendingNative {
                    call: None,
                    ack: None,
                    transmit,
                    kind: NativeKind::Effect(id),
                    attempted: false,
                    exposed: false,
                    known_written: false,
                    closing: true,
                    bound,
                });
                self.session
                    .core_mut()
                    .ok_or(Fault::NotReady)?
                    .admit_effect(id)?;
            }
            Action::CloseClient => {
                self.io.retire();
                self.report.physical_closed = true;
                self.session
                    .core_mut()
                    .ok_or(Fault::NotReady)?
                    .admit_effect(id)?;
                self.settle(id, Completion::Written)?;
                return Err(Fault::Cancelled.into());
            }
        }
        self.mark();
        self.account()?;
        Ok(true)
    }
}
