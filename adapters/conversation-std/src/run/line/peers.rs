use super::{
    Call, Completion, Error, Fault, LocalEvent, NativeKind, Packet, PendingNative, Reject, Source,
    State, cadet,
};
use gnunet_conversation::Session;
use std::task::{Context, Poll};
impl<'s, 'p, 'c, 'slots> State<'s, 'p, 'c, 'slots> {
    pub(super) fn reject_call(&mut self, index: usize, reason: Fault) -> Result<bool, Error> {
        let call = self
            .calls
            .get_mut(index)
            .and_then(Option::as_mut)
            .ok_or(Fault::StaleGeneration)?;
        if call.gone || call.retiring.is_some() {
            return Ok(false);
        }
        let channel = call.channel.ok_or(Fault::NotReady)?;
        call.retiring = Some(reason);
        if self
            .pending_native
            .as_ref()
            .is_some_and(|p| p.call == Some(call.id) && !p.closing)
        {
            return Err(reason.into());
        }
        if self.rejects.len() > self.limits.core.calls {
            return Err(Fault::Capacity.into());
        }
        self.rejects.push(Reject {
            channel,
            reason,
            bound: self.origin.after(std::time::Duration::from_micros(
                self.limits.core.close_timeout,
            ))?,
            queued: false,
        });
        self.mark();
        Ok(true)
    }
    fn reject_unbound(
        &mut self,
        channel: cadet::Channel<'c>,
        reason: Fault,
    ) -> Result<bool, Error> {
        if self.rejects.iter().any(|r| r.channel == channel) {
            return Ok(false);
        }
        if self.rejects.len() > self.limits.core.calls {
            return Err(Fault::Capacity.into());
        }
        self.rejects.push(Reject {
            channel,
            reason,
            bound: self.origin.after(std::time::Duration::from_micros(
                self.limits.core.close_timeout,
            ))?,
            queued: false,
        });
        self.mark();
        Ok(true)
    }
    pub(super) fn gone(&mut self, channel: cadet::Channel<'c>, reason: Fault) -> Result<(), Error> {
        if let Some(index) = self
            .calls
            .iter()
            .position(|row| row.as_ref().is_some_and(|c| c.channel == Some(channel)))
        {
            let call = self.calls[index].as_mut().ok_or(Fault::Stale)?;
            if !call.gone {
                let source = call.source.ok_or(Fault::NotReady)?;
                call.gone = true;
                call.input = None;
                self.session
                    .core_mut()
                    .ok_or(Fault::NotReady)?
                    .peer_lost(call.id, source, reason)?;
            }
        }
        if let Some(index) = self.rejects.iter().position(|r| r.channel == channel) {
            self.rejects.swap_remove(index);
        }
        self.mark();
        Ok(())
    }
    fn incoming(
        &mut self,
        channel: cadet::Channel<'c>,
        port: cadet::Port<'c>,
    ) -> Result<bool, Error> {
        if self.port != Some(port) || !self.cadet.port_announced(port)? {
            return self.reject_unbound(channel, Fault::Closed);
        }
        let info = self.cadet.channel_info(channel)?;
        if self.port_hash != Some(info.port) {
            return Err(Fault::Authentication.into());
        }
        let Some(index) = self.calls.iter().position(Option::is_none) else {
            return self.reject_unbound(channel, Fault::Capacity);
        };
        let lease = match self.registry.call() {
            Ok(lease) => lease,
            Err(Error::Protocol(Fault::Capacity)) => {
                return self.reject_unbound(channel, Fault::Capacity);
            }
            Err(error) => return Err(error),
        };
        let now = self.now()?;
        let current = self.selected()?;
        let source = self.source.ok_or(Fault::NotReady)?;
        let id = match self
            .session
            .core_mut()
            .ok_or(Fault::NotReady)?
            .incoming(&current, source, source, info.peer, now)
        {
            Ok(id) => id,
            Err(Fault::Capacity | Fault::WouldBlock | Fault::NotReady | Fault::Closed) => {
                return self.reject_unbound(channel, Fault::Capacity);
            }
            Err(error) => return Err(error.into()),
        };
        self.calls[index] = Some(Call {
            id,
            channel: Some(channel),
            source: Some(source),
            gone: false,
            retiring: None,
            input: None,
            _lease: lease,
        });
        self.report.calls_started = self.report.calls_started.saturating_add(1);
        self.mark();
        Ok(true)
    }
    fn data(&mut self, received: cadet::Received<'c>, bound: super::Bounds) -> Result<bool, Error> {
        let channel = received.channel();
        if self.rejects.iter().any(|r| r.channel == channel) {
            return Ok(true);
        }
        let index = self
            .calls
            .iter()
            .position(|row| row.as_ref().is_some_and(|c| c.channel == Some(channel)))
            .ok_or(Fault::StaleGeneration)?;
        let call = self.calls[index].as_mut().ok_or(Fault::Stale)?;
        if call.gone || call.retiring.is_some() {
            return Ok(true);
        }
        if call.input.is_some() {
            return Err(Fault::Replay.into());
        }
        if received.messages().is_empty() {
            return self.reject_call(index, Fault::Malformed);
        }
        call.input = Some(Packet {
            received,
            validation: 0,
            validated: false,
            offset: 0,
            waiting: None,
            bound,
        });
        self.mark();
        self.account()?;
        Ok(true)
    }
    pub(super) fn written(&mut self, written: cadet::Written<'c>) -> Result<bool, Error> {
        let Some(pending) = self.pending_native.as_mut() else {
            return Err(Fault::StaleGeneration.into());
        };
        if pending.transmit != written.transmit {
            return Err(Fault::StaleGeneration.into());
        }
        pending.known_written = true;
        if let Some((call, delivery)) = pending.ack {
            let entry = self
                .calls
                .iter()
                .flatten()
                .find(|c| c.id == call)
                .ok_or(Fault::StaleGeneration)?;
            let input = entry.input.as_ref().ok_or(Fault::StaleGeneration)?;
            if input.waiting != Some(delivery)
                || input.offset != input.received.messages().len()
                || entry.channel != Some(input.received.channel())
            {
                return Err(Fault::StaleGeneration.into());
            }
        }
        match pending.kind {
            NativeKind::Effect(id) => {
                let completed = self
                    .session
                    .core_mut()
                    .ok_or(Fault::NotReady)?
                    .complete_effect(id, Completion::Written, self.last_now)?;
                match completed.action {
                    gnunet_conversation::Action::PeerFrame { .. } => {
                        self.report.peer_frames_written =
                            self.report.peer_frames_written.saturating_add(1);
                    }
                    gnunet_conversation::Action::CloseChannel { call } => {
                        if let Some(entry) = self.calls.iter_mut().flatten().find(|c| c.id == call)
                        {
                            entry.gone = true;
                            entry.input = None;
                        }
                    }
                    gnunet_conversation::Action::ClosePort { .. } => {
                        self.port = None;
                        self.port_hash = None;
                    }
                    gnunet_conversation::Action::ReceiveDone { call, delivery } => {
                        let entry = self
                            .calls
                            .iter_mut()
                            .flatten()
                            .find(|c| c.id == call)
                            .ok_or(Fault::StaleGeneration)?;
                        let input = entry.input.as_ref().ok_or(Fault::StaleGeneration)?;
                        if input.waiting != Some(delivery)
                            || input.offset != input.received.messages().len()
                        {
                            return Err(Fault::StaleGeneration.into());
                        }
                        entry.input = None;
                    }
                    _ => {}
                }
                self.report.effects_written = self.report.effects_written.saturating_add(1);
            }
            NativeKind::Reject(channel) => {
                let reason = self
                    .rejects
                    .iter()
                    .find(|r| r.channel == channel)
                    .map_or(Fault::Closed, |r| r.reason);
                self.gone(channel, reason)?;
            }
            NativeKind::Internal => {}
        }
        self.pending_native = None;
        self.mark();
        Ok(true)
    }
    pub(super) fn poll_cadet(&mut self, cx: &mut Context<'_>) -> Result<bool, Error> {
        self.native_gate()?;
        // Reserve one diagnostic slot before consuming an event which can
        // retire a channel. CallClosed has its own later preflight and remains
        // ordered after this original channel observation.
        if !self.events.room()? {
            return Ok(false);
        }
        let held_input = self.calls.iter().flatten().any(|call| call.input.is_some());
        let entry = self.origin.now()?;
        let input_bound = self.origin.at(entry
            .checked_add(
                u64::try_from(self.limits.peer_input.as_micros()).map_err(|_| Fault::Overflow)?,
            )
            .ok_or(Fault::Overflow)?)?;
        let internal_bound = self.origin.at(entry
            .checked_add(self.limits.core.write_timeout)
            .ok_or(Fault::Overflow)?)?;
        let pending_id = self.pending_native.as_ref().and_then(|p| match p.kind {
            NativeKind::Effect(id) => Some((id, p.call, p.closing)),
            _ => None,
        });
        if let Some(p) = self.pending_native.as_mut() {
            p.attempted = true;
        }
        let control = &self.control;
        let clock = &self.sources.clock;
        let pils = &self.pils;
        let expected = self.session.observed();
        let core = self.session.core();
        let identity = core.map(Session::identity);
        let calls = &self.calls;
        let origin = self.origin;
        let mut guard = || -> Result<(), cadet::Error> {
            control.check(clock.as_ref(), true)?;
            super::identity::current(pils, expected)?;
            if let Some((id, call, closing)) = pending_id {
                let current = identity.ok_or(Fault::NotReady)?;
                if !core
                    .ok_or(Fault::NotReady)?
                    .effect_io_allowed(id, &current, origin.now()?)?
                {
                    return Err(Fault::Cancelled.into());
                }
                if !closing
                    && call.is_some_and(|id| {
                        calls
                            .iter()
                            .flatten()
                            .any(|c| c.id == id && (c.gone || c.retiring.is_some()))
                    })
                {
                    return Err(Fault::Cancelled.into());
                }
            }
            Ok(())
        };
        let wait = self.earliest()?.map(|b| b.hard.into());
        // The current Packet owns the original DATA and its input credit.
        // Drain only existing output until its final real ACK is Written;
        // dispatching a later Destroyed must not erase these received bytes.
        let event = match if held_input {
            self.cadet.poll_output_guarded(cx, wait, &mut guard)
        } else {
            self.cadet.poll_guarded(cx, wait, &mut guard)
        } {
            Poll::Pending => return Ok(false),
            Poll::Ready(event) => event?,
        };
        if matches!(
            &event,
            cadet::Step::Incoming { .. }
                | cadet::Step::Destroyed(_)
                | cadet::Step::Credit { .. }
                | cadet::Step::Data(_)
                | cadet::Step::RejectedIncoming { .. }
                | cadet::Step::Ignored { .. }
        ) && let Some(original) = self.cadet_input
        {
            original.check(self.sources.clock.as_ref())?;
        }
        match event {
            cadet::Step::Connected(epoch) => {
                if self.source.is_some() {
                    return Err(Fault::StaleGeneration.into());
                }
                self.source = Some(Source::new(epoch.value())?);
                self.startup = None;
                self.mark();
                Ok(true)
            }
            cadet::Step::Written(written) => self.written(written),
            cadet::Step::Incoming { channel, port } => {
                self.cadet_input = None;
                self.incoming(channel, port)
            }
            cadet::Step::Destroyed(channel) => {
                self.cadet_input = None;
                let diagnostic = self
                    .calls
                    .iter()
                    .flatten()
                    .find(|call| call.channel == Some(channel) && !call.gone)
                    .map(|call| {
                        Ok::<_, Error>(LocalEvent::ChannelDestroyed {
                            call: call.id.value(),
                            cid: self.session.core().ok_or(Fault::NotReady)?.cid(call.id)?,
                            channel: channel.value(),
                            epoch: channel.epoch().value(),
                            mq_current: self.cadet.epoch() == Some(channel.epoch())
                                && self.source.is_some_and(|source| {
                                    source.value() == channel.epoch().value()
                                })
                                && self.retired.is_none(),
                        })
                    })
                    .transpose()?;
                self.gone(channel, Fault::Closed)?;
                if let Some(diagnostic) = diagnostic {
                    self.events.emit(diagnostic)?;
                }
                if !self.pending_allowed()? {
                    return Err(Fault::Cancelled.into());
                }
                Ok(true)
            }
            cadet::Step::Credit { .. } => {
                self.cadet_input = None;
                self.mark();
                Ok(true)
            }
            cadet::Step::Data(received) => {
                self.cadet_input = None;
                self.data(received, input_bound)
            }
            cadet::Step::RejectedIncoming { transmit, .. } => {
                self.cadet_input = None;
                if self.pending_native.is_some() {
                    return Err(Fault::Conflict.into());
                }
                self.pending_native = Some(PendingNative {
                    call: None,
                    ack: None,
                    transmit,
                    kind: NativeKind::Internal,
                    attempted: false,
                    exposed: false,
                    known_written: false,
                    closing: true,
                    bound: internal_bound,
                });
                self.mark();
                Ok(true)
            }
            cadet::Step::Ignored { .. } => {
                self.cadet_input = None;
                Ok(true)
            }
            cadet::Step::Blocked {
                reason,
                input_retained,
                ..
            } => {
                if !matches!(reason, Fault::Capacity | Fault::WouldBlock) {
                    return Err(reason.into());
                }
                if input_retained && self.cadet_input.is_none() {
                    self.cadet_input = Some(input_bound);
                }
                Ok(false)
            }
            cadet::Step::Lost { report, cause, .. } => {
                self.retired = Some(report);
                Err(Error::Cadet(cause))
            }
            cadet::Step::ConnectRetry { error, .. } => {
                self.report.first_cadet_retry.get_or_insert(error);
                Ok(true)
            }
            cadet::Step::Unavailable(error) => Err(error.into()),
            cadet::Step::Activity {
                source,
                read_bytes,
                written_bytes,
            } => {
                if self.cadet.epoch() != Some(source) {
                    return Err(Fault::StaleGeneration.into());
                }
                if read_bytes > 0 && self.cadet_input.is_none() {
                    self.cadet_input = Some(input_bound);
                }
                if written_bytes > 0 {
                    let pending = self.pending_native.as_mut().ok_or(Fault::StaleGeneration)?;
                    if pending.transmit.epoch() != source {
                        return Err(Fault::StaleGeneration.into());
                    }
                    pending.exposed = true;
                }
                Ok(read_bytes > 0 || written_bytes > 0)
            }
            cadet::Step::WaitDeadline => {
                self.refresh()?;
                self.control.check(self.sources.clock.as_ref(), true)?;
                Ok(false)
            }
            cadet::Step::Closed => Err(Fault::Closed.into()),
        }
    }
}
