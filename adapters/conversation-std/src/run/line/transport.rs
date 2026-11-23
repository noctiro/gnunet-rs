//! Physical CADET loss ends calls while the original local Line stays owned.
use super::{
    Bounds, Completion, Error, Fault, NativeKind, PendingNative, ReceiveOwner, Source, State, cadet,
};
use std::io;

pub(super) struct Recovery {
    pub previous: Source,
    pub bound: Bounds,
}

fn recoverable(cause: &cadet::LossCause) -> bool {
    match cause {
        cadet::LossCause::Eof => true,
        cadet::LossCause::Io(error) => {
            gnunet_client_host::resolution::PortError::from_io(error).is_none()
                && matches!(
                    error.kind(),
                    io::ErrorKind::BrokenPipe
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::NotConnected
                        | io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::NetworkDown
                        | io::ErrorKind::NetworkUnreachable
                        | io::ErrorKind::HostUnreachable
                )
        }
        cadet::LossCause::Protocol(_) | cadet::LossCause::Requested => false,
    }
}

impl<'s, 'p, 'c, 'slots> State<'s, 'p, 'c, 'slots> {
    pub(super) fn cadet_receive_deadline(&self) -> Option<(ReceiveOwner, Bounds)> {
        // The CADET poller holds at most one DATA packet while it advances output.
        if let Some(bound) = self.cadet_input {
            return Some((ReceiveOwner::Stream, bound));
        }
        self.calls.iter().enumerate().find_map(|(index, entry)| {
            let call = entry.as_ref()?;
            if call.gone || call.retiring.is_some() {
                return None;
            }
            let packet = call.input.as_ref()?;
            let bound = self
                .pending_native
                .as_ref()
                .filter(|pending| pending.ack.is_some_and(|(id, _)| id == call.id))
                .map_or(packet.bound, |pending| pending.bound);
            Some((ReceiveOwner::Call(index), bound))
        })
    }

    pub(super) fn expire_cadet_input(&mut self) -> Result<bool, Error> {
        let Some((owner, bound)) = self.cadet_receive_deadline() else {
            return Ok(false);
        };
        match bound.check(self.sources.clock.as_ref()) {
            Ok(()) => Ok(false),
            Err(Fault::Deadline) => self.expire_cadet_receive_owner(owner),
            Err(reason) => Err(reason.into()),
        }
    }

    pub(super) fn expire_cadet_receive_owner(
        &mut self,
        owner: ReceiveOwner,
    ) -> Result<bool, Error> {
        let ReceiveOwner::Call(index) = owner else {
            // An incomplete frame cannot be removed from an MQ byte stream.
            return self.retire_cadet_for(Fault::Deadline);
        };
        let call = self.calls[index].as_ref().ok_or(Fault::StaleGeneration)?.id;
        self.reject_call(index, Fault::Deadline)?;
        if let Some(pending) = self.pending_native.as_ref()
            && pending.ack.is_some_and(|(id, _)| id == call)
            && !pending.known_written
        {
            let NativeKind::Effect(id) = pending.kind else {
                return Err(Fault::Conflict.into());
            };
            if !self.cadet.discard_unexposed(pending.transmit)? {
                // Never transfer the suffix of an exposed credit to a new MQ.
                return self.retire_cadet_for(Fault::Deadline);
            }
            self.settle(id, Completion::Unsent(Fault::Deadline))?;
            self.pending_native = None;
        }
        Ok(true)
    }

    pub(super) fn retire_cadet_for(&mut self, reason: Fault) -> Result<bool, Error> {
        let cadet::Step::Lost { report, cause, .. } = self.cadet.reconnect()? else {
            return Err(Fault::StaleGeneration.into());
        };
        self.recover_cadet(report, cause, reason)
    }

    pub(super) fn cadet_lost(
        &mut self,
        report: cadet::Loss<'c>,
        cause: cadet::LossCause,
    ) -> Result<bool, Error> {
        self.retired = Some(report);
        if !recoverable(&cause) {
            return Err(Error::Cadet(cause));
        }
        self.recover_cadet(report, cause, Fault::Closed)
    }
    fn recover_cadet(
        &mut self,
        report: cadet::Loss<'c>,
        cause: cadet::LossCause,
        reason: Fault,
    ) -> Result<bool, Error> {
        self.retired = Some(report);
        let previous = self.source.ok_or(Fault::StaleGeneration)?;
        if previous.value() != report.epoch.value() || self.cadet.epoch().is_some() {
            return Err(Fault::StaleGeneration.into());
        }
        self.report.first_cadet_loss.get_or_insert(cause);
        if self.cadet_recovery.is_none() {
            let mut bound = self.origin.after(self.limits.startup)?;
            if let Some(pending) = &self.pending_native
                && pending.call.is_none()
                && !pending.closing
                && matches!(pending.kind, NativeKind::Effect(_))
            {
                // An initial registration keeps its original remaining budget.
                bound.hard = bound.hard.min(pending.bound.hard);
                bound.canonical = bound.canonical.min(pending.bound.canonical);
            }
            self.cadet_recovery = Some(Recovery { previous, bound });
        }
        if let Some(pending) = &self.pending_native
            && pending.known_written
        {
            self.written(cadet::Written {
                transmit: pending.transmit,
            })?;
        }
        let keep = match &self.pending_client {
            Some(pending)
                if !self
                    .session
                    .core()
                    .ok_or(Fault::NotReady)?
                    .effect_cancelled(pending.effect)? =>
            {
                Some(pending.effect)
            }
            _ => None,
        };
        self.session
            .core_mut()
            .ok_or(Fault::NotReady)?
            .transport_lost(previous, reason, keep)?;
        if let Some(pending) = &self.pending_native {
            let actual = report
                .pending
                .filter(|actual| actual.transmit == pending.transmit)
                .ok_or(Fault::StaleGeneration)?;
            if let NativeKind::Effect(id) = pending.kind {
                let completion = if !pending.attempted && !actual.exposed {
                    Completion::Unsent(reason)
                } else {
                    Completion::Lost {
                        reason,
                        exposed: actual.exposed,
                    }
                };
                self.settle(id, completion)?;
            }
            self.pending_native = None;
        }
        for call in self.calls.iter_mut().flatten() {
            if call.source == Some(previous) {
                call.gone = true;
                call.input = None;
            }
        }
        self.rejects.clear();
        self.cadet_input = None;
        self.source = None;
        self.retired = None;
        self.refresh()?;
        self.mark();
        Ok(true)
    }

    /// Resolve logical cancellation before another syscall uses the old cursor.
    /// Prefixes drain on the same source; only an unsafe drain retires its MQ.
    pub(super) fn reconcile_cancelled(&mut self) -> Result<bool, Error> {
        let mut changed = false;
        if let Some(pending) = &self.pending_client
            && !pending.known_written
            && self
                .session
                .core()
                .ok_or(Fault::NotReady)?
                .effect_cancelled(pending.effect)?
        {
            if pending.written == 0 {
                let id = pending.effect;
                let removed = self
                    .io
                    .remove_unwritten(|origin, _| origin.0 == id.value(), |_, _| {});
                if removed != 1 {
                    return Err(Fault::StaleGeneration.into());
                }
                self.settle(id, Completion::Unsent(Fault::Cancelled))?;
                self.pending_client = None;
                changed = true;
            } else if !self
                .session
                .core()
                .ok_or(Fault::NotReady)?
                .effect_drain_allowed(pending.effect, &self.selected()?, self.origin.now()?)?
            {
                return Err(Fault::Cancelled.into());
            }
        }
        let Some(pending) = &self.pending_native else {
            return Ok(changed);
        };
        let NativeKind::Effect(id) = pending.kind else {
            return Ok(changed);
        };
        if pending.known_written
            || !self
                .session
                .core()
                .ok_or(Fault::NotReady)?
                .effect_cancelled(id)?
        {
            return Ok(changed);
        }
        if !pending.exposed {
            let transmit = pending.transmit;
            if self.cadet.discard_unexposed(transmit)? {
                let removed_call = if transmit.kind() == cadet::TransmitKind::ChannelCreate {
                    pending.call
                } else {
                    None
                };
                self.settle(id, Completion::Unsent(Fault::Cancelled))?;
                if let Some(id) = removed_call {
                    let call = self
                        .calls
                        .iter_mut()
                        .flatten()
                        .find(|call| call.id == id)
                        .ok_or(Fault::StaleGeneration)?;
                    call.gone = true;
                    call.input = None;
                }
                self.pending_native = None;
                return Ok(true);
            }
            // The SDK retained an actual positive-write observation.
            self.pending_native
                .as_mut()
                .ok_or(Fault::StaleGeneration)?
                .exposed = true;
        }
        if self
            .pending_native
            .as_ref()
            .ok_or(Fault::StaleGeneration)?
            .io_allowed(
                self.session.core().ok_or(Fault::NotReady)?,
                &self.calls,
                self.origin.now()?,
            )?
        {
            return Ok(changed);
        }
        self.retire_cadet_for(Fault::Cancelled)
    }

    pub(super) fn track_port_restore(&mut self) {
        if self.pending_native.is_none()
            && let (Some(recovery), Some(_), Some(transmit)) = (
                &self.cadet_recovery,
                self.port,
                self.cadet.pending_transmit(),
            )
        {
            self.pending_native = Some(PendingNative {
                call: None,
                ack: None,
                transmit,
                kind: NativeKind::RestorePort,
                attempted: true,
                exposed: false,
                known_written: false,
                closing: false,
                bound: recovery.bound,
            });
        }
    }

    pub(super) fn port_restored(&mut self, written: cadet::Written<'c>) -> Result<bool, Error> {
        let recovery = self.cadet_recovery.as_ref().ok_or(Fault::StaleGeneration)?;
        let source = self.source.ok_or(Fault::NotReady)?;
        let port = self.port.ok_or(Fault::NotReady)?;
        if self.cadet.epoch() != Some(written.transmit.epoch())
            || source.value() != written.transmit.epoch().value()
            || !self.cadet.port_announced(port)?
        {
            return Err(Fault::StaleGeneration.into());
        }
        recovery.bound.check(self.sources.clock.as_ref())?;
        self.session
            .core_mut()
            .ok_or(Fault::NotReady)?
            .restore_port(recovery.previous, source)?;
        self.pending_native = None;
        self.cadet_recovery = None;
        self.refresh()?;
        self.mark();
        Ok(true)
    }
}
