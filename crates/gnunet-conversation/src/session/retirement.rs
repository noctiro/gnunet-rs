//! Call failure, local termination notices and original retirement obligations.
use super::{
    Action, CallId, CallReport, ClientControl, EffectId, EndReason, Error, Message, Phase, Session,
    Source,
};

impl<'id> Session<'id> {
    /// Revoke one call and queue its actual channel retirement. Native effects
    /// retain their original debt; no physical disappearance is fabricated.
    pub fn reject_call(&mut self, id: CallId<'id>, reason: Error, now: u64) -> Result<(), Error> {
        self.begin_close(id, EndReason::Failed(reason), now, None)?;
        self.last_now = self.last_now.max(now);
        Ok(())
    }
    pub(super) fn begin_close(
        &mut self,
        id: CallId<'id>,
        reason: EndReason,
        now: u64,
        keep: Option<EffectId<'id>>,
    ) -> Result<(), Error> {
        let notify = !self.client_closing;
        let c = self.call_mut(id)?;
        c.reason.get_or_insert(reason);
        if let EndReason::Failed(error) = reason {
            c.failure.get_or_insert(error);
        }
        if c.close_queued {
            return Ok(());
        }
        // The local caller must leave its active call state even when closure
        // starts from a timeout/write failure rather than a peer callback.
        // Unauthenticated incoming channels have never announced a local CID.
        c.notify_hangup |= notify
            && matches!(reason, EndReason::Failed(_))
            && !matches!(c.phase, Phase::AwaitRing | Phase::Closing | Phase::Closed);
        let hard = match Self::deadline(now, self.limits.close_timeout) {
            Ok(hard) => hard,
            Err(error) => {
                self.failure.get_or_insert(error);
                now
            }
        };
        let c = self.call_mut(id)?;
        c.close_deadline = Some(hard);
        c.phase = if c.gone {
            Phase::Closed
        } else {
            Phase::Closing
        };
        if !self.client_closing {
            self.suppress(id, keep);
        }
        self.push_close(Action::CloseChannel { call: id }, hard)?;
        self.call_mut(id)?.close_queued = true;
        Ok(())
    }
    /// Record actual original Channel disappearance. EOF is retained as its
    /// original error; it never becomes a remote pickup or peer HangUp741.
    /// No allocation or clock provider is needed to retain this terminal fact.
    pub fn peer_lost(
        &mut self,
        id: CallId<'id>,
        source: Source,
        reason: Error,
    ) -> Result<(), Error> {
        self.lose_peer(id, source, reason, None)
    }
    fn lose_peer(
        &mut self,
        id: CallId<'id>,
        source: Source,
        reason: Error,
        keep: Option<EffectId<'id>>,
    ) -> Result<(), Error> {
        let now = self.last_now;
        let c = self.call_mut(id)?;
        if c.source != Some(source) {
            return Err(Error::StaleGeneration);
        }
        if c.gone {
            return Err(Error::Replay);
        }
        c.gone = true;
        c.channel_ready = false;
        self.begin_close(id, EndReason::Failed(reason), now, keep)?;
        // Physical disappearance revokes even a previously retained HangUp
        // intent from an already-closing call. Original admitted debt remains.
        self.suppress(id, keep);
        Ok(())
    }
    /// Terminal source loss closes the Line when its listening port is lost.
    /// Use `transport_lost` to retain a recoverable listening intent.
    pub fn source_lost(&mut self, source: Source, reason: Error) -> Result<(), Error> {
        let port_lost = self.port_source == Some(source);
        if port_lost {
            self.failure.get_or_insert(reason);
        }
        self.transport_lost(source, reason, None)?;
        if port_lost {
            self.cancel(reason, self.last_now)?;
        }
        Ok(())
    }
    /// Observe a physically retired CADET MQ while preserving the local Line
    /// and its logical listening intent. Old calls end; no peer frame is replayed.
    /// An already admitted local frame may finish on its original client MQ.
    pub fn transport_lost(
        &mut self,
        source: Source,
        reason: Error,
        keep_client: Option<EffectId<'id>>,
    ) -> Result<(), Error> {
        if let Some(id) = keep_client {
            let effect = self
                .effects
                .get(self.effect_index(id)?)
                .ok_or(Error::StaleGeneration)?;
            if !effect.admitted
                || effect.cancelled
                || !matches!(effect.action, Action::ClientFrame { .. })
            {
                return Err(Error::InvalidInput);
            }
        }
        let port_lost = self.port_source == Some(source);
        if port_lost {
            self.port_ready = false;
            self.port_gone = true;
        }
        for index in 0..self.calls.len() {
            let id = self.calls[index]
                .as_ref()
                .filter(|c| c.source == Some(source) && !c.gone)
                .map(|c| c.id);
            if let Some(id) = id {
                self.lose_peer(id, source, reason, keep_client)?;
            }
        }
        Ok(())
    }
    /// The trusted native owner observed the same logical port's whole
    /// announcement on a replacement MQ. This restores no original call.
    pub fn restore_port(&mut self, previous: Source, replacement: Source) -> Result<(), Error> {
        if self.mode != super::Mode::Listener
            || self.port.is_none()
            || self.port_source != Some(previous)
            || !self.port_gone
            || self.port_closing
            || self.client_closing
            || previous == replacement
            || self
                .effects
                .iter()
                .any(|e| matches!(e.action, Action::OpenPort { .. }))
        {
            return Err(Error::NotReady);
        }
        self.port_source = Some(replacement);
        self.port_gone = false;
        self.port_ready = true;
        Ok(())
    }
    /// Record that this actual local IPC is already physically gone before
    /// cancelling remaining original native channels and effects.
    pub fn client_lost(&mut self, reason: Error, now: u64) -> Result<(), Error> {
        self.client_closed = true;
        self.failure.get_or_insert(reason);
        self.cancel(reason, now)
    }
    /// Cancel this original Line. Physical retirement must happen first in the
    /// host; pending/admitted effects and their real outcomes remain retained.
    /// Queue space for every original close was reserved at construction.
    pub fn cancel(&mut self, reason: Error, now: u64) -> Result<(), Error> {
        if self.client_closing {
            return Ok(());
        }
        self.client_closing = true;
        self.port_ready = false;
        for e in &mut self.effects {
            if !e.action.close() {
                e.cancelled = true;
            }
        }
        for index in 0..self.calls.len() {
            let id = self.calls[index].as_ref().map(|c| c.id);
            if let Some(id) = id {
                self.call_mut(id)?.notify_hangup = false;
                self.begin_close(id, EndReason::Cancelled(reason), now, None)?;
            }
        }
        let deadline = Self::deadline(now, self.limits.close_timeout).unwrap_or(now);
        if let Some(port) = self.port
            && !self.port_closing
        {
            self.push_close(Action::ClosePort { port }, deadline)?;
            self.port_closing = true;
        }
        self.push_close(Action::CloseClient, deadline)?;
        self.last_now = self.last_now.max(now);
        Ok(())
    }
    /// Observe known identity source loss and fence all subsequent normal I/O.
    /// The native owner physically retires the old MQs before settling debts.
    pub fn identity_lost(&mut self, reason: Error, now: u64) -> Result<(), Error> {
        self.failure.get_or_insert(reason);
        self.cancel(reason, now)
    }
    /// Advance at most one deferred local HangUp notification. This allocation
    /// is separate from retaining the original source-loss fact. Resource
    /// pressure parks the notice without failing the Line or erasing the cause.
    /// A local failure notification never claims a peer HangUp was received.
    pub fn progress(&mut self, now: u64) -> Result<bool, Error> {
        let pending = self
            .calls
            .iter()
            .flatten()
            .find(|c| c.notify_hangup)
            .map(|c| (c.id, c.cid, c.close_deadline));
        let Some((id, cid, until)) = pending else {
            return Ok(false);
        };
        if self.client_closing {
            self.call_mut(id)?.notify_hangup = false;
            return Ok(true);
        }
        let until = until.ok_or(Error::NotReady)?;
        if now >= until {
            // A mandatory local terminal notice cannot acquire a fresh write
            // allowance after the original call's retirement bound. Closing
            // the shared IPC gives the caller its actual EOF instead.
            self.failure.get_or_insert(Error::Deadline);
            self.cancel(Error::Deadline, now)?;
            return Ok(true);
        }
        let deadline = Self::deadline(now, self.limits.write_timeout.min(until - now))?;
        let queued = (|| {
            let frame = self.client_frame(
                id,
                Message::Control {
                    action: ClientControl::HangUp,
                    cid,
                },
            )?;
            self.batch_until([Some(frame), None, None], now, deadline)
        })();
        match queued {
            Err(Error::WouldBlock) => return Ok(false),
            result => result?,
        }
        self.call_mut(id)?.notify_hangup = false;
        Ok(true)
    }
    /// Expire original setup/output intents without refreshing any hard bound.
    /// Connected calls have no invented protocol duration; the native parent's
    /// original lifetime/cancel guard remains authoritative for ongoing calls.
    pub fn tick(&mut self, now: u64) -> Result<(), Error> {
        self.last_now = self.last_now.max(now);
        for index in 0..self.calls.len() {
            let id = self.calls[index]
                .as_ref()
                .filter(|c| {
                    matches!(
                        c.phase,
                        Phase::Opening | Phase::AwaitRing | Phase::Ringing | Phase::Calling
                    ) && now >= c.setup_deadline
                })
                .map(|c| c.id);
            if let Some(id) = id {
                self.begin_close(id, EndReason::Failed(Error::Timeout), now, None)?;
            }
        }
        let expired = self.effects.iter().position(|effect| {
            !effect.action.close()
                && !effect.cancelled
                && now >= effect.deadline
                && (!effect.unadmitted_audio() || self.eligible(effect))
        });
        if let Some(at) = expired {
            if self.effects[at].unadmitted_audio() {
                // Its predecessors have settled and no native owner exists.
                drop(self.remove_effect(at)?);
            } else if let Some(id) = self.effects[at].action.call() {
                self.begin_close(id, EndReason::Failed(Error::Deadline), now, None)?;
            }
        }
        Ok(())
    }
    /// Earliest original retained intent deadline. Native cleanup may continue
    /// after it only to retire physical resources and report undrained debt.
    pub fn next_deadline(&self) -> Option<u64> {
        self.effects
            .iter()
            .filter(|effect| !effect.unadmitted_audio() || self.eligible(effect))
            .map(|e| e.deadline)
            .chain(self.calls.iter().flatten().filter_map(|c| {
                if c.notify_hangup {
                    return c.close_deadline;
                }
                match c.phase {
                    Phase::Opening | Phase::AwaitRing | Phase::Ringing | Phase::Calling => {
                        Some(c.setup_deadline)
                    }
                    Phase::Closing => c.close_deadline,
                    _ => None,
                }
            }))
            .min()
    }
    /// Remove a fully retired original owner after all original outcomes and
    /// required local notifications have been observed. No CID is ever reused.
    pub fn take_report(&mut self, id: CallId<'id>) -> Result<Option<CallReport<'id>>, Error> {
        let c = self.call(id)?;
        if !c.gone || c.debt != 0 || c.notify_hangup {
            return Ok(None);
        }
        let report = CallReport {
            call: id,
            cid: c.cid,
            peer: c.peer,
            reason: c.reason.ok_or(Error::NotReady)?,
            failure: c.failure,
            ring_written: c.ring_written,
            remote_pickup: c.remote_pickup,
            local_pickup_written: c.local_pickup_written,
            remote_hangup: c.remote_hangup,
            local_hangup_written: c.local_hangup_written,
        };
        let slot = id.slot;
        self.calls[slot] = None;
        Ok(Some(report))
    }
}

#[cfg(test)]
mod tests;
