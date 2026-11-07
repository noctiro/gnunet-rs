use super::{Action, Completion, Error, Fault, LineReport, NativeKind, State, cadet};
impl<'s, 'p, 'c, 'slots> State<'s, 'p, 'c, 'slots> {
    fn cleanup_error(&mut self, error: Error) {
        self.report.cleanup.get_or_insert(error);
    }
    pub(super) fn finish(&mut self, error: Option<Error>) -> LineReport {
        if self.closed {
            return std::mem::take(&mut self.report);
        }
        let owner_cancel = self.control.reason() == Some(Fault::Cancelled) || self.client_lost;
        let reason = error.as_ref().map_or(Fault::Cancelled, Error::classified);
        if let Some(error) = error {
            self.report.primary.get_or_insert(error);
        }
        self.control.cancel(reason);
        // No clock/provider/wire IO occurs after this point. Physical original
        // owners disappear before any metadata effect/Call debt is settled.
        self.io.retire();
        self.report.physical_closed = true;
        let ids = self.pils.close();
        self.report.pils_closed = true;
        let unexpected = ids.iter().flatten().count();
        if unexpected != 0 {
            self.report.undrained = self.report.undrained.saturating_add(unexpected);
            self.cleanup_error(Fault::StaleGeneration.into());
        }
        let closed = self.cadet.close();
        self.report.cadet_closed = true;
        let mut receipt = self.retired.take();
        match closed {
            Ok(actual) => {
                if receipt.is_none() {
                    receipt = actual;
                } else if actual.is_some() {
                    self.cleanup_error(Fault::StaleGeneration.into());
                    self.report.undrained = self.report.undrained.saturating_add(1);
                }
            }
            Err(error) => self.cleanup_error(error.into()),
        }
        // Known Written is a fact from the original actual syscall and must not
        // be rewritten to Lost merely because later policy/cleanup failed.
        if self
            .pending_native
            .as_ref()
            .is_some_and(|p| p.known_written)
        {
            let transmit = self.pending_native.as_ref().map(|p| p.transmit);
            if let Some(transmit) = transmit
                && let Err(error) = self.written(cadet::Written { transmit })
            {
                self.cleanup_error(error);
            }
        }
        if self
            .pending_client
            .as_ref()
            .is_some_and(|p| p.known_written)
        {
            let id = self.pending_client.as_ref().map(|p| p.effect);
            if let Some(id) = id {
                match self.settle(id, Completion::Written) {
                    Ok(()) => self.pending_client = None,
                    Err(error) => self.cleanup_error(error),
                }
            }
        }
        if let Some(core) = self.session.core_mut()
            && owner_cancel
            && let Err(error) = core.client_lost(reason, self.last_now)
        {
            self.cleanup_error(error.into());
        }
        if let Some(source) = self.source
            && let Some(core) = self.session.core_mut()
            && let Err(error) = core.source_lost(source, reason)
        {
            self.cleanup_error(error.into());
        }
        if let Some(core) = self.session.core_mut()
            && !owner_cancel
            && let Err(error) = core.client_lost(reason, self.last_now)
        {
            self.cleanup_error(error.into());
        }
        // Original queued/partial native exposure is matched by its actual
        // Transmit token. Missing/mismatched receipts leave explicit debt.
        if let Some(pending) = self.pending_native.as_ref() {
            let id = match pending.kind {
                NativeKind::Effect(id) => Some(id),
                _ => None,
            };
            if !pending.known_written {
                let actual = receipt
                    .and_then(|r| r.pending)
                    .filter(|p| p.transmit == pending.transmit);
                match (id, actual) {
                    (Some(id), Some(actual)) => {
                        let completion = if !pending.attempted && !actual.exposed {
                            Completion::Unsent(reason)
                        } else {
                            Completion::Lost {
                                reason,
                                exposed: actual.exposed,
                            }
                        };
                        match self.settle(id, completion) {
                            Ok(()) => self.pending_native = None,
                            Err(error) => self.cleanup_error(error),
                        }
                    }
                    (Some(_), None) => self.cleanup_error(Fault::NotReady.into()),
                    (None, _) => self.pending_native = None,
                }
            }
        }
        if let Some(pending) = self.pending_client.as_ref()
            && !pending.known_written
        {
            let id = pending.effect;
            let completion = if pending.attempted {
                Completion::Lost {
                    reason,
                    exposed: pending.written != 0,
                }
            } else {
                Completion::Unsent(reason)
            };
            match self.settle(id, completion) {
                Ok(()) => self.pending_client = None,
                Err(error) => self.cleanup_error(error),
            }
        }
        for call in self.calls.iter_mut().flatten() {
            call.gone = true;
            call.input = None;
        }
        self.rejects.clear();
        self.port = None;
        self.port_hash = None;
        let max = self.session.core().map_or(0, |core| core.pending_effects());
        for _ in 0..max {
            let Some(core) = self.session.core() else {
                break;
            };
            let Some(effect) = core.effect() else {
                break;
            };
            if effect.admitted() {
                break;
            }
            let id = effect.id();
            let close_client = matches!(effect.action(), Action::CloseClient);
            let completion = if close_client {
                if let Err(error) = self
                    .session
                    .core_mut()
                    .ok_or(Fault::NotReady)
                    .and_then(|core| core.admit_effect(id))
                {
                    self.cleanup_error(error.into());
                    break;
                }
                Completion::Written
            } else {
                Completion::Unsent(reason)
            };
            if let Err(error) = self.settle(id, completion) {
                self.cleanup_error(error);
                break;
            }
        }
        for _ in 0..self.calls.len() {
            match self.collect_reports() {
                Ok(true) => {}
                Ok(false) => break,
                Err(error) => {
                    self.cleanup_error(error);
                    break;
                }
            }
        }
        let pending = self.session.core().map_or(0, |c| c.pending_effects());
        let calls = self.calls.iter().flatten().count();
        if pending != 0
            || calls != 0
            || self.pending_native.is_some()
            || self.pending_client.is_some()
            || self.session.core().is_some_and(|c| !c.is_quiescent())
        {
            self.report.undrained = self
                .report
                .undrained
                .saturating_add(pending.saturating_add(calls).max(1));
            self.cleanup_error(Fault::NotReady.into());
        }
        self.closed = true;
        std::mem::take(&mut self.report)
    }
}
impl Drop for State<'_, '_, '_, '_> {
    fn drop(&mut self) {
        if !self.closed {
            let _retired = self.finish(Some(Fault::Cancelled.into()));
        }
    }
}
