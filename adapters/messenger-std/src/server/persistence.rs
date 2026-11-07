use super::*;
impl<'c, 'slots, 'p, E: Entropy, const O: usize> Server<'c, 'slots, 'p, E, O> {
    /// Install the original recovered pair before socket polling/admission.
    /// Every failure leaves both original owners in `pending` so the caller can
    /// actually drain/join the same worker and retain its independent failure.
    /// Success alone consumes the pair, after all checks and without allocation.
    pub fn try_install_history(
        &mut self,
        pending: &mut Option<(crate::history::History, crate::history::Restored<'c>)>,
    ) -> Result<(), Error> {
        if self.history.is_some()
            || self.current_peer().is_some()
            || self.cadet.epoch().is_some()
            || self.pils.epoch().is_some()
            || self.apps.iter().any(Option::is_some)
            || self.rooms.iter().any(Option::is_some)
        {
            return Err(Fault::NotReady.into());
        }
        let (history, restored) = pending.as_ref().ok_or(Fault::NotReady)?;
        history.check_restored(restored)?;
        if restored.profile() != self.limits.profile {
            return Err(Fault::InvalidInput.into());
        }
        let (history, restored) = pending.take().ok_or(Fault::NotReady)?;
        self.core = restored.into_core();
        self.history = Some(history);
        Ok(())
    }
    /// Set explicit immutable producer/relay policy before original IO begins.
    pub fn set_layout_policy(&mut self, policy: crate::layout::Policy) -> Result<(), Error> {
        if self.apps.iter().any(Option::is_some)
            || self.tunnels.iter().any(Option::is_some)
            || self.rooms.iter().any(Option::is_some)
        {
            return Err(Fault::NotReady.into());
        }
        self.layouts = policy;
        Ok(())
    }
    /// Current actual history generation, absent only for explicit volatile mode.
    #[must_use]
    pub fn history_generation(&self) -> Option<u64> {
        self.history
            .as_ref()
            .map(crate::history::History::generation)
    }
    /// Actual configured history worker committed the current event cut. This
    /// is independent of live PILS authority and remains meaningful after stop.
    /// Explicit volatile mode supplies no durable receipt and returns false.
    #[must_use]
    pub fn history_committed(&self) -> bool {
        self.history
            .as_ref()
            .is_some_and(crate::history::History::ready)
    }
    /// Live-output gate: the current event cut and applied identity are durable,
    /// or the caller explicitly selected volatile operation. Physical PILS stop
    /// revokes identity readiness without undoing an actual history receipt.
    #[must_use]
    pub fn history_ready(&self) -> bool {
        self.history.as_ref().is_none_or(|history| {
            history.ready() && history.historical_peer() == self.current_peer()
        })
    }
    /// Current authority is supplied by real PILS, not by the restored image.
    /// Force its new cut before fresh output/READY can use that identity.
    pub(super) fn history_identity_changed(&mut self) -> Result<(), Error> {
        if let Some(history) = &mut self.history {
            history.identity_changed()?;
        }
        Ok(())
    }
    pub(super) fn history_frozen(&self) -> bool {
        self.history
            .as_ref()
            .is_some_and(crate::history::History::frozen)
    }
    pub(super) fn history_poll(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event),
    ) -> Poll<Result<Progress, Error>> {
        if let Some(history) = &mut self.history {
            match history.poll(cx, &self.core, false) {
                Poll::Pending => {}
                Poll::Ready(Ok(p)) => {
                    observe(Event::History(p));
                    return Poll::Ready(Ok(Progress::Activity));
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
            }
        }
        Poll::Pending
    }
    /// After physical MQ stop, finish original local semantics for retained actual
    /// signatures, submit the final image, drain real disk outcomes and join the
    /// sole worker. No logical clock is sampled and no fsync deadline is fabricated.
    pub async fn finish_history(
        &mut self,
        observe: &mut impl FnMut(Event),
    ) -> Result<Option<gnunet_snapshot_host::worker::Stopped>, Error> {
        if !self.closed {
            return Err(Fault::NotReady.into());
        }
        let mut first = None;
        // Allocate the bounded enumeration once. Even its failure cannot skip
        // actual original worker shutdown/join below.
        let mut rooms = Vec::new();
        if rooms
            .try_reserve_exact(self.core.retained_rooms().count())
            .is_err()
        {
            first = Some(Error::Protocol(Fault::Capacity));
        } else {
            rooms.extend(self.core.retained_rooms());
            for _ in 0..self.limits.deliveries {
                let mut progress = false;
                for room in &rooms {
                    self.drain_events();
                    match self.core.advance(*room, self.last_now) {
                        Ok(n) => progress |= n > 0,
                        Err(e) => {
                            if first.is_none() {
                                first = Some(Error::Core(e));
                            }
                        }
                    }
                }
                if !progress {
                    break;
                }
            }
        }
        self.drain_events();
        if let Some(history) = &mut self.history {
            if first.is_none()
                && let Err(e) = history
                    .flush(&self.core, &mut |p| observe(Event::History(p)))
                    .await
            {
                first = Some(e.into())
            }
            let stopped = history.shutdown().await;
            match (first, stopped) {
                (Some(original), Err(cleanup)) => Err(Error::HistoryShutdown {
                    original: Box::new(original),
                    cleanup,
                }),
                (Some(e), Ok(_stopped)) => Err(e),
                (None, Ok(stopped)) => Ok(Some(stopped)),
                (None, Err(e)) => Err(e.into()),
            }
        } else {
            first.map_or(Ok(None), Err)
        }
    }
}
