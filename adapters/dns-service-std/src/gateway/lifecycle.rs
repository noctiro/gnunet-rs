//! Gateway reporting, hard deadlines and original native-owner shutdown.
use super::{Error, Event, Gateway, GatewayReport};
use tokio::time::Instant;

impl<'id> Gateway<'id> {
    #[cfg(any(windows, target_os = "linux"))]
    pub(super) fn suspend_source_work(&mut self) -> Result<(), Error> {
        self.source_suspended = true;
        self.held_input = None;
        let mut first = None;
        for slot in &mut self.maps {
            if let Some(map) = slot.take() {
                if let Err(error) = self.stub.resolve_cancel(map.native) {
                    first.get_or_insert(Error::from(error));
                }
                if let Err(error) = self.server.engine_mut().resolve_stopped(map.job) {
                    first.get_or_insert(Error::from(error));
                }
            }
        }
        for span in self.spans.iter_mut().flatten() {
            span.permit = None;
            if let Err(error) = self.server.engine_mut().abort(span.request) {
                first.get_or_insert(Error::from(error));
            }
        }
        first.map_or(Ok(()), Err)
    }
    /// Actual captured outcomes, not a full-node/cryptographic acceptance claim.
    pub const fn report(&self) -> &GatewayReport {
        &self.report
    }
    /// Close local owners and retain their observations. Drive `Stopped` first
    /// to collect asynchronous source retirement, including helper exit and the
    /// native WFP worker's receipts. Missing source retirement remains unconfirmed.
    pub fn into_report(mut self) -> GatewayReport {
        self.close(None, &mut |_| {});
        std::mem::take(&mut self.report)
    }
    /// Exact live local totals for the six upstream nonpersistent DNS statistics.
    /// The answered label means helper queue admission as in the C producer,
    /// never a TUN write, response delivery or STATISTICS processing receipt.
    pub fn statistics(&self) -> [u64; 6] {
        [
            self.report.outputs_queued,
            self.report.resolver_socket_failures,
            self.report.resolver_discarded,
            self.server.report().client_responses_discarded,
            self.report.non_dns_udp,
            self.report.packets,
        ]
    }
    pub(super) fn cleanup(&mut self, error: Error) {
        self.report.cleanup_count = self.report.cleanup_count.saturating_add(1);
        if self.report.cleanup.is_none() {
            self.report.cleanup = Some(error)
        }
    }
    /// Stop physical admission and retain native owners before logical settlement.
    /// Canonical clock is not sampled, and child wait/firewall cleanup stays owned.
    pub fn close(&mut self, cause: Option<Error>, observe: &mut impl FnMut(Event<'id>)) {
        if self.report.first.is_none() {
            self.report.first = cause;
        }
        if self.closing {
            return;
        }
        self.closing = true;
        if let Some(error) = self.server.close_all(observe) {
            self.cleanup(error)
        }
        self.held_input = None;
        for index in 0..self.packets.pending_capacity() {
            if let Some(pending) = self.packets.pending_at(index) {
                observe(Event::PacketOutputLost {
                    effect: pending.effect,
                    exposure: pending.exposure,
                    total: pending.total,
                });
            }
        }
        self.packets.request_stop();
        if !self.source_done
            && let Some(retirement) = self.packets.take_immediate_retirement()
        {
            self.report.source_retirement = Some(retirement);
            self.source_done = true;
        }
        let _stopped = self.stub.stop();
        if let Some(retirement) = self.stub.take_immediate_retirement() {
            self.report.upstream_retirement = Some(retirement);
            self.upstream_done = true;
        }
        for i in 0..self.maps.len() {
            if let Some(map) = self.maps[i].take()
                && let Err(e) = self.server.engine_mut().resolve_stopped(map.job)
            {
                self.cleanup(e.into())
            }
        }
        for i in 0..self.spans.len() {
            if let Some(request) = self.spans[i].as_ref().map(|span| span.request)
                && let Err(error) = self.server.engine_mut().abort(request)
            {
                self.cleanup(error.into());
            }
        }
        if self.upstream_done && (self.source_done || !self.packets.defers_settlement()) {
            self.settle_source();
        }
        self.report.ipc = self.server.report();
    }
    pub(super) fn settle_source(&mut self) {
        if self.source_settled {
            return;
        }
        self.source_settled = true;
        if self.source_attached {
            if let Err(e) = self.server.engine_mut().source_lost(self.source) {
                self.cleanup(e.into())
            }
            self.source_attached = false;
        }
        for i in 0..self.spans.len() {
            if let Some(span) = self.spans[i].take() {
                if let Err(e) = self.server.engine_mut().abort(span.request) {
                    self.cleanup(e.into());
                }
                if let Err(e) = self.server.engine_mut().retire(span.request) {
                    self.cleanup(e.into())
                }
            }
        }
    }
    pub(super) fn hard_expire(&mut self) -> Result<(), Error> {
        let now = Instant::now();
        for span in self.spans.iter().flatten() {
            if now >= span.hard {
                self.server.engine_mut().abort(span.request)?;
            }
        }
        Ok(())
    }
}
impl Drop for Gateway<'_> {
    fn drop(&mut self) {
        self.close(None, &mut |_| {});
    }
}
