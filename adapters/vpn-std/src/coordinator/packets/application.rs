//! Exact application packet completion and raw-source retirement.
use super::*;
use provider::{CloseOutcome, PacketCompletion, PacketOutcome};

impl<'id, 'store, 'bytes, 'cadet, 'cstore, 'policy>
    Coordinator<'id, 'store, 'bytes, 'cadet, 'cstore, 'policy>
{
    pub(super) fn provider_write_receipt(
        &mut self,
        receipt: PacketCompletion,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<(), Error> {
        let Some(TunOutput {
            write: PacketWrite::Provider { request, bytes },
            effect,
        }) = self.output.as_ref()
        else {
            return Ok(());
        };
        if request.id != receipt.id {
            return Ok(());
        }
        let effect = *effect;
        match receipt.outcome {
            PacketOutcome::Written { bytes: accepted } if accepted == *bytes => {
                self.server.engine_mut().exposed(effect)?;
                self.server.engine_mut().written(effect)?;
                self.report.tun_written = self.report.tun_written.saturating_add(1);
                observe(Event::ProviderWritten {
                    write: receipt.id,
                    effect,
                    bytes: accepted,
                });
            }
            PacketOutcome::Written { bytes: accepted } => {
                if accepted != 0 {
                    self.server.engine_mut().exposed(effect)?;
                }
                self.control
                    .provider_error
                    .get_or_insert(Fault::OutcomeUnknown.into());
                self.request_shutdown();
            }
            PacketOutcome::Unsent { error } => {
                let reason = match error.kind() {
                    io::ErrorKind::TimedOut => Fault::Deadline,
                    io::ErrorKind::Interrupted => Fault::Cancelled,
                    _ => Fault::Io,
                };
                self.server.engine_mut().unsent(effect, reason)?;
                observe(Event::NativeError(error));
            }
            PacketOutcome::Unknown { error, exposed } => {
                if exposed {
                    self.server.engine_mut().exposed(effect)?;
                }
                self.control
                    .provider_error
                    .get_or_insert(Error::Native(error));
                self.request_shutdown();
            }
        }
        self.output = None;
        Ok(())
    }

    pub(super) fn poll_provider_output(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
    ) -> Result<bool, Error> {
        let owner = self.device.io.provider_mut().ok_or(Fault::Conflict)?;
        let expired = self.output.as_ref().and_then(|output| match &output.write {
            PacketWrite::Provider { request, .. } if Instant::now() >= request.deadline => {
                Some(request.id)
            }
            _ => None,
        });
        let outcome = if let Some(id) = expired {
            Poll::Ready(PacketCompletion {
                id,
                outcome: owner.driver.cancel_write(id),
            })
        } else {
            owner.driver.poll_write(cx)
        };
        match outcome {
            Poll::Pending => Ok(false),
            Poll::Ready(receipt) => {
                self.provider_write_receipt(receipt, observe)?;
                Ok(true)
            }
        }
    }

    pub(in crate::coordinator) fn close_application(
        &mut self,
        observe: &mut impl FnMut(Event<'id, 'cadet>),
        failure: &mut Option<Error>,
    ) -> Option<CloseOutcome> {
        if let Some(TunOutput {
            write: PacketWrite::Provider { request, .. },
            ..
        }) = &self.output
        {
            let id = request.id;
            if let Some(owner) = self.device.io.provider_mut() {
                let outcome = owner.driver.cancel_write(id);
                if let Err(error) =
                    self.provider_write_receipt(PacketCompletion { id, outcome }, observe)
                {
                    failure.get_or_insert(error);
                }
            }
        }
        if let Some(error) = self.control.provider_error.take() {
            failure.get_or_insert(error);
        }
        let closed = self.device.io.close_provider()?;
        if let Some(source) = self.source {
            let engine = self.server.engine_mut();
            if let Err(error) = engine.route_lost(source, Fault::OutcomeUnknown) {
                failure.get_or_insert(error.into());
            }
            match engine.tun_lost(source, Fault::Closed) {
                Ok(fact) => observe(Event::TunCoreLost(fact)),
                Err(error) => {
                    failure.get_or_insert(error.into());
                }
            }
            if closed.routes_absent {
                if let Err(error) = engine.confirm_routes_absent(source) {
                    failure.get_or_insert(error.into());
                }
            } else if engine
                .route_state(source)
                .is_ok_and(|state| state != core::RouteState::Absent)
            {
                failure.get_or_insert(Fault::OutcomeUnknown.into());
                observe(Event::CleanupUncertain {
                    reason: Fault::OutcomeUnknown,
                });
            }
        }
        self.control.dead = true;
        self.output = None;
        self.input = None;
        Some(closed)
    }
}
