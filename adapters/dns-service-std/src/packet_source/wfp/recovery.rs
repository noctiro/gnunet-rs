//! Physical old-file discharge before a fresh native capture generation.
use super::{
    SourceEvent, Wfp,
    connect::{self, Connector},
    report,
};
use gnunet_wfp_dns_host::device;
use std::{
    io,
    task::{Context, Poll},
};
use tokio::time::Instant;

pub(super) struct Recovery {
    announced: bool,
    pub(super) reason: device::Error,
    pub(super) connector: Option<Connector>,
}

pub(super) fn source_unavailable(error: &io::Error) -> Option<device::Error> {
    error
        .get_ref()?
        .downcast_ref::<device::Error>()
        .copied()
        .filter(|reason| reason.is_policy_loss() || reason.is_write_not_ready())
}

impl<'id> Wfp<'id> {
    pub(super) fn begin_recovery(&mut self, reason: device::Error) {
        if self.recovery.is_some() || self.closing {
            return;
        }
        self.ready = false;
        self.owner.close();
        self.record_error(reason);
        self.retire_file();
        self.recovery = Some(Recovery {
            announced: false,
            reason,
            connector: None,
        });
    }

    pub(super) fn poll_recovery(&mut self, cx: &mut Context<'_>) -> Poll<SourceEvent<'id>> {
        let Some(recovery) = &mut self.recovery else {
            return Poll::Pending;
        };
        if !recovery.announced {
            recovery.announced = true;
            return Poll::Ready(SourceEvent::Suspended(report::device_error(
                recovery.reason,
            )));
        }
        if let Some(connector) = &mut recovery.connector {
            let Some(reservations) = &self.reservations else {
                return Poll::Ready(SourceEvent::Failed(io::ErrorKind::NotConnected.into()));
            };
            let started = match connector.poll(cx, reservations) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(SourceEvent::Failed(error)),
                Poll::Ready(Ok(started)) => started,
            };
            let until = connector.deadline();
            self.retirement_until = None;
            self.report = Some(super::WfpRetirement::default());
            let wait = self.verify_started(&started).and_then(|()| {
                let wait = started.event_wait();
                if wait.is_err()
                    && let Some(report) = &mut self.report
                {
                    report.wait_failed = true;
                }
                wait
            });
            // Failed adoption still owns this original file. Shutdown sends
            // it to the same retirement worker.
            self.started = Some(started);
            let wait = match wait {
                Ok(wait) => wait,
                Err(error) => return Poll::Ready(SourceEvent::Failed(error)),
            };
            if let Err(error) = connect::check_deadline(until) {
                return Poll::Ready(SourceEvent::Failed(error));
            }
            self.wait = Some(wait);
            self.owner = std::sync::Arc::new(super::Owner::new());
            self.recovery = None;
            self.ready = true;
            return Poll::Ready(SourceEvent::Attached);
        }

        match self.poll_retired_file(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(Some(event))) => return Poll::Ready(event),
            Poll::Ready(Ok(None)) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(SourceEvent::Failed(error)),
        }
        let pending = self.pending();
        let Some(until) = Instant::now().checked_add(self.limits.open_timeout) else {
            return Poll::Ready(SourceEvent::Failed(io::ErrorKind::InvalidInput.into()));
        };
        self.release_packet_owners();
        if let Some(recovery) = &mut self.recovery {
            recovery.connector = Some(Connector::new(until));
        }
        Poll::Ready(SourceEvent::Detached {
            retirement: super::Retirement::Wfp(self.report.unwrap_or_default()),
            pending,
        })
    }
}
