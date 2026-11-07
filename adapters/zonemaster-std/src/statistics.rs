//! Reuses the actual admitted STATISTICS owner, same live config/Resolver/clock.
//! Admission is never a processing/storage receipt. Unknown writes are not replayed.
use crate::{
    Failure,
    metrics::{Metrics, NAMES, RELATIVE},
};
use gnunet_client::statistics_handle::{DestroyOutcome, DestroyReport, GetFlow};
use gnunet_client_host::{LiveConfiguration, resolution::SharedResolution};
use gnunet_ipc_unix::handle::{self, StatisticsHandle};
use std::{
    future::Future,
    task::{Context, Poll},
};
use tokio::time::Instant;
type Handle<'a> = StatisticsHandle<'a, 64, 128, 1, 1, 8>;
/// Bounded relative delta publisher. No new client/runtime/Resolver implementation.
pub struct Publisher<'a> {
    handle: Option<Handle<'a>>,
    attempted: [u64; 16],
    cursor: usize,
    initialized: [bool; 16],
    destroying: bool,
    report: Option<DestroyReport>,
}
impl<'a> Publisher<'a> {
    /// Read official statistics.DISABLE once and retain actual live configuration.
    pub fn new(
        instance: &'a mut handle::Instance,
        configuration: LiveConfiguration,
        resolution: SharedResolution,
    ) -> Result<Self, Failure> {
        Ok(Self {
            handle: Handle::from_live_config(
                instance,
                configuration,
                resolution,
                b"zonemaster",
                handle::Limits {
                    max_frame_bytes: 2048,
                    write_chunk_bytes: 2048,
                },
            )?,
            attempted: [0; 16],
            cursor: 0,
            initialized: [false; 16],
            destroying: false,
            report: None,
        })
    }
    /// Admit at most one actual nonpersistent delta per turn. Count an attempted
    /// mutation before calling the shared API: any post-admission failure is
    /// ambiguous, so this source is retired and that delta is never replayed.
    pub fn admit(&mut self, metrics: Metrics) -> Result<bool, Failure> {
        let counts = metrics.values();
        let Some(handle) = &mut self.handle else {
            return Ok(false);
        };
        for offset in 0..16 {
            let i = (self.cursor + offset) % 16;
            if RELATIVE[i] {
                let delta = counts[i].saturating_sub(self.attempted[i]);
                if delta == 0 {
                    continue;
                }
                let chunk = delta.min(i64::MAX as u64);
                self.attempted[i] = self.attempted[i].saturating_add(chunk);
                self.cursor = (i + 1) % 16;
                if let Err(error) = handle.update(NAMES[i], i64::try_from(chunk)?, false) {
                    return Err(self.retire(error.into()));
                }
            } else {
                if self.initialized[i] && self.attempted[i] == counts[i] {
                    continue;
                }
                self.initialized[i] = true;
                self.attempted[i] = counts[i];
                self.cursor = (i + 1) % 16;
                if let Err(error) = handle.set(NAMES[i], counts[i], false) {
                    return Err(self.retire(error.into()));
                }
            }
            return Ok(true);
        }
        Ok(false)
    }
    /// Poll actual IO. A lost source/partial mutation is never re-issued from the
    /// local totals. Existing shared-owner unsent-queue semantics remain intact.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        until: Option<Instant>,
    ) -> Poll<Result<(), Failure>> {
        let report = &mut self.report;
        let result = if let Some(handle) = &mut self.handle {
            if !self.destroying && handle.is_idle() {
                return Poll::Pending;
            }
            let mut driving = std::pin::pin!(handle.drive(until, |event, _context| {
                if let handle::Event::Destroyed(r) = event {
                    *report = Some(r);
                }
                GetFlow::Continue
            }));
            driving.as_mut().poll(cx)
        } else {
            return Poll::Pending;
        };
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(self.retire(error.into()))),
        }
    }
    /// Start actual destroy(sync_first), while the shared Resolver remains live.
    pub fn destroy(&mut self) -> Result<(), Failure> {
        self.destroying = true;
        if let Some(handle) = &mut self.handle
            && let Err(error) = handle.destroy(true)
        {
            return Err(self.retire(error.into()));
        }
        Ok(())
    }
    /// Original statistics owner has actually retired; no durable claim follows.
    pub fn closed(&self) -> bool {
        self.handle.is_none() || self.report.is_some()
    }
    /// Report actual unconfirmed/discarded shutdown facts. A successful local
    /// close is never strengthened into a durable-storage assertion.
    pub fn check_report(&self) -> Result<(), Failure> {
        if let Some(r) = self.report
            && (r.queued_mutations_discarded != 0
                || r.unconfirmed_mutations != 0
                || matches!(
                    r.outcome,
                    DestroyOutcome::Deadline | DestroyOutcome::ConnectionLost
                ))
        {
            return Err(format!("ZONEMASTER STATISTICS original shutdown: {r:?}").into());
        }
        Ok(())
    }
    /// Physically retire unconfirmed original IO after the foreground's finite
    /// independent hard bound. Drop is not a fake processing/flush receipt.
    pub fn abort(&mut self) -> Result<(), Failure> {
        let result = self.handle.take().map(|mut handle| {
            if handle.is_closed() {
                Ok(())
            } else {
                handle.destroy(false)
            }
        });
        result.transpose().map(|_| ()).map_err(Into::into)
    }
    fn retire(&mut self, original: Failure) -> Failure {
        let cleanup = self.abort().err().into_iter().collect();
        Box::new(crate::owner::Failures {
            original: Some(original),
            cleanup,
        })
    }
}
