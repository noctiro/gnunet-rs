//! Existing original-MQ STATISTICS owner; no new client, worker or protocol.
use crate::{
    Failure,
    reporting::{Cleanup, Reports},
};
use gnunet_client::statistics_handle::GetFlow;
use gnunet_client_host::{LiveConfiguration, resolution::SharedResolution};
use gnunet_ipc_unix::{IpcError, handle};
use gnunet_topology_host::Statistics;
use std::{
    future::Future,
    task::{Context, Poll},
};
use tokio::time::Instant;

type Owner<'id> = handle::StatisticsHandle<'id, 8, 64, 1, 1, 4>;
const COUNTERS: [&[u8]; 3] = [
    b"# connect requests issued to ATS",
    b"# HELLO messages received",
    b"# HELLO messages gossipped",
];

#[derive(Debug)]
struct Errors {
    original: Option<IpcError>,
    cleanup: Option<IpcError>,
}
impl std::fmt::Display for Errors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TOPOLOGY statistics original={:?} cleanup={:?}",
            self.original, self.cleanup
        )
    }
}
impl std::error::Error for Errors {}

pub(super) struct Forwarder<'id> {
    owner: Option<Owner<'id>>,
    peers: Option<u64>,
    admitted: [u64; 3],
    original_error: Option<IpcError>,
    cleanup_error: Option<IpcError>,
    reports: Reports,
}
impl<'id> Forwarder<'id> {
    pub fn new(
        instance: &'id mut handle::Instance,
        live: LiveConfiguration,
        resolution: SharedResolution,
        reports: Reports,
    ) -> Result<Self, IpcError> {
        let owner = Owner::from_live_config(
            instance,
            live,
            resolution,
            b"topology",
            handle::Limits {
                max_frame_bytes: 256,
                write_chunk_bytes: 256,
            },
        )?;
        Ok(Self {
            owner,
            peers: None,
            admitted: [0; 3],
            original_error: None,
            cleanup_error: None,
            reports,
        })
    }
    fn stop_owner(&mut self) {
        if let Some(mut owner) = self.owner.take()
            && let Err(error) = owner.destroy(false)
        {
            self.cleanup_error = Some(error);
        }
        // Dropping the original handle closes its physical stream even if
        // command cleanup failed. No admitted mutation is retried elsewhere.
    }
    fn fail(&mut self, error: IpcError) {
        self.reports.warning(
            "topology.statistics.failed",
            format_args!("topology statistics stopped: {error}"),
        );
        self.original_error = Some(error);
        self.stop_owner();
    }
    fn admit(&mut self, observed: Statistics) -> Result<(), IpcError> {
        let Some(owner) = self.owner.as_mut() else {
            return Ok(());
        };
        if self.peers != Some(observed.peers_connected) {
            owner.set(b"# peers connected", observed.peers_connected, false)?;
            self.peers = Some(observed.peers_connected);
        }
        let values = [
            observed.connect_requests,
            observed.hellos_received,
            observed.hellos_gossipped,
        ];
        for (i, value) in values.into_iter().enumerate() {
            // Saturated counters never go backwards. A huge delta is split over
            // bounded turns rather than overflowing official signed updates.
            let delta = value.saturating_sub(self.admitted[i]).min(i64::MAX as u64);
            if delta != 0 {
                let signed = i64::try_from(delta).map_err(|_| gnunet_types::Error::Overflow)?;
                owner.update(COUNTERS[i], signed, false)?;
                self.admitted[i] += delta;
            }
        }
        Ok(())
    }
    pub fn refresh(&mut self, observed: Statistics) {
        if let Err(error) = self.admit(observed) {
            // A command can fail after original local admission (for example a
            // clock-port failure). Fence this owner instead of retrying a delta
            // whose original exposure is unknown.
            self.fail(error);
        }
    }
    pub fn poll(&mut self, cx: &mut Context<'_>, wait: Option<Instant>) -> Poll<()> {
        let result = {
            let Some(owner) = self.owner.as_mut() else {
                return Poll::Pending;
            };
            if owner.is_idle() || owner.is_closed() {
                return Poll::Pending;
            }
            let mut driving = std::pin::pin!(owner.drive(wait, |event, _context| {
                self.reports.debug(
                    "topology.statistics.event",
                    format_args!("topology STATISTICS={event:?}"),
                );
                GetFlow::Continue
            }));
            driving.as_mut().poll(cx)
        };
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(_)) => Poll::Ready(()),
            Poll::Ready(Err(error)) => {
                self.fail(error);
                Poll::Ready(())
            }
        }
    }
    pub fn close(&mut self) -> Option<Failure> {
        self.stop_owner();
        let original = self.original_error.take();
        let cleanup = self.cleanup_error.take();
        if original.is_none() && cleanup.is_none() {
            None
        } else {
            Some(Box::new(Errors { original, cleanup }))
        }
    }
}
impl Drop for Forwarder<'_> {
    fn drop(&mut self) {
        if let Some(error) = self.close() {
            self.reports.cleanup(Cleanup::Statistics, error);
        }
    }
}
