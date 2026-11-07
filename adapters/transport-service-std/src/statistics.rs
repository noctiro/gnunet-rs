//! Existing shared STATISTICS handle. Only counters with an exact observable
//! production result are exported; no synthetic C internal counts or ACKs.
use crate::Failure;
use crate::owner::Statistics;
use gnunet_client::statistics_handle::GetFlow;
use gnunet_client_host::{LiveConfiguration, resolution::SharedResolution};
use gnunet_ipc_unix::{IpcError, handle};
use std::{
    future::Future,
    task::{Context, Poll},
};
type Native<'id> = handle::StatisticsHandle<'id, 8, 64, 1, 1, 4>;
/// One original nonpersistent STATISTICS stream. Errors after admission fence
/// this owner; no relative mutation is replayed on another source.
pub(crate) struct Publisher<'id> {
    owner: Option<Native<'id>>,
    last: Option<u64>,
    errors: Vec<Failure>,
}
impl<'id> Publisher<'id> {
    pub fn new(
        instance: &'id mut handle::Instance,
        live: LiveConfiguration,
        resolution: SharedResolution,
    ) -> Result<Self, Failure> {
        let mut errors = Vec::new();
        errors
            .try_reserve_exact(2)
            .map_err(|_| gnunet_types::Error::Capacity)?;
        Ok(Self {
            owner: Native::from_live_config(
                instance,
                live,
                resolution,
                b"transport",
                handle::Limits {
                    max_frame_bytes: 256,
                    write_chunk_bytes: 256,
                },
            )?,
            last: None,
            errors,
        })
    }
    fn fence(&mut self, error: IpcError) {
        self.errors.push(Box::new(error));
        self.retire();
    }
    fn retire(&mut self) {
        if let Some(mut owner) = self.owner.take()
            && let Err(e) = owner.destroy(false)
        {
            self.errors.push(Box::new(e));
        }
    }
    pub fn refresh(&mut self, statistics: Statistics) {
        if self.last == Some(statistics.foreign_address_failures) {
            return;
        }
        let Some(owner) = &mut self.owner else { return };
        match owner.set(
            b"# Peerstore failed to store foreign address",
            statistics.foreign_address_failures,
            false,
        ) {
            Ok(_) => self.last = Some(statistics.foreign_address_failures),
            Err(e) => self.fence(e),
        }
    }
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        let result = {
            let Some(owner) = &mut self.owner else {
                return Poll::Pending;
            };
            if owner.is_idle() || owner.is_closed() {
                return Poll::Pending;
            }
            let mut driving = std::pin::pin!(owner.drive(None, |_, _| GetFlow::Continue));
            driving.as_mut().poll(cx)
        };
        match result {
            Poll::Ready(Err(e)) => {
                self.fence(e);
                Poll::Ready(())
            }
            Poll::Ready(Ok(_)) => Poll::Ready(()),
            Poll::Pending => Poll::Pending,
        }
    }
    pub fn close(&mut self) -> Option<Failure> {
        self.retire();
        if self.errors.is_empty() {
            None
        } else {
            Some(Box::new(crate::Failures {
                original: None,
                cleanup: std::mem::take(&mut self.errors),
            }))
        }
    }
}
impl Drop for Publisher<'_> {
    fn drop(&mut self) {
        let _original = self.close();
    }
}
