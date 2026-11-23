//! Native startup and shutdown completions remain exclusive host obligations.
use super::{
    Session,
    bridge::{Bridge, StartData, StopData},
    native::{NativeProvider, StartCompletion, StopCompletion},
};
use std::{
    collections::VecDeque,
    fmt, io,
    path::{Path, PathBuf},
    sync::Arc,
    task::{Context, Poll},
};

/// Original native startup request and its validated configuration snapshot.
pub struct StartRequest {
    bridge: Arc<Bridge>,
    callback: Option<StartCompletion>,
    configuration: PathBuf,
    _provider: NativeProvider,
}
impl StartRequest {
    pub(super) fn new(bridge: Arc<Bridge>, data: StartData) -> Self {
        Self {
            bridge,
            callback: Some(data.callback),
            configuration: data.configuration,
            _provider: data.provider,
        }
    }
    /// Absolute GNUNET_CONFIG copied from the original provider configuration.
    pub fn configuration_file(&self) -> &Path {
        &self.configuration
    }
    /// Original session authority for upstream and relay resource loans.
    pub fn session(&self) -> Session {
        self.bridge.session.clone()
    }
    /// Report readiness only after the host established its service and sources.
    /// # Errors
    /// A native stop observed before the readiness commit refuses startup.
    pub fn ready(mut self) -> io::Result<()> {
        self.bridge.ready()?;
        if let Some(callback) = self.callback.take() {
            callback.ready();
        }
        Ok(())
    }
    /// Report actual startup failure; no readiness acknowledgement is emitted.
    pub fn reject(mut self) {
        self.bridge.request_shutdown();
        drop(self.callback.take());
    }
}
impl fmt::Debug for StartRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StartRequest")
            .field("configuration", &self.configuration)
            .finish_non_exhaustive()
    }
}
impl Drop for StartRequest {
    fn drop(&mut self) {
        if self.callback.is_some() {
            self.bridge.request_shutdown();
        }
        // An unfulfilled StartCompletion reports an SDK error from its Drop.
    }
}

/// Original stop obligation. Drop reports cancellation, never a successful drain.
pub struct StopRequest {
    bridge: Arc<Bridge>,
    callback: Option<StopCompletion>,
    reason: isize,
    queued: VecDeque<super::AcceptedFlow>,
    _provider: NativeProvider,
}
impl StopRequest {
    pub(super) fn new(bridge: Arc<Bridge>, data: StopData) -> Self {
        Self {
            bridge,
            _provider: data.provider,
            callback: Some(data.callback),
            reason: data.reason,
            queued: data.queued,
        }
    }
    /// Unmodified NEProviderStopReason native value.
    pub const fn reason(&self) -> isize {
        self.reason
    }
    /// Close queued, unopened flows immediately, without acknowledging stop.
    /// Call this when receiving Stop, before draining the host's other owners.
    pub fn begin_drain(&mut self) {
        self.queued.clear();
    }
    /// Fulfil stop after the host closed its service, relays and upstream owner.
    /// Native flow/connection callback keepers are independently checked here.
    pub fn poll_complete(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.callback.is_none() {
            return Poll::Ready(Ok(()));
        }
        self.begin_drain();
        if self.bridge.session.counter.poll_drained(cx).is_pending() {
            return Poll::Pending;
        }
        self.bridge.stopped()?;
        if let Some(callback) = self.callback.take() {
            callback.complete();
        }
        Poll::Ready(Ok(()))
    }
}
impl fmt::Debug for StopRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StopRequest")
            .field("reason", &self.reason)
            .field("unadopted", &self.queued.len())
            .finish_non_exhaustive()
    }
}
impl Drop for StopRequest {
    fn drop(&mut self) {
        if self.callback.is_some() {
            self.bridge.abandon();
            // The SDK stop completion is void. Releasing it without invoking
            // success cannot turn unconfirmed retirement into an ACK.
        }
    }
}
