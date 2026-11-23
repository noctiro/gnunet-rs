//! Exact device file ownership and bounded capture and completion queues.
use super::queue::Queue;
use crate::{capture::Captured, device, sdk};
use core::num::NonZeroU64;
use gnunet_wfp_dns::{Error, InjectionObservation, RequestId, SessionId, device as record};

mod capture;
mod event;
mod file;
mod upstream;

pub use capture::CaptureError;

pub(super) struct Channel<const R: usize> {
    active: Option<FileSession>,
    closing: Option<usize>,
    captures: Queue<Capture, R>,
    copying: usize,
    completions: Queue<Completion, R>,
    replies: usize,
    wake: Option<event::Event>,
    sockets: Option<upstream::Sockets>,
    socket_operation_pending: bool,
    failed_sockets: Option<upstream::Sockets>,
    started: bool,
    stopped: bool,
    policy_epoch: Option<u64>,
}

impl<const R: usize> Channel<R> {
    pub(super) const fn new() -> Self {
        Self {
            active: None,
            closing: None,
            captures: Queue::new(),
            copying: 0,
            completions: Queue::new(),
            replies: 0,
            wake: None,
            sockets: None,
            socket_operation_pending: false,
            failed_sockets: None,
            started: false,
            stopped: false,
            policy_epoch: None,
        }
    }

    pub(super) fn intercepts(&self, endpoint: NonZeroU64) -> bool {
        self.policy_epoch.is_some()
            && self.started
            && !self.stopped
            && self
                .sockets
                .as_ref()
                .is_some_and(|sockets| !sockets.excludes(endpoint))
    }

    fn check_policy(&self) -> Result<(), DeviceError> {
        // Policy loss stops the original file but leaves its socket set until
        // explicit STOP. Publishing a replacement epoch cannot rearm this file.
        if self.started && self.sockets.is_some() && (self.stopped || self.policy_epoch.is_none()) {
            return Err(DeviceError::Native(sdk::GNUNET_WFP_STATUS_DEVICE_NOT_READY));
        }
        Ok(())
    }

    fn signal(&self) {
        if let Some(wake) = &self.wake {
            wake.signal();
        }
    }

    fn session(&self, original: usize) -> Result<SessionId, DeviceError> {
        let current = self.active.ok_or(DeviceError::Stale)?;
        if original != current.file {
            return Err(DeviceError::Stale);
        }
        Ok(current.session)
    }
}

#[derive(Clone, Copy)]
struct FileSession {
    file: usize,
    session: SessionId,
}

struct Capture {
    request: RequestId,
    packet: Captured,
}

/// Actual original WFP completion and the independent receive-gate result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Completion {
    /// Request token issued to this original device file.
    pub request: RequestId,
    /// Status observed on the original NBL in the native completion callback.
    pub status: sdk::NTSTATUS,
    /// Original receive-gate observation. This does not prove socket delivery.
    pub observation: InjectionObservation,
}

/// Refusal from the original buffered device path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceError {
    /// The prepared driver has not initialized its state.
    Uninitialized,
    /// The original file/session is absent or stale.
    Stale,
    /// Another file holds the active or closing device session.
    Busy,
    /// Reply completions are bounded and the current file must consume them.
    Capacity,
    /// A complete original record needs a larger system buffer.
    Buffer {
        /// Exact bytes required for the next captured record.
        needed: usize,
    },
    /// Native outbound admission is closed.
    Admission(device::Error),
    /// The local buffered record was invalid.
    Record(record::Error),
    /// The bounded authority state refused the request.
    State(Error),
    /// Original WDK operation refused.
    Native(sdk::NTSTATUS),
}

impl<const F: usize, const R: usize> super::Runtime<F, R> {
    /// Observe the original owners under their nonpaged state lock.
    ///
    /// # Safety
    /// The initialized runtime lives at its original address. Call at IRQL
    /// no higher than DISPATCH_LEVEL without the state lock held.
    pub unsafe fn retirement_snapshot(
        self: core::pin::Pin<&Self>,
    ) -> Option<super::RetirementSnapshot> {
        // SAFETY: the caller retains the original lock and its nonpaged state.
        let state = unsafe { self.lock() }?;
        Some(super::RetirementSnapshot {
            flows: state.core.flow_count(),
            native_injections: state.core.native_debt(),
            queued_captures: state.channel.captures.len(),
            capture_copies: state.channel.copying,
            completion_records: state.channel.completions.len(),
            file_owned: state.channel.active.is_some() || state.channel.closing.is_some(),
            upstream_custody: state.channel.sockets.is_some()
                || state.channel.socket_operation_pending
                || state.channel.closing.is_some()
                || state.channel.failed_sockets.is_some(),
            upstream_close_failure: state
                .channel
                .failed_sockets
                .as_ref()
                .and_then(upstream::Sockets::close_failure),
        })
    }

    /// Publish the actual committed and verified policy epoch for this generation.
    ///
    /// # Safety
    /// Start once on the pinned original runtime with live native guards.
    pub unsafe fn publish_policy(self: core::pin::Pin<&Self>, epoch: u64) {
        // SAFETY: the original runtime's lock remains live.
        if let Some(mut state) = unsafe { self.lock() } {
            state.channel.policy_epoch = Some(epoch);
        }
    }

    /// Revoke this generation's capture and reply authority. A loss epoch
    /// revokes only an older committed policy. None forces local retirement.
    ///
    /// # Safety
    /// The caller retains the original runtime and its native receive guard
    /// through outstanding submissions.
    pub unsafe fn revoke_policy(self: core::pin::Pin<&Self>, before: Option<u64>) -> bool {
        // SAFETY: caller retains the original live, initialized state.
        let Some(mut state) = (unsafe { self.lock() }) else {
            return false;
        };
        if state
            .channel
            .policy_epoch
            .is_none_or(|epoch| before.is_some_and(|limit| epoch >= limit))
        {
            return false;
        }
        state.channel.policy_epoch = None;
        if state.channel.started
            && !state.channel.stopped
            && let Some(file) = state.channel.active
        {
            let _ = state.core.close_session(file.session);
            state.channel.stopped = true;
            state.channel.signal();
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replacement_policy_keeps_loss_visible_until_original_stop() {
        let mut channel = Channel::<1>::new();
        channel.started = true;
        channel.sockets = Some(upstream::Sockets::new());
        channel.policy_epoch = Some(1);
        assert_eq!(channel.check_policy(), Ok(()));
        channel.stopped = true;
        channel.policy_epoch = None;
        let lost = Err(DeviceError::Native(sdk::GNUNET_WFP_STATUS_DEVICE_NOT_READY));
        assert_eq!(channel.check_policy(), lost);
        channel.policy_epoch = Some(2);
        assert_eq!(channel.check_policy(), lost);
        channel.sockets = None;
        assert_eq!(channel.check_policy(), Ok(()));
    }
}
