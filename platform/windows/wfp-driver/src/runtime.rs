//! Original flow associations and receive decisions under pinned native state.
use crate::{
    device::{self, Rundown},
    lock::{Locked, StateLock},
    receive::{self, Decision, Verdict},
    sdk,
};
use core::{ffi::c_void, pin::Pin, ptr::NonNull};
use gnunet_wfp_dns::State;

mod channel;
mod flows;
mod queue;

use channel::Channel;
pub use channel::{CaptureError, Completion, DeviceError};
pub use flows::{AssociationError, Removal};

struct DriverState<const F: usize, const R: usize> {
    core: State<F, R>,
    channel: Channel<R>,
}

/// Accounting snapshot for the original device and WFP operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetirementSnapshot {
    /// Flow contexts still owed an actual native deletion.
    pub flows: usize,
    /// Submitted injection reservations awaiting a native disposition.
    pub native_injections: usize,
    /// Original DNS records still queued for the device.
    pub queued_captures: usize,
    /// Packet copies presently owned by a producer or device read.
    pub capture_copies: usize,
    /// Actual injection completion records not yet consumed by the file.
    pub completion_records: usize,
    /// An original file still owns the runtime or is completing CLEANUP.
    pub file_owned: bool,
    /// A file still retains upstream handles, a socket operation is running,
    /// or a native close has an unresolved original handle.
    pub upstream_custody: bool,
    /// First recorded refusal to close an original upstream handle.
    pub upstream_close_failure: Option<sdk::NTSTATUS>,
}

/// Pinned nonpaged callback state. Its outbound rundown does not stop inbound
/// decisions or flow-deletion callbacks during retirement.
pub struct Runtime<const F: usize, const R: usize> {
    outbound: Rundown,
    state: StateLock<DriverState<F, R>>,
}

impl<const F: usize, const R: usize> Runtime<F, R> {
    /// Construct unpublished state without touching the SDK.
    pub const fn new() -> Self {
        Self {
            outbound: Rundown::new(),
            state: StateLock::new(DriverState {
                core: State::new(),
                channel: Channel::new(),
            }),
        }
    }

    /// Initialize all fields at their final address.
    ///
    /// # Safety
    /// Exclusive startup at `PASSIVE_LEVEL`. Keep the original state pinned
    /// and nonpaged through all external native entries and loan retirement.
    ///
    /// # Errors
    /// Returns original initialization or IRQL refusal.
    pub unsafe fn initialize(self: Pin<&mut Self>) -> Result<(), device::Error> {
        // SAFETY: both fields are initialized in place without moves.
        let owner = unsafe { self.get_unchecked_mut() };
        // SAFETY: exclusive startup owns both pins before publication.
        unsafe { Pin::new_unchecked(&mut owner.outbound).initialize()? };
        // SAFETY: same nonpaged allocation and original startup loan.
        if !unsafe { Pin::new_unchecked(&mut owner.state).initialize() } {
            return Err(device::Error::AlreadyInitialized);
        }
        Ok(())
    }

    /// Borrow the original state for bounded native callback work.
    ///
    /// # Safety
    /// Same-thread use at IRQL <= `DISPATCH_LEVEL` with the lock unheld. No
    /// WFP registration, injection, context removal, waits or user memory
    /// access may occur while holding this lock.
    unsafe fn lock(self: Pin<&Self>) -> Option<Locked<'_, DriverState<F, R>>> {
        // SAFETY: both the pin projection and acquisition retain the inline
        // original lock; the caller meets the SDK's thread and IRQL contract.
        unsafe { self.map_unchecked(|owner| &owner.state).lock() }
    }

    /// Original outbound admission. Drain this owner before context removal.
    pub fn admission(self: Pin<&Self>) -> Pin<&Rundown> {
        // SAFETY: the inline rundown field cannot move under a shared pin.
        unsafe { self.map_unchecked(|owner| &owner.outbound) }
    }

    /// Inspect the original inbound callback, then apply its verdict with the
    /// original state lock only when an injection needs authorization. Deadline
    /// units are native 100 ns ticks.
    ///
    /// # Safety
    /// Original initialized nonpaged state and WFP callback args must satisfy
    /// the lease and IRQL requirements of [`receive::inspect`].
    ///
    /// # Errors
    /// Refuses unpublished state. Install guards only after initialization.
    pub unsafe fn receive(
        self: Pin<&Self>,
        handles: &[NonNull<c_void>; 2],
        packet: *const sdk::NET_BUFFER_LIST,
        fixed: &sdk::FWPS_INCOMING_VALUES0,
        metadata: Option<&sdk::FWPS_INCOMING_METADATA_VALUES0>,
        context: u64,
        output: &mut sdk::FWPS_CLASSIFY_OUT0,
    ) -> Result<Verdict, AssociationError> {
        // SAFETY: original callback and native handles are live by contract.
        let classify =
            unsafe { receive::inspect(handles, packet, fixed, metadata, context, output) };
        let candidate = match classify.decide() {
            Decision::Complete(verdict) => return Ok(verdict),
            Decision::NeedsAuthority(candidate) => candidate,
        };
        // SAFETY: original callback retains its initialized nonpaged lock.
        let Some(mut state) = (unsafe { self.lock() }) else {
            candidate.refuse();
            return Err(AssociationError::Uninitialized);
        };
        Ok(candidate.enforce(&mut state.core, now()))
    }
}

fn now() -> u64 {
    let mut counter = 0;
    // SAFETY: the SDK accepts this live timestamp output at any IRQL.
    unsafe { sdk::KeQueryInterruptTimePrecise(&mut counter) }
}

impl<const F: usize, const R: usize> Default for Runtime<F, R> {
    fn default() -> Self {
        Self::new()
    }
}
