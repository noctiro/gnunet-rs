//! Bounded preparation and explicit passive retirement of original WFP owners.
//!
//! Preparation never destroys injection handles or removes receiving guards.
//! Finalization unregisters datagram callouts while those UNKNOWN guards remain
//! installed, then uses the native handle-destruction wait. This retires this
//! driver's original receive/injection and memory owners; it asserts no custody
//! over new injections made independently by another component afterward.
use super::{COLD, Driver, FAILED, Generation, PREPARED, RETIRING, STARTING, from_device};
use crate::{callbacks, device, inject, policy, registration, runtime, sdk};
use core::{
    pin::Pin,
    ptr::NonNull,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

const CLOSED: usize = 1 << (usize::BITS - 1);

pub(super) struct Dispatches(AtomicUsize);

impl Dispatches {
    pub(super) const fn new() -> Self {
        Self(AtomicUsize::new(0))
    }

    pub(super) fn enter(&self) -> Option<Dispatch<'_>> {
        self.0
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < CLOSED - 1).then_some(count + 1)
            })
            .ok()?;
        Some(Dispatch(self))
    }

    pub(super) fn stop(&self) {
        self.0.fetch_or(CLOSED, Ordering::AcqRel);
    }
    pub(super) fn outstanding(&self) -> usize {
        self.0.load(Ordering::Acquire) & !CLOSED
    }

    /// Reopen a stable selection gate only after its original reservations end.
    /// The caller must finish replacing the inaccessible generation first.
    pub(super) fn reopen(&self) -> Result<(), sdk::NTSTATUS> {
        self.0
            .compare_exchange(CLOSED, 0, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| sdk::GNUNET_WFP_STATUS_DEVICE_BUSY)
    }
}

pub(super) struct Dispatch<'a>(&'a Dispatches);
impl Drop for Dispatch<'_> {
    fn drop(&mut self) {
        self.0.0.fetch_sub(1, Ordering::Release);
    }
}

/// Original cleanup refusal. Complete native outcomes remain in [`Receipts`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Failure {
    /// Original admission could not obtain its actual native drain.
    Admission(device::Error),
    /// The original capture transaction did not retire successfully.
    CapturePolicy,
    /// Original SDK refusal; independent observations remain in [`Receipts`].
    Native(registration::NativeFailure),
    /// An original flow removal was refused.
    Flow(runtime::AssociationError),
    /// The original callback publication could not be cleared.
    Publication(callbacks::Error),
    /// The original NDIS pool could not retire after native cutoff.
    Pool(inject::Error),
    /// The final original guard-engine retirement failed.
    GuardPolicy,
}

/// Current original retirement boundary, without a deadline-derived success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// Existing outer dispatch or original rundown reservations are still live.
    Admission,
    /// Original flow-delete callbacks still owe their native dispositions.
    FlowDeletion,
    /// Preparation finished; an explicit passive native wait can now begin.
    PreparedForNativeWait,
    /// Native handles were destroyed, but original completion accounting remains.
    Completion,
    /// This driver's original WFP receive/injection owners have retired.
    /// Device files, extension storage and executable unload are separate.
    NativeRetired,
    /// A native refusal is retained; no automatic retry targets an uncertain owner.
    Failed,
}

/// Live accounting observed under the original runtime lock.
/// These observations never substitute for the native unregistration/wait.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Counts {
    /// Outer dispatch borrows that precede inner runtime admission.
    pub dispatches: usize,
    /// Original contexts not yet returned by native flow-delete callbacks.
    pub flows: usize,
    /// Original injection reservations still owing disposition.
    pub native_injections: usize,
    /// NDIS packet preparations or native completions retaining the original pool.
    pub packet_owners: usize,
    /// Original copied requests retained for physical file cleanup.
    pub queued_captures: usize,
    /// Original capture copies still outside the metadata lock.
    pub capture_copies: usize,
    /// Original completion records retained for their file owner.
    pub completion_records: usize,
    /// An original native control file still owns this packet generation.
    pub file_owned: bool,
    /// Original upstream kernel handles or uncertain close custody still held.
    /// `NativeRetired` does not retire this independent file-owned custody.
    pub upstream_custody: bool,
    /// First recorded refusal to close an original upstream handle.
    pub upstream_close_failure: Option<sdk::NTSTATUS>,
}

impl Counts {
    /// Accounting required in addition to actual native retirement before the
    /// stable driver can overwrite this generation's original storage.
    pub(super) const fn can_replace(&self) -> bool {
        self.dispatches == 0
            && self.flows == 0
            && self.native_injections == 0
            && self.packet_owners == 0
            && self.queued_captures == 0
            && self.capture_copies == 0
            && self.completion_records == 0
            && !self.file_owned
            && !self.upstream_custody
            && self.upstream_close_failure.is_none()
    }
}

/// One bounded preparation or explicit native-finalization observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub struct Progress {
    /// Actual boundary reached by the original owners.
    pub phase: Phase,
    /// Current original counters, independent of native lifetime proof.
    pub counts: Counts,
    /// Original refusal, including one recovered by a later authoritative close.
    pub failure: Option<Failure>,
}

type Unregister = [Result<Option<u32>, registration::NativeFailure>; 2];
type Handles = [Result<bool, registration::NativeFailure>; 2];

/// Independent original native outcomes, retained even after later stages.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[must_use]
pub struct Receipts {
    /// Original capture lifecycle filter transaction with inbound guards retained.
    pub capture: Option<policy::Retirement>,
    /// Original discovery and endpoint closure unregistration observations.
    pub discovery: Option<[Result<Option<u32>, registration::NativeFailure>; 4]>,
    /// Original datagram unregistration observations.
    pub datagrams: Option<Unregister>,
    /// Actual original injection-handle destruction results.
    pub handles: Option<Handles>,
    /// Actual original stopped NDIS pool retirement result.
    pub pool: Option<Result<bool, inject::Error>>,
    /// Final original guard-engine retirement observations.
    pub guards: Option<policy::Retirement>,
}

#[derive(Clone, Copy)]
enum Step {
    New,
    Admission,
    Capture,
    Discovery,
    Flows,
    Prepared,
    Datagrams,
    Handles,
    Completion,
    Publication,
    Pool,
    Guards,
    Done,
    Failed,
}

pub(super) struct Retirement {
    step: Step,
    drained: Option<device::Drained<'static>>,
    cursor: usize,
    failure: Option<Failure>,
    receipts: Receipts,
}

impl Retirement {
    pub(super) const fn native_retired(&self) -> bool {
        matches!(self.step, Step::Done)
    }

    pub(super) const fn observations(&self) -> Receipts {
        self.receipts
    }

    pub(super) const fn new() -> Self {
        Self {
            step: Step::New,
            drained: None,
            cursor: 0,
            failure: None,
            receipts: Receipts {
                capture: None,
                discovery: None,
                datagrams: None,
                handles: None,
                pool: None,
                guards: None,
            },
        }
    }

    fn fail(&mut self, failure: Failure) {
        self.failure = Some(failure);
        self.step = Step::Failed;
    }
}

/// Stop new packet work and advance at most `budget` original flow slots.
/// Native transaction/unregistration calls have their documented SDK latency;
/// the budget bounds slot work, not wall-clock duration. No busy wait is used.
///
/// # Safety
/// Call from an original protected passive control path with the device live.
/// This control path must not hold this driver's outer dispatch reservation or
/// an original runtime loan. Retain the device, state and executable code;
/// a pending result is not permission to free or unload anything. In particular,
/// receiving guards and original handles remain available throughout preparation.
///
/// # Errors
/// Refuses non-passive use, a different device, concurrent native startup or
/// retirement control, or unavailable original runtime state.
pub unsafe fn poll(
    device: NonNull<sdk::DEVICE_OBJECT>,
    budget: usize,
) -> Result<Progress, sdk::NTSTATUS> {
    // SAFETY: caller retains this original protected device and passive context.
    let (owner, _control) = unsafe { control(device) }?;
    // Only an acquired original administrative control makes stop sticky;
    // a racing or invalid request cannot cancel generation recovery.
    owner.stop_requested.store(true, Ordering::Release);
    // SAFETY: stable control excludes generation replacement until return.
    unsafe { poll_generation(owner.generation(), budget) }
}

/// Advance one generation without requesting whole-driver shutdown.
///
/// # Safety
/// Hold the stable driver's original `Control` throughout this operation and
/// retain this exact generation at its initialized nonpaged address. Exclude
/// replacement until the control and every original native/file owner retire.
/// Do not hold an original packet dispatch or runtime admission reservation.
pub(super) unsafe fn poll_generation(
    generation: &'static Generation,
    budget: usize,
) -> Result<Progress, sdk::NTSTATUS> {
    begin(generation)?;
    // SAFETY: the control reservation serializes all retirement-state mutations.
    let retirement = unsafe { &mut *generation.retirement.get() };
    // SAFETY: only this control mutates native owners, each through its own cell.
    let native = unsafe { &*generation.native.get() };
    match retirement.step {
        Step::New => {
            generation.dispatches.stop();
            // SAFETY: bounded local revocation keeps guards and original owners live.
            unsafe { generation.runtime().revoke_policy(None) };
            // SAFETY: only the completed original callback field may be observed.
            if let Some(callback) = unsafe { generation.callback() } {
                callback.stop_capture();
            }
            // SAFETY: original runtime and pool remain pinned throughout retirement.
            let _ = unsafe { generation.runtime() }.admission().stop();
            unsafe { Pin::new_unchecked(&*native.pool.get()) }.stop();
            retirement.step = Step::Admission;
        }
        Step::Failed
        | Step::Done
        | Step::Prepared
        | Step::Datagrams
        | Step::Handles
        | Step::Completion
        | Step::Publication
        | Step::Pool
        | Step::Guards => return unsafe { report(generation, retirement) },
        _ => {}
    }
    if matches!(retirement.step, Step::Admission) {
        if generation.dispatches.outstanding() != 0 {
            return unsafe { report(generation, retirement) };
        }
        // SAFETY: the original stopped admission remains pinned and live.
        match unsafe { generation.runtime() }.admission().try_drain() {
            Ok(Some(drained)) => {
                retirement.drained = Some(drained);
                retirement.step = Step::Capture;
            }
            Ok(None) => return unsafe { report(generation, retirement) },
            Err(error) => {
                retirement.fail(Failure::Admission(error));
                return unsafe { report(generation, retirement) };
            }
        }
    }
    if matches!(retirement.step, Step::Capture) {
        // SAFETY: capture admission and its original reservations have drained;
        // capture lifecycle filters retire while original inbound guards remain.
        let policy = unsafe { &mut *native.policy.get() };
        let receipt = unsafe { policy.retire_capture() };
        retirement.receipts.capture = Some(receipt);
        if receipt.has_failure() {
            retirement.failure.get_or_insert(Failure::CapturePolicy);
        }
        if !policy.capture_retired() {
            retirement.fail(Failure::CapturePolicy);
            return unsafe { report(generation, retirement) };
        }
        retirement.step = Step::Discovery;
    }
    if matches!(retirement.step, Step::Discovery) {
        // SAFETY: capture lifecycle policy and original admission retired,
        // without an arena lock. Keep callback storage and native owners live.
        let result = unsafe { (&mut *native.registrations.get()).unregister_discovery() };
        retirement.receipts.discovery = Some(result);
        if let Some(failure) = result.into_iter().find_map(Result::err) {
            retirement.fail(Failure::Native(failure));
            return unsafe { report(generation, retirement) };
        }
        retirement.step = Step::Flows;
    }
    if matches!(retirement.step, Step::Flows) {
        // SAFETY: same original serialized registration remains live for deletion.
        let registration = unsafe { &*native.registrations.get() };
        let drained = retirement
            .drained
            .as_ref()
            .ok_or(sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_STATE)?;
        for _ in 0..budget.min(callbacks::FLOWS) {
            let slot = retirement.cursor;
            retirement.cursor = (slot + 1) % callbacks::FLOWS;
            // SAFETY: actual original admission drain, registration and flow slot;
            // Runtime releases its metadata lock before native context removal.
            if let Err(error) =
                unsafe { generation.runtime().remove_at(drained, registration, slot) }
            {
                retirement.fail(Failure::Flow(error));
                return unsafe { report(generation, retirement) };
            }
        }
        // SAFETY: snapshot is bounded local work under the original runtime lock.
        if unsafe { counts(generation) }?.flows == 0 {
            retirement.step = Step::Prepared;
        }
    }
    unsafe { report(generation, retirement) }
}

/// Perform explicit PASSIVE native finalization after [`poll`] prepares it.
/// Handle destruction executes the real SDK wait and has no invented timeout.
/// Original UNKNOWN guards stay installed while datagram callouts unregister;
/// WFP supplies temporary BLOCK until all handle queries and pending injections
/// end. Guards are removed only after that native boundary.
///
/// # Safety
/// Meet [`poll`]'s original-device, control, pin and executable-lifetime contract.
/// Do not call from a callback, a BFE notification, with a spin lock held, or
/// while holding an original dispatch/admission loan. Pending completion still
/// retains every original resource. `NativeRetired` concerns this driver's WFP
/// owners; it does not authorize freeing active file/device state or exporting
/// an unloadable product without its independent I/O manager lifetime proof.
///
/// # Errors
/// Refuses incorrect context, concurrency or unavailable original state. Native
/// cleanup failures are retained in the returned progress and [`receipts`].
pub unsafe fn finalize(device: NonNull<sdk::DEVICE_OBJECT>) -> Result<Progress, sdk::NTSTATUS> {
    // SAFETY: caller retains the original device at PASSIVE_LEVEL.
    let (owner, _control) = unsafe { control(device) }?;
    // SAFETY: the original stable control excludes replacement until return.
    unsafe { finalize_generation(owner.generation()) }
}

/// Finish native packet retirement while the stable WDM/BFE owner survives.
///
/// # Safety
/// Meet [`poll_generation`]'s exact original generation and control contract.
/// Use PASSIVE_LEVEL outside every native callback and without a spin lock or
/// original packet dispatch/admission reservation. A successful native wait
/// does not itself permit overwriting retained file or request storage.
pub(super) unsafe fn finalize_generation(
    generation: &'static Generation,
) -> Result<Progress, sdk::NTSTATUS> {
    if generation.phase.load(Ordering::Acquire) != RETIRING {
        return Err(sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_STATE);
    }
    // SAFETY: this original control exclusively mutates retirement stages.
    let retirement = unsafe { &mut *generation.retirement.get() };
    if !matches!(
        retirement.step,
        Step::Prepared
            | Step::Datagrams
            | Step::Handles
            | Step::Completion
            | Step::Publication
            | Step::Pool
            | Step::Guards
    ) {
        return unsafe { report(generation, retirement) };
    }
    // SAFETY: native fields have independent cells, without borrowing a mutable
    // whole Native while original completion permits still borrow its pool.
    let native = unsafe { &*generation.native.get() };
    if matches!(retirement.step, Step::Prepared | Step::Datagrams) {
        retirement.step = Step::Datagrams;
        // SAFETY: original flows deleted, outbound and dispatch admission joined;
        // actual inbound UNKNOWN guards remain installed through handle drain.
        let result = unsafe { (&mut *native.registrations.get()).unregister_datagrams() };
        retirement.receipts.datagrams = Some(result);
        if let Some(failure) = result.into_iter().find_map(Result::err) {
            retirement.fail(Failure::Native(failure));
            return unsafe { report(generation, retirement) };
        }
        retirement.step = Step::Handles;
    }
    if matches!(retirement.step, Step::Handles) {
        // SAFETY: true FWPS unregistration ended native handle queries. Stopped
        // submitters cannot enter, and retained guards provide SDK BLOCK. This
        // native call waits for accepted original injections to complete.
        let result = unsafe { (&mut *native.transport.get()).close() };
        retirement.receipts.handles = Some(result);
        if let Some(failure) = result.into_iter().find_map(Result::err) {
            retirement.fail(Failure::Native(failure));
            return unsafe { report(generation, retirement) };
        }
        retirement.step = Step::Completion;
    }
    if matches!(retirement.step, Step::Completion) {
        // Native destruction is the actual wait; these counters additionally
        // refuse freeing Rust packet owners before their exact dispositions.
        let snapshot = unsafe { counts(generation) }?;
        if snapshot.native_injections != 0
            || snapshot.packet_owners != 0
            || snapshot.capture_copies != 0
        {
            return unsafe { report(generation, retirement) };
        }
        retirement.step = Step::Publication;
    }
    if matches!(retirement.step, Step::Publication) {
        if generation.callback_published.load(Ordering::Acquire) {
            // SAFETY: all original FWPS callbacks unregistered and native handle
            // waits finished; no SDK entry can rediscover this publication.
            let callback = unsafe { generation.callback() }
                .ok_or(sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_STATE)?;
            if let Err(error) = unsafe { callback.clear_after_unregister() } {
                retirement.fail(Failure::Publication(error));
                return unsafe { report(generation, retirement) };
            }
            generation
                .callback_published
                .store(false, Ordering::Release);
        }
        retirement.step = Step::Pool;
    }
    if matches!(retirement.step, Step::Pool) {
        // SAFETY: outer dispatch and native submitters joined; actual native
        // unregistration/destruction ended pool borrowers, with no owners left.
        let result = unsafe { Pin::new_unchecked(&mut *native.pool.get()).retire_after_drain() };
        retirement.receipts.pool = Some(result);
        if let Err(error) = result {
            retirement.fail(Failure::Pool(error));
            return unsafe { report(generation, retirement) };
        }
        retirement.step = Step::Guards;
    }
    if matches!(retirement.step, Step::Guards) {
        // SAFETY: actual native receive/injection and callback cutoff precedes
        // deletion of the retained original guard policy and engine.
        let policy = unsafe { &mut *native.policy.get() };
        let receipt = unsafe { policy.retire_after_drain() };
        retirement.receipts.guards = Some(receipt);
        if receipt.has_failure() {
            retirement.failure.get_or_insert(Failure::GuardPolicy);
        }
        if policy.has_original_engine() {
            retirement.fail(Failure::GuardPolicy);
            return unsafe { report(generation, retirement) };
        }
        retirement.step = Step::Done;
    }
    unsafe { report(generation, retirement) }
}

/// Copy original retirement outcomes without issuing or retrying native calls.
///
/// # Safety
/// Retain the original device and use its protected passive control context.
///
/// # Errors
/// Refuses incorrect context or simultaneous retirement control.
pub unsafe fn receipts(device: NonNull<sdk::DEVICE_OBJECT>) -> Result<Receipts, sdk::NTSTATUS> {
    // SAFETY: original protected device and caller-owned passive context.
    let (owner, _control) = unsafe { control(device) }?;
    // SAFETY: stable control excludes replacement and retained-record mutation.
    let generation = unsafe { owner.generation() };
    Ok(unsafe { &*generation.retirement.get() }.receipts)
}

pub(super) unsafe fn terminal_counts(
    device: NonNull<sdk::DEVICE_OBJECT>,
) -> Result<Counts, sdk::NTSTATUS> {
    // SAFETY: original passive control keeps the exact registered device live.
    let (owner, _control) = unsafe { control(device) }?;
    // SAFETY: this stable control excludes replacement until return.
    let generation = unsafe { owner.generation() };
    // SAFETY: this exclusive control protects the original phase observation.
    if !unsafe { &*generation.retirement.get() }.native_retired() {
        return Err(sdk::GNUNET_WFP_STATUS_DEVICE_BUSY);
    }
    // SAFETY: retirement retains the original runtime and native storage.
    unsafe { counts(generation) }
}

fn begin(generation: &Generation) -> Result<(), sdk::NTSTATUS> {
    let phase = generation.phase.load(Ordering::Acquire);
    match phase {
        RETIRING => Ok(()),
        STARTING => Err(sdk::GNUNET_WFP_STATUS_DEVICE_BUSY),
        COLD | PREPARED | FAILED => generation
            .phase
            .compare_exchange(phase, RETIRING, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| sdk::GNUNET_WFP_STATUS_DEVICE_BUSY),
        _ => Err(sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_STATE),
    }
}

pub(super) struct Control<'a>(&'a AtomicBool);
impl Drop for Control<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

unsafe fn control(
    device: NonNull<sdk::DEVICE_OBJECT>,
) -> Result<(&'static Driver, Control<'static>), sdk::NTSTATUS> {
    // SAFETY: caller supplies this driver's original live device object.
    let owner = unsafe { from_device(device.as_ptr()) }
        .ok_or(sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_STATE)?;
    Ok((owner, control_owner(owner)?))
}

/// Reserve stable lifecycle control before selecting or replacing a generation.
pub(super) fn control_owner(owner: &Driver) -> Result<Control<'_>, sdk::NTSTATUS> {
    // SAFETY: the SDK wrapper only observes the current native IRQL.
    if u32::from(unsafe { sdk::gnunet_wfp_current_irql() }) != sdk::PASSIVE_LEVEL {
        return Err(sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_STATE);
    }
    owner
        .retirement_busy
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| sdk::GNUNET_WFP_STATUS_DEVICE_BUSY)?;
    Ok(Control(&owner.retirement_busy))
}

unsafe fn counts(generation: &Generation) -> Result<Counts, sdk::NTSTATUS> {
    // SAFETY: original initialized runtime and native pool remain live.
    let runtime = unsafe { generation.runtime().retirement_snapshot() }
        .ok_or(sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_STATE)?;
    let native = unsafe { &*generation.native.get() };
    // SAFETY: original control excludes replacement of this pool storage.
    let packet_owners = unsafe { &*native.pool.get() }.outstanding();
    Ok(Counts {
        dispatches: generation.dispatches.outstanding(),
        flows: runtime.flows,
        native_injections: runtime.native_injections,
        packet_owners,
        queued_captures: runtime.queued_captures,
        capture_copies: runtime.capture_copies,
        completion_records: runtime.completion_records,
        file_owned: runtime.file_owned,
        upstream_custody: runtime.upstream_custody,
        upstream_close_failure: runtime.upstream_close_failure,
    })
}

unsafe fn report(
    generation: &Generation,
    retirement: &Retirement,
) -> Result<Progress, sdk::NTSTATUS> {
    let phase = match retirement.step {
        Step::New | Step::Admission | Step::Capture | Step::Discovery => Phase::Admission,
        Step::Flows => Phase::FlowDeletion,
        Step::Prepared | Step::Datagrams | Step::Handles => Phase::PreparedForNativeWait,
        Step::Completion | Step::Publication | Step::Pool | Step::Guards => Phase::Completion,
        Step::Done => Phase::NativeRetired,
        Step::Failed => Phase::Failed,
    };
    // SAFETY: the original control and native owners stay live during the snapshot.
    Ok(Progress {
        phase,
        counts: unsafe { counts(generation) }?,
        failure: retirement.failure,
    })
}

pub(super) fn failure_status(
    failure: Option<Failure>,
    receipts: Option<Receipts>,
) -> sdk::NTSTATUS {
    match failure {
        Some(Failure::Native(error)) => error.status,
        Some(Failure::Flow(runtime::AssociationError::Native(status))) => status,
        Some(Failure::Pool(inject::Error::Native { status, .. })) => status,
        Some(Failure::CapturePolicy | Failure::GuardPolicy) => receipts
            .and_then(|receipts| {
                if matches!(failure, Some(Failure::CapturePolicy)) {
                    receipts.capture
                } else {
                    receipts.guards
                }
            })
            .and_then(policy::Retirement::first_failure)
            .map_or(sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_STATE, |failure| {
                failure.status
            }),
        _ => sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_STATE,
    }
}

pub(super) fn refusal_status(status: sdk::NTSTATUS) -> sdk::NTSTATUS {
    if status < 0 {
        status
    } else {
        sdk::GNUNET_WFP_STATUS_INVALID_DEVICE_STATE
    }
}
