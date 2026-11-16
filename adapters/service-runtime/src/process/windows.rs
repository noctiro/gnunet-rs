//! Bounded Windows child records over original process handles and kernel waits.
#![forbid(unsafe_code)]
use super::identity::{OriginalChild, RegistryIdentity};
use gnunet_native::process::{
    LaunchLimits, Process, ProcessIdentity, ProcessWait, ResourceUsage, ResumeFailure, Spawn,
    SuspendedProcess,
};
use std::{
    collections::VecDeque,
    fmt, io,
    mem::MaybeUninit,
    num::NonZeroU64,
    sync::Arc,
    task::{Context, Poll},
};

/// A refused registry operation, never a synthesized child exit/readiness result.
#[derive(Debug)]
pub enum RegistryError {
    /// Active/completed credit, generation or explicit backing capacity exhausted.
    Capacity,
    /// The token belongs to another registry or an already retired generation.
    Stale,
    /// Original native launch, wait, termination or resource error.
    Native(io::Error),
}
impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capacity => f.write_str("Windows child registry capacity"),
            Self::Stale => f.write_str("stale original child authority"),
            Self::Native(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for RegistryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Native(error) => Some(error),
            _ => None,
        }
    }
}
impl From<io::Error> for RegistryError {
    fn from(error: io::Error) -> Self {
        Self::Native(error)
    }
}
/// One consuming exit receipt from the original process handle. Windows codes
/// retain their full unsigned width, including a real completed code of 259.
#[derive(Clone, Debug)]
pub struct Reaped {
    /// Original registry-branded generation, not a new numeric-PID lookup.
    pub child: OriginalChild,
    /// Actual GetExitCodeProcess result after the kernel signaled termination.
    pub exit_code: u32,
}
enum Execution {
    Running(Process),
    Preparing(SuspendedProcess),
    StartFailed(SuspendedProcess),
}
impl Execution {
    fn original(&self) -> &Process {
        match self {
            Self::Running(process) => process,
            Self::Preparing(process) | Self::StartFailed(process) => process.process(),
        }
    }
}
enum Start {
    Running,
    Suspended,
}
struct Entry {
    // Native wait cancellation precedes the last ordinary process-handle owner.
    wait: Option<ProcessWait>,
    process: Execution,
    child: OriginalChild,
    usage: Option<Box<MaybeUninit<ResourceUsage>>>,
}
struct Completion {
    event: Reaped,
    usage: Option<Box<ResourceUsage>>,
}
impl Completion {
    fn into_parts(self) -> (Reaped, Option<ResourceUsage>) {
        (self.event, self.usage.map(|usage| *usage))
    }
}
impl Entry {
    fn complete(self, exit_code: u32) -> Completion {
        let Self {
            wait,
            process,
            child,
            usage,
        } = self;
        let usage = usage.map(|backing| Box::write(backing, process.original().resource_usage()));
        drop(wait);
        drop(process);
        Completion {
            event: Reaped { child, exit_code },
            usage,
        }
    }
}
/// Original child/wait ownership independent of a launcher or canceled drive
/// future. Active plus untaken completed records consume one shared credit.
/// Spawn preflights all registry backing before admitting a process. Final Drop
/// cancels local wait registrations and closes handles; it never kills a child,
/// waits for child exit or manufactures completion. Callers explicitly drain.
pub struct ChildRegistry {
    entries: Vec<Entry>,
    completed: VecDeque<Completion>,
    usage_enabled: bool,
    identity: Arc<RegistryIdentity>,
    next_generation: Option<NonZeroU64>,
    maximum: usize,
}
impl fmt::Debug for ChildRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChildRegistry")
            .field("active", &self.entries.len())
            .field("completed", &self.completed.len())
            .field("maximum", &self.maximum)
            .finish_non_exhaustive()
    }
}
impl ChildRegistry {
    /// Allocate bounded active/completed backing before any child can be created.
    pub fn new(maximum: usize) -> Result<Self, RegistryError> {
        if maximum == 0 {
            return Err(RegistryError::Capacity);
        }
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(maximum)
            .map_err(|_| RegistryError::Capacity)?;
        let mut completed = VecDeque::new();
        completed
            .try_reserve_exact(maximum)
            .map_err(|_| RegistryError::Capacity)?;
        Ok(Self {
            entries,
            completed,
            usage_enabled: false,
            identity: Arc::new(RegistryIdentity { _nonzero: 1 }),
            next_generation: Some(NonZeroU64::MIN),
            maximum,
        })
    }
    /// Enable actual native resource queries before any child admission. Query
    /// failures are retained per field with consuming exits, never zero-filled.
    pub fn enable_resource_usage(&mut self) -> Result<(), RegistryError> {
        if !self.entries.is_empty() || !self.completed.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "resource collection must precede native child admission",
            )
            .into());
        }
        self.usage_enabled = true;
        Ok(())
    }
    /// Create a real native child and publish its original handle record before
    /// returning the lookup token. Native refusal installs no child record. This
    /// is process admission only, never a successful image/READY/ARM protocol claim.
    pub fn spawn(
        &mut self,
        command: Spawn<'_>,
        limits: LaunchLimits,
    ) -> Result<OriginalChild, RegistryError> {
        self.admit(command, limits, Start::Running)
    }
    /// Admit an original child before its primary thread runs. The record remains
    /// authoritative throughout socket/handle setup. Resume or terminate/drain it
    /// explicitly; Drop never runs or kills a suspended child.
    pub fn spawn_suspended(
        &mut self,
        command: Spawn<'_>,
        limits: LaunchLimits,
    ) -> Result<OriginalChild, RegistryError> {
        self.admit(command, limits, Start::Suspended)
    }
    fn admit(
        &mut self,
        command: Spawn<'_>,
        limits: LaunchLimits,
        start: Start,
    ) -> Result<OriginalChild, RegistryError> {
        if !self.credit_available(self.maximum) {
            return Err(RegistryError::Capacity);
        }
        let generation = self.next_generation.ok_or(RegistryError::Capacity)?;
        let usage = self.usage_enabled.then(Box::<ResourceUsage>::new_uninit);
        let process = match start {
            Start::Running => Execution::Running(command.launch(limits)?),
            Start::Suspended => Execution::Preparing(command.suspend(limits)?),
        };
        let child = OriginalChild {
            identity: Arc::clone(&self.identity),
            generation: generation.get(),
            pid: process.original().id(),
        };
        self.next_generation = generation.checked_add(1);
        self.entries.push(Entry {
            wait: None,
            usage,
            process,
            child: child.clone(),
        });
        Ok(child)
    }
    /// Borrow the exact original native process while this registry record lives.
    /// No numeric PID is opened or reconstructed; the borrow excludes record
    /// retirement during native setup using that authority.
    pub fn original(&self, child: &OriginalChild) -> Result<&Process, RegistryError> {
        self.entries
            .iter()
            .find(|entry| entry.child == *child)
            .map(|entry| entry.process.original())
            .ok_or(RegistryError::Stale)
    }
    /// Revoke an original suspended child's start permission after setup failure.
    /// The same process/thread owners remain available for explicit termination
    /// and physical exit observation. Running children cannot be revoked.
    pub fn cancel_preparation(&mut self, child: &OriginalChild) -> Result<(), RegistryError> {
        let index = self
            .entries
            .iter()
            .position(|entry| entry.child == *child)
            .ok_or(RegistryError::Stale)?;
        if !matches!(self.entries[index].process, Execution::Preparing(_)) {
            return Err(RegistryError::Native(io::Error::new(
                io::ErrorKind::InvalidInput,
                "child has no unconsumed start permission",
            )));
        }
        let Entry {
            wait,
            process,
            child,
            usage,
        } = self.entries.swap_remove(index);
        let process = match process {
            Execution::Preparing(process) => Execution::StartFailed(process),
            other => other,
        };
        self.entries.push(Entry {
            wait,
            process,
            child,
            usage,
        });
        Ok(())
    }
    /// Resume this original prepared child once after native setup is published.
    /// A failed attempt retains original owners in a non-retryable failure phase;
    /// explicit termination/reaping remains available. No readiness is inferred.
    pub fn resume(&mut self, child: &OriginalChild) -> Result<(), RegistryError> {
        let index = self
            .entries
            .iter()
            .position(|entry| entry.child == *child)
            .ok_or(RegistryError::Stale)?;
        if !matches!(self.entries[index].process, Execution::Preparing(_)) {
            return Err(RegistryError::Native(io::Error::new(
                io::ErrorKind::InvalidInput,
                "child has no unconsumed start permission",
            )));
        }
        let Entry {
            wait,
            process,
            child,
            usage,
        } = self.entries.swap_remove(index);
        let (process, result) = match process {
            Execution::Preparing(process) => match process.resume() {
                Ok(process) => (Execution::Running(process), Ok(())),
                Err(ResumeFailure { error, original }) => (
                    Execution::StartFailed(original),
                    Err(RegistryError::Native(error)),
                ),
            },
            other => (other, Err(RegistryError::Stale)),
        };
        // Backing was allocated before admission; removal leaves room for this
        // same original record without allocating or lending it to a replacement.
        self.entries.push(Entry {
            wait,
            process,
            child,
            usage,
        });
        result
    }
    /// Available admission credit includes untaken completions and the caller's
    /// possibly narrower bound; it cannot raise this registry's allocated bound.
    #[must_use]
    pub fn credit_available(&self, maximum: usize) -> bool {
        self.next_generation.is_some()
            && self.entries.len() + self.completed.len() < self.maximum.min(maximum)
    }
    /// Actual process records whose exit has not yet been consumed by this owner.
    #[must_use]
    pub fn pending_children(&self) -> usize {
        self.entries.len()
    }
    /// Borrow live original child identities. Numeric PIDs alone grant no action.
    pub fn children(&self) -> impl Iterator<Item = &OriginalChild> {
        self.entries.iter().map(|entry| &entry.child)
    }
    /// Diagnostic PIDs for this registry's original live records.
    pub fn child_pids(&self) -> impl Iterator<Item = u32> + '_ {
        self.children().map(OriginalChild::pid)
    }
    /// Check a live original registry/generation token without any OS lookup.
    #[must_use]
    pub fn owns(&self, child: &OriginalChild) -> bool {
        self.entries.iter().any(|entry| entry.child == *child)
    }
    /// Pin immutable original-object identity while a separate startup operation
    /// qualifies its actual pipe peer. This lease does not authorize signaling,
    /// waiting or a replacement generation and may outlive an exit receipt.
    pub fn identity(&self, child: &OriginalChild) -> Result<ProcessIdentity, RegistryError> {
        let entry = self
            .entries
            .iter()
            .find(|entry| entry.child == *child)
            .ok_or(RegistryError::Stale)?;
        Ok(entry.process.original().identity())
    }
    /// Observe this original process independently of registry reaping. Windows
    /// process waits are nonconsuming; the observer retains its own original
    /// handle lease and grants no termination or replacement-PID authority.
    pub fn exit_observer(&self, child: &OriginalChild) -> Result<ProcessWait, RegistryError> {
        let entry = self
            .entries
            .iter()
            .find(|entry| entry.child == *child)
            .ok_or(RegistryError::Stale)?;
        Ok(ProcessWait::new(entry.process.original())?)
    }
    /// Request forced native termination of this exact original process handle.
    /// The exit code is not a POSIX signal, and success is not an exit receipt.
    pub fn terminate(&self, child: &OriginalChild, exit_code: u32) -> Result<(), RegistryError> {
        let entry = self
            .entries
            .iter()
            .find(|entry| entry.child == *child)
            .ok_or(RegistryError::Stale)?;
        entry.process.original().terminate(exit_code)?;
        Ok(())
    }
    /// Observe and consume every currently completed original process. Prior
    /// receipts remain available if a later native query fails. Registrations and
    /// this registry's process-handle owners release before the receipt is
    /// published. Explicit read-only identity leases may retain the object.
    pub fn reap_completed(&mut self) -> Result<usize, RegistryError> {
        let mut count = 0;
        let mut index = 0;
        while index < self.entries.len() {
            let Some(exit_code) = self.entries[index].process.original().try_wait()? else {
                index += 1;
                continue;
            };
            let completed = self.entries.swap_remove(index).complete(exit_code);
            self.completed.push_back(completed);
            count += 1;
        }
        Ok(count)
    }
    /// Take one original receipt and release its admission credit exactly once.
    /// Discards any recorded optional resource observation; use
    /// take_completed_with_usage when those counters/query errors are required.
    pub fn take_reaped(&mut self) -> Option<Reaped> {
        self.completed
            .pop_front()
            .map(|completion| completion.event)
    }
    /// Take one complete exit/resource observation and release its shared credit.
    /// Native query errors remain attached to their original fields.
    pub fn take_completed_with_usage(&mut self) -> Option<(Reaped, Option<ResourceUsage>)> {
        self.completed.pop_front().map(Completion::into_parts)
    }
    /// Consume only this original child's actual exit, preserving other receipts.
    /// A live original returns None; an unknown/consumed token is stale. Native
    /// query failure leaves its original record and admission credit unchanged.
    pub fn reap_child(&mut self, child: &OriginalChild) -> Result<Option<Reaped>, RegistryError> {
        self.reap_child_with_usage(child)
            .map(|event| event.map(|(event, _usage)| event))
    }
    /// Consume only this original child, retaining its optional native resource
    /// observations. Other children/completions and their admission credit stay
    /// untouched. An active original returns None without sampling resources.
    pub fn reap_child_with_usage(
        &mut self,
        child: &OriginalChild,
    ) -> Result<Option<(Reaped, Option<ResourceUsage>)>, RegistryError> {
        if let Some(index) = self
            .completed
            .iter()
            .position(|receipt| receipt.event.child == *child)
        {
            return Ok(self.completed.remove(index).map(Completion::into_parts));
        }
        let index = self
            .entries
            .iter()
            .position(|entry| entry.child == *child)
            .ok_or(RegistryError::Stale)?;
        let Some(exit_code) = self.entries[index].process.original().try_wait()? else {
            return Ok(None);
        };
        Ok(Some(
            self.entries
                .swap_remove(index)
                .complete(exit_code)
                .into_parts(),
        ))
    }
    /// Wait for native exit evidence without consuming a receipt. Registrations
    /// stay in this owner across canceled poll_fn futures. A failed registration
    /// leaves the original process record intact for retry or explicit handling.
    pub fn poll_child_signal(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), RegistryError>> {
        let mut ready = false;
        for entry in &mut self.entries {
            if entry.wait.is_none() {
                if entry.process.original().try_wait()?.is_some() {
                    ready = true;
                    continue;
                }
                entry.wait = Some(ProcessWait::new(entry.process.original())?);
            }
            if let Some(wait) = &mut entry.wait {
                match wait.poll_exit(cx) {
                    Poll::Ready(Ok(_)) => ready = true,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                    Poll::Pending => {}
                }
            }
        }
        if ready {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}
