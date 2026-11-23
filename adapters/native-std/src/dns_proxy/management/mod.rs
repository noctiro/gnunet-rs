//! Explicit containing-application DNS proxy preferences with original callback retirement.
//!
//! Applying an enabled configuration can activate it and disable another app's
//! DNS proxy. Callers must obtain extension activation separately. Dropping an
//! operation does not cancel or roll back its native effect; callback loans keep
//! the unique manager reservation until their actual disposal.
mod configuration;
mod ownership;
#[expect(
    unsafe_code,
    reason = "Narrow retained NEDNSProxyManager selectors and bounded Foundation decoding"
)]
mod sdk;
use super::{
    callback::{Callback, thread_safe},
    lifetime::{self, Pending},
};
use block2::RcBlock;
pub use configuration::{Configuration, Mode, Operation, Snapshot};
use objc2_foundation::NSError;
use ownership::{Exclusive, OperationGuard};
use std::{
    fmt, io,
    marker::PhantomData,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
};

enum Outcome {
    Loaded(Snapshot),
    Finished(Operation),
}

/// Exclusive thread-confined preference manager with one pending native operation.
pub struct Manager {
    native: sdk::NativeManager,
    expected: String,
    snapshot: Option<Snapshot>,
    pending: Option<Pending<Outcome>>,
    _thread: PhantomData<Rc<()>>,
    exclusive: Arc<Exclusive>,
}
impl fmt::Debug for Manager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Manager")
            .field("expected", &self.expected)
            .field("snapshot", &self.snapshot)
            .field("pending", &self.pending.is_some())
            .finish_non_exhaustive()
    }
}
impl Manager {
    /// Acquires the process singleton without loading or modifying preferences.
    pub fn new(expected_provider_bundle_id: &str) -> io::Result<Self> {
        configuration::identifier(expected_provider_bundle_id)?;
        let exclusive = Exclusive::acquire()?;
        Ok(Self {
            native: sdk::NativeManager::shared()?,
            expected: expected_provider_bundle_id.into(),
            snapshot: None,
            pending: None,
            _thread: PhantomData,
            exclusive,
        })
    }
    /// Begins loading the caller's preferences; no mutation is performed.
    pub fn begin_load(&mut self) -> io::Result<()> {
        self.idle()?;
        self.snapshot = None;
        self.start(Operation::Load);
        Ok(())
    }
    /// Saves an owned provider configuration after a successful explicit load.
    ///
    /// Enabled saves can activate the proxy and disable other applications'
    /// proxies. This method does not request extension activation or user approval.
    pub fn begin_apply(&mut self, configuration: &Configuration, mode: Mode) -> io::Result<()> {
        self.mutation(true)?;
        if configuration.identifier != self.expected {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "configuration provider differs from the manager's expected provider",
            ));
        }
        let prepared = sdk::Prepared::new(configuration)?;
        self.snapshot = None;
        self.native.apply(&prepared, mode);
        self.start(Operation::Apply);
        Ok(())
    }
    /// Disables the owned original protocol without replacing any vendor fields.
    pub fn begin_disable(&mut self) -> io::Result<()> {
        self.mutation(false)?;
        self.snapshot = None;
        self.native.disable();
        self.start(Operation::Disable);
        Ok(())
    }
    /// Removes only the original configuration matching the expected provider.
    pub fn begin_remove(&mut self) -> io::Result<()> {
        self.mutation(false)?;
        self.snapshot = None;
        self.start(Operation::Remove);
        Ok(())
    }
    /// Observes completion only after the original SDK callback loans retire.
    ///
    /// Native errors retain the original NSError. Every mutation invalidates the
    /// snapshot even on failure; load again before observing or mutating preferences.
    pub fn poll_completion(&mut self, cx: &mut Context<'_>) -> Poll<Option<io::Result<Operation>>> {
        let Some(pending) = &mut self.pending else {
            return Poll::Ready(None);
        };
        match pending.poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.pending = None;
                Poll::Ready(result.map(|result| {
                    result.map(|outcome| match outcome {
                        Outcome::Loaded(snapshot) => {
                            self.snapshot = Some(snapshot);
                            Operation::Load
                        }
                        Outcome::Finished(operation) => operation,
                    })
                }))
            }
        }
    }
    /// Returns the last successfully loaded snapshot, before any later mutation.
    pub fn snapshot(&self) -> io::Result<&Snapshot> {
        self.snapshot.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "DNS proxy preferences must be loaded",
            )
        })
    }
    fn idle(&self) -> io::Result<()> {
        if self.pending.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "an original DNS proxy preference operation is pending",
            ));
        }
        Ok(())
    }
    fn mutation(&self, create: bool) -> io::Result<()> {
        self.idle()?;
        self.snapshot()?.owned(&self.expected, create)?;
        // OS preference notifications may update the shared in-memory manager.
        // Recheck that original object's current identity; the OS additionally
        // rejects stale preference versions without an automatic overwrite retry.
        self.native.snapshot()?.owned(&self.expected, create)
    }
    fn start(&mut self, operation: Operation) {
        let (pending, publish, disposed) = lifetime::reserve();
        let guard = OperationGuard {
            context: Callback::new(publish, (), disposed, None, self.native.clone()),
            _exclusive: self.exclusive.clone(),
        };
        let callback = RcBlock::new(thread_safe(move |error: *mut NSError| {
            guard.invoke(|| {
                sdk::result(error)?;
                if operation == Operation::Load {
                    guard.data().snapshot().map(Outcome::Loaded)
                } else {
                    Ok(Outcome::Finished(operation))
                }
            });
        }));
        self.pending = Some(pending);
        self.native.begin(operation, &callback);
    }
}
