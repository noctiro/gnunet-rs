//! Original SystemExtensions requests with explicit replacement and retained callback obligations.
//!
//! The containing application's main AppKit event loop must remain running.
//! Dropping an operation or reaching a host deadline does not cancel its native
//! effect. Pending requests retain a bounded registry entry until the original
//! terminal delegate callback and deferred main-queue loan disposal.
#[expect(
    unsafe_code,
    reason = "Exact main-queue Objective-C delegate subclass and required SystemExtensions protocol callbacks"
)]
mod delegate;
mod policy;
mod registry;
#[expect(
    unsafe_code,
    reason = "Exact SystemExtensions factory/delegate selectors and original main-queue dispatch ABI"
)]
mod sdk;
mod state;

use super::{completion, lifetime::Pending};
use objc2::{MainThreadMarker, rc::Retained};
use objc2_foundation::NSString;
pub use policy::{ReplacementDecision, ReplacementPolicy, Version};
pub use state::{Event, Finished, Replacement};
use std::{
    fmt, io,
    rc::Rc,
    task::{Context, Poll},
};

/// Maximum submitted or retiring original requests in this process.
pub const MAX_OPERATIONS: usize = 8;

/// Unique main-thread observation owner for one original activation/deactivation.
#[must_use]
pub struct Operation {
    progress: Rc<state::Progress>,
    final_result: Pending<Finished>,
    consumed: bool,
}
impl fmt::Debug for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Operation")
            .field("consumed", &self.consumed)
            .finish_non_exhaustive()
    }
}
impl Operation {
    /// Submit an original activation with an explicit existing-version policy.
    /// # Errors
    /// Refuses non-main callers, invalid identifiers, duplicate in-flight bundle
    /// operations, exhausted callback capacity or unavailable native classes.
    /// Successful submission is not activation or user-approval confirmation.
    pub fn activate(identifier: &str, replacement: ReplacementPolicy) -> io::Result<Self> {
        Self::begin(identifier, sdk::Kind::Activate, replacement)
    }
    /// Submit an original deactivation; a reboot may remain necessary.
    /// # Errors
    /// Uses the same local admission checks as [`Self::activate`].
    pub fn deactivate(identifier: &str) -> io::Result<Self> {
        Self::begin(identifier, sdk::Kind::Deactivate, ReplacementPolicy::Reject)
    }
    fn begin(
        identifier: &str,
        kind: sdk::Kind,
        replacement: ReplacementPolicy,
    ) -> io::Result<Self> {
        let main = MainThreadMarker::new().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "system-extension requests require the application main thread",
            )
        })?;
        validate_identifier(identifier)?;
        sdk::available()?;
        let reservation = registry::reserve(identifier)?;
        let progress = Rc::new(state::Progress::default());
        let (final_result, publish, disposed) = super::lifetime::reserve();
        let identifier: Retained<NSString> = NSString::from_str(identifier);
        let retirement = registry::Release::reserve();
        let delegate = delegate::Delegate::new(
            main,
            delegate::Ivars {
                key: reservation.key(),
                identifier: identifier.clone(),
                replacement,
                progress: Rc::clone(&progress),
                publish: std::cell::RefCell::new(Some(publish)),
                release: std::cell::RefCell::new(Some(retirement)),
            },
        );
        let request = sdk::request(&identifier, kind)?;
        sdk::set_delegate(&request, &delegate);
        reservation.submit(request, delegate, disposed)?;
        Ok(Self {
            progress,
            final_result,
            consumed: false,
        })
    }
    /// Poll coalesced native progress and then the original final result once.
    /// Approval is pending; `AfterReboot` is not current activation. A final event
    /// waits for the deferred callback-loan disposal before becoming observable.
    /// The caller must drive the application's main event loop between polls.
    pub fn poll_event(&mut self, cx: &mut Context<'_>) -> Poll<Option<Event>> {
        if self.consumed {
            return Poll::Ready(None);
        }
        if let Poll::Ready(event) = self.progress.poll(cx) {
            return Poll::Ready(Some(event));
        }
        match self.final_result.poll(cx) {
            Poll::Ready(Some(result)) => {
                self.consumed = true;
                Poll::Ready(Some(match result {
                    Ok(done) => Event::Finished(done),
                    Err(error) => Event::Failed(error),
                }))
            }
            Poll::Ready(None) => {
                self.consumed = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
fn validate_identifier(identifier: &str) -> io::Result<()> {
    if identifier.len() > 255
        || !identifier.contains('.')
        || identifier.split('.').any(|part| {
            part.is_empty()
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid system-extension bundle identifier",
        ));
    }
    Ok(())
}

pub(super) fn contain<T>(fallback: T, body: impl FnOnce() -> T) -> T {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)) {
        Ok(value) => value,
        Err(payload) => {
            completion::dispose_panic(payload);
            fallback
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Event, Finished, Operation, state};
    use std::{
        rc::Rc,
        task::{Context, Poll, Waker},
    };

    #[test]
    fn final_native_disposition_waits_for_the_original_loan_disposal() {
        // Exercise the actual public poll owner and shared completion gate;
        // no SystemExtensions request or Objective-C delegate is constructed.
        let progress = Rc::new(state::Progress::default());
        let (final_result, publish, disposed) = super::super::lifetime::reserve();
        let mut operation = Operation {
            progress: Rc::clone(&progress),
            final_result,
            consumed: false,
        };
        let mut cx = Context::from_waker(Waker::noop());
        progress.approval();
        assert!(matches!(
            operation.poll_event(&mut cx),
            Poll::Ready(Some(Event::ApprovalRequired))
        ));
        assert!(operation.poll_event(&mut cx).is_pending());
        progress.finish();
        publish.publish(Ok(Finished::AfterReboot));
        assert!(operation.poll_event(&mut cx).is_pending());
        drop(disposed);
        assert!(matches!(
            operation.poll_event(&mut cx),
            Poll::Ready(Some(Event::Finished(Finished::AfterReboot)))
        ));
        assert!(matches!(operation.poll_event(&mut cx), Poll::Ready(None)));
    }
}
