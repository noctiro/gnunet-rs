//! Bounded coalesced progress; actual final results use the disposal-gated slot.
use super::{ReplacementDecision, Version, contain};
use std::{
    cell::RefCell,
    io,
    task::{Context, Poll, Waker},
};

/// Actual native successful request result, distinct from current running state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Finished {
    /// The original request completed; no DNS-provider readiness is implied.
    Completed,
    /// The request will complete after reboot; activation/deactivation is deferred.
    AfterReboot,
}
/// Most recent bounded replacement observation; repeated observations coalesce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Replacement {
    /// Parsed existing CFBundleVersion, when supported.
    pub existing: Option<Version>,
    /// Parsed proposed CFBundleVersion, when supported.
    pub proposed: Option<Version>,
    /// Exact local disposition; the SDK reports final success/failure separately.
    pub decision: ReplacementDecision,
    /// Total original conflict callbacks observed, saturating on overflow.
    pub observations: u32,
}
/// Original native progress or one final request result.
#[derive(Debug)]
pub enum Event {
    /// The native request is still pending user approval.
    ApprovalRequired,
    /// The delegate returned this explicit replacement disposition.
    Replacement(Replacement),
    /// Original terminal success, including deferred-after-reboot disposition.
    Finished(Finished),
    /// Original native NSError, or an explicit malformed callback result.
    Failed(io::Error),
}
#[derive(Default)]
struct Snapshot {
    approval_seen: bool,
    approval: bool,
    replacement: Option<Replacement>,
    replacements: u32,
    finished: bool,
    waker: Option<Waker>,
}
#[derive(Default)]
pub(super) struct Progress(RefCell<Snapshot>);
impl Progress {
    pub(super) fn approval(&self) {
        let wake = {
            let mut state = self.0.borrow_mut();
            if state.finished || state.approval_seen {
                return;
            }
            state.approval_seen = true;
            state.approval = true;
            state.waker.take()
        };
        wake_callback(wake);
    }
    pub(super) fn replacement(
        &self,
        existing: Option<Version>,
        proposed: Option<Version>,
        decision: ReplacementDecision,
    ) {
        let wake = {
            let mut state = self.0.borrow_mut();
            if state.finished {
                return;
            }
            state.replacements = state.replacements.saturating_add(1);
            state.replacement = Some(Replacement {
                existing,
                proposed,
                decision,
                observations: state.replacements,
            });
            state.waker.take()
        };
        wake_callback(wake);
    }
    pub(super) fn finish(&self) {
        let wake = {
            let mut state = self.0.borrow_mut();
            state.finished = true;
            state.waker.take()
        };
        wake_callback(wake);
    }
    pub(super) fn poll(&self, cx: &mut Context<'_>) -> Poll<Event> {
        let candidate = cx.waker().clone();
        let (event, previous) = {
            let mut state = self.0.borrow_mut();
            let event = if std::mem::take(&mut state.approval) {
                Some(Event::ApprovalRequired)
            } else {
                state.replacement.take().map(Event::Replacement)
            };
            let previous = if event.is_none() && !state.finished {
                state.waker.replace(candidate)
            } else {
                state.waker.take()
            };
            (event, previous)
        };
        drop(previous);
        event.map_or(Poll::Pending, Poll::Ready)
    }
}
fn wake_callback(waker: Option<Waker>) {
    if let Some(waker) = waker {
        contain((), || waker.wake());
    }
}

#[cfg(test)]
mod tests {
    use super::{Event, Progress};
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll, Wake, Waker},
    };
    struct Counter(AtomicUsize);
    impl Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    #[test]
    fn approval_is_pending_one_shot_and_final_closes_late_progress() {
        let state = Progress::default();
        let count = Arc::new(Counter(AtomicUsize::new(0)));
        let waker = Waker::from(count.clone());
        let mut cx = Context::from_waker(&waker);
        assert!(state.poll(&mut cx).is_pending());
        state.approval();
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert!(matches!(
            state.poll(&mut cx),
            Poll::Ready(Event::ApprovalRequired)
        ));
        state.approval();
        assert!(state.poll(&mut cx).is_pending());
        state.finish();
        state.approval();
        assert!(state.poll(&mut cx).is_pending());
    }
}
