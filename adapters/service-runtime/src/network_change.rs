use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    sync::{Notify, futures::OwnedNotified},
    time::{Instant, Sleep, sleep_until},
};

#[cfg(any(
    windows,
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "freebsd"
))]
mod monitor;
#[cfg(any(
    windows,
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "freebsd"
))]
pub use monitor::RouteMonitor;

const MINIMUM_HINT_SPACING: Duration = Duration::from_millis(250);

/// A thread-safe hint that the original scan owner should check its interfaces.
#[derive(Clone)]
pub struct NetworkChange(Arc<Notify>);

impl NetworkChange {
    /// Wake the scan owner. Repeated hints can coalesce before a scan.
    pub fn notify(&self) {
        self.0.notify_one();
    }
}

struct Wait {
    source: Arc<Notify>,
    wake: Pin<Box<OwnedNotified>>,
    pacing: Option<Pin<Box<Sleep>>>,
    pending: bool,
}

/// The sole consumer for one scan owner. The default uses its normal timers.
#[derive(Default)]
pub struct NetworkChanges(Option<Wait>);

impl NetworkChanges {
    /// Observe a coalesced hint. The owned wait survives a dropped outer poll
    /// future and stays pending if the host drops every notifier. Poll on the
    /// scan owner's Tokio time driver.
    pub fn poll_changed(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        let Some(wait) = &mut self.0 else {
            return Poll::Pending;
        };
        if !wait.pending {
            if wait.wake.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            wait.wake.set(wait.source.clone().notified_owned());
            wait.pending = true;
        }
        if wait
            .pacing
            .as_mut()
            .is_some_and(|alarm| alarm.as_mut().poll(cx).is_pending())
        {
            return Poll::Pending;
        }
        let next = Instant::now() + MINIMUM_HINT_SPACING;
        if let Some(alarm) = &mut wait.pacing {
            alarm.as_mut().reset(next);
        } else {
            wait.pacing = Some(Box::pin(sleep_until(next)));
        }
        wait.pending = false;
        Poll::Ready(())
    }
}

/// Create one notifier and its matching single consumer.
pub fn channel() -> (NetworkChange, NetworkChanges) {
    let source = Arc::new(Notify::new());
    let wake = Box::pin(source.clone().notified_owned());
    let changes = NetworkChanges(Some(Wait {
        source: source.clone(),
        wake,
        pacing: None,
        pending: false,
    }));
    (NetworkChange(source), changes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn bursts_coalesce_and_cannot_outpace_the_scan() {
        let (notifier, mut changes) = channel();
        let mut cx = Context::from_waker(std::task::Waker::noop());
        notifier.notify();
        notifier.notify();
        assert!(changes.poll_changed(&mut cx).is_ready());
        assert!(changes.poll_changed(&mut cx).is_pending());

        notifier.notify();
        assert!(changes.poll_changed(&mut cx).is_pending());
        tokio::time::advance(MINIMUM_HINT_SPACING).await;
        assert!(changes.poll_changed(&mut cx).is_ready());

        drop(notifier);
        assert!(changes.poll_changed(&mut cx).is_pending());
    }
}
