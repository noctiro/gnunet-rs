//! Pure result delivery fixtures; no provider, handle or native I/O is used.
use super::*;
use std::{
    error::Error,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::Wake,
};

#[derive(Default)]
struct Notifications(AtomicUsize);
impl Wake for Notifications {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn queried_native_status_and_extent_survive_delivery_and_are_consumed_once() -> io::Result<()> {
    let notifications = Arc::new(Notifications::default());
    let waker = Waker::from(Arc::clone(&notifications));
    let mut cx = Context::from_waker(&waker);
    let success = Notice::new();
    if !success.pending() || !success.poll(&mut cx).is_pending() {
        return Err(io::Error::other("new operation was already complete"));
    }
    if let Some(waker) = success.publish(Ok(Ok(53))) {
        waker.wake();
    }
    if success.pending()
        || notifications.0.load(Ordering::Relaxed) != 1
        || !matches!(success.poll(&mut cx), Poll::Ready(Ok(53)))
        || !matches!(success.poll(&mut cx), Poll::Ready(Err(_)))
    {
        return Err(io::Error::other(
            "native success was lost or delivered twice",
        ));
    }

    for code in [995, 232, 1234] {
        let failure = Notice::new();
        let wake = failure.publish(Ok(Err(io::Error::from_raw_os_error(code))));
        if wake.is_some() {
            return Err(io::Error::other("unregistered operation acquired a waiter"));
        }
        let Poll::Ready(Err(error)) = failure.poll(&mut cx) else {
            return Err(io::Error::other("original native error was not delivered"));
        };
        if error.raw_os_error() != Some(code) || error.get_ref().is_some() {
            return Err(io::Error::other(format!(
                "native error {code} changed during completion delivery"
            )));
        }
    }
    Ok(())
}

#[test]
fn lost_original_handle_never_becomes_a_native_cancellation_receipt() -> io::Result<()> {
    let notice = Notice::new();
    let wake = notice.publish(Err(io::ErrorKind::NotConnected.into()));
    if wake.is_some() {
        return Err(io::Error::other("unregistered operation acquired a waiter"));
    }
    let mut cx = Context::from_waker(Waker::noop());
    let Poll::Ready(Err(error)) = notice.poll(&mut cx) else {
        return Err(io::Error::other("missing original handle was not reported"));
    };
    if error.kind() != io::ErrorKind::NotConnected || error.raw_os_error().is_some() {
        return Err(io::Error::other("handle loss became a native status"));
    }
    let unavailable = error
        .get_ref()
        .and_then(|cause| cause.downcast_ref::<CompletionStatusUnavailable>())
        .ok_or_else(|| io::Error::other("native status uncertainty lost its typed cause"))?;
    if unavailable.original.kind() != io::ErrorKind::NotConnected
        || unavailable.original.raw_os_error().is_some()
        || unavailable.source().is_none()
        || !matches!(notice.poll(&mut cx), Poll::Ready(Err(_)))
    {
        return Err(io::Error::other(
            "original handle loss was lost or delivered twice",
        ));
    }
    Ok(())
}

#[test]
fn detaching_releases_the_waiter_and_preserves_late_native_completion() {
    let notifications = Arc::new(Notifications::default());
    let waker = Waker::from(Arc::clone(&notifications));
    let mut cx = Context::from_waker(&waker);
    let notice = Notice::new();
    assert!(notice.poll(&mut cx).is_pending());
    assert_eq!(Arc::strong_count(&notifications), 3);

    notice.detach_observer();
    assert_eq!(Arc::strong_count(&notifications), 2);
    assert!(notice.pending());
    assert!(notice.publish(Ok(Ok(53))).is_none());
    assert!(matches!(notice.poll(&mut cx), Poll::Ready(Ok(53))));
}
