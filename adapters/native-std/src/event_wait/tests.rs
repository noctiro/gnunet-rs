#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions inspect actual unprivileged Windows event waits, canceled futures and callback-safe retirement"
)]
use super::*;
use std::{
    os::windows::io::FromRawHandle,
    sync::mpsc,
    task::Wake,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT},
    System::Threading::{CreateEventW, SetEvent, WaitForSingleObject},
};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
#[expect(
    unsafe_code,
    reason = "CreateEventW transfers one checked real auto-reset event; its duplicate independently belongs to the original wait registration"
)]
fn event() -> io::Result<(OwnedHandle, Wait)> {
    // SAFETY: no attributes/name, initialized Boolean scalars, unique returned handle.
    let raw = unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
    if raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful native creation transfers exactly one owned handle.
    let original = unsafe { OwnedHandle::from_raw_handle(raw) };
    let duplicate = original.try_clone()?;
    // SAFETY: this is the independent duplicate of the real kernel event above.
    let wait = unsafe { Wait::new(duplicate) }?;
    Ok((original, wait))
}
#[expect(
    unsafe_code,
    reason = "SetEvent borrows the actual live original event created by this fixture"
)]
fn signal(event: &OwnedHandle) -> io::Result<()> {
    // SAFETY: original kernel event remains owned for the complete call.
    if unsafe { SetEvent(event.as_raw_handle()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
struct Unpark(std::thread::Thread);
impl Wake for Unpark {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
}
#[test]
fn canceled_wait_keeps_the_original_registration_and_rearms_without_a_fake_signal() -> Result {
    use std::future::{Future, poll_fn};
    let (original, mut wait) = event()?;
    let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut context = Context::from_waker(&waker);
    {
        let mut future = std::pin::pin!(poll_fn(|cx| wait.poll_ready(cx)));
        assert!(future.as_mut().poll(&mut context).is_pending());
    }
    assert!(wait.is_armed());
    signal(&original)?;
    let hard = Instant::now() + Duration::from_secs(3);
    loop {
        match wait.poll_ready(&mut context) {
            Poll::Ready(result) => {
                result?;
                break;
            }
            Poll::Pending if Instant::now() < hard => {
                std::thread::park_timeout(Duration::from_millis(10))
            }
            Poll::Pending => return Err("actual event callback did not wake".into()),
        }
    }
    assert!(!wait.is_armed());
    assert!(wait.poll_ready(&mut context).is_pending());
    drop(wait);
    // The registration closed only its duplicate; the original event still works.
    signal(&original)?;
    #[expect(
        unsafe_code,
        reason = "Two zero-timeout waits borrow the actual original auto-reset event and observe its consumed signal"
    )]
    // SAFETY: original is still owned; no foreign wait or close can reuse it.
    unsafe {
        assert_eq!(
            WaitForSingleObject(original.as_raw_handle(), 0),
            WAIT_OBJECT_0
        );
        assert_eq!(
            WaitForSingleObject(original.as_raw_handle(), 0),
            WAIT_TIMEOUT
        );
    }
    Ok(())
}
struct CloseInsideWake {
    original_wait: Mutex<Option<Wait>>,
    done: mpsc::SyncSender<()>,
}
impl Wake for CloseInsideWake {
    fn wake(self: Arc<Self>) {
        let wait = match self.original_wait.lock() {
            Ok(mut guard) => guard.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        };
        // This runs in the real Windows callback. Closing must not join itself
        // or free its callback context before the independent wake guard returns.
        drop(wait);
        let _delivered = self.done.send(());
    }
}
#[test]
fn actual_callback_can_retire_its_registration_without_joining_itself() -> Result {
    let (original, wait) = event()?;
    let (done, receiver) = mpsc::sync_channel(1);
    let owner = Arc::new(CloseInsideWake {
        original_wait: Mutex::new(Some(wait)),
        done,
    });
    let waker = Waker::from(owner.clone());
    {
        let mut guard = owner
            .original_wait
            .lock()
            .map_err(|_| "test wait mutex poisoned")?;
        let wait = guard.as_mut().ok_or("original wait missing")?;
        assert!(
            wait.poll_ready(&mut Context::from_waker(&waker))
                .is_pending()
        );
    }
    signal(&original)?;
    receiver.recv_timeout(Duration::from_secs(3))?;
    assert!(
        owner
            .original_wait
            .lock()
            .map_err(|_| "test wait mutex poisoned")?
            .is_none()
    );
    Ok(())
}
