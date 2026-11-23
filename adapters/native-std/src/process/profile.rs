//! Scoped Windows account profile with cleanup triggered by the original process.
use super::{LaunchLimits, PrimaryToken, Process, environment::wide, launch::ProcessObject};
use crate::identity::{self, Sid};
use std::{
    ffi::{OsString, c_void},
    io,
    num::NonZeroUsize,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle},
    ptr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
};
use windows_sys::Win32::{
    Foundation::{GetLastError, WAIT_OBJECT_0},
    System::{
        GroupPolicy::PI_NOUI,
        Threading::{
            CallbackMayRunLong, CloseThreadpoolWait, CreateEventW, CreateThreadpoolWait,
            PTP_CALLBACK_INSTANCE, PTP_WAIT, SetThreadpoolWait,
        },
    },
    UI::Shell::{LoadUserProfileW, PROFILEINFOW, UnloadUserProfile},
};

/// Actual cleanup of the selected Windows profile, independently of process exit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileRetirement {
    /// Native UnloadUserProfile succeeded after the original wait was signaled.
    Unloaded,
    /// Native UnloadUserProfile refused cleanup with the original Win32 status.
    Failed {
        /// Error returned for the actual held profile and token.
        os_error: u32,
    },
    /// The native registration returned an unexpected observation.
    WaitRefused,
    /// The supervisor stopped waiting; the original native cleanup still owns the profile.
    WaitDeadline,
}

#[derive(Default)]
struct Observation {
    result: Option<ProfileRetirement>,
    waker: Option<Waker>,
}

/// A read-only receipt subscription. Dropping it never unloads a still-live process's profile.
pub struct ProfileCleanup(Arc<Mutex<Observation>>);
impl ProfileCleanup {
    /// Original completed cleanup observation, if already available.
    #[must_use]
    pub fn result(&self) -> Option<ProfileRetirement> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .result
    }

    /// Observe original cleanup without blocking the caller or polling the process.
    pub fn poll(&self, cx: &mut Context<'_>) -> Poll<ProfileRetirement> {
        let mut observation = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(result) = observation.result {
            return Poll::Ready(result);
        }
        if observation
            .waker
            .as_ref()
            .is_none_or(|old| !old.will_wake(cx.waker()))
        {
            observation.waker = Some(cx.waker().clone());
        }
        Poll::Pending
    }
}
impl Drop for ProfileCleanup {
    fn drop(&mut self) {
        let waker = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .waker
            .take();
        drop(waker);
    }
}

struct Loaded {
    token: PrimaryToken,
    // The returned HKEY is consumed only by UnloadUserProfile. It must not be
    // converted to OwnedHandle or passed to CloseHandle/RegCloseKey.
    key: NonZeroUsize,
}
impl Loaded {
    #[expect(
        unsafe_code,
        reason = "LoadUserProfileW fills one initialized profile record for the retained verified token"
    )]
    fn open(token: PrimaryToken) -> io::Result<Self> {
        let name = identity::account_name(token.user())?;
        let mut name = wide(&name, 32767)?;
        name.push(0);
        let mut info = PROFILEINFOW {
            dwSize: size_of::<PROFILEINFOW>() as u32,
            dwFlags: PI_NOUI,
            lpUserName: name.as_mut_ptr(),
            ..PROFILEINFOW::default()
        };
        // SAFETY: token and terminated name stay live for the synchronous call.
        if unsafe { LoadUserProfileW(token.raw(), &mut info) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let key = NonZeroUsize::new(info.hProfile as usize).ok_or(io::ErrorKind::InvalidData)?;
        Ok(Self { token, key })
    }

    #[expect(
        unsafe_code,
        reason = "UnloadUserProfile is the sole consumer of the original token/profile pair"
    )]
    fn unload(self) -> ProfileRetirement {
        // SAFETY: the native profile and token are the exact original pair.
        if unsafe { UnloadUserProfile(self.token.raw(), self.key.get() as RawHandle) } != 0 {
            ProfileRetirement::Unloaded
        } else {
            // SAFETY: same thread immediately samples the failed native call.
            let os_error = unsafe { GetLastError() };
            ProfileRetirement::Failed { os_error }
        }
    }
}

enum Trigger {
    BeforeLaunch(OwnedHandle),
    Child(Arc<ProcessObject>),
}
impl Trigger {
    fn raw(&self) -> RawHandle {
        match self {
            Self::BeforeLaunch(event) => event.as_raw_handle(),
            Self::Child(process) => process.handle.as_raw_handle(),
        }
    }
}
struct Callback {
    trigger: Trigger,
    profile: Option<Loaded>,
    observation: Arc<Mutex<Observation>>,
    _credit: Credit,
}

// A slow OS profile operation must retain its credit, even if the supervisor
// has returned a timed-out receipt or dropped its registry.
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
const MAX_ACTIVE: usize = 64;
struct Credit;
impl Credit {
    fn acquire() -> io::Result<Self> {
        ACTIVE
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < MAX_ACTIVE).then_some(count + 1)
            })
            .map_err(|_| io::ErrorKind::ResourceBusy)?;
        Ok(Self)
    }
}
impl Drop for Credit {
    fn drop(&mut self) {
        ACTIVE.fetch_sub(1, Ordering::AcqRel);
    }
}
struct Prepared {
    wait: PTP_WAIT,
    callback: Box<Callback>,
}

/// An original loaded profile and an unarmed native cleanup reservation.
/// Dropping before launch triggers unload off the caller's thread. Once applied
/// to a child, the native wait retains the profile through that exact process exit.
pub struct AccountProfile(Option<Prepared>);
impl AccountProfile {
    /// Load the profile for the verified primary token, with no interactive UI.
    /// The caller needs the native privileges required by LoadUserProfileW.
    #[expect(
        unsafe_code,
        reason = "Reserve an original private event and one unarmed native wait before loading a profile"
    )]
    pub fn load(token: PrimaryToken) -> io::Result<Self> {
        let credit = Credit::acquire()?;
        // SAFETY: unnamed event borrows no external security data; success transfers its handle.
        let event = unsafe { CreateEventW(ptr::null(), 1, 1, ptr::null()) };
        if event.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: this is the unique successful native event handle.
        let event = unsafe { OwnedHandle::from_raw_handle(event) };
        let mut callback = Box::new(Callback {
            trigger: Trigger::BeforeLaunch(event),
            profile: None,
            observation: Arc::new(Mutex::new(Observation::default())),
            _credit: credit,
        });
        // SAFETY: the pinned box remains owned until registration is closed or the one-shot wait takes it.
        let wait = unsafe {
            CreateThreadpoolWait(
                Some(retire),
                ptr::from_mut(callback.as_mut()).cast(),
                ptr::null(),
            )
        };
        if wait == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut original = Self(Some(Prepared { wait, callback }));
        let prepared = original.0.as_mut().ok_or(io::ErrorKind::InvalidData)?;
        prepared.callback.profile = Some(Loaded::open(token)?);
        Ok(original)
    }

    pub(crate) fn token(&self) -> io::Result<&PrimaryToken> {
        self.0
            .as_ref()
            .and_then(|owner| owner.callback.profile.as_ref())
            .map(|profile| &profile.token)
            .ok_or_else(|| io::ErrorKind::InvalidData.into())
    }

    /// Verified SID used for the original private control pipe.
    pub fn user(&self) -> io::Result<&Sid> {
        Ok(self.token()?.user())
    }

    /// Build the selected account environment while its original profile is loaded.
    pub fn environment(&self, limits: LaunchLimits) -> io::Result<Vec<(OsString, OsString)>> {
        self.token()?.environment(limits)
    }

    pub(super) fn cleanup(&self) -> io::Result<ProfileCleanup> {
        self.0
            .as_ref()
            .map(|owner| ProfileCleanup(owner.callback.observation.clone()))
            .ok_or_else(|| io::ErrorKind::InvalidData.into())
    }

    pub(super) fn attach(mut self, process: &Process) {
        if let Some(mut original) = self.0.take() {
            original.callback.trigger = Trigger::Child(process.0.clone());
            original.arm();
        }
    }
}
impl Drop for AccountProfile {
    fn drop(&mut self) {
        if let Some(original) = self.0.take() {
            original.arm();
        }
    }
}

impl Prepared {
    #[expect(
        unsafe_code,
        reason = "Transfer exactly one boxed native callback context before arming its one-shot wait"
    )]
    fn arm(self) {
        if self.callback.profile.is_none() {
            // SAFETY: this original wait has never been armed; no callback can use the box.
            unsafe { CloseThreadpoolWait(self.wait) };
            return;
        }
        let trigger = self.callback.trigger.raw();
        let observation = self.callback.observation.clone();
        // A fast native completion may run immediately on a pool thread.
        // Keep its trigger and wait alive until the arming call returns.
        let arming = observation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _callback = Box::into_raw(self.callback);
        // SAFETY: the raw context owns the live trigger until this one-shot callback completes.
        unsafe { SetThreadpoolWait(self.wait, trigger, ptr::null()) };
        drop(arming);
    }
}

#[expect(
    unsafe_code,
    reason = "The native one-shot callback consumes the pre-reserved box and closes only its original wait"
)]
unsafe extern "system" fn retire(
    instance: PTP_CALLBACK_INSTANCE,
    context: *mut c_void,
    wait: PTP_WAIT,
    result: u32,
) {
    // SAFETY: scheduling transfers the unique box and never rearms this native wait.
    let mut owner = unsafe { Box::from_raw(context.cast::<Callback>()) };
    // The scheduler holds this mutex until SetThreadpoolWait has returned.
    drop(
        owner
            .observation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    );
    // SAFETY: callback can request pool capacity for a blocking profile unload.
    let _capacity = unsafe { CallbackMayRunLong(instance) };
    // SAFETY: close is asynchronous while this callback is running; the owned trigger stays live.
    unsafe { CloseThreadpoolWait(wait) };
    let receipt = match (result, owner.profile.take()) {
        (WAIT_OBJECT_0, Some(profile)) => profile.unload(),
        _ => ProfileRetirement::WaitRefused,
    };
    let waker = {
        let mut observation = owner
            .observation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        observation.result = Some(receipt);
        observation.waker.take()
    };
    if let Some(waker) = waker {
        let _ready = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| waker.wake()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        task::Wake,
    };

    struct Task(AtomicUsize);
    impl Wake for Task {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn dropping_observer_releases_waiting_task_while_cleanup_still_owns_state() {
        let native_observation = Arc::new(Mutex::new(Observation::default()));
        let cleanup = ProfileCleanup(native_observation.clone());
        let task = Arc::new(Task(AtomicUsize::new(0)));
        let lifetime = Arc::downgrade(&task);
        let waker = Waker::from(task);
        assert!(cleanup.poll(&mut Context::from_waker(&waker)).is_pending());
        drop(waker);
        assert!(
            lifetime
                .upgrade()
                .is_some_and(|task| task.0.load(Ordering::Relaxed) == 0)
        );
        drop(cleanup);
        assert!(lifetime.upgrade().is_none());
        assert!(
            native_observation
                .lock()
                .is_ok_and(|observation| observation.result.is_none())
        );
    }
}
