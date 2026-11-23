//! Coalesced Windows interface, address and route hints with original subscriptions.
//!
//! Notifications require a fresh authoritative snapshot; callback rows are never
//! retained or interpreted. The IP Helper callbacks only set one auto-reset
//! event. Caller wake code runs through the independent [`crate::event_wait`]
//! owner, outside the IP Helper callback, so it can safely retire this owner.
//!
//! [`NotifyIpInterfaceChange`](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-notifyipinterfacechange),
//! [`NotifyUnicastIpAddressChange`](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-notifyunicastipaddresschange)
//! and [`NotifyRouteChange2`](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-notifyroutechange2)
//! subscribe to both IP families. Their original registrations are retired with
//! [`CancelMibChangeNotify2`](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-cancelmibchangenotify2),
//! which must not run inside their callbacks or while holding callback dependencies.
use crate::event_wait::Wait;
use std::{
    ffi::c_void,
    fmt, io,
    num::NonZeroUsize,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    task::{Context, Poll},
};
use windows_sys::Win32::{
    Foundation::{ERROR_INVALID_FUNCTION, GetLastError},
    NetworkManagement::IpHelper::{
        CancelMibChangeNotify2, MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE,
        MIB_UNICASTIPADDRESS_ROW, NotifyIpInterfaceChange, NotifyRouteChange2,
        NotifyUnicastIpAddressChange,
    },
    Networking::WinSock::AF_UNSPEC,
    System::Threading::{CreateEventW, SetEvent},
};

struct Signal {
    event: OwnedHandle,
    enabled: AtomicBool,
    failure: AtomicU32,
}

impl Signal {
    #[expect(
        unsafe_code,
        reason = "The registration retains this original owned kernel event until all callback uses have retired"
    )]
    fn hint(&self) {
        if !self.enabled.load(Ordering::Acquire) {
            return;
        }
        // SAFETY: the signal owns this event independently of the caller's wait.
        if unsafe { SetEvent(self.event.as_raw_handle()) } == 0 {
            // SAFETY: read the error from this thread immediately after SetEvent.
            let error = unsafe { GetLastError() }.max(ERROR_INVALID_FUNCTION);
            let _first =
                self.failure
                    .compare_exchange(0, error, Ordering::AcqRel, Ordering::Acquire);
        }
    }

    fn result(&self) -> io::Result<()> {
        match self.failure.load(Ordering::Acquire) {
            0 => Ok(()),
            error => Err(io::Error::from_raw_os_error(error as i32)),
        }
    }
}

enum Subscription {
    Interface,
    Address,
    Route,
}

/// One original set of Windows network subscriptions and a coalesced wake event.
///
/// Own this across canceled waiting futures. There is no event queue, callback
/// allocation, background task or native row retention. An event means only that
/// the host should recheck its network, not that a route or DNS server is usable.
/// Explicit [`Self::close`] reports native cancellation errors. Drop retries
/// cancellation; if it still fails, the disabled callback context and its event
/// remain allocated until process exit rather than invalidating a native loan.
pub struct RouteNotifications {
    // IP Helper handles are opaque scalar tokens, not CloseHandle resources.
    // Storing their values also permits moving this owner between caller threads.
    registrations: [Option<NonZeroUsize>; 3],
    signal: Arc<Signal>,
    wait: Option<Wait>,
}

impl fmt::Debug for RouteNotifications {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RouteNotifications")
            .field(
                "registrations",
                &self.registrations.iter().flatten().count(),
            )
            .field("closed", &self.wait.is_none())
            .finish_non_exhaustive()
    }
}

impl RouteNotifications {
    /// Subscribe to native interface, unicast-address and route changes for both IP families.
    ///
    /// No initial hint is synthesized: the host must take its initial snapshot
    /// after subscribing. Changes during setup remain coalesced in the event.
    ///
    /// # Errors
    /// Preserves event, wait and registration failures. Partial subscriptions are
    /// canceled before returning; any cancellation failure accompanies the
    /// initiating error and retains the disabled original callback context.
    #[expect(
        unsafe_code,
        reason = "A real unnamed event is transferred to OwnedHandle and its independently owned duplicate to the checked native wait boundary"
    )]
    pub fn subscribe() -> io::Result<Self> {
        // SAFETY: no attributes/name; false selects an initially clear auto-reset
        // event, so arbitrarily many notifications occupy one kernel signal bit.
        let event = unsafe { CreateEventW(ptr::null(), 0, 0, ptr::null()) };
        if event.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful creation transfers exactly one live kernel handle.
        let event = unsafe { OwnedHandle::from_raw_handle(event) };
        let duplicate = event.try_clone()?;
        // SAFETY: the duplicate refers to the real auto-reset event just created.
        let wait = unsafe { Wait::new(duplicate) }?;
        let mut owner = Self {
            registrations: [None; 3],
            signal: Arc::new(Signal {
                event,
                enabled: AtomicBool::new(true),
                failure: AtomicU32::new(0),
            }),
            wait: Some(wait),
        };
        if let Err(registration) = owner.register() {
            return match owner.close() {
                Ok(()) => Err(registration),
                Err(cancellation) => Err(io::Error::other(RegistrationFailure {
                    registration,
                    cancellation,
                })),
            };
        }
        Ok(owner)
    }

    #[expect(
        unsafe_code,
        reason = "All native registrations borrow one stable Arc context until cancellation joins the callbacks; callback signatures match the exact SDK row types"
    )]
    fn register(&mut self) -> io::Result<()> {
        let context = Arc::as_ptr(&self.signal).cast();
        for (slot, subscription) in self.registrations.iter_mut().zip([
            Subscription::Interface,
            Subscription::Address,
            Subscription::Route,
        ]) {
            let mut handle = ptr::null_mut();
            // SAFETY: context and output storage remain valid; AF_UNSPEC covers
            // both families. No initial confirmation callback is requested.
            let result = unsafe {
                match subscription {
                    Subscription::Interface => NotifyIpInterfaceChange(
                        AF_UNSPEC,
                        Some(interface_changed),
                        context,
                        false,
                        &raw mut handle,
                    ),
                    Subscription::Address => NotifyUnicastIpAddressChange(
                        AF_UNSPEC,
                        Some(address_changed),
                        context,
                        false,
                        &raw mut handle,
                    ),
                    Subscription::Route => NotifyRouteChange2(
                        AF_UNSPEC,
                        Some(route_changed),
                        context,
                        false,
                        &raw mut handle,
                    ),
                }
            };
            if result != 0 {
                return Err(io::Error::from_raw_os_error(result as i32));
            }
            let Some(handle) = NonZeroUsize::new(handle.expose_provenance()) else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "network notification registration returned no handle",
                ));
            };
            *slot = Some(handle);
        }
        Ok(())
    }

    /// Poll one coalesced native hint without taking a network or DNS snapshot.
    ///
    /// # Errors
    /// Reports event delivery/wait failures, or `BrokenPipe` after close begins.
    /// Notifications are hints and do not report native route-application success.
    pub fn poll_changed(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(wait) = &mut self.wait else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "network notification subscription is closed",
            )));
        };
        self.signal.result()?;
        let result = wait.poll_ready(cx);
        self.signal.result()?;
        result
    }

    /// Fence delivery and cancel every original subscription outside its callback.
    ///
    /// No caller mutex or callback dependency is held while native cancellation
    /// joins callbacks. Successful cancellation is not repeated. Failed original
    /// registrations remain owned and disabled so a subsequent close can retry.
    ///
    /// # Errors
    /// Returns the first cancellation error after attempting all subscriptions.
    /// Delivery remains fenced even on failure; this is not a network cleanup
    /// receipt. Hosts should call this explicitly to report teardown failures.
    #[expect(
        unsafe_code,
        reason = "Only original nonzero notification tokens reach the documented cancellation API, after delivery is fenced and without callback dependencies"
    )]
    pub fn close(&mut self) -> io::Result<()> {
        self.signal.enabled.store(false, Ordering::Release);
        let mut failure = None;
        for slot in &mut self.registrations {
            let Some(handle) = *slot else {
                continue;
            };
            // SAFETY: original IP Helper token, not a kernel CloseHandle loan.
            // IP Helper callbacks never invoke user code or call cancellation.
            let result =
                unsafe { CancelMibChangeNotify2(ptr::with_exposed_provenance_mut(handle.get())) };
            if result == 0 {
                *slot = None;
            } else if failure.is_none() {
                failure = Some(io::Error::from_raw_os_error(result as i32));
            }
        }
        // The duplicate wait can retire even if a failed native subscription
        // still borrows Signal: that context owns an independent event handle.
        drop(self.wait.take());
        failure.map_or(Ok(()), Err)
    }
}

impl Drop for RouteNotifications {
    fn drop(&mut self) {
        if self.close().is_err() {
            // A failing cancellation supplies no callback-retirement proof.
            // Retain one disabled context for all remaining registrations; no
            // callback can access the dropped wait or a later owner generation.
            let _retained_context = Arc::into_raw(Arc::clone(&self.signal));
        }
    }
}

#[derive(Debug)]
struct RegistrationFailure {
    registration: io::Error,
    cancellation: io::Error,
}

impl fmt::Display for RegistrationFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "network notification registration failed: {}; cancellation failed: {}",
            self.registration, self.cancellation
        )
    }
}

impl std::error::Error for RegistrationFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.registration)
    }
}

#[expect(
    unsafe_code,
    reason = "IP Helper supplies the exact callback ABI and a stable live Signal context; the optional OS-owned row is neither read nor retained"
)]
unsafe extern "system" fn interface_changed(
    context: *const c_void,
    _row: *const MIB_IPINTERFACE_ROW,
    _kind: MIB_NOTIFICATION_TYPE,
) {
    // SAFETY: original context stays live until native callback retirement.
    unsafe { &*context.cast::<Signal>() }.hint();
}

#[expect(
    unsafe_code,
    reason = "IP Helper supplies the exact callback ABI and a stable live Signal context; the optional OS-owned row is neither read nor retained"
)]
unsafe extern "system" fn address_changed(
    context: *const c_void,
    _row: *const MIB_UNICASTIPADDRESS_ROW,
    _kind: MIB_NOTIFICATION_TYPE,
) {
    // SAFETY: original context stays live until native callback retirement.
    unsafe { &*context.cast::<Signal>() }.hint();
}

#[expect(
    unsafe_code,
    reason = "IP Helper supplies the exact callback ABI and a stable live Signal context; the optional OS-owned row is neither read nor retained"
)]
unsafe extern "system" fn route_changed(
    context: *const c_void,
    _row: *const MIB_IPFORWARD_ROW2,
    _kind: MIB_NOTIFICATION_TYPE,
) {
    // SAFETY: original context stays live until native callback retirement.
    unsafe { &*context.cast::<Signal>() }.hint();
}
