//! Explicit WinDivert packet capture/injection with original overlapped I/O loans.
mod abi;
mod observations;
mod operation;
mod route;
use crate::library::Library;
use abi::Api;
pub use operation::{Completion, InjectionLengthError, Request};
pub use route::{CapturedAddress, ReplyAddress, RouteUnavailable};
use std::{
    ffi::CStr,
    fmt, io,
    path::Path,
    sync::{Arc, Mutex, atomic::AtomicBool},
};
use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
/// Finite native queue controls, separate from caller-owned packet buffers.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Native queue packets, 32..=16384.
    pub packets: u64,
    /// Native queue bytes, 65535..=33554432.
    pub bytes: u64,
    /// Native queue residence bound, 100..=16000 milliseconds.
    pub millis: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            packets: 128,
            bytes: 1024 * 1024,
            millis: 1000,
        }
    }
}
impl Limits {
    fn validate(self) -> io::Result<()> {
        if !(32..=16384).contains(&self.packets)
            || !(65535..=33554432).contains(&self.bytes)
            || !(100..=16000).contains(&self.millis)
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(())
    }
}
/// One explicitly selected official provider; loading does not open a filter.
#[derive(Clone)]
pub struct Driver(Arc<Api>);
impl fmt::Debug for Driver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WinDivertDriver").finish_non_exhaustive()
    }
}
impl Driver {
    /// Load an absolute provider path and resolve the official 2.2 ABI.
    ///
    /// # Safety
    /// The caller trusts this provider and dependencies, certifies the exact C
    /// ABI, and permits its thread-safe calls/destruction on completion threads.
    #[expect(
        unsafe_code,
        reason = "The caller explicitly certifies native provider code and its thread-safe official C ABI"
    )]
    pub unsafe fn load(path: &Path) -> io::Result<Self> {
        // SAFETY: the caller transfers the explicit DLL/ABI trust boundary.
        let library = unsafe { Library::load(path) }?;
        // SAFETY: the same contract covers every resolved export.
        Ok(Self(Arc::new(unsafe { Api::resolve(library) }?)))
    }
    /// Open a NETWORK filter using an already installed driver.
    /// Filter text is caller-selected native policy, not a GNUnet wire format.
    /// No driver installation or alternate provider is attempted.
    #[expect(
        unsafe_code,
        reason = "The typed trusted export borrows a terminated filter and returns one original handle; all scalar SDK results are captured immediately"
    )]
    pub fn open(&self, filter: &CStr, priority: i16, limits: Limits) -> io::Result<Session> {
        limits.validate()?;
        if !(-30000..=30000).contains(&priority) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let compartment = crate::interfaces::compartment();
        let (since, identities) = route::interface_snapshot()?;
        let observations = observations::History::new(since, identities)?;
        // SAFETY: terminated filter remains live; NETWORK=0, NO_INSTALL=0x10.
        let handle = unsafe { (self.0.open)(filter.as_ptr(), 0, priority, 0x10) };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let session = Session(Arc::new(Device {
            api: Arc::clone(&self.0),
            compartment,
            observations: Mutex::new(observations),
            handle: Mutex::new(Some(handle as usize)),
            receive: AtomicBool::new(false),
            send: AtomicBool::new(false),
        }));
        let setup = {
            let mut major = 0;
            let mut minor = 0;
            session.0.call(|raw| {
                // SAFETY: original handle and initialized scalar outputs remain live.
                if unsafe { (self.0.get)(raw, 3, &mut major) } == 0 {
                    return Err(io::Error::last_os_error());
                }
                // SAFETY: same original live handle and initialized output.
                if unsafe { (self.0.get)(raw, 4, &mut minor) } == 0 {
                    return Err(io::Error::last_os_error());
                }
                if major != 2 || minor != 2 {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "WinDivert 2.2 driver is required",
                    ));
                }
                for (parameter, value) in
                    [(0, limits.packets), (1, limits.millis), (2, limits.bytes)]
                {
                    // SAFETY: validated queue values and original owned handle.
                    if unsafe { (self.0.set)(raw, parameter, value) } == 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                Ok(())
            })
        };
        if let Err(original) = setup {
            let close = session.close().err();
            return Err(io::Error::other(OpenFailure { original, close }));
        }
        Ok(session)
    }
}
#[derive(Debug)]
/// Failed post-open setup and its independent original close observation.
#[non_exhaustive]
pub struct OpenFailure {
    /// Original version or native queue configuration failure.
    pub original: io::Error,
    /// Failure to close the already opened filter; retirement is unconfirmed.
    pub close: Option<io::Error>,
}
impl fmt::Display for OpenFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "WinDivert setup: {}; close={:?}",
            self.original, self.close
        )
    }
}
impl std::error::Error for OpenFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}
struct Device {
    pub api: Arc<Api>,
    pub compartment: u32,
    observations: Mutex<observations::History>,
    handle: Mutex<Option<usize>>,
    pub receive: AtomicBool,
    pub send: AtomicBool,
}
impl Device {
    #[expect(
        clippy::expect_used,
        reason = "A poisoned provenance cache is fatal; native loans must never use recovered data to invent interface identity"
    )]
    fn route_observations(&self) -> std::sync::MutexGuard<'_, observations::History> {
        self.observations
            .lock()
            .expect("capture interface observations poisoned")
    }
    pub fn call<T>(&self, operation: impl FnOnce(HANDLE) -> io::Result<T>) -> io::Result<T> {
        let guard = self
            .handle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let raw = guard.ok_or(io::ErrorKind::NotConnected)?;
        operation(raw as HANDLE)
    }
    #[expect(
        unsafe_code,
        reason = "The original handle is removed under its mutex and closed once; callbacks cannot query or cancel a numerically reused handle"
    )]
    fn close(&self) -> io::Result<()> {
        let mut guard = self
            .handle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(raw) = guard.take() else {
            return Ok(());
        };
        // SAFETY: this is the one original handle, still excluded from other calls.
        if unsafe { (self.api.close)(raw as HANDLE) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
impl Drop for Device {
    fn drop(&mut self) {
        let _closed = self.close();
    }
}
/// Original filter handle. Pending requests retain its provider and their buffers.
/// Closing removes admission once; callbacks keep canceled loan storage alive.
pub struct Session(Arc<Device>);
impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WinDivertSession").finish_non_exhaustive()
    }
}
impl Session {
    /// Refresh complete interface observations without replacing the capture
    /// filter or its original I/O loans. Earlier captures keep their old view.
    ///
    /// # Errors
    /// Native query, malformed/oversized table, compartment and clock errors
    /// leave the previous observations intact.
    ///
    /// # Panics
    /// Panics if the shared interface-observation mutex was poisoned.
    pub fn refresh_routes(&self) -> io::Result<()> {
        if crate::interfaces::compartment() != self.0.compartment {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "original capture compartment changed",
            ));
        }
        let (since, identities) = route::interface_snapshot()?;
        let prepared = observations::View::new(since, identities)?;
        let retired = self.0.route_observations().publish(prepared)?;
        drop(retired);
        Ok(())
    }
    /// Admit one bounded capture operation without a blocking receive worker.
    pub fn receive(&self, bytes: usize) -> io::Result<Request> {
        if crate::interfaces::compartment() != self.0.compartment {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "original capture compartment changed",
            ));
        }
        Request::receive(Arc::clone(&self.0), bytes)
    }
    /// Inject a complete reply using metadata from this exact original session.
    /// Checksums must already be correct; no payload or checksum is rewritten.
    pub fn send(&self, packet: Vec<u8>, address: &ReplyAddress) -> io::Result<Request> {
        let packet = zeroize::Zeroizing::new(packet);
        if !std::sync::Weak::ptr_eq(&address.owner, &Arc::downgrade(&self.0)) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        address.check().map_err(io::Error::other)?;
        Request::send(Arc::clone(&self.0), packet, address.raw)
    }
    /// Stop queuing and injecting new packets. Existing loans still need completion.
    #[expect(
        unsafe_code,
        reason = "The documented shutdown export borrows the retained original handle under its exclusive close/query guard"
    )]
    pub fn shutdown(&self) -> io::Result<()> {
        self.0.call(|raw| {
            // SAFETY: original live handle, BOTH=3, no retained pointer arguments.
            if unsafe { (self.0.api.shutdown)(raw, 3) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        })
    }
    /// Close this original filter exactly once. This is independent of whether
    /// a pending send committed; its completion and unknown exposure remain separate.
    pub fn close(&self) -> io::Result<()> {
        self.0.close()
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        let _closed = self.close();
    }
}
