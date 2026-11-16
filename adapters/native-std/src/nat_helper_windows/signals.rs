//! Process-local console stop callback with explicit removal diagnostics.
use std::{
    io,
    sync::atomic::{AtomicBool, Ordering},
};
use windows_sys::Win32::System::Console::{
    CTRL_BREAK_EVENT, CTRL_C_EVENT, CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT,
    SetConsoleCtrlHandler,
};
static OWNED: AtomicBool = AtomicBool::new(false);
static STOP: AtomicBool = AtomicBool::new(false);
extern "system" fn control(event: u32) -> i32 {
    if matches!(
        event,
        CTRL_C_EVENT
            | CTRL_BREAK_EVENT
            | CTRL_CLOSE_EVENT
            | CTRL_LOGOFF_EVENT
            | CTRL_SHUTDOWN_EVENT
    ) {
        STOP.store(true, Ordering::Release);
        1
    } else {
        0
    }
}
/// One original process stop subscription. The callback does no I/O/allocation.
pub struct Signals {
    active: bool,
}
impl Signals {
    /// Install without console attachment, detachment or privilege changes.
    #[expect(
        unsafe_code,
        reason = "Registers only the static allocation-free callback for this process"
    )]
    pub fn install() -> io::Result<Self> {
        if OWNED.swap(true, Ordering::AcqRel) {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        STOP.store(false, Ordering::Release);
        // SAFETY: the static callback outlives registration and owns no pointers.
        if unsafe { SetConsoleCtrlHandler(Some(control), 1) } == 0 {
            OWNED.store(false, Ordering::Release);
            return Err(io::Error::last_os_error());
        }
        Ok(Self { active: true })
    }
    /// Observe a real console stop; parent/output loss is handled independently.
    pub fn stopped(&self) -> bool {
        STOP.load(Ordering::Acquire)
    }
    /// Remove this callback, preserving an actual native removal error.
    #[expect(
        unsafe_code,
        reason = "Removes the same static callback registered by this owner"
    )]
    pub fn restore(&mut self) -> io::Result<()> {
        if self.active {
            // SAFETY: removes only this owner's still-registered static callback.
            if unsafe { SetConsoleCtrlHandler(Some(control), 0) } == 0 {
                return Err(io::Error::last_os_error());
            }
            self.active = false;
            OWNED.store(false, Ordering::Release);
        }
        Ok(())
    }
}
impl Drop for Signals {
    fn drop(&mut self) {
        let _restored = self.restore();
    }
}
