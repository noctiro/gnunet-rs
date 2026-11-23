//! System-extension entry and race-free main-loop stop requests.
use super::bridge;
use block2::{Block, RcBlock};
use objc2::{msg_send, runtime::AnyClass};
use std::{
    ffi::c_void,
    io,
    sync::atomic::{AtomicBool, Ordering},
};

static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRunLoopGetMain() -> *mut c_void;
    fn CFRunLoopRun();
    fn CFRunLoopStop(loop_ref: *mut c_void);
    fn CFRunLoopWakeUp(loop_ref: *mut c_void);
    fn CFRunLoopPerformBlock(loop_ref: *mut c_void, mode: *const c_void, block: &Block<dyn Fn()>);
    static kCFRunLoopCommonModes: *const c_void;
}
/// Enter native system-extension mode and service the main CFRunLoop.
/// Registration, signed deployment and provider activation remain separate.
/// # Errors
/// Refuses a non-main caller, missing controller, unavailable modern selectors
/// or missing OS-reported DNS system-extension entitlement. The entitlement is
/// a prerequisite, not proof that deployment or activation succeeded.
pub fn run_system_extension() -> io::Result<()> {
    // SAFETY: Darwin's predicate has no arguments and performs no mutation.
    if unsafe { libc::pthread_main_np() } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "DNS provider entry requires the main thread",
        ));
    }
    if bridge::registered().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "DNS provider controller is not registered",
        ));
    }
    super::availability::check()?;
    let provider = AnyClass::get(c"NEProvider")
        .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "NEProvider unavailable"))?;
    super::security::require_entitlement()?;
    if STOP_REQUESTED.load(Ordering::Acquire) {
        return Ok(());
    }
    // SAFETY: Exact SDK class entry. This starts no app activation request and
    // returns control to the system extension's normal native session manager.
    unsafe {
        let _: () = msg_send![provider, startSystemExtensionMode];
        CFRunLoopRun();
    }
    Ok(())
}
/// Request main-loop return after host/native retirement, from any Rust thread.
/// A queued block preserves this request even before the main loop starts.
pub fn stop_run_loop() {
    if STOP_REQUESTED.swap(true, Ordering::AcqRel) {
        return;
    }
    let stop = RcBlock::new(|| {
        // SAFETY: CoreFoundation owns the process main loop for its full life.
        unsafe {
            CFRunLoopStop(CFRunLoopGetMain());
        }
    });
    // SAFETY: PerformBlock retains its escaping empty-capture block. Common
    // modes and the process main loop are live SDK objects; wake is thread safe.
    unsafe {
        let main = CFRunLoopGetMain();
        CFRunLoopPerformBlock(main, kCFRunLoopCommonModes, &stop);
        CFRunLoopWakeUp(main);
    }
}
