//! Retained native provider, application flow and original completion blocks.
use block2::{Block, RcBlock};
use objc2::{
    msg_send,
    rc::Retained,
    runtime::{AnyClass, AnyObject},
};
use objc2_foundation::{NSError, ns_string};
use std::{
    ffi::c_void,
    io,
    panic::{AssertUnwindSafe, catch_unwind},
    path::Path,
};

/// Retained original provider, used only for its documented thread-safe API.
#[derive(Clone)]
pub(super) struct NativeProvider(Retained<AnyObject>);
// SAFETY: NEProvider.h documents instances as thread safe; this wrapper receives
// only this bridge's actual NEDNSProxyProvider subclass, never arbitrary objects.
unsafe impl Send for NativeProvider {}
// SAFETY: All mutable Rust state belongs to the synchronized bridge, not ivars.
unsafe impl Sync for NativeProvider {}
impl NativeProvider {
    pub(super) fn retain(object: &AnyObject) -> io::Result<Self> {
        // SAFETY: The original defined provider remains live for its callback.
        unsafe { Retained::retain((object as *const AnyObject).cast_mut()) }
            .map(Self)
            .ok_or_else(|| io::Error::other("native provider retain returned null"))
    }
    pub(super) fn same(&self, other: &Self) -> bool {
        Retained::as_ptr(&self.0) == Retained::as_ptr(&other.0)
    }
    pub(super) fn cancel(&self) {
        contain(|| {
            let error = failure();
            // SAFETY: Exact inherited NEDNSProxyProvider cancellation selector;
            // no subclass overrides it and the original SDK object is retained.
            let _: () = unsafe { msg_send![&*self.0, cancelProxyWithError: &*error] };
        });
    }
}

pub(super) struct NativeIncoming {
    object: Retained<AnyObject>,
    close: bool,
}
// SAFETY: Both SDK flow classes are documented thread safe. This unique unopened
// reference is moved to one Rust adopter; no flow I/O begins during transfer.
unsafe impl Send for NativeIncoming {}
impl NativeIncoming {
    pub(super) fn retain(flow: &AnyObject) -> Option<(Self, bool)> {
        let udp = AnyClass::get(c"NEAppProxyUDPFlow")?;
        let tcp = AnyClass::get(c"NEAppProxyTCPFlow")?;
        // SAFETY: SDK handleNewFlow supplied a live NEAppProxyFlow. Check exact
        // transport class membership before exposing its exclusive typed loan.
        let is_udp: bool = unsafe { msg_send![flow, isKindOfClass: udp] };
        // SAFETY: Same live SDK object and NSObject class-membership selector.
        let is_tcp: bool = unsafe { msg_send![flow, isKindOfClass: tcp] };
        if !is_udp && !is_tcp {
            return None;
        }
        // SAFETY: Retain the borrowed native flow before returning YES.
        unsafe { Retained::retain((flow as *const AnyObject).cast_mut()) }.map(|object| {
            (
                Self {
                    object,
                    close: true,
                },
                is_udp,
            )
        })
    }
    pub(super) fn as_ptr(&self) -> *mut c_void {
        Retained::as_ptr(&self.object).cast_mut().cast()
    }
    pub(super) fn disarm(&mut self) {
        self.close = false;
    }
}
impl Drop for NativeIncoming {
    fn drop(&mut self) {
        if self.close {
            contain(|| {
                // SAFETY: These inherited selectors close an original retained SDK
                // flow that was accepted but never adopted by a Rust I/O owner.
                unsafe {
                    let _: () =
                        msg_send![&*self.object, closeReadWithError: Option::<&NSError>::None];
                    let _: () =
                        msg_send![&*self.object, closeWriteWithError: Option::<&NSError>::None];
                }
            });
        }
    }
}

pub(super) struct StartCompletion(Option<RcBlock<dyn Fn(*mut NSError)>>);
// SAFETY: Apple's startProxy completion is explicitly @Sendable and escaping.
// This wrapper is exclusive, copies its original block and invokes it once.
unsafe impl Send for StartCompletion {}
impl StartCompletion {
    pub(super) fn copy(block: &Block<dyn Fn(*mut NSError)>) -> io::Result<Self> {
        // SAFETY: Exact SDK block signature and live callback borrow; copy owns
        // one independent block reference beyond this native method invocation.
        unsafe { RcBlock::copy((block as *const Block<_>).cast_mut()) }
            .map(|block| Self(Some(block)))
            .ok_or_else(|| io::Error::other("DNS startup completion copy refused"))
    }
    pub(super) fn ready(mut self) {
        if let Some(block) = self.0.take() {
            contain(|| block.call((std::ptr::null_mut(),)));
        }
    }
}
impl Drop for StartCompletion {
    fn drop(&mut self) {
        if let Some(block) = self.0.take() {
            contain(|| fail_start(&block));
        }
    }
}
pub(super) struct StopCompletion(Option<RcBlock<dyn Fn()>>);
// SAFETY: Apple's stopProxy completion is explicitly @Sendable and escaping.
unsafe impl Send for StopCompletion {}
impl StopCompletion {
    pub(super) fn copy(block: &Block<dyn Fn()>) -> io::Result<Self> {
        // SAFETY: Exact live SDK stop completion and independent retained copy.
        unsafe { RcBlock::copy((block as *const Block<_>).cast_mut()) }
            .map(|block| Self(Some(block)))
            .ok_or_else(|| io::Error::other("DNS stop completion copy refused"))
    }
    pub(super) fn complete(mut self) {
        if let Some(block) = self.0.take() {
            contain(|| block.call(()));
        }
    }
}
fn failure() -> Retained<NSError> {
    NSError::new(1, ns_string!("org.gnunet.rs.dns-proxy"))
}
pub(super) fn fail_start(block: &Block<dyn Fn(*mut NSError)>) {
    let error = failure();
    block.call((Retained::as_ptr(&error).cast_mut(),));
}

pub(super) fn configuration_path(path: &Path) -> io::Result<()> {
    let bytes = path.as_os_str().as_encoded_bytes();
    if !path.is_absolute() || bytes.len() > 4096 || bytes.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "GNUNET_CONFIG must be a bounded absolute file path",
        ));
    }
    Ok(())
}

pub(super) fn contain(body: impl FnOnce()) {
    boundary(|| (), body);
}
pub(super) fn boundary<T>(failed: impl FnOnce() -> T, body: impl FnOnce() -> T) -> T {
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(value) => value,
        Err(payload) => {
            if let Err(_second) = catch_unwind(AssertUnwindSafe(|| drop(payload))) {
                std::process::abort();
            }
            match catch_unwind(AssertUnwindSafe(failed)) {
                Ok(value) => value,
                Err(_payload) => std::process::abort(),
            }
        }
    }
}
