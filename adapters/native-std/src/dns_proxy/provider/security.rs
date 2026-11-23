//! OS-reported process entitlement prerequisite; no plist assertion grants it.
use objc2_foundation::{NSString, ns_string};
use std::{ffi::c_void, io, ptr::NonNull};

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecTaskCreateFromSelf(allocator: *const c_void) -> *const c_void;
    fn SecTaskCopyValueForEntitlement(
        task: *const c_void,
        key: *const c_void,
        error: *mut *const c_void,
    ) -> *const c_void;
}
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRelease(value: *const c_void);
    fn CFGetTypeID(value: *const c_void) -> usize;
    fn CFArrayGetTypeID() -> usize;
    fn CFStringGetTypeID() -> usize;
    fn CFArrayGetCount(array: *const c_void) -> isize;
    fn CFArrayGetValueAtIndex(array: *const c_void, index: isize) -> *const c_void;
    fn CFEqual(left: *const c_void, right: *const c_void) -> u8;
}
struct Owned(NonNull<c_void>);
impl Owned {
    fn take(raw: *const c_void) -> Option<Self> {
        NonNull::new(raw.cast_mut()).map(Self)
    }
    fn as_ptr(&self) -> *const c_void {
        self.0.as_ptr()
    }
}
impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: Every Owned originates in a documented Create/Copy +1 result,
        // is non-null, and releases that exact original reference once.
        unsafe {
            CFRelease(self.as_ptr());
        }
    }
}
pub(super) fn require_entitlement() -> io::Result<()> {
    // SAFETY: A null allocator selects the default; only this task is inspected.
    let task = Owned::take(unsafe { SecTaskCreateFromSelf(std::ptr::null()) })
        .ok_or_else(|| denied("Security.framework could not inspect this task"))?;
    let key = ns_string!("com.apple.developer.networking.networkextension");
    let mut error = std::ptr::null();
    // SAFETY: Exact Security SDK signature, retained task and constant NSString
    // toll-free CFString. Returned entitlement and optional CFError are +1 owners.
    let value = unsafe {
        SecTaskCopyValueForEntitlement(
            task.as_ptr(),
            (key as *const NSString).cast(),
            &raw mut error,
        )
    };
    let error = Owned::take(error);
    let Some(value) = Owned::take(value) else {
        if let Some(error) = error {
            // SAFETY: Security returns a CFError, toll-free bridged to NSError.
            // error_result retains a separate reference before Owned CFRelease.
            let cause = super::super::sdk::error_result(error.as_ptr().cast_mut().cast());
            return Err(match cause {
                Err(cause) => io::Error::new(io::ErrorKind::PermissionDenied, cause),
                Ok(()) => denied("native DNS entitlement lookup failed"),
            });
        }
        return Err(denied("dns-proxy-systemextension entitlement is absent"));
    };
    // SAFETY: CF type inspection accepts any non-null returned CFType.
    if unsafe { CFGetTypeID(value.as_ptr()) != CFArrayGetTypeID() } {
        return Err(denied("native DNS entitlement is not an array"));
    }
    // SAFETY: The value has the exact checked CFArray type.
    let count = unsafe { CFArrayGetCount(value.as_ptr()) };
    if !(1..=64).contains(&count) {
        return Err(denied("native DNS entitlement array exceeds its bound"));
    }
    let required = ns_string!("dns-proxy-systemextension");
    for index in 0..count {
        // SAFETY: The immutable OS-returned array is retained and index checked.
        let item = unsafe { CFArrayGetValueAtIndex(value.as_ptr(), index) };
        if item.is_null() {
            continue;
        }
        // SAFETY: Check each element is CFString before comparing with the
        // constant NSString/CFString; no unbounded conversion or allocation.
        if unsafe {
            CFGetTypeID(item) == CFStringGetTypeID()
                && CFEqual(item, (required as *const NSString).cast()) != 0
        } {
            return Ok(());
        }
    }
    Err(denied("dns-proxy-systemextension entitlement is absent"))
}
fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}
