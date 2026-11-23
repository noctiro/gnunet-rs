//! Admission from the iOS app extension's OS-instantiated principal class.
use super::{
    bridge::Bridge,
    native::{NativeIncoming, NativeProvider, StartCompletion, StopCompletion, configuration_path},
};
use block2::Block;
use objc2::{
    msg_send,
    runtime::{AnyClass, AnyObject},
};
use objc2_foundation::NSError;
use std::{ffi::c_void, fmt, io, path::PathBuf, sync::Arc};

/// Callback input for one original iOS DNS provider session.
pub struct AppExtensionCallbacks(pub(super) Arc<Bridge>);

impl fmt::Debug for AppExtensionCallbacks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppExtensionCallbacks")
            .finish_non_exhaustive()
    }
}

impl AppExtensionCallbacks {
    /// Admit a startup request with its original OS completion.
    ///
    /// # Errors
    /// A validation or copy error leaves the completion with the caller. Once
    /// copied, the original startup outcome is delivered through the block.
    ///
    /// # Safety
    /// `provider` must borrow the live NEDNSProxyProvider invoking this callback.
    /// `completion` must borrow an escaping, cross-thread Apple ABI block
    /// with signature `void (^)(NSError *)`. Both must live through this call.
    pub unsafe fn start(
        &self,
        provider: *mut c_void,
        configuration: PathBuf,
        completion: *mut c_void,
    ) -> io::Result<()> {
        configuration_path(&configuration)?;
        // SAFETY: The caller lends the original provider and its startup block.
        let (provider, block) = unsafe {
            (
                retain_provider(provider)?,
                borrow::<Block<dyn Fn(*mut NSError)>>(completion)?,
            )
        };
        let completion = StartCompletion::copy(block)?;
        self.0.start(provider, configuration, completion);
        Ok(())
    }

    /// Retain the original unopened flow and return the native admission verdict.
    ///
    /// # Safety
    /// Both pointers must borrow their live NEDNSProxyProvider and NEAppProxyFlow
    /// objects. A true return transfers sole authority to open and close the flow.
    pub unsafe fn accept(&self, provider: *mut c_void, flow: *mut c_void) -> bool {
        // SAFETY: Both pointers are live SDK objects borrowed from flow admission.
        let Ok(provider) = (unsafe { retain_provider(provider) }) else {
            return false;
        };
        // SAFETY: The SDK callback retains the original unopened flow for this call.
        let Ok(flow) = (unsafe { borrow::<AnyObject>(flow) }) else {
            return false;
        };
        let Some((flow, udp)) = NativeIncoming::retain(flow) else {
            return false;
        };
        self.0.accept(&provider, flow, udp)
    }

    /// Fence admission and queue the original stop obligation for the host.
    ///
    /// # Errors
    /// An error leaves the completion with the caller and provides no evidence
    /// that the native session retired.
    ///
    /// # Safety
    /// `provider` must borrow the live NEDNSProxyProvider invoking this callback.
    /// `completion` must borrow an escaping, cross-thread Apple ABI block
    /// with signature `void (^)(void)`. Both must live through this call.
    pub unsafe fn stop(
        &self,
        provider: *mut c_void,
        reason: isize,
        completion: *mut c_void,
    ) -> io::Result<()> {
        // SAFETY: The caller lends the original provider and its stop block.
        let (provider, block) = unsafe {
            (
                retain_provider(provider)?,
                borrow::<Block<dyn Fn()>>(completion)?,
            )
        };
        let completion = StopCompletion::copy(block)?;
        self.0
            .stop(provider, reason, completion)
            .map_err(|_provider| {
                io::Error::new(
                    io::ErrorKind::NotConnected,
                    "no matching active DNS provider session",
                )
            })
    }
}

unsafe fn retain_provider(raw: *mut c_void) -> io::Result<NativeProvider> {
    // SAFETY: The app extension callback keeps this Objective-C object live.
    let object: &AnyObject = unsafe { borrow(raw)? };
    let class = AnyClass::get(c"NEDNSProxyProvider").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "DNS proxy provider class unavailable",
        )
    })?;
    // SAFETY: A live NSObject supports the class membership selector.
    let matches: bool = unsafe { msg_send![object, isKindOfClass: class] };
    if !matches {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected an original NEDNSProxyProvider",
        ));
    }
    NativeProvider::retain(object)
}

unsafe fn borrow<'callback, T>(raw: *mut c_void) -> io::Result<&'callback T> {
    // SAFETY: The caller supplies a live, correctly typed invocation borrow.
    unsafe { raw.cast::<T>().as_ref() }.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "null native DNS callback argument",
        )
    })
}
