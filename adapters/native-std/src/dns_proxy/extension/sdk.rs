//! Exact SystemExtensions selectors and main-queue dispatch ABI.
use super::{Version, delegate::Delegate};
use block2::Block;
use objc2::{
    extern_class, extern_protocol, msg_send,
    rc::Retained,
    runtime::{AnyClass, AnyObject, NSObject},
};
use objc2_foundation::{NSError, NSObjectProtocol, NSString};
use std::{ffi::c_void, io};

#[link(name = "SystemExtensions", kind = "framework")]
unsafe extern "C" {}
unsafe extern "C" {
    static _dispatch_main_q: c_void;
    fn dispatch_async(queue: *const c_void, block: &Block<dyn Fn()>);
}
extern_class!(
    #[unsafe(super(NSObject))]
    #[name = "OSSystemExtensionRequest"]
    pub(super) struct Request;
);
extern_class!(
    #[unsafe(super(NSObject))]
    #[name = "OSSystemExtensionProperties"]
    pub(super) struct Properties;
);
extern_protocol!(
    /// Exact required SystemExtensions delegate callbacks.
    ///
    /// # Safety
    ///
    /// Implementations must preserve these Objective-C ABI signatures and keep
    /// callback arguments borrowed only for their original invocation.
    #[expect(
        clippy::missing_safety_doc,
        reason = "objc2 extern_protocol expands this documented Safety section, but Clippy does not associate the macro-generated trait with its documentation"
    )]
    #[name = "OSSystemExtensionRequestDelegate"]
    pub(super) unsafe trait RequestDelegate: NSObjectProtocol {
        #[unsafe(method(request:actionForReplacingExtension:withExtension:))]
        fn replacement(
            &self,
            request: &Request,
            existing: &Properties,
            proposed: &Properties,
        ) -> isize;
        #[unsafe(method(requestNeedsUserApproval:))]
        fn approval(&self, request: &Request);
        #[unsafe(method(request:didFinishWithResult:))]
        fn finished(&self, request: &Request, result: isize);
        #[unsafe(method(request:didFailWithError:))]
        fn failed(&self, request: &Request, error: &NSError);
    }
);
pub(super) enum Kind {
    Activate,
    Deactivate,
}
pub(super) fn available() -> io::Result<()> {
    for name in [c"OSSystemExtensionRequest", c"OSSystemExtensionManager"] {
        if AnyClass::get(name).is_none() {
            return Err(unavailable());
        }
    }
    Ok(())
}
pub(super) fn request(identifier: &NSString, kind: Kind) -> io::Result<Retained<Request>> {
    let class = AnyClass::get(c"OSSystemExtensionRequest").ok_or_else(unavailable)?;
    // SAFETY: The process main dispatch queue is an immortal dispatch object.
    // Both exact factory selectors return an autoreleased request and dispatch
    // every delegate method on this queue. No request is submitted by creation.
    let request: Option<Retained<Request>> = unsafe {
        let queue = &*((&raw const _dispatch_main_q).cast::<AnyObject>());
        match kind {
            Kind::Activate => {
                msg_send![class, activationRequestForExtension: identifier, queue: queue]
            }
            Kind::Deactivate => {
                msg_send![class, deactivationRequestForExtension: identifier, queue: queue]
            }
        }
    };
    request.ok_or_else(|| io::Error::other("system-extension request factory returned null"))
}
pub(super) fn manager() -> io::Result<Retained<AnyObject>> {
    let class = AnyClass::get(c"OSSystemExtensionManager").ok_or_else(unavailable)?;
    // SAFETY: Exact class singleton selector; retaining preserves this +0 SDK object.
    let manager: Option<Retained<AnyObject>> = unsafe { msg_send![class, sharedManager] };
    manager.ok_or_else(|| io::Error::other("system-extension manager returned null"))
}
pub(super) fn set_delegate(request: &Request, delegate: &Delegate) {
    // SAFETY: The defined class implements all required protocol methods. Its
    // independent registry loan outlives this SDK weak delegate reference.
    let _: () = unsafe { msg_send![request, setDelegate: delegate] };
}
pub(super) fn submit(manager: &AnyObject, request: &Request) {
    // SAFETY: The original request's exact manager entry, after the native loan
    // is registered. Submission may produce user-visible activation UI.
    let _: () = unsafe { msg_send![manager, submitRequest: request] };
}
pub(super) fn defer_release(block: &Block<dyn Fn()>) {
    // SAFETY: dispatch_async copies this preallocated escaping block onto the
    // serial main queue. It cannot run before this main-queue callback returns.
    unsafe {
        dispatch_async((&raw const _dispatch_main_q).cast(), block);
    }
}
pub(super) fn same_identifier(properties: &Properties, expected: &NSString) -> bool {
    // SAFETY: Live SDK delegate properties, exact readonly nonnull NSString property.
    let value: Retained<NSString> = unsafe { msg_send![properties, bundleIdentifier] };
    value.isEqualToString(expected)
}
pub(super) fn versions(properties: &Properties) -> (Option<Version>, Option<Version>) {
    // SAFETY: These readonly version strings belong to live SDK callback properties.
    let (version, short): (Retained<NSString>, Retained<NSString>) = unsafe {
        (
            msg_send![properties, bundleVersion],
            msg_send![properties, bundleShortVersion],
        )
    };
    (version_value(&version), version_value(&short))
}
fn version_value(value: &NSString) -> Option<Version> {
    // Three u32 values and dots require at most 32 ASCII characters. Refuse a
    // larger native UTF-16 string before bounded UTF-8 conversion/allocation.
    (value.length() <= 32)
        .then(|| value.to_string().parse().ok())
        .flatten()
}
fn unavailable() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "SystemExtensions framework is unavailable",
    )
}
