//! Typed TCP flow SDK selectors; only original retained endpoint objects open it.
use super::super::sdk::{Endpoint, EndpointRole, EndpointScope, ErrorBlock};
use block2::Block;
use objc2::{
    extern_class, msg_send,
    rc::Retained,
    runtime::{AnyClass, AnyObject, NSObject},
    sel,
};
use objc2_foundation::{NSData, NSError};
use std::{ffi::c_void, io, net::SocketAddr, ptr::NonNull};

#[link(name = "Network", kind = "framework")]
unsafe extern "C" {
    fn nw_interface_get_index(interface: *mut c_void) -> u32;
    fn nw_parameters_require_interface(parameters: *mut c_void, interface: *mut c_void);
}

extern_class!(
    #[unsafe(super(NSObject))]
    pub(super) struct NEAppProxyTCPFlow;
);
// SAFETY: NEAppProxyFlow documents native instances as thread safe. The public
// owner stays thread-confined; only callback guards retain/release references.
unsafe impl Send for NEAppProxyTCPFlow {}
// SAFETY: The same native thread-safety covers shared retained references.
unsafe impl Sync for NEAppProxyTCPFlow {}
pub(super) type Native = Retained<NEAppProxyTCPFlow>;
pub(super) type ReadBlock = Block<dyn Fn(*mut NSData, *mut NSError)>;

pub(super) unsafe fn adopt(raw: *mut c_void) -> io::Result<Native> {
    let raw = NonNull::new(raw)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "null TCP proxy flow"))?;
    let class = AnyClass::get(c"NEAppProxyTCPFlow")
        .ok_or_else(|| unsupported("NetworkExtension TCP flow class unavailable"))?;
    // SAFETY: The adoption caller supplies a live Objective-C object.
    let object = unsafe { raw.cast::<AnyObject>().as_ref() };
    // SAFETY: NSObject accepts this class test before typed adoption.
    let valid: bool = unsafe { msg_send![object, isKindOfClass: class] };
    if !valid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "object is not NEAppProxyTCPFlow",
        ));
    }
    for selector in [
        sel!(remoteFlowEndpoint),
        sel!(openWithLocalFlowEndpoint:completionHandler:),
        sel!(readDataWithCompletionHandler:),
        sel!(writeData:withCompletionHandler:),
        #[cfg(target_os = "macos")]
        sel!(setMetadata:),
        sel!(isBound),
        sel!(networkInterface),
    ] {
        // SAFETY: NSObject selector availability check requires no flow operation.
        let present: bool = unsafe { msg_send![object, respondsToSelector: selector] };
        if !present {
            return Err(unsupported("native TCP flow selectors unavailable"));
        }
    }
    // SAFETY: A live checked +0 SDK object becomes one independent +1 reference.
    unsafe { Retained::retain(raw.cast::<NEAppProxyTCPFlow>().as_ptr()) }
        .ok_or_else(|| io::Error::other("TCP flow retain returned null"))
}
pub(super) fn remote(flow: &Native) -> io::Result<Endpoint> {
    // SAFETY: The checked selector returns the original flow's remote endpoint.
    let endpoint: Option<Retained<AnyObject>> = unsafe { msg_send![flow, remoteFlowEndpoint] };
    Endpoint::from_retained(endpoint.ok_or_else(|| unsupported("TCP flow has no remote endpoint"))?)
}

pub(super) struct Interface(Retained<AnyObject>);
impl Interface {
    fn raw(&self) -> *mut c_void {
        Retained::as_ptr(&self.0).cast_mut().cast()
    }
}

pub(super) fn bound_interface(flow: &Native, remote: &Endpoint) -> io::Result<Option<Interface>> {
    let scope = remote.scope_for(EndpointRole::TcpRemote)?;
    if scope == EndpointScope::LegacySiteLocal {
        return Err(unsupported(
            "site-local TCP flow has no original local zone",
        ));
    }
    // SAFETY: Flow adoption checked these original SDK properties.
    let bound: bool = unsafe { msg_send![flow, isBound] };
    if !bound && scope != EndpointScope::LinkLocal {
        return Ok(None);
    }
    // SAFETY: Retain this original nullable +0 nw_interface_t. Numeric facts
    // can qualify that object but never replace it during connection creation.
    let interface: Option<Retained<AnyObject>> = unsafe { msg_send![flow, networkInterface] };
    let interface = Interface(interface.ok_or_else(|| {
        unsupported("bound or link-local TCP flow has no original network interface")
    })?);
    if scope == EndpointScope::LinkLocal {
        let SocketAddr::V6(peer) = remote.socket_addr()? else {
            return Err(io::ErrorKind::InvalidData.into());
        };
        // SAFETY: This retained SDK interface is the one supplied by the flow.
        if unsafe { nw_interface_get_index(interface.raw()) } != peer.scope_id() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TCP link zone differs from its original network interface",
            ));
        }
    }
    Ok(Some(interface))
}

/// Parameters must belong to the unsubmitted upstream connection.
pub(super) unsafe fn configure_upstream(
    flow: &Native,
    interface: Option<&Interface>,
    parameters: *mut c_void,
) {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: The macOS SDK accepts metadata on these exclusive parameters.
        let _: () = unsafe { msg_send![flow, setMetadata: parameters] };
    }
    #[cfg(target_os = "ios")]
    let _ = flow;
    if let Some(interface) = interface {
        // SAFETY: The live parameters retain the original SDK interface.
        unsafe { nw_parameters_require_interface(parameters, interface.raw()) };
    }
}

pub(super) fn open(flow: &Native, callback: &ErrorBlock) {
    // SAFETY: The public SDK accepts nil and preserves an app-bound local
    // endpoint. The escaping block owns the original open callback context.
    let _: () = unsafe {
        msg_send![flow, openWithLocalFlowEndpoint: Option::<&AnyObject>::None, completionHandler: callback]
    };
}
pub(super) fn read(flow: &Native, callback: &ReadBlock) {
    // SAFETY: The original operation callback owns its preallocated result slot.
    let _: () = unsafe { msg_send![flow, readDataWithCompletionHandler: callback] };
}
pub(super) fn write(flow: &Native, data: &WriteData, callback: &ErrorBlock) {
    // SAFETY: Immutable copied data remains retained in the callback until disposal.
    let _: () = unsafe { msg_send![flow, writeData: &*data.0, withCompletionHandler: callback] };
}
pub(super) fn close_read(flow: &Native) {
    // SAFETY: Inherited SDK close selector accepts nil for normal half-close.
    let _: () = unsafe { msg_send![flow, closeReadWithError: Option::<&NSError>::None] };
}
pub(super) fn close_write(flow: &Native) {
    // SAFETY: Inherited SDK close selector accepts nil for normal half-close.
    let _: () = unsafe { msg_send![flow, closeWriteWithError: Option::<&NSError>::None] };
}
fn unsupported(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}

pub(super) fn copy_read(data: *mut NSData, maximum: usize, out: &mut Vec<u8>) -> io::Result<bool> {
    // SAFETY: Only SDK read callbacks pass invocation-borrowed data here.
    let Some(data) = (unsafe { data.as_ref() }) else {
        return Ok(false);
    };
    if data.length() == 0 {
        return Ok(false);
    }
    if data.length() > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native TCP read exceeds reserved bound",
        ));
    }
    super::super::sdk::copy_data(data, out);
    Ok(true)
}

/// Private immutable copied data, retained until final callback disposal.
#[derive(Clone)]
pub(super) struct WriteData(Retained<NSData>);
// SAFETY: Only immutable NSData copied from Rust bytes enters this wrapper.
unsafe impl Send for WriteData {}
// SAFETY: Neither this native immutable NSData nor its storage is mutated.
unsafe impl Sync for WriteData {}
impl WriteData {
    pub(super) fn new(bytes: &[u8]) -> Self {
        Self(NSData::with_bytes(bytes))
    }
}
