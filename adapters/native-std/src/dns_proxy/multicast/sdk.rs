//! Network group ABI with original flow parameters and invocation-borrowed messages.
use super::path::Path;
use crate::dns_proxy::{
    connection::sdk::{self as network, CBool, Dispatch, Object},
    sdk::{Endpoint, NativeFlow},
};
use block2::Block;
use objc2::{msg_send, rc::Retained, runtime::AnyObject, sel};
use std::{ffi::c_void, io};

pub(super) type StateBlock = Block<dyn Fn(u32, *mut c_void)>;
pub(super) type ReceiveBlock = Block<dyn Fn(*mut c_void, *mut c_void, CBool)>;
pub(super) type SendBlock = Block<dyn Fn(*mut c_void)>;

#[link(name = "Network", kind = "framework")]
unsafe extern "C" {
    fn nw_group_descriptor_create_multicast(endpoint: *mut c_void) -> *mut c_void;
    fn nw_multicast_group_descriptor_set_disable_unicast_traffic(
        descriptor: *mut c_void,
        disable_unicast_traffic: bool,
    );
    fn nw_parameters_require_interface(parameters: *mut c_void, interface: *mut c_void);
    fn nw_interface_get_index(interface: *mut c_void) -> u32;
    fn nw_parameters_set_local_endpoint(parameters: *mut c_void, local: *mut c_void);
    fn nw_connection_group_create(descriptor: *mut c_void, parameters: *mut c_void) -> *mut c_void;
    fn nw_connection_group_set_queue(group: *mut c_void, queue: *mut c_void);
    fn nw_connection_group_set_state_changed_handler(group: *mut c_void, handler: *const c_void);
    fn nw_connection_group_set_receive_handler(
        group: *mut c_void,
        maximum_message_size: u32,
        reject_oversized_messages: bool,
        handler: *const c_void,
    );
    fn nw_connection_group_start(group: *mut c_void);
    fn nw_connection_group_cancel(group: *mut c_void);
    fn nw_connection_group_send_message(
        group: *mut c_void,
        content: *mut c_void,
        endpoint: *mut c_void,
        context: *mut c_void,
        completion: *const c_void,
    );
    fn nw_connection_group_copy_remote_endpoint_for_message(
        group: *mut c_void,
        context: *mut c_void,
    ) -> *mut c_void;
    fn nw_connection_group_copy_local_endpoint_for_message(
        group: *mut c_void,
        context: *mut c_void,
    ) -> *mut c_void;
    fn nw_connection_group_copy_path_for_message(
        group: *mut c_void,
        context: *mut c_void,
    ) -> *mut c_void;
    static _nw_content_context_default_message: *mut c_void;
}

fn endpoint_raw(endpoint: &Endpoint) -> *mut c_void {
    std::ptr::from_ref(endpoint.object()).cast_mut().cast()
}

/// Prepare a group without starting it or installing callbacks. The caller
/// supplies the original qualified endpoints and keeps their admission policy.
pub(super) fn create(
    flow: &NativeFlow,
    local: &Endpoint,
    group: &Endpoint,
    path: &Path,
) -> io::Result<(Object, Dispatch)> {
    for selector in [
        #[cfg(target_os = "macos")]
        sel!(setMetadata:),
        sel!(isBound),
        sel!(networkInterface),
    ] {
        // SAFETY: NativeFlow contains an adopted NEAppProxyUDPFlow; NSObject
        // capability queries perform no flow operation or pointer conversion.
        let present: bool = unsafe { msg_send![flow, respondsToSelector: selector] };
        if !present {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "multicast flow metadata/interface selectors unavailable",
            ));
        }
    }
    // SAFETY: The checked SDK property identifies an application's explicit
    // interface binding. An unbound route is not expanded to all interfaces.
    let bound: bool = unsafe { msg_send![flow, isBound] };
    if !bound {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "multicast relay requires the original bound interface",
        ));
    }
    // SAFETY: The property returns a nullable +0 nw_interface_t. Retaining the
    // SDK object keeps that original snapshot through parameter construction.
    let interface: Option<Retained<AnyObject>> = unsafe { msg_send![flow, networkInterface] };
    let interface = interface.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "bound multicast flow has no original network interface",
        )
    })?;
    let interface_raw = Retained::as_ptr(&interface).cast_mut().cast();
    // SAFETY: the retained original nw_interface_t supplies its documented
    // if_nametoindex value. This is snapshot metadata, not an interface lease.
    let index = unsafe { nw_interface_get_index(interface_raw) };
    // A native binding must not override a contradictory explicit link zone.
    // Wider scopes retain their own zone numbering, separate from ifindex.
    path.require_interface(index)?;
    let parameters = network::udp_parameters()?;
    // SAFETY: The unsubmitted plain-UDP parameters are exclusively configured.
    // Each argument is an original retained SDK object, not a reconstructed
    // address or interface index. The parameters retain their native inputs.
    unsafe {
        #[cfg(target_os = "macos")]
        let _: () = msg_send![flow, setMetadata: parameters.raw()];
        nw_parameters_require_interface(parameters.raw(), interface_raw);
        nw_parameters_set_local_endpoint(parameters.raw(), endpoint_raw(local));
    }
    // SAFETY: The descriptor constructor copies/retains this original address
    // endpoint and returns a +1 group descriptor, or NULL on invalid input.
    let descriptor =
        Object::owned(unsafe { nw_group_descriptor_create_multicast(endpoint_raw(group)) })?;
    // SAFETY: The descriptor is exclusively configured before group creation.
    // Unicast responders must remain enabled independently of SDK defaults.
    unsafe {
        nw_multicast_group_descriptor_set_disable_unicast_traffic(descriptor.raw(), false);
    }
    // SAFETY: Both retained descriptor and parameters remain live throughout
    // synchronous creation; no connection group has been started.
    let native =
        Object::owned(unsafe { nw_connection_group_create(descriptor.raw(), parameters.raw()) })?;
    let queue = network::serial_queue(c"org.gnunet.dns.multicast")?;
    // SAFETY: The queue is assigned before handlers or group startup; Network
    // retains the original serial queue for subsequent callback delivery.
    unsafe { nw_connection_group_set_queue(native.raw(), queue.raw()) };
    Ok((native, queue))
}

/// Install once before start. The group API forbids changing this after start.
pub(super) fn set_state(group: &Object, callback: &StateBlock) {
    // SAFETY: The caller owns an unstarted group and the exact escaping native
    // block. Its state mapper uses connection-group state values.
    unsafe {
        nw_connection_group_set_state_changed_handler(
            group.raw(),
            std::ptr::from_ref(callback).cast(),
        );
    }
}

/// Install once before start; incomplete/oversized messages remain caller drops.
pub(super) fn set_receive(group: &Object, maximum: u32, callback: &ReceiveBlock) {
    // SAFETY: The exact receive block is retained by the unstarted native group.
    // False prevents Network from automatically sending oversized-message errors.
    unsafe {
        nw_connection_group_set_receive_handler(
            group.raw(),
            maximum,
            false,
            std::ptr::from_ref(callback).cast(),
        );
    }
}

pub(super) fn start(group: &Object) {
    // SAFETY: The caller installs queue/state/receive handlers before this sole
    // startup and retains their original callback loans through cancellation.
    unsafe { nw_connection_group_start(group.raw()) };
}

pub(super) fn cancel(group: &Object) {
    // SAFETY: The retained original group accepts asynchronous cancellation.
    // Final Cancelled and callback disposal are observed by its caller.
    unsafe { nw_connection_group_cancel(group.raw()) };
}

/// Send only to the original selected destination; a completion is no peer ACK.
pub(super) fn send(group: &Object, data: &Dispatch, endpoint: &Endpoint, callback: &SendBlock) {
    // SAFETY: The caller's one original send owns independent group, immutable
    // data and callback loans. The global default context is SDK-owned.
    unsafe {
        nw_connection_group_send_message(
            group.raw(),
            data.raw(),
            endpoint_raw(endpoint),
            _nw_content_context_default_message,
            std::ptr::from_ref(callback).cast(),
        );
    }
}

fn copied_endpoint(raw: *mut c_void) -> io::Result<Endpoint> {
    // SAFETY: Only the +1 result of a native endpoint-copy function enters this
    // helper. Each successful conversion transfers exactly one native owner.
    let retained = unsafe { Retained::from_raw(raw.cast::<AnyObject>()) }.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "message has no original native endpoint",
        )
    })?;
    Endpoint::from_retained(retained)
}

/// Copy the actual inbound sender without replacing it by the group address.
///
/// # Safety
/// `context` must be a live message context delivered by this exact original
/// group's receive handler, retained or borrowed for this entire call.
pub(super) unsafe fn message_sender(group: &Object, context: *mut c_void) -> io::Result<Endpoint> {
    // SAFETY: The caller supplies the still-live original group/message pair;
    // Network returns a separate +1 endpoint or NULL for an invalid context.
    copied_endpoint(unsafe {
        nw_connection_group_copy_remote_endpoint_for_message(group.raw(), context)
    })
}

/// Copy this inbound message's local endpoint, independently of its sender.
///
/// # Safety
/// `context` must be a live message context delivered by this exact original
/// group's receive handler, retained or borrowed for this entire call.
pub(super) unsafe fn message_local(group: &Object, context: *mut c_void) -> io::Result<Endpoint> {
    // SAFETY: The same original message-context contract bounds this SDK copy.
    copied_endpoint(unsafe {
        nw_connection_group_copy_local_endpoint_for_message(group.raw(), context)
    })
}

/// Retain the original message path snapshot, without claiming interface liveness.
///
/// # Safety
/// `context` must be a live message context delivered by this exact original
/// group's receive handler, retained or borrowed for this entire call.
pub(super) unsafe fn message_path(group: &Object, context: *mut c_void) -> io::Result<Object> {
    // SAFETY: Network synchronously copies the path of the supplied original
    // inbound message. A retained snapshot grants no interface-generation proof.
    Object::owned(unsafe { nw_connection_group_copy_path_for_message(group.raw(), context) })
}
