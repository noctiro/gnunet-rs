//! Narrow Network and libdispatch ABI, with original reference-counted owners.
use block2::Block;
use std::{
    ffi::{CStr, c_void},
    io,
    net::SocketAddr,
    ptr::NonNull,
};

/// C99 _Bool in a block signature, independent of platform Objective-C BOOL.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub(in crate::dns_proxy) struct CBool(bool);
// SAFETY: The transparent Rust bool has C99 _Bool's layout and valid values;
// Network's callback takes C bool, whose Objective-C encoding is exactly B.
unsafe impl objc2::encode::Encode for CBool {
    const ENCODING: objc2::encode::Encoding = objc2::encode::Encoding::Bool;
}
impl CBool {
    pub(in crate::dns_proxy) const fn get(self) -> bool {
        self.0
    }
}

#[link(name = "Network", kind = "framework")]
unsafe extern "C" {
    fn nw_retain(object: *mut c_void) -> *mut c_void;
    fn nw_release(object: *mut c_void);
    fn nw_endpoint_create_address(address: *const libc::sockaddr) -> *mut c_void;
    fn nw_parameters_create_secure_tcp(tls: *const c_void, tcp: *const c_void) -> *mut c_void;
    fn nw_parameters_create_secure_udp(dtls: *const c_void, udp: *const c_void) -> *mut c_void;
    static _nw_parameters_configure_protocol_disable: *const c_void;
    static _nw_parameters_configure_protocol_default_configuration: *const c_void;
    static _nw_content_context_default_message: *mut c_void;
    static _nw_content_context_final_send: *mut c_void;
    fn nw_connection_create(endpoint: *mut c_void, parameters: *mut c_void) -> *mut c_void;
    fn nw_connection_set_queue(connection: *mut c_void, queue: *mut c_void);
    fn nw_connection_set_state_changed_handler(connection: *mut c_void, handler: *const c_void);
    fn nw_connection_start(connection: *mut c_void);
    fn nw_connection_cancel(connection: *mut c_void);
    fn nw_connection_send(
        connection: *mut c_void,
        content: *mut c_void,
        context: *mut c_void,
        complete: bool,
        callback: *const c_void,
    );
    fn nw_connection_receive(
        connection: *mut c_void,
        minimum: u32,
        maximum: u32,
        callback: *const c_void,
    );
    fn nw_connection_receive_message(connection: *mut c_void, callback: *const c_void);
    fn nw_content_context_get_is_final(context: *mut c_void) -> bool;
    fn nw_error_get_error_domain(error: *mut c_void) -> u32;
    fn nw_error_get_error_code(error: *mut c_void) -> i32;
}
unsafe extern "C" {
    fn dispatch_queue_create(label: *const libc::c_char, attribute: *const c_void) -> *mut c_void;
    fn dispatch_retain(object: *mut c_void);
    fn dispatch_release(object: *mut c_void);
    fn dispatch_data_create(
        buffer: *const c_void,
        size: usize,
        queue: *mut c_void,
        destructor: *const c_void,
    ) -> *mut c_void;
    fn dispatch_data_get_size(data: *mut c_void) -> usize;
    fn dispatch_data_create_map(
        data: *mut c_void,
        buffer: *mut *const c_void,
        size: *mut usize,
    ) -> *mut c_void;
}

/// Owned reference-counted Network object. SDK leaves keep setup exclusive.
pub(in crate::dns_proxy) struct Object(NonNull<c_void>);
// SAFETY: Only the SDK leaves construct these owners. The Swift Network SDK
// marks connections, connection groups and paths Sendable. Parameters and
// descriptors are configured and consumed locally before sharing any owner.
unsafe impl Send for Object {}
// SAFETY: Shared owners of the same objects never expose mutable Rust memory.
unsafe impl Sync for Object {}
impl Object {
    pub(in crate::dns_proxy) fn owned(raw: *mut c_void) -> io::Result<Self> {
        NonNull::new(raw)
            .map(Self)
            .ok_or_else(|| io::Error::other("Network object allocation failed"))
    }
    pub(in crate::dns_proxy) fn raw(&self) -> *mut c_void {
        self.0.as_ptr()
    }
}
impl Clone for Object {
    fn clone(&self) -> Self {
        // SAFETY: This independent owner keeps the object live during retain.
        unsafe {
            nw_retain(self.raw());
        }
        Self(self.0)
    }
}
impl Drop for Object {
    fn drop(&mut self) {
        // SAFETY: Each constructed/cloned owner releases its one +1 reference.
        unsafe {
            nw_release(self.raw());
        }
    }
}
pub(in crate::dns_proxy) struct Dispatch(NonNull<c_void>);
// SAFETY: Only thread-safe libdispatch queues and immutable data enter this owner.
unsafe impl Send for Dispatch {}
// SAFETY: The wrapper exposes no mutable storage, only documented dispatch calls.
unsafe impl Sync for Dispatch {}
impl Dispatch {
    fn owned(raw: *mut c_void) -> io::Result<Self> {
        NonNull::new(raw)
            .map(Self)
            .ok_or_else(|| io::Error::other("dispatch allocation failed"))
    }
    pub(in crate::dns_proxy) fn raw(&self) -> *mut c_void {
        self.0.as_ptr()
    }
}
impl Clone for Dispatch {
    fn clone(&self) -> Self {
        // SAFETY: The original independent +1 reference remains live.
        unsafe {
            dispatch_retain(self.raw());
        }
        Self(self.0)
    }
}
impl Drop for Dispatch {
    fn drop(&mut self) {
        // SAFETY: This owner releases exactly its one retained dispatch reference.
        unsafe {
            dispatch_release(self.raw());
        }
    }
}
pub(super) fn numeric_endpoint(address: SocketAddr) -> io::Result<Object> {
    let mut storage = std::mem::MaybeUninit::<libc::sockaddr_storage>::zeroed();
    // SAFETY: The zeroed storage has sufficient size/alignment for either checked
    // native sockaddr. Every family-specific field is initialized before use.
    unsafe {
        match address {
            SocketAddr::V4(address) => {
                let value = &mut *storage.as_mut_ptr().cast::<libc::sockaddr_in>();
                value.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
                value.sin_family = libc::AF_INET as u8;
                value.sin_port = address.port().to_be();
                value.sin_addr.s_addr = u32::from_ne_bytes(address.ip().octets());
            }
            SocketAddr::V6(address) => {
                let value = &mut *storage.as_mut_ptr().cast::<libc::sockaddr_in6>();
                value.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
                value.sin6_family = libc::AF_INET6 as u8;
                value.sin6_port = address.port().to_be();
                value.sin6_flowinfo = address.flowinfo().to_be();
                value.sin6_scope_id = address.scope_id();
                value.sin6_addr.s6_addr = address.ip().octets();
            }
        }
        Object::owned(nw_endpoint_create_address(storage.as_ptr().cast()))
    }
}
pub(super) enum Transport<'a> {
    Tcp(&'a super::TcpFlow),
    Udp,
}
pub(in crate::dns_proxy) fn udp_parameters() -> io::Result<Object> {
    // SAFETY: Immutable SDK blocks select ordinary UDP with DTLS disabled.
    Object::owned(unsafe {
        nw_parameters_create_secure_udp(
            _nw_parameters_configure_protocol_disable,
            _nw_parameters_configure_protocol_default_configuration,
        )
    })
}

pub(in crate::dns_proxy) fn serial_queue(label: &CStr) -> io::Result<Dispatch> {
    // SAFETY: The initialized C label is copied. Null attributes select
    // a serial queue backed by the system worker pool.
    Dispatch::owned(unsafe { dispatch_queue_create(label.as_ptr(), std::ptr::null()) })
}

pub(super) fn create(
    endpoint: *mut c_void,
    transport: Transport<'_>,
) -> io::Result<(Object, Dispatch)> {
    let parameters = match transport {
        Transport::Udp => udp_parameters()?,
        Transport::Tcp(original) => {
            // SAFETY: Immutable SDK blocks select ordinary TCP with TLS disabled.
            let parameters = Object::owned(unsafe {
                nw_parameters_create_secure_tcp(
                    _nw_parameters_configure_protocol_disable,
                    _nw_parameters_configure_protocol_default_configuration,
                )
            })?;
            // SAFETY: The original parameters are live, exclusive and unsubmitted.
            unsafe { original.configure_upstream(parameters.raw()) };
            parameters
        }
    };
    // SAFETY: The retained original or freshly constructed numeric endpoint and
    // parameters remain live during the constructor, which returns a +1 object.
    let connection = Object::owned(unsafe { nw_connection_create(endpoint, parameters.raw()) })?;
    let queue = serial_queue(c"org.gnunet.dns.upstream")?;
    // SAFETY: Queue assignment precedes connection start and retains its SDK owner.
    unsafe {
        nw_connection_set_queue(connection.raw(), queue.raw());
    }
    Ok((connection, queue))
}
pub(super) fn state(connection: &Object, callback: &Block<dyn Fn(u32, *mut c_void)>) {
    // SAFETY: Exact Network signature; the escaping block retains its callback loans.
    unsafe {
        nw_connection_set_state_changed_handler(
            connection.raw(),
            std::ptr::from_ref(callback).cast(),
        );
    }
}
pub(super) fn clear_state(connection: &Object) {
    // SAFETY: Called only at the SDK's final cancelled state to break registration ownership.
    unsafe {
        nw_connection_set_state_changed_handler(connection.raw(), std::ptr::null());
    }
}
pub(super) fn start(connection: &Object) {
    // SAFETY: Private state handler and serial queue were installed before this call.
    unsafe {
        nw_connection_start(connection.raw());
    }
}
pub(super) fn cancel(connection: &Object) {
    // SAFETY: Original retained connection; cancellation is idempotent and asynchronous.
    unsafe {
        nw_connection_cancel(connection.raw());
    }
}
pub(in crate::dns_proxy) fn copy_data(bytes: &[u8]) -> io::Result<Dispatch> {
    // SAFETY: Default null destructor copies bytes synchronously; Rust input is
    // borrowed only for this call. No SDK pointer into Rust storage is retained.
    Dispatch::owned(unsafe {
        dispatch_data_create(
            bytes.as_ptr().cast(),
            bytes.len(),
            std::ptr::null_mut(),
            std::ptr::null(),
        )
    })
}
pub(super) fn send(
    connection: &Object,
    data: &Dispatch,
    finish: bool,
    callback: &Block<dyn Fn(*mut c_void)>,
) {
    // SAFETY: The original data and connection are independently retained by the
    // escaping callback until disposal; the final context sends TCP FIN only.
    unsafe {
        let context = if finish {
            _nw_content_context_final_send
        } else {
            _nw_content_context_default_message
        };
        nw_connection_send(
            connection.raw(),
            data.raw(),
            context,
            true,
            std::ptr::from_ref(callback).cast(),
        );
    }
}
pub(super) fn receive(
    connection: &Object,
    maximum: u32,
    datagram: bool,
    callback: &Block<dyn Fn(*mut c_void, *mut c_void, CBool, *mut c_void)>,
) {
    // SAFETY: The exact callback signature has one completion per operation.
    // Stream reads are length-bounded; datagrams are checked before Rust copying.
    unsafe {
        let callback = std::ptr::from_ref(callback).cast();
        if datagram {
            nw_connection_receive_message(connection.raw(), callback);
        } else {
            nw_connection_receive(connection.raw(), 1, maximum, callback);
        }
    }
}
pub(in crate::dns_proxy) fn content(
    data: *mut c_void,
    maximum: usize,
) -> io::Result<zeroize::Zeroizing<Vec<u8>>> {
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    if data.is_null() {
        return Ok(bytes);
    }
    // SAFETY: Called only within a Network receive callback borrowing this data.
    let length = unsafe { dispatch_data_get_size(data) };
    if length > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Network receive exceeds bound",
        ));
    }
    bytes.try_reserve_exact(length).map_err(io::Error::other)?;
    if bytes.capacity() > maximum {
        return Err(io::Error::other("Network receive allocation exceeds bound"));
    }
    if length == 0 {
        return Ok(bytes);
    }
    let mut buffer = std::ptr::null();
    let mut size = 0;
    // SAFETY: Mapping retains the callback-owned data and supplies one contiguous
    // extent; its owner remains live until copying the checked bytes completes.
    let mapped =
        Dispatch::owned(unsafe { dispatch_data_create_map(data, &mut buffer, &mut size) })?;
    if size != length || buffer.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid mapped Network data",
        ));
    }
    // SAFETY: The retained map guarantees this initialized read-only extent.
    bytes.extend_from_slice(unsafe { std::slice::from_raw_parts(buffer.cast::<u8>(), length) });
    drop(mapped);
    Ok(bytes)
}
pub(super) fn final_context(context: *mut c_void) -> bool {
    // SAFETY: Optional context is borrowed only during its SDK callback.
    !context.is_null() && unsafe { nw_content_context_get_is_final(context) }
}
#[derive(Clone, Copy, Debug)]
pub(in crate::dns_proxy) struct Failure {
    pub domain: u32,
    pub code: i32,
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Network error domain {} code {}", self.domain, self.code)
    }
}
impl std::error::Error for Failure {}
impl Failure {
    pub(in crate::dns_proxy) fn into_error(self) -> io::Error {
        if self.domain == 1 {
            io::Error::from_raw_os_error(self.code)
        } else {
            io::Error::other(self)
        }
    }
}
pub(in crate::dns_proxy) fn failure(error: *mut c_void) -> Option<Failure> {
    if error.is_null() {
        return None;
    }
    // SAFETY: The SDK callback keeps its optional original error alive here.
    Some(unsafe {
        Failure {
            domain: nw_error_get_error_domain(error),
            code: nw_error_get_error_code(error),
        }
    })
}
