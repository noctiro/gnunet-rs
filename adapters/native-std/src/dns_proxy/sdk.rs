//! Modern Apple DNS flow selectors and retained SDK values.
use block2::Block;
use objc2::{
    extern_class, msg_send,
    rc::Retained,
    runtime::{AnyClass, AnyObject, NSObject},
    sel,
};
use objc2_foundation::{NSArray, NSData, NSError};
use std::{ffi::c_void, fmt, io, mem::size_of, net::SocketAddr, ptr::NonNull};
mod scope;
pub(super) use scope::numeric_scope;

/// Native endpoint purpose; a reply source is not interchangeable with a TCP peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum EndpointRole {
    Local,
    UdpReply,
    TcpRemote,
}
/// Qualified original scope. The zone remains in the retained SDK endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum EndpointScope {
    Unscoped,
    LinkLocal,
    LegacySiteLocal,
}
impl EndpointScope {
    pub(super) const fn requires_local_endpoint(self) -> bool {
        !matches!(self, Self::Unscoped)
    }
}

#[link(name = "NetworkExtension", kind = "framework")]
unsafe extern "C" {}
#[link(name = "Network", kind = "framework")]
unsafe extern "C" {
    fn nw_endpoint_get_type(endpoint: *const c_void) -> u32;
    fn nw_endpoint_get_address(endpoint: *const c_void) -> *const libc::sockaddr;
}

extern_class!(
    #[unsafe(super(NSObject))]
    pub(super) struct NEAppProxyFlow;
);
extern_class!(
    #[unsafe(super(NEAppProxyFlow, NSObject))]
    pub(super) struct NEAppProxyUDPFlow;
);

// SAFETY: NEAppProxyUDPFlow.h and NEAppProxyFlow.h explicitly document instances
// as thread safe. The public Rust owner remains thread-confined; only operation
// guards retain/release this object from SDK callback threads.
unsafe impl Send for NEAppProxyUDPFlow {}
// SAFETY: The same documented native thread-safety covers shared references.
unsafe impl Sync for NEAppProxyUDPFlow {}

pub(super) type NativeFlow = Retained<NEAppProxyUDPFlow>;
pub(super) type ErrorBlock = Block<dyn Fn(*mut NSError)>;
pub(super) type ReadBlock =
    Block<dyn Fn(*mut NSArray<NSData>, *mut NSArray<AnyObject>, *mut NSError)>;

/// Original retained SDK error, including its native domain and code.
pub struct NativeError(Retained<NSError>);
impl NativeError {
    /// Native error code in its original domain.
    pub fn code(&self) -> isize {
        self.0.code()
    }
    /// Native domain; conversion allocates only when requested by the caller.
    pub fn domain(&self) -> String {
        self.0.domain().to_string()
    }
}
impl fmt::Debug for NativeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeError")
            .field("domain", &self.0.domain())
            .field("code", &self.code())
            .finish()
    }
}
impl fmt::Display for NativeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.0.domain(), self.code())
    }
}
impl std::error::Error for NativeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.0)
    }
}

pub(super) fn error_result(error: *mut NSError) -> io::Result<()> {
    // SAFETY: Every caller is an SDK completion whose optional NSError remains
    // valid for this invocation. Retaining preserves the original cause.
    match unsafe { Retained::retain(error) } {
        Some(error) => Err(io::Error::other(NativeError(error))),
        None => Ok(()),
    }
}

pub(super) unsafe fn adopt(raw: *mut c_void) -> io::Result<NativeFlow> {
    let raw = NonNull::new(raw)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "null DNS proxy flow"))?;
    let class = AnyClass::get(c"NEAppProxyUDPFlow")
        .ok_or_else(|| unsupported("NetworkExtension UDP flow class unavailable"))?;
    // SAFETY: The adoption caller supplies a live Objective-C object. Validate
    // its native class before treating it as the declared SDK subclass.
    let object = unsafe { raw.cast::<AnyObject>().as_ref() };
    // SAFETY: NSObject's selector receives the native class object.
    let valid: bool = unsafe { msg_send![object, isKindOfClass: class] };
    if !valid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "object is not an NEAppProxyUDPFlow",
        ));
    }
    for selector in [
        sel!(localFlowEndpoint),
        sel!(openWithLocalFlowEndpoint:completionHandler:),
        sel!(readDatagramsAndFlowEndpointsWithCompletionHandler:),
        sel!(writeDatagrams:sentByFlowEndpoints:completionHandler:),
    ] {
        // SAFETY: NSObject supports this query; no unavailable selector is sent.
        let available: bool = unsafe { msg_send![object, respondsToSelector: selector] };
        if !available {
            return Err(unsupported("native UDP flow selectors unavailable"));
        }
    }
    // SAFETY: The live class-checked native object has a +0 borrowed reference;
    // this creates one independent +1 reference for the Rust flow owner.
    unsafe { Retained::retain(raw.cast::<NEAppProxyUDPFlow>().as_ptr()) }.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "native flow retain returned null",
        )
    })
}

pub(super) fn local_endpoint(flow: &NativeFlow) -> io::Result<Option<Endpoint>> {
    // SAFETY: Adoption checked the selector. The SDK returns a nullable +0
    // nw_endpoint_t, which is an Objective-C OS object on Apple platforms.
    let endpoint: Option<Retained<AnyObject>> = unsafe { msg_send![flow, localFlowEndpoint] };
    endpoint.map(Endpoint::from_retained).transpose()
}
pub(super) fn open(flow: &NativeFlow, local: Option<&Endpoint>, callback: &ErrorBlock) {
    let local = local.map(|value| &*value.0);
    // SAFETY: Exact SDK signature, checked selector, retained endpoint and an
    // escaping block whose closure owns every callback loan.
    let _: () =
        unsafe { msg_send![flow, openWithLocalFlowEndpoint: local, completionHandler: callback] };
}
pub(super) fn read(flow: &NativeFlow, callback: &ReadBlock) {
    // SAFETY: Exact SDK signature and checked selector; callback owns its slot.
    let _: () =
        unsafe { msg_send![flow, readDatagramsAndFlowEndpointsWithCompletionHandler: callback] };
}
pub(super) fn write(flow: &NativeFlow, objects: &WriteObjects, callback: &ErrorBlock) {
    // SAFETY: One immutable NSData and its original retained native endpoint;
    // both arrays remain retained through final callback-block disposal.
    let _: () = unsafe {
        msg_send![flow, writeDatagrams: &*objects.data, sentByFlowEndpoints: &*objects.endpoints, completionHandler: callback]
    };
}
pub(super) fn close(flow: &NativeFlow) {
    // SAFETY: Both inherited selectors are present on every adopted SDK flow.
    // They accept nil for a normal local stop and return no close acknowledgement.
    unsafe {
        let _: () = msg_send![flow, closeReadWithError: Option::<&NSError>::None];
        let _: () = msg_send![flow, closeWriteWithError: Option::<&NSError>::None];
    }
}

/// One original Network endpoint. No address constructor is exposed.
#[derive(Clone)]
pub(super) struct Endpoint(Retained<AnyObject>);
// SAFETY: Network/endpoint.h declares nw_endpoint with NW_SENDABLE_OBJECT_DECL,
// which Network/nw_object.h defines as NW_SWIFT_SENDABLE. Only actual endpoints
// received from the SDK enter this wrapper; it exposes no object mutation.
unsafe impl Send for Endpoint {}
// SAFETY: The same native Sendable endpoint contract permits shared retention.
unsafe impl Sync for Endpoint {}
impl fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativeEndpoint")
    }
}
impl Endpoint {
    pub(super) fn object(&self) -> &AnyObject {
        &self.0
    }
    pub(super) fn is_address(&self) -> bool {
        self.kind() == 1
    }
    pub(super) fn socket_addr(&self) -> io::Result<SocketAddr> {
        let address = self.address()?;
        match i32::from(address.ss_family) {
            libc::AF_INET => {
                // SAFETY: address() copied a complete checked sockaddr_in.
                let address = unsafe { &*(&raw const address).cast::<libc::sockaddr_in>() };
                Ok(std::net::SocketAddr::new(
                    std::net::Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()).into(),
                    u16::from_be(address.sin_port),
                ))
            }
            libc::AF_INET6 => {
                // SAFETY: address() copied a complete checked sockaddr_in6.
                let address = unsafe { &*(&raw const address).cast::<libc::sockaddr_in6>() };
                Ok(std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                    std::net::Ipv6Addr::from(address.sin6_addr.s6_addr),
                    u16::from_be(address.sin6_port),
                    u32::from_be(address.sin6_flowinfo),
                    address.sin6_scope_id,
                )))
            }
            _ => Err(unsupported("unsupported DNS flow address family")),
        }
    }
    pub(super) fn from_retained(endpoint: Retained<AnyObject>) -> io::Result<Self> {
        let value = Self(endpoint);
        match value.kind() {
            0 => return Err(unsupported("invalid native DNS flow endpoint")),
            1 => {
                value.address()?;
            }
            _ => {}
        }
        Ok(value)
    }
    fn kind(&self) -> u32 {
        // SAFETY: Only original SDK-provided nw_endpoint_t objects are retained.
        unsafe { nw_endpoint_get_type(Retained::as_ptr(&self.0).cast()) }
    }
    pub(super) fn address(&self) -> io::Result<libc::sockaddr_storage> {
        let raw = Retained::as_ptr(&self.0).cast();
        // SAFETY: This retained object is an SDK-provided nw_endpoint_t.
        if self.kind() != 1 {
            return Err(unsupported("non-address DNS flow endpoint"));
        }
        // SAFETY: Native address storage is borrowed from the still-live endpoint.
        let address = unsafe { nw_endpoint_get_address(raw) };
        let Some(address) = NonNull::new(address.cast_mut()) else {
            return Err(unsupported("DNS flow endpoint lacks an address"));
        };
        // SAFETY: The endpoint API returns at least a native sockaddr header.
        let header = unsafe { address.as_ref() };
        let required = match i32::from(header.sa_family) {
            libc::AF_INET => size_of::<libc::sockaddr_in>(),
            libc::AF_INET6 => size_of::<libc::sockaddr_in6>(),
            _ => return Err(unsupported("unsupported DNS flow address family")),
        };
        if usize::from(header.sa_len) < required {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated native flow sockaddr",
            ));
        }
        // SAFETY: Zero is a valid sockaddr_storage and the checked native extent
        // fits it. Copying facts never replaces the retained reply endpoint.
        let mut storage = unsafe { std::mem::zeroed::<libc::sockaddr_storage>() };
        // SAFETY: Non-overlapping SDK source and local destination have the
        // validated extent and remain live for this bounded copy.
        unsafe {
            std::ptr::copy_nonoverlapping(
                address.as_ptr().cast::<u8>(),
                (&raw mut storage).cast::<u8>(),
                required,
            )
        };
        Ok(storage)
    }
    pub(super) fn scope_for(&self, role: EndpointRole) -> io::Result<EndpointScope> {
        // Opaque native endpoints retain their complete SDK identity. Numeric
        // scope qualification must not force a host/service into a sockaddr.
        if self.is_address() {
            return numeric_scope(self.socket_addr()?, role);
        }
        Ok(EndpointScope::Unscoped)
    }
    pub(super) fn qualify_flow_peer(
        &self,
        role: EndpointRole,
        local: Option<&Self>,
    ) -> io::Result<()> {
        if !self.is_address() {
            return Ok(());
        }
        let peer = self.socket_addr()?;
        let scope = numeric_scope(peer, role)?;
        if !scope.requires_local_endpoint() {
            return Ok(());
        }
        let local = local
            .ok_or_else(|| unsupported("scoped DNS flow lacks its original local endpoint"))?;
        if local.is_address() {
            scope::check_local_zone(peer, scope, local.socket_addr()?)?;
        }
        Ok(())
    }
}

#[derive(Clone)]
pub(super) struct WriteObjects {
    data: Retained<NSArray<NSData>>,
    endpoints: Retained<NSArray<AnyObject>>,
}
// SAFETY: These private arrays are created here, are immutable, and contain only
// immutable NSData copied from Rust and native Sendable endpoints. No SDK object
// borrowed from an arbitrary caller can enter this wrapper.
unsafe impl Send for WriteObjects {}
// SAFETY: Neither array nor its elements is mutated after construction.
unsafe impl Sync for WriteObjects {}
impl WriteObjects {
    pub(super) fn new(bytes: &[u8], endpoint: &Endpoint) -> Self {
        let data = NSData::with_bytes(bytes);
        Self {
            data: NSArray::from_slice(&[&*data]),
            endpoints: NSArray::from_slice(&[&*endpoint.0]),
        }
    }
}
pub(super) fn unsupported(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}

#[cfg(test)]
mod tests;

pub(super) fn copy_data(data: &NSData, out: &mut Vec<u8>) {
    // SAFETY: Read callbacks borrow SDK-owned, stable datagram data for their
    // invocation. The destination was reserved for exactly this checked length.
    out.extend_from_slice(unsafe { data.as_bytes_unchecked() });
}

pub(super) fn with_arrays<R>(
    data: *mut NSArray<NSData>,
    endpoints: *mut NSArray<AnyObject>,
    use_arrays: impl FnOnce(&NSArray<NSData>, &NSArray<AnyObject>) -> io::Result<R>,
) -> io::Result<R> {
    // SAFETY: Only SDK read callbacks call this helper and bound these references
    // to their invocation. Neither borrowed reference is returned publicly.
    match unsafe { (data.as_ref(), endpoints.as_ref()) } {
        (Some(data), Some(endpoints)) => use_arrays(data, endpoints),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing native DNS read arrays",
        )),
    }
}
