//! Own a platform's original per-socket protection callback for a VPN worker.
use super::{
    GnNode, GnNodeOptions, GnVpn, GnVpnOptions, INVALID, SocketPolicy, clear_outputs, start,
};
use std::{
    ffi::c_void,
    io,
    os::fd::{AsRawFd, BorrowedFd},
    ptr::NonNull,
};

type Protect = unsafe extern "C" fn(*mut c_void, i32) -> i32;
type Release = unsafe extern "C" fn(*mut c_void);

/// Original application protection context and its matching callbacks.
#[repr(C)]
pub struct GnSocketProtection {
    pub(super) context: *mut c_void,
    pub(super) protect: Option<Protect>,
    pub(super) release: Option<Release>,
}

struct Owner {
    context: NonNull<c_void>,
    protect: Protect,
    release: Release,
}

// SAFETY: the C contract allows both callbacks on worker threads and requires
// synchronized access through that original context for the borrowed lifetime.
unsafe impl Send for Owner {}
// SAFETY: shared invocations only use the caller's synchronized callback.
unsafe impl Sync for Owner {}

impl Owner {
    fn from_input(input: &GnSocketProtection) -> Option<Self> {
        Some(Self {
            context: NonNull::new(input.context)?,
            protect: input.protect?,
            release: input.release?,
        })
    }

    fn prepare(&self, socket: BorrowedFd<'_>) -> io::Result<()> {
        // SAFETY: the owner retains the original context, and the socket
        // remains borrowed through this synchronous application callback.
        let result = unsafe { (self.protect)(self.context.as_ptr(), socket.as_raw_fd()) };
        if result != 1 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "application refused protection of the original upstream socket",
            ));
        }
        Ok(())
    }
}

impl Drop for Owner {
    fn drop(&mut self) {
        // SAFETY: this is the only owner of the consumed context and no
        // protection invocation can still borrow it after the last policy drop.
        unsafe { (self.release)(self.context.as_ptr()) };
    }
}

/// Start a VPN worker that requires protection on its original Internet sockets.
///
/// # Safety
/// All readable options and their ranges are live through the call. Outputs are
/// independent and writable. Non-null context and callbacks transfer one valid
/// original context even if options or startup fail. The callbacks may run on
/// worker threads, borrow the socket for the call and never close or retain it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gnunet_node_start_with_protected_vpn(
    options: *const GnNodeOptions,
    vpn_options: *const GnVpnOptions,
    protection: *const GnSocketProtection,
    out: *mut *mut GnNode,
    vpn_out: *mut *mut GnVpn,
) -> i32 {
    // SAFETY: caller lends readable protection configuration through this operation.
    let Some(owner) = (unsafe { protection.as_ref() }).and_then(Owner::from_input) else {
        // SAFETY: caller supplies writable independent outputs or rejected nulls.
        let _cleared = unsafe { clear_outputs(out, vpn_out) };
        return INVALID;
    };
    let policy = SocketPolicy::protected(move |socket| owner.prepare(socket));
    // SAFETY: both FFI start entries share the same input and output contract.
    unsafe { start(options, vpn_options, policy, out, vpn_out) }
}
