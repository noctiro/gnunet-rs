//! C boundary for platform application owners of the Rust GNUnet peer.
#![cfg(any(unix, windows))]

mod config;
#[cfg(target_os = "ios")]
mod dns_proxy;
mod vpn;
mod worker;

#[cfg(unix)]
pub use vpn::GnSocketProtection;
pub use vpn::{GnVpn, GnVpnCommand, GnVpnOptions, GnVpnPrefix, GnVpnToken};

use std::ptr;

const OK: i32 = 0;
const INVALID: i32 = 1;
const SETUP_ERROR: i32 = 2;

/// Opaque handle for one caller-owned worker.
pub struct GnNode(worker::Node);

/// Borrowed UTF-8 byte range.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct GnBytes {
    data: *const u8,
    len: usize,
}

/// Application-selected configuration, numeric addresses and startup budgets.
#[repr(C)]
#[derive(Default)]
pub struct GnNodeOptions {
    state_dir: GnBytes,
    ipc_dir: GnBytes,
    config_file: GnBytes,
    bootstrap_data_dir: GnBytes,
    tcp_bind: GnBytes,
    udp4_bind: GnBytes,
    udp6_bind: GnBytes,
    dns_servers: GnBytes,
    startup_timeout_ms: u32,
    drain_timeout_ms: u32,
}

/// Initial local readiness facts and current phase of the original worker.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct GnNodeSnapshot {
    phase: u32,
    has_ready: u32,
    peer: [u8; 32],
    tcp_port: u16,
    udp4_port: u16,
    udp6_port: u16,
    quic_port: u16,
    http3_port: u16,
    unix_mtu: u16,
}

/// Copy options and start one worker. On failure `out` receives null.
///
/// # Safety
/// Supply readable options and byte ranges and a separate writable output slot.
/// The worker exclusively owns the specified state namespace until joined.
#[expect(
    unsafe_code,
    reason = "Exported C ABI and validated caller-borrowed configuration/output"
)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gnunet_node_start(
    options: *const GnNodeOptions,
    out: *mut *mut GnNode,
) -> i32 {
    if out.is_null() {
        return INVALID;
    }
    // SAFETY: the caller supplies an independent writable output slot.
    unsafe {
        out.write(ptr::null_mut());
    }
    // SAFETY: the caller supplies readable options and their explicit byte extents.
    let Some(options) = (unsafe {
        options
            .as_ref()
            .and_then(|raw| config::Options::read(raw, false))
    }) else {
        return INVALID;
    };
    let Ok(worker) = worker::Node::start(options) else {
        return SETUP_ERROR;
    };
    let node = Box::into_raw(Box::new(GnNode(worker)));
    // SAFETY: out is the same writable caller slot. This transfers one handle.
    unsafe {
        out.write(node);
    }
    OK
}

/// Request stop while retaining the original handle.
///
/// # Safety
/// A non-null handle must be live and cannot be destroyed during this call.
#[expect(unsafe_code, reason = "Exported C ABI reads a live opaque handle")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gnunet_node_stop(node: *mut GnNode) -> i32 {
    // SAFETY: caller keeps the original handle alive for the shared operation.
    let Some(node) = (unsafe { node.as_ref() }) else {
        return INVALID;
    };
    node.0.stop();
    OK
}

/// Request an address rescan on this worker while it starts or runs.
/// Success acknowledges the notification. Pending notices may be coalesced.
///
/// # Safety
/// Keep the handle alive and exclude destruction during this call.
#[expect(unsafe_code, reason = "Exported C ABI reads a live shared handle")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gnunet_node_notify_network_change(node: *const GnNode) -> i32 {
    // SAFETY: a non-null node is a live shared handle supplied by the caller.
    let Some(node) = (unsafe { node.as_ref() }) else {
        return INVALID;
    };
    node.0.notify_network_change();
    OK
}

/// Publish the current network's DNS upstreams and request an address rescan.
/// An empty list revokes upstreams. Success reports acceptance of the snapshot.
/// Workers that are stopping or terminal discard the snapshot.
///
/// # Safety
/// Keep the handle alive and lend the readable UTF-8 range through this call.
#[expect(unsafe_code, reason = "Exported C ABI copies a bounded DNS snapshot")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gnunet_node_set_dns_servers(
    node: *const GnNode,
    dns_servers: GnBytes,
) -> i32 {
    // SAFETY: a non-null handle remains live throughout the call.
    let Some(node) = (unsafe { node.as_ref() }) else {
        return INVALID;
    };
    // SAFETY: the caller lends a readable range through the copy.
    let Some(upstreams) = (unsafe { dns_servers.dns_upstreams() }) else {
        return INVALID;
    };
    node.0.set_dns_upstreams(upstreams);
    OK
}

/// Copy the node status and the first readiness observation.
///
/// # Safety
/// Keep a non-null handle alive and supply a separate writable output slot.
#[expect(unsafe_code, reason = "Exported C ABI writes one initialized snapshot")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gnunet_node_snapshot(
    node: *const GnNode,
    out: *mut GnNodeSnapshot,
) -> i32 {
    // SAFETY: a non-null node is an owned live handle supplied by the caller.
    let Some(node) = (unsafe { node.as_ref() }) else {
        return INVALID;
    };
    if out.is_null() {
        return INVALID;
    }
    // SAFETY: the caller keeps the independent output slot writable.
    unsafe {
        out.write(node.0.snapshot());
    }
    OK
}

/// Return the diagnostic byte count and copy at most `capacity` UTF-8 bytes.
///
/// # Safety
/// Keep the handle alive. A non-null output buffer must be separately writable
/// for `capacity` bytes. The caller decodes the complete result as UTF-8.
#[expect(
    unsafe_code,
    reason = "Exported C ABI copies a bounded diagnostic into caller storage"
)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gnunet_node_error(
    node: *const GnNode,
    out: *mut u8,
    capacity: usize,
) -> usize {
    // SAFETY: a non-null node is a live shared handle throughout the call.
    let Some(node) = (unsafe { node.as_ref() }) else {
        return 0;
    };
    node.0.with_error(|error| {
        if !out.is_null() && capacity != 0 {
            // SAFETY: the caller supplies a distinct output buffer of at least capacity bytes.
            unsafe {
                ptr::copy_nonoverlapping(error.as_ptr(), out, error.len().min(capacity));
            }
        }
        error.len()
    })
}

/// Consume an owned handle and join its stopped worker on the calling thread.
///
/// # Safety
/// A non-null pointer must transfer exactly one live handle created by start.
/// Exclude concurrent calls and all later uses of that handle.
#[expect(
    unsafe_code,
    reason = "Exported C ABI consumes the original Rust allocation exactly once"
)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gnunet_node_destroy(node: *mut GnNode) {
    if !node.is_null() {
        // SAFETY: the caller transfers the exact unique pointer from Box::into_raw.
        let node = unsafe { Box::from_raw(node) };
        node.0.join();
    }
}

#[cfg(test)]
mod tests;
