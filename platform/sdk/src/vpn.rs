//! C boundary for an application-owned packet provider and its original receipts.
#![expect(
    unsafe_code,
    reason = "C exports lend explicit buffers and opaque original owners"
)]

use crate::{GnBytes, GnNode, GnNodeOptions, INVALID, OK, SETUP_ERROR, config::Options, worker};
use gnunet_node_host::VpnProvider;
use gnunet_service_runtime::network::SocketPolicy;
use gnunet_vpn::{Address, Prefix, RouteAction};
use gnunet_vpn_host::coordinator::{
    application::{self, Command},
    provider::{
        CloseOutcome, PacketCompletion, PacketOutcome, RequestId, RouteCompletion, RouteOutcome,
    },
};
use std::{
    io,
    num::NonZeroU16,
    ptr,
    sync::{Mutex, MutexGuard},
    time::Duration,
};
use tokio::time::Instant;

#[cfg(unix)]
mod protection;
#[cfg(unix)]
pub use protection::GnSocketProtection;

const WAIT: i32 = 3;
const WOULD_BLOCK: i32 = 4;

/// Application VPN transport and queue bounds.
#[repr(C)]
pub struct GnVpnOptions {
    peer_mode: u32,
    packet_source: u32,
    maximum_packet: u16,
    ingress_packets: u16,
}

/// The original VPN source and operation revision.
#[repr(C)]
#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub struct GnVpnToken {
    epoch: u64,
    revision: u64,
}

impl From<RequestId> for GnVpnToken {
    fn from(id: RequestId) -> Self {
        Self {
            epoch: id.epoch().get(),
            revision: id.revision().get(),
        }
    }
}

/// Canonical network and interface address for an optional IP family.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct GnVpnPrefix {
    family: u8,
    bits: u8,
    network: [u8; 16],
    interface_address: [u8; 16],
}

impl From<Prefix> for GnVpnPrefix {
    fn from(prefix: Prefix) -> Self {
        let mut exported = Self {
            bits: prefix.bits,
            ..Self::default()
        };
        match (prefix.network, prefix.interface) {
            (Address::V4(network), Address::V4(interface)) => {
                exported.family = 4;
                exported.network[..4].copy_from_slice(&network);
                exported.interface_address[..4].copy_from_slice(&interface);
            }
            (Address::V6(network), Address::V6(interface)) => {
                exported.family = 6;
                exported.network = network;
                exported.interface_address = interface;
            }
            _ => {}
        }
        exported
    }
}

/// An actual original application-provider command.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct GnVpnCommand {
    kind: u32,
    mtu: u32,
    token: GnVpnToken,
    ipv4: GnVpnPrefix,
    ipv6: GnVpnPrefix,
    packet_len: u32,
    remaining_ms: u32,
}

#[derive(Default)]
struct Claims {
    route: Option<RequestId>,
    packet: Option<(RequestId, usize)>,
}

enum Source {
    Packets(application::Controller),
    #[cfg(unix)]
    Descriptor(application::descriptor::Controller),
}

impl Source {
    fn packets(&self) -> Option<&application::Controller> {
        match self {
            Self::Packets(source) => Some(source),
            #[cfg(unix)]
            Self::Descriptor(_) => None,
        }
    }

    fn next(&self, wait: Duration) -> Option<Command> {
        match self {
            Self::Packets(source) => source.next(wait),
            #[cfg(unix)]
            Self::Descriptor(source) => source.next(wait).map(|command| match command {
                application::descriptor::Command::Route(request) => Command::Route(request),
                application::descriptor::Command::Closed => Command::Closed,
            }),
        }
    }

    fn complete_route(&self, completion: RouteCompletion) -> io::Result<()> {
        match self {
            Self::Packets(source) => source.complete_route(completion),
            #[cfg(unix)]
            Self::Descriptor(source) => source.complete_route(completion),
        }
    }

    fn fence_packets(&self) {
        match self {
            Self::Packets(source) => source.fence_packets(),
            #[cfg(unix)]
            Self::Descriptor(source) => source.fence_packets(),
        }
    }

    fn revoke(&self, outcome: CloseOutcome) {
        match self {
            Self::Packets(source) => source.revoke(outcome),
            #[cfg(unix)]
            Self::Descriptor(source) => source.revoke(outcome),
        }
    }
}

/// Original application VPN control handle. Release after all calls complete.
pub struct GnVpn {
    source: Source,
    packet_capacity: usize,
    claims: Mutex<Claims>,
    reader: Mutex<()>,
}

impl GnVpn {
    fn new(source: Source, packet_capacity: usize) -> Self {
        Self {
            source,
            packet_capacity,
            claims: Mutex::default(),
            reader: Mutex::default(),
        }
    }

    fn route(&self, token: GnVpnToken, finish: impl FnOnce(RequestId) -> io::Result<()>) -> i32 {
        let mut claims = lock(&self.claims);
        let Some(id) = claims.route.filter(|id| GnVpnToken::from(*id) == token) else {
            return INVALID;
        };
        let outcome = finish(id);
        if outcome.is_ok() {
            claims.route = None;
        }
        status(outcome)
    }
}

fn lock<T>(state: &Mutex<T>) -> MutexGuard<'_, T> {
    state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn status(result: io::Result<()>) -> i32 {
    match result {
        Ok(()) => OK,
        Err(error) => match error.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::NotConnected => WOULD_BLOCK,
            io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => INVALID,
            _ => SETUP_ERROR,
        },
    }
}

fn channel(options: &GnVpnOptions) -> io::Result<(GnVpn, Box<dyn VpnProvider + Send>)> {
    let maximum = NonZeroU16::new(options.maximum_packet).ok_or(io::ErrorKind::InvalidInput)?;
    match options.packet_source {
        1 => {
            let ingress =
                NonZeroU16::new(options.ingress_packets).ok_or(io::ErrorKind::InvalidInput)?;
            let (controller, provider) = application::channel(maximum, ingress)?;
            Ok((
                GnVpn::new(Source::Packets(controller), usize::from(maximum.get())),
                Box::new(provider),
            ))
        }
        #[cfg(unix)]
        2 if options.ingress_packets == 0 => {
            let (controller, provider) = application::descriptor::channel(maximum)?;
            Ok((
                GnVpn::new(Source::Descriptor(controller), 0),
                Box::new(provider),
            ))
        }
        _ => Err(io::ErrorKind::InvalidInput.into()),
    }
}

/// Copy options and start a worker with an application-owned VPN provider.
///
/// # Safety
/// All inputs and their ranges are readable. Both output slots are distinct
/// writable locations. The caller keeps the two original owners live until
/// their accesses and native callbacks have retired.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gnunet_node_start_with_vpn(
    options: *const GnNodeOptions,
    vpn_options: *const GnVpnOptions,
    out: *mut *mut GnNode,
    vpn_out: *mut *mut GnVpn,
) -> i32 {
    // SAFETY: input and output requirements are the shared startup contract.
    unsafe { start(options, vpn_options, SocketPolicy::default(), out, vpn_out) }
}

unsafe fn clear_outputs(out: *mut *mut GnNode, vpn_out: *mut *mut GnVpn) -> bool {
    if out.is_null() || vpn_out.is_null() || out.cast::<()>() == vpn_out.cast::<()>() {
        return false;
    }
    // SAFETY: both output slots are independent and writable as specified.
    unsafe {
        out.write(ptr::null_mut());
        vpn_out.write(ptr::null_mut());
    }
    true
}

unsafe fn start(
    options: *const GnNodeOptions,
    vpn_options: *const GnVpnOptions,
    socket_policy: SocketPolicy,
    out: *mut *mut GnNode,
    vpn_out: *mut *mut GnVpn,
) -> i32 {
    // SAFETY: caller supplies distinct writable outputs except for rejected nulls.
    if !unsafe { clear_outputs(out, vpn_out) } {
        return INVALID;
    }
    // SAFETY: the caller lends each readable options object through this call.
    let (Some(options), Some(vpn_options)) = (unsafe { (options.as_ref(), vpn_options.as_ref()) })
    else {
        return INVALID;
    };
    let outbound_only = match vpn_options.peer_mode {
        1 => false,
        2 => true,
        _ => return INVALID,
    };
    // SAFETY: the options owner also lends the stated readable byte ranges.
    let Some(options) = (unsafe { Options::read(options, outbound_only) }) else {
        return INVALID;
    };
    let (vpn, provider) = match channel(vpn_options) {
        Ok(channel) => channel,
        Err(error) => return status(Err(error)),
    };
    let Ok(node) = worker::Node::start(options.with_vpn(provider, socket_policy)) else {
        return SETUP_ERROR;
    };
    // SAFETY: the original output slots remain writable and disjoint here.
    unsafe {
        out.write(Box::into_raw(Box::new(GnNode(node))));
        vpn_out.write(Box::into_raw(Box::new(vpn)));
    }
    OK
}

fn remaining_ms(deadline: Instant) -> u32 {
    let micros = deadline
        .saturating_duration_since(Instant::now())
        .as_micros();
    u32::try_from(micros.div_ceil(1000)).unwrap_or(u32::MAX)
}

/// Claim one complete command and copy its optional raw packet.
///
/// # Safety
/// The handle is live and the command and packet output areas are writable
/// and disjoint from each other and the handle, for the entire call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gnunet_vpn_next(
    vpn: *const GnVpn,
    timeout_ms: u32,
    command: *mut GnVpnCommand,
    packet: *mut u8,
    capacity: usize,
) -> i32 {
    // SAFETY: a non-null handle stays live for this shared call.
    let Some(vpn) = (unsafe { vpn.as_ref() }) else {
        return INVALID;
    };
    if command.is_null()
        || capacity < vpn.packet_capacity
        || (vpn.packet_capacity != 0 && packet.is_null())
    {
        return INVALID;
    }
    let Ok(_reader) = vpn.reader.try_lock() else {
        return WOULD_BLOCK;
    };
    let Some(original) = vpn.source.next(Duration::from_millis(timeout_ms.into())) else {
        return WAIT;
    };
    let mut claims = lock(&vpn.claims);
    let mut output = GnVpnCommand::default();
    match original {
        Command::Route(request) => {
            output.kind = match request.action {
                RouteAction::Install => 1,
                RouteAction::Remove => 2,
                _ => return SETUP_ERROR,
            };
            output.mtu = request.mtu;
            output.token = request.id.into();
            output.ipv4 = request.ipv4.map_or_else(GnVpnPrefix::default, Into::into);
            output.ipv6 = request.ipv6.map_or_else(GnVpnPrefix::default, Into::into);
            output.remaining_ms = remaining_ms(request.deadline);
            claims.route = Some(request.id);
        }
        Command::Write(original) => {
            let request = original.request();
            let bytes = original.bytes();
            output.kind = 3;
            output.token = request.id.into();
            output.packet_len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
            output.remaining_ms = remaining_ms(request.deadline);
            // SAFETY: the application supplies the fixed capacity contracted by
            // this handle, and the immutable packet comes from its bounded source.
            unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), packet, bytes.len()) };
            claims.packet = Some((request.id, bytes.len()));
        }
        Command::Closed => output.kind = 4,
    }
    // SAFETY: this is the caller's independent writable output slot.
    unsafe { command.write(output) };
    OK
}

fn diagnostic(detail: &str) -> io::Error {
    if detail.is_empty() {
        io::Error::other("application VPN operation failed")
    } else {
        io::Error::other(detail.to_owned())
    }
}

/// Complete the exact original configuration request.
///
/// # Safety
/// Keep the handle live and lend the diagnostic range through this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gnunet_vpn_route_complete(
    vpn: *const GnVpn,
    token: GnVpnToken,
    outcome: u32,
    detail: GnBytes,
) -> i32 {
    // SAFETY: both the handle and the UTF-8 range are live during the call.
    let (Some(vpn), Some(detail)) = (unsafe { (vpn.as_ref(), detail.text(4096)) }) else {
        return INVALID;
    };
    let outcome = match outcome {
        1 => RouteOutcome::Installed,
        2 => RouteOutcome::Removed,
        3 | 4 => RouteOutcome::Failed {
            error: diagnostic(detail),
            routes_absent: outcome == 4,
        },
        _ => return INVALID,
    };
    vpn.route(token, |id| {
        vpn.source.complete_route(RouteCompletion { id, outcome })
    })
}

/// Complete installation with a synchronously borrowed native raw IP descriptor.
///
/// # Safety
/// The handle is live. The caller retains its original validated descriptor
/// throughout this call. A negative value is invalid.
#[cfg(unix)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gnunet_vpn_install_descriptor(
    vpn: *const GnVpn,
    token: GnVpnToken,
    fd: i32,
) -> i32 {
    // SAFETY: the caller retains the original live handle.
    let Some(vpn) = (unsafe { vpn.as_ref() }) else {
        return INVALID;
    };
    let Source::Descriptor(source) = &vpn.source else {
        return INVALID;
    };
    if fd < 0 {
        return INVALID;
    }
    // SAFETY: the provider guarantees that this exact live descriptor remains
    // borrowed for the synchronous call. The controller duplicates it.
    let fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
    vpn.route(token, |id| source.installed(id, fd))
}

/// Complete an actual packet write without replay.
///
/// # Safety
/// Keep the handle live and lend the diagnostic range through this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gnunet_vpn_write_complete(
    vpn: *const GnVpn,
    token: GnVpnToken,
    outcome: u32,
    detail: GnBytes,
) -> i32 {
    // SAFETY: caller lends the handle and diagnostic for the duration.
    let (Some(vpn), Some(detail)) = (unsafe { (vpn.as_ref(), detail.text(4096)) }) else {
        return INVALID;
    };
    let Some(source) = vpn.source.packets() else {
        return INVALID;
    };
    let mut claims = lock(&vpn.claims);
    let Some((id, bytes)) = claims
        .packet
        .filter(|(id, _)| GnVpnToken::from(*id) == token)
    else {
        return INVALID;
    };
    let outcome = match outcome {
        1 => PacketOutcome::Written { bytes },
        2 => PacketOutcome::Unsent {
            error: diagnostic(detail),
        },
        3 => PacketOutcome::Unknown {
            error: diagnostic(detail),
            exposed: true,
        },
        _ => return INVALID,
    };
    let result = source.complete_write(PacketCompletion { id, outcome });
    if result.is_ok() {
        claims.packet = None;
    }
    status(result)
}

/// Submit a whole input packet, copying only after provider admission.
///
/// # Safety
/// Keep the handle live and supply a readable extent for the original packet.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gnunet_vpn_receive(
    vpn: *const GnVpn,
    packet: *const u8,
    size: usize,
) -> i32 {
    // SAFETY: the caller keeps the opaque handle live for this call.
    let Some(vpn) = (unsafe { vpn.as_ref() }) else {
        return INVALID;
    };
    let Some(source) = vpn.source.packets() else {
        return INVALID;
    };
    if packet.is_null() || size == 0 || size > vpn.packet_capacity {
        return INVALID;
    }
    // SAFETY: the caller lends this original packet's readable extent.
    status(source.receive(unsafe { std::slice::from_raw_parts(packet, size) }))
}

/// Stop new packet I/O on this provider. Routing and claimed writes may still
/// complete using their original tokens while the node shuts down.
///
/// # Safety
/// Keep the handle live throughout this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gnunet_vpn_fence(vpn: *const GnVpn) -> i32 {
    // SAFETY: the caller keeps the opaque handle live for this call.
    let Some(vpn) = (unsafe { vpn.as_ref() }) else {
        return INVALID;
    };
    vpn.source.fence_packets();
    OK
}

/// Fence the provider and report actual native teardown.
///
/// # Safety
/// Keep the handle live and lend any diagnostic range through this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gnunet_vpn_revoke(vpn: *const GnVpn, absent: u32, detail: GnBytes) -> i32 {
    // SAFETY: both external borrows stay live through this call.
    let (Some(vpn), Some(detail)) = (unsafe { (vpn.as_ref(), detail.text(4096)) }) else {
        return INVALID;
    };
    if absent > 1 {
        return INVALID;
    }
    vpn.source.revoke(CloseOutcome {
        routes_absent: absent == 1,
        error: (!detail.is_empty()).then(|| diagnostic(detail)),
    });
    OK
}

/// Release an original VPN control handle.
///
/// # Safety
/// Non-null handles must have been transferred by start exactly once. Exclude
/// every other access during destruction and retire native callbacks first.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gnunet_vpn_destroy(vpn: *mut GnVpn) {
    if !vpn.is_null() {
        // SAFETY: this is the original singly owned transferred allocation.
        drop(unsafe { Box::from_raw(vpn) });
    }
}

#[cfg(all(test, unix))]
mod tests;
