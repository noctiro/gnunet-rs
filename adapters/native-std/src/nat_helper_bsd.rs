//! Explicit Darwin/modern FreeBSD NAT-helper native boundary.
//!
//! Open privileged raw descriptors before inspecting helper input, then call
//! `drop_to_real_ids` in the dedicated single-threaded helper. No operation here
//! is invoked implicitly. FreeBSD packet handling targets the network-order ABI
//! introduced in FreeBSD 11, rather than historical BSD raw-header conventions.
pub use crate::nat_helper_io::{Output, Signals};
use std::{
    io,
    mem::size_of,
    os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
};

/// Open the privileged full-header IPv4 writer, with close-on-exec set before
/// returning its unique ownership. It is not yet configured for packet output.
pub fn open_raw_send() -> io::Result<OwnedFd> {
    open_raw(libc::IPPROTO_RAW)
}

/// Open the privileged IPv4 ICMP reader. Raw input includes the outer IP header.
pub fn open_raw_icmp() -> io::Result<OwnedFd> {
    open_raw(libc::IPPROTO_ICMP)
}

#[expect(
    unsafe_code,
    reason = "socket returns one fresh descriptor, adopted once; fcntl uses constant integer commands on that retained descriptor"
)]
fn open_raw(protocol: libc::c_int) -> io::Result<OwnedFd> {
    // SAFETY: target libc supplies the socket constants; no pointer is passed.
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, protocol) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful socket returned one fresh descriptor owned only here.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    // Darwin has no SOCK_CLOEXEC. This dedicated helper is single-threaded and
    // does not exec/spawn between socket and fcntl. A failure drops the same fd.
    // SAFETY: F_GETFD takes no variadic argument and borrows the retained fd.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: F_SETFD takes the initialized c_int flags; it does not adopt fd.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

/// Receipt of the actual permanent ID transition. Real UID zero remains root;
/// this type never represents that case as an unprivileged ordinary caller.
#[derive(Clone, Copy, Debug)]
pub struct Dropped {
    uid: u32,
    gid: u32,
}
impl Dropped {
    /// Original real UID, now also effective and saved UID.
    pub const fn uid(self) -> u32 {
        self.uid
    }
    /// Original real GID, now also effective and saved GID.
    pub const fn gid(self) -> u32 {
        self.gid
    }
    /// Linux ambient capabilities do not exist on these platforms. False does
    /// not claim that a Linux capability syscall ran or that real UID0 ceased.
    pub const fn ambient_supported(self) -> bool {
        false
    }
}

/// Permanently set real/effective/saved IDs to the invoking real UID/GID. An
/// effective-root helper first clears supplementary groups. No username, NSS,
/// environment or file lookup occurs. Call once before input, configuration,
/// output ownership or additional threads. Partial failure is terminal: close
/// captured descriptors and exit rather than processing helper input.
#[expect(
    unsafe_code,
    reason = "target credential syscalls affect only this dedicated single-threaded helper; scalar IDs come from the same process and checked out-pointers address live scalars"
)]
pub fn drop_to_real_ids() -> io::Result<Dropped> {
    // SAFETY: these current-process identity queries take no pointers.
    let (uid, gid, euid) = unsafe { (libc::getuid(), libc::getgid(), libc::geteuid()) };
    if euid == 0 {
        // SAFETY: zero groups permits a null array. This helper deliberately
        // removes supplementary privilege before dropping its effective root ID.
        if unsafe { libc::setgroups(0, std::ptr::null()) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    #[cfg(target_os = "macos")]
    {
        // Darwin setre{g,u}id with both IDs specified equal replaces the saved
        // ID when it differs, including a set-ID invocation by an ordinary UID.
        // Drop group privilege before the UID that authorizes that transition.
        // SAFETY: original real GID is a valid target; no pointers are passed.
        if unsafe { libc::setregid(gid, gid) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: original real UID is a valid target; no pointers are passed.
        if unsafe { libc::setreuid(uid, uid) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    #[cfg(target_os = "freebsd")]
    {
        // SAFETY: all three group IDs deliberately become the original real GID.
        if unsafe { libc::setresgid(gid, gid, gid) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: all three user IDs deliberately become the original real UID.
        if unsafe { libc::setresuid(uid, uid, uid) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let (mut ru, mut eu, mut su, mut rg, mut eg, mut sg) = (0, 0, 0, 0, 0, 0);
        // SAFETY: the outputs are distinct live, aligned target uid_t scalars;
        // successful getresuid initializes each before inspection.
        if unsafe { libc::getresuid(&mut ru, &mut eu, &mut su) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: same invariant for the three target gid_t outputs.
        if unsafe { libc::getresgid(&mut rg, &mut eg, &mut sg) } < 0 {
            return Err(io::Error::last_os_error());
        }
        if [ru, eu, su] != [uid; 3] || [rg, eg, sg] != [gid; 3] {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "helper saved IDs did not become the original real IDs",
            ));
        }
    }
    // Darwin has no getresuid/getresgid syscall. Saved-ID replacement above
    // relies on its actual setreuid/setregid contract; verify exposed IDs too.
    // SAFETY: identity queries take no pointers and do not change credentials.
    let actual = unsafe {
        (
            libc::getuid(),
            libc::geteuid(),
            libc::getgid(),
            libc::getegid(),
        )
    };
    if actual != (uid, uid, gid, gid) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "helper real/effective ID transition did not persist",
        ));
    }
    Ok(Dropped { uid, gid })
}

/// Check the original launching parent after the credential transition. Darwin
/// and FreeBSD use the runner's bounded periodic exact-parent checks; this call
/// does not claim to install Linux PDEATHSIG or an asynchronous death signal.
#[expect(
    unsafe_code,
    reason = "getppid only queries this current process and takes no pointers"
)]
pub fn watch_parent(original: i32) -> io::Result<bool> {
    // SAFETY: getppid has no ownership or pointer parameters.
    Ok(original > 1 && unsafe { libc::getppid() } == original)
}

/// Enable full-header IPv4 output and broadcast on the retained raw socket.
/// Both options must actually succeed; the caller retains its descriptor.
#[expect(
    unsafe_code,
    reason = "setsockopt borrows a live owned fd and reads a correctly sized initialized c_int only during each call"
)]
pub fn configure_raw(fd: &impl AsFd) -> io::Result<()> {
    let one: libc::c_int = 1;
    for (level, option) in [
        (libc::SOL_SOCKET, libc::SO_BROADCAST),
        (libc::IPPROTO_IP, libc::IP_HDRINCL),
    ] {
        // SAFETY: fd and the aligned initialized value remain live for the call;
        // target libc supplies all constants and exact socklen_t representation.
        if unsafe {
            libc::setsockopt(
                fd.as_fd().as_raw_fd(),
                level,
                option,
                (&one as *const libc::c_int).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn malformed() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid raw ICMP kernel envelope",
    )
}

/// Restore the raw ICMP kernel representation to network-order packet bytes for
/// the existing pure NAT parser. This is not an integrity/authenticity receipt.
/// Only a validated outer IPv4 header and Darwin's type11/code0 quoted length
/// are changed; original checksums and all remaining bytes are retained.
/// Failure leaves the caller's packet unchanged. Never call twice on a Darwin
/// packet or pass ordinary network-order input as a Darwin raw-kernel packet.
pub fn normalize_received(packet: &mut [u8]) -> io::Result<()> {
    let h = packet.get(..20).ok_or_else(malformed)?;
    let ihl = usize::from(h[0] & 15) * 4;
    if h[0] >> 4 != 4 || !(20..=60).contains(&ihl) || ihl > packet.len() {
        return Err(malformed());
    }
    #[cfg(target_os = "macos")]
    {
        // XNU ip_input supplies host-order payload length and fragment offset.
        // icmp_input's error delivery additionally converts the quoted ip_len
        // to host order before the packet is handed to raw ICMP listeners.
        let total = usize::from(u16::from_ne_bytes([h[2], h[3]]))
            .checked_add(ihl)
            .filter(|n| *n == packet.len())
            .and_then(|n| u16::try_from(n).ok())
            .ok_or_else(malformed)?;
        let offset = u16::from_ne_bytes([h[6], h[7]]);
        let quote =
            if h[9] == libc::IPPROTO_ICMP as u8 && packet.get(ihl..ihl + 2) == Some(&[11, 0]) {
                let start = ihl.checked_add(8).ok_or_else(malformed)?;
                let quoted = packet.get(start..start + 20).ok_or_else(malformed)?;
                let qihl = usize::from(quoted[0] & 15) * 4;
                let length = u16::from_ne_bytes([quoted[2], quoted[3]]);
                if quoted[0] >> 4 != 4
                    || !(20..=60).contains(&qihl)
                    || usize::from(length) < qihl
                    || packet.get(start..start + qihl).is_none()
                {
                    return Err(malformed());
                }
                Some((start + 2, length))
            } else {
                None
            };
        // All validation precedes mutation, and only kernel-altered fields are
        // restored. In particular the quoted ip_off remains network order.
        packet[2..4].copy_from_slice(&total.to_be_bytes());
        packet[6..8].copy_from_slice(&offset.to_be_bytes());
        if let Some((at, length)) = quote {
            packet[at..at + 2].copy_from_slice(&length.to_be_bytes());
        }
    }
    #[cfg(target_os = "freebsd")]
    {
        // FreeBSD 11+ leaves every raw IPv4 header field in network order.
        if usize::from(u16::from_be_bytes([h[2], h[3]])) != packet.len() {
            return Err(malformed());
        }
    }
    Ok(())
}
