//! Linux NAT-helper native boundary. Call raw capture first, then permanently
//! drop IDs/capabilities before arguments, diagnostics, socket options or I/O.
//! These functions are never invoked implicitly or by another service owner.
pub use crate::nat_helper_io::{Output, Signals};
use std::{
    io,
    mem::size_of,
    os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
};
/// Open only the privileged raw IPv4 write descriptor. No input is inspected.
#[expect(
    unsafe_code,
    reason = "Linux socket returns a fresh exclusively owned descriptor; only nonnegative results are adopted exactly once"
)]
pub fn open_raw_send() -> io::Result<OwnedFd> {
    // SAFETY: all socket arguments are constant Linux ABI values, with no pointers.
    let fd = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::IPPROTO_RAW,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful socket created one fresh fd not owned elsewhere.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
/// Open only the privileged raw IPv4 ICMP input descriptor.
#[expect(
    unsafe_code,
    reason = "Linux socket returns a fresh exclusively owned descriptor; only nonnegative results are adopted exactly once"
)]
pub fn open_raw_icmp() -> io::Result<OwnedFd> {
    // SAFETY: constant arguments and no external pointers.
    let fd = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::IPPROTO_ICMP,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fresh successful socket fd has one unique Rust owner.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}
const _: () = assert!(size_of::<CapHeader>() == 8 && size_of::<CapData>() == 12);
/// Actual permanent credential/capability-drop receipt. A real root caller still
/// has UID0; this report does not falsely describe that case as an ordinary UID.
#[derive(Clone, Copy, Debug)]
pub struct Dropped {
    uid: u32,
    gid: u32,
    ambient_supported: bool,
}
impl Dropped {
    /// Actual real/res/effective UID after the transition.
    pub const fn uid(self) -> u32 {
        self.uid
    }
    /// Actual real/res/effective GID after the transition.
    pub const fn gid(self) -> u32 {
        self.gid
    }
    /// Whether ambient-capability CLEAR_ALL was supported and succeeded.
    pub const fn ambient_supported(self) -> bool {
        self.ambient_supported
    }
}
/// Irreversibly reduce to the real invoking IDs, clear supplementary groups when
/// effective-root, clear all three capability sets and ambient capabilities, and
/// enable no_new_privs. No username/NSS/env/config/file lookup occurs. Call once
/// in a single-threaded helper before untrusted input or any other native owner.
#[expect(
    unsafe_code,
    reason = "Fixed Linux credential/prctl/UAPI capset calls touch only current-process IDs and correctly laid-out caller-owned scalar buffers"
)]
pub fn drop_to_real_ids() -> io::Result<Dropped> {
    // SAFETY: identity queries have no pointer/ownership arguments.
    let (uid, gid, euid) = unsafe { (libc::getuid(), libc::getgid(), libc::geteuid()) };
    // SAFETY: prctl's remaining variadic integer arguments are provided as c_ulong.
    if unsafe {
        libc::prctl(
            libc::PR_SET_KEEPCAPS,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    if euid == 0 {
        // SAFETY: zero count explicitly permits a null gid array; current helper owns
        // this single-threaded process and intentionally removes supplementary groups.
        if unsafe { libc::setgroups(0, std::ptr::null()) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    // SAFETY: real IDs came from the same current process, no pointers are passed.
    if unsafe { libc::setresgid(gid, gid, gid) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: all saved/effective IDs are permanently replaced with the real UID.
    if unsafe { libc::setresuid(uid, uid, uid) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // Linux UAPI capability.h v3 is u32 version + s32 pid, followed by two
    // {u32 effective,u32 permitted,u32 inheritable} words for the current task.
    let header = CapHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: syscall number comes from target libc, header/data have the exact
    // Linux v3 C representation, fixed initialized lengths, and live stack storage.
    if unsafe {
        libc::syscall(
            libc::SYS_capset,
            &header as *const CapHeader,
            &data as *const [CapData; 2],
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: PR_CAP_AMBIENT_CLEAR_ALL has integer-only arguments for current task.
    let ambient = unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    let ambient_supported = if ambient < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EINVAL) {
            false
        } else {
            return Err(error);
        }
    } else {
        true
    };
    // SAFETY: fixed no_new_privs request, current task only, no pointer arguments.
    if unsafe {
        libc::prctl(
            libc::PR_SET_NO_NEW_PRIVS,
            1 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let (mut ru, mut eu, mut su, mut rg, mut eg, mut sg) = (0, 0, 0, 0, 0, 0);
    // SAFETY: each out pointer addresses a live correctly typed scalar of sufficient
    // size; successful calls initialize all outputs before they are inspected.
    if unsafe { libc::getresuid(&mut ru, &mut eu, &mut su) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: same argument/lifetime guarantees for the GID output scalars.
    if unsafe { libc::getresgid(&mut rg, &mut eg, &mut sg) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if [ru, eu, su] != [uid; 3] || [rg, eg, sg] != [gid; 3] {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "helper credential transition did not persist",
        ));
    }
    Ok(Dropped {
        uid,
        gid,
        ambient_supported,
    })
}
/// Bind this dedicated helper to its observed original launching parent after
/// the credential drop (Linux clears PDEATHSIG on a set-ID transition). Recheck
/// the same parent immediately so an intervening parent death cannot be retagged.
#[expect(
    unsafe_code,
    reason = "PR_SET_PDEATHSIG takes a constant signal number and no pointers; the following getppid only queries this task"
)]
pub fn watch_parent(original: i32) -> io::Result<bool> {
    // SAFETY: integer-only prctl affects this single-threaded helper task; SIGTERM
    // is handled by its later process-local owner or has the kernel default action.
    if unsafe {
        libc::prctl(
            libc::PR_SET_PDEATHSIG,
            libc::SIGTERM as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: getppid has no pointer or ownership parameters.
    Ok(original > 1 && unsafe { libc::getppid() } == original)
}
/// Enable actual IPv4 full-header raw output after the drop. The borrowed fd
/// remains caller-owned; both SO_BROADCAST and IP_HDRINCL must really succeed.
#[expect(
    unsafe_code,
    reason = "setsockopt borrows an owned socket and a correctly sized initialized c_int; it neither adopts nor closes the descriptor"
)]
pub fn configure_raw(fd: &impl AsFd) -> io::Result<()> {
    let one: libc::c_int = 1;
    for (level, option) in [
        (libc::SOL_SOCKET, libc::SO_BROADCAST),
        (libc::IPPROTO_IP, libc::IP_HDRINCL),
    ] {
        // SAFETY: fd is borrowed live; option data is an aligned c_int of exact length,
        // and the OS only reads it during this synchronous call.
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
