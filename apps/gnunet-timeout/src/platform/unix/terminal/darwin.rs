//! Reopen the process's original terminal when its `/dev/tty` alias cannot answer ioctls.
use super::same_terminal_session;
use nix::{
    libc,
    sys::stat::fstat,
    unistd::{getpid, tcgetpgrp},
};
use std::{
    ffi::{CStr, OsStr},
    fs::OpenOptions,
    mem::{MaybeUninit, size_of},
    os::{
        fd::OwnedFd,
        unix::{ffi::OsStrExt, fs::OpenOptionsExt},
    },
    path::Path,
};

pub(super) fn controlling_terminal() -> Option<OwnedFd> {
    let device = controlling_device()?;
    let mut storage = [0; libc::PATH_MAX as usize];
    let name = device_name(device, &mut storage)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(Path::new("/dev").join(name))
        .ok()?;
    let stat = fstat(&file).ok()?;
    (stat.st_mode & libc::S_IFMT == libc::S_IFCHR
        && stat.st_rdev == device
        && same_terminal_session(&file)
        && tcgetpgrp(&file).is_ok()
        && controlling_device() == Some(device))
    .then(|| file.into())
}

#[expect(
    unsafe_code,
    reason = "Darwin's fixed proc_bsdinfo result is initialized by an exact-size self-process query"
)]
fn controlling_device() -> Option<libc::dev_t> {
    let pid = getpid().as_raw();
    let mut info = MaybeUninit::<libc::proc_bsdinfo>::uninit();
    let size = size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: the SDK-shaped writable buffer stays live through the synchronous self-query.
    let bytes = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if bytes != size {
        return None;
    }
    // SAFETY: an exact-size result initializes the entire declared structure.
    let info = unsafe { info.assume_init() };
    // Darwin's NODEV is -1. Preserve the bits of every other kernel device number.
    (info.pbi_pid == pid as u32 && info.e_tdev != u32::MAX).then_some(info.e_tdev as libc::dev_t)
}

#[expect(
    unsafe_code,
    reason = "Darwin devname_r writes into caller-owned bounded storage and supplies only a path hint"
)]
fn device_name(device: libc::dev_t, storage: &mut [u8; libc::PATH_MAX as usize]) -> Option<&OsStr> {
    unsafe extern "C" {
        fn devname_r(
            device: libc::dev_t,
            kind: libc::mode_t,
            name: *mut libc::c_char,
            size: libc::c_int,
        ) -> *mut libc::c_char;
    }
    let buffer = storage.as_mut_ptr().cast();
    // SAFETY: Darwin's SDK declaration takes this finite, live, writable buffer. An
    // unrecognized return pointer is refused and never dereferenced.
    if unsafe { devname_r(device, libc::S_IFCHR, buffer, libc::PATH_MAX) } != buffer {
        return None;
    }
    let name = CStr::from_bytes_until_nul(storage).ok()?.to_bytes();
    if matches!(name, b"" | b"." | b"..") || name.contains(&b'/') {
        return None;
    }
    Some(OsStr::from_bytes(name))
}
