//! Exact FreeBSD PF state retirement through the `DIOCKILLSTATESNV` device ABI.
mod nv;

use std::{
    ffi::c_void,
    fs::{File, OpenOptions},
    io,
    num::{NonZeroU32, NonZeroU64},
    os::{
        fd::AsRawFd,
        unix::fs::{FileTypeExt, OpenOptionsExt},
    },
    time::Instant,
};

#[repr(C)]
struct Request {
    data: *mut c_void,
    len: usize,
    size: usize,
}

// FreeBSD sys/ioccom.h _IOWR('D', 41, struct pfioc_nv).
const DIOCKILLSTATESNV: libc::c_ulong = 0xc000_0000
    | ((size_of::<Request>() as libc::c_ulong) << 16)
    | (b'D' as libc::c_ulong) << 8
    | 41;

/// One original PF device and a fixed deadline for exact-ID state retirement.
/// Call all operations in the original jail/VNET context. The kernel selects
/// the VNET from the calling thread, independent of the retained descriptor.
pub struct StateKiller {
    file: Option<File>,
    deadline: Instant,
}

impl StateKiller {
    /// Open the original PF device before attempting a state mutation.
    ///
    /// # Errors
    /// Preserves the open error and refuses a non-character device or an
    /// expired original deadline.
    pub fn open(deadline: Instant) -> io::Result<Self> {
        timely(deadline)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open("/dev/pf")?;
        if !file.metadata()?.file_type().is_char_device() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "PF source must be a character device",
            ));
        }
        timely(deadline)?;
        Ok(Self {
            file: Some(file),
            deadline,
        })
    }

    /// Retire only the original state identified by the full native pair.
    /// `false` means the original pair no longer exists in the caller's VNET.
    ///
    /// # Errors
    /// A failed ioctl, unrecognized reply or late return retires this handle.
    /// The syscall may have applied the effect before reporting an error.
    #[expect(
        unsafe_code,
        reason = "PF ioctl borrows one live device and one exact native request whose byte buffer remains exclusive"
    )]
    pub fn retire(&mut self, state: NonZeroU64, creator: NonZeroU32) -> io::Result<bool> {
        let (mut bytes, len) = nv::kill(state, creator)?;
        timely(self.deadline)?;
        let file = self.file.take().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "PF original retirement handle is closed",
            )
        })?;
        let mut request = Request {
            data: bytes.as_mut_ptr().cast(),
            len,
            size: bytes.len(),
        };
        // SAFETY: the buffer has `size` bytes and outlives this synchronous ioctl.
        // The supplied command selects the exact C-compatible Request layout.
        if unsafe { libc::ioctl(file.as_raw_fd(), DIOCKILLSTATESNV, &raw mut request) } < 0 {
            return Err(io::Error::last_os_error());
        }
        timely(self.deadline)?;
        let killed = nv::ack(bytes.get(..request.len).ok_or_else(nv::invalid)?)?;
        self.file = Some(file);
        Ok(killed)
    }
}

fn timely(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "original PF state retirement deadline",
        ));
    }
    Ok(())
}
