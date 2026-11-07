//! Owned stdio duplication; the same restoration rule as the normal terminal.
use gnunet_service_runtime::readiness::RegisteredIo;
use nix::{
    fcntl::{FcntlArg, OFlag, fcntl},
    unistd,
};
use std::{
    future::Future,
    io,
    os::fd::{AsFd, OwnedFd},
    os::unix::fs::FileTypeExt,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
fn flags(fd: &impl AsFd) -> io::Result<OFlag> {
    Ok(OFlag::from_bits_retain(fcntl(fd, FcntlArg::F_GETFL)?))
}
fn restore(fd: &impl AsFd, original: OFlag) -> io::Result<()> {
    let current = flags(fd)?;
    // XNU's kernel-owned write-history bit can change after our real write.
    // Preserve it; only user-controlled NONBLOCK was borrowed by this owner.
    let history = if cfg!(target_os = "macos") {
        0x0001_0000
    } else {
        0
    };
    let old = original.bits() & !history;
    let now = current.bits() & !history;
    if now != old && now != (old | OFlag::O_NONBLOCK.bits()) {
        return Err(io::Error::other(
            "stdio flags changed independently; original flags not overwritten",
        ));
    }
    let value = OFlag::from_bits_retain(
        (current.bits() & !OFlag::O_NONBLOCK.bits()) | (original.bits() & OFlag::O_NONBLOCK.bits()),
    );
    if value != current {
        fcntl(fd, FcntlArg::F_SETFL(value))?;
    }
    Ok(())
}
enum Source {
    Reactor(RegisteredIo),
    File(OwnedFd),
    // Unregisterable character devices still use actual nonblocking IO. A
    // fixed retry timer after EAGAIN prevents a readiness-free busy loop.
    Character(OwnedFd, Pin<Box<tokio::time::Sleep>>),
}
pub(super) struct Descriptor {
    source: Option<Source>,
    original: OFlag,
}
#[derive(Debug)]
pub(super) struct Acquisition {
    pub original: io::Error,
    pub output_restore: Option<io::Error>,
    pub input_restore: Option<io::Error>,
}
impl std::fmt::Display for Acquisition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "stdio acquisition: {}; output restore={:?}; input restore={:?}",
            self.original, self.output_restore, self.input_restore
        )
    }
}
impl std::error::Error for Acquisition {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}
impl Descriptor {
    fn open(fd: &impl AsFd, original: OFlag) -> Result<Self, Acquisition> {
        let prepare = || -> io::Result<OwnedFd> { fd.as_fd().try_clone_to_owned() };
        let owned = prepare().map_err(|original| Acquisition {
            original,
            output_restore: None,
            input_restore: None,
        })?;
        let file = std::fs::File::from(owned);
        let metadata = file.metadata().map_err(|original| Acquisition {
            original,
            output_restore: None,
            input_restore: None,
        })?;
        let regular = metadata.is_file();
        let character = metadata.file_type().is_char_device();
        let owned: OwnedFd = file.into();
        let changed = (|| -> io::Result<()> {
            let current = flags(&owned)?;
            let history = if cfg!(target_os = "macos") {
                0x0001_0000
            } else {
                0
            };
            let old = original.bits() & !history;
            let now = current.bits() & !history;
            if now != old && now != (old | OFlag::O_NONBLOCK.bits()) {
                return Err(io::Error::other("stdio flags changed during acquisition"));
            }
            fcntl(&owned, FcntlArg::F_SETFL(current | OFlag::O_NONBLOCK))?;
            Ok(())
        })();
        if let Err(error) = changed {
            return Err(Acquisition {
                original: error,
                output_restore: restore(&owned, original).err(),
                input_restore: None,
            });
        }
        if regular {
            return Ok(Self {
                source: Some(Source::File(owned)),
                original,
            });
        }
        match RegisteredIo::new(owned) {
            Ok(value) => Ok(Self {
                source: Some(Source::Reactor(value)),
                original,
            }),
            Err(error)
                if character
                    && matches!(error.error.raw_os_error(), Some(code) if code == nix::errno::Errno::EPERM as i32 || code == nix::errno::Errno::EINVAL as i32) =>
            {
                Ok(Self {
                    source: Some(Source::Character(
                        error.descriptor,
                        Box::pin(tokio::time::sleep(Duration::ZERO)),
                    )),
                    original,
                })
            }
            Err(error) => Err(Acquisition {
                output_restore: restore(&error.descriptor, original).err(),
                original: error.error,
                input_restore: None,
            }),
        }
    }
    pub fn pair() -> Result<(Self, Self), Acquisition> {
        let stdin = io::stdin();
        let stdout = io::stdout();
        // Capture both before either duplicate changes shared OFD flags.
        let input_flags = flags(&stdin).map_err(|original| Acquisition {
            original,
            output_restore: None,
            input_restore: None,
        })?;
        let output_flags = flags(&stdout).map_err(|original| Acquisition {
            original,
            output_restore: None,
            input_restore: None,
        })?;
        let mut input = Self::open(&stdin, input_flags).map_err(|mut error| {
            error.input_restore = error.output_restore.take();
            error
        })?;
        match Self::open(&stdout, output_flags) {
            Ok(output) => Ok((input, output)),
            Err(mut error) => {
                error.input_restore = input.close();
                Err(error)
            }
        }
    }
    pub fn read(&mut self, cx: &mut Context<'_>, bytes: &mut [u8]) -> Poll<io::Result<usize>> {
        match self.source.as_mut() {
            Some(Source::Reactor(fd)) => fd.poll_read(cx, bytes),
            Some(Source::File(fd)) => Poll::Ready(unistd::read(fd, bytes).map_err(io::Error::from)),
            Some(Source::Character(fd, timer)) => {
                if timer.as_mut().poll(cx).is_pending() {
                    return Poll::Pending;
                }
                match unistd::read(&*fd, bytes).map_err(io::Error::from) {
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        timer
                            .as_mut()
                            .reset(tokio::time::Instant::now() + Duration::from_millis(10));
                        if timer.as_mut().poll(cx).is_ready() {
                            cx.waker().wake_by_ref();
                        }
                        Poll::Pending
                    }
                    result => Poll::Ready(result),
                }
            }
            None => Poll::Ready(Err(io::ErrorKind::NotConnected.into())),
        }
    }
    pub fn write(&mut self, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        match self.source.as_mut() {
            Some(Source::Reactor(fd)) => fd.poll_write(cx, bytes),
            Some(Source::File(fd)) => {
                Poll::Ready(unistd::write(fd, bytes).map_err(io::Error::from))
            }
            Some(Source::Character(fd, timer)) => {
                if timer.as_mut().poll(cx).is_pending() {
                    return Poll::Pending;
                }
                match unistd::write(&*fd, bytes).map_err(io::Error::from) {
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        timer
                            .as_mut()
                            .reset(tokio::time::Instant::now() + Duration::from_millis(10));
                        if timer.as_mut().poll(cx).is_ready() {
                            cx.waker().wake_by_ref();
                        }
                        Poll::Pending
                    }
                    result => Poll::Ready(result),
                }
            }
            None => Poll::Ready(Err(io::ErrorKind::NotConnected.into())),
        }
    }
    pub fn close(&mut self) -> Option<io::Error> {
        let owned = self.source.take().map(|s| match s {
            Source::Reactor(fd) => fd.into_owned(),
            Source::File(fd) => fd,
            Source::Character(fd, _) => fd,
        });
        let error = owned
            .as_ref()
            .and_then(|fd| restore(fd, self.original).err());
        drop(owned);
        error
    }
}
impl Drop for Descriptor {
    fn drop(&mut self) {
        let _actual = self.close();
    }
}
