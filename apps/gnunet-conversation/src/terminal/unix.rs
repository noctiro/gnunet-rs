use crate::Failure;
use gnunet_service_runtime::readiness::RegisteredIo;
use nix::{
    fcntl::{FcntlArg, OFlag, fcntl},
    unistd,
};
use std::{
    io,
    os::fd::{AsFd, OwnedFd},
    task::{Context, Poll},
};
#[derive(Debug)]
struct Acquisition {
    original: Failure,
    cleanup: Option<io::Error>,
}
impl std::fmt::Display for Acquisition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "terminal acquisition: {}; independent restore: {:?}",
            self.original, self.cleanup
        )
    }
}
impl std::error::Error for Acquisition {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.original.as_ref())
    }
}
// XNU exposes its kernel-owned FWASWRITTEN history bit through F_GETFL.
// It can appear after our own successful write; only macOS excludes this
// known bit from the user-controlled flag ownership comparison.
fn restoration_flags(
    original: OFlag,
    current: OFlag,
    macos_written_history: bool,
) -> Option<OFlag> {
    let history = if macos_written_history {
        0x0001_0000
    } else {
        0
    };
    let observed = current.bits() & !history;
    let expected = original.bits() & !history;
    if observed != expected && observed != (expected | OFlag::O_NONBLOCK.bits()) {
        return None;
    }
    Some(OFlag::from_bits_retain(
        (current.bits() & !OFlag::O_NONBLOCK.bits()) | (original.bits() & OFlag::O_NONBLOCK.bits()),
    ))
}
fn restore_standard(fd: &impl AsFd, original: OFlag) -> io::Result<()> {
    let current = Descriptor::flags(fd)?;
    let restored = restoration_flags(original, current, cfg!(target_os = "macos"))
        .ok_or_else(|| io::Error::other(format!(
            "terminal open-file flags changed independently; original flags were not overwritten (original={:#010x}, expected_nonblocking={:#010x}, current={:#010x})",
            original.bits(),
            (original | OFlag::O_NONBLOCK).bits(),
            current.bits(),
        )))?;
    // STDIN/STDOUT can share an open-file description. Another owned
    // descriptor may already have restored NONBLOCK. Keep every live other
    // bit, including XNU's write history, rather than reinstalling a snapshot.
    if restored != current {
        fcntl(fd, FcntlArg::F_SETFL(restored))?;
    }
    Ok(())
}
enum Source {
    Reactor(RegisteredIo),
    File(OwnedFd),
}
/// Explicit duplicated stdio/owned pipe FD, without a blocking worker thread.
pub(crate) struct Descriptor {
    source: Option<Source>,
    restore: Option<OFlag>,
}
impl Descriptor {
    pub fn standard_pair() -> Result<(Self, Self), Failure> {
        let stdin = std::io::stdin();
        let stdout = std::io::stdout();
        // Capture both before mutation: stdin/stdout can share one open file description.
        let input_flags = Self::flags(&stdin)?;
        let output_flags = Self::flags(&stdout)?;
        let mut input = Self::standard(&stdin, input_flags)?;
        match Self::standard(&stdout, output_flags) {
            Ok(output) => Ok((input, output)),
            Err(original) => Err(Box::new(Acquisition {
                original,
                cleanup: input.close(),
            })),
        }
    }
    pub fn poll_close(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(0))
    }
    pub fn retire(&mut self, _hard: std::time::Instant) -> Option<io::Error> {
        self.close()
    }
    pub fn closed(&self) -> bool {
        self.source.is_none()
    }
    pub fn poll_closed(&mut self, _cx: &mut Context<'_>, _error: &mut Option<io::Error>) -> bool {
        self.closed()
    }

    pub fn flags(fd: &impl AsFd) -> io::Result<OFlag> {
        Ok(OFlag::from_bits_retain(fcntl(fd, FcntlArg::F_GETFL)?))
    }
    pub fn standard(fd: &impl AsFd, flags: OFlag) -> Result<Self, Failure> {
        let own = fd.as_fd().try_clone_to_owned()?;
        let file = std::fs::File::from(own);
        let regular = file.metadata()?.is_file();
        let own: OwnedFd = file.into();
        let current = Self::flags(&own)?;
        if restoration_flags(flags, current, cfg!(target_os = "macos")).is_none() {
            return Err(format!(
                "terminal original flags changed during acquisition (original={:#010x}, expected_nonblocking={:#010x}, current={:#010x})",
                flags.bits(),
                (flags | OFlag::O_NONBLOCK).bits(),
                current.bits(),
            ).into());
        }
        if let Err(error) = fcntl(&own, FcntlArg::F_SETFL(current | OFlag::O_NONBLOCK)) {
            let cleanup = restore_standard(&own, flags).err();
            return Err(Box::new(Acquisition {
                original: Box::new(error),
                cleanup,
            }));
        }
        if regular {
            return Ok(Self {
                source: Some(Source::File(own)),
                restore: Some(flags),
            });
        }
        match RegisteredIo::new(own) {
            Ok(reactor) => Ok(Self {
                source: Some(Source::Reactor(reactor)),
                restore: Some(flags),
            }),
            Err(failure) => {
                let cleanup = restore_standard(&failure.descriptor, flags).err();
                Err(Box::new(Acquisition {
                    original: Box::new(failure.error),
                    cleanup,
                }))
            }
        }
    }
    pub fn pipe(fd: OwnedFd) -> Result<Self, Failure> {
        Ok(Self {
            source: Some(Source::Reactor(
                RegisteredIo::new(fd).map_err(|failure| failure.error)?,
            )),
            restore: None,
        })
    }
    pub fn read(&mut self, cx: &mut Context<'_>, out: &mut [u8]) -> Poll<io::Result<usize>> {
        match self.source.as_ref() {
            Some(Source::File(fd)) => Poll::Ready(unistd::read(fd, out).map_err(io::Error::from)),
            Some(Source::Reactor(fd)) => fd.poll_read(cx, out),
            None => Poll::Ready(Err(io::ErrorKind::NotConnected.into())),
        }
    }
    pub fn write(&mut self, cx: &mut Context<'_>, input: &[u8]) -> Poll<io::Result<usize>> {
        match self.source.as_ref() {
            Some(Source::File(fd)) => {
                Poll::Ready(unistd::write(fd, input).map_err(io::Error::from))
            }
            Some(Source::Reactor(fd)) => fd.poll_write(cx, input),
            None => Poll::Ready(Err(io::ErrorKind::NotConnected.into())),
        }
    }
    pub fn close(&mut self) -> Option<io::Error> {
        let descriptor = self.source.take().map(|source| match source {
            Source::Reactor(registered) => registered.into_owned(),
            Source::File(owned) => owned,
        });
        let mut error = None;
        if let Some(original) = self.restore.take() {
            let restored = descriptor
                .as_ref()
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))
                .and_then(|fd| restore_standard(fd, original));
            error = restored.err();
        }
        drop(descriptor);
        error
    }
}
impl Drop for Descriptor {
    fn drop(&mut self) {
        let _actual = self.close();
    }
}

#[cfg(test)]
mod flag_tests {
    use super::{OFlag, restoration_flags};

    #[test]
    fn macos_write_history_preserves_live_bits() {
        let history = OFlag::from_bits_retain(0x0001_0000);
        let original = OFlag::O_WRONLY | OFlag::O_APPEND;
        let written = original | OFlag::O_NONBLOCK | history;
        assert_eq!(
            restoration_flags(original, written, true),
            Some(original | history)
        );
        assert_eq!(
            restoration_flags(original, original | history, true),
            Some(original | history)
        );
        let originally_nonblocking = original | OFlag::O_NONBLOCK;
        assert_eq!(
            restoration_flags(originally_nonblocking, written, true),
            Some(written)
        );
    }

    #[test]
    fn independent_append_change_remains_refused() {
        let original = OFlag::O_WRONLY;
        let history = OFlag::from_bits_retain(0x0001_0000);
        let changed = original | OFlag::O_NONBLOCK | OFlag::O_APPEND | history;
        assert_eq!(restoration_flags(original, changed, true), None);
        assert_eq!(
            restoration_flags(original | OFlag::O_APPEND, original | history, true),
            None
        );
    }

    #[test]
    fn other_platforms_do_not_ignore_the_same_numeric_bit() {
        let original = OFlag::O_WRONLY;
        let expected = original | OFlag::O_NONBLOCK;
        assert_eq!(restoration_flags(original, expected, false), Some(original));
        assert_eq!(
            restoration_flags(
                original,
                expected | OFlag::from_bits_retain(0x0001_0000),
                false
            ),
            None
        );
    }
}
