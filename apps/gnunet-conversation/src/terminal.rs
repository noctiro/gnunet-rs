use crate::Failure;
use gnunet_service_runtime::readiness::RegisteredIo;
use nix::{
    fcntl::{FcntlArg, OFlag, fcntl},
    unistd,
};
use std::{
    collections::VecDeque,
    io,
    os::fd::{AsFd, OwnedFd},
    task::{Context, Poll},
};
use zeroize::Zeroizing;

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
pub(super) struct Descriptor {
    source: Option<Source>,
    restore: Option<OFlag>,
}
impl Descriptor {
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

pub(super) struct Text {
    bytes: Zeroizing<Vec<u8>>,
    limit: usize,
}
impl Text {
    pub fn new(limit: usize) -> Self {
        Self {
            bytes: Zeroizing::new(Vec::new()),
            limit,
        }
    }
    pub fn push(&mut self, input: &[u8]) -> Result<(), Failure> {
        let n = self
            .bytes
            .len()
            .checked_add(input.len())
            .ok_or(gnunet_types::Error::Overflow)?;
        if n > self.limit {
            return Err("Conversation text exceeds the output profile".into());
        }
        if n > self.bytes.capacity() {
            let proposed = self
                .bytes
                .capacity()
                .saturating_mul(2)
                .max(64)
                .max(n)
                .min(self.limit);
            let additional = proposed - self.bytes.len();
            self.bytes.try_reserve_exact(additional)?;
        }
        if self.bytes.capacity() > self.limit {
            return Err("Conversation output allocation exceeds its profile".into());
        }
        self.bytes.extend_from_slice(input);
        Ok(())
    }
    pub fn escaped(&mut self, input: &[u8]) -> Result<(), Failure> {
        self.push(b"\"")?;
        for b in input {
            match *b {
                b' '..=b'~' if *b != b'"' && *b != b'\\' => self.push(&[*b])?,
                other => {
                    const HEX: &[u8; 16] = b"0123456789abcdef";
                    self.push(&[
                        b'\\',
                        b'x',
                        HEX[usize::from(other >> 4)],
                        HEX[usize::from(other & 15)],
                    ])?;
                }
            }
        }
        self.push(b"\"")
    }
    pub fn number(&mut self, n: u64) -> Result<(), Failure> {
        self.push(n.to_string().as_bytes())
    }
}
struct Write {
    bytes: Zeroizing<Vec<u8>>,
    at: usize,
}
pub(super) enum Event {
    Command(Vec<u8>),
    Eof,
    Activity,
}
#[derive(Debug, Default)]
pub(super) struct Report {
    pub read_bytes: usize,
    pub written_bytes: usize,
    pub eof: bool,
    pub output_drained: bool,
    pub input_restore: Option<io::Error>,
    pub output_restore: Option<io::Error>,
}
pub(super) struct Terminal {
    input: Descriptor,
    output: Descriptor,
    buffer: Zeroizing<Vec<u8>>,
    input_cursor: usize,
    command_limit: usize,
    queue: VecDeque<Write>,
    queued_bytes: usize,
    output_limit: usize,
    read_first: bool,
    eof: bool,
    pub report: Report,
}
impl Terminal {
    pub fn new(command_limit: usize, output_limit: usize) -> Result<Self, Failure> {
        let mut buffer = Zeroizing::new(Vec::new());
        let cap = command_limit
            .checked_add(4096)
            .ok_or(gnunet_types::Error::Overflow)?;
        buffer.try_reserve_exact(cap)?;
        if buffer.capacity() > cap {
            return Err("terminal input allocation exceeded its bound".into());
        }
        let mut queue = VecDeque::new();
        queue.try_reserve_exact(64)?;
        let stdin = io::stdin();
        let stdout = io::stdout();
        // Capture both originals before either descriptor changes shared OFD
        // flags. Duplication alone does not create a distinct open-file owner.
        let input_flags = Descriptor::flags(&stdin)?;
        let output_flags = Descriptor::flags(&stdout)?;
        let mut input = Descriptor::standard(&stdin, input_flags)?;
        let output = match Descriptor::standard(&stdout, output_flags) {
            Ok(v) => v,
            Err(original) => {
                let cleanup = input.close();
                return Err(Box::new(Acquisition { original, cleanup }));
            }
        };
        Ok(Self {
            input,
            output,
            buffer,
            input_cursor: 0,
            command_limit,
            queue,
            queued_bytes: 0,
            output_limit,
            read_first: true,
            eof: false,
            report: Report::default(),
        })
    }
    pub fn text(&self) -> Text {
        Text::new(self.output_limit)
    }
    pub fn enqueue(&mut self, text: Text) -> Result<(), Failure> {
        if text.bytes.is_empty() {
            return Ok(());
        }
        let total = self
            .queued_bytes
            .checked_add(text.bytes.capacity())
            .ok_or(gnunet_types::Error::Overflow)?;
        if self.queue.len() >= 64 || total > self.output_limit {
            return Err("Conversation stdout backpressure exhausted its finite queue".into());
        }
        self.queue.push_back(Write {
            bytes: text.bytes,
            at: 0,
        });
        self.queued_bytes = total;
        Ok(())
    }
    pub fn message(&mut self, input: &[u8]) -> Result<(), Failure> {
        let mut text = self.text();
        text.push(input)?;
        self.enqueue(text)
    }
    fn command(&mut self) -> Result<Option<Event>, Failure> {
        let remaining = &self.buffer[self.input_cursor..];
        let newline = remaining.iter().position(|b| *b == b'\n');
        if let Some(end) = newline {
            if end > self.command_limit {
                return Err("interactive command exceeds COMMAND_BYTES".into());
            }
            let end = self.input_cursor + end;
            let mut bytes = crate::options::copy(
                &self.buffer[self.input_cursor..end],
                self.command_limit,
                true,
            )?;
            if bytes.last() == Some(&b'\r') {
                bytes.pop();
            }
            self.input_cursor = end + 1;
            return Ok(Some(Event::Command(bytes)));
        }
        if remaining.len() > self.command_limit {
            return Err("interactive command exceeds COMMAND_BYTES".into());
        }
        if self.eof {
            if !remaining.is_empty() {
                let bytes = crate::options::copy(remaining, self.command_limit, true)?;
                self.input_cursor = self.buffer.len();
                return Ok(Some(Event::Command(bytes)));
            }
            return Ok(Some(Event::Eof));
        }
        Ok(None)
    }
    fn read(&mut self, cx: &mut Context<'_>) -> Poll<Result<Event, Failure>> {
        if let Some(event) = self.command()? {
            return Poll::Ready(Ok(event));
        }
        if self.input_cursor != 0 {
            let keep = self.buffer.len() - self.input_cursor;
            self.buffer.copy_within(self.input_cursor.., 0);
            use zeroize::Zeroize;
            self.buffer[keep..].zeroize();
            self.buffer.truncate(keep);
            self.input_cursor = 0;
        }
        let mut bytes = [0u8; 4096];
        match self.input.read(cx, &mut bytes) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::Interrupted => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(n)) => {
                if n == 0 {
                    self.eof = true;
                    self.report.eof = true;
                } else {
                    if self.buffer.len() + n > self.command_limit + 4096 {
                        return Poll::Ready(Err("terminal read extent exceeds its bound".into()));
                    }
                    self.buffer.extend_from_slice(&bytes[..n]);
                    self.report.read_bytes = self
                        .report
                        .read_bytes
                        .checked_add(n)
                        .ok_or(gnunet_types::Error::Overflow)?;
                }
                Poll::Ready(Ok(Event::Activity))
            }
        }
    }
    pub fn poll_write(&mut self, cx: &mut Context<'_>) -> Poll<Result<Event, Failure>> {
        let Some(front) = self.queue.front_mut() else {
            return Poll::Pending;
        };
        let end = front.at.saturating_add(16384).min(front.bytes.len());
        match self.output.write(cx, &front.bytes[front.at..end]) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::Interrupted => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(0)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "Conversation stdout made no progress",
            )
            .into())),
            Poll::Ready(Ok(n)) => {
                front.at += n;
                self.report.written_bytes = self
                    .report
                    .written_bytes
                    .checked_add(n)
                    .ok_or(gnunet_types::Error::Overflow)?;
                if front.at == front.bytes.len() {
                    let original = self
                        .queue
                        .pop_front()
                        .ok_or("stdout FIFO lost its original frame")?;
                    self.queued_bytes -= original.bytes.capacity();
                }
                Poll::Ready(Ok(Event::Activity))
            }
        }
    }
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Event, Failure>> {
        let first = self.read_first;
        self.read_first = !first;
        for read in [first, !first] {
            let event = if read {
                self.read(cx)
            } else {
                self.poll_write(cx)
            };
            if event.is_ready() {
                return event;
            }
        }
        Poll::Pending
    }
    pub fn drained(&self) -> bool {
        self.queue.is_empty()
    }
    pub fn abort_output(&mut self) {
        if let Some(error) = self.output.close() {
            self.report.output_restore = Some(error);
        }
    }
    pub fn close(&mut self) -> Report {
        self.report.output_drained = self.drained();
        if let Some(error) = self.output.close() {
            self.report.output_restore = Some(error);
        }
        self.report.input_restore = self.input.close();
        std::mem::take(&mut self.report)
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
