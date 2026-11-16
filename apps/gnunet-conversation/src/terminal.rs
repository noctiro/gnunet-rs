use crate::Failure;
use std::{
    collections::VecDeque,
    io,
    task::{Context, Poll},
    time::Instant,
};
use zeroize::Zeroizing;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
#[cfg(unix)]
pub(super) use unix::Descriptor;
#[cfg(windows)]
use windows::Descriptor;
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
    #[cfg(windows)]
    pub input_retirement: Option<windows::Retirement>,
    #[cfg(windows)]
    pub output_retirement: Option<windows::Retirement>,
    pub input_restore: Option<io::Error>,
    pub output_restore: Option<io::Error>,
}
impl Report {
    pub fn successful(&self) -> bool {
        #[cfg(windows)]
        if !self
            .input_retirement
            .as_ref()
            .is_some_and(windows::Retirement::successful)
            || !self
                .output_retirement
                .as_ref()
                .is_some_and(windows::Retirement::successful)
        {
            return false;
        }
        self.output_drained && self.input_restore.is_none() && self.output_restore.is_none()
    }
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
    closing: Option<Instant>,
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
        let (input, output) = Descriptor::standard_pair()?;
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
            closing: None,
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
        let mut end = front.at.saturating_add(16384).min(front.bytes.len());
        // Console text writes require complete UTF-8; redirected output retains
        // the same byte stream. Queue cursors advance only after native completion.
        while end < front.bytes.len() && front.bytes[end] & 0xc0 == 0x80 {
            end -= 1;
        }
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
    pub fn begin_close(&mut self, hard: Instant) {
        if self.closing.is_none() {
            self.closing = Some(hard);
        }
        if let Some(error) = self.input.retire(hard) {
            self.report.input_restore = Some(error);
        }
    }
    pub fn poll_close(&mut self, cx: &mut Context<'_>) -> bool {
        let Some(hard) = self.closing else {
            return false;
        };
        if self.drained()
            && let Some(error) = self.output.retire(hard)
        {
            self.report.output_restore = Some(error);
        }
        let input = self.input.poll_closed(cx, &mut self.report.input_restore);
        let output = self.output.poll_closed(cx, &mut self.report.output_restore);
        input && output
    }
    pub fn closed(&self) -> bool {
        self.input.closed() && self.output.closed()
    }
    pub fn abort_output(&mut self) {
        let hard = self.closing.unwrap_or_else(Instant::now);
        if let Some(error) = self.output.retire(hard) {
            self.report.output_restore = Some(error);
        }
    }
    pub fn close(&mut self) -> Report {
        self.report.output_drained = self.drained();
        if let Some(error) = self.output.close() {
            self.report.output_restore = Some(error);
        }
        if let Some(error) = self.input.close() {
            self.report.input_restore = Some(error);
        }
        #[cfg(windows)]
        {
            self.report.input_retirement = self.input.take_retirement();
            self.report.output_retirement = self.output.take_retirement();
        }
        std::mem::take(&mut self.report)
    }
}
