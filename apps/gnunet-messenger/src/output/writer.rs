//! Bounded frozen display rows over one original native binary writer.
use gnunet_program_host::binary_io;
use std::{
    collections::VecDeque,
    future::{Future, poll_fn},
    io::{self, Write},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Instant;
use zeroize::{Zeroize, Zeroizing};

pub(super) struct Frame {
    bytes: Zeroizing<Vec<u8>>,
    maximum: usize,
    hard: Instant,
}
impl Write for Frame {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let length = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or(io::ErrorKind::OutOfMemory)?;
        if length > self.maximum {
            return Err(io::Error::other(
                "Messenger output row exceeds OUTPUT_BYTES",
            ));
        }
        self.bytes
            .try_reserve(bytes.len())
            .map_err(io::Error::other)?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other(
            "a staged display row has no native flush receipt",
        ))
    }
}
struct Row {
    end: u64,
    hard: Instant,
    display: bool,
}
#[derive(Default)]
pub(crate) struct Written {
    pub bytes: usize,
    pub displayed: u64,
}
pub(crate) struct Writer {
    owner: Option<binary_io::Output>,
    bytes: Zeroizing<Vec<u8>>,
    offset: usize,
    rows: VecDeque<Row>,
    maximum: usize,
    maximum_rows: usize,
    timeout: Duration,
    pending: Option<usize>,
    written: u64,
    end: u64,
    uncertain: bool,
    alarm: Pin<Box<tokio::time::Sleep>>,
    retry: Pin<Box<tokio::time::Sleep>>,
}
impl Writer {
    pub(crate) fn new(maximum: usize, maximum_rows: usize, timeout: Duration) -> Self {
        Self {
            owner: None,
            bytes: Zeroizing::new(Vec::new()),
            offset: 0,
            rows: VecDeque::new(),
            maximum,
            maximum_rows,
            timeout,
            pending: None,
            written: 0,
            end: 0,
            uncertain: false,
            alarm: Box::pin(tokio::time::sleep(Duration::ZERO)),
            retry: Box::pin(tokio::time::sleep(Duration::ZERO)),
        }
    }
    pub(super) fn frame(&self) -> io::Result<Frame> {
        Ok(Frame {
            bytes: Zeroizing::new(Vec::new()),
            maximum: self.maximum,
            hard: Instant::now()
                .checked_add(self.timeout)
                .ok_or(io::ErrorKind::InvalidInput)?,
        })
    }
    pub(super) fn enqueue(&mut self, frame: Frame, display: bool) -> io::Result<()> {
        let remaining = self.bytes.len() - self.offset;
        if self.rows.len() >= self.maximum_rows
            || remaining
                .checked_add(frame.bytes.len())
                .is_none_or(|n| n > self.maximum)
        {
            return Err(io::Error::other("bounded Messenger output queue exhausted"));
        }
        let end = self
            .end
            .checked_add(u64::try_from(frame.bytes.len()).map_err(io::Error::other)?)
            .ok_or(io::ErrorKind::InvalidData)?;
        self.rows.try_reserve(1).map_err(io::Error::other)?;
        if self.offset != 0 && self.bytes.len().saturating_add(frame.bytes.len()) > self.maximum {
            self.bytes.copy_within(self.offset.., 0);
            self.bytes[remaining..].zeroize();
            self.bytes.truncate(remaining);
            self.offset = 0;
        }
        self.bytes
            .try_reserve(frame.bytes.len())
            .map_err(io::Error::other)?;
        self.bytes.extend_from_slice(&frame.bytes);
        self.rows.push_back(Row {
            end,
            hard: frame.hard,
            display,
        });
        self.end = end;
        Ok(())
    }
    fn collect(&mut self) -> u64 {
        let mut displayed = 0;
        while self.rows.front().is_some_and(|row| row.end <= self.written) {
            if self.rows.pop_front().is_some_and(|row| row.display) {
                displayed += 1;
            }
        }
        if self.offset == self.bytes.len() {
            self.bytes.as_mut_slice().zeroize();
            self.bytes.clear();
            self.offset = 0;
        }
        displayed
    }
    fn accepted(&mut self, count: usize) -> io::Result<Written> {
        let requested = self
            .pending
            .take()
            .ok_or_else(|| io::Error::other("missing original Messenger output write"))?;
        if count == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        if count > requested || count > self.bytes.len() - self.offset {
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.offset += count;
        self.written = self
            .written
            .checked_add(count as u64)
            .ok_or(io::ErrorKind::InvalidData)?;
        Ok(Written {
            bytes: count,
            displayed: self.collect(),
        })
    }
    pub(crate) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Written>> {
        let displayed = self.collect();
        if displayed != 0 {
            return Poll::Ready(Ok(Written {
                bytes: 0,
                displayed,
            }));
        }
        let Some(row) = self.rows.front() else {
            return Poll::Pending;
        };
        self.alarm.as_mut().reset(row.hard);
        if Instant::now() >= row.hard || self.alarm.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original Messenger display deadline expired",
            )));
        }
        if self.pending.is_none() {
            if self.retry.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            if self.owner.is_none() {
                self.owner = Some(binary_io::Output::stdout(512).map_err(io::Error::other)?);
            }
            let end = self.bytes.len().min(self.offset + 512);
            self.owner
                .as_mut()
                .ok_or(io::ErrorKind::NotConnected)?
                .begin(&self.bytes[self.offset..end])?;
            self.pending = Some(end - self.offset);
        }
        let step = {
            let completion = self
                .owner
                .as_mut()
                .ok_or(io::ErrorKind::NotConnected)?
                .complete();
            let mut completion = std::pin::pin!(completion);
            completion.as_mut().poll(cx)
        };
        match step {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(count)) => Poll::Ready(self.accepted(count)),
            Poll::Ready(Err(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                self.pending = None;
                self.retry
                    .as_mut()
                    .reset(Instant::now() + Duration::from_millis(25));
                let _registered = self.retry.as_mut().poll(cx);
                Poll::Pending
            }
            Poll::Ready(Err(error)) => {
                self.pending = None;
                self.uncertain = true;
                Poll::Ready(Err(error))
            }
        }
    }
    pub(crate) async fn drain(
        &mut self,
        hard: Instant,
        report: &mut super::Report,
        reporter: &gnunet_program_host::reporting::Reporter,
    ) -> io::Result<()> {
        let alarm = tokio::time::sleep_until(hard);
        let mut alarm = std::pin::pin!(alarm);
        while !self.rows.is_empty() {
            let progress = poll_fn(|cx| {
                reporter.register(cx);
                if reporter.failed() {
                    return Poll::Ready(Err(io::Error::other(
                        "selected Messenger diagnostics failed",
                    )));
                }
                if Instant::now() >= hard || alarm.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
                }
                self.poll(cx)
            })
            .await?;
            report.displayed = report.displayed.saturating_add(progress.displayed);
        }
        Ok(())
    }
    pub(crate) fn retire(&mut self) -> Option<binary_io::Retirement> {
        self.owner.take().map(binary_io::Output::retire)
    }
    pub(crate) fn late(&mut self, count: usize, report: &mut super::Report) -> io::Result<()> {
        report.displayed = report
            .displayed
            .saturating_add(self.accepted(count)?.displayed);
        Ok(())
    }
    pub(crate) fn snapshot(&self, report: &mut super::Report) {
        report.output_written = self.written;
        report.output_pending = self.bytes.len() - self.offset;
        report.output_pending_rows = self.rows.len();
        report.output_uncertain = self.uncertain || self.pending.is_some();
    }
}
