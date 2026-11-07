//! One original bounded stdio line. This uses conventional synchronous stdout,
//! never changes inherited descriptor/status flags and spawns no worker/task.
//! OS write/flush duration is explicitly not cancellable by a network deadline.
use super::Failure;
use crate::Estimate;
use std::{
    fmt::{self, Write as _},
    io::{self, Write as _},
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Instant;
/// Single bounded line and its actual stdio-accepted prefix.
pub(super) struct Output {
    stdout: io::Stdout,
    bytes: [u8; 2048],
    len: usize,
    at: usize,
    hard: Option<Instant>,
    timeout: Duration,
}
impl Output {
    pub(super) fn new(timeout: Duration) -> Result<Self, Failure> {
        if timeout.is_zero() || Instant::now().checked_add(timeout).is_none() {
            return Err("invalid NSE output timeout".into());
        }
        Ok(Self {
            stdout: io::stdout(),
            bytes: [0; 2048],
            len: 0,
            at: 0,
            hard: None,
            timeout,
        })
    }
    pub(super) fn pending(&self) -> bool {
        self.hard.is_some()
    }
    pub(super) fn admit(&mut self, value: Estimate) -> Result<(), Failure> {
        if self.pending() {
            return Err("NSE output backpressure: original line still pending".into());
        }
        let mut out = Fixed {
            bytes: &mut self.bytes,
            at: 0,
        };
        let micros = value.timestamp.as_micros();
        if micros == u64::MAX {
            out.write_str("forever")?;
        } else {
            let seconds = micros / 1_000_000;
            let days = i64::try_from(seconds / 86400)?;
            // Gregorian civil date from nonnegative Unix days, no host clock/TZ.
            let z = days + 719468;
            let era = z / 146097;
            let doe = z - era * 146097;
            let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
            let mut year = yoe + era * 400;
            let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
            let mp = (5 * doy + 2) / 153;
            let day = doy - (153 * mp + 2) / 5 + 1;
            let month = mp + if mp < 10 { 3 } else { -9 };
            year += i64::from(month <= 2);
            let rem = seconds % 86400;
            write!(
                out,
                "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
                rem / 3600,
                rem / 60 % 60,
                rem % 60
            )?;
        }
        let log = value.log2_size.value();
        writeln!(
            out,
            ": #peers={} (ld(#peers)={}, stddev={})",
            Number(log.exp2()),
            Number(log),
            Number(value.deviation.value())
        )?;
        self.len = out.at;
        self.at = 0;
        self.hard = Some(
            Instant::now()
                .checked_add(self.timeout)
                .ok_or("NSE stdout deadline overflow")?,
        );
        Ok(())
    }
    /// A complete line was accepted/flushed through real stdio; this is not a
    /// fsync, remote receipt, or exact count of bytes physically exposed by the
    /// stdio implementation. Each call handles only this bounded original line.
    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<bool, Failure>> {
        let Some(hard) = self.hard else {
            return Poll::Pending;
        };
        if Instant::now() >= hard {
            return Poll::Ready(Err(format!(
                "NSE stdout line expired before next write: {}/{} bytes accepted by stdio",
                self.at, self.len
            )
            .into()));
        }
        // The kernel/stdio duration of this synchronous call is an explicit OS
        // boundary. No network/native target is claimed able to force it to end.
        match self.stdout.write(&self.bytes[self.at..self.len]) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(error) => Poll::Ready(Err(error.into())),
            Ok(0) => Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero).into())),
            Ok(n) => {
                self.at = self.at.checked_add(n).ok_or("NSE stdout cursor overflow")?;
                if self.at > self.len {
                    return Poll::Ready(Err("NSE stdout invalid stdio byte count".into()));
                }
                if self.at == self.len {
                    self.stdout.flush()?;
                    self.hard = None;
                    Poll::Ready(Ok(true))
                } else {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
        }
    }
}
struct Fixed<'a> {
    bytes: &'a mut [u8],
    at: usize,
}
impl fmt::Write for Fixed<'_> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self
            .at
            .checked_add(text.len())
            .filter(|n| *n <= self.bytes.len())
            .ok_or(fmt::Error)?;
        self.bytes[self.at..end].copy_from_slice(text.as_bytes());
        self.at = end;
        Ok(())
    }
}
struct Number(f64);
impl fmt::Display for Number {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_nan() {
            f.write_str(if self.0.is_sign_negative() {
                "-nan"
            } else {
                "nan"
            })
        } else if self.0.is_infinite() {
            f.write_str(if self.0.is_sign_negative() {
                "-inf"
            } else {
                "inf"
            })
        } else {
            write!(f, "{:.6}", self.0)
        }
    }
}
