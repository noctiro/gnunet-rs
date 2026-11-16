//! One bounded original line and cancel-safe native stdout work.
mod retirement;
use super::Failure;
use crate::Estimate;
use gnunet_program_host::binary_io;
pub(super) use retirement::settle;
use std::{
    fmt::{self, Write as _},
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
const CAPACITY: usize = 2048;
/// One line, one original native write, and its exact observed positive prefix.
pub(super) struct Output {
    native: Option<binary_io::Output>,
    bytes: [u8; CAPACITY],
    len: usize,
    at: usize,
    pending: bool,
    hard: Option<Instant>,
    alarm: Pin<Box<Sleep>>,
    timeout: Duration,
}
impl Output {
    pub(super) fn new(timeout: Duration) -> Result<Self, Failure> {
        if timeout.is_zero() || Instant::now().checked_add(timeout).is_none() {
            return Err("invalid NSE output timeout".into());
        }
        Ok(Self {
            native: Some(binary_io::Output::stdout_text(CAPACITY)?),
            bytes: [0; CAPACITY],
            len: 0,
            at: 0,
            pending: false,
            hard: None,
            alarm: Box::pin(tokio::time::sleep(Duration::ZERO)),
            timeout,
        })
    }
    pub(super) fn pending(&self) -> bool {
        self.hard.is_some()
    }
    pub(super) fn admit(&mut self, value: Estimate) -> Result<(), Failure> {
        if self.pending() {
            return Err("NSE output backpressure: original line remains pending".into());
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
        let hard = Instant::now()
            .checked_add(self.timeout)
            .ok_or("NSE stdout deadline overflow")?;
        self.alarm.as_mut().reset(hard);
        self.hard = Some(hard);
        Ok(())
    }
    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<bool, Failure>> {
        let Some(hard) = self.hard else {
            return Poll::Pending;
        };
        let native = self
            .native
            .as_mut()
            .ok_or("NSE stdout owner already retired")?;
        if self.pending {
            let result = {
                let mut completion = std::pin::pin!(native.complete());
                completion.as_mut().poll(cx)
            };
            if let Poll::Ready(result) = result {
                self.pending = false;
                let count = result?;
                if count == 0 {
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero).into()));
                }
                self.at = self
                    .at
                    .checked_add(count)
                    .filter(|at| *at <= self.len)
                    .ok_or("NSE stdout invalid native count")?;
            }
        }
        if Instant::now() >= hard || self.alarm.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(format!(
                "NSE stdout line deadline: {}/{} bytes observed, native work pending={}",
                self.at, self.len, self.pending
            )
            .into()));
        }
        if self.pending {
            return Poll::Pending;
        }
        if self.at == self.len {
            self.hard = None;
            return Poll::Ready(Ok(true));
        }
        native.begin(&self.bytes[self.at..self.len])?;
        self.pending = true;
        // Register the original reply waker immediately; waiting cancellation
        // never re-admits the write. One next cooperative poll observes progress.
        let result = {
            let mut completion = std::pin::pin!(native.complete());
            completion.as_mut().poll(cx)
        };
        if let Poll::Ready(result) = result {
            self.pending = false;
            let count = result?;
            if count == 0 {
                return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero).into()));
            }
            self.at = self
                .at
                .checked_add(count)
                .filter(|at| *at <= self.len)
                .ok_or("NSE stdout invalid native count")?;
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
    pub(super) fn retire(&mut self) -> Option<binary_io::Retirement> {
        self.native.take().map(binary_io::Output::retire)
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
