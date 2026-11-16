//! Original binary I/O and caller-owned retirement, shared on every native host.
#[cfg(test)]
mod tests;
use crate::{
    Failure,
    foreground::{Budget, Driver},
};
use gnunet_program_host::binary_io::{
    Closed, Input, Output, Retirement, Transfer as NativeTransfer,
};
use std::{
    cell::RefCell,
    future::{Future, poll_fn},
    io,
    path::Path,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
    time::{Duration, Instant},
};
const CHUNK: usize = 16 * 1024;
const CLEANUP: Duration = Duration::from_secs(1);
#[derive(Debug)]
pub(super) struct CloseError {
    report: Option<Closed>,
    transfer: Option<NativeTransfer>,
    observation: Option<io::Error>,
    retirement: Option<Retirement>,
    until: Instant,
    late: bool,
}
impl std::fmt::Display for CloseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "binary stream retirement: report={:?}, transfer={:?}, observation={:?}, pending={}, late={}",
            self.report,
            self.transfer,
            self.observation,
            self.retirement.is_some(),
            self.late
        )
    }
}
impl std::error::Error for CloseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.observation
            .as_ref()
            .or_else(|| {
                self.report
                    .as_ref()
                    .and_then(|report| report.flush.as_ref().or(report.close.as_ref()))
            })
            .or_else(|| {
                self.transfer
                    .as_ref()
                    .and_then(|transfer| transfer.result().as_ref().err())
            })
            .map(|error| error as &dyn std::error::Error)
    }
}
#[derive(Debug)]
enum Slot {
    Vacant,
    Live,
    Retiring(Box<CloseError>),
}
#[derive(Debug)]
pub(super) struct Cleanup {
    slots: [Slot; 2],
}
impl Default for Cleanup {
    fn default() -> Self {
        Self {
            slots: [Slot::Vacant, Slot::Vacant],
        }
    }
}
impl Cleanup {
    pub(super) fn failed(&self) -> bool {
        self.slots.iter().any(|slot| !matches!(slot, Slot::Vacant))
    }
    pub(super) fn first_error(&self) -> Option<&CloseError> {
        self.slots.iter().find_map(|slot| {
            if let Slot::Retiring(error) = slot {
                Some(error.as_ref())
            } else {
                None
            }
        })
    }
    fn reserve(&mut self) -> io::Result<usize> {
        let (index, slot) = self
            .slots
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| matches!(slot, Slot::Vacant))
            .ok_or_else(|| io::Error::other("binary stream ownership capacity"))?;
        *slot = Slot::Live;
        Ok(index)
    }
    fn poll(&mut self, cx: &mut Context<'_>) -> Option<Instant> {
        let now = Instant::now();
        let mut next: Option<Instant> = None;
        for slot in &mut self.slots {
            let Slot::Retiring(error) = slot else {
                continue;
            };
            if error.observation.is_none()
                && let Some(retirement) = &mut error.retirement
            {
                match retirement.poll_closed(cx) {
                    Poll::Ready(Ok(report)) => {
                        error.late |= report.observed_at > error.until;
                        error.transfer = retirement.take_transfer();
                        error.report = Some(report);
                        error.retirement = None;
                    }
                    Poll::Ready(Err(cause)) => error.observation = Some(cause),
                    Poll::Pending => {}
                }
            }
            if error.retirement.is_some() {
                error.late |= now >= error.until;
                if !error.late && error.observation.is_none() {
                    next = Some(next.map_or(error.until, |old| old.min(error.until)));
                }
            }
            if error.retirement.is_none()
                && !error.late
                && error.observation.is_none()
                && error.transfer.is_none()
                && error.report.as_ref().is_some_and(Closed::successful)
            {
                *slot = Slot::Vacant;
            }
        }
        next
    }
}
pub(super) type Retained = Rc<RefCell<Cleanup>>;
pub(super) fn retained() -> Retained {
    Rc::new(RefCell::new(Cleanup::default()))
}
/// A canceled settle retains every receipt and its original hard target.
pub(super) async fn settle(retained: &Retained) {
    let mut timer: Option<Pin<Box<tokio::time::Sleep>>> = None;
    poll_fn(|cx| {
        let next = retained.borrow_mut().poll(cx);
        let Some(next) = next else {
            return Poll::Ready(());
        };
        let next = tokio::time::Instant::from_std(next);
        if timer.as_ref().is_none_or(|timer| timer.deadline() != next) {
            timer = Some(Box::pin(tokio::time::sleep_until(next)));
        }
        if let Some(timer) = &mut timer
            && timer.as_mut().poll(cx).is_ready()
        {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    })
    .await
}
#[derive(Debug)]
struct Transfer {
    stage: &'static str,
    confirmed: usize,
    expected: usize,
    cause: Failure,
}
impl std::fmt::Display for Transfer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} confirmed prefix {}/{} bytes: {}",
            self.stage, self.confirmed, self.expected, self.cause
        )
    }
}
impl std::error::Error for Transfer {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.cause)
    }
}
enum Endpoint {
    Input(Input),
    Output(Output),
}
pub(super) struct Stream {
    endpoint: Option<(Endpoint, Box<std::mem::MaybeUninit<CloseError>>)>,
    retained: Retained,
    slot: usize,
}
impl Stream {
    pub fn input(path: Option<&Path>, retained: Retained) -> Result<Self, Failure> {
        let slot = retained.borrow_mut().reserve()?;
        let backing = Box::new_uninit();
        let result = match path {
            Some(path) => Input::open(path, CHUNK),
            None => Input::stdin(CHUNK),
        };
        match result {
            Ok(input) => Ok(Self {
                endpoint: Some((Endpoint::Input(input), backing)),
                retained,
                slot,
            }),
            Err(error) => {
                retained.borrow_mut().slots[slot] = Slot::Vacant;
                Err(error.into())
            }
        }
    }
    pub fn output(path: Option<&Path>, retained: Retained) -> Result<Self, Failure> {
        let slot = retained.borrow_mut().reserve()?;
        let backing = Box::new_uninit();
        let result = match path {
            Some(path) => Output::open(path, CHUNK),
            None => Output::stdout(CHUNK),
        };
        match result {
            Ok(output) => Ok(Self {
                endpoint: Some((Endpoint::Output(output), backing)),
                retained,
                slot,
            }),
            Err(error) => {
                retained.borrow_mut().slots[slot] = Slot::Vacant;
                Err(error.into())
            }
        }
    }
    pub async fn read_exact(
        &mut self,
        driver: &mut Driver<'_, '_, '_, '_>,
        budget: &mut Budget,
        out: &mut [u8],
        eof: bool,
        stage: &'static str,
    ) -> Result<bool, Failure> {
        let mut used = 0;
        while used < out.len() {
            driver.check(budget).await?;
            let Some((Endpoint::Input(input), _)) = &mut self.endpoint else {
                return Err("not an original readable stream".into());
            };
            input.begin((out.len() - used).min(CHUNK))?;
            match driver.native(budget, input.complete()).await {
                Ok([]) if used == 0 && eof => return Ok(false),
                Ok([]) => {
                    return Err(Box::new(Transfer {
                        stage,
                        confirmed: used,
                        expected: out.len(),
                        cause: io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "truncated original input",
                        )
                        .into(),
                    }));
                }
                Ok(bytes) => {
                    out[used..used + bytes.len()].copy_from_slice(bytes);
                    used += bytes.len();
                }
                Err(cause)
                    if cause
                        .downcast_ref::<io::Error>()
                        .is_some_and(|error| error.kind() == io::ErrorKind::WouldBlock) =>
                {
                    driver.pause(budget).await?
                }
                Err(cause) => {
                    return Err(Box::new(Transfer {
                        stage,
                        confirmed: used,
                        expected: out.len(),
                        cause,
                    }));
                }
            }
            driver.check(budget).await?;
        }
        Ok(true)
    }
    pub async fn write_all(
        &mut self,
        driver: &mut Driver<'_, '_, '_, '_>,
        budget: &mut Budget,
        data: &[u8],
        stage: &'static str,
    ) -> Result<(), Failure> {
        let mut used = 0;
        while used < data.len() {
            driver.check(budget).await?;
            let Some((Endpoint::Output(output), _)) = &mut self.endpoint else {
                return Err("not an original writable stream".into());
            };
            output.begin(&data[used..data.len().min(used + CHUNK)])?;
            match driver.native(budget, output.complete()).await {
                Ok(0) => {
                    return Err(Box::new(Transfer {
                        stage,
                        confirmed: used,
                        expected: data.len(),
                        cause: io::Error::from(io::ErrorKind::WriteZero).into(),
                    }));
                }
                Ok(count) => used = used.checked_add(count).ok_or("output count overflow")?,
                Err(cause)
                    if cause
                        .downcast_ref::<io::Error>()
                        .is_some_and(|error| error.kind() == io::ErrorKind::WouldBlock) =>
                {
                    driver.pause(budget).await?
                }
                Err(cause) => {
                    return Err(Box::new(Transfer {
                        stage,
                        confirmed: used,
                        expected: data.len(),
                        cause,
                    }));
                }
            }
            driver.check(budget).await?;
        }
        Ok(())
    }
    fn retire(&mut self) {
        if let Some((endpoint, backing)) = self.endpoint.take() {
            let retirement = match endpoint {
                Endpoint::Input(input) => input.retire(),
                Endpoint::Output(output) => output.retire(),
            };
            let now = Instant::now();
            let until = now.checked_add(CLEANUP).unwrap_or(now);
            self.retained.borrow_mut().slots[self.slot] = Slot::Retiring(Box::write(
                backing,
                CloseError {
                    report: None,
                    transfer: None,
                    observation: None,
                    retirement: Some(retirement),
                    until,
                    late: false,
                },
            ));
        }
    }
    pub async fn finish(mut self) -> Result<(), Failure> {
        self.retire();
        settle(&self.retained).await;
        if matches!(self.retained.borrow().slots[self.slot], Slot::Vacant) {
            Ok(())
        } else {
            Err(io::Error::other("original binary stream close failed or remains unproven").into())
        }
    }
}
impl Drop for Stream {
    fn drop(&mut self) {
        self.retire();
    }
}
