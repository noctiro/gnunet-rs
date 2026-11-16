//! Native stop and one original deadline for finite command operations.
use gnunet_service_runtime::signals::Termination;
use std::{
    error::Error,
    future::{Future, poll_fn},
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
pub(crate) struct Control {
    termination: Termination,
    hard: Instant,
    timer: Pin<Box<Sleep>>,
    context: &'static str,
}
impl Control {
    pub(crate) fn hard(&self) -> Instant {
        self.hard
    }
    pub(crate) fn new(timeout: Duration, context: &'static str) -> io::Result<Self> {
        let hard = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| io::Error::other("command deadline overflow"))?;
        Self::until(hard, context)
    }
    pub(crate) fn until(hard: Instant, context: &'static str) -> io::Result<Self> {
        Ok(Self {
            termination: Termination::new()?,
            hard,
            timer: Box::pin(tokio::time::sleep_until(hard)),
            context,
        })
    }
    pub(crate) fn check(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if Instant::now() >= self.hard || self.timer.as_mut().poll(cx).is_ready() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("original {} deadline", self.context),
            ));
        }
        match self.termination.poll_stop(cx) {
            Poll::Ready(Ok(())) => Err(io::Error::new(
                io::ErrorKind::Interrupted,
                format!("{} stopped", self.context),
            )),
            Poll::Ready(Err(error)) => Err(error),
            Poll::Pending => Ok(()),
        }
    }
    pub(crate) async fn gate(&mut self) -> Result<(), Box<dyn Error>> {
        poll_fn(|cx| Poll::Ready(self.check(cx))).await?;
        Ok(())
    }
    pub(crate) async fn drive<T, E: Error + 'static>(
        &mut self,
        operation: impl Future<Output = Result<T, E>>,
    ) -> Result<T, Box<dyn Error>> {
        let mut operation = std::pin::pin!(operation);
        poll_fn(|cx| {
            if let Err(error) = self.check(cx) {
                return Poll::Ready(Err(Box::new(error) as Box<dyn Error>));
            }
            operation
                .as_mut()
                .poll(cx)
                .map(|result| result.map_err(|error| Box::new(error) as Box<dyn Error>))
        })
        .await
    }
}
