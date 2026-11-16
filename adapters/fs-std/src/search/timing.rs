//! One original search lifetime, independent of historical replay timestamps.
use super::{Error, Session};
use crate::ipc;
use gnunet_types::Error as ProtocolError;
use std::task::{Context, Poll};

impl<F, const KNOWN: usize> Session<'_, F, KNOWN>
where
    F: FnMut() -> Result<ipc::EndpointSource, ipc::Error>,
{
    fn synchronize_time(&mut self) -> Result<(), ProtocolError> {
        let time = self.time.as_ref().ok_or(ProtocolError::NotReady)?;
        if self.last_now.is_some_and(|old| time.now < old) {
            return Err(ProtocolError::TimeUncertain);
        }
        self.last_now = Some(time.now);
        Ok(())
    }
    fn settle_time(&mut self, result: Result<(), ProtocolError>) -> Result<(), Error> {
        match result.and_then(|()| self.synchronize_time()) {
            Ok(()) => Ok(()),
            Err(cause) => {
                self.abort(cause)?;
                Err(cause.into())
            }
        }
    }
    pub(super) fn check_time(&mut self) -> Result<(), Error> {
        let result = self.time.as_mut().ok_or(ProtocolError::NotReady)?.check();
        self.settle_time(result)
    }
    pub(super) fn poll_time(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let result = match self.time.as_mut().ok_or(ProtocolError::NotReady)?.poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result,
        };
        Poll::Ready(self.settle_time(result))
    }
}
