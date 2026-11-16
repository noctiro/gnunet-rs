//! Original parent-control and process signals; no hidden watcher task.
use super::Failure;
use gnunet_service_runtime::signals::Termination;
use gnunet_service_startup::{ControlReceiver, ParentControl};
use std::task::{Context, Poll};
pub(super) struct Signals {
    parent: Option<ControlReceiver>,
    native: Termination,
}
impl Signals {
    pub fn new(parent: Option<ParentControl>) -> Result<Self, Failure> {
        #[cfg(unix)]
        let parent = parent
            .map(|parent| {
                parent
                    .register()
                    .map_err(|error| Box::new(error.error) as Failure)
            })
            .transpose()?;
        // PROGRAM consumes control only; dropping an unused readiness direction
        // does not half-close the original Windows pipe or report SERVICE ready.
        #[cfg(windows)]
        let parent = parent
            .map(|parent| {
                parent
                    .register()
                    .map(|connected| connected.control)
                    .map_err(|error| Box::new(error) as Failure)
            })
            .transpose()?;
        Ok(Self {
            parent,
            native: Termination::new()?,
        })
    }
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Failure>> {
        if let Some(parent) = &mut self.parent {
            match parent.poll_signal(cx) {
                Poll::Ready(Ok(Some(2 | 15))) => return Poll::Ready(Ok(())),
                Poll::Ready(Ok(Some(_))) => cx.waker().wake_by_ref(),
                Poll::Ready(Ok(None)) => self.parent = None,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(Box::new(error))),
                Poll::Pending => {}
            }
        }
        self.native
            .poll_stop(cx)
            .map(|result| result.map_err(|error| Box::new(error) as Failure))
    }
}
