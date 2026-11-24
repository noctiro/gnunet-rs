//! Retained original bootstrap, cooperative-stop outbox and exit observation.
use super::registry_error;
use crate::process::{ChildRegistry, ControlEvent, ControlMode, LaunchError, OriginalChild};
use gnunet_native::process::ProcessWait;
use gnunet_native::socket_activation::OwnedSource;
use gnunet_service_startup::{ControlSender, launch};
use std::{
    io,
    mem::MaybeUninit,
    sync::Arc,
    task::{Context, Poll},
};
pub(crate) struct Control(Box<Session>);
struct Session {
    parent: Option<launch::Parent>,
    sender: Option<ControlSender>,
    mode: ControlMode,
    // Provider failures must outlive original-child retirement even if a bounded
    // diagnostic is consumed or omitted. Arc shares only that immutable failure.
    failure: Option<Arc<launch::LaunchFailure>>,
    retirement_requested: bool,
    stop_started: bool,
    stop_exit: Option<ProcessWait>,
    signal_notice: Option<LaunchError>,
    sources: Vec<OwnedSource>,
}

pub(super) enum Initial {
    Starting(launch::Parent),
    Failed(Arc<launch::LaunchFailure>),
}
/// Reserve retained state before the kernel admits a process.
pub(super) struct Prepared(Box<MaybeUninit<Session>>);
impl Prepared {
    pub(super) fn new() -> Self {
        Self(Box::new_uninit())
    }
    pub(super) fn finish(
        self,
        initial: Initial,
        mode: ControlMode,
        sources: Vec<OwnedSource>,
    ) -> Control {
        let (parent, failure) = match initial {
            Initial::Starting(parent) => (Some(parent), None),
            Initial::Failed(failure) => (None, Some(failure)),
        };
        Control(Box::write(
            self.0,
            Session {
                parent,
                failure,
                mode,
                sender: None,
                retirement_requested: false,
                stop_started: false,
                stop_exit: None,
                signal_notice: None,
                sources,
            },
        ))
    }
}
fn connect(
    control: &mut Session,
    cx: &mut Context<'_>,
) -> Poll<Result<(), gnunet_service_startup::ParentFailure>> {
    let Some(parent) = &mut control.parent else {
        return Poll::Pending;
    };
    match parent.poll_connect(cx) {
        Poll::Ready(Ok(())) => {
            if control.sender.is_none() {
                control.sender = parent.take_control();
            }
            Poll::Ready(Ok(()))
        }
        other => other,
    }
}
pub(crate) fn poll_control(
    control: &mut Control,
    children: &mut ChildRegistry,
    child: &OriginalChild,
    cx: &mut Context<'_>,
) -> Poll<Result<ControlEvent, LaunchError>> {
    let control = &mut control.0;
    if control.failure.is_some() {
        if !control.retirement_requested {
            control.retirement_requested = true;
            return Poll::Ready(
                children
                    .terminate(child, 0xffff_ff01)
                    .map(|()| ControlEvent::RetirementRequested)
                    .map_err(registry_error),
            );
        }
        return Poll::Pending;
    }
    match connect(control, cx) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Err(error)) => {
            control.parent = None;
            Poll::Ready(Err(io::Error::other(error).into()))
        }
        Poll::Ready(Ok(())) => {
            let result = match control.parent.as_mut() {
                Some(parent) => parent.poll_ready(cx),
                None => return Poll::Pending,
            };
            match result {
                Poll::Pending => Poll::Pending,
                Poll::Ready(result) => {
                    if result.is_ok() {
                        control.sources.clear();
                    }
                    control.parent = None;
                    Poll::Ready(
                        result
                            .map(|_| ControlEvent::Ready)
                            .map_err(|error| io::Error::other(error).into()),
                    )
                }
            }
        }
    }
}
pub(crate) fn poll_stop(
    children: &mut ChildRegistry,
    child: &OriginalChild,
    control: &mut Control,
    cx: &mut Context<'_>,
) -> Poll<Result<(), LaunchError>> {
    let control = &mut control.0;
    if !children.owns(child) {
        return Poll::Ready(Err(LaunchError::Stale));
    }
    if control.mode == ControlMode::Pipe {
        if control.sender.is_none()
            && let Poll::Ready(Err(error)) = connect(control, cx)
        {
            control.signal_notice = Some(io::Error::other(error).into());
        }
        if let Some(sender) = &mut control.sender {
            let admission = if control.stop_started {
                true
            } else {
                match sender.begin(children, 15) {
                    Ok(()) => true,
                    Err(error) => {
                        control.signal_notice = Some(io::Error::other(error).into());
                        false
                    }
                }
            };
            if admission {
                control.stop_started = true;
                match sender.poll_send(cx) {
                    Poll::Ready(Ok(_)) => {
                        let _credit = sender.take_submission();
                        control.stop_started = false;
                        control.stop_exit = None;
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Pending => {
                        // Retain this byte across drive cancellation. A separate
                        // read-only wait wakes the same pending action if the
                        // original child dies before the pipe write settles.
                        if control.stop_exit.is_none() {
                            match children.exit_observer(child) {
                                Ok(wait) => control.stop_exit = Some(wait),
                                Err(error) => {
                                    control.signal_notice = Some(registry_error(error));
                                    return fallback(children, child, control);
                                }
                            }
                        }
                        if let Some(wait) = &mut control.stop_exit {
                            match wait.poll_exit(cx) {
                                Poll::Pending => return Poll::Pending,
                                Poll::Ready(Err(error)) => {
                                    control.signal_notice = Some(error.into())
                                }
                                Poll::Ready(Ok(_)) => {}
                            }
                        }
                    }
                    Poll::Ready(Err(error)) => {
                        control.signal_notice = Some(io::Error::other(error).into());
                    }
                }
            }
        }
    }
    fallback(children, child, control)
}
fn fallback(
    children: &mut ChildRegistry,
    child: &OriginalChild,
    control: &mut Session,
) -> Poll<Result<(), LaunchError>> {
    // Unavailable or failed cooperative control uses the original native handle.
    // Retiring local outbox owners never retargets an admitted byte to a PID.
    control.sender = None;
    control.parent = None;
    control.stop_started = false;
    control.stop_exit = None;
    Poll::Ready(children.terminate(child, 15).map_err(registry_error))
}
pub(crate) fn take_signal_notice(control: &mut Control) -> Option<LaunchError> {
    control.0.signal_notice.take()
}
