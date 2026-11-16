//! One original managed-parent writer retained outside the static PROGRAM task.
use crate::Failure;
use gnunet_service_startup::{ReadyStatus, ReadyWriter};
use std::{
    cell::RefCell,
    future::{Future, poll_fn},
    io,
    rc::Rc,
    task::{Context, Poll},
};
enum State {
    Unmanaged,
    Pending {
        writer: ReadyWriter,
        selected: ReadyStatus,
    },
    Retired,
}
/// This shared owner holds the actual native writer, not reconstructible metadata.
/// Cancelling a scheduled future preserves its original pipe and native intent.
pub(super) struct Owner(Rc<RefCell<State>>);
pub(super) fn prepare(
    writer: Option<ReadyWriter>,
) -> (Owner, impl Future<Output = Result<(), Failure>> + 'static) {
    let state = Rc::new(RefCell::new(match writer {
        Some(writer) => State::Pending {
            writer,
            selected: ReadyStatus::AcceptRegistered,
        },
        None => State::Unmanaged,
    }));
    let notification = state.clone();
    (Owner(state), async move {
        poll_fn(|cx| poll(&notification, ReadyStatus::AcceptRegistered, cx)).await
    })
}
fn poll(
    state: &Rc<RefCell<State>>,
    status: ReadyStatus,
    cx: &mut Context<'_>,
) -> Poll<Result<(), Failure>> {
    let mut slot = state.borrow_mut();
    match &mut *slot {
        State::Unmanaged => {}
        State::Retired => {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "original EXIT readiness already retired",
            )
            .into()));
        }
        State::Pending { writer, selected } => {
            if *selected != status {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "original EXIT readiness intent revoked before admission",
                )
                .into()));
            }
            if writer.intent().is_none() {
                writer.begin(status)?;
            }
            match writer.poll_signal(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                Poll::Ready(Ok(_)) => {}
            }
        }
    }
    let original = std::mem::replace(&mut *slot, State::Retired);
    drop(slot);
    drop(original);
    Poll::Ready(Ok(()))
}
impl Owner {
    /// Select failure only before any original ready byte was admitted. Revoking
    /// that selection fences a stale scheduled notifier; an existing native intent
    /// is never replaced by a contradictory initialization-failure byte.
    pub(super) async fn failure(&mut self) -> Result<(), Failure> {
        let selected = {
            let mut slot = self.0.borrow_mut();
            match &mut *slot {
                State::Pending { writer, selected } if writer.intent().is_none() => {
                    *selected = ReadyStatus::InitializationFailed;
                    true
                }
                _ => false,
            }
        };
        if selected {
            poll_fn(|cx| poll(&self.0, ReadyStatus::InitializationFailed, cx)).await
        } else {
            Ok(())
        }
    }
}
