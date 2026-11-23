//! One Network.framework group and one bounded receive slot.
use super::{Datagram, Object};
use crate::dns_proxy::{completion::dispose_panic, connection::sdk::Failure};
use std::{
    io,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::Mutex,
    task::{Context, Poll, Waker},
};

// nw_connection_group_state_t from Network/connection_group.h.
const WAITING: u32 = 1;
const READY: u32 = 2;
const FAILED: u32 = 3;
const CANCELLED: u32 = 4;

#[derive(Clone, Copy)]
enum Phase {
    Opening,
    Ready,
    Failed(GroupFailure),
    Cancelled(Option<GroupFailure>),
}

#[derive(Clone, Copy)]
struct GroupFailure(Option<Failure>);
impl GroupFailure {
    fn into_error(self) -> io::Error {
        self.0.map_or_else(
            || io::Error::other("native multicast group failed"),
            Failure::into_error,
        )
    }
}

struct State {
    native: Option<Object>,
    phase: Phase,
    admit: bool,
    reply: Option<Datagram>,
    waker: Option<Waker>,
}

pub(super) struct Watch(Mutex<State>);
impl Watch {
    pub(super) fn new(native: Object) -> Self {
        Self(Mutex::new(State {
            native: Some(native),
            phase: Phase::Opening,
            admit: false,
            reply: None,
            waker: None,
        }))
    }

    pub(super) fn publish(&self, value: u32, failure: Option<Failure>) {
        let (native, expired, wake) = {
            let mut state = self.lock();
            if matches!(state.phase, Phase::Cancelled(_))
                || matches!(state.phase, Phase::Failed(_)) && value != CANCELLED
            {
                return;
            }
            state.phase = match value {
                WAITING => Phase::Opening,
                READY => Phase::Ready,
                FAILED => Phase::Failed(GroupFailure(failure)),
                CANCELLED => Phase::Cancelled(match state.phase {
                    Phase::Failed(failure) => Some(failure),
                    _ => None,
                }),
                _ => return,
            };
            let expired = if value == READY {
                None
            } else {
                state.reply.take()
            };
            let native = if value == CANCELLED {
                state.admit = false;
                state.native.take()
            } else {
                None
            };
            (native, expired, state.waker.take())
        };
        // Release the callback's group keeper after the last native event.
        // The app owner releases its own reference when requesting cancellation.
        drop(native);
        drop(expired);
        wake_one(wake);
    }

    pub(super) fn arm(&self) {
        self.lock().admit = true;
    }

    pub(super) fn disarm(&self) {
        let reply = {
            let mut state = self.lock();
            state.admit = false;
            state.reply.take()
        };
        drop(reply);
    }

    pub(super) fn receive_on(&self) -> Option<Object> {
        let state = self.lock();
        if state.admit && state.reply.is_none() && matches!(state.phase, Phase::Ready) {
            state.native.clone()
        } else {
            None
        }
    }

    pub(super) fn reply(&self, reply: Datagram) {
        let wake = {
            let mut state = self.lock();
            if !state.admit || state.reply.is_some() || !matches!(state.phase, Phase::Ready) {
                return;
            }
            state.reply = Some(reply);
            state.waker.take()
        };
        wake_one(wake);
    }

    pub(super) fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll(cx, |state| match state.phase {
            Phase::Opening => Poll::Pending,
            Phase::Ready => Poll::Ready(Ok(())),
            Phase::Failed(failure) | Phase::Cancelled(Some(failure)) => {
                Poll::Ready(Err(failure.into_error()))
            }
            Phase::Cancelled(None) => Poll::Ready(Err(io::ErrorKind::NotConnected.into())),
        })
    }

    pub(super) fn poll_reply(&self, cx: &mut Context<'_>) -> Poll<Datagram> {
        self.poll(cx, |state| match state.reply.take() {
            Some(reply) => Poll::Ready(reply),
            None => Poll::Pending,
        })
    }

    pub(super) fn poll_cancelled(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll(cx, |state| match state.phase {
            Phase::Cancelled(failure) => {
                Poll::Ready(failure.map_or(Ok(()), |failure| Err(failure.into_error())))
            }
            _ => Poll::Pending,
        })
    }

    fn poll<T>(
        &self,
        cx: &mut Context<'_>,
        observe: impl FnOnce(&mut State) -> Poll<T>,
    ) -> Poll<T> {
        let waker = cx.waker().clone();
        let (outcome, previous) = {
            let mut state = self.lock();
            let outcome = observe(&mut state);
            (outcome, state.waker.replace(waker))
        };
        drop(previous);
        outcome
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn wake_one(waker: Option<Waker>) {
    if let Some(waker) = waker {
        contain(|| waker.wake());
    }
}

pub(super) fn contain(body: impl FnOnce()) {
    if let Err(payload) = catch_unwind(AssertUnwindSafe(body)) {
        dispose_panic(payload);
    }
}
