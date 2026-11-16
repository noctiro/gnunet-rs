//! One original Wintun read-event wait and bounded send-ring backpressure.
use super::{Input, Refusal};
use crate::OwnedTun;
use gnunet_native::{
    event_wait::Wait,
    wintun::{Receive, SendStatus},
};
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
pub(in crate::reactor) struct Registered {
    // Native wait retirement precedes session/adapter/event closure.
    read_wait: Wait,
    tun: OwnedTun,
    write_alarm: Option<Pin<Box<Sleep>>>,
}
impl Registered {
    pub(in crate::reactor) fn new(tun: OwnedTun) -> Result<Self, Box<Refusal>> {
        let prepared = (|| {
            let event = tun.session().read_event()?.try_clone_to_owned()?;
            #[expect(
                unsafe_code,
                reason = "The trusted Wintun API returns a kernel event; only its independent duplicate transfers to this wait owner"
            )]
            // SAFETY: valid original session event, independently duplicated;
            // this private registration closes its wait before the session.
            unsafe {
                Wait::new(event)
            }
        })();
        match prepared {
            Ok(read_wait) => Ok(Self {
                read_wait,
                tun,
                write_alarm: None,
            }),
            Err(cause) => Err(Box::new(Refusal { tun, cause })),
        }
    }
    pub(in crate::reactor) fn get_ref(&self) -> &OwnedTun {
        &self.tun
    }
    pub(in crate::reactor) fn get_mut(&mut self) -> &mut OwnedTun {
        &mut self.tun
    }
    pub(in crate::reactor) fn into_inner(self) -> OwnedTun {
        let Self {
            read_wait,
            tun,
            write_alarm,
        } = self;
        drop(read_wait);
        drop(write_alarm);
        tun
    }
    pub(in crate::reactor) fn reset_write_wait(&mut self) {
        self.write_alarm = None;
    }
    pub(in crate::reactor) fn read(
        &mut self,
        cx: &mut Context<'_>,
        bytes: &mut [u8],
    ) -> Poll<io::Result<Input>> {
        if self.read_wait.is_armed() {
            match self.read_wait.poll_ready(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {}
            }
        }
        let received = match self.tun.session().receive(bytes) {
            Ok(received) => received,
            Err(error) => return Poll::Ready(Err(error)),
        };
        match received {
            Receive::Packet(bytes) => Poll::Ready(Ok(Input::Data(bytes))),
            Receive::Discarded { .. } => Poll::Ready(Ok(Input::Oversize)),
            Receive::Empty => match self.read_wait.poll_ready(cx) {
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Poll::Pending => Poll::Pending,
            },
        }
    }
    pub(in crate::reactor) fn write(
        &mut self,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(alarm) = &mut self.write_alarm
            && alarm.as_mut().poll(cx).is_pending()
        {
            return Poll::Pending;
        }
        match self.tun.session().send(bytes) {
            Ok(SendStatus::Queued) => {
                self.write_alarm = None;
                Poll::Ready(Ok(bytes.len()))
            }
            Ok(SendStatus::Full) => {
                // Wintun exposes no send-capacity event. One bounded native timer
                // retries the same immutable packet; its original hard never moves.
                let retry = Instant::now() + Duration::from_millis(1);
                let alarm = self
                    .write_alarm
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(retry)));
                alarm.as_mut().reset(retry);
                let _observed = alarm.as_mut().poll(cx);
                Poll::Pending
            }
            Err(error) => {
                self.write_alarm = None;
                Poll::Ready(Err(error))
            }
        }
    }
}
