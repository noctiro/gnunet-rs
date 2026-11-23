//! Route one native in-flight probe and retain completed proofs by operation.

use super::probe::Worker;
use gnunet_native::transparent_dns::exclusion::{
    Ingresses, ProbeReceipt, ProbeRequest, ProbeSocket,
};
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};

const PROBE_LIMIT: Duration = Duration::from_millis(250);

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Lane {
    Input,
    Output,
}

struct InFlight {
    lane: Option<Lane>,
    until: Instant,
    armed: bool,
}

pub(super) struct Probes {
    worker: Worker,
    inflight: Option<InFlight>,
    completed: [Option<ProbeReceipt>; 2],
    timer: Option<Pin<Box<Sleep>>>,
}

impl Probes {
    pub(super) fn launch(socket: ProbeSocket) -> io::Result<Self> {
        Ok(Self {
            worker: Worker::launch(socket)?,
            inflight: None,
            completed: [None, None],
            timer: None,
        })
    }

    pub(super) fn available(&self, lane: Lane) -> bool {
        self.inflight.is_none() && self.completed[lane as usize].is_none()
    }

    pub(super) fn submit(&mut self, lane: Lane, request: ProbeRequest) -> io::Result<()> {
        if !self.available(lane) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.worker.submit(request)?;
        let until = Instant::now() + PROBE_LIMIT;
        self.inflight = Some(InFlight {
            lane: Some(lane),
            until,
            armed: false,
        });
        self.timer
            .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(until)))
            .as_mut()
            .reset(until);
        Ok(())
    }

    pub(super) fn abandon(&mut self, lane: Lane, ingress: &mut Ingresses) {
        if let Some(job) = &mut self.inflight
            && job.lane == Some(lane)
        {
            job.lane = None;
        }
        if let Some(receipt) = self.completed[lane as usize].take() {
            ingress.discard_probe(receipt);
        }
    }

    // The guard polls this even when ingress admission is suspended or an
    // output was cancelled. A cancelled job still owns the worker until return.
    pub(super) fn drive(
        &mut self,
        cx: &mut Context<'_>,
        ingress: &mut Ingresses,
    ) -> io::Result<()> {
        let Some(job) = &mut self.inflight else {
            return Ok(());
        };
        job.armed = true;
        if Instant::now() >= job.until {
            return Err(expired());
        }
        match self.worker.poll(cx) {
            Poll::Ready(receipt) => {
                let lane = job.lane;
                self.inflight = None;
                let receipt = receipt?;
                if let Some(lane) = lane {
                    self.completed[lane as usize] = Some(receipt);
                } else {
                    ingress.discard_probe(receipt);
                }
            }
            Poll::Pending => {
                if self
                    .timer
                    .as_mut()
                    .is_some_and(|timer| timer.as_mut().poll(cx).is_ready())
                {
                    return Err(expired());
                }
            }
        }
        Ok(())
    }

    pub(super) fn poll(&mut self, cx: &mut Context<'_>, lane: Lane) -> Poll<ProbeReceipt> {
        // Registration may occur after the guard's poll in the same turn.
        // Only the watch guard observes actual worker completion.
        if let Some(receipt) = self.completed[lane as usize].take() {
            Poll::Ready(receipt)
        } else {
            if self.inflight.as_ref().is_some_and(|job| !job.armed) {
                // Schedule a guard poll to register the new request.
                cx.waker().wake_by_ref();
            }
            Poll::Pending
        }
    }

    pub(super) fn retire(mut self) -> Worker {
        self.worker.cancel();
        self.worker
    }
}

fn expired() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "original transparent DNS link probe exceeded its deadline",
    )
}
