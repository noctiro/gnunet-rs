//! Sticky stop intent from the owning process or embedded supervisor.
use gnunet_service_startup::StopSignals;
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};

pub(super) enum StopSource<'a> {
    Process(StopSignals),
    Embedded(Pin<&'a mut dyn Future<Output = io::Result<()>>>),
}
pub(super) struct Signals<'a> {
    original: StopSource<'a>,
    requested: bool,
}
impl<'a> Signals<'a> {
    pub(super) fn new(original: StopSource<'a>) -> Self {
        Self {
            original,
            requested: false,
        }
    }
    pub(super) fn requested(&self) -> bool {
        self.requested
    }
    pub(super) fn process(&mut self) -> io::Result<&mut StopSignals> {
        match &mut self.original {
            StopSource::Process(signals) => Ok(signals),
            StopSource::Embedded(_) => Err(io::Error::other(
                "process readiness requires native stop signals",
            )),
        }
    }
    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.requested {
            return Poll::Ready(Ok(()));
        }
        let result = match &mut self.original {
            StopSource::Process(signals) => signals.poll_stop(cx).map_err(io::Error::other),
            StopSource::Embedded(stop) => stop.as_mut().poll(cx),
        };
        result.map(|result| {
            if result.is_ok() {
                self.requested = true;
            }
            result
        })
    }
}
