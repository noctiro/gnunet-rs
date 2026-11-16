//! Lazy original binary I/O owners, independent of protocol flow-control.
mod input;
mod output;
mod retirement;
use input::Input;
use output::Output;
pub(super) use retirement::Retired;
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};

struct Retry(Pin<Box<Sleep>>);
impl Retry {
    fn new() -> Self {
        Self(Box::pin(tokio::time::sleep(Duration::ZERO)))
    }
    fn ready(&mut self, cx: &mut Context<'_>) -> bool {
        self.0.as_mut().poll(cx).is_ready()
    }
    fn pause(&mut self, cx: &mut Context<'_>) {
        self.0
            .as_mut()
            .reset(Instant::now() + Duration::from_millis(25));
        let _registered = self.0.as_mut().poll(cx);
    }
}
fn temporary(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
    )
}
pub(super) struct Stdio {
    input: Input,
    output: Output,
}
impl Stdio {
    pub(super) fn new(chunk: usize) -> Self {
        Self {
            input: Input::new(chunk),
            output: Output::new(),
        }
    }
    pub(super) fn read(
        &mut self,
        cx: &mut Context<'_>,
        bytes: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.input.poll(cx, bytes)
    }
    pub(super) fn write(&mut self, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        self.output.poll(cx, bytes)
    }
    pub(super) async fn retire(self, hard: Instant) -> Retired {
        retirement::retire(self.input.retire(), self.output.retire(), hard).await
    }
}
