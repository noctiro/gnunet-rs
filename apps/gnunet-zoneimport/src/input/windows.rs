//! One captured Unicode/byte reader with capacity-one original work and cancellation.
use gnunet_program_host::binary_io::{self, StartError};
use std::{
    fs::File,
    future::Future,
    io,
    task::{Context, Poll},
};
use tokio::time::Instant;
pub(crate) struct Input {
    port: binary_io::Input,
    requested: Option<usize>,
}
pub(crate) type Retired = binary_io::RetiredSet<1>;
impl Input {
    pub(crate) fn new(file: File) -> Result<Self, StartError> {
        Ok(Self {
            port: binary_io::Input::text(file, 4096)?,
            requested: None,
        })
    }
    pub(crate) fn poll(
        &mut self,
        cx: &mut Context<'_>,
        output: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if output.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let count = self.requested.unwrap_or(output.len().min(4096));
        if output.len() < count {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "original input read still requires its admitted output extent",
            )));
        }
        if self.requested.is_none() {
            self.port.begin(count)?;
            self.requested = Some(count);
        }
        let result = {
            let completion = self.port.complete();
            let mut completion = std::pin::pin!(completion);
            match completion.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(bytes)) => {
                    output[..bytes.len()].copy_from_slice(bytes);
                    Ok(bytes.len())
                }
                Poll::Ready(Err(error)) => Err(error),
            }
        };
        self.requested = None;
        Poll::Ready(result)
    }
    pub(crate) async fn retire(self, hard: Instant) -> Retired {
        binary_io::settle([Some(self.port.retire())], hard.into_std()).await
    }
}
