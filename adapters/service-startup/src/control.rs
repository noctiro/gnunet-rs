//! Original parent-control descriptor registration; no synthetic signal or EOF.
use gnunet_service_runtime::readiness::{RegisterError, RegisteredReadiness};
use std::{
    io,
    os::fd::OwnedFd,
    task::{Context, Poll},
};
/// One original nonblocking signal-control stream, owned through canceled polls.
/// EOF deregisters/closes only this stream and produces no shutdown signal.
pub struct ControlReceiver {
    reader: Option<RegisteredReadiness>,
}
impl ControlReceiver {
    pub(crate) fn from_owned(descriptor: OwnedFd) -> Result<Self, RegisterError> {
        Ok(Self {
            reader: Some(RegisteredReadiness::new(descriptor)?),
        })
    }
    /// Read one actual signed control byte after native readiness. The consumer
    /// dispatches only its installed handlers, like GNUNET_SIGNAL_raise; this
    /// does not call the OS raise syscall or invent a signal on EOF.
    pub fn poll_signal(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<i8>>> {
        loop {
            let Some(reader) = &self.reader else {
                return Poll::Ready(Ok(None));
            };
            match reader.poll_ready(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(_)) => {}
            }
            let mut byte = [0];
            match nix::unistd::read(reader.as_fd(), &mut byte) {
                Ok(0) => {
                    self.reader = None;
                    return Poll::Ready(Ok(None));
                }
                Ok(1) => return Poll::Ready(Ok(Some(byte[0] as i8))),
                Ok(_) => {
                    return Poll::Ready(Err(io::Error::other(
                        "one-byte parent control read exceeded its buffer",
                    )));
                }
                Err(nix::errno::Errno::EAGAIN) => {}
                Err(error) => return Poll::Ready(Err(error.into())),
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::future::poll_fn;
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Actual pipe byte order and physical EOF retirement are independent ownership assertions"
    )]
    fn original_control_bytes_survive_canceled_wait_and_eof_closes_the_registration()
    -> Result<(), Box<dyn std::error::Error>> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let (reader, writer) = gnunet_service_runtime::process::pipe()?;
            let mut receiver = ControlReceiver::from_owned(reader).map_err(|e| e.error)?;
            assert!(
                tokio::time::timeout(
                    std::time::Duration::from_millis(5),
                    poll_fn(|cx| receiver.poll_signal(cx))
                )
                .await
                .is_err()
            );
            assert_eq!(nix::unistd::write(&writer, &[15, 2])?, 2);
            assert_eq!(poll_fn(|cx| receiver.poll_signal(cx)).await?, Some(15));
            assert_eq!(poll_fn(|cx| receiver.poll_signal(cx)).await?, Some(2));
            drop(writer);
            assert_eq!(poll_fn(|cx| receiver.poll_signal(cx)).await?, None);
            assert!(receiver.reader.is_none());
            Ok::<_, Box<dyn std::error::Error>>(())
        })
    }
}
