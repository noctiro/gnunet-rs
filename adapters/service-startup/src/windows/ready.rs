//! Immutable Windows startup-status outbox and transport submission facts.
use crate::ReadyStatus;
use gnunet_service_runtime::pipe::{ByteWriter, PipeError, WriteSubmission};
use std::{
    error::Error,
    fmt,
    task::{Context, Poll},
};
/// Refused readiness intent or sticky original transport failure.
#[derive(Clone, Debug)]
pub enum ReadyFailure {
    /// A different status cannot replace the original admitted status.
    IntentMismatch {
        /// Original immutable intent.
        original: ReadyStatus,
        /// Refused new intent.
        attempted: ReadyStatus,
    },
    /// No readiness intent has been admitted.
    NoIntent,
    /// Original native transport failure.
    Pipe(PipeError),
}
impl fmt::Display for ReadyFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl Error for ReadyFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Pipe(error) => Some(error),
            _ => None,
        }
    }
}
/// Status accepted by Tokio/Mio, not native completion or parent consumption.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadySubmission {
    status: ReadyStatus,
    transport: WriteSubmission,
}
impl ReadySubmission {
    /// Original immutable startup intent.
    pub fn status(self) -> ReadyStatus {
        self.status
    }
    /// Exact submitted status byte.
    pub fn byte(self) -> u8 {
        self.transport.byte()
    }
}
/// Once-only readiness outbox. Repeated same-status calls resume the original
/// write; there is no flush/native-completion or parent-receipt claim.
pub struct ReadyWriter {
    writer: ByteWriter,
    status: Option<ReadyStatus>,
}
impl ReadyWriter {
    pub(super) fn new(writer: ByteWriter) -> Self {
        Self {
            writer,
            status: None,
        }
    }
    /// Original status, once admitted, including a pending or failed submission.
    pub fn intent(&self) -> Option<ReadyStatus> {
        self.status
    }
    /// Admit the first status or resume that same immutable intent.
    pub fn begin(&mut self, status: ReadyStatus) -> Result<(), ReadyFailure> {
        match self.status {
            Some(original) if original != status => Err(ReadyFailure::IntentMismatch {
                original,
                attempted: status,
            }),
            Some(_) => Ok(()),
            None => {
                self.writer
                    .begin(status.byte())
                    .map_err(ReadyFailure::Pipe)?;
                self.status = Some(status);
                Ok(())
            }
        }
    }
    /// Drive the original outbox. Completed polls are sticky and never resubmit.
    pub fn poll_signal(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<ReadySubmission, ReadyFailure>> {
        let Some(status) = self.status else {
            return Poll::Ready(Err(ReadyFailure::NoIntent));
        };
        self.writer.poll_send(cx).map(|result| {
            result
                .map(|transport| ReadySubmission { status, transport })
                .map_err(ReadyFailure::Pipe)
        })
    }
    /// Cancellation retains the intent in this owner for a subsequent call.
    pub async fn signal(&mut self, status: ReadyStatus) -> Result<ReadySubmission, ReadyFailure> {
        self.begin(status)?;
        std::future::poll_fn(|cx| self.poll_signal(cx)).await
    }
}
