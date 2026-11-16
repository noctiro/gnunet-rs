//! Exact control bytes attached to one original physical process connection.
use gnunet_service_runtime::{
    pipe::{ByteReader, ByteWriter, PipeError, WriteSubmission},
    process::{ChildRegistry, OriginalChild, RegistryError},
};
use std::{
    error::Error,
    fmt,
    task::{Context, Poll},
};
/// Unique original parent-control read owner.
pub struct ControlReceiver {
    reader: ByteReader,
}
impl ControlReceiver {
    pub(super) fn new(reader: ByteReader) -> Self {
        Self { reader }
    }
    /// Read one actual signed control byte. EOF retires this direction only;
    /// canceled waits retain the original read operation and buffered input.
    pub fn poll_signal(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<i8>, PipeError>> {
        self.reader
            .poll_byte(cx)
            .map(|result| result.map(|byte| byte.map(|byte| byte as i8)))
    }
}
/// Refused control admission, preserving registry and native error identities.
#[derive(Debug)]
pub enum ControlError {
    /// The exact original child token is no longer live in this registry.
    Registry(RegistryError),
    /// The original outbox refused admission or failed natively.
    Pipe(PipeError),
}
impl fmt::Display for ControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl Error for ControlError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Registry(error) => Some(error),
            Self::Pipe(error) => Some(error),
        }
    }
}
/// Control outbox attached to one original qualified child connection.
pub struct ControlSender {
    child: OriginalChild,
    writer: ByteWriter,
}
impl ControlSender {
    pub(super) fn new(child: OriginalChild, writer: ByteWriter) -> Self {
        Self { child, writer }
    }
    /// Admit an exact signed byte only for this registry's live original child.
    /// Cancellation after admission retains that byte; it never retargets a PID.
    pub fn begin(&mut self, registry: &ChildRegistry, signal: i8) -> Result<(), ControlError> {
        if !registry.owns(&self.child) {
            return Err(ControlError::Registry(RegistryError::Stale));
        }
        self.writer.begin(signal as u8).map_err(ControlError::Pipe)
    }
    /// Drive the retained original byte. Submission is not peer processing.
    pub fn poll_send(&mut self, cx: &mut Context<'_>) -> Poll<Result<WriteSubmission, PipeError>> {
        self.writer.poll_send(cx)
    }
    /// Release one software outbox credit after acceptance by Tokio/Mio.
    pub fn take_submission(&mut self) -> Option<WriteSubmission> {
        self.writer.take_submission()
    }
}
