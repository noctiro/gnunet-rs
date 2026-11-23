//! Original-child qualification and actual parent readiness observations.
use super::{control::ControlSender, grant::SignedGrant};
use crate::ReadyStatus;
use gnunet_native::process::{ProcessIdentity, ProcessWait};
use gnunet_service_runtime::{
    pipe::{ByteReader, PipeConnection, PipeError, PipeListener},
    process::{ChildRegistry, OriginalChild, RegistryError},
};
use std::{
    error::Error,
    fmt,
    future::{Future, poll_fn},
    io,
    sync::Arc,
    task::{Context, Poll},
};
/// Failure to obtain actual readiness from the original child's connection.
#[derive(Clone, Debug)]
pub enum ParentFailure {
    /// Original native transport error.
    Pipe(PipeError),
    /// The qualified connection closed before reporting success.
    Eof,
    /// Actual official failure byte from the qualified connection.
    Reported(ReadyStatus),
    /// Unrecognized actual status byte.
    Unexpected(u8),
    /// No qualified connection has yet been accepted.
    NotConnected,
    /// Actual original-process exit observed before connection qualification.
    Exited(u32),
    /// Original native process-wait failure, distinct from pipe I/O failure.
    ExitObservation(Arc<io::Error>),
}
impl fmt::Display for ParentFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl Error for ParentFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Pipe(error) => Some(error),
            Self::ExitObservation(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}
/// Actual '.' observed on the original child's qualified physical connection.
/// This does not imply that the child remains live after the observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadyReceipt {
    child: OriginalChild,
}
impl ReadyReceipt {
    /// Original registry incarnation that produced this observation.
    pub fn child(&self) -> &OriginalChild {
        &self.child
    }
}
enum ParentState {
    Listening {
        listener: PipeListener,
        identity: ProcessIdentity,
        exit: ProcessWait,
    },
    SendingGrant {
        connection: Option<PipeConnection>,
        grant: Box<SignedGrant>,
        sent: usize,
    },
    Reading {
        reader: ByteReader,
        control: Option<ControlSender>,
    },
    Finished {
        result: Result<ReadyReceipt, ParentFailure>,
        control: Option<ControlSender>,
    },
}
/// Parent startup owner bound to an original live registry incarnation.
pub struct ParentBootstrap {
    child: OriginalChild,
    state: ParentState,
    grant: Option<Box<SignedGrant>>,
}
impl ParentBootstrap {
    /// Exact original registry incarnation this bootstrap qualifies.
    pub fn child(&self) -> &OriginalChild {
        &self.child
    }
    /// Bind one pre-reserved endpoint to a live child from this exact registry.
    /// Only the registry lends its original process identity; callers cannot pair
    /// a numeric PID or another process's pin with this token.
    pub fn new(
        listener: PipeListener,
        registry: &ChildRegistry,
        child: &OriginalChild,
    ) -> Result<Self, RegistryError> {
        let identity = registry.identity(child)?;
        let exit = registry.exit_observer(child)?;
        Ok(Self {
            child: child.clone(),
            grant: None,
            state: ParentState::Listening {
                listener,
                identity,
                exit,
            },
        })
    }
    pub(super) fn set_activation_grant(&mut self, grant: Box<SignedGrant>) {
        self.grant = Some(grant);
    }
    /// Accept and qualify the original peer. Cancellation retains the same
    /// listener/identity/exit observer. Actual pre-connect exit fails startup
    /// without an invented timeout. The leases release after qualification or
    /// terminal failure. Connect failure retires this bootstrap permanently.
    pub fn poll_connect(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), ParentFailure>> {
        let connection = match &mut self.state {
            ParentState::Finished {
                result: Err(error), ..
            } => return Poll::Ready(Err(error.clone())),
            ParentState::Finished { .. } | ParentState::Reading { .. } => {
                return Poll::Ready(Ok(()));
            }
            ParentState::SendingGrant { .. } => return self.poll_grant(cx),
            ParentState::Listening {
                listener,
                identity,
                exit,
            } => {
                let mut accepting = std::pin::pin!(listener.accept(identity));
                match accepting.as_mut().poll(cx) {
                    Poll::Ready(result) => {
                        result.map_err(|error| ParentFailure::Pipe(error.into()))
                    }
                    Poll::Pending => match exit.poll_exit(cx) {
                        Poll::Ready(Ok(code)) => Err(ParentFailure::Exited(code)),
                        Poll::Ready(Err(error)) => {
                            Err(ParentFailure::ExitObservation(Arc::new(error)))
                        }
                        Poll::Pending => return Poll::Pending,
                    },
                }
            }
        };
        match connection {
            Ok(connection) => {
                if let Some(grant) = self.grant.take() {
                    self.state = ParentState::SendingGrant {
                        connection: Some(connection),
                        grant,
                        sent: 0,
                    };
                    self.poll_grant(cx)
                } else {
                    self.connected(connection)
                }
            }
            Err(error) => self.fail(error),
        }
    }
    fn poll_grant(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), ParentFailure>> {
        let ParentState::SendingGrant {
            connection,
            grant,
            sent,
        } = &mut self.state
        else {
            return self.fail(ParentFailure::NotConnected);
        };
        let Some(pipe) = connection.as_mut() else {
            return self.fail(ParentFailure::NotConnected);
        };
        let bytes = grant.bytes();
        match pipe.poll_startup_prefix(cx, &bytes[*sent..]) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return self.fail(ParentFailure::Pipe(error)),
            Poll::Ready(Ok(count)) => *sent += count,
        }
        if *sent != bytes.len() {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        match connection.take() {
            Some(connection) => self.connected(connection),
            None => self.fail(ParentFailure::NotConnected),
        }
    }
    fn connected(&mut self, connection: PipeConnection) -> Poll<Result<(), ParentFailure>> {
        let (reader, writer) = connection.split();
        self.state = ParentState::Reading {
            reader,
            control: Some(ControlSender::new(self.child.clone(), writer)),
        };
        Poll::Ready(Ok(()))
    }
    fn fail(&mut self, error: ParentFailure) -> Poll<Result<(), ParentFailure>> {
        self.state = ParentState::Finished {
            result: Err(error.clone()),
            control: None,
        };
        Poll::Ready(Err(error))
    }
    /// Await original peer qualification. Dropping this future preserves the
    /// same endpoint, process identity and native exit observation.
    pub async fn connect(&mut self) -> Result<(), ParentFailure> {
        poll_fn(|cx| self.poll_connect(cx)).await
    }
    /// Observe one actual status byte. Terminal results are sticky; canceled
    /// waits retain the original reader and never relabel a replacement source.
    pub fn poll_status(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<ReadyReceipt, ParentFailure>> {
        let (reader, control) = match &mut self.state {
            ParentState::Listening { .. } | ParentState::SendingGrant { .. } => {
                return Poll::Ready(Err(ParentFailure::NotConnected));
            }
            ParentState::Finished { result, .. } => return Poll::Ready(result.clone()),
            ParentState::Reading { reader, control } => (reader, control),
        };
        let result = match reader.poll_byte(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => Err(ParentFailure::Pipe(error)),
            Poll::Ready(Ok(None)) => Err(ParentFailure::Eof),
            Poll::Ready(Ok(Some(byte))) => match ReadyStatus::from_byte(byte) {
                Some(ReadyStatus::AcceptRegistered) => Ok(ReadyReceipt {
                    child: self.child.clone(),
                }),
                Some(status) => Err(ParentFailure::Reported(status)),
                None => Err(ParentFailure::Unexpected(byte)),
            },
        };
        let control = control.take();
        self.state = ParentState::Finished {
            result: result.clone(),
            control,
        };
        Poll::Ready(result)
    }
    /// Wait for qualification and the actual byte; no invented startup timeout.
    pub async fn wait_ready(&mut self) -> Result<ReadyReceipt, ParentFailure> {
        self.connect().await?;
        std::future::poll_fn(|cx| self.poll_status(cx)).await
    }
    /// Transfer the unique control sender once after connection qualification.
    pub fn take_control(&mut self) -> Option<ControlSender> {
        match &mut self.state {
            ParentState::Listening { .. } | ParentState::SendingGrant { .. } => None,
            ParentState::Reading { control, .. } | ParentState::Finished { control, .. } => {
                control.take()
            }
        }
    }
}
