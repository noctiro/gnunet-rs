//! Private Windows process byte channels over actual overlapped named pipes.
use gnunet_native::identity::PrivateSecurityDescriptor;
use gnunet_native::pipe::{Endpoint, StartupPipe};
use gnunet_native::process::ProcessIdentity;
use std::{
    error::Error,
    fmt, io,
    os::windows::io::{AsHandle, BorrowedHandle, IntoRawHandle},
    sync::Arc,
    task::{Context, Poll},
};
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, PipeMode, ServerOptions,
};

mod stdio;
pub use stdio::{InputWriter, OutputReader};

/// Sticky original pipe failure. Clones preserve the original I/O cause and code.
#[derive(Clone, Debug)]
pub struct PipeError(Arc<io::Error>);
impl PipeError {
    /// Original native error classification.
    pub fn kind(&self) -> io::ErrorKind {
        self.0.kind()
    }
    /// Original OS error, when the failed operation supplied one.
    pub fn raw_os_error(&self) -> Option<i32> {
        self.0.raw_os_error()
    }
}
impl fmt::Display for PipeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl Error for PipeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.0.as_ref())
    }
}
impl From<io::Error> for PipeError {
    fn from(error: io::Error) -> Self {
        Self(Arc::new(error))
    }
}

/// One first-instance, owner-only local pipe waiting for its one child connection.
/// No numeric foreign handle is captured or reconstructed. Call from an entered
/// Tokio runtime with I/O enabled; a runtime without I/O may panic on registration.
pub struct PipeListener {
    endpoint: Endpoint,
    server: Option<NamedPipeServer>,
}
impl PipeListener {
    /// Reserve one random local pipe name with a protected owner-only DACL,
    /// one instance and remote clients refused. Existing names are never reused.
    /// Caller excludes thread impersonation during security preparation.
    pub fn bind() -> io::Result<Self> {
        Self::bind_with(PrivateSecurityDescriptor::owner_only()?)
    }
    /// Reserve a private local pipe with access for the selected child account.
    pub fn bind_for_user(user: &gnunet_native::identity::Sid) -> io::Result<Self> {
        Self::bind_with(PrivateSecurityDescriptor::pipe_with_client(user)?)
    }
    #[expect(
        unsafe_code,
        reason = "The private descriptor and borrowed initialized attributes stay live throughout the synchronous Tokio native constructor, which copies their security data"
    )]
    fn bind_with(descriptor: PrivateSecurityDescriptor) -> io::Result<Self> {
        tokio::runtime::Handle::try_current().map_err(io::Error::other)?;
        let endpoint = Endpoint::generate()?;
        let mut attributes = descriptor.attributes();
        let mut options = ServerOptions::new();
        options
            .pipe_mode(PipeMode::Byte)
            .first_pipe_instance(true)
            .max_instances(1)
            .reject_remote_clients(true)
            .in_buffer_size(64)
            .out_buffer_size(64);
        // SAFETY: complete initialized attributes and their descriptor owner stay
        // live through this synchronous CreateNamedPipe-backed call.
        let server = unsafe {
            options
                .create_with_security_attributes_raw(endpoint.as_os_str(), attributes.as_mut_ptr())
        }?;
        Ok(Self {
            endpoint,
            server: Some(server),
        })
    }
    /// Captured local location, not readiness or peer-authentication evidence.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }
    /// Accept the actual pinned process's connection. A canceled future retains
    /// the same listener/overlapped connect. A failed/foreign qualification
    /// retires this physical pipe instead of recycling its buffered read state.
    /// The identity lease pins its
    /// process object; qualification proves identity, not continued liveness.
    pub async fn accept(&mut self, expected: &ProcessIdentity) -> io::Result<PipeConnection> {
        let server = self
            .server
            .as_ref()
            .ok_or_else(|| io::Error::from(io::ErrorKind::AlreadyExists))?;
        server.connect().await?;
        match expected.matches_pipe_client(server.as_handle()) {
            Ok(true) => {}
            result => {
                self.server = None;
                return Err(result.err().unwrap_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "private pipe client is not the original child",
                    )
                }));
            }
        }
        let server = self
            .server
            .take()
            .ok_or_else(|| io::Error::from(io::ErrorKind::AlreadyExists))?;
        Ok(PipeConnection(Arc::new(Io::Server(server))))
    }
}
enum Io {
    Server(NamedPipeServer),
    Client(NamedPipeClient),
}
impl Io {
    fn poll_read_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            Self::Server(pipe) => pipe.poll_read_ready(cx),
            Self::Client(pipe) => pipe.poll_read_ready(cx),
        }
    }
    fn poll_write_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            Self::Server(pipe) => pipe.poll_write_ready(cx),
            Self::Client(pipe) => pipe.poll_write_ready(cx),
        }
    }
    fn read(&self, bytes: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Server(pipe) => pipe.try_read(bytes),
            Self::Client(pipe) => pipe.try_read(bytes),
        }
    }
    fn write(&self, bytes: &[u8]) -> io::Result<usize> {
        match self {
            Self::Server(pipe) => pipe.try_write(bytes),
            Self::Client(pipe) => pipe.try_write(bytes),
        }
    }
}
impl AsHandle for Io {
    fn as_handle(&self) -> BorrowedHandle<'_> {
        match self {
            Self::Server(pipe) => pipe.as_handle(),
            Self::Client(pipe) => pipe.as_handle(),
        }
    }
}
impl Drop for Io {
    fn drop(&mut self) {
        // Last logical owner only. Mio cancels reads/connects on Drop but keeps
        // writes to flush them. Request write cancellation as well, without
        // freeing Mio's native loans or waiting for completion/peer progress.
        let _cancellation = gnunet_native::pipe::request_cancellation(self.as_handle());
    }
}
/// One physical connected pipe. Splitting creates one read and one write owner;
/// neither half is cloneable. Dropping one half is not a native half-close.
/// Last-owner Drop requests cancellation best effort without waiting. Accepted
/// bytes can therefore be canceled; submission never guarantees delivery.
pub struct PipeConnection(Arc<Io>);
impl PipeConnection {
    /// Open the captured local bootstrap location with fresh overlapped ownership,
    /// avoiding unsafe adoption of environment-provided raw handles. There is no
    /// retry/timeout or alternate endpoint hidden in this call.
    pub fn connect(endpoint: &Endpoint) -> io::Result<Self> {
        tokio::runtime::Handle::try_current().map_err(io::Error::other)?;
        let client = ClientOptions::new()
            .pipe_mode(PipeMode::Byte)
            .open(endpoint.as_os_str())?;
        Ok(Self(Arc::new(Io::Client(client))))
    }
    /// Register the same physical client used to receive its startup prefix.
    /// The native owner has settled all outstanding reads before transfer.
    #[expect(
        unsafe_code,
        reason = "StartupPipe uniquely owns the original overlapped client with all early operations settled"
    )]
    pub fn register_startup_pipe(pipe: StartupPipe) -> io::Result<Self> {
        tokio::runtime::Handle::try_current().map_err(io::Error::other)?;
        let raw = pipe.into_handle()?.into_raw_handle();
        // SAFETY: the exclusively owned overlapped client is transferred to
        // Tokio, which owns the handle even if its reactor registration fails.
        let client = unsafe { NamedPipeClient::from_raw_handle(raw) }?;
        Ok(Self(Arc::new(Io::Client(client))))
    }
    /// Submit some of the bounded startup prefix before splitting the connection.
    /// The caller owns the prefix and advances it only by the accepted count.
    /// Peer receipt and later service readiness remain separate observations.
    pub fn poll_startup_prefix(
        &mut self,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<Result<usize, PipeError>> {
        if bytes.is_empty() || bytes.len() > 256 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid startup prefix extent",
            )
            .into()));
        }
        match self.0.poll_write_ready(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
            Poll::Ready(Ok(())) => {}
        }
        match self.0.write(bytes) {
            Ok(accepted) if (1..=bytes.len()).contains(&accepted) => Poll::Ready(Ok(accepted)),
            Ok(_) => Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero).into())),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                match self.0.poll_write_ready(cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Ok(())) => {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
                }
            }
            Err(error) => Poll::Ready(Err(error.into())),
        }
    }
    /// Move the original physical pipe into its unique logical direction owners.
    pub fn split(self) -> (ByteReader, ByteWriter) {
        (
            ByteReader {
                io: Some(Arc::clone(&self.0)),
                failure: None,
            },
            ByteWriter {
                io: self.0,
                state: SendState::Idle,
            },
        )
    }
}
/// Original control/readiness read direction. EOF retires only this direction
/// and never synthesizes a signal or successful startup byte.
pub struct ByteReader {
    io: Option<Arc<Io>>,
    failure: Option<PipeError>,
}
impl ByteReader {
    /// Read one actual byte with at most one transport read per poll. Native
    /// read/overlapped storage remains in this owner across canceled waits.
    pub fn poll_byte(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<u8>, PipeError>> {
        if let Some(error) = &self.failure {
            return Poll::Ready(Err(error.clone()));
        }
        let Some(io) = &self.io else {
            return Poll::Ready(Ok(None));
        };
        let outcome = match io.poll_read_ready(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => Err(error),
            Poll::Ready(Ok(())) => {
                let mut byte = [0];
                match io.read(&mut byte) {
                    Ok(0) => Ok(None),
                    Ok(1) => Ok(Some(byte[0])),
                    Ok(_) => Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "one-byte pipe read exceeded its buffer",
                    )),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        return match io.poll_read_ready(cx) {
                            Poll::Pending => Poll::Pending,
                            Poll::Ready(Ok(())) => {
                                cx.waker().wake_by_ref();
                                Poll::Pending
                            }
                            Poll::Ready(Err(error)) => self.fail(error),
                        };
                    }
                    Err(error) => Err(error),
                }
            }
        };
        match outcome {
            Ok(None) => {
                self.io = None;
                Poll::Ready(Ok(None))
            }
            Ok(value) => Poll::Ready(Ok(value)),
            Err(error) if gnunet_native::pipe::is_peer_closed(&error) => {
                self.io = None;
                Poll::Ready(Ok(None))
            }
            Err(error) => self.fail(error),
        }
    }
    fn fail(&mut self, error: io::Error) -> Poll<Result<Option<u8>, PipeError>> {
        let error = PipeError::from(error);
        self.failure = Some(error.clone());
        self.io = None;
        Poll::Ready(Err(error))
    }
}
/// A byte accepted by Tokio/Mio. This is not native I/O completion, parent
/// consumption, application processing or an exit/readiness receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WriteSubmission {
    byte: u8,
}
impl WriteSubmission {
    /// Original accepted byte.
    #[must_use]
    pub fn byte(self) -> u8 {
        self.byte
    }
}
enum SendState {
    Idle,
    Pending(u8),
    Submitted(WriteSubmission),
    Failed(PipeError),
}
/// One bounded byte outbox plus the original write direction. Tokio/Mio owns
/// overlapped loans after acceptance; flush/shutdown is not a completion barrier.
pub struct ByteWriter {
    io: Arc<Io>,
    state: SendState,
}
impl ByteWriter {
    /// Admit one immutable byte. An outstanding or untaken submission refuses
    /// another intent. No byte is written before `poll_send` is driven.
    pub fn begin(&mut self, byte: u8) -> Result<(), PipeError> {
        if !matches!(self.state, SendState::Idle) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "pipe outbox already owns an intent",
            )
            .into());
        }
        self.state = SendState::Pending(byte);
        Ok(())
    }
    /// Drive the original byte once; canceled waits preserve its state. Repeated
    /// completed polls return the same submission without another transport write.
    pub fn poll_send(&mut self, cx: &mut Context<'_>) -> Poll<Result<WriteSubmission, PipeError>> {
        let byte = match &self.state {
            SendState::Idle => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "pipe outbox has no intent",
                )
                .into()));
            }
            SendState::Pending(byte) => *byte,
            SendState::Submitted(receipt) => return Poll::Ready(Ok(*receipt)),
            SendState::Failed(error) => return Poll::Ready(Err(error.clone())),
        };
        let result = match self.io.poll_write_ready(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => Err(error),
            Poll::Ready(Ok(())) => match self.io.write(&[byte]) {
                Ok(1) => Ok(WriteSubmission { byte }),
                Ok(_) => Err(io::ErrorKind::WriteZero.into()),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    return match self.io.poll_write_ready(cx) {
                        Poll::Pending => Poll::Pending,
                        Poll::Ready(Ok(())) => {
                            cx.waker().wake_by_ref();
                            Poll::Pending
                        }
                        Poll::Ready(Err(error)) => self.fail(error),
                    };
                }
                Err(error) => Err(error),
            },
        };
        match result {
            Ok(receipt) => {
                self.state = SendState::Submitted(receipt);
                Poll::Ready(Ok(receipt))
            }
            Err(error) => self.fail(error),
        }
    }
    /// Consume one submission and release software outbox credit. This does not
    /// assert that Mio's native overlapped loan has completed or reset its state.
    pub fn take_submission(&mut self) -> Option<WriteSubmission> {
        if let SendState::Submitted(receipt) = self.state {
            self.state = SendState::Idle;
            Some(receipt)
        } else {
            None
        }
    }
    fn fail(&mut self, error: io::Error) -> Poll<Result<WriteSubmission, PipeError>> {
        let error = PipeError::from(error);
        self.state = SendState::Failed(error.clone());
        Poll::Ready(Err(error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        future::{Future, poll_fn},
        task::Waker,
        time::Duration,
    };
    fn check(value: bool, message: &'static str) -> io::Result<()> {
        if value {
            Ok(())
        } else {
            Err(io::Error::other(message))
        }
    }
    fn cancel_pending(future: impl Future) -> io::Result<()> {
        let mut future = std::pin::pin!(future);
        check(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending(),
            "wait completed before release",
        )
    }
    async fn original_pipe() -> Result<(), Box<dyn Error>> {
        let mut listener = PipeListener::bind()?;
        let identity = ProcessIdentity::current()?;
        cancel_pending(listener.accept(&identity))?;
        let client = PipeConnection::connect(listener.endpoint())?;
        let server = listener.accept(&identity).await?;
        let (mut reader, server_writer) = server.split();
        let (client_reader, mut writer) = client.split();
        cancel_pending(poll_fn(|cx| reader.poll_byte(cx)))?;
        writer.begin(255)?;
        check(
            writer.begin(15).err().map(|error| error.kind()) == Some(io::ErrorKind::WouldBlock),
            "pending intent was replaced",
        )?;
        let submission = poll_fn(|cx| writer.poll_send(cx)).await?;
        check(submission.byte() == 255, "submitted byte changed")?;
        check(
            poll_fn(|cx| writer.poll_send(cx)).await? == submission,
            "submission was not sticky",
        )?;
        check(
            poll_fn(|cx| reader.poll_byte(cx)).await? == Some(255),
            "actual byte changed",
        )?;
        cancel_pending(poll_fn(|cx| reader.poll_byte(cx)))?;
        check(
            writer.take_submission() == Some(submission) && writer.take_submission().is_none(),
            "credit was duplicated",
        )?;
        writer.begin(15)?;
        check(
            poll_fn(|cx| writer.poll_send(cx)).await?.byte() == 15,
            "next submission changed",
        )?;
        check(
            poll_fn(|cx| reader.poll_byte(cx)).await? == Some(15),
            "next actual byte changed",
        )?;
        drop(writer);
        drop(client_reader);
        check(
            poll_fn(|cx| reader.poll_byte(cx)).await?.is_none(),
            "EOF became data",
        )?;
        check(
            poll_fn(|cx| reader.poll_byte(cx)).await?.is_none(),
            "EOF was not sticky",
        )?;
        drop(server_writer);
        Ok(())
    }
    #[tokio::test(flavor = "current_thread")]
    async fn canceled_waits_keep_original_pipe_without_duplicate_writes()
    -> Result<(), Box<dyn Error>> {
        tokio::time::timeout(Duration::from_secs(10), original_pipe()).await?
    }
}
