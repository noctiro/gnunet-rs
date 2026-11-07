//! Streaming authenticated file transfer through official local FS services.
//!
//! These operations consume the real service protocols. Success establishes
//! whole-file or selected-range authentication, or actual local store acknowledgements; it does
//! not establish remote replication or indefinite network availability.
mod directory;
pub mod probe;
#[cfg(feature = "network")]
pub(crate) mod publish;
pub mod range;
pub mod tree_download;
#[cfg(feature = "network")]
pub mod tree_publish;
#[cfg(feature = "network")]
pub mod ublock;
#[cfg(feature = "network")]
pub mod unindex;
use crate::{BlockSource, Buffers, Control, Limits, Progress, ReadFile, Repository};
use gnunet_client_host::{
    EndpointSource,
    channel::{Channel, ConnectionStep},
};
use gnunet_fs::{
    Content, Location,
    content::{BlockKey, FileReader, NodeRef, TAG_BYTES, VerifiedChunk},
};
use gnunet_service_runtime::{
    clock::{Deadline, RuntimeClock},
    framing::{Accounting, Budget, Class, Limits as FrameLimits, OwnedFrame, ReadStep},
};
use gnunet_types::{AbsoluteTime, Error as ProtocolError};
use gnunet_wire::official::fs::{
    BlockType, CLIENT_PUT_PREFIX, Request, Response, SEARCH_LOOPBACK_ONLY, SEARCH_PREFIX, Search,
};
#[cfg(feature = "network")]
pub use publish::{
    BlockOptions, IndexPublishCause, IndexPublishError, IndexRegistration, IndexedFile,
    PublishOptions, RegistrationFailure, StoreFailure, StoredFile,
};
use std::{
    fmt,
    future::{Future, poll_fn},
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{AsyncWrite, AsyncWriteExt};

/// Transfer failure; an output writer can retain an authenticated prefix.
#[derive(Debug)]
pub enum Error {
    /// Original filesystem, resource or source error.
    Local(crate::Error),
    /// Actual CLIENT configuration or socket/port refusal.
    Client(gnunet_client_host::ConnectError),
    /// Original protocol, authentication or clock-regression refusal.
    Protocol(ProtocolError),
    /// The original operation deadline elapsed. Preserve the first connection
    /// loss too, if reconnect attempts preceded the deadline.
    Deadline {
        /// First actual connection/read/write error during this operation.
        first_io: Option<io::Error>,
    },
    /// Caller stopped between blocks or during a quiet native read; no completion is claimed.
    Cancelled(Progress),
    /// Original DATASTORE result/uncertainty and its retained actual reply.
    #[cfg(feature = "network")]
    Store(Box<StoreFailure>),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local(error) => error.fmt(f),
            Self::Client(error) => error.fmt(f),
            Self::Protocol(error) => write!(f, "FS transfer: {error}"),
            Self::Deadline {
                first_io: Some(error),
            } => {
                write!(f, "FS transfer deadline after connection loss: {error}")
            }
            Self::Deadline { first_io: None } => f.write_str("FS transfer deadline"),
            Self::Cancelled(_) => f.write_str("FS transfer cancelled"),
            #[cfg(feature = "network")]
            Self::Store(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Local(error) => Some(error),
            Self::Client(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::Deadline {
                first_io: Some(error),
            } => Some(error),
            Self::Deadline { first_io: None } | Self::Cancelled(_) => None,
            #[cfg(feature = "network")]
            Self::Store(error) => Some(error.as_ref()),
        }
    }
}
impl From<crate::Error> for Error {
    fn from(error: crate::Error) -> Self {
        Self::Local(error)
    }
}
impl From<ProtocolError> for Error {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}
impl From<gnunet_client_host::ConnectError> for Error {
    fn from(error: gnunet_client_host::ConnectError) -> Self {
        Self::Client(error)
    }
}
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Local(crate::Error::Io(error))
    }
}

/// File lookup policy. D/I expiry does not invalidate authenticated content.
#[derive(Clone, Copy, Debug)]
pub struct DownloadOptions {
    /// Maximum file and encoded-tree work admitted before buffer growth.
    pub limits: Limits,
    /// One absolute target in the EndpointSource clock, shared across every block
    /// and reconnect. No new per-block lifetime is silently granted.
    pub deadline: AbsoluteTime,
    /// Official search anonymity value.
    pub anonymity: u32,
    /// Signed LOC placement peer, or all zeroes for ordinary CHK discovery.
    pub target: [u8; 32],
    /// Restrict lookup to the service's own datastore.
    pub local_only: bool,
    /// Additional bound on queries admitted to one dedicated MQ before rotation.
    /// Official services normally release completed D/I searches themselves;
    /// rotation also clears pending/late input. There is no per-search cancel
    /// frame. Must be nonzero.
    pub queries_per_connection: u32,
    /// Maximum physical bytes offered in one read/write step, nonzero.
    pub io_slice_bytes: usize,
}
impl DownloadOptions {
    /// Ordinary anonymous CHK discovery with bounded connection reuse.
    #[must_use]
    pub fn new(deadline: AbsoluteTime) -> Self {
        Self {
            limits: Limits::default(),
            deadline,
            anonymity: 1,
            target: [0; 32],
            local_only: false,
            queries_per_connection: 32,
            io_slice_bytes: 65535,
        }
    }
    /// Use the peer from an already signature-verified LOC. This does not claim
    /// present reachability or retention; current LOC validity is caller policy.
    #[must_use]
    pub fn location(location: Location, deadline: AbsoluteTime) -> Self {
        Self {
            target: *location.peer().as_bytes(),
            ..Self::new(deadline)
        }
    }
}

pub(crate) struct TimeLimit {
    clock: Arc<dyn RuntimeClock>,
    timer: Deadline,
    now: AbsoluteTime,
    target: AbsoluteTime,
    native: Option<(tokio::time::Instant, Pin<Box<tokio::time::Sleep>>)>,
}
impl TimeLimit {
    pub(crate) fn new(clock: Arc<dyn RuntimeClock>, target: AbsoluteTime) -> Result<Self, Error> {
        let now = clock.sample()?.now;
        if target <= now {
            return Err(Error::Deadline { first_io: None });
        }
        let timer = Deadline::at(clock.clone(), target)?;
        Ok(Self {
            clock,
            timer,
            now,
            target,
            native: None,
        })
    }
    fn bounded(
        clock: Arc<dyn RuntimeClock>,
        target: AbsoluteTime,
        hard: tokio::time::Instant,
    ) -> Result<Self, Error> {
        if tokio::time::Instant::now() >= hard {
            return Err(Error::Deadline { first_io: None });
        }
        let native = Box::pin(tokio::time::sleep_until(hard));
        let mut result = Self::new(clock, target)?;
        if tokio::time::Instant::now() >= hard {
            return Err(Error::Deadline { first_io: None });
        }
        result.native = Some((hard, native));
        Ok(result)
    }
    fn native_guard(&mut self, cx: &mut Context<'_>) -> Result<(), Error> {
        if let Some((hard, timer)) = self.native.as_mut()
            && (tokio::time::Instant::now() >= *hard || timer.as_mut().poll(cx).is_ready())
        {
            return Err(Error::Deadline { first_io: None });
        }
        Ok(())
    }
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        self.native_guard(cx)?;
        let now = self.clock.sample()?.now;
        self.native_guard(cx)?;
        if now < self.now {
            return Poll::Ready(Err(ProtocolError::TimeUncertain.into()));
        }
        self.now = now;
        if now >= self.target {
            return Poll::Ready(Err(Error::Deadline { first_io: None }));
        }
        match Pin::new(&mut self.timer).poll(cx) {
            Poll::Pending => Poll::Ready(self.native_guard(cx)),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
            Poll::Ready(Ok(())) => Poll::Ready(Err(Error::Deadline { first_io: None })),
        }
    }
    #[cfg(feature = "network")]
    async fn during<F: Future>(&mut self, future: F) -> Result<F::Output, Error> {
        let mut future = std::pin::pin!(future);
        poll_fn(|cx| {
            match self.poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => result?,
            }
            future.as_mut().poll(cx).map(Ok)
        })
        .await
    }
    #[cfg(feature = "network")]
    fn remaining(&self) -> gnunet_types::Duration {
        gnunet_types::Duration(self.target.as_micros().saturating_sub(self.now.as_micros()))
    }
}

// One transfer owns this complete physical channel. Each query is sequential;
// current-query validation prevents delayed replies from becoming another block.
struct Lookup {
    channel: Channel<u64>,
    time: TimeLimit,
    options: DownloadOptions,
    connected: bool,
    queries: u32,
    serial: u64,
    first_io: Option<io::Error>,
    queries_written: u64,
}
impl Lookup {
    fn new(source: EndpointSource, options: DownloadOptions) -> Result<Self, Error> {
        if options.queries_per_connection == 0 || options.io_slice_bytes == 0 {
            return Err(ProtocolError::InvalidInput.into());
        }
        let time = TimeLimit::new(source.clock(), options.deadline)?;
        Self::with_time(source, options, time)
    }
    fn bounded(
        source: EndpointSource,
        options: DownloadOptions,
        hard: tokio::time::Instant,
    ) -> Result<Self, Error> {
        if options.queries_per_connection == 0 || options.io_slice_bytes == 0 {
            return Err(ProtocolError::InvalidInput.into());
        }
        let time = TimeLimit::bounded(source.clock(), options.deadline, hard)?;
        Self::with_time(source, options, time)
    }
    fn with_time(
        source: EndpointSource,
        options: DownloadOptions,
        time: TimeLimit,
    ) -> Result<Self, Error> {
        let channel = Channel::new(
            source,
            FrameLimits {
                frame_bytes: CLIENT_PUT_PREFIX + gnunet_fs::content::BLOCK_BYTES + TAG_BYTES,
                ordinary: Budget {
                    frames: 1,
                    bytes: SEARCH_PREFIX,
                },
                reserved: Budget::default(),
                accounting: Accounting::Retained,
                io_slice_bytes: options.io_slice_bytes,
            },
        )?;
        Ok(Self {
            channel,
            time,
            options,
            connected: false,
            queries: 0,
            serial: 0,
            first_io: None,
            queries_written: 0,
        })
    }
    fn time(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        if self.time.native_guard(cx).is_err() {
            return Poll::Ready(Err(Error::Deadline {
                first_io: self.first_io.take(),
            }));
        }
        match self.channel.poll_clock(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result?,
        }
        self.time.poll(cx).map(|result| {
            result.map_err(|error| match error {
                Error::Deadline { .. } => Error::Deadline {
                    first_io: self.first_io.take(),
                },
                error => error,
            })
        })
    }
    fn lost(&mut self, error: io::Error) -> Result<(), Error> {
        if self.first_io.is_none() {
            self.first_io = Some(error);
        }
        self.channel.detach();
        self.connected = false;
        self.channel.schedule_retry()?;
        Ok(())
    }
    async fn during<F: Future>(&mut self, future: F) -> Result<F::Output, Error> {
        let mut future = std::pin::pin!(future);
        poll_fn(|cx| {
            match self.time(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => result?,
            }
            future.as_mut().poll(cx).map(Ok)
        })
        .await
    }
    async fn fetch(&mut self, request: NodeRef) -> Result<(), Error> {
        if self.queries >= self.options.queries_per_connection {
            self.channel.detach();
            self.connected = false;
        }
        let kind = if request.node().level() == 0 {
            BlockType::DBLOCK
        } else {
            BlockType::IBLOCK
        };
        let query = request.key().query;
        let mut queued = false;
        let mut written = false;
        poll_fn(|cx| {
            match self.time(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => result?,
            }
            if !self.connected {
                match self.channel.poll_connect(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                    Poll::Ready(Ok(ConnectionStep::Attached)) => {
                        self.connected = true;
                        self.queries = 0;
                    }
                    Poll::Ready(Ok(ConnectionStep::Unavailable(error))) => {
                        return Poll::Ready(Err(error.into()));
                    }
                    Poll::Ready(Ok(ConnectionStep::Retry { error, .. })) => {
                        if self.first_io.is_none() {
                            self.first_io = Some(error);
                        }
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
            }
            if !queued {
                let framed = self.channel.framing_mut().ok_or(ProtocolError::NotReady)?;
                framed.reserve(SEARCH_PREFIX, Class::Ordinary)?;
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact(SEARCH_PREFIX)
                    .map_err(|_| ProtocolError::Capacity)?;
                bytes.resize(SEARCH_PREFIX, 0);
                Request::Search(Search {
                    options: if self.options.local_only {
                        SEARCH_LOOPBACK_ONLY
                    } else {
                        0
                    },
                    block_type: kind,
                    anonymity: self.options.anonymity,
                    target: self.options.target,
                    query,
                    seen: &[],
                })
                .encode(&mut bytes)?;
                self.serial = self.serial.checked_add(1).ok_or(ProtocolError::Overflow)?;
                framed
                    .enqueue_owned(OwnedFrame::new(bytes), self.serial, Class::Ordinary)
                    .map_err(|rejected| rejected.reason)?;
                self.queries += 1;
                queued = true;
            }
            let framed = self.channel.framing_mut().ok_or(ProtocolError::NotReady)?;
            if !written {
                match framed.poll_write(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => {
                        self.lost(error)?;
                        queued = false;
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    Poll::Ready(Ok(progress)) => {
                        if progress.origin != self.serial {
                            return Poll::Ready(Err(ProtocolError::Stale.into()));
                        }
                        written = progress.complete;
                        if written {
                            self.queries_written = self
                                .queries_written
                                .checked_add(1)
                                .ok_or(ProtocolError::Overflow)?;
                        }
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
            }
            if let Some(frame) = framed.frame() {
                match Response::decode(frame)? {
                    Response::Put(put) => {
                        // Old D/I searches can deliver delayed replies on this
                        // same MQ. Route only the actual ciphertext query.
                        if gnunet_crypto::hash512(put.block) == query {
                            if put.block_type != kind
                                || put.block.len() != request.node().plaintext_bytes() + TAG_BYTES
                            {
                                return Poll::Ready(Err(ProtocolError::Authentication.into()));
                            }
                            return Poll::Ready(Ok(()));
                        }
                    }
                    Response::Unknown(_) => {}
                    _ => return Poll::Ready(Err(ProtocolError::Malformed.into())),
                }
                framed.release_frame();
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            match framed.poll_read(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Ok(ReadStep::Progress { .. })) => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Poll::Ready(Ok(ReadStep::Eof)) => {
                    self.lost(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "FS lookup MQ closed",
                    ))?;
                    queued = false;
                    written = false;
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Poll::Ready(Err(error)) => {
                    self.lost(error)?;
                    queued = false;
                    written = false;
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
        })
        .await
    }
    async fn fetch_controlled(
        &mut self,
        request: NodeRef,
        progress: Progress,
        control: &mut impl FnMut(Progress) -> Control,
    ) -> Result<(), Error> {
        // This same future retains the original queue, partial write/read
        // cursors and reconnect state while quiet reads observe caller control.
        // The physical timer grants neither a new MQ nor a logical lifetime.
        let mut fetch = std::pin::pin!(self.fetch(request));
        let mut observe = std::pin::pin!(async {
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                if control(progress) == Control::Cancel {
                    return Err(Error::Cancelled(progress));
                }
            }
        });
        poll_fn(|cx| match fetch.as_mut().poll(cx) {
            Poll::Ready(result) => Poll::Ready(result),
            Poll::Pending => observe.as_mut().poll(cx),
        })
        .await
    }
    fn block(&self) -> Result<&[u8], Error> {
        let frame = self
            .channel
            .framing()
            .and_then(|framed| framed.frame())
            .ok_or(ProtocolError::NotReady)?;
        match Response::decode(frame)? {
            Response::Put(put) => Ok(put.block),
            _ => Err(ProtocolError::Malformed.into()),
        }
    }
    fn release(&mut self) {
        if let Some(framed) = self.channel.framing_mut() {
            framed.release_frame();
        }
    }
}

// Shared authenticated transfer, extracted from the original Buffers::download.
// Lookup remains the sole owner of MQ, reconnect, query and deadline semantics.
struct Download<'buffers, 'cache> {
    reader: FileReader<'buffers>,
    plain: &'buffers mut [u8],
    encoded: &'buffers mut [u8],
    lookup: Lookup,
    cache: Option<&'cache mut Repository>,
    progress: Progress,
}
trait DownloadSink {
    async fn chunk(&mut self, chunk: VerifiedChunk<'_>) -> Result<(), Error>;
    async fn finish(&mut self) -> Result<(), Error>;
}
impl<'buffers, 'cache> Download<'buffers, 'cache> {
    fn new(
        source: EndpointSource,
        content: Content,
        cache: Option<&'cache mut Repository>,
        options: DownloadOptions,
        keys: &'buffers mut [BlockKey],
        plain: &'buffers mut [u8],
        encoded: &'buffers mut [u8],
    ) -> Result<Self, Error> {
        Ok(Self {
            lookup: Lookup::new(source, options)?,
            reader: FileReader::new(content, keys)?,
            plain,
            encoded,
            cache,
            progress: Progress::default(),
        })
    }
    async fn run(
        &mut self,
        sink: &mut impl DownloadSink,
        mut control: impl FnMut(Progress) -> Control,
    ) -> Result<ReadFile, Error> {
        while let Some(request) = self.reader.next() {
            self.lookup.during(std::future::ready(())).await?;
            if control(self.progress) == Control::Cancel {
                return Err(Error::Cancelled(self.progress));
            }
            let cached = if let Some(store) = self.cache.as_deref_mut() {
                match store.read_block(request, self.encoded) {
                    Ok(length) => Some(length),
                    Err(crate::Error::Io(error)) if error.kind() == io::ErrorKind::NotFound => None,
                    Err(error) => return Err(error.into()),
                }
            } else {
                None
            };
            let (length, chunk) = if let Some(length) = cached {
                let bytes = self.encoded.get(..length).ok_or(ProtocolError::Malformed)?;
                (length, self.reader.open_next(bytes, self.plain)?)
            } else {
                self.lookup
                    .fetch_controlled(request, self.progress, &mut control)
                    .await?;
                if control(self.progress) == Control::Cancel {
                    return Err(Error::Cancelled(self.progress));
                }
                let bytes = self.lookup.block()?;
                let chunk = self.reader.open_next(bytes, self.plain)?;
                if let Some(store) = self.cache.as_deref_mut() {
                    store.cache(request.key().query, bytes)?;
                }
                let length = bytes.len();
                self.lookup.release();
                (length, chunk)
            };
            if let Some(chunk) = chunk {
                let length = chunk.bytes().len();
                self.lookup.during(sink.chunk(chunk)).await??;
                self.progress.plaintext_bytes += length as u64;
            }
            self.progress.blocks += 1;
            self.progress.encoded_bytes += length as u128;
        }
        if control(self.progress) == Control::Cancel {
            return Err(Error::Cancelled(self.progress));
        }
        self.lookup.during(sink.finish()).await??;
        Ok(ReadFile {
            verified: self.reader.completion().ok_or(ProtocolError::NotReady)?,
            progress: self.progress,
        })
    }
}
struct Writer<'output, W> {
    output: &'output mut W,
}
impl<W: AsyncWrite + Unpin> DownloadSink for Writer<'_, W> {
    async fn chunk(&mut self, chunk: VerifiedChunk<'_>) -> Result<(), Error> {
        self.output.write_all(chunk.bytes()).await?;
        Ok(())
    }
    async fn finish(&mut self) -> Result<(), Error> {
        self.output.flush().await?;
        Ok(())
    }
}

impl Buffers {
    /// Download every real D/I block, authenticate its root-bound tree and stream
    /// plaintext to an async writer. An optional local cache is read first and
    /// populated only after full block authentication. Corrupt cache is refused.
    ///
    /// Dropping this whole future cancels the transfer and closes its dedicated
    /// MQ; the writer keeps any authenticated prefix. Each `write_all` retains
    /// its cursor across ordinary awaits. Only a full authenticated tree plus a
    /// successful writer flush returns ReadFile; flush is not a durability claim.
    pub async fn download(
        &mut self,
        source: EndpointSource,
        content: Content,
        output: &mut (impl AsyncWrite + Unpin),
        cache: Option<&mut Repository>,
        options: DownloadOptions,
        control: impl FnMut(Progress) -> Control,
    ) -> Result<ReadFile, Error> {
        self.prepare(content, options.limits)?;
        Download::new(
            source,
            content,
            cache,
            options,
            &mut self.keys,
            &mut self.plain,
            &mut self.encoded,
        )?
        .run(&mut Writer { output }, control)
        .await
    }
}
