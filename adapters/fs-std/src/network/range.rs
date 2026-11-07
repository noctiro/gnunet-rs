//! Selected native retrieval with root-authenticated plaintext delivery.
//!
//! Only intersecting data leaves and their index ancestors are fetched. Chunks
//! retain their absolute file ranges; the convenience writer concatenates the
//! selected bytes starting at its current cursor, without a sparse-file claim.
//! A completed selection authenticates neither the rest of the file nor output
//! durability. Every lookup, cache block and sink future shares the original
//! logical deadline and the caller's original native deadline.

use super::{DownloadOptions, Error, Lookup};
use crate::{BlockSource, Buffers, Control, Progress, Repository};
use gnunet_client_host::EndpointSource;
use gnunet_fs::{
    Content,
    content::{RangeReader, VerifiedChunk, VerifiedRange},
};
use gnunet_types::Error as ProtocolError;
use std::{future::Future, ops::Range, task::Poll};
use tokio::{
    io::{AsyncWrite, AsyncWriteExt},
    time::Instant,
};

/// Original transfer policy and an independent, caller-captured physical bound.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// Existing lookup, cache and whole-content admission policy. Limits retain
    /// their existing whole-file meaning even though only a selection is read.
    pub download: DownloadOptions,
    /// Original native hard deadline, captured before caller clock/setup work.
    /// It is never replaced when a block, cache hit or sink makes progress.
    pub native_deadline: Instant,
}

/// Lending plaintext destination. Each future retains the original chunk loan.
/// A sink may use `chunk.range()` for absolute-offset writes. Its success means
/// that it accepted the complete chunk; it does not prove durable storage.
pub trait RangeSink {
    /// Consume one authenticated selected chunk. Failure or cancellation may
    /// leave a partial destination write, identified by `Report::pending_delivery`.
    fn chunk<'chunk>(
        &'chunk mut self,
        chunk: VerifiedChunk<'chunk>,
    ) -> impl Future<Output = Result<(), Error>> + 'chunk;

    /// Complete the destination after every selected chunk was accepted.
    /// Cancellation may interrupt this future after all chunks were delivered.
    fn finish(&mut self) -> impl Future<Output = Result<(), Error>> + '_;
}

/// What this operation actually completed. Neither variant is a whole-file proof.
#[derive(Clone, Copy, Debug)]
pub enum Completion {
    /// All selected data and necessary ancestors were authenticated. The
    /// actual destination confirmation is identified separately by Destination.
    Verified(VerifiedRange),
    /// A valid empty selection in a nonempty file performed no source-clock, native-connection,
    /// cache or sink work. This contains no authentication or flush receipt.
    EmptySelection,
}

/// Actual destination fact, independently of selected tree authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Destination {
    /// The original sink accepted every chunk and completed its finish future.
    SinkCompleted,
    /// Selected authenticated bytes were compared with an existing held file.
    /// This records no new writes or sink-finish invocation.
    ExistingFileCompared,
    /// Empty selection performed no destination work or authentication.
    Untouched,
}

/// Successful selected authentication and explicitly identified destination work.
#[derive(Clone, Debug)]
pub struct ReadRange {
    /// Original CHK and logical file size.
    pub content: Content,
    /// Exact original absolute selection.
    pub selection: Range<u64>,
    /// Actual selected authentication, or explicitly no authentication for an
    /// empty selection in a nonempty file.
    pub completion: Completion,
    /// Original sink completion, existing-file comparison, or no destination work.
    pub destination: Destination,
    /// Actual authenticated blocks, ciphertext and selected plaintext bytes.
    /// Cached blocks are included only after the same reader authenticated them.
    pub authenticated: Progress,
    /// Selected bytes accepted by the identified destination. Existing-file
    /// comparison does not assert new writes.
    pub delivered_bytes: u64,
    /// Complete accepted chunks, including the empty file's real empty-root chunk.
    pub delivered_chunks: u64,
}

/// Original selection and actual progress retained after a failed transfer.
#[derive(Clone, Debug)]
pub struct Report {
    /// Original CHK and logical file size, independent of output progress.
    pub content: Content,
    /// Original absolute selection, including an invalid selection on refusal.
    pub selection: Range<u64>,
    /// Actual authenticated work; it is counted before attempting sink delivery.
    pub authenticated: Progress,
    /// Bytes in complete successful chunk futures, excluding a possibly partial
    /// failed/cancelled chunk. This is not a destination durability claim.
    pub delivered_bytes: u64,
    /// Chunk futures that completed successfully.
    pub delivered_chunks: u64,
    /// Original chunk whose sink future was attempted but did not succeed.
    /// It may already have written a prefix; dropping it does not mean zero I/O.
    pub pending_delivery: Option<Range<u64>>,
    /// Real reader completion, retained even if later sink completion failed.
    pub verified: Option<VerifiedRange>,
    /// Whether the original sink finish future was started. Its failure may
    /// leave uncertain flush state even when all chunks were fully delivered.
    pub finish_started: bool,
}

/// Original failure plus its bounded progress snapshot. Only a failed operation
/// allocates this report; no payload or per-block snapshot is retained here.
#[derive(Debug)]
pub struct Failure {
    /// Actual native, source, authentication, cache, sink or caller error.
    pub cause: Error,
    /// Actual selection, authentication and destination progress. Any constructed
    /// lookup has been physically closed before this failure is returned.
    pub report: Box<Report>,
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.cause.fmt(f)
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}
impl Report {
    fn new(content: Content, selection: Range<u64>) -> Self {
        Self {
            content,
            selection,
            authenticated: Progress::default(),
            delivered_bytes: 0,
            delivered_chunks: 0,
            pending_delivery: None,
            verified: None,
            finish_started: false,
        }
    }
    fn fail(self, cause: Error) -> Failure {
        Failure {
            cause,
            report: Box::new(self),
        }
    }
    fn complete(self, completion: Completion) -> ReadRange {
        ReadRange {
            content: self.content,
            selection: self.selection,
            completion,
            destination: match completion {
                Completion::Verified(_) => Destination::SinkCompleted,
                Completion::EmptySelection => Destination::Untouched,
            },
            authenticated: self.authenticated,
            delivered_bytes: self.delivered_bytes,
            delivered_chunks: self.delivered_chunks,
        }
    }
}

fn native_guard(hard: Instant) -> Result<(), Error> {
    if Instant::now() >= hard {
        Err(Error::Deadline { first_io: None })
    } else {
        Ok(())
    }
}

// Retain the same sink future and its actual partial cursor while checking the
// original lookup deadlines and caller control. No replacement sink is created.
async fn deliver<F: Future<Output = Result<(), Error>>>(
    lookup: &mut Lookup,
    future: F,
    progress: Progress,
    control: &mut impl FnMut(Progress) -> Control,
) -> Result<(), Error> {
    let mut delivery = std::pin::pin!(lookup.during(future));
    let mut observe = std::pin::pin!(async {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            if control(progress) == Control::Cancel {
                return Err(Error::Cancelled(progress));
            }
        }
    });
    std::future::poll_fn(|cx| match delivery.as_mut().poll(cx) {
        Poll::Ready(result) => Poll::Ready(result?),
        Poll::Pending => observe.as_mut().poll(cx),
    })
    .await
}

struct Writer<'output, W> {
    output: &'output mut W,
}
impl<W: AsyncWrite + Unpin> RangeSink for Writer<'_, W> {
    async fn chunk<'chunk>(&'chunk mut self, chunk: VerifiedChunk<'chunk>) -> Result<(), Error> {
        self.output
            .write_all(chunk.bytes())
            .await
            .map_err(Into::into)
    }
    async fn finish(&mut self) -> Result<(), Error> {
        self.output.flush().await.map_err(Into::into)
    }
}

impl Buffers {
    /// Retrieve only the selected tree and lend its authenticated plaintext with
    /// original absolute ranges. Reuses the existing native lookup and shared
    /// block/frontier buffers; it never reads a whole file and slices afterward.
    ///
    /// A nonempty file's empty selection does not invoke the source, cache or
    /// sink, and returns no proof. Empty content selected as `0..0` instead fetches
    /// and authenticates its real root and completes the sink normally. Reversed
    /// or out-of-file endpoints are refused without offset/length arithmetic.
    /// Whole-file resource limits and nonzero lookup settings are still checked.
    ///
    /// Cache bytes remain untrusted until this original range reader accepts
    /// them. Authentication is counted before sink delivery; a sink error can
    /// retain a partial chunk and a verified prefix. Only successful finish
    /// returns `ReadRange`. The exact lookup is closed on return or future drop;
    /// dropping a sink future cannot prove that its output was untouched.
    /// Synchronous cache or sink work cannot be forcibly interrupted; the same
    /// hard deadline is checked before subsequent native/sink polls.
    #[expect(
        clippy::too_many_arguments,
        reason = "Original content, selection, native policy, lending destination, cache and caller control have distinct ownership"
    )]
    pub async fn download_range_to(
        &mut self,
        source: EndpointSource,
        content: Content,
        selection: Range<u64>,
        sink: &mut impl RangeSink,
        cache: Option<&mut Repository>,
        options: Options,
        mut control: impl FnMut(Progress) -> Control,
    ) -> Result<ReadRange, Failure> {
        let mut report = Report::new(content, selection.clone());
        let preflight = (|| -> Result<(), Error> {
            native_guard(options.native_deadline)?;
            if selection.start > selection.end
                || selection.end > content.size
                || options.download.queries_per_connection == 0
                || options.download.io_slice_bytes == 0
            {
                return Err(ProtocolError::InvalidInput.into());
            }
            self.prepare(content, options.download.limits)?;
            native_guard(options.native_deadline)?;
            if control(report.authenticated) == Control::Cancel {
                return Err(Error::Cancelled(report.authenticated));
            }
            Ok(())
        })();
        if let Err(cause) = preflight {
            return Err(report.fail(cause));
        }
        if content.size != 0 && selection.is_empty() {
            return Ok(report.complete(Completion::EmptySelection));
        }
        let mut reader = match RangeReader::new(content, selection, &mut self.keys) {
            Ok(reader) => reader,
            Err(cause) => return Err(report.fail(cause.into())),
        };
        let mut lookup = match Lookup::bounded(source, options.download, options.native_deadline) {
            Ok(lookup) => lookup,
            Err(cause) => return Err(report.fail(cause)),
        };
        let mut cache = cache;
        let result = async {
            while let Some(request) = reader.next() {
                lookup.during(std::future::ready(())).await?;
                if control(report.authenticated) == Control::Cancel {
                    return Err(Error::Cancelled(report.authenticated));
                }
                let cached = if let Some(store) = cache.as_deref_mut() {
                    match store.read_block(request, &mut self.encoded) {
                        Ok(length) => Some(length),
                        Err(crate::Error::Io(error))
                            if error.kind() == std::io::ErrorKind::NotFound =>
                        {
                            None
                        }
                        Err(error) => return Err(error.into()),
                    }
                } else {
                    None
                };
                if cached.is_none() {
                    lookup
                        .fetch_controlled(request, report.authenticated, &mut control)
                        .await?;
                }
                lookup.during(std::future::ready(())).await?;
                if control(report.authenticated) == Control::Cancel {
                    return Err(Error::Cancelled(report.authenticated));
                }
                let bytes = match cached {
                    Some(length) => self.encoded.get(..length).ok_or(ProtocolError::Malformed)?,
                    None => lookup.block()?,
                };
                let length = bytes.len();
                let chunk = reader.open_next(bytes, &mut self.plain)?;
                // Retain authentication facts before a later cache or sink
                // failure. Cache storage cannot revoke this reader's receipt.
                report.authenticated.blocks += 1;
                report.authenticated.encoded_bytes += length as u128;
                report.verified = reader.completion();
                if let Some(chunk) = chunk.as_ref() {
                    report.authenticated.plaintext_bytes += chunk.bytes().len() as u64;
                }
                if cached.is_none() {
                    if Instant::now() >= options.native_deadline {
                        return Err(Error::Deadline {
                            first_io: lookup.first_io.take(),
                        });
                    }
                    if let Some(store) = cache.as_deref_mut() {
                        store.cache(request.key().query, bytes)?;
                    }
                    lookup.release();
                }
                if let Some(chunk) = chunk {
                    let length = chunk.bytes().len() as u64;
                    lookup.during(std::future::ready(())).await?;
                    if control(report.authenticated) == Control::Cancel {
                        return Err(Error::Cancelled(report.authenticated));
                    }
                    report.pending_delivery = Some(chunk.range());
                    deliver(
                        &mut lookup,
                        sink.chunk(chunk),
                        report.authenticated,
                        &mut control,
                    )
                    .await?;
                    report.pending_delivery = None;
                    report.delivered_bytes += length;
                    report.delivered_chunks += 1;
                }
            }
            let verified = reader.completion().ok_or(ProtocolError::NotReady)?;
            report.verified = Some(verified);
            lookup.during(std::future::ready(())).await?;
            if control(report.authenticated) == Control::Cancel {
                return Err(Error::Cancelled(report.authenticated));
            }
            report.finish_started = true;
            deliver(
                &mut lookup,
                sink.finish(),
                report.authenticated,
                &mut control,
            )
            .await?;
            Ok(verified)
        }
        .await;
        // This original owner also covers cache-only work and sink waits. Do
        // not leave a live lookup behind after a destination error or cancel.
        lookup.channel.close();
        match result {
            Ok(verified) => Ok(report.complete(Completion::Verified(verified))),
            Err(cause) => Err(report.fail(cause)),
        }
    }

    /// Concatenate the selected plaintext at this writer's current cursor and
    /// flush once. This makes no absolute-offset, sparse-file, truncate, durable
    /// commit or whole-file claim. Use `download_range_to` for offset-aware sinks.
    /// Actual partial writes survive errors; `Failure::report` identifies a
    /// possibly partial original chunk separately from complete delivered chunks.
    #[expect(
        clippy::too_many_arguments,
        reason = "Selection is independent of the original lookup, writer, cache and caller control"
    )]
    pub async fn download_range(
        &mut self,
        source: EndpointSource,
        content: Content,
        selection: Range<u64>,
        output: &mut (impl AsyncWrite + Unpin),
        cache: Option<&mut Repository>,
        options: Options,
        control: impl FnMut(Progress) -> Control,
    ) -> Result<ReadRange, Failure> {
        self.download_range_to(
            source,
            content,
            selection,
            &mut Writer { output },
            cache,
            options,
            control,
        )
        .await
    }
}
