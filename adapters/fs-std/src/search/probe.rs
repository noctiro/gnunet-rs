//! Caller-driven native availability probes scoped to an original search result.
//!
//! A detached ticket owns its real endpoint and can run while the caller drives
//! search queries. Its private completion binds the actual native run to exactly
//! one result and attempt. Callers cannot substitute an older range receipt.

use super::{Error, ResultId, Session, availability};
use crate::{Buffers, Control, Progress, ipc, network};
use availability::{Attempt, Book, Summary, Target};
use gnunet_fs::Uri;
use gnunet_types::{AbsoluteTime, Error as ProtocolError};
use std::{fmt, mem::size_of, sync::Arc};

/// Bounds for an explicit probe. Search anonymity, loopback policy and signed
/// LOC placement are inherited from the original result and cannot be replaced.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// Fresh absolute deadline in the search source's original clock domain.
    pub deadline: AbsoluteTime,
    /// Lifetime observation limits, installed when this result is first probed.
    pub observations: availability::Limits,
    /// Largest advertised file size admitted, independently of path work.
    pub max_file_bytes: u64,
    /// Maximum authenticated blocks on the selected path, including its root.
    pub max_path_blocks: u64,
    /// Maximum exact ciphertext bytes across the selected path.
    pub max_encoded_bytes: u128,
    /// Bound on sequential searches before rotating the native connection.
    pub queries_per_connection: u32,
    /// Maximum bytes handled in one native read/write poll.
    pub io_slice_bytes: usize,
}
impl Options {
    /// Use ordinary transfer bounds and a bounded eight-trial observation book.
    #[must_use]
    pub fn new(deadline: AbsoluteTime) -> Self {
        let native = network::probe::Options::new(deadline);
        Self {
            deadline,
            observations: availability::Limits::default(),
            max_file_bytes: native.max_file_bytes,
            max_path_blocks: native.max_path_blocks,
            max_encoded_bytes: native.max_encoded_bytes,
            queries_per_connection: native.transfer.queries_per_connection,
            io_slice_bytes: native.transfer.io_slice_bytes,
        }
    }
}

/// One detached, single-use probe admission. No native request has been sent
/// until `run` is polled. Dropping it requires explicit local `forget_probe`
/// before a new attempt; dropping a running future also drops its native owner.
pub struct Probe {
    result: ResultId,
    attempt: Attempt,
    source: ipc::EndpointSource,
    options: network::probe::Options,
}
impl Probe {
    pub(crate) fn source(&self) -> &ipc::EndpointSource {
        &self.source
    }
    pub(crate) fn content(&self) -> gnunet_fs::Content {
        self.attempt.content()
    }
    pub(crate) fn leaf(&self) -> u64 {
        self.attempt.leaf()
    }
    pub(crate) fn native_options(&self) -> network::probe::Options {
        self.options
    }
    pub(crate) async fn run_recorded(
        self,
        buffers: &mut Buffers,
        control: impl FnMut(Progress) -> Control,
    ) -> (Completion, Vec<Vec<u8>>) {
        let recorded = buffers
            .probe_recorded(
                self.source,
                self.attempt.content(),
                self.attempt.leaf(),
                self.options,
                control,
            )
            .await;
        let (observation, frames) = recorded.into_parts();
        (
            Completion {
                result: self.result,
                attempt: self.attempt,
                observation,
            },
            frames,
        )
    }
    /// Original result identity, retaining its private session owner stamp.
    #[must_use]
    pub const fn result(&self) -> ResultId {
        self.result
    }
    /// Perform this ticket's actual native run. The private completion cannot be
    /// constructed from a boolean, a cached block or an unrelated old receipt.
    pub async fn run(
        self,
        buffers: &mut Buffers,
        control: impl FnMut(Progress) -> Control,
    ) -> Completion {
        let observation = buffers
            .probe(
                self.source,
                self.attempt.content(),
                self.attempt.leaf(),
                self.options,
                control,
            )
            .await;
        Completion {
            result: self.result,
            attempt: self.attempt,
            observation,
        }
    }
}

/// Actual completed native run, awaiting its original result's accounting.
/// Its fields are private and the wrapper is neither Clone nor constructible.
#[derive(Debug)]
pub struct Completion {
    result: ResultId,
    attempt: Attempt,
    observation: Result<network::probe::Observed, network::probe::Failure>,
}
impl Completion {
    /// Original result; its diagnostic index alone cannot select another owner.
    #[must_use]
    pub const fn result(&self) -> ResultId {
        self.result
    }
    /// Borrow the complete native proof or original failure before settlement.
    #[must_use]
    pub const fn observation(&self) -> &Result<network::probe::Observed, network::probe::Failure> {
        &self.observation
    }
}

/// Settled observation retaining the actual proof, raw response and typed cause.
#[derive(Debug)]
pub struct Report {
    /// Original selected result, including its session identity.
    pub result: ResultId,
    /// Updated observations for this result/revision only.
    pub summary: Summary,
    /// Original actual native outcome; no evidence is discarded by accounting.
    pub observation: Result<network::probe::Observed, network::probe::Failure>,
}

/// Refused accounting with the original ticket/completion still owned by caller.
/// A foreign session refusal never consumes another session's native evidence.
pub struct Refused<T> {
    /// Actual scope, generation, clock or accounting refusal.
    pub cause: ProtocolError,
    /// Original value, recoverable for its correct owner or explicit retirement.
    pub original: Box<T>,
}
impl<T> fmt::Debug for Refused<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Refused")
            .field("cause", &self.cause)
            .finish_non_exhaustive()
    }
}
impl<T> fmt::Display for Refused<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.cause.fmt(f)
    }
}
impl<T> std::error::Error for Refused<T> {}

impl<F, const KNOWN: usize> Session<'_, F, KNOWN>
where
    F: FnMut() -> Result<ipc::EndpointSource, ipc::Error>,
{
    /// Current observations for an original result, or None for an unprobed or
    /// foreign result. Books are allocated only for explicitly probed results.
    #[must_use]
    pub fn availability_summary(&self, result: ResultId) -> Option<Summary> {
        let index = self.result(result)?.probe_book?;
        self.probe_books.get(index).map(Book::summary)
    }

    /// Admit one explicit canonical leaf. The caller may use
    /// `network::probe::sample_leaf` for uniform sampling including a short tail.
    /// Empty-file leaf0 authenticates its actual empty root. Mandatory partial
    /// hits and unresolved KSK/SKS targets cannot be probed. One run per result
    /// may be in flight; different results may be driven concurrently by caller.
    pub fn begin_probe(
        &mut self,
        result: ResultId,
        leaf: u64,
        options: Options,
    ) -> Result<Probe, Error> {
        if self.closed {
            return Err(ProtocolError::Closed.into());
        }
        let record = self.result(result).ok_or(ProtocolError::Stale)?;
        if !record.visible() {
            return Err(ProtocolError::NotReady.into());
        }
        let (content, mut transfer) = match record.uri(self.options.block.uri)? {
            Uri::Content(content) => (content, network::DownloadOptions::new(options.deadline)),
            Uri::Location(location) => (
                location.content(),
                network::DownloadOptions::location(location, options.deadline),
            ),
            _ => return Err(ProtocolError::Unsupported.into()),
        };
        transfer.anonymity = self.options.anonymity;
        transfer.local_only = self.options.local_only;
        transfer.queries_per_connection = options.queries_per_connection;
        transfer.io_slice_bytes = options.io_slice_bytes;
        let existing = record.probe_book;
        if existing.is_none() {
            self.check_room(size_of::<Book>())?;
            super::reserve(&mut self.probe_books, 1)?;
        }
        let source = (self.source)()?;
        let clock = source.clock();
        if self
            .clock
            .as_ref()
            .is_none_or(|original| !Arc::ptr_eq(original, &clock))
        {
            return Err(ProtocolError::InvalidInput.into());
        }
        let now = clock.sample()?.now;
        if self.last_now.is_some_and(|previous| now < previous) {
            return Err(ProtocolError::TimeUncertain.into());
        }
        let attempt = if let Some(index) = existing {
            self.probe_books[index].begin(leaf, transfer, now)?
        } else {
            let mut book = Book::new(Target::new(content, transfer), options.observations)?;
            let attempt = book.begin(leaf, transfer, now)?;
            let index = self.probe_books.len();
            self.probe_books.push(book);
            self.results[result.index()].probe_book = Some(index);
            self.retained += size_of::<Book>();
            attempt
        };
        self.last_now = Some(now);
        Ok(Probe {
            result,
            attempt,
            source,
            options: network::probe::Options {
                transfer,
                max_file_bytes: options.max_file_bytes,
                max_path_blocks: options.max_path_blocks,
                max_encoded_bytes: options.max_encoded_bytes,
            },
        })
    }

    /// Consume the private actual run into only its original result's book.
    /// Foreign/stale refusals return the intact completion. Search cancellation
    /// does not discard an already completed detached observation.
    pub fn finish_probe(&mut self, completed: Completion) -> Result<Report, Refused<Completion>> {
        let outcome =
            self.book_mut(completed.result)
                .and_then(|book| match &completed.observation {
                    Ok(observed) => book.settle_success(&completed.attempt, observed),
                    Err(failure) => book.settle_failure(&completed.attempt, failure),
                });
        match outcome {
            Ok(summary) => {
                let checked = match &completed.observation {
                    Ok(observed) => Some(observed.finished()),
                    Err(failure) => failure.last_checked(),
                };
                // Detached runs can settle out of order. Preserve the greatest
                // actual sample across all result books so a new result cannot
                // accept a rollback already observed by another completed run.
                if let Some(now) = checked {
                    self.last_now = Some(self.last_now.map_or(now, |previous| previous.max(now)));
                }
                Ok(Report {
                    result: completed.result,
                    summary,
                    observation: completed.observation,
                })
            }
            Err(cause) => Err(Refused {
                cause,
                original: Box::new(completed),
            }),
        }
    }

    /// Consume an admitted ticket before native execution and cancel its local
    /// accounting. No service socket or network cancellation message is needed.
    pub fn cancel_probe(&mut self, ticket: Probe) -> Result<Summary, Refused<Probe>> {
        match self
            .book_mut(ticket.result)
            .and_then(|book| book.cancel(&ticket.attempt))
        {
            Ok(summary) => Ok(summary),
            Err(cause) => Err(Refused {
                cause,
                original: Box::new(ticket),
            }),
        }
    }

    /// Forget an outstanding accounting slot after dropping a ticket/future.
    /// This operation invalidates old completions and counts caller cancellation.
    /// It does not close a separately owned live probe: caller must drop or stop
    /// that future. No trial, native duration or socket-retirement fact is minted.
    pub fn forget_probe(&mut self, result: ResultId) -> Result<Summary, ProtocolError> {
        self.book_mut(result)?.abandon()
    }

    fn book_mut(&mut self, result: ResultId) -> Result<&mut Book, ProtocolError> {
        let index = self
            .result(result)
            .ok_or(ProtocolError::Stale)?
            .probe_book
            .ok_or(ProtocolError::NotReady)?;
        self.probe_books.get_mut(index).ok_or(ProtocolError::Stale)
    }
}
