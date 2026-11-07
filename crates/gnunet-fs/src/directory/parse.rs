use super::{Error, Limits, MAGIC, next_boundary, word};
use crate::{Uri, metadata};
use core::ops::Range;

/// One contiguous input slice with unambiguous global coordinates.
#[derive(Clone, Copy, Debug)]
pub struct Segment<'a> {
    /// Absolute offset of `bytes[0]`. Must equal Parser::offset on each call.
    pub base: u64,
    /// Available bytes; only Progress::consumed bytes were accepted.
    pub bytes: &'a [u8],
    /// Known whole-directory final extent, retained across calls once supplied.
    pub final_extent: Option<u64>,
}
/// Explicit strict or reference-style recovery policy.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    /// Metadata strict body validation or explicit valid-prefix recovery.
    pub metadata: metadata::Mode,
    /// Recover after invalid URI by skipping to the next block boundary.
    pub recover_uri: bool,
    /// Require all padding bytes to be zero; ordinary C-compatible reading does not.
    pub canonical_padding: bool,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            metadata: metadata::Mode::Strict,
            recover_uri: false,
            canonical_padding: false,
        }
    }
}
/// The exact field awaiting bytes or storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    /// Eight-byte magic and root metadata length.
    Header,
    /// Root metadata artifact.
    DirectoryMetadata,
    /// NUL-terminated entry URI.
    Uri,
    /// Four-byte entry metadata length.
    Length,
    /// Entry metadata artifact.
    EntryMetadata,
    /// Remainder of padding/recovery gap.
    Padding,
    /// Known final extent reached.
    End,
}
/// A validated URI and metadata body, borrowing caller carry/plaintext storage.
#[derive(Clone, Copy, Debug)]
pub struct Entry<'a> {
    /// Absolute range including URI, NUL, length and metadata.
    pub range: RangeRef,
    /// Exact URI representation without terminating NUL.
    pub raw_uri: &'a [u8],
    /// Exact raw coded metadata bytes.
    pub raw_metadata: &'a [u8],
    /// Complete metadata or explicitly identified recovered prefix.
    pub metadata: metadata::Metadata<'a>,
    /// Entry boundary followed from header/preceding records, or caller asserted
    /// from_boundary. False for independently scanned block candidates.
    pub boundary_tracked: bool,
    uri_limits: crate::Limits,
}
impl<'a> Entry<'a> {
    /// Obtain the URI value by re-parsing its immutable validated representation.
    /// Keeping large LOC values out of every event bounds noalloc event size.
    /// This explicit accessor repeats signature work under the retained limits.
    pub fn uri(self) -> Result<Uri<'a>, Error> {
        Uri::parse(self.raw_uri, self.uri_limits).map_err(Error::Uri)
    }
}
/// Copyable absolute range, avoiding ownership of a mutable cursor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RangeRef {
    /// Inclusive absolute start.
    pub start: u64,
    /// Exclusive absolute end.
    pub end: u64,
}
/// One lending parser event; no references survive the next mutable parser call.
#[derive(Clone, Copy, Debug)]
pub enum Event<'a> {
    /// Present root metadata; no authenticated MIME/type claim is implied.
    Directory {
        /// Absolute metadata range excluding the outer12-byte header.
        range: RangeRef,
        /// Original raw coded metadata.
        raw: &'a [u8],
        /// Valid complete body or explicitly recovered prefix.
        metadata: metadata::Metadata<'a>,
    },
    /// A complete framed entry; recovered metadata remains visible on the entry.
    Entry(Entry<'a>),
    /// Observed padding or explicit invalid-URI recovery gap.
    Padding {
        /// Entire observed skip, including its initial zero or invalid URI.
        range: RangeRef,
        /// True when invalid URI bytes caused recovery rather than a zero marker.
        invalid_uri: bool,
        /// Known final EOF ended the skip before the next block boundary.
        terminal: bool,
    },
}
/// Whole-stream accounting, independent of authentication or recursive output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Summary {
    /// Absolute consumed end offset.
    pub end: u64,
    /// Emitted entry count.
    pub entries: usize,
    /// Whether the root header and present metadata were actually consumed.
    pub root_seen: bool,
    /// Whether a missing prefix or recovered URI/metadata prevents strict completeness.
    pub recovered: bool,
    /// Copied/skipped input, URI verification and declared metadata body work bytes.
    pub work: u64,
}
/// Progress result, with explicit nonterminal capacity and final completeness.
#[derive(Debug)]
pub enum Status<'a> {
    /// One lending event; feed the remaining bytes again afterwards.
    Event(Event<'a>),
    /// No known final EOF; more contiguous bytes are needed for this stage.
    NeedMore {
        /// Current stage.
        stage: Stage,
        /// Minimum additional bytes to complete the current known field.
        minimum: usize,
    },
    /// Grow the parser record arena using replace_buffer, then retry.
    NeedRecord {
        /// Total required carry capacity for the current known field.
        required: usize,
    },
    /// Supply a larger decompression buffer and retry without input advancement.
    NeedPlain {
        /// Declared metadata body bytes.
        required: usize,
    },
    /// Strict syntax consumed the known whole extent from its root header.
    Complete(Summary),
    /// Known final extent reached with missing prefix or explicit recovery.
    Partial(Summary),
}
/// Input consumption is always explicit, including when an event used no new input.
#[derive(Debug)]
pub struct Progress<'a> {
    /// Bytes consumed from this call's Segment.
    pub consumed: usize,
    /// Event, nonterminal refusal or exact final state.
    pub status: Status<'a>,
}
/// Terminal parser failure. Previously emitted records remain accounted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Failure {
    /// Bytes consumed from the failing call's segment.
    pub consumed: usize,
    /// Absolute offset at which parsing stopped.
    pub at: u64,
    /// Exact field being parsed.
    pub stage: Stage,
    /// Typed cause.
    pub error: Error,
}
impl core::fmt::Display for Failure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "directory at {} {:?}: {}",
            self.at, self.stage, self.error
        )
    }
}
impl core::error::Error for Failure {}
#[derive(Clone, Copy)]
enum Phase {
    Header,
    Root,
    RootReady,
    Uri,
    Length,
    Body,
    EntryReady,
    Padding { start: u64, end: u64, invalid: bool },
    Failed,
}
/// Bounded contiguous whole/incremental parser. The caller carry arena retains
/// incomplete records; successful event references lend from it and plain scratch.
/// This parser does no I/O and creates no authenticated source or file tokens.
pub struct Parser<'a> {
    carry: &'a mut [u8],
    used: usize,
    need: usize,
    uri_len: usize,
    cursor: u64,
    record_start: u64,
    extent: Option<u64>,
    phase: Phase,
    limits: Limits,
    policy: Policy,
    entries: usize,
    root_seen: bool,
    recovered: bool,
    tracked: bool,
    work: u64,
}
impl<'a> Parser<'a> {
    /// Start from the directory magic at absolute offset0.
    pub fn new(carry: &'a mut [u8], limits: Limits, policy: Policy) -> Self {
        Self {
            carry,
            used: 0,
            need: 12,
            uri_len: 0,
            cursor: 0,
            record_start: 0,
            extent: None,
            phase: Phase::Header,
            limits,
            policy,
            entries: 0,
            root_seen: false,
            recovered: false,
            tracked: true,
            work: 0,
        }
    }
    /// Start at an explicitly caller-asserted entry boundary. This omits root
    /// coverage and always finishes Partial, even if every later entry is valid.
    pub fn from_boundary(
        carry: &'a mut [u8],
        base: u64,
        limits: Limits,
        policy: Policy,
    ) -> Result<Self, Error> {
        if base > limits.max_extent {
            return Err(Error::Limit);
        }
        let mut parser = Self::new(carry, limits, policy);
        parser.cursor = base;
        parser.record_start = base;
        parser.phase = Phase::Uri;
        parser.need = 0;
        parser.recovered = true;
        Ok(parser)
    }
    /// Independently scan a block at an absolute alignment boundary. Entries
    /// remain unproven candidates; arbitrary record continuations may mimic URIs.
    pub fn from_block(
        carry: &'a mut [u8],
        base: u64,
        limits: Limits,
        policy: Policy,
    ) -> Result<Self, Error> {
        if !base.is_multiple_of(super::BLOCK_BYTES) {
            return Err(Error::Input);
        }
        let mut parser = Self::from_boundary(carry, base, limits, policy)?;
        parser.tracked = false;
        Ok(parser)
    }
    /// Exact next absolute byte expected, independent of the local slice index.
    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.cursor
    }
    /// Current completed-event and source coverage accounting.
    #[must_use]
    pub const fn summary(&self) -> Summary {
        Summary {
            end: self.cursor,
            entries: self.entries,
            root_seen: self.root_seen,
            recovered: self.recovered,
            work: self.work,
        }
    }
    /// Replace insufficient carry without losing an unfinished record. Refusal
    /// preserves both buffers. Returns the former caller buffer on success.
    pub fn replace_buffer(&mut self, buffer: &'a mut [u8]) -> Result<&'a mut [u8], Error> {
        if buffer.len() < self.used {
            return Err(Error::Capacity);
        }
        buffer[..self.used].copy_from_slice(&self.carry[..self.used]);
        Ok(core::mem::replace(&mut self.carry, buffer))
    }
    fn stage(&self) -> Stage {
        match self.phase {
            Phase::Header => Stage::Header,
            Phase::Root | Phase::RootReady => Stage::DirectoryMetadata,
            Phase::Uri => Stage::Uri,
            Phase::Length => Stage::Length,
            Phase::Body | Phase::EntryReady => Stage::EntryMetadata,
            Phase::Padding { .. } => Stage::Padding,
            Phase::Failed => Stage::End,
        }
    }
    fn charge(&mut self, bytes: u64) -> Result<(), Error> {
        let work = self.work.checked_add(bytes).ok_or(Error::Overflow)?;
        if work > self.limits.max_work {
            return Err(Error::Limit);
        }
        self.work = work;
        Ok(())
    }
    fn advance(&mut self, bytes: usize) -> Result<(), Error> {
        let bytes = u64::try_from(bytes).map_err(|_| Error::Overflow)?;
        let end = self.cursor.checked_add(bytes).ok_or(Error::Overflow)?;
        if end > self.limits.max_extent {
            return Err(Error::Limit);
        }
        self.charge(bytes)?;
        self.cursor = end;
        Ok(())
    }
    /// Consume contiguous input until one event, capacity request or input end.
    /// Fatal syntax/resource failures require a new Parser. Capacity requests are
    /// retryable: retained bytes/event count stay intact and codec is not called.
    pub fn feed<'p>(
        &'p mut self,
        segment: Segment<'_>,
        plain: &'p mut [u8],
        inflater: &mut impl metadata::Inflater,
    ) -> Result<Progress<'p>, Failure> {
        let mut consumed = 0;
        macro_rules! fail {
            ($error:expr) => {{
                let stage = self.stage();
                self.phase = Phase::Failed;
                return Err(Failure {
                    consumed,
                    at: self.cursor,
                    stage,
                    error: $error,
                });
            }};
        }
        macro_rules! attempt {
            ($value:expr) => {
                match $value {
                    Ok(value) => value,
                    Err(error) => fail!(error),
                }
            };
        }
        if matches!(self.phase, Phase::Failed) {
            fail!(Error::Input);
        }
        if segment.base != self.cursor {
            fail!(Error::Input);
        }
        let end = attempt!(
            segment
                .base
                .checked_add(segment.bytes.len() as u64)
                .ok_or(Error::Overflow)
        );
        if end > self.limits.max_extent {
            fail!(Error::Limit);
        }
        if let Some(extent) = segment.final_extent {
            if extent > self.limits.max_extent {
                fail!(Error::Limit);
            }
            if self.extent.is_some_and(|old| old != extent) {
                fail!(Error::Input);
            }
            self.extent = Some(extent);
        }
        if self.extent.is_some_and(|extent| end > extent) {
            fail!(Error::Input);
        }
        loop {
            if matches!(self.phase, Phase::RootReady | Phase::EntryReady) {
                break;
            }
            if let Phase::Padding {
                start,
                end,
                invalid,
            } = self.phase
            {
                let stop = self.extent.map_or(end, |extent| extent.min(end));
                let n = (stop - self.cursor).min((segment.bytes.len() - consumed) as u64) as usize;
                if self.policy.canonical_padding
                    && segment.bytes[consumed..consumed + n]
                        .iter()
                        .any(|byte| *byte != 0)
                {
                    fail!(Error::Input);
                }
                attempt!(self.advance(n));
                consumed += n;
                if self.cursor == stop {
                    self.phase = Phase::Uri;
                    self.record_start = self.cursor;
                    self.used = 0;
                    return Ok(Progress {
                        consumed,
                        status: Status::Event(Event::Padding {
                            range: RangeRef { start, end: stop },
                            invalid_uri: invalid,
                            terminal: stop < end,
                        }),
                    });
                }
            } else if matches!(self.phase, Phase::Uri) {
                if self.used == 0 && self.extent == Some(self.cursor) {
                    let summary = self.summary();
                    return Ok(Progress {
                        consumed,
                        status: if summary.root_seen && !summary.recovered {
                            Status::Complete(summary)
                        } else {
                            Status::Partial(summary)
                        },
                    });
                }
                if consumed < segment.bytes.len() {
                    let byte = segment.bytes[consumed];
                    if self.used == 0 && byte == 0 {
                        let start = self.cursor;
                        let end = attempt!(next_boundary(start));
                        attempt!(self.advance(1));
                        consumed += 1;
                        self.phase = Phase::Padding {
                            start,
                            end,
                            invalid: false,
                        };
                        continue;
                    }
                    if self.entries >= self.limits.max_entries {
                        fail!(Error::Limit);
                    }
                    if self.used >= self.limits.uri.max_input_bytes && byte != 0 {
                        fail!(Error::Limit);
                    }
                    let required = attempt!(self.used.checked_add(1).ok_or(Error::Overflow));
                    if required > self.limits.max_record_bytes {
                        fail!(Error::Limit);
                    }
                    if required > self.carry.len() {
                        return Ok(Progress {
                            consumed,
                            status: Status::NeedRecord { required },
                        });
                    }
                    attempt!(self.advance(1));
                    consumed += 1;
                    self.carry[self.used] = byte;
                    self.used += 1;
                    if byte == 0 {
                        self.uri_len = self.used - 1;
                        attempt!(self.charge(self.uri_len as u64));
                        match Uri::parse(&self.carry[..self.uri_len], self.limits.uri) {
                            Ok(Uri::Keywords(_)) => fail!(Error::Keyword),
                            Ok(_) => {
                                self.need =
                                    attempt!(self.used.checked_add(4).ok_or(Error::Overflow));
                                self.phase = Phase::Length;
                            }
                            Err(error) if self.policy.recover_uri => {
                                let end = attempt!(next_boundary(self.cursor - 1));
                                self.phase = Phase::Padding {
                                    start: self.record_start,
                                    end,
                                    invalid: true,
                                };
                                self.recovered = true;
                                self.tracked = false;
                                let _ = error;
                            }
                            Err(error) => fail!(Error::Uri(error)),
                        }
                    }
                    continue;
                }
            } else {
                if self.need > self.limits.max_record_bytes {
                    fail!(Error::Limit);
                }
                if self.need > self.carry.len() {
                    return Ok(Progress {
                        consumed,
                        status: Status::NeedRecord {
                            required: self.need,
                        },
                    });
                }
                let n = (self.need - self.used).min(segment.bytes.len() - consumed);
                attempt!(self.advance(n));
                self.carry[self.used..self.used + n]
                    .copy_from_slice(&segment.bytes[consumed..consumed + n]);
                self.used += n;
                consumed += n;
                if self.used == self.need {
                    match self.phase {
                        Phase::Header => {
                            if &self.carry[..8] != MAGIC {
                                fail!(Error::Magic);
                            }
                            let length = word(self.carry, 8) as usize;
                            if length > self.limits.metadata.max_coded_bytes {
                                fail!(Error::Metadata(metadata::Error::Limit));
                            }
                            self.need =
                                attempt!(12_usize.checked_add(length).ok_or(Error::Overflow));
                            self.phase = Phase::Root;
                        }
                        Phase::Length => {
                            let length = word(self.carry, self.uri_len + 1) as usize;
                            if length > self.limits.metadata.max_coded_bytes {
                                fail!(Error::Metadata(metadata::Error::Limit));
                            }
                            self.need =
                                attempt!(self.used.checked_add(length).ok_or(Error::Overflow));
                            self.phase = Phase::Body;
                        }
                        Phase::Root => self.phase = Phase::RootReady,
                        Phase::Body => self.phase = Phase::EntryReady,
                        _ => fail!(Error::Input),
                    }
                    continue;
                }
            }
            if consumed == segment.bytes.len() {
                if self.extent == Some(self.cursor) {
                    fail!(Error::Truncated);
                }
                let minimum = if matches!(self.phase, Phase::Uri) {
                    1
                } else if let Phase::Padding { end, .. } = self.phase {
                    usize::try_from(end - self.cursor).unwrap_or(usize::MAX)
                } else {
                    self.need - self.used
                };
                return Ok(Progress {
                    consumed,
                    status: Status::NeedMore {
                        stage: self.stage(),
                        minimum,
                    },
                });
            }
        }
        let root = matches!(self.phase, Phase::RootReady);
        let md_start = if root { 12 } else { self.uri_len + 5 };
        let raw = &self.carry[md_start..self.used];
        let declared = if raw.len() >= 12 {
            word(raw, 8) as usize
        } else {
            0
        };
        if raw.len() >= 12
            && word(raw, 0) == 2 | metadata::COMPRESSED
            && declared <= self.limits.metadata.max_plain_bytes
            && plain.len() < declared
        {
            return Ok(Progress {
                consumed,
                status: Status::NeedPlain { required: declared },
            });
        }
        attempt!(self.charge(declared as u64));
        let raw = &self.carry[md_start..self.used];
        let decoded = metadata::decode(
            raw,
            plain,
            inflater,
            self.limits.metadata,
            self.policy.metadata,
        );
        let md = match decoded {
            Ok(metadata::Decoded::Present(md)) => md,
            Ok(metadata::Decoded::NullMarker) => fail!(Error::NullMetadata),
            Err(error) => fail!(Error::Metadata(error)),
        };
        self.recovered |= !md.is_complete();
        self.phase = Phase::Uri;
        self.used = 0;
        let start = self.record_start;
        self.record_start = self.cursor;
        let event = if root {
            self.root_seen = true;
            Event::Directory {
                range: RangeRef {
                    start: start + 12,
                    end: self.cursor,
                },
                raw,
                metadata: md,
            }
        } else {
            let raw_uri = &self.carry[..self.uri_len];
            self.entries += 1;
            Event::Entry(Entry {
                range: RangeRef {
                    start,
                    end: self.cursor,
                },
                raw_uri,
                raw_metadata: raw,
                metadata: md,
                boundary_tracked: self.tracked,
                uri_limits: self.limits.uri,
            })
        };
        Ok(Progress {
            consumed,
            status: Status::Event(event),
        })
    }
}

impl From<RangeRef> for Range<u64> {
    fn from(value: RangeRef) -> Self {
        value.start..value.end
    }
}
