//! Bind streaming directory syntax to actual CHK-authenticated source ranges.
use super::{Entry, Error, Event, Failure, Limits, Parser, Policy, Progress, Segment, Status};
use crate::{Content, content::VerifiedChunk, metadata};

/// A real directory entry reached through a strict, contiguous parse of
/// authenticated bytes from its parent CHK. Prefix membership does not certify
/// later records, child contents, recursive completion or a durable output.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedEntry<'a> {
    source: &'a Content,
    entry: Entry<'a>,
}
impl<'a> VerifiedEntry<'a> {
    /// Exact parent file whose authenticated bytes contain this record.
    #[must_use]
    pub const fn source(self) -> Content {
        *self.source
    }
    /// Validated entry view, retaining its parent range and metadata hints.
    #[must_use]
    pub const fn entry(self) -> Entry<'a> {
        self.entry
    }
}

/// Complete strict directory syntax over authenticated bytes of one CHK root.
/// This receipt carries no child-transfer or filesystem completion claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedDirectory {
    source: Content,
    entries: usize,
}
impl VerifiedDirectory {
    /// Complete parent artifact whose source and directory syntax were checked.
    #[must_use]
    pub const fn content(self) -> Content {
        self.source
    }
    /// Actual entry events in the complete strict directory parse.
    #[must_use]
    pub const fn entries(self) -> usize {
        self.entries
    }
}

/// Source binding failures are distinct from an actual directory syntax error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceError {
    /// The authenticated chunk belongs to another CHK root.
    Source,
    /// The requested local position is outside the authenticated chunk.
    Range,
    /// The ordinary parser refused coordinates, syntax or caller resources.
    Parse(Failure),
}
impl core::fmt::Display for SourceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "directory source {self:?}")
    }
}
impl core::error::Error for SourceError {}

/// Lending parser progress whose private origin can mint a VerifiedEntry.
pub struct SourceProgress<'a> {
    /// Bytes accepted from this call's authenticated chunk suffix.
    pub consumed: usize,
    source: &'a Content,
    status: Status<'a>,
}
impl<'a> SourceProgress<'a> {
    /// Ordinary event, storage request or terminal status for the owner loop.
    #[must_use]
    pub const fn status(&self) -> &Status<'a> {
        &self.status
    }
    /// Source-bound entry capability, available only for an actual entry event.
    #[must_use]
    pub fn entry(&self) -> Option<VerifiedEntry<'a>> {
        match self.status {
            Status::Event(Event::Entry(entry)) => Some(VerifiedEntry {
                source: self.source,
                entry,
            }),
            _ => None,
        }
    }
}

/// Strict whole-source directory parser over sealed FileReader chunks. It
/// reuses one record arena and one decompression buffer, even across many data
/// blocks; it never buffers or re-encodes the complete source directory.
pub struct SourceParser<'a> {
    source: Content,
    parser: Parser<'a>,
    complete: bool,
}
impl<'a> SourceParser<'a> {
    /// Anchor a strict parse at byte zero of the expected directory CHK.
    pub fn new(source: Content, carry: &'a mut [u8], limits: Limits) -> Result<Self, Error> {
        if source.size > limits.max_extent {
            return Err(Error::Limit);
        }
        Ok(Self {
            source,
            parser: Parser::new(carry, limits, Policy::default()),
            complete: false,
        })
    }
    /// Exact next whole-file byte expected, including incomplete records.
    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.parser.offset()
    }
    /// A whole-directory receipt only after the actual parser reached Complete.
    #[must_use]
    pub fn completion(&self) -> Option<VerifiedDirectory> {
        self.complete.then_some(VerifiedDirectory {
            source: self.source,
            entries: self.parser.summary().entries,
        })
    }
    /// Grow the reusable record arena after a real NeedRecord result.
    pub fn replace_buffer(&mut self, buffer: &'a mut [u8]) -> Result<&'a mut [u8], Error> {
        self.parser.replace_buffer(buffer)
    }
    /// Feed the unconsumed suffix of an authenticated chunk. Repeat with the
    /// updated local offset after an event or capacity request. Chunk identity
    /// and actual parser coordinates prevent cross-file, skipped and replayed
    /// plaintext from acquiring a parent-entry capability.
    pub fn feed<'p>(
        &'p mut self,
        chunk: &VerifiedChunk<'_>,
        local_offset: usize,
        plain: &'p mut [u8],
        inflater: &mut impl metadata::Inflater,
    ) -> Result<SourceProgress<'p>, SourceError> {
        if chunk.content() != self.source {
            return Err(SourceError::Source);
        }
        let bytes = chunk
            .bytes()
            .get(local_offset..)
            .ok_or(SourceError::Range)?;
        let base = chunk
            .range()
            .start
            .checked_add(local_offset as u64)
            .ok_or(SourceError::Range)?;
        let Progress { consumed, status } = self
            .parser
            .feed(
                Segment {
                    base,
                    bytes,
                    final_extent: Some(self.source.size),
                },
                plain,
                inflater,
            )
            .map_err(SourceError::Parse)?;
        self.complete |= matches!(status, Status::Complete(_));
        Ok(SourceProgress {
            consumed,
            source: &self.source,
            status,
        })
    }
}
