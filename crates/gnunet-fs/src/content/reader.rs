//! Range and whole-file authenticated reads over one bounded tree traversal.
use super::{BlockKey, NodeRef, RangeTraversal};
use crate::Content;
use core::ops::Range;
use gnunet_types::Error;

/// A file range reached through authenticated parents from one exact CHK root.
/// Private fields prevent arbitrary plaintext or a public DataSlice from
/// asserting membership. Bytes borrow only the caller's reusable block buffer.
#[derive(Clone, Debug)]
pub struct VerifiedChunk<'a> {
    content: Content,
    range: Range<u64>,
    bytes: &'a [u8],
}
impl<'a> VerifiedChunk<'a> {
    /// Original complete file identifier anchoring the authenticated path.
    #[must_use]
    pub const fn content(&self) -> Content {
        self.content
    }
    /// Exact half-open file coordinates of these plaintext bytes.
    #[must_use]
    pub fn range(&self) -> Range<u64> {
        self.range.clone()
    }
    /// Authenticated plaintext, without any storage or filesystem claim.
    #[must_use]
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

/// Receipt that one exact selected range was authenticated from its CHK root.
/// It does not certify unselected leaves, current availability or durable storage.
/// A nonempty file never receives this proof for a zero-length selection; the
/// empty file's 0..0 proof still requires its real encrypted root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedRange {
    content: Content,
    start: u64,
    end: u64,
}
impl VerifiedRange {
    /// Original complete file identifier anchoring the selected range.
    #[must_use]
    pub const fn content(self) -> Content {
        self.content
    }
    /// Exact authenticated half-open byte selection.
    #[must_use]
    pub const fn range(self) -> Range<u64> {
        self.start..self.end
    }
}

/// Caller-driven authenticated range reader with bounded borrowed key storage.
/// Only intersecting data leaves and their real ancestors are requested. This
/// owns no I/O, allocator or plaintext buffer, and produces no VerifiedFile.
pub struct RangeReader<'a> {
    content: Content,
    range: Range<u64>,
    traversal: RangeTraversal<'a>,
    empty_pending: bool,
}
impl<'a> RangeReader<'a> {
    /// Select a nonempty range within a nonempty file, or 0..0 for an empty
    /// file. Nonempty selections require Layout::required_keys slots. Empty-file
    /// proof needs no key slots but does require authenticating its actual root.
    /// Invalid selection or insufficient storage changes no caller key slots.
    pub fn new(
        content: Content,
        range: Range<u64>,
        keys: &'a mut [BlockKey],
    ) -> Result<Self, Error> {
        if content.size != 0 && range.start == range.end {
            return Err(Error::InvalidInput);
        }
        let traversal = RangeTraversal::new(content, range.clone(), keys)?;
        Ok(Self {
            content,
            range,
            traversal,
            empty_pending: content.size == 0,
        })
    }
    /// Complete file identifier anchoring this original selection.
    #[must_use]
    pub const fn content(&self) -> Content {
        self.content
    }
    /// Original exact selection; completion is a separate proof.
    #[must_use]
    pub fn range(&self) -> Range<u64> {
        self.range.clone()
    }
    /// Exact pending lookup. No URI, geometry or selection alone authenticates it.
    #[must_use]
    pub fn next(&self) -> Option<NodeRef> {
        if self.empty_pending {
            Some(NodeRef::root(self.content))
        } else {
            self.traversal.next()
        }
    }
    /// Authenticate the exact pending node and advance its original range walk.
    /// Index blocks return None; data blocks lend only their selected plaintext.
    /// Framing, capacity or authentication refusal retains the same pending
    /// reference. No unselected leaf is authenticated or counted as processed.
    pub fn open_next<'b>(
        &mut self,
        ciphertext: &[u8],
        plaintext: &'b mut [u8],
    ) -> Result<Option<VerifiedChunk<'b>>, Error> {
        let request = self.next().ok_or(Error::Closed)?;
        let opened = request.open(ciphertext, plaintext)?;
        if self.empty_pending {
            let bytes = opened.data().ok_or(Error::InvalidInput)?;
            self.empty_pending = false;
            return Ok(Some(VerifiedChunk {
                content: self.content,
                range: 0..0,
                bytes,
            }));
        }
        Ok(self.traversal.accept(opened)?.map(|data| VerifiedChunk {
            content: self.content,
            range: data.range,
            bytes: data.bytes,
        }))
    }
    /// Present only after every selected data leaf and necessary ancestor,
    /// including an empty file's actual root, was authenticated.
    #[must_use]
    pub fn completion(&self) -> Option<VerifiedRange> {
        self.next().is_none().then_some(VerifiedRange {
            content: self.content,
            start: self.range.start,
            end: self.range.end,
        })
    }
}

/// Receipt that every block of the specified file was authenticated. It does
/// not assert that plaintext or encrypted blocks were durably retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedFile {
    content: Content,
}
impl VerifiedFile {
    /// Complete file identifier whose data and index blocks were checked.
    #[must_use]
    pub const fn content(self) -> Content {
        self.content
    }
}

/// Sequential whole-file reader over the same authenticated range owner.
/// Its constructor always selects the complete file; only this wrapper can
/// turn that owner's actual completion into a VerifiedFile.
pub struct FileReader<'a> {
    reader: RangeReader<'a>,
}
impl<'a> FileReader<'a> {
    /// Use Layout::required_keys slots and one reusable plaintext block buffer.
    /// An empty file still requires authenticating its actual encrypted root.
    pub fn new(content: Content, keys: &'a mut [BlockKey]) -> Result<Self, Error> {
        RangeReader::new(content, 0..content.size, keys).map(|reader| Self { reader })
    }
    /// Exact pending lookup; failures leave it available for a retry.
    #[must_use]
    pub fn next(&self) -> Option<NodeRef> {
        self.reader.next()
    }
    /// Authenticate the exact pending block and advance its original tree path.
    /// Index blocks return None; data blocks return a sealed source-bound view.
    /// No file-sized allocation, buffering or index re-encoding is performed.
    pub fn open_next<'b>(
        &mut self,
        ciphertext: &[u8],
        plaintext: &'b mut [u8],
    ) -> Result<Option<VerifiedChunk<'b>>, Error> {
        self.reader.open_next(ciphertext, plaintext)
    }
    /// Available only after all real data/index blocks, including an empty
    /// file's root, were authenticated against the original content identifier.
    #[must_use]
    pub fn completion(&self) -> Option<VerifiedFile> {
        self.reader.completion().map(|verified| VerifiedFile {
            content: verified.content(),
        })
    }
}
