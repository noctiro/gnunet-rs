//! Document-bound payloads for the external stream data in a PDF file.

use super::{Error, copy};
use gnunet_crypto::Hash512State;
use gnunet_native::filesystem::{EntryInfo, FileInfo, FileReader, file_info};
use std::{fs::File, io::ErrorKind};

pub(super) const MAX_NAME_BYTES: usize = 4096;
pub(super) const MAX_PAYLOAD_BYTES: usize = 1 << 20;
pub(super) const MAX_BINDINGS: usize = 64;

/// Exact decoded file-specification key. Local byte strings and Unicode file
/// names identify PDF strings, and URL keys identify PDF `/FS /URL` values.
/// Paths and URLs serve solely as keys for the supplied bytes.
#[derive(Clone, Copy)]
pub enum PdfExternalName<'a> {
    /// Bytes of a portable or platform-specific file specification string.
    File(&'a [u8]),
    /// Decoded text from the file specification's Unicode file name.
    UnicodeFile(&'a str),
    /// Exact bytes of the URL file specification.
    Url(&'a [u8]),
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum NameKind {
    File,
    UnicodeFile,
    Url,
}

impl<'a> PdfExternalName<'a> {
    fn parts(self) -> (NameKind, &'a [u8]) {
        match self {
            Self::File(bytes) => (NameKind::File, bytes),
            Self::UnicodeFile(text) => (NameKind::UnicodeFile, text.as_bytes()),
            Self::Url(bytes) => (NameKind::Url, bytes),
        }
    }
}

impl NameKind {
    pub(super) const fn code(self) -> u8 {
        match self {
            Self::File => 0,
            Self::UnicodeFile => 1,
            Self::Url => 2,
        }
    }

    pub(super) fn parse(code: u8) -> Option<Self> {
        Some(match code {
            0 => Self::File,
            1 => Self::UnicodeFile,
            2 => Self::Url,
            _ => return None,
        })
    }

    fn valid(self, bytes: &[u8]) -> bool {
        (1..=MAX_NAME_BYTES).contains(&bytes.len())
            && !bytes.contains(&0)
            && match self {
                Self::File => true,
                Self::UnicodeFile => std::str::from_utf8(bytes).is_ok(),
                Self::Url => bytes.is_ascii(),
            }
    }
}

/// Immutable snapshots of caller-supplied external stream bytes. Each entry is
/// bound to the observed version of a held regular PDF file. The whole set
/// admits at most 64 bindings and 1 MiB of payloads.
#[derive(Default)]
pub struct PdfExternalStreams {
    documents: Vec<Document>,
    bindings: usize,
    payload_bytes: usize,
}

pub(super) struct Document {
    source: Source,
    pub(super) observed: FileInfo,
    pub(super) streams: Vec<Stream>,
}

enum Source {
    // Holds the original identity while the immediate binding remains live.
    Held(File),
    Frozen([u8; 64]),
}

pub(super) struct Stream {
    pub(super) kind: NameKind,
    pub(super) name: Box<[u8]>,
    pub(super) payload: Box<[u8]>,
}

/// Exact digest of a source already read and re-observed by its normal owner.
#[derive(Clone, Copy)]
pub(crate) struct VerifiedSource {
    pub(crate) observed: FileInfo,
    pub(crate) digest: [u8; 64],
}

impl Document {
    pub(super) fn digest_for_snapshot(&self) -> Result<[u8; 64], Error> {
        match &self.source {
            Source::Held(file) => hash_document(file, self.observed, || Ok(())),
            Source::Frozen(digest) => Ok(*digest),
        }
    }

    #[cfg(feature = "network")]
    pub(super) fn matches_frozen_digest(&self, digest: [u8; 64]) -> bool {
        matches!(self.source, Source::Frozen(expected) if expected == digest)
    }
}

/// The slice of the authority for the actual document being read.
#[derive(Clone, Copy)]
pub(super) struct DocumentStreams<'a>(&'a [Stream]);

impl<'a> DocumentStreams<'a> {
    pub(super) fn find(self, kind: NameKind, name: &[u8]) -> Option<&'a [u8]> {
        self.0.iter().find_map(|stream| {
            (stream.kind == kind && &*stream.name == name).then_some(&*stream.payload)
        })
    }
}

impl PdfExternalStreams {
    /// Bind a file specification key to the bytes explicitly supplied by the
    /// caller. Duplicate keys for the same document version are refused.
    pub fn bind(
        &mut self,
        document: &File,
        name: PdfExternalName<'_>,
        payload: &[u8],
    ) -> Result<(), Error> {
        let (kind, name) = name.parts();
        let observed = observe(document)?;
        self.insert(observed, kind, name, payload, || {
            let mut signature = [0; 5];
            if observed.bytes < signature.len() as u64 {
                return Err(Error::Binding);
            }
            FileReader::from_file(document)?.read_exact_at(&mut signature, 0)?;
            if observe(document)? != observed {
                return Err(Error::SourceChanged);
            }
            if signature != *b"%PDF-" {
                return Err(Error::Binding);
            }
            Ok(Source::Held(document.try_clone()?))
        })
    }

    fn insert(
        &mut self,
        observed: FileInfo,
        kind: NameKind,
        name: &[u8],
        payload: &[u8],
        source: impl FnOnce() -> Result<Source, Error>,
    ) -> Result<(), Error> {
        if !kind.valid(name) {
            return Err(Error::Binding);
        }
        let bytes = self
            .payload_bytes
            .checked_add(payload.len())
            .filter(|&n| n <= MAX_PAYLOAD_BYTES)
            .ok_or(Error::Limit)?;
        if self.bindings == MAX_BINDINGS {
            return Err(Error::Limit);
        }
        let existing = self
            .documents
            .iter_mut()
            .find(|doc| doc.observed == observed);
        if existing
            .as_ref()
            .is_some_and(|doc| DocumentStreams(&doc.streams).find(kind, name).is_some())
        {
            return Err(Error::Binding);
        }
        let stream = Stream {
            kind,
            name: copy(name)?.into_boxed_slice(),
            payload: copy(payload)?.into_boxed_slice(),
        };
        if let Some(doc) = existing {
            doc.streams.try_reserve(1).map_err(|_| Error::Limit)?;
            doc.streams.push(stream);
        } else {
            self.documents.try_reserve(1).map_err(|_| Error::Limit)?;
            self.documents.push(Document {
                source: source()?,
                observed,
                streams: vec![stream],
            });
        }
        self.bindings += 1;
        self.payload_bytes = bytes;
        Ok(())
    }

    pub(super) fn restore_stream(
        &mut self,
        observed: FileInfo,
        digest: [u8; 64],
        kind: NameKind,
        name: &[u8],
        payload: &[u8],
    ) -> Result<(), Error> {
        self.insert(observed, kind, name, payload, || Ok(Source::Frozen(digest)))
    }

    pub(super) fn documents(&self) -> &[Document] {
        &self.documents
    }

    pub(super) fn for_document(
        &self,
        file: &File,
        observed: FileInfo,
        verified: Option<VerifiedSource>,
        check: impl FnMut() -> Result<(), Error>,
    ) -> Result<Option<DocumentStreams<'_>>, Error> {
        let Some(document) = self
            .documents
            .iter()
            .find(|document| document.observed == observed)
        else {
            return Ok(None);
        };
        if let Source::Frozen(expected) = document.source {
            let digest = match verified.filter(|proof| proof.observed == observed) {
                Some(proof) => proof.digest,
                None => hash_document(file, observed, check)?,
            };
            if digest != expected {
                return Err(Error::SourceChanged);
            }
        }
        Ok(Some(DocumentStreams(&document.streams)))
    }

    pub(super) fn is_empty(&self) -> bool {
        self.bindings == 0
    }

    pub(super) fn retained_bytes(&self) -> usize {
        size_of::<Self>()
            + self.documents.capacity() * size_of::<Document>()
            + self
                .documents
                .iter()
                .map(|doc| {
                    doc.streams.capacity() * size_of::<Stream>()
                        + doc
                            .streams
                            .iter()
                            .map(|stream| stream.name.len() + stream.payload.len())
                            .sum::<usize>()
                })
                .sum::<usize>()
    }
}

pub(super) fn observe(file: &File) -> Result<FileInfo, Error> {
    match file_info(file)? {
        EntryInfo::File(observed) => Ok(observed),
        _ => Err(Error::Binding),
    }
}

fn hash_document(
    file: &File,
    observed: FileInfo,
    mut check: impl FnMut() -> Result<(), Error>,
) -> Result<[u8; 64], Error> {
    check()?;
    if observe(file)? != observed {
        return Err(Error::SourceChanged);
    }
    let reader = FileReader::from_file(file)?;
    let mut hash = Hash512State::new();
    let mut offset = 0_u64;
    let mut buffer = [0; 8192];
    while offset < observed.bytes {
        check()?;
        let width = (observed.bytes - offset).min(buffer.len() as u64) as usize;
        match reader.read_at(&mut buffer[..width], offset) {
            Ok(0) => return Err(Error::SourceChanged),
            Ok(count) => {
                hash.update(&buffer[..count]);
                offset += count as u64;
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    check()?;
    if observe(file)? != observed {
        return Err(Error::SourceChanged);
    }
    Ok(hash.finish())
}
