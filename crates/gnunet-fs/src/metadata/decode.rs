use super::{
    COMPRESSED, CodecError, ENTRY_BYTES, EntryIssue, Error, HEADER_BYTES, Inflater, Items, Limits,
    NoCodec, records, word,
};

/// Structural validation policy; recovery never becomes an implicit full success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    /// Require every declared entry and exact variable-payload consumption.
    Strict,
    /// Preserve only the valid prefix, with the stopping reason and unused bytes.
    ReferencePrefix,
}
/// Why a structurally admissible body did not become a complete container.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Recovery {
    /// The reference stops before this invalid entry and keeps earlier entries.
    Entry {
        /// Zero-based first rejected descriptor.
        index: u32,
        /// Exact rejection category.
        issue: EntryIssue,
    },
    /// All descriptors were accepted, but variable payload remains unreferenced.
    Trailing,
}

/// Borrowed validated complete body or explicitly identified accepted prefix.
#[derive(Clone, Copy, Debug)]
pub struct Metadata<'a> {
    body: &'a [u8],
    total: usize,
    accepted: usize,
    unused: usize,
    recovery: Option<Recovery>,
    compressed: bool,
}
impl<'a> Metadata<'a> {
    /// Number of descriptors declared on the wire, before semantic deduplication.
    #[must_use]
    pub const fn declared_entries(self) -> usize {
        self.total
    }
    /// Exact number of complete accepted wire records; not a deduplicated count.
    #[must_use]
    pub const fn accepted_entries(self) -> usize {
        self.accepted
    }
    /// Whether every descriptor and variable-payload byte was accepted.
    #[must_use]
    pub const fn is_complete(self) -> bool {
        self.recovery.is_none()
    }
    /// Explicit prefix recovery; None is a structurally complete container.
    #[must_use]
    pub const fn recovery(self) -> Option<Recovery> {
        self.recovery
    }
    /// Variable payload not consumed by the complete accepted prefix.
    #[must_use]
    pub const fn unused_payload_bytes(self) -> usize {
        self.unused
    }
    /// Whether the original envelope used zlib compression.
    #[must_use]
    pub const fn was_compressed(self) -> bool {
        self.compressed
    }
    /// Complete decompressed body, including any explicitly reported unused data.
    #[must_use]
    pub const fn body(self) -> &'a [u8] {
        self.body
    }
    /// Only already-validated entries, including raw names and duplicate records.
    #[must_use]
    pub fn items(self) -> Items<'a> {
        Items {
            body: self.body,
            total: self.total,
            accepted: self.accepted,
            index: 0,
            left: self.body.len() - self.total * ENTRY_BYTES,
        }
    }
}

/// A raw artifact's null marker is distinct from a present empty container.
#[derive(Clone, Copy, Debug)]
pub enum Decoded<'a> {
    /// Recognized version1 header. Outer zero-length absence belongs to framing.
    NullMarker,
    /// Version2 complete body or explicitly reported recovered prefix.
    Present(Metadata<'a>),
}

/// Decode one raw metadata artifact. Uncompressed bodies borrow input; compressed
/// bodies borrow the caller's plaintext scratch. A codec error wipes the entire
/// declared scratch prefix and produces no Metadata. Framing/capacity rejection
/// happens before a codec is invoked. Outer zero-length absence is not a raw v2
/// blob and must be handled by the embedding's optional-value framing.
pub fn decode<'a>(
    input: &'a [u8],
    scratch: &'a mut [u8],
    inflater: &mut impl Inflater,
    limits: Limits,
    mode: Mode,
) -> Result<Decoded<'a>, Error> {
    if input.len() > limits.max_coded_bytes {
        return Err(Error::Limit);
    }
    if input.len() < HEADER_BYTES {
        return Err(Error::Truncated);
    }
    let version = word(input, 0);
    match version & !COMPRESSED {
        1 => return Ok(Decoded::NullMarker),
        2 => (),
        other => return Err(Error::Version(other)),
    }
    let count = usize::try_from(word(input, 4)).map_err(|_| Error::Overflow)?;
    let length = usize::try_from(word(input, 8)).map_err(|_| Error::Overflow)?;
    if count > limits.max_entries || length > limits.max_plain_bytes {
        return Err(Error::Limit);
    }
    let table = count.checked_mul(ENTRY_BYTES).ok_or(Error::Overflow)?;
    if table > length {
        return Err(Error::Invalid);
    }
    let compressed = version & COMPRESSED != 0;
    let body = if compressed {
        if scratch.len() < length {
            return Err(Error::Capacity);
        }
        let target = &mut scratch[..length];
        let result = inflater
            .inflate(&input[HEADER_BYTES..], target)
            .and_then(|progress| {
                if progress.produced != length {
                    Err(CodecError::Length)
                } else if progress.consumed != input.len() - HEADER_BYTES {
                    Err(CodecError::Trailing)
                } else {
                    Ok(())
                }
            });
        if let Err(error) = result {
            target.fill(0);
            return Err(Error::Codec(error));
        }
        &*target
    } else {
        if length != input.len() - HEADER_BYTES {
            return Err(Error::Invalid);
        }
        &input[HEADER_BYTES..]
    };
    let mut left = length - table;
    let mut accepted = 0;
    let mut recovery = None;
    for index in 0..count {
        if let Err(issue) = records::read(body, count, index, &mut left) {
            let index = u32::try_from(index).map_err(|_| Error::Overflow)?;
            if mode == Mode::Strict {
                return Err(Error::Entry { index, issue });
            }
            recovery = Some(Recovery::Entry { index, issue });
            break;
        }
        accepted += 1;
    }
    if recovery.is_none() && left != 0 {
        if mode == Mode::Strict {
            return Err(Error::Trailing(left));
        }
        recovery = Some(Recovery::Trailing);
    }
    Ok(Decoded::Present(Metadata {
        body,
        total: count,
        accepted,
        unused: left,
        recovery,
        compressed,
    }))
}

/// Decode an uncompressed artifact without selecting any codec backend.
pub fn decode_uncompressed(input: &[u8], limits: Limits, mode: Mode) -> Result<Decoded<'_>, Error> {
    // NoCodec rejects a compressed artifact before returning a borrowed body.
    decode(input, &mut [], &mut NoCodec, limits, mode)
}

/// Decode one standard BIO-style optional length-prefixed value, returning the
/// exact consumed prefix. Zero length is absent; a present v1 null marker and
/// present empty v2 container remain distinguishable in the returned value.
/// Trailing bytes belong to the surrounding stream and are not consumed.
pub fn decode_length_prefixed<'a>(
    input: &'a [u8],
    scratch: &'a mut [u8],
    inflater: &mut impl Inflater,
    limits: Limits,
    mode: Mode,
) -> Result<(Option<Decoded<'a>>, usize), Error> {
    if input.len() < 4 {
        return Err(Error::Truncated);
    }
    let length = usize::try_from(word(input, 0)).map_err(|_| Error::Overflow)?;
    let end = length.checked_add(4).ok_or(Error::Overflow)?;
    if length > limits.max_coded_bytes {
        return Err(Error::Limit);
    }
    if end > input.len() {
        return Err(Error::Truncated);
    }
    if length == 0 {
        return Ok((None, 4));
    }
    decode(&input[4..end], scratch, inflater, limits, mode).map(|value| (Some(value), end))
}
