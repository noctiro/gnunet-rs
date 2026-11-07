//! Private, versioned task bytes. Checksums detect damage, not malicious owners.
use super::{Certainty, Error, FailureKind, Limits};
pub(super) const HEADER: usize = 128;
pub(super) const RECORD_HEADER: usize = 96;
pub(super) const DIGEST: usize = 64;
const MAGIC: &[u8; 8] = b"GNFTSK01";
const RECORD_MAGIC: &[u8; 8] = b"FSTREC01";

pub(super) fn header(id: &[u8; 32]) -> [u8; HEADER] {
    let mut bytes = [0; HEADER];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
    bytes[10..12].copy_from_slice(&(HEADER as u16).to_be_bytes());
    bytes[16..48].copy_from_slice(id);
    let hash = gnunet_crypto::hash512(&bytes[..64]);
    bytes[64..].copy_from_slice(&hash);
    bytes
}
pub(super) fn decode_header(bytes: &[u8; HEADER]) -> Result<[u8; 32], Error> {
    if &bytes[..8] != MAGIC || bytes[12..16] != [0; 4] || bytes[48..64] != [0; 16] {
        return Err(bad("header-shape", FailureKind::Malformed));
    }
    if bytes[8..10] != 1_u16.to_be_bytes() || bytes[10..12] != (HEADER as u16).to_be_bytes() {
        return Err(bad("header-version", FailureKind::Version));
    }
    if bytes[64..] != gnunet_crypto::hash512(&bytes[..64]) {
        return Err(bad("header-checksum", FailureKind::Checksum));
    }
    let mut id = [0; 32];
    id.copy_from_slice(&bytes[16..48]);
    Ok(id)
}
pub(super) fn record_size(body_bytes: usize) -> Result<usize, Error> {
    u32::try_from(body_bytes).map_err(|_| bad("record-length", FailureKind::Limit))?;
    RECORD_HEADER
        .checked_add(body_bytes)
        .and_then(|n| n.checked_add(DIGEST))
        .ok_or_else(|| bad("record-length", FailureKind::Limit))
}
pub(super) fn frame(
    sequence: u64,
    kind: u16,
    body: &[u8],
    bytes: &mut [u8],
) -> Result<[u8; DIGEST], Error> {
    let total = record_size(body.len())?;
    if bytes.len() != total {
        return Err(bad("append-frame-size", FailureKind::Limit));
    }
    let length = u32::try_from(body.len()).map_err(|_| bad("append-length", FailureKind::Limit))?;
    bytes[..RECORD_HEADER].fill(0);
    bytes[..8].copy_from_slice(RECORD_MAGIC);
    bytes[8..12].copy_from_slice(&length.to_be_bytes());
    bytes[12..14].copy_from_slice(&kind.to_be_bytes());
    bytes[16..24].copy_from_slice(&sequence.to_be_bytes());
    let hash = gnunet_crypto::hash512(&bytes[..32]);
    bytes[32..RECORD_HEADER].copy_from_slice(&hash);
    let end = total - DIGEST;
    bytes[RECORD_HEADER..end].copy_from_slice(body);
    let hash = gnunet_crypto::hash512(&bytes[..end]);
    bytes[end..].copy_from_slice(&hash);
    Ok(hash)
}
// A truncated header must agree with every fixed/header-checksum byte present.
// A complete header is independently authenticated before trusting its length.
pub(super) fn prefix(
    bytes: &[u8],
    sequence: u64,
    limits: Limits,
) -> Result<Option<(u16, usize)>, Error> {
    let n = bytes.len();
    if bytes[..n.min(8)] != RECORD_MAGIC[..n.min(8)] {
        return Err(bad("record-magic", FailureKind::Malformed));
    }
    for range in [14..16, 24..32] {
        if bytes
            .get(range.start..n.min(range.end))
            .is_some_and(|part| part.iter().any(|b| *b != 0))
        {
            return Err(bad("record-reserved", FailureKind::Malformed));
        }
    }
    if n > 16 {
        let count = (n - 16).min(8);
        if bytes[16..16 + count] != sequence.to_be_bytes()[..count] {
            return Err(bad("record-sequence", FailureKind::Sequence));
        }
    }
    if n > 8 {
        let count = (n - 8).min(4);
        let mut word = [0; 4];
        word[..count].copy_from_slice(&bytes[8..8 + count]);
        if u32::from_be_bytes(word) as usize > limits.max_body_bytes {
            return Err(bad("record-partial-body-limit", FailureKind::Limit));
        }
    }
    let length = if n >= 12 {
        let mut word = [0; 4];
        word.copy_from_slice(&bytes[8..12]);
        let length = u32::from_be_bytes(word) as usize;
        if length > limits.max_body_bytes {
            return Err(bad("record-body-limit", FailureKind::Limit));
        }
        Some(length)
    } else {
        None
    };
    if n > 32 {
        let hash = gnunet_crypto::hash512(&bytes[..32]);
        if bytes[32..] != hash[..n - 32] {
            return Err(bad("record-header-checksum", FailureKind::Checksum));
        }
    }
    if n < RECORD_HEADER {
        return Ok(None);
    }
    let mut word = [0; 2];
    word.copy_from_slice(&bytes[12..14]);
    Ok(Some((
        u16::from_be_bytes(word),
        length.ok_or_else(|| bad("record-length", FailureKind::Malformed))?,
    )))
}
pub(super) fn verify_incomplete_frame(bytes: &[u8], body_len: usize) -> Result<(), Error> {
    let end = RECORD_HEADER
        .checked_add(body_len)
        .ok_or_else(|| bad("record-partial-length", FailureKind::Limit))?;
    if bytes.len() > end {
        let hash = gnunet_crypto::hash512(&bytes[..end]);
        if bytes[end..] != hash[..bytes.len() - end] {
            return Err(bad("record-partial-checksum", FailureKind::Checksum));
        }
    }
    Ok(())
}
pub(super) fn verify_frame(bytes: &[u8]) -> Result<[u8; DIGEST], Error> {
    let end = bytes
        .len()
        .checked_sub(DIGEST)
        .ok_or_else(|| bad("record-size", FailureKind::Malformed))?;
    let digest = gnunet_crypto::hash512(&bytes[..end]);
    if bytes[end..] != digest {
        return Err(bad("record-checksum", FailureKind::Checksum));
    }
    Ok(digest)
}
fn bad(stage: &'static str, kind: FailureKind) -> Error {
    Error::new(stage, kind, Certainty::NotWritten, None)
}
