//! Durable original-policy intent in the exclusively locked PF lease file.
use super::rules;
use std::{
    fs::File,
    io::{self, Seek, SeekFrom, Write},
    os::unix::fs::FileExt,
};

// One bounded command response and its ownership metadata; no history is kept.
const RULE_BYTES: usize = 32768;
const HEADER_BYTES: usize = 24;
const HASH_BYTES: usize = 32;
const LABEL_BYTES: usize = 46;
const FILE_BYTES: usize = HEADER_BYTES + LABEL_BYTES + RULE_BYTES + HASH_BYTES;

#[derive(Debug, Eq, PartialEq)]
pub(super) struct Policy {
    pub label: String,
    pub canonical: Vec<u8>,
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid PF policy journal")
}
fn valid_label(label: &str) -> bool {
    label.len() == LABEL_BYTES
        && label.strip_prefix("gnunet-rs-dns-").is_some_and(|suffix| {
            suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}
fn encode(label: &str, canonical: &[u8]) -> io::Result<Vec<u8>> {
    if !valid_label(label) || canonical.len() > RULE_BYTES || !rules::owned(canonical, label) {
        return Err(invalid());
    }
    let total = HEADER_BYTES + LABEL_BYTES + canonical.len() + HASH_BYTES;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(total).map_err(io::Error::other)?;
    bytes.resize(HEADER_BYTES, 0);
    bytes[..8].copy_from_slice(b"GNPFDNS1");
    bytes[8..12].copy_from_slice(&(canonical.len() as u32).to_be_bytes());
    bytes.extend_from_slice(label.as_bytes());
    bytes.extend_from_slice(canonical);
    bytes.extend_from_slice(&gnunet_crypto::hash256(&bytes));
    Ok(bytes)
}
fn decode(bytes: &[u8]) -> io::Result<Policy> {
    if bytes.len() < HEADER_BYTES + LABEL_BYTES + HASH_BYTES
        || bytes.len() > FILE_BYTES
        || &bytes[..8] != b"GNPFDNS1"
        || bytes[12..HEADER_BYTES].iter().any(|byte| *byte != 0)
    {
        return Err(invalid());
    }
    let length = u32::from_be_bytes(bytes[8..12].try_into().map_err(|_| invalid())?) as usize;
    let end = bytes.len() - HASH_BYTES;
    if HEADER_BYTES + LABEL_BYTES + length != end
        || bytes[end..] != gnunet_crypto::hash256(&bytes[..end])
    {
        return Err(invalid());
    }
    let label = std::str::from_utf8(&bytes[HEADER_BYTES..HEADER_BYTES + LABEL_BYTES])
        .map_err(|_| invalid())?;
    let canonical = &bytes[HEADER_BYTES + LABEL_BYTES..end];
    if !valid_label(label) || !rules::owned(canonical, label) {
        return Err(invalid());
    }
    Ok(Policy {
        label: label.to_owned(),
        canonical: canonical.to_vec(),
    })
}
/// Empty is the only no-debt representation. Damaged nonempty records fence
/// startup; checksums detect torn writes, not a hostile privileged writer.
pub(super) fn read(file: &File) -> io::Result<Option<Policy>> {
    let length = usize::try_from(file.metadata()?.len()).map_err(|_| invalid())?;
    if length == 0 {
        return Ok(None);
    }
    if length > FILE_BYTES {
        return Err(invalid());
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(io::Error::other)?;
    bytes.resize(length, 0);
    file.read_exact_at(&mut bytes, 0)?;
    decode(&bytes).map(Some)
}
/// Called before spawning the first mutating command. An occupied original
/// record is never overwritten. A failed write grants no policy admission.
pub(super) fn store(file: &mut File, label: &str, canonical: &[u8]) -> io::Result<()> {
    if file.metadata()?.len() != 0 {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "PF policy journal is occupied",
        ));
    }
    let bytes = encode(label, canonical)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&bytes)?;
    file.sync_all()
}
/// Called only after confirmed absence, or before any mutating command was
/// admitted. A failed clear keeps the controller's retirement obligation.
pub(super) fn clear(file: &File) -> io::Result<()> {
    file.set_len(0)?;
    file.sync_all()
}

#[cfg(test)]
mod tests;
