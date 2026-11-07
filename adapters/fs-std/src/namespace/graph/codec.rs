//! Checked private graph bytes; official URI/metadata parsing stays authoritative.
use super::{Error, Limits, Record};
use gnunet_fs::{Uri, metadata};
use gnunet_fs_codec::Inflate;
#[derive(Clone, Copy)]
pub(super) struct Span {
    start: u32,
    end: u32,
}
impl Span {
    pub fn get(self, body: &[u8]) -> &[u8] {
        &body[self.start as usize..self.end as usize]
    }
}
#[derive(Clone, Copy)]
pub(super) struct Index {
    pub identifier: Span,
    pub update: Span,
    pub uri: Span,
    pub metadata: Option<Span>,
    pub origin: Option<[u8; 32]>,
}
pub(super) fn encode(record: Record<'_>, limits: Limits) -> Result<(Vec<u8>, Index), Error> {
    encode_origin(record, None, limits)
}
pub(super) fn encode_task(
    record: Record<'_>,
    origin: [u8; 32],
    limits: Limits,
) -> Result<(Vec<u8>, Index), Error> {
    encode_origin(record, Some(origin), limits)
}
fn encode_origin(
    record: Record<'_>,
    origin: Option<[u8; 32]>,
    limits: Limits,
) -> Result<(Vec<u8>, Index), Error> {
    labels(record.identifier, record.update, limits)?;
    if record
        .metadata
        .is_some_and(|bytes| bytes.len() > limits.metadata.max_coded_bytes)
    {
        return Err(Error::Limit);
    }
    let uri_length = record.uri.encoded_len()?;
    if uri_length > limits.max_uri_bytes {
        return Err(Error::Limit);
    }
    let total = 3usize
        .checked_add(if origin.is_some() { 32 } else { 0 })
        .and_then(|n| n.checked_add(4))
        .and_then(|n| n.checked_add(record.identifier.len()))
        .and_then(|n| n.checked_add(4))
        .and_then(|n| n.checked_add(record.update.len()))
        .and_then(|n| n.checked_add(4))
        .and_then(|n| n.checked_add(uri_length))
        .and_then(|n| n.checked_add(1))
        .and_then(|n| match record.metadata {
            Some(m) => n.checked_add(4)?.checked_add(m.len()),
            None => Some(n),
        })
        .filter(|n| *n <= u32::MAX as usize && *n <= limits.max_record_bytes)
        .ok_or(Error::Limit)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(total).map_err(|_| Error::Limit)?;
    bytes.extend_from_slice(&2u16.to_be_bytes());
    bytes.push(u8::from(origin.is_some()));
    if let Some(origin) = origin {
        bytes.extend_from_slice(&origin);
    }
    put_blob(&mut bytes, record.identifier)?;
    put_blob(&mut bytes, record.update)?;
    bytes.extend_from_slice(
        &u32::try_from(uri_length)
            .map_err(|_| Error::Limit)?
            .to_be_bytes(),
    );
    let start = bytes.len();
    bytes.resize(start + uri_length, 0);
    record.uri.encode(&mut bytes[start..])?;
    bytes.push(u8::from(record.metadata.is_some()));
    if let Some(value) = record.metadata {
        put_blob(&mut bytes, value)?;
    }
    let index = decode(&bytes)?;
    Ok((bytes, index))
}
pub(super) fn decode(body: &[u8]) -> Result<Index, Error> {
    let mut r = Reader { body, at: 0 };
    if r.take(2)? != 2u16.to_be_bytes() {
        return Err(Error::Version);
    }
    let origin = match r.take(1)?[0] {
        0 => None,
        1 => Some(r.take(32)?.try_into().map_err(|_| Error::Format)?),
        _ => return Err(Error::Format),
    };
    let identifier = r.blob()?;
    let update = r.blob()?;
    let uri = r.blob()?;
    let metadata = match r.take(1)?[0] {
        0 => None,
        1 => Some(r.blob()?),
        _ => return Err(Error::Format),
    };
    if r.at != body.len() {
        return Err(Error::Format);
    }
    Ok(Index {
        identifier,
        update,
        uri,
        metadata,
        origin,
    })
}
pub(super) fn validate(
    body: &[u8],
    index: &Index,
    limits: Limits,
    scratch: &mut Vec<u8>,
    inflater: &mut Inflate,
) -> Result<(), Error> {
    if body.len() > limits.max_record_bytes {
        return Err(Error::Limit);
    }
    labels(index.identifier.get(body), index.update.get(body), limits)?;
    let raw = index.uri.get(body);
    if raw.len() > limits.max_uri_bytes {
        return Err(Error::Limit);
    }
    Uri::parse(raw, limits.uri)?;
    if let Some(span) = index.metadata {
        let raw = span.get(body);
        if raw.len() > limits.metadata.max_coded_bytes {
            return Err(Error::Limit);
        }
        let header = raw
            .get(..metadata::HEADER_BYTES)
            .ok_or(metadata::Error::Truncated)?;
        let mut version = [0; 4];
        version.copy_from_slice(&header[..4]);
        let mut plain = [0; 4];
        plain.copy_from_slice(&header[8..12]);
        let needed = if u32::from_be_bytes(version) & metadata::COMPRESSED != 0 {
            u32::from_be_bytes(plain) as usize
        } else {
            0
        };
        if needed > limits.metadata.max_plain_bytes {
            return Err(Error::Limit);
        }
        scratch
            .try_reserve(needed.saturating_sub(scratch.len()))
            .map_err(|_| Error::Limit)?;
        scratch.resize(needed, 0);
        if !matches!(
            metadata::decode(
                raw,
                scratch,
                inflater,
                limits.metadata,
                metadata::Mode::Strict
            )?,
            metadata::Decoded::Present(_)
        ) {
            return Err(Error::Format);
        }
    }
    Ok(())
}
fn labels(identifier: &[u8], update: &[u8], limits: Limits) -> Result<(), Error> {
    if identifier.len() > limits.max_label_bytes || update.len() > limits.max_label_bytes {
        return Err(Error::Limit);
    }
    if identifier.contains(&0) || update.contains(&0) {
        return Err(Error::Format);
    }
    Ok(())
}
fn put_blob(output: &mut Vec<u8>, input: &[u8]) -> Result<(), Error> {
    output.extend_from_slice(
        &u32::try_from(input.len())
            .map_err(|_| Error::Limit)?
            .to_be_bytes(),
    );
    output.extend_from_slice(input);
    Ok(())
}
struct Reader<'a> {
    body: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(length).ok_or(Error::Format)?;
        let out = self.body.get(self.at..end).ok_or(Error::Format)?;
        self.at = end;
        Ok(out)
    }
    fn blob(&mut self) -> Result<Span, Error> {
        let mut word = [0; 4];
        word.copy_from_slice(self.take(4)?);
        let length = u32::from_be_bytes(word) as usize;
        let start = u32::try_from(self.at).map_err(|_| Error::Limit)?;
        self.take(length)?;
        let end = u32::try_from(self.at).map_err(|_| Error::Limit)?;
        Ok(Span { start, end })
    }
}
