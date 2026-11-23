//! Standard and extended XMP carried by JPEG APP1 markers.

use md5::{Digest, Md5};

use super::super::xmp::{Profile, parse_guid};
use super::{Input, Segment};

pub(super) const PROBE_PREFIX: &[u8; 6] = b"http:/";
const STANDARD: &[u8; 29] = b"http://ns.adobe.com/xap/1.0/\0";
const EXTENDED: &[u8; 35] = b"http://ns.adobe.com/xmp/extension/\0";
const CHUNK_HEADER: usize = 40;

#[derive(Clone, Copy)]
struct SourceSpan {
    offset: u64,
    len: usize,
}

pub(super) struct Packets {
    standard: Option<SourceSpan>,
    extended: Option<Vec<SourceSpan>>,
}

impl Default for Packets {
    fn default() -> Self {
        Self {
            standard: None,
            extended: Some(Vec::new()),
        }
    }
}

impl Packets {
    /// The caller has read the common HTTP prefix from this APP1 segment.
    pub(super) fn observe<E>(
        &mut self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        segment: &Segment,
    ) -> Result<(), E> {
        if segment.len <= STANDARD.len() {
            return Ok(());
        }
        let start = PROBE_PREFIX.len();
        let Some(identifier) = input.range(segment.body + start as u64, STANDARD.len() - start)?
        else {
            return Ok(());
        };
        if identifier == &STANDARD[start..] {
            self.standard.get_or_insert(SourceSpan {
                offset: segment.body + STANDARD.len() as u64,
                len: segment.len - STANDARD.len(),
            });
        } else if identifier == &EXTENDED[start..STANDARD.len()]
            && segment.len > EXTENDED.len() + CHUNK_HEADER
            && let Some(extended) = &mut self.extended
            && input.range(
                segment.body + STANDARD.len() as u64,
                EXTENDED.len() - STANDARD.len(),
            )? == Some(&EXTENDED[STANDARD.len()..])
        {
            if extended.try_reserve(1).is_err() {
                self.extended = None;
            } else {
                extended.push(SourceSpan {
                    offset: segment.body + EXTENDED.len() as u64,
                    len: segment.len - EXTENDED.len(),
                });
            }
        }
        Ok(())
    }

    pub(super) fn emit<E>(
        self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        limit: usize,
        emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        let Some(span) = self.standard else {
            return Ok(());
        };
        let Some(mut profile) = input
            .range(span.offset, span.len)?
            .and_then(|data| parse_packet(data, limit))
        else {
            return Ok(());
        };
        if let Some(guid) = profile.extended_id()
            && let Some(spans) = self.extended
            && let Some(packet) = assemble(input, spans, guid)?
            && let Some(extension) = parse_packet(&packet, limit)
        {
            profile.merge(extension);
        }
        profile.emit(emit)
    }
}

fn parse_packet(bytes: &[u8], limit: usize) -> Option<Profile> {
    // Adobe requires UTF-8 in both types of JPEG XMP packet.
    if bytes.contains(&0) || std::str::from_utf8(bytes).is_err() {
        return None;
    }
    Profile::parse(bytes, limit)
}

struct Chunk {
    source: SourceSpan,
    at: usize,
}

fn assemble<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    spans: Vec<SourceSpan>,
    guid: [u8; 16],
) -> Result<Option<Vec<u8>>, E> {
    let mut chunks = Vec::new();
    let mut expected = None;
    for span in spans {
        let Some(header) = input.range(span.offset, CHUNK_HEADER)? else {
            return Ok(None);
        };
        if parse_guid(&header[..32]) != Some(guid) {
            continue;
        }
        let Some((total, at)) = chunk_range(&header[32..]) else {
            return Ok(None);
        };
        let len = span.len - CHUNK_HEADER;
        if expected.is_some_and(|previous| previous != total)
            || at.checked_add(len).is_none_or(|end| end > total)
            || chunks.try_reserve(1).is_err()
        {
            return Ok(None);
        }
        expected = Some(total);
        chunks.push(Chunk {
            source: SourceSpan {
                offset: span.offset + CHUNK_HEADER as u64,
                len,
            },
            at,
        });
    }
    let Some(total) = expected else {
        return Ok(None);
    };
    if total > input.prefix.len().saturating_add(input.unread_bytes()) {
        return Ok(None);
    }
    chunks.sort_unstable_by_key(|chunk| chunk.at);
    let mut next = 0;
    for chunk in &chunks {
        if chunk.at != next {
            return Ok(None);
        }
        next += chunk.source.len;
    }
    if next != total {
        return Ok(None);
    }
    let mut packet = Vec::new();
    if packet.try_reserve_exact(total).is_err() {
        return Ok(None);
    }
    for chunk in chunks {
        let Some(bytes) = input.range(chunk.source.offset, chunk.source.len)? else {
            return Ok(None);
        };
        packet.extend_from_slice(bytes);
    }
    let actual: [u8; 16] = Md5::digest(&packet).into();
    Ok((actual == guid).then_some(packet))
}

fn chunk_range(bytes: &[u8]) -> Option<(usize, usize)> {
    let (total, rest) = bytes.split_first_chunk()?;
    let total = usize::try_from(u32::from_be_bytes(*total)).ok()?;
    let at = usize::try_from(u32::from_be_bytes(*rest.first_chunk()?)).ok()?;
    Some((total, at))
}
