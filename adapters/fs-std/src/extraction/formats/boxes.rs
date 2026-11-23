//! Positioned box framing for image containers.

pub(super) mod compressed;
pub(super) mod samples;

use super::Input;

const BOX_BYTES: usize = 8;
pub(super) const EXTENDED_BOX_BYTES: usize = 16;

#[derive(Clone, Copy)]
pub(super) struct BoxSpan {
    pub(super) kind: [u8; 4],
    pub(super) data: u64,
    pub(super) end: u64,
}

impl BoxSpan {
    pub(super) fn read<E>(
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        at: u64,
        bound: u64,
    ) -> Result<Option<Self>, E> {
        let Some(standard_end) = at.checked_add(BOX_BYTES as u64).filter(|&end| end <= bound)
        else {
            return Ok(None);
        };
        let Some((len, kind)) = input.range(at, BOX_BYTES)?.and_then(box_header) else {
            return Ok(None);
        };
        let (end, data) = match len {
            0 => (Some(input.extent), standard_end),
            1 => {
                let Some(data) = at
                    .checked_add(EXTENDED_BOX_BYTES as u64)
                    .filter(|&end| end <= bound)
                else {
                    return Ok(None);
                };
                let Some(length) = input
                    .range(standard_end, BOX_BYTES)?
                    .and_then(|bytes| bytes.first_chunk().copied())
                    .map(u64::from_be_bytes)
                else {
                    return Ok(None);
                };
                (at.checked_add(length), data)
            }
            length => (at.checked_add(u64::from(length)), standard_end),
        };
        Ok(end
            .filter(|&end| end >= data && end <= bound.min(input.extent))
            .map(|end| Self { kind, data, end }))
    }

    pub(super) fn len(&self) -> u64 {
        self.end - self.data
    }
}

pub(super) struct FileType<'a> {
    pub(super) major: [u8; 4],
    pub(super) minor: Option<u32>,
    pub(super) payload_bytes: u64,
    pub(super) compatible: &'a [[u8; 4]],
}

pub(super) fn file_type_probe_len(prefix: &[u8], minimum: usize) -> usize {
    let Some((length, _)) = box_header(prefix) else {
        return BOX_BYTES;
    };
    match length {
        1 => prefix
            .get(BOX_BYTES..)
            .and_then(|bytes| bytes.first_chunk::<8>())
            .map_or(EXTENDED_BOX_BYTES, |extended| {
                usize::try_from(u64::from_be_bytes(*extended))
                    .unwrap_or(usize::MAX)
                    .max(minimum)
            }),
        length => (length as usize).max(minimum),
    }
}

pub(super) fn file_type(prefix: &[u8]) -> Option<FileType<'_>> {
    let (length, kind) = box_header(prefix)?;
    if kind != *b"ftyp" || length == 0 {
        return None;
    }
    let (length, header) = if length == 1 {
        (
            u64::from_be_bytes(*prefix.get(BOX_BYTES..)?.first_chunk()?),
            EXTENDED_BOX_BYTES,
        )
    } else {
        (u64::from(length), BOX_BYTES)
    };
    let payload = length.checked_sub(header as u64)?;
    if payload < 8 || !payload.is_multiple_of(4) {
        return None;
    }
    let prefix = prefix.get(header..)?;
    let available = prefix
        .len()
        .min(usize::try_from(payload).unwrap_or(usize::MAX));
    let bytes = &prefix[..available];
    let (major, tail) = bytes.split_first_chunk()?;
    Some(FileType {
        major: *major,
        minor: tail.first_chunk().copied().map(u32::from_be_bytes),
        payload_bytes: payload,
        compatible: bytes.get(8..).unwrap_or_default().as_chunks::<4>().0,
    })
}

fn box_header(bytes: &[u8]) -> Option<(u32, [u8; 4])> {
    let (length, tail) = bytes.split_first_chunk()?;
    Some((u32::from_be_bytes(*length), *tail.first_chunk()?))
}
