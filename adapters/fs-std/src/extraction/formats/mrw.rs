//! Positioned Minolta MRW metadata from the TIFF stored in its TTW block.

use super::{Input, tiff};

pub(super) const SIGNATURE: &[u8; 4] = b"\0MRM";
const HEADER_BYTES: u64 = 8;

pub(super) fn visit<E>(
    mut input: Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    let Some(header) = input
        .range(0, HEADER_BYTES as usize)?
        .and_then(Header::parse)
    else {
        return Ok(());
    };
    if header.kind != *SIGNATURE {
        return Ok(());
    }
    let end = HEADER_BYTES + header.length;
    if end > input.extent {
        return Ok(());
    }
    let mut offset = HEADER_BYTES;
    while offset + HEADER_BYTES <= end {
        let Some(block) = input
            .range(offset, HEADER_BYTES as usize)?
            .and_then(Header::parse)
        else {
            break;
        };
        let body = offset + HEADER_BYTES;
        offset = body + block.length;
        if offset > end {
            break;
        }
        if block.kind == *b"\0TTW" {
            if let Some(section) = input.section(body, block.length) {
                tiff::visit_raw_tiff(section, limit, emit)?;
            }
            break;
        }
    }
    Ok(())
}

struct Header {
    kind: [u8; 4],
    length: u64,
}

impl Header {
    fn parse(bytes: &[u8]) -> Option<Self> {
        let (kind, rest) = bytes.split_first_chunk()?;
        let length = u32::from_be_bytes(*rest.first_chunk()?);
        Some(Self {
            kind: *kind,
            length: length.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extraction::formats::Format;
    use std::convert::Infallible;

    #[test]
    fn mrw_tiff_is_limited_to_the_metadata_container() {
        const PAD_BYTES: usize = 8192;
        const TTW_AT: usize = 16 + PAD_BYTES;
        const TIFF: &[u8] = b"MM\0*\0\0\0\x08\0\x01\x01\x0f\0\x02\0\0\0\x04Cam\0\0\0\0\0";
        let mut file = b"\0MRM\0\0\0\0\0PAD\0\0\x20\0".to_vec();
        file.resize(TTW_AT, 0);
        file.extend_from_slice(b"\0TTW");
        file.extend_from_slice(&(TIFF.len() as u32).to_be_bytes());
        file.extend_from_slice(TIFF);
        for complete in [true, false] {
            let mrm_length = (file.len() - 8) as u32 - u32::from(!complete);
            file[4..8].copy_from_slice(&mrm_length.to_be_bytes());
            let prefix = &file[..8];
            let mut scratch = [0; 96];
            let input = Input::new(
                prefix,
                file.len() as u64,
                &mut scratch,
                |at, out: &mut [u8]| {
                    let at = at as usize;
                    assert!(at == 8 || at >= TTW_AT);
                    out.copy_from_slice(&file[at..at + out.len()]);
                    Ok::<_, Infallible>(())
                },
            );
            let format = Format::detect(prefix);
            assert!(format.is_some());
            let Some(format) = format else {
                return;
            };
            assert_eq!(format.mime(), b"image/x-minolta-mrw");
            let mut fields = Vec::new();
            let Ok(()) = format.visit_text(input, 32, &mut |kind, value| {
                fields.push((kind, value.to_vec()));
                Ok(())
            });
            if complete {
                assert_eq!(
                    fields,
                    [(1, b"image/x-minolta-mrw".to_vec()), (95, b"Cam".to_vec())]
                );
            } else {
                assert_eq!(fields, [(1, b"image/x-minolta-mrw".to_vec())]);
            }
        }
    }
}
