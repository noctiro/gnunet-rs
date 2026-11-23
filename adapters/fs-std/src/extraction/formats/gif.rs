//! Positioned metadata extraction from a GIF data stream.

use super::{Dimensions, Input, xmp};

pub(super) const HEADER_BYTES: usize = 13;
const XMP_APPLICATION: &[u8; 11] = b"XMP DataXMP";
const XMP_TRAILER: [u8; 258] = xmp_trailer();

pub(super) fn visit<E>(
    mut input: Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    let Some(
        &[
            b'G',
            b'I',
            b'F',
            b'8',
            version @ (b'7' | b'9'),
            b'a',
            w0,
            w1,
            h0,
            h1,
            flags,
            _,
            _,
        ],
    ) = input.range(0, HEADER_BYTES)?
    else {
        return Ok(());
    };
    if let Some(dimensions) = Dimensions::new(
        u16::from_le_bytes([w0, w1]).into(),
        u16::from_le_bytes([h0, h1]).into(),
    ) {
        dimensions.emit(emit)?;
    }
    if version != b'9' {
        return Ok(());
    }

    let mut offset = HEADER_BYTES as u64 + color_table_bytes(flags);
    while let Some(&[tag]) = input.range(offset, 1)? {
        match tag {
            0x2c => {
                let Some(next) = image_end(&mut input, offset)? else {
                    break;
                };
                offset = next;
            }
            0x21 => {
                let Some(&[label, size]) = input.range(offset + 1, 2)? else {
                    break;
                };
                let data = offset + 3;
                if size == 0 {
                    offset = data;
                    continue;
                }
                let Some(body) = data.checked_add(u64::from(size)) else {
                    break;
                };
                let is_xmp = label == 0xff
                    && usize::from(size) == XMP_APPLICATION.len()
                    && input.range(data, XMP_APPLICATION.len())?
                        == Some(XMP_APPLICATION.as_slice());
                let Some(next) = sub_blocks_end(&mut input, body)? else {
                    break;
                };
                if is_xmp && visit_xmp(&mut input, body, next, limit, emit)? {
                    break;
                }
                offset = next;
            }
            _ => break,
        }
    }
    Ok(())
}

fn color_table_bytes(flags: u8) -> u64 {
    if flags & 0x80 == 0 {
        0
    } else {
        3 << (1 + (flags & 7))
    }
}

fn image_end<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    offset: u64,
) -> Result<Option<u64>, E> {
    let Some(&[_, _, _, _, _, _, _, _, flags]) = input.range(offset + 1, 9)? else {
        return Ok(None);
    };
    // The LZW minimum code size follows the optional local color table.
    let Some(first_block) = (offset + 10).checked_add(color_table_bytes(flags) + 1) else {
        return Ok(None);
    };
    sub_blocks_end(input, first_block)
}

fn sub_blocks_end<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    mut offset: u64,
) -> Result<Option<u64>, E> {
    while let Some(&[size]) = input.range(offset, 1)? {
        if size == 0 {
            return Ok(Some(offset + 1));
        }
        let Some(next) = (offset + 1).checked_add(u64::from(size)) else {
            break;
        };
        offset = next;
    }
    Ok(None)
}

fn visit_xmp<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    body: u64,
    end: u64,
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<bool, E> {
    let Some(packet_len) = end
        .checked_sub(XMP_TRAILER.len() as u64)
        .and_then(|trailer| trailer.checked_sub(body))
        .and_then(|len| usize::try_from(len).ok())
    else {
        return Ok(false);
    };
    let trailer_start = body + packet_len as u64;
    if input.range(trailer_start, XMP_TRAILER.len())? != Some(XMP_TRAILER.as_slice()) {
        return Ok(false);
    }
    // Adobe XMP Part 3 stores the physical UTF-8 bytes without inserted size tags.
    let Some(packet) = input.range(body, packet_len)? else {
        return Ok(false);
    };
    if std::str::from_utf8(packet).is_err() {
        return Ok(false);
    }
    xmp::visit(packet, limit, emit)
}

const fn xmp_trailer() -> [u8; 258] {
    // The descending ramp leads any sub-block cursor to the final zero terminator.
    let mut bytes = [0; 258];
    bytes[0] = 1;
    let mut index = 1;
    while index <= 256 {
        bytes[index] = (256 - index) as u8;
        index += 1;
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;

    #[test]
    fn reads_late_xmp_through_sparse_image_data_and_checks_the_whole_trailer() {
        const SCREEN: &[u8] = b"GIF89a\x11\0\x0d\0\x80\0\0";
        const IMAGE: &[u8] = b",\0\0\0\0\x11\0\x0d\0\x80";
        const PACKET: &[u8] = br#"<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns:xmp="http://ns.adobe.com/xap/1.0/"><rdf:Description xmp:CreatorTool="Canvas"/></rdf:RDF>"#;
        const IMAGE_AT: u64 = SCREEN.len() as u64 + 6;
        const IMAGE_DATA: u64 = IMAGE_AT + IMAGE.len() as u64 + 6 + 1;
        const IMAGE_END: u64 = IMAGE_DATA + 256 * 256;
        const APPLICATION_AT: u64 = IMAGE_END + 1;

        let mut metadata = b"\x21\xff\x0bXMP DataXMP".to_vec();
        metadata.extend_from_slice(PACKET);
        metadata.push(1);
        metadata.extend((0..=u8::MAX).rev());
        metadata.extend([0, 0x3b]);
        let extent = APPLICATION_AT + metadata.len() as u64;

        for valid in [true, false] {
            if !valid {
                // This byte is not a sub-block length, so traversal still reaches the terminator.
                let penultimate_trailer_byte = metadata.len() - 3;
                metadata[penultimate_trailer_byte] = 1;
            }
            let mut scratch = [0; 768];
            let input = Input::new(SCREEN, extent, &mut scratch, |offset, out: &mut [u8]| {
                if offset >= APPLICATION_AT {
                    let start = (offset - APPLICATION_AT) as usize;
                    out.copy_from_slice(&metadata[start..start + out.len()]);
                } else if (IMAGE_AT..IMAGE_AT + IMAGE.len() as u64).contains(&offset) {
                    let start = (offset - IMAGE_AT) as usize;
                    out.copy_from_slice(&IMAGE[start..start + out.len()]);
                } else {
                    assert!((IMAGE_DATA..=IMAGE_END).contains(&offset));
                    assert!((offset - IMAGE_DATA).is_multiple_of(256));
                    assert_eq!(out.len(), 1);
                    out[0] = if offset == IMAGE_END { 0 } else { 255 };
                }
                Ok(())
            });
            let mut fields = Vec::new();
            let Ok(()) = visit(input, 64, &mut |kind, value| -> Result<(), Infallible> {
                fields.push((kind, value.to_vec()));
                Ok(())
            });
            let mut expected = vec![(112, b"17x13".to_vec())];
            if valid {
                expected.push((56, b"Canvas".to_vec()));
            }
            assert_eq!(fields, expected);
        }
    }
}
