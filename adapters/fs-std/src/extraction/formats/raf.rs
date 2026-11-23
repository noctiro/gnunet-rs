//! Fujifilm RAF metadata in the directory, JPEG preview and optional CFA TIFF.

use super::{Dimensions, IMAGE_DIMENSIONS, Input, jpeg, tiff};

pub(super) const SIGNATURE: &[u8; 16] = b"FUJIFILMCCD-RAW ";

const DIRECTORY_OFFSET: u64 = 84;
const HEADER_END: u64 = DIRECTORY_OFFSET + 24;
const SENSOR_SIZE: u16 = 0x0100;
const OUTPUT_SIZE: u16 = 0x0121;

pub(super) fn visit<E>(
    mut input: Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    if input.range(0, SIGNATURE.len())? != Some(SIGNATURE.as_slice()) {
        return Ok(());
    }
    let Some(&entries) = input
        .range(DIRECTORY_OFFSET, 24)?
        .and_then(|bytes| bytes.as_chunks::<8>().0.first_chunk::<3>())
    else {
        return Ok(());
    };
    let [preview, records, raw] = entries.map(Region::parse);

    let image_size = if let Some(mut section) = records.open(&mut input) {
        dimensions(&mut section)?
    } else {
        None
    };
    if let Some(size) = &image_size {
        size.emit(emit)?;
    }
    if let Some(section) = preview.open(&mut input) {
        jpeg::visit_preview(section, limit, jpeg::Profiles::All, emit)?;
    }
    if let Some(section) = raw.open(&mut input) {
        tiff::visit_raw_tiff(section, limit, &mut |kind, value| {
            if kind == IMAGE_DIMENSIONS && image_size.is_some() {
                return Ok(());
            }
            emit(kind, value)
        })?;
    }
    Ok(())
}

struct Region {
    start: u64,
    length: u64,
}

impl Region {
    fn parse([a, b, c, d, e, f, g, h]: [u8; 8]) -> Self {
        Self {
            start: u64::from(u32::from_be_bytes([a, b, c, d])),
            length: u64::from(u32::from_be_bytes([e, f, g, h])),
        }
    }

    fn open<'a, 'input, E, Read: FnMut(u64, &mut [u8]) -> Result<(), E>>(
        self,
        input: &'a mut Input<'input, Read>,
    ) -> Option<Input<'a, &'a mut Read>> {
        if self.start < HEADER_END || self.length == 0 {
            return None;
        }
        input.section(self.start, self.length)
    }
}

fn dimensions<E>(
    input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
) -> Result<Option<Dimensions>, E> {
    let Some(&count) = input.range(0, 4)?.and_then(<[u8]>::first_chunk) else {
        return Ok(None);
    };
    let count = u64::from(u32::from_be_bytes(count));
    if count > (input.extent - 4) / 4 {
        return Ok(None);
    }
    let mut sensor = None;
    let mut output = None;
    let mut offset = 4;
    for _ in 0..count {
        let Some(&[tag_high, tag_low, len_high, len_low]) = input.range(offset, 4)? else {
            return Ok(None);
        };
        let body = offset + 4;
        let length = u16::from_be_bytes([len_high, len_low]);
        offset = body + u64::from(length);
        if offset > input.extent {
            return Ok(None);
        }
        let field = match u16::from_be_bytes([tag_high, tag_low]) {
            SENSOR_SIZE => &mut sensor,
            OUTPUT_SIZE => &mut output,
            _ => continue,
        };
        if field.is_none()
            && length == 4
            && let Some(&[h0, h1, w0, w1]) = input.range(body, 4)?
        {
            *field = Dimensions::new(
                u16::from_be_bytes([w0, w1]).into(),
                u16::from_be_bytes([h0, h1]).into(),
            );
        }
    }
    Ok(output.or(sensor))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extraction::formats::Format;
    use std::convert::Infallible;

    #[test]
    fn raf_reads_bounded_preview_and_cfa_with_the_same_probe_budget() {
        const RECORDS_AT: usize = 128;
        const PREVIEW_AT: usize = 256;
        const XMP_AT: usize = PREVIEW_AT + 6 + 8192;
        const CFA_AT: usize = 10 * 1024;
        const XMP_NAMESPACE: &[u8] = b"http://ns.adobe.com/xap/1.0/\0";
        const XMP: &[u8] = br#"<r:RDF xmlns:r="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><r:Description xmlns:p="http://ns.adobe.com/photoshop/1.0/" p:City="Dakar"/></r:RDF>"#;
        const TIFF: &[u8] = b"II*\0\x08\0\0\0\x01\0\x0f\x01\x02\0\x04\0\0\0Cam\0\0\0\0\0";

        let mut file = vec![0; CFA_AT];
        file[..SIGNATURE.len()].copy_from_slice(SIGNATURE);
        file[RECORDS_AT..RECORDS_AT + 12]
            .copy_from_slice(b"\0\0\0\x01\x01\x21\0\x04\x0f\xa0\x17\x70");
        file[PREVIEW_AT..PREVIEW_AT + 6].copy_from_slice(b"\xff\xd8\xff\xe2\x20\x02");
        let mut metadata = b"\xff\xe1".to_vec();
        metadata.extend_from_slice(&((XMP_NAMESPACE.len() + XMP.len() + 2) as u16).to_be_bytes());
        metadata.extend_from_slice(XMP_NAMESPACE);
        metadata.extend_from_slice(XMP);
        metadata.extend_from_slice(b"\xff\xd9");
        let preview_end = XMP_AT + metadata.len();
        file[XMP_AT..preview_end].copy_from_slice(&metadata);
        file.extend_from_slice(TIFF);

        for (preview_len, allowance, expect_xmp, expect_cfa) in [
            (preview_end - PREVIEW_AT, 384, true, true),
            (preview_end - PREVIEW_AT, 228, true, false),
            (XMP_AT - PREVIEW_AT, 384, false, true),
        ] {
            for (entry, (start, length)) in [
                (PREVIEW_AT, preview_len),
                (RECORDS_AT, 12),
                (CFA_AT, TIFF.len()),
            ]
            .into_iter()
            .enumerate()
            {
                let at = DIRECTORY_OFFSET as usize + entry * 8;
                file[at..at + 4].copy_from_slice(&(start as u32).to_be_bytes());
                file[at + 4..at + 8].copy_from_slice(&(length as u32).to_be_bytes());
            }
            let prefix = &file[..SIGNATURE.len()];
            let mut scratch = vec![0; allowance];
            let input = Input::new(
                prefix,
                file.len() as u64,
                &mut scratch,
                |at, out: &mut [u8]| {
                    let at = at as usize;
                    assert!(!(PREVIEW_AT + 6..XMP_AT).contains(&at));
                    out.copy_from_slice(&file[at..at + out.len()]);
                    Ok::<_, Infallible>(())
                },
            );
            let format = Format::detect(prefix);
            assert!(format.is_some());
            let Some(format) = format else {
                return;
            };
            assert_eq!(format.mime(), b"image/x-fuji-raf");
            let mut fields = Vec::new();
            let Ok(()) = format.visit_text(input, 32, &mut |kind, value| {
                fields.push((kind, value.to_vec()));
                Ok(())
            });
            let mut expected = vec![
                (1, b"image/x-fuji-raf".to_vec()),
                (112, b"6000x4000".to_vec()),
            ];
            if expect_xmp {
                expected.push((41, b"Dakar".to_vec()));
            }
            if expect_cfa {
                expected.push((95, b"Cam".to_vec()));
            }
            assert_eq!(fields, expected);
        }
    }
}
