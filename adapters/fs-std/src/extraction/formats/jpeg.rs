//! JPEG (ITU-T T.81) marker metadata shared with Exiv2 EXV sidecars.

use super::{Dimensions, Input, photoshop, tiff};

mod xmp;

const START: &[u8; 2] = b"\xff\xd8";
pub(super) const EXV_SIGNATURE: &[u8; 7] = b"\xff\x01Exiv2";
const EXIF: &[u8; 6] = b"Exif\0\0";
const COMMENT: u32 = 3;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Profiles {
    All,
    // EXIF, IPTC and XMP in an embedded image serving as a metadata carrier.
    Metadata,
    Exif,
}

pub(super) fn visit<E>(
    mut input: Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    max_text_bytes: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    if !input.prefix.starts_with(START) {
        return Ok(());
    }
    // Establish the frame before emitting optional fields. Revisit only the
    // metadata-bearing preamble and retain the same positioned-read budget.
    let mut cursor = START.len() as u64;
    let mut preamble = None;
    let dimensions = loop {
        let Some(segment) = Segment::read(&mut input, &mut cursor)? else {
            return Ok(());
        };
        match segment.marker {
            0xe1 if segment.len >= EXIF.len() + 8 => {
                preamble.get_or_insert(segment.start);
            }
            0xed if segment.len > photoshop::APP13_PREFIX.len() => {
                preamble.get_or_insert(segment.start);
            }
            0xfe if (1..=max_text_bytes).contains(&segment.len) => {
                preamble.get_or_insert(segment.start);
            }
            0xc0..=0xc3 | 0xc5..=0xc7 | 0xc9..=0xcb | 0xcd..=0xcf if segment.len >= 6 => {
                if let Some(size) = input
                    .range(segment.body, 6)?
                    .and_then(|frame| frame_dimensions(frame, segment.len))
                {
                    break size;
                }
            }
            _ => {}
        }
    };
    dimensions.emit(emit)?;
    visit_metadata(
        input,
        preamble.unwrap_or(cursor),
        max_text_bytes,
        Profiles::All,
        emit,
    )
}

pub(super) fn visit_exv<E>(
    mut input: Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    max_text_bytes: usize,
    profiles: Profiles,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    if input.range(0, EXV_SIGNATURE.len())? != Some(EXV_SIGNATURE.as_slice()) {
        return Ok(());
    }
    visit_metadata(
        input,
        EXV_SIGNATURE.len() as u64,
        max_text_bytes,
        profiles,
        emit,
    )
}

pub(super) fn visit_preview<E>(
    mut input: Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    max_text_bytes: usize,
    profiles: Profiles,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    if input.range(0, START.len())? != Some(START.as_slice()) {
        return Ok(());
    }
    visit_metadata(input, START.len() as u64, max_text_bytes, profiles, emit)
}

fn visit_metadata<E>(
    mut input: Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    mut cursor: u64,
    max_text_bytes: usize,
    profiles: Profiles,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    let mut resources = Some(photoshop::Fragments::default());
    let mut xmp = xmp::Packets::default();
    while let Some(segment) = Segment::read(&mut input, &mut cursor)? {
        match segment.marker {
            0xfe if profiles == Profiles::All && (1..=max_text_bytes).contains(&segment.len) => {
                if let Some(body) = input.range(segment.body, segment.len)? {
                    emit(COMMENT, body)?;
                }
            }
            0xe1 if segment.len >= EXIF.len() + 8 => {
                let Some(prefix) = input.range(segment.body, EXIF.len())? else {
                    continue;
                };
                if prefix == EXIF {
                    if let Some(profile) =
                        input.range(segment.body + EXIF.len() as u64, segment.len - EXIF.len())?
                    {
                        tiff::visit_exif(profile, max_text_bytes, emit)?;
                    }
                } else if profiles != Profiles::Exif && prefix == xmp::PROBE_PREFIX {
                    xmp.observe(&mut input, &segment)?;
                }
            }
            0xed if profiles != Profiles::Exif && segment.len > photoshop::APP13_PREFIX.len() => {
                if let Some(fragments) = &mut resources {
                    let prefix = photoshop::APP13_PREFIX.len();
                    if input.range(segment.body, prefix)?
                        == Some(photoshop::APP13_PREFIX.as_slice())
                        && fragments
                            .push(segment.body + prefix as u64, segment.len - prefix)
                            .is_none()
                    {
                        resources = None;
                    }
                }
            }
            _ => {}
        }
    }
    if let Some(resources) = resources {
        resources.visit_iptc(&mut input, max_text_bytes, emit)?;
    }
    xmp.emit(&mut input, max_text_bytes, emit)
}

fn frame_dimensions(header: &[u8], len: usize) -> Option<Dimensions> {
    let header = header.first_chunk::<6>()?;
    let components = usize::from(header[5]);
    if !(2..=16).contains(&header[0]) || components == 0 || len != 6 + 3 * components {
        return None;
    }
    Dimensions::new(
        u16::from_be_bytes([header[3], header[4]]).into(),
        u16::from_be_bytes([header[1], header[2]]).into(),
    )
}

struct Segment {
    start: u64,
    marker: u8,
    body: u64,
    len: usize,
}

impl Segment {
    fn read<E>(
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        cursor: &mut u64,
    ) -> Result<Option<Self>, E> {
        loop {
            let start = *cursor;
            let Some(&[0xff, marker, high, low]) = input.range(start, 4)? else {
                return Ok(None);
            };
            match marker {
                0xff => {
                    *cursor += 1;
                    continue;
                }
                0x01 => {
                    *cursor += 2;
                    continue;
                }
                // Entropy-coded scan data requires a different marker grammar.
                0x00 | 0xd0..=0xda => return Ok(None),
                _ => {}
            }
            let Some(len) = usize::from(u16::from_be_bytes([high, low])).checked_sub(2) else {
                return Ok(None);
            };
            let body = start + 4;
            let Some(next) = body
                .checked_add(len as u64)
                .filter(|&end| end <= input.extent)
            else {
                return Ok(None);
            };
            *cursor = next;
            return Ok(Some(Self {
                start,
                marker,
                body,
                len,
            }));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jpeg_uses_frame_dimensions_and_header_comments() {
        let image = [
            b"\xff\xd8\xff\xfe\x00\x07hello".as_slice(),
            b"\xff\xff\xc2\x00\x0b\x08\x00\x21\x00\x40\x01\x01\x11\x00",
            b"\xff\xda\xff\xfe\x00\x05bad",
        ]
        .concat();
        let mut fields = Vec::new();
        let input = Input::new(
            &image,
            image.len() as u64,
            &mut [],
            |_, _: &mut [u8]| Ok(()),
        );
        let result = visit(input, 64, &mut |kind, text| {
            fields.push((kind, text.to_vec()));
            Ok::<_, std::convert::Infallible>(())
        });
        assert_eq!(result, Ok(()));
        assert_eq!(fields, [(112, b"64x33".to_vec()), (3, b"hello".to_vec())]);
    }

    #[test]
    fn jpeg_reads_exif_after_a_large_unrelated_segment() {
        let mut image = b"\xff\xd8\xff\xe2\x10\x02".to_vec();
        let padding = image.len()..image.len() + 4096;
        image.resize(padding.end, 0);
        image.extend_from_slice(b"\xff\xe1\x00\x10http://ns.xml!");
        image.extend_from_slice(b"\xff\xe1\x00\x22Exif\0\0");
        image.extend_from_slice(b"II*\0\x08\0\0\0\x01\0\x0f\x01\x02\0\x04\0\0\0Cam\0\0\0\0\0");
        image.extend_from_slice(b"\xff\xc0\x00\x0b\x08\0\x21\0\x40\x01\x01\x11\0");
        image.extend_from_slice(b"\xff\xda\0\x08");

        let mut scratch = [0; 100];
        let input = Input::new(
            START,
            image.len() as u64,
            &mut scratch,
            |offset, out: &mut [u8]| {
                let from = offset as usize;
                let to = from + out.len();
                assert!(to <= padding.start || from >= padding.end);
                out.copy_from_slice(&image[from..to]);
                Ok(())
            },
        );
        let mut fields = Vec::new();
        let result = visit(input, 64, &mut |kind, text| {
            fields.push((kind, text.to_vec()));
            Ok::<_, std::convert::Infallible>(())
        });
        assert_eq!(result, Ok(()));
        assert_eq!(fields, [(112, b"64x33".to_vec()), (95, b"Cam".to_vec())]);
    }
}
