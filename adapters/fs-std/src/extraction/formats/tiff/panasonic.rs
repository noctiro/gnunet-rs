//! Panasonic RAW root fields and bounded supplemental preview EXIF.

use super::super::{Input, jpeg};
use super::{
    Container, GPS_IFD, IPTC_NAA, ISO_SPEED, Kind, PHOTO_IFD, PHOTOSHOP_RESOURCES, ProfileKind,
    Representation, Selection, Tiff, XMP, image_field,
};

const MARKER: &[u8; 4] = b"IIU\0";
const RW2_SIGNATURE: [u8; 16] = [
    0x88, 0xe7, 0x74, 0xd8, 0xf8, 0x25, 0x1d, 0x4d, 0x94, 0x7a, 0x6e, 0x77, 0x82, 0x2b, 0x5d, 0x6a,
];
pub(super) const RW2_HEADER_BYTES: usize = 8 + RW2_SIGNATURE.len();

const SENSOR_WIDTH: u16 = 0x0002;
const SENSOR_HEIGHT: u16 = 0x0003;
const NATIVE_ISO: u16 = 0x0017;
const NATIVE_ISO_LONG: u16 = 0x0037;
const PREVIEW: u16 = 0x002e;
const SECONDARY_PREVIEW: u16 = 0x0127;

fn first_directory(prefix: &[u8]) -> Option<u32> {
    let offset = u32::from_le_bytes(*prefix.strip_prefix(MARKER)?.first_chunk()?);
    (offset >= 8 && offset.is_multiple_of(2)).then_some(offset)
}

pub(super) fn identification_bytes(prefix: &[u8]) -> Option<usize> {
    (first_directory(prefix)? >= RW2_HEADER_BYTES as u32).then_some(RW2_HEADER_BYTES)
}

pub(super) fn container(prefix: &[u8]) -> Option<Container> {
    let first = first_directory(prefix)?;
    if first >= RW2_HEADER_BYTES as u32 && prefix.get(8..RW2_HEADER_BYTES)? == RW2_SIGNATURE {
        Some(Container::Rw2)
    } else {
        Some(Container::PanasonicRaw)
    }
}

pub(super) fn visit<E>(
    input: Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    profile: ProfileKind,
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    let Some(mut tiff) = Tiff::open(input, profile)? else {
        return Ok(());
    };
    let root = tiff.first_offset();
    let Some(image) = Selection::read(&mut tiff, root, |tag| {
        matches!(
            tag,
            SENSOR_WIDTH
                | SENSOR_HEIGHT
                | NATIVE_ISO
                | NATIVE_ISO_LONG
                | PREVIEW
                | SECONDARY_PREVIEW
                | PHOTO_IFD
                | GPS_IFD
                | XMP
                | IPTC_NAA
                | PHOTOSHOP_RESOURCES
        ) || root_field(tag).is_some()
    })?
    else {
        return Ok(());
    };
    if let Some(dimensions) = image.dimensions(&mut tiff, SENSOR_WIDTH, SENSOR_HEIGHT)? {
        dimensions.emit(emit)?;
    }
    // The RAW header and its standard child directories take priority over
    // the JPEG's EXIF projection of the same scalar fields.
    let mut present = [false; 131];
    let mut native = |kind: u32, bytes: &[u8]| {
        if let Some(field) = present.get_mut(kind as usize) {
            *field = true;
        }
        emit(kind, bytes)
    };
    image.emit(&mut tiff, limit, root_field, &mut native)?;
    image.emit_children(&mut tiff, profile, limit, &mut native)?;
    if !present[ISO_SPEED as usize] {
        let iso = match image.dimension(&mut tiff, NATIVE_ISO)? {
            Some(iso) if iso != 0 => Some(iso),
            _ => image
                .dimension(&mut tiff, NATIVE_ISO_LONG)?
                .filter(|&iso| iso != 0),
        };
        if let Some(iso) = iso {
            let value = iso.to_string();
            if value.len() <= limit {
                present[ISO_SPEED as usize] = true;
                emit(ISO_SPEED, value.as_bytes())?;
            }
        }
    }
    image.emit_profiles(&mut tiff, limit, emit)?;
    if let Some(field) = image
        .find(PREVIEW)
        .or_else(|| image.find(SECONDARY_PREVIEW))
        && !field.duplicate
        && field.row.kind() == Kind::Undefined
        && let Some(section) = tiff.section_for_field(field.row)
    {
        jpeg::visit_preview(section, limit, jpeg::Profiles::Exif, &mut |kind, bytes| {
            if !present.get(kind as usize).copied().unwrap_or(false) {
                emit(kind, bytes)?;
            }
            Ok(())
        })?;
    }
    Ok(())
}

fn root_field(tag: u16) -> Option<(u32, Representation)> {
    match tag {
        0x010f | 0x0110 | 0x0112 | 0x013b | 0x8298 => image_field(tag, ProfileKind::Embedded),
        _ => None,
    }
}
