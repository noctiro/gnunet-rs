//! Sony settings stored in headered EXIF and bare RAW MakerNote directories.

mod srf;

use super::{
    ByteOrder, DirectoryTail, Field, Fields, IMAGE_QUALITY, Kind, MACRO_MODE, NoteLayout, RATING,
    Row, Selection, Tiff, WHITE_BALANCE,
};

const DSC_HEADER: &[u8; 12] = b"SONY DSC \0\0\0";
const CAM_HEADER: &[u8; 12] = b"SONY CAM \0\0\0";
const FILE_FORMAT: u16 = 0xb000;

pub(super) use srf::visit as visit_srf;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::extraction::formats::tiff) enum Model {
    Other,
    Srf,
}

impl Model {
    pub(super) const MAX_BYTES: usize = 16;

    pub(super) fn from_ascii(model: Option<&[u8]>) -> Self {
        if model
            .and_then(|model| model.strip_suffix(&[0]))
            .is_some_and(|model| matches!(model.trim_ascii_end(), b"DSC-F828" | b"DSC-V3"))
        {
            Self::Srf
        } else {
            Self::Other
        }
    }
}

pub(super) fn layout(header: &[u8], order: ByteOrder, model: Model) -> Option<NoteLayout> {
    if matches!(order, ByteOrder::Little) && srf::has_signature(header) {
        return (model == Model::Srf).then_some(NoteLayout::SonySrf);
    }
    let (displacement, tail) = directory_layout(header)?;
    Some(NoteLayout::Parent {
        order,
        displacement,
        tail,
        fields: Fields::Sony,
    })
}

fn directory_layout(header: &[u8]) -> Option<(u64, DirectoryTail)> {
    Some(
        if header.starts_with(DSC_HEADER) || header.starts_with(CAM_HEADER) {
            (DSC_HEADER.len() as u64, DirectoryTail::RowsOnly)
        } else if header.starts_with(b"SONY ") {
            return None;
        } else {
            (0, DirectoryTail::NextOffset)
        },
    )
}

#[derive(Clone, Copy)]
pub(in crate::extraction::formats::tiff) enum RawFormat {
    Srf,
    Sr2,
    Arw1,
    Arw,
}

/// Interpret a Sony MakerNote belonging to the root TIFF's EXIF directory.
pub(in crate::extraction::formats::tiff) fn raw_format<E>(
    tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    image: &Selection,
    note: Row,
) -> Result<Option<RawFormat>, E> {
    if note.kind() != Kind::Undefined {
        return Ok(None);
    }
    let order = tiff.byte_order();
    let Some(header) = tiff.read_field_range(&note, 0, note.len().min(srf::HEADER_BYTES))? else {
        return Ok(None);
    };
    if matches!(order, ByteOrder::Little) && srf::first_encrypted_link(header, note).is_some() {
        let Some(model) = image.find(super::MODEL).filter(|model| {
            !model.duplicate
                && model.row.kind() == Kind::Ascii
                && model.row.len() <= Model::MAX_BYTES
        }) else {
            return Ok(None);
        };
        let model = tiff.read_field(&model.row)?.map(|entry| entry.bytes());
        return Ok((Model::from_ascii(model) == Model::Srf).then_some(RawFormat::Srf));
    }
    let Some((displacement, tail)) = directory_layout(header) else {
        return Ok(None);
    };
    let Some(directory) = tiff.parent_relative_maker(note, displacement, order, tail)? else {
        return Ok(None);
    };
    let fields = Selection::read_directory(tiff, directory, |tag| tag == FILE_FORMAT)?;
    let Some(field) = fields
        .as_ref()
        .and_then(|fields| fields.find(FILE_FORMAT))
        .filter(|field| {
            !field.duplicate && field.row.kind() == Kind::Byte && field.row.count() == 4
        })
    else {
        return Ok(None);
    };
    Ok(
        match tiff.read_field(&field.row)?.map(|entry| entry.bytes()) {
            Some([1, 0, 0, 0]) => Some(RawFormat::Sr2),
            Some([2, 0, 0, 0]) => Some(RawFormat::Arw1),
            Some([6, 0, 0, 0] | [3, 0..=2, 0, 0] | [3, 3, 0..=3 | 5, 0] | [4 | 5, 0, 0..=1, 0]) => {
                Some(RawFormat::Arw)
            }
            _ => None,
        },
    )
}

pub(super) fn field(tag: u16) -> Option<(u32, Field)> {
    let (kind, width, labels) = match tag {
        0x0102 => (IMAGE_QUALITY, Kind::Long, QUALITY),
        0x0115 => (WHITE_BALANCE, Kind::Long, BALANCE),
        0x2002 => (RATING, Kind::Long, STARS),
        0xb040 => (MACRO_MODE, Kind::Short, MACRO),
        _ => return None,
    };
    Some((kind, Field::KnownLabel(width, labels)))
}

const QUALITY: &[(u32, &str)] = &[
    (0, "RAW"),
    (1, "Super Fine"),
    (2, "Fine"),
    (3, "Standard"),
    (4, "Economy"),
    (5, "Extra Fine"),
    (6, "RAW + JPEG/HEIF"),
    (7, "Compressed RAW"),
    (8, "Compressed RAW + JPEG"),
    (9, "Light"),
];

const BALANCE: &[(u32, &str)] = &[
    (0x00, "Auto"),
    (0x01, "Color Temperature/Color Filter"),
    (0x10, "Daylight"),
    (0x20, "Cloudy"),
    (0x30, "Shade"),
    (0x40, "Tungsten"),
    (0x50, "Flash"),
    (0x60, "Fluorescent"),
    (0x70, "Custom"),
    (0x80, "Underwater"),
];

const STARS: &[(u32, &str)] = &[(0, "0"), (1, "1"), (2, "2"), (3, "3"), (4, "4"), (5, "5")];
const MACRO: &[(u32, &str)] = &[(0, "Off"), (1, "On"), (2, "Close Focus")];
