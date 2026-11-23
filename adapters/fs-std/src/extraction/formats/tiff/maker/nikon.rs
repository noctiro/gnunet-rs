//! Nikon MakerNote headers, bounded embedded TIFF and RAW identification data.

use super::super::{Kind, ProfileKind, Row, Selection, Tiff};

const TIFF_OFFSET: u64 = 10;
const NRW_DATA: u16 = 0x0014;
const NRW_SIGNATURE: &[u8] = b"NRW ";

pub(in crate::extraction::formats::tiff) enum Header {
    Bare,
    ParentRelative,
    Embedded,
}

impl Header {
    pub(in crate::extraction::formats::tiff) fn parse(header: &[u8]) -> Option<Self> {
        match header.strip_prefix(b"Nikon\0") {
            Some([1, ..]) => Some(Self::ParentRelative),
            Some([2, ..]) => Some(Self::Embedded),
            Some(_) => None,
            None => Some(Self::Bare),
        }
    }
}

pub(in crate::extraction::formats::tiff) fn open_embedded<
    'reader,
    E,
    Read: FnMut(u64, &mut [u8]) -> Result<(), E>,
>(
    tiff: &'reader mut Tiff<'_, Read>,
    row: Row,
) -> Result<Option<Tiff<'reader, &'reader mut Read>>, E> {
    let Some(section) = tiff.section_for_field_from(row, TIFF_OFFSET) else {
        return Ok(None);
    };
    Tiff::open(section, ProfileKind::Embedded)
}

/// Identifies RAW-capable Nikon MakerNotes and their NRW-specific color data.
pub(in crate::extraction::formats::tiff) fn raw_identity<E>(
    tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    row: Row,
) -> Result<Option<RawIdentity>, E> {
    if row.kind() != Kind::Undefined {
        return Ok(None);
    }
    let Some(header) = tiff.read_field_range(&row, 0, 7)?.and_then(Header::parse) else {
        return Ok(None);
    };
    match header {
        Header::Bare => Ok(None),
        Header::ParentRelative => {
            // Type 2 uses its containing TIFF's offsets and byte order.
            let order = tiff.byte_order();
            Ok(tiff
                .parent_relative_maker(row, 8, order, super::DirectoryTail::RowsOnly)?
                .map(|_| RawIdentity::Nikon))
        }
        Header::Embedded => {
            let Some(mut note) = open_embedded(tiff, row)? else {
                return Ok(None);
            };
            let offset = note.first_offset();
            let Some(fields) = Selection::read(&mut note, offset, |tag| tag == NRW_DATA)? else {
                return Ok(None);
            };
            let Some(field) = fields.find(NRW_DATA).filter(|field| {
                !field.duplicate && matches!(field.row.kind(), Kind::Undefined | Kind::Byte)
            }) else {
                return Ok(Some(RawIdentity::Nikon));
            };
            let prefix = note.read_field_range(&field.row, 0, NRW_SIGNATURE.len())?;
            Ok(Some(if prefix == Some(NRW_SIGNATURE) {
                RawIdentity::Nrw
            } else {
                RawIdentity::Nikon
            }))
        }
    }
}

pub(in crate::extraction::formats::tiff) enum RawIdentity {
    Nikon,
    Nrw,
}
