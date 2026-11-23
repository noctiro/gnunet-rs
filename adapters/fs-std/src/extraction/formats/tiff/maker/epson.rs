//! Epson's classic camera IFD, also found in TIFF-based ERF files.

use super::{
    ByteOrder, DirectoryTail, Field, IMAGE_QUALITY, Kind, NoteLayout, Row, Selection, Tiff,
    emit_field,
};

const CAMERA_SOFTWARE: u32 = 113;

pub(super) fn layout(header: &[u8], inherited: ByteOrder) -> Option<NoteLayout> {
    // The version following the signature does not select the IFD byte order.
    // The R-D1 ERF uses big-endian IFD rows after version bytes 01 00.
    let version = header.strip_prefix(b"EPSON\0")?.first_chunk::<2>()?;
    (*version == [1, 0]).then_some(NoteLayout::Epson(inherited))
}

pub(super) fn visit<E>(
    tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    note: Row,
    order: ByteOrder,
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    let Some(end) = note
        .external_offset()
        .and_then(|offset| offset.checked_add(note.len() as u64))
    else {
        return Ok(());
    };
    let Some(directory) = tiff.parent_relative_maker(note, 8, order, DirectoryTail::RowsOnly)?
    else {
        return Ok(());
    };
    let start = directory.encoded_end();
    let Some(fields) = Selection::read_directory(tiff, directory, |tag| field(tag).is_some())?
    else {
        return Ok(());
    };
    for selected in fields
        .rows
        .iter()
        .flatten()
        .filter(|selected| !selected.duplicate)
    {
        let row = selected.row;
        let owned = row.external_offset().is_none_or(|offset| {
            offset >= start
                && offset
                    .checked_add(row.len() as u64)
                    .is_some_and(|end_of_value| end_of_value <= end)
        });
        if owned && let Some((kind, value)) = field(row.tag()) {
            emit_field(tiff, row, kind, value, limit, emit)?;
        }
    }
    Ok(())
}

fn field(tag: u16) -> Option<(u32, Field)> {
    Some(match tag {
        0x0201 => (
            IMAGE_QUALITY,
            Field::KnownLabel(Kind::Short, &[(0x10, "RAW")]),
        ),
        0x020d => (CAMERA_SOFTWARE, Field::Ascii),
        _ => return None,
    })
}
