//! Ricoh GR MakerNote directories and their camera settings.

use super::{
    ByteOrder, DirectoryTail, EXPOSURE_PROGRAM, FLASH, Field, Fields, Kind, MACRO_MODE, NoteLayout,
    WHITE_BALANCE, pentax,
};

const HEADER_BYTES: u64 = 8;

pub(super) fn layout(header: &[u8], inherited: ByteOrder) -> Option<NoteLayout> {
    if let Some(order) = header
        .strip_prefix(b"RICOH\0")
        .and_then(|marker| ByteOrder::from_marker(marker.get(..2)?))
    {
        return Some(NoteLayout::Relative {
            order,
            first: HEADER_BYTES,
            data_start: HEADER_BYTES,
            fields: Fields::Pentax,
        });
    }
    if header.len() >= HEADER_BYTES as usize && header[..5].eq_ignore_ascii_case(b"Ricoh") {
        return Some(NoteLayout::Parent {
            order: inherited,
            displacement: HEADER_BYTES,
            tail: DirectoryTail::RowsOnly,
            fields: Fields::Ricoh,
        });
    }
    pentax::layout(header)
}

pub(super) fn field(tag: u16) -> Option<(u32, Field)> {
    let (kind, labels) = match tag {
        0x1001 => (EXPOSURE_PROGRAM, PROGRAM),
        0x1003 => (WHITE_BALANCE, BALANCE),
        0x1009 => (MACRO_MODE, MACRO),
        0x100a => (FLASH, FLASH_MODE),
        _ => return None,
    };
    Some((kind, Field::KnownLabel(Kind::Short, labels)))
}

const PROGRAM: &[(u32, &str)] = &[
    (1, "Auto"),
    (2, "Program AE"),
    (3, "Aperture-priority AE"),
    (4, "Shutter speed priority AE"),
    (5, "Shutter/aperture priority AE"),
    (6, "Manual"),
    (7, "Movie"),
];

const BALANCE: &[(u32, &str)] = &[
    (0, "Auto"),
    (1, "Multi-pattern auto"),
    (2, "Daylight"),
    (3, "Cloudy"),
    (4, "Incandescent 1"),
    (5, "Incandescent 2"),
    (6, "Daylight Fluorescent"),
    (7, "Neutral White Fluorescent"),
    (8, "Cool White Fluorescent"),
    (9, "Warm White Fluorescent"),
    (10, "Manual"),
    (11, "Kelvin"),
    (12, "Shade"),
];

const MACRO: &[(u32, &str)] = &[(0, "Off"), (1, "On")];

const FLASH_MODE: &[(u32, &str)] = &[
    (0, "Off"),
    (1, "Auto, fired"),
    (2, "On"),
    (3, "Auto, fired, red-eye reduction"),
    (4, "Slow sync"),
    (5, "Manual"),
    (6, "On, red-eye reduction"),
    (7, "Synchro, red-eye reduction"),
    (8, "Auto, did not fire"),
];
