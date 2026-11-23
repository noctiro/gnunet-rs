//! Conventional Panasonic MakerNote camera settings.

use super::{
    ByteOrder, DirectoryTail, Field, Fields, IMAGE_QUALITY, MACRO_MODE, NoteLayout, WHITE_BALANCE,
};

const HEADER_BYTES: usize = 12;

pub(super) fn layout(header: &[u8], order: ByteOrder) -> Option<NoteLayout> {
    (header.len() >= HEADER_BYTES && header.starts_with(b"Panasonic")).then_some(
        NoteLayout::Parent {
            order,
            displacement: HEADER_BYTES as u64,
            tail: DirectoryTail::RowsOnly,
            fields: Fields::Panasonic,
        },
    )
}

pub(super) fn field(tag: u16) -> Option<(u32, Field)> {
    Some(match tag {
        0x0001 => (IMAGE_QUALITY, Field::Label(QUALITY)),
        0x0003 => (WHITE_BALANCE, Field::Label(BALANCE)),
        0x001c => (MACRO_MODE, Field::Label(MACRO)),
        _ => return None,
    })
}

const QUALITY: &[(u16, &str)] = &[
    (1, "TIFF"),
    (2, "High"),
    (3, "Normal"),
    (6, "Very High"),
    (7, "RAW"),
    (9, "Motion Picture"),
    (11, "Full HD Movie"),
    (12, "4K Movie"),
];

const BALANCE: &[(u16, &str)] = &[
    (1, "Auto"),
    (2, "Daylight"),
    (3, "Cloudy"),
    (4, "Incandescent"),
    (5, "Manual"),
    (8, "Flash"),
    (10, "Black and white"),
    (11, "Manual 2"),
    (12, "Shade"),
    (13, "Kelvin"),
    (14, "Manual 3"),
    (15, "Manual 4"),
    (19, "Auto (cool)"),
];

const MACRO: &[(u16, &str)] = &[
    (1, "On"),
    (2, "Off"),
    (0x101, "Tele-macro"),
    (0x201, "Macro zoom"),
];
