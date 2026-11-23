//! Sanyo's classic MakerNote directory with inline camera settings.

use super::{
    DirectoryTail, FLASH, Field, Fields, IMAGE_QUALITY, Kind, MACRO_MODE, NoteLayout,
    classic_ifd_order,
};

pub(super) fn layout(header: &[u8]) -> Option<NoteLayout> {
    if !header.starts_with(b"SANYO\0") {
        return None;
    }
    // External offsets vary across Sanyo models. These SHORTs reside in the IFD rows.
    Some(NoteLayout::Parent {
        order: classic_ifd_order(header.get(12..14)?)?,
        displacement: 8,
        tail: DirectoryTail::RowsOnly,
        fields: Fields::Sanyo,
    })
}

pub(super) fn field(tag: u16) -> Option<(u32, Field)> {
    let (kind, labels) = match tag {
        0x0201 => (IMAGE_QUALITY, QUALITY),
        0x0202 => (MACRO_MODE, MACRO),
        0x0225 => (FLASH, FLASH_MODE),
        _ => return None,
    };
    Some((kind, Field::KnownLabel(Kind::Short, labels)))
}

const QUALITY: &[(u32, &str)] = &[
    (0x0000, "Normal/Very Low"),
    (0x0001, "Normal/Low"),
    (0x0002, "Normal/Medium Low"),
    (0x0003, "Normal/Medium"),
    (0x0004, "Normal/Medium High"),
    (0x0005, "Normal/High"),
    (0x0006, "Normal/Very High"),
    (0x0007, "Normal/Super High"),
    (0x0100, "Fine/Very Low"),
    (0x0101, "Fine/Low"),
    (0x0102, "Fine/Medium Low"),
    (0x0103, "Fine/Medium"),
    (0x0104, "Fine/Medium High"),
    (0x0105, "Fine/High"),
    (0x0106, "Fine/Very High"),
    (0x0107, "Fine/Super High"),
    (0x0200, "Super Fine/Very Low"),
    (0x0201, "Super Fine/Low"),
    (0x0202, "Super Fine/Medium Low"),
    (0x0203, "Super Fine/Medium"),
    (0x0204, "Super Fine/Medium High"),
    (0x0205, "Super Fine/High"),
    (0x0206, "Super Fine/Very High"),
    (0x0207, "Super Fine/Super High"),
];

const MACRO: &[(u32, &str)] = &[(0, "Normal"), (1, "Macro"), (2, "View"), (3, "Manual")];

const FLASH_MODE: &[(u32, &str)] = &[(0, "Auto"), (1, "Force"), (2, "Disabled"), (3, "Red eye")];
