//! Classic and self-contained Pentax MakerNote directories.

use super::{
    ByteOrder, DirectoryTail, Field, Fields, IMAGE_QUALITY, ISO_SPEED, METERING_MODE, NoteLayout,
    WHITE_BALANCE,
};

pub(super) fn layout(header: &[u8]) -> Option<NoteLayout> {
    if let Some(order) = header.strip_prefix(b"AOC\0") {
        Some(NoteLayout::Parent {
            order: ByteOrder::from_marker(order.get(..2)?)?,
            displacement: 6,
            tail: DirectoryTail::NextOffset,
            fields: Fields::Pentax,
        })
    } else {
        let order = header.strip_prefix(b"PENTAX \0")?;
        Some(NoteLayout::Relative {
            order: ByteOrder::from_marker(order.get(..2)?)?,
            first: 10,
            data_start: 10,
            fields: Fields::Pentax,
        })
    }
}

pub(super) fn field(tag: u16) -> Option<(u32, Field)> {
    Some(match tag {
        0x0008 => (IMAGE_QUALITY, Field::Label(QUALITY)),
        0x0014 => (ISO_SPEED, Field::PentaxIso),
        0x0017 => (METERING_MODE, Field::Label(METERING)),
        0x0019 => (WHITE_BALANCE, Field::Label(BALANCE)),
        _ => return None,
    })
}

pub(super) fn sensitivity(code: u64) -> Option<u32> {
    const THIRD_STOPS: [u32; 43] = [
        50, 64, 80, 100, 125, 160, 200, 250, 320, 400, 500, 640, 800, 1000, 1250, 1600, 2000, 2500,
        3200, 4000, 5000, 6400, 8000, 10000, 12800, 16000, 20000, 25600, 32000, 40000, 51200,
        64000, 80000, 102400, 128000, 160000, 204800, 256000, 320000, 409600, 512000, 640000,
        819200,
    ];
    const HALF_STOPS: [u32; 29] = [
        50, 70, 100, 140, 200, 280, 400, 560, 800, 1100, 1600, 2200, 3200, 4500, 6400, 9000, 12800,
        18000, 25600, 36000, 51200, 72000, 102400, 144000, 204800, 288000, 409600, 576000, 819200,
    ];
    match code {
        3..=45 => THIRD_STOPS.get((code - 3) as usize).copied(),
        258..=286 => HALF_STOPS.get((code - 258) as usize).copied(),
        50 | 100 | 200 | 400 | 800 | 1600 | 3200 => u32::try_from(code).ok(),
        _ => None,
    }
}

const QUALITY: &[(u16, &str)] = &[
    (0, "Good"),
    (1, "Better"),
    (2, "Best"),
    (3, "TIFF"),
    (4, "RAW"),
    (5, "Premium"),
    (7, "RAW (pixel shift enabled)"),
    (8, "Dynamic Pixel Shift"),
    (9, "Monochrome"),
    (65535, "n/a"),
];

const METERING: &[(u16, &str)] = &[
    (0, "Multi-segment"),
    (1, "Center weighted average"),
    (2, "Spot"),
    (6, "Highlight"),
];

const BALANCE: &[(u16, &str)] = &[
    (0, "Auto"),
    (1, "Daylight"),
    (2, "Shade"),
    (3, "Fluorescent"),
    (4, "Tungsten"),
    (5, "Manual"),
    (6, "Daylight Fluorescent"),
    (7, "Day White Fluorescent"),
    (8, "White Fluorescent"),
    (9, "Flash"),
    (10, "Cloudy"),
    (11, "Warm White Fluorescent"),
    (14, "Multi Auto"),
    (15, "Color Temperature Enhancement"),
    (17, "Kelvin"),
    (65534, "Unknown"),
    (65535, "User-Selected"),
];
