//! Minolta's classic IFD, packed camera settings and Olympus-compatible notes.

use super::{
    ByteOrder, Directory, DirectoryTail, EXPOSURE_PROGRAM, FLASH, Field, Fields, IMAGE_QUALITY,
    ISO_SPEED, Kind, METERING_MODE, NoteLayout, Selection, Tiff, WHITE_BALANCE, classic_ifd_order,
    emit_selection,
};

const LEGACY_SETTINGS: u16 = 0x0001;
const CLASSIC_SETTINGS: u16 = 0x0003;
const SETTINGS_7D: u16 = 0x0004;
const SETTINGS_5D: u16 = 0x0114;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::extraction::formats::tiff) enum Model {
    Unknown,
    ClassicSettings,
    DiMageX31,
    FiveD,
}

impl Model {
    pub(super) const MAX_BYTES: usize = 64;

    pub(super) fn from_ascii(bytes: Option<&[u8]>) -> Self {
        let Some(name) = bytes
            .filter(|bytes| bytes.len() <= Self::MAX_BYTES)
            .and_then(|bytes| bytes.split(|&byte| byte == 0).next())
            .map(<[u8]>::trim_ascii)
            .filter(|name| !name.is_empty() && name.is_ascii())
        else {
            return Self::Unknown;
        };
        if name.eq_ignore_ascii_case(b"DiMAGE X31") {
            Self::DiMageX31
        } else if [b"DYNAX 5D".as_slice(), b"MAXXUM 5D", b"ALPHA SWEET"]
            .iter()
            .any(|prefix| {
                name.get(..prefix.len())
                    .is_some_and(|start| start.eq_ignore_ascii_case(prefix))
            })
        {
            Self::FiveD
        } else {
            Self::ClassicSettings
        }
    }
}

pub(super) fn layout(header: &[u8], inherited: ByteOrder, model: Model) -> Option<NoteLayout> {
    for signature in [b"MINOL\0", b"CAMER\0"] {
        if header.starts_with(signature) {
            let order = classic_ifd_order(header.get(12..14)?)?;
            return Some(NoteLayout::Parent {
                order,
                displacement: 8,
                tail: DirectoryTail::RowsOnly,
                fields: Fields::Olympus,
            });
        }
    }
    if [
        b"MINOL".as_slice(),
        b"CAMER",
        b"MLY0",
        b"KC",
        b"+M+M",
        b"\xd7",
    ]
    .iter()
    .any(|signature| header.starts_with(signature))
    {
        return None;
    }
    let order = match header.get(2..10) {
        Some([0, 0, 0, 7, 0, 0, 0, 4]) => ByteOrder::Big,
        Some([0, 0, 7, 0, 4, 0, 0, 0]) => ByteOrder::Little,
        _ => inherited,
    };
    Some(NoteLayout::Minolta(order, model))
}

pub(super) fn field(tag: u16) -> Option<(u32, Field)> {
    let (kind, labels) = match tag {
        0x0102 => (IMAGE_QUALITY, QUALITY),
        0x0115 => (WHITE_BALANCE, BALANCE),
        _ => return None,
    };
    Some((kind, Field::KnownLabel(Kind::Long, labels)))
}

pub(super) fn visit_directory<E>(
    tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    directory: Directory,
    model: Model,
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    let layouts = [
        (
            SETTINGS_5D,
            (model == Model::FiveD).then_some(Settings::FiveD),
        ),
        (SETTINGS_7D, Some(Settings::SevenD)),
        (
            CLASSIC_SETTINGS,
            matches!(model, Model::ClassicSettings | Model::FiveD).then_some(Settings::Legacy),
        ),
        (LEGACY_SETTINGS, Some(Settings::Legacy)),
    ];
    let Some(selection) = Selection::read_directory(tiff, directory, |tag| {
        layouts
            .iter()
            .any(|&(candidate, layout)| candidate == tag && layout.is_some())
            || field(tag).is_some()
    })?
    else {
        return Ok(());
    };
    let mut quality = false;
    let mut balance = false;
    emit_selection(
        tiff,
        &selection,
        Fields::Minolta,
        limit,
        &mut |kind, value| {
            quality |= kind == IMAGE_QUALITY;
            balance |= kind == WHITE_BALANCE;
            emit(kind, value)
        },
    )?;

    for (tag, layout) in layouts {
        let Some(layout) = layout else { continue };
        let Some(settings) = selection.find(tag).filter(|field| {
            !field.duplicate
                && field.row.kind() == Kind::Undefined
                && field.row.len().is_multiple_of(layout.word_bytes())
        }) else {
            continue;
        };
        let Some(prefix) = tiff.read_field_range(&settings.row, 0, layout.prefix_bytes())? else {
            continue;
        };
        layout.visit(prefix, limit, &mut |kind, value| match kind {
            IMAGE_QUALITY if quality => Ok(()),
            WHITE_BALANCE if balance => Ok(()),
            _ => emit(kind, value),
        })?;
        break;
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Settings {
    Legacy,
    SevenD,
    FiveD,
}

impl Settings {
    fn word_bytes(self) -> usize {
        match self {
            Self::Legacy => 4,
            Self::SevenD | Self::FiveD => 2,
        }
    }

    fn prefix_bytes(self) -> usize {
        match self {
            Self::Legacy => 9 * self.word_bytes(),
            Self::SevenD => 29 * self.word_bytes(),
            Self::FiveD => 39 * self.word_bytes(),
        }
    }

    fn word(self, prefix: &[u8], index: usize) -> Option<u32> {
        let bytes = prefix.get(index * self.word_bytes()..)?;
        match self {
            Self::Legacy => Some(u32::from_be_bytes(*bytes.first_chunk()?)),
            Self::SevenD | Self::FiveD => Some(u16::from_be_bytes(*bytes.first_chunk()?).into()),
        }
    }

    fn visit<E>(
        self,
        prefix: &[u8],
        limit: usize,
        emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        let field_value = |index, labels: &[(u32, &'static str)]| {
            let value = self.word(prefix, index)?;
            labels
                .iter()
                .find_map(|&(code, label)| (code == value).then_some(label))
        };
        let (fields, sensitivity) = match self {
            Self::Legacy => (
                [
                    (EXPOSURE_PROGRAM, field_value(1, &PROGRAM[..4])),
                    (FLASH, field_value(2, FLASH_MODE)),
                    (WHITE_BALANCE, field_value(3, LEGACY_BALANCE)),
                    (IMAGE_QUALITY, field_value(5, QUALITY)),
                    (METERING_MODE, field_value(7, METERING)),
                ],
                self.word(prefix, 8).and_then(legacy_sensitivity),
            ),
            Self::SevenD => (
                [
                    (EXPOSURE_PROGRAM, field_value(0, PROGRAM)),
                    (IMAGE_QUALITY, field_value(3, DSLR_QUALITY)),
                    (WHITE_BALANCE, field_value(4, BALANCE_7D)),
                    (FLASH, field_value(0x15, FLASH_7D)),
                    (METERING_MODE, None),
                ],
                self.word(prefix, 0x1c).and_then(dslr_sensitivity),
            ),
            Self::FiveD => (
                [
                    (EXPOSURE_PROGRAM, field_value(0x0a, &PROGRAM[..4])),
                    (IMAGE_QUALITY, field_value(0x0d, DSLR_QUALITY)),
                    (WHITE_BALANCE, field_value(0x0e, BALANCE_5D)),
                    (FLASH, field_value(0x1f, FLASH_5D)),
                    (METERING_MODE, field_value(0x25, METERING)),
                ],
                match self.word(prefix, 0x26) {
                    Some(8) => Some(200),
                    Some(10) => Some(80),
                    code => code.and_then(dslr_sensitivity),
                },
            ),
        };
        for (kind, value) in fields {
            if let Some(value) = value.filter(|value| value.len() <= limit) {
                emit(kind, value.as_bytes())?;
            }
        }
        if let Some(sensitivity) = sensitivity {
            let value = sensitivity.to_string();
            if value.len() <= limit {
                emit(ISO_SPEED, value.as_bytes())?;
            }
        }
        Ok(())
    }
}

fn dslr_sensitivity(code: u32) -> Option<u32> {
    match code {
        1 => Some(100),
        3..=7 => Some(200 << (code - 3)),
        _ => None,
    }
}

fn legacy_sensitivity(value: u32) -> Option<u32> {
    let sensitivity = (100.0 * ((f64::from(value) - 48.0) / 8.0).exp2()).round();
    (1.0..=f64::from(u32::MAX))
        .contains(&sensitivity)
        .then_some(sensitivity as u32)
}

const QUALITY: &[(u32, &str)] = &[
    (0, "RAW"),
    (1, "Super Fine"),
    (2, "Fine"),
    (3, "Standard"),
    (4, "Economy"),
    (5, "Extra Fine"),
];

const BALANCE: &[(u32, &str)] = &[
    (0, "Auto"),
    (1, "Color Temperature/Color Filter"),
    (0x10, "Daylight"),
    (0x20, "Cloudy"),
    (0x30, "Shade"),
    (0x40, "Tungsten"),
    (0x50, "Flash"),
    (0x60, "Fluorescent"),
    (0x70, "Custom"),
];

const PROGRAM: &[(u32, &str)] = &[
    (0, "Program"),
    (1, "Aperture Priority"),
    (2, "Shutter Priority"),
    (3, "Manual"),
    (4, "Auto"),
    (5, "Program-shift A"),
    (6, "Program-shift S"),
];

const FLASH_MODE: &[(u32, &str)] = &[
    (0, "Fill flash"),
    (1, "Red-eye reduction"),
    (2, "Rear flash sync"),
    (3, "Wireless"),
];

const LEGACY_BALANCE: &[(u32, &str)] = &[
    (0, "Auto"),
    (1, "Daylight"),
    (2, "Cloudy"),
    (3, "Tungsten"),
    (5, "Custom"),
    (7, "Fluorescent"),
    (8, "Fluorescent 2"),
    (11, "Custom 2"),
    (12, "Custom 3"),
    (0x0080_0000, "Auto"),
    (0x0180_0000, "Daylight"),
    (0x0280_0000, "Cloudy"),
    (0x0380_0000, "Tungsten"),
    (0x0480_0000, "Flash"),
    (0x0580_0000, "Fluorescent"),
    (0x0680_0000, "Shade"),
];

const METERING: &[(u32, &str)] = &[
    (0, "Multi-segment"),
    (1, "Center-weighted average"),
    (2, "Spot"),
];

const DSLR_QUALITY: &[(u32, &str)] = &[
    (0, "RAW"),
    (16, "Fine"),
    (32, "Normal"),
    (34, "RAW+JPEG"),
    (48, "Economy"),
];

const BALANCE_7D: &[(u32, &str)] = &[
    (0, "Auto"),
    (1, "Daylight"),
    (2, "Shade"),
    (3, "Cloudy"),
    (4, "Tungsten"),
    (5, "Fluorescent"),
    (0x100, "Kelvin"),
    (0x200, "Manual"),
];

const FLASH_7D: &[(u32, &str)] = &[(0, "Off"), (1, "On")];

const BALANCE_5D: &[(u32, &str)] = &[
    (0, "Auto"),
    (1, "Daylight"),
    (2, "Cloudy"),
    (3, "Shade"),
    (4, "Tungsten"),
    (5, "Fluorescent"),
    (6, "Flash"),
    (0x100, "Kelvin"),
    (0x200, "Manual"),
];

const FLASH_5D: &[(u32, &str)] = &[(0, "Did not fire"), (1, "Fired")];
