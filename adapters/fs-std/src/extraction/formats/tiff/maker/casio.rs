//! Casio's classic camera IFD and the QVC/DCI Type 2 layout.

use super::{
    Directory, DirectoryTail, EXPOSURE_PROGRAM, FLASH, Field, IMAGE_QUALITY, ISO_SPEED, Kind,
    MACRO_MODE, NoteLayout, Selection, Tiff, WHITE_BALANCE, classic_ifd_order, emit_field,
};

pub(super) enum Make {
    Casio,
    Concord,
}

#[derive(Clone, Copy)]
pub(super) enum Format {
    Classic,
    Type2,
}

pub(super) fn layout(header: &[u8], make: Make) -> Option<NoteLayout> {
    let format = match (make, header) {
        (Make::Casio, [b'Q', b'V', b'C', 0, ..]) | (Make::Concord, [b'D', b'C', b'I', 0, ..]) => {
            Format::Type2
        }
        (Make::Casio, [b'D', b'C', b'I', 0, ..]) | (Make::Concord, _) => return None,
        (Make::Casio, _) => Format::Classic,
    };
    let type_at = usize::try_from(format.displacement()).ok()? + 4;
    let order = classic_ifd_order(header.get(type_at..type_at + 2)?)?;
    Some(NoteLayout::Casio(order, format))
}

impl Format {
    pub(super) const fn displacement(self) -> u64 {
        match self {
            Self::Classic => 0,
            Self::Type2 => 6,
        }
    }

    pub(super) const fn tail(self) -> DirectoryTail {
        match self {
            Self::Classic => DirectoryTail::RowsOnly,
            Self::Type2 => DirectoryTail::NextOffset,
        }
    }

    pub(super) fn visit<E>(
        self,
        tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        directory: Directory,
        limit: usize,
        emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        let properties = match self {
            Self::Classic => CLASSIC,
            Self::Type2 => TYPE_2,
        };
        let Some(selection) = Selection::read_directory(tiff, directory, |tag| {
            properties
                .iter()
                .any(|&(_, candidates)| candidates.iter().any(|&(candidate, _)| candidate == tag))
        })?
        else {
            return Ok(());
        };
        for &(kind, candidates) in properties {
            for &(tag, field) in candidates {
                if let Some(selected) = selection.find(tag).filter(|selected| !selected.duplicate)
                    && emit_field(tiff, selected.row, kind, field, limit, emit)?
                {
                    break;
                }
            }
        }
        Ok(())
    }
}

type Property = (u32, &'static [(u16, Field)]);

const fn labels(values: &'static [(u32, &'static str)]) -> Field {
    Field::KnownLabel(Kind::Short, values)
}

const QUALITY: Field = labels(&[(1, "Economy"), (2, "Normal"), (3, "Fine")]);
const ISO: Field = Field::IntegerIso(Kind::Short);

const CLASSIC: &[Property] = &[
    (IMAGE_QUALITY, &[(0x0002, QUALITY)]),
    (MACRO_MODE, &[(0x0003, labels(CLASSIC_FOCUS))]),
    (
        FLASH,
        &[(0x0004, labels(&[(1, "Auto"), (2, "On"), (3, "Off")]))],
    ),
    (WHITE_BALANCE, &[(0x0007, labels(CLASSIC_BALANCE))]),
    (ISO_SPEED, &[(0x0014, ISO)]),
];

const TYPE_2: &[Property] = &[
    (
        IMAGE_QUALITY,
        &[(0x3002, QUALITY), (0x0008, labels(TYPE_2_QUALITY))],
    ),
    (
        MACRO_MODE,
        &[
            (0x3003, labels(TYPE_2_FOCUS)),
            (0x000d, labels(&[(0, "Off"), (1, "On")])),
        ],
    ),
    (
        WHITE_BALANCE,
        &[
            (0x2012, labels(TYPE_2_BALANCE_EXTENDED)),
            (0x0019, labels(TYPE_2_BALANCE)),
        ],
    ),
    (EXPOSURE_PROGRAM, &[(0x3000, labels(TYPE_2_PROGRAM))]),
    (ISO_SPEED, &[(0x3014, ISO), (0x0014, labels(TYPE_2_ISO))]),
];

const CLASSIC_FOCUS: &[(u32, &str)] = &[(2, "On"), (3, "Off"), (4, "Off"), (5, "Off"), (7, "Off")];
const CLASSIC_BALANCE: &[(u32, &str)] = &[
    (1, "Auto"),
    (2, "Tungsten"),
    (3, "Daylight"),
    (4, "Fluorescent"),
    (5, "Shade"),
    (129, "Manual"),
];
const TYPE_2_QUALITY: &[(u32, &str)] = &[(0, "Economy"), (1, "Normal"), (2, "Fine")];
const TYPE_2_FOCUS: &[(u32, &str)] = &[
    (2, "On"),
    (3, "Off"),
    (5, "Off"),
    (6, "Off"),
    (8, "Super Macro"),
];
const TYPE_2_BALANCE: &[(u32, &str)] = &[
    (0, "Auto"),
    (1, "Daylight"),
    (2, "Shade"),
    (3, "Tungsten"),
    (4, "Fluorescent"),
    (5, "Manual"),
];
const TYPE_2_BALANCE_EXTENDED: &[(u32, &str)] = &[
    (0, "Manual"),
    (1, "Daylight"),
    (2, "Cloudy"),
    (3, "Shade"),
    (6, "Fluorescent"),
    (10, "Tungsten"),
    (12, "Flash"),
];
const TYPE_2_PROGRAM: &[(u32, &str)] = &[
    (2, "Program AE"),
    (3, "Shutter Priority"),
    (4, "Aperture Priority"),
    (5, "Manual"),
    (6, "Best Shot"),
];
const TYPE_2_ISO: &[(u32, &str)] = &[(3, "50"), (4, "64"), (6, "100"), (9, "200")];
