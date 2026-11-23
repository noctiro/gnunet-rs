//! Camera-specific EXIF MakerNotes projected into GNU metadata fields.

use super::{
    Directory, ISO_SPEED, Kind, Row, Selection, Tiff,
    reader::{ByteOrder, DirectoryTail, Entry},
};
use std::borrow::Cow;

pub(super) mod canon;
mod casio;
mod epson;
pub(super) mod kodak;
mod minolta;
pub(super) mod nikon;
mod panasonic;
mod pentax;
mod ricoh;
mod samsung;
mod sanyo;
pub(super) mod sony;

pub(super) use kodak::CaptureFields;

#[cfg(test)]
mod tests;

pub(super) const TAG: u16 = 0x927c;
pub(super) const MAKE: u16 = 0x010f;
pub(super) const MODEL: u16 = 0x0110;
const FLASH: u32 = 100;
const FOCAL_LENGTH_35MM: u32 = 103;
const EXPOSURE_PROGRAM: u32 = 105;
const METERING_MODE: u32 = 106;
const MACRO_MODE: u32 = 107;
const IMAGE_QUALITY: u32 = 108;
const WHITE_BALANCE: u32 = 109;
const RATING: u32 = 175;
const MAKE_PREFIX_BYTES: usize = b"Konica Minolta".len();
const HEADER_BYTES: usize = 16;
const FUJI_HEADER_BYTES: u64 = 12;
const OLYMPUS_CAMERA_SETTINGS: u16 = 0x2020;

#[derive(Clone, Copy)]
pub(super) enum Vendor {
    Canon,
    Casio,
    Concord,
    Epson,
    Fujifilm,
    Kodak,
    Minolta(minolta::Model),
    Nikon,
    Olympus,
    Panasonic,
    Pentax,
    Ricoh,
    Samsung(samsung::Model),
    Sanyo,
    Sony(sony::Model),
}

impl Vendor {
    pub(super) fn read<E>(
        tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        image: &Selection,
    ) -> Result<Option<Self>, E> {
        let Some(make) = image
            .find(MAKE)
            .filter(|field| !field.duplicate && field.row.kind() == Kind::Ascii)
        else {
            return Ok(None);
        };
        let Some(prefix) =
            tiff.read_field_range(&make.row, 0, make.row.len().min(MAKE_PREFIX_BYTES))?
        else {
            return Ok(None);
        };
        let Some(vendor) = Self::from_prefix(prefix) else {
            return Ok(None);
        };
        let model_limit = match vendor {
            Self::Kodak => kodak::MAX_MODEL_BYTES,
            Self::Minolta(_) | Self::Samsung(_) => minolta::Model::MAX_BYTES,
            Self::Sony(_) => sony::Model::MAX_BYTES,
            _ => return Ok(Some(vendor)),
        };
        let model = if let Some(field) = image.find(MODEL).filter(|field| {
            !field.duplicate && field.row.kind() == Kind::Ascii && field.row.len() <= model_limit
        }) {
            tiff.read_field_range(&field.row, 0, field.row.len())?
        } else {
            None
        };
        if matches!(vendor, Self::Kodak) && !kodak::is_p_series(model) {
            return Ok(None);
        }
        Ok(Some(vendor.with_model(model)))
    }

    fn from_prefix(prefix: &[u8]) -> Option<Self> {
        let starts_with = |make: &[u8]| {
            prefix
                .get(..make.len())
                .is_some_and(|bytes| bytes.eq_ignore_ascii_case(make))
        };
        if prefix.starts_with(b"Canon") {
            Some(Self::Canon)
        } else if starts_with(b"CASIO") {
            Some(Self::Casio)
        } else if starts_with(b"Concord") {
            Some(Self::Concord)
        } else if starts_with(b"SEIKO EPSON") || starts_with(b"EPSON") {
            Some(Self::Epson)
        } else if prefix.starts_with(b"FUJI") {
            Some(Self::Fujifilm)
        } else if kodak::is_kodak_make(prefix) {
            Some(Self::Kodak)
        } else if starts_with(b"Minolta") || starts_with(b"Konica Minolta") {
            Some(Self::Minolta(minolta::Model::Unknown))
        } else if prefix.starts_with(b"NIKON") {
            Some(Self::Nikon)
        } else if [b"OLYMPUS".as_slice(), b"OM Digital", b"OM SYSTEM"]
            .iter()
            .any(|maker| prefix.starts_with(maker))
        {
            Some(Self::Olympus)
        } else if [b"Panasonic".as_slice(), b"LEICA", b"Leica"]
            .iter()
            .any(|maker| prefix.starts_with(maker))
        {
            Some(Self::Panasonic)
        } else if prefix.starts_with(b"RICOH") || prefix.starts_with(b"PENTAX RICOH") {
            Some(Self::Ricoh)
        } else if prefix.starts_with(b"PENTAX") {
            Some(Self::Pentax)
        } else if starts_with(b"Samsung") {
            Some(Self::Samsung(samsung::Model::Unknown))
        } else if starts_with(b"Sanyo") {
            Some(Self::Sanyo)
        } else if prefix.starts_with(b"SONY") {
            Some(Self::Sony(sony::Model::Other))
        } else {
            None
        }
    }

    fn with_model(self, model: Option<&[u8]>) -> Self {
        match self {
            Self::Minolta(_) => Self::Minolta(minolta::Model::from_ascii(model)),
            Self::Samsung(_) => Self::Samsung(samsung::Model::from_ascii(model)),
            Self::Sony(_) => Self::Sony(sony::Model::from_ascii(model)),
            _ => self,
        }
    }

    fn layout(self, header: &[u8], inherited: ByteOrder) -> Option<NoteLayout> {
        Some(match self {
            Self::Canon => NoteLayout::Canon,
            Self::Casio => return casio::layout(header, casio::Make::Casio),
            Self::Concord => return casio::layout(header, casio::Make::Concord),
            Self::Epson => return epson::layout(header, inherited),
            Self::Kodak => return kodak::bare_order(header).map(NoteLayout::Kodak),
            Self::Fujifilm => {
                let offset = *header.strip_prefix(b"FUJIFILM")?.first_chunk()?;
                NoteLayout::Relative {
                    order: ByteOrder::Little,
                    first: u64::from(u32::from_le_bytes(offset)),
                    data_start: FUJI_HEADER_BYTES,
                    fields: Fields::Fuji,
                }
            }
            Self::Minolta(model) => return minolta::layout(header, inherited, model),
            Self::Nikon => match nikon::Header::parse(header)? {
                nikon::Header::ParentRelative => NoteLayout::Parent {
                    order: inherited,
                    displacement: 8,
                    tail: DirectoryTail::RowsOnly,
                    fields: Fields::NikonNumeric,
                },
                nikon::Header::Embedded => NoteLayout::NikonEmbedded,
                nikon::Header::Bare => NoteLayout::Parent {
                    order: inherited,
                    displacement: 0,
                    tail: DirectoryTail::RowsOnly,
                    fields: Fields::NikonAscii,
                },
            },
            Self::Olympus => {
                if let Some(version) = header.strip_prefix(b"OLYMP\0") {
                    let order = match version.get(..2)? {
                        [1, 0] => ByteOrder::Little,
                        [0, 1] => ByteOrder::Big,
                        _ => inherited,
                    };
                    NoteLayout::Parent {
                        order,
                        displacement: 8,
                        tail: DirectoryTail::RowsOnly,
                        fields: Fields::Olympus,
                    }
                } else {
                    let (marker, first) = if let Some(marker) = header.strip_prefix(b"OLYMPUS\0") {
                        (marker, 12)
                    } else {
                        (header.strip_prefix(b"OM SYSTEM\0\0\0")?, 16)
                    };
                    NoteLayout::Relative {
                        order: ByteOrder::from_marker(marker.get(..2)?)?,
                        first,
                        data_start: first,
                        fields: Fields::Olympus,
                    }
                }
            }
            Self::Panasonic => return panasonic::layout(header, inherited),
            Self::Pentax => return pentax::layout(header),
            Self::Ricoh => return ricoh::layout(header, inherited),
            Self::Samsung(model) => return samsung::layout(header, model),
            Self::Sanyo => return sanyo::layout(header),
            Self::Sony(model) => return sony::layout(header, inherited, model),
        })
    }
}

fn classic_ifd_order(first_field_type: &[u8]) -> Option<ByteOrder> {
    match first_field_type {
        [0, 1..=13] => Some(ByteOrder::Big),
        [1..=13, 0] => Some(ByteOrder::Little),
        _ => None,
    }
}

enum NoteLayout {
    Canon,
    Casio(ByteOrder, casio::Format),
    Epson(ByteOrder),
    Kodak(ByteOrder),
    Minolta(ByteOrder, minolta::Model),
    Samsung(samsung::Note),
    SonySrf,
    Parent {
        order: ByteOrder,
        displacement: u64,
        tail: DirectoryTail,
        fields: Fields,
    },
    Relative {
        order: ByteOrder,
        first: u64,
        data_start: u64,
        fields: Fields,
    },
    NikonEmbedded,
}

#[derive(Clone, Copy)]
enum Fields {
    Fuji,
    Minolta,
    NikonAscii,
    NikonNumeric,
    Olympus,
    OlympusSettings,
    Panasonic,
    Pentax,
    Ricoh,
    Samsung(Option<samsung::FocalLengthScale>),
    Sanyo,
    Sony,
}

impl Fields {
    fn field(self, tag: u16) -> Option<(u32, Field)> {
        Some(match (self, tag) {
            (Self::Fuji, 0x1000) | (Self::NikonAscii, 0x0004) => (IMAGE_QUALITY, Field::Ascii),
            (Self::Fuji, 0x1002) => (WHITE_BALANCE, Field::Label(FUJI_WHITE_BALANCE)),
            (Self::Fuji, 0x1020) => (MACRO_MODE, Field::Label(OFF_ON)),
            (Self::NikonAscii, 0x0002) => (ISO_SPEED, Field::NikonIso),
            (Self::NikonAscii, 0x0005) => (WHITE_BALANCE, Field::Ascii),
            (Self::NikonNumeric, 0x0003) => (IMAGE_QUALITY, Field::Label(NIKON_QUALITY)),
            (Self::NikonNumeric, 0x0006) => (ISO_SPEED, Field::CodedIso),
            (Self::NikonNumeric, 0x0007) => (WHITE_BALANCE, Field::Label(NIKON_WHITE_BALANCE)),
            (Self::Olympus, 0x0201) => (IMAGE_QUALITY, Field::Label(OLYMPUS_QUALITY)),
            (Self::OlympusSettings, 0x0603) => {
                (IMAGE_QUALITY, Field::Label(OLYMPUS_SETTINGS_QUALITY))
            }
            (Self::Olympus, 0x0202) | (Self::OlympusSettings, 0x0300) => {
                (MACRO_MODE, Field::Label(OLYMPUS_MACRO))
            }
            (Self::OlympusSettings, 0x0500) => (WHITE_BALANCE, Field::Label(OLYMPUS_WHITE_BALANCE)),
            (Self::Minolta, tag) => return minolta::field(tag),
            (Self::Panasonic, tag) => return panasonic::field(tag),
            (Self::Pentax, tag) => return pentax::field(tag),
            (Self::Ricoh, tag) => return ricoh::field(tag),
            (Self::Samsung(scale), tag) => return samsung::field(tag, scale),
            (Self::Sanyo, tag) => return sanyo::field(tag),
            (Self::Sony, tag) => return sony::field(tag),
            _ => return None,
        })
    }
}

pub(super) fn visit<E>(
    tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    row: Row,
    vendor: Vendor,
    observed: CaptureFields,
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    if row.kind() != Kind::Undefined {
        return Ok(());
    }
    let order = tiff.byte_order();
    let layout = if matches!(vendor, Vendor::Canon) {
        vendor.layout(&[], order)
    } else {
        tiff.read_field_range(&row, 0, row.len().min(HEADER_BYTES))?
            .and_then(|header| vendor.layout(header, order))
    };
    let Some(layout) = layout else {
        return Ok(());
    };
    match layout {
        NoteLayout::Canon => {
            if let Some(directory) =
                tiff.parent_relative_maker(row, 0, order, DirectoryTail::RowsOnly)?
            {
                canon::visit_directory(tiff, directory, limit, emit)?;
            }
        }
        NoteLayout::Casio(order, format) => {
            if let Some(directory) =
                tiff.parent_relative_maker(row, format.displacement(), order, format.tail())?
            {
                format.visit(tiff, directory, limit, emit)?;
            }
        }
        NoteLayout::Epson(order) => epson::visit(tiff, row, order, limit, emit)?,
        NoteLayout::Kodak(order) => {
            kodak::visit_camera_info(tiff, row, order, observed, limit, emit)?
        }
        NoteLayout::Minolta(order, model) => {
            if let Some(directory) =
                tiff.parent_relative_maker(row, 0, order, DirectoryTail::RowsOnly)?
            {
                minolta::visit_directory(tiff, directory, model, limit, emit)?;
            }
        }
        NoteLayout::Samsung(note) => note.visit(tiff, row, limit, emit)?,
        NoteLayout::SonySrf => sony::visit_srf(tiff, row, limit, emit)?,
        NoteLayout::Parent {
            order,
            displacement,
            tail,
            fields,
        } => {
            if let Some(directory) = tiff.parent_relative_maker(row, displacement, order, tail)? {
                emit_fields(tiff, directory, fields, limit, emit)?;
            }
        }
        NoteLayout::Relative {
            order,
            first,
            data_start,
            fields,
        } => {
            if let Some(note) = tiff.section_for_field(row)
                && let Some(mut maker) = Tiff::open_classic_ifd(note, order, first, data_start)
            {
                if matches!(fields, Fields::Olympus) {
                    if let Some(directory) = maker.maker_directory(first)? {
                        visit_olympus(&mut maker, directory, limit, emit)?;
                    }
                } else if let Some(directory) = maker.directory(first)? {
                    emit_fields(&mut maker, directory, fields, limit, emit)?;
                }
            }
        }
        NoteLayout::NikonEmbedded => {
            if let Some(mut maker) = nikon::open_embedded(tiff, row)?
                && let Some(directory) = maker.directory(maker.first_offset())?
            {
                emit_fields(&mut maker, directory, Fields::NikonAscii, limit, emit)?;
            }
        }
    }
    Ok(())
}

fn visit_olympus<E>(
    maker: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    directory: Directory,
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    let fields = Fields::Olympus;
    let Some(root) = Selection::read_directory(maker, directory, |tag| {
        tag == OLYMPUS_CAMERA_SETTINGS || fields.field(tag).is_some()
    })?
    else {
        return Ok(());
    };
    let mut settings_have_quality = false;
    let mut settings_have_macro = false;
    if let Some(link) = root.find(OLYMPUS_CAMERA_SETTINGS).filter(|field| {
        !field.duplicate
            && matches!(field.row.kind(), Kind::Long | Kind::Ifd)
            && field.row.count() == 1
    }) && let Some(offset) = maker
        .read_field(&link.row)?
        .and_then(|entry| entry.unsigned(0))
        .filter(|&offset| offset != maker.first_offset())
        && let Some(settings) = maker.maker_directory(offset)?
    {
        emit_fields(
            maker,
            settings,
            Fields::OlympusSettings,
            limit,
            &mut |kind, value| {
                settings_have_quality |= kind == IMAGE_QUALITY;
                settings_have_macro |= kind == MACRO_MODE;
                emit(kind, value)
            },
        )?;
    }
    emit_selection(maker, &root, fields, limit, &mut |kind, value| match kind {
        IMAGE_QUALITY if settings_have_quality => Ok(()),
        MACRO_MODE if settings_have_macro => Ok(()),
        _ => emit(kind, value),
    })
}

fn emit_fields<E>(
    maker: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    directory: Directory,
    fields: Fields,
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    if let Some(selection) =
        Selection::read_directory(maker, directory, |tag| fields.field(tag).is_some())?
    {
        emit_selection(maker, &selection, fields, limit, emit)?;
    }
    Ok(())
}

fn emit_selection<E>(
    maker: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    selection: &Selection,
    fields: Fields,
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    for selected in selection
        .rows
        .iter()
        .flatten()
        .filter(|field| !field.duplicate)
    {
        if let Some((kind, field)) = fields.field(selected.row.tag()) {
            emit_field(maker, selected.row, kind, field, limit, emit)?;
        }
    }
    Ok(())
}

fn emit_field<E>(
    maker: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    row: Row,
    kind: u32,
    field: Field,
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<bool, E> {
    if field.accepts(row, limit)
        && let Some(entry) = maker.read_field(&row)?
        && let Some(value) = field.decode(entry)
        && !value.is_empty()
        && value.len() <= limit
    {
        emit(kind, value.as_bytes())?;
        Ok(true)
    } else {
        Ok(false)
    }
}

#[derive(Clone, Copy)]
enum Field {
    Ascii,
    Label(&'static [(u16, &'static str)]),
    KnownLabel(Kind, &'static [(u32, &'static str)]),
    NikonIso,
    CodedIso,
    PentaxIso,
    IntegerIso(Kind),
    LongFocalLength35mm(samsung::FocalLengthScale),
}

impl Field {
    fn accepts(&self, row: Row, limit: usize) -> bool {
        match self {
            Self::Ascii => row.kind() == Kind::Ascii && row.len() <= limit.saturating_add(1),
            Self::Label(_) | Self::CodedIso => row.kind() == Kind::Short && row.count() == 1,
            Self::KnownLabel(kind, _) | Self::IntegerIso(kind) => {
                row.kind() == *kind && row.count() == 1
            }
            Self::NikonIso => row.kind() == Kind::Short && row.count() == 2,
            Self::PentaxIso => matches!(row.kind(), Kind::Short | Kind::Long) && row.count() == 1,
            Self::LongFocalLength35mm(_) => row.kind() == Kind::Long && row.count() == 1,
        }
    }

    fn decode(self, entry: Entry<'_>) -> Option<Cow<'_, str>> {
        Some(match self {
            Self::Ascii => Cow::Borrowed(
                entry
                    .string()?
                    .split('\0')
                    .next()?
                    .trim_start_matches(|ch: char| ch.is_ascii_whitespace()),
            ),
            Self::Label(labels) => {
                let value = u16::try_from(entry.unsigned(0)?).ok()?;
                labels
                    .iter()
                    .find_map(|&(code, label)| (code == value).then_some(Cow::Borrowed(label)))
                    .unwrap_or_else(|| Cow::Owned(format!("({value})")))
            }
            Self::KnownLabel(_, labels) => {
                let value = u32::try_from(entry.unsigned(0)?).ok()?;
                Cow::Borrowed(
                    labels
                        .iter()
                        .find_map(|&(code, label)| (code == value).then_some(label))?,
                )
            }
            Self::NikonIso => Cow::Owned(entry.unsigned(1)?.to_string()),
            Self::CodedIso => Cow::Borrowed(match entry.unsigned(0)? {
                0 => "80",
                2 => "160",
                4 => "320",
                5 => "100",
                _ => return None,
            }),
            Self::PentaxIso => Cow::Owned(pentax::sensitivity(entry.unsigned(0)?)?.to_string()),
            Self::IntegerIso(_) => {
                let value = entry.unsigned(0)?;
                (value != 0).then(|| Cow::Owned(value.to_string()))?
            }
            Self::LongFocalLength35mm(scale) => match (entry.unsigned(0)?, scale) {
                (0, _) => Cow::Borrowed("Unknown"),
                (value, samsung::FocalLengthScale::Decimillimetre) => {
                    Cow::Owned(format!("{}.{} mm", value / 10, value % 10))
                }
                (value, samsung::FocalLengthScale::Millimetre) => {
                    Cow::Owned(format!("{value}.0 mm"))
                }
            },
        })
    }
}

const OFF_ON: &[(u16, &str)] = &[(0, "Off"), (1, "On")];

const NIKON_QUALITY: &[(u16, &str)] = &[
    (1, "VGA Basic"),
    (2, "VGA Normal"),
    (3, "VGA Fine"),
    (4, "SXGA Basic"),
    (5, "SXGA Normal"),
    (6, "SXGA Fine"),
];

const NIKON_WHITE_BALANCE: &[(u16, &str)] = &[
    (0, "Auto"),
    (1, "Preset"),
    (2, "Daylight"),
    (3, "Incandescent"),
    (4, "Fluorescent"),
    (5, "Cloudy"),
    (6, "Speedlight"),
];

const OLYMPUS_MACRO: &[(u16, &str)] = &[(0, "Off"), (1, "On"), (2, "Super Macro")];

const OLYMPUS_QUALITY: &[(u16, &str)] = &[(1, "SQ"), (2, "HQ"), (3, "SHQ"), (6, "RAW")];

const OLYMPUS_SETTINGS_QUALITY: &[(u16, &str)] =
    &[(1, "SQ"), (2, "HQ"), (3, "SHQ"), (4, "RAW"), (5, "SQ (5)")];

const OLYMPUS_WHITE_BALANCE: &[(u16, &str)] = &[
    (0, "Auto"),
    (1, "Auto (Keep Warm Color Off)"),
    (16, "7500 K (Shade)"),
    (17, "6000 K (Cloudy)"),
    (18, "5300 K (Daylight)"),
    (20, "3000 K (Tungsten)"),
    (21, "3600 K (Tungsten-like)"),
    (22, "Auto Setup"),
    (23, "5500 K (Flash)"),
    (33, "6600 K (Daylight Fluorescent)"),
    (34, "4500 K (Neutral White Fluorescent)"),
    (35, "4000 K (Cool White Fluorescent)"),
    (36, "White Fluorescent"),
    (48, "3600 K (Tungsten-like)"),
    (67, "Underwater"),
    (256, "One Touch WB 1"),
    (257, "One Touch WB 2"),
    (258, "One Touch WB 3"),
    (259, "One Touch WB 4"),
    (512, "Custom WB 1"),
    (513, "Custom WB 2"),
    (514, "Custom WB 3"),
    (515, "Custom WB 4"),
];

const FUJI_WHITE_BALANCE: &[(u16, &str)] = &[
    (0, "Auto"),
    (1, "Auto White Priority"),
    (2, "Auto Ambience Priority"),
    (256, "Daylight"),
    (512, "Cloudy"),
    (768, "Fluorescent (daylight)"),
    (769, "Fluorescent (warm white)"),
    (770, "Fluorescent (cool white)"),
    (1024, "Incandescent"),
    (1536, "Underwater"),
    (3480, "Custom"),
    (3840, "Custom 1"),
    (3841, "Custom 2"),
    (3842, "Custom 3"),
    (3843, "Custom 4"),
    (3844, "Custom 5"),
    (4080, "Kelvin"),
];
