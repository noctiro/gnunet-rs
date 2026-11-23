//! Projection of typed TIFF fields into GNU publication metadata.

use super::super::{
    IMAGE_ORIENTATION, ORIENTATION_LABELS,
    camera::{self, Rational},
};
use super::{
    ProfileKind, jis,
    raw::samsung,
    reader::{Entry, Kind},
};
use std::borrow::Cow;

pub(super) enum Representation {
    Text,
    TiffText,
    TiffMake,
    Date,
    Copyright,
    Label(u32, &'static [&'static str]),
    Exposure,
    Aperture,
    ExposureBias,
    Metering,
    Flash,
    FocalLength,
    FocalLength35mm,
    Comment(UnicodeComment),
    Hemisphere([u8; 2], [&'static str; 2]),
    Coordinate(i64),
}

impl Representation {
    pub(super) fn byte_limit(&self, limit: usize) -> usize {
        match self {
            Self::Text | Self::TiffText => limit.saturating_add(1),
            Self::TiffMake => limit.saturating_add(1).max(samsung::MAKE_BYTES),
            Self::Copyright => limit.saturating_add(2),
            // The ISO-2022-JP comment can alternate character sets with escapes.
            Self::Comment(_) => limit.saturating_mul(3).saturating_add(16),
            Self::Date => 20,
            Self::Coordinate(_) => 24,
            Self::Exposure | Self::Aperture | Self::ExposureBias | Self::FocalLength => 8,
            Self::Label(..)
            | Self::Metering
            | Self::Flash
            | Self::FocalLength35mm
            | Self::Hemisphere(..) => 2,
        }
    }

    pub(super) fn decode(self, entry: Entry<'_>, limit: usize) -> Option<Cow<'_, str>> {
        Some(match self {
            Self::Text => text(entry, limit)?,
            Self::TiffText => Cow::Borrowed(tiff_text(entry)?),
            Self::TiffMake => {
                let value = match samsung::make_token(entry) {
                    Some(make) => make,
                    None if entry.bytes().len() <= limit.saturating_add(1) => tiff_text(entry)?,
                    None => return None,
                };
                Cow::Borrowed(value)
            }
            Self::Date => {
                if entry.kind() != Kind::Ascii || entry.count() != 20 {
                    return None;
                }
                text(entry, limit)?
            }
            Self::Copyright => copyright(entry, limit)?,
            Self::Label(base, names) => label(entry, base, names)?,
            Self::Exposure => rational(entry, Kind::Rational)?.exposure()?.into(),
            Self::Aperture => rational(entry, Kind::Rational)?.aperture()?.into(),
            Self::ExposureBias => exposure_bias(rational(entry, Kind::SRational)?).into(),
            Self::Metering => metering(entry)?,
            Self::Flash => flash(entry)?,
            Self::FocalLength => rational(entry, Kind::Rational)?.focal_length()?.into(),
            Self::FocalLength35mm => match short(entry)? {
                0 => "Unknown".into(),
                length => format!("{length}.0 mm").into(),
            },
            Self::Comment(encoding) => user_comment(entry, limit, encoding)?,
            Self::Hemisphere(codes, names) => {
                if entry.kind() != Kind::Ascii || entry.count() != 2 {
                    return None;
                }
                let [code] = entry.string()?.as_bytes() else {
                    return None;
                };
                let offset = codes.iter().position(|expected| code == expected)?;
                names[offset].into()
            }
            Self::Coordinate(maximum) => coordinate(entry, maximum)?.into(),
        })
    }
}

pub(super) fn image_field(tag: u16, profile_kind: ProfileKind) -> Option<(u32, Representation)> {
    use Representation::{Copyright, Date, Label, Text};
    if profile_kind.is_standalone() {
        let kind = match tag {
            269 => 4,  // DocumentName
            270 => 46, // ImageDescription
            271 => return Some((95, Representation::TiffMake)),
            272 => 96,   // Model
            285 => 12,   // PageName
            305 => 56,   // Software
            306 => 58,   // DateTime
            315 => 130,  // Artist
            316 => 87,   // HostComputer
            337 => 83,   // TargetPrinter
            33432 => 47, // Copyright
            // Orientation supplements the GNU TIFF text fields.
            274 => return Some((IMAGE_ORIENTATION, Label(1, ORIENTATION_LABELS))),
            _ => return None,
        };
        return Some((kind, Representation::TiffText));
    }
    Some(match tag {
        0x010e => (46, Text), // ImageDescription
        0x010f => (95, Text), // Make
        0x0110 => (96, Text), // Model
        0x0112 => (IMAGE_ORIENTATION, Label(1, ORIENTATION_LABELS)),
        0x0131 => (113, Text), // Software
        0x0132 => (59, Date),  // DateTime
        0x013b => (130, Text), // Artist
        0x8298 => (47, Copyright),
        _ => return None,
    })
}

pub(super) fn photo_field(tag: u16, encoding: UnicodeComment) -> Option<(u32, Representation)> {
    use Representation::{
        Aperture, Comment, Date, Exposure, ExposureBias, Flash, FocalLength, FocalLength35mm,
        Label, Metering, Text,
    };
    Some(match tag {
        0x829a => (camera::EXPOSURE, Exposure),
        0x829d => (camera::APERTURE, Aperture),
        0x8822 => (105, Label(0, EXPOSURE_PROGRAM)),
        0x9003 => (58, Date), // DateTimeOriginal
        0x9204 => (99, ExposureBias),
        0x9207 => (106, Metering),
        0x9209 => (100, Flash),
        0x920a => (camera::FOCAL_LENGTH, FocalLength),
        0x9286 => (3, Comment(encoding)),
        0xa403 => (109, Label(0, &["Auto", "Manual"])),
        0xa405 => (103, FocalLength35mm),
        0xa436 => (4, Text),  // ImageTitle
        0xa437 => (13, Text), // Photographer
        _ => return None,
    })
}

pub(super) fn gps_field(tag: u16) -> Option<(u32, Representation)> {
    use Representation::{Coordinate, Hemisphere};
    Some(match tag {
        0x0001 => (37, Hemisphere(*b"NS", ["North", "South"])),
        0x0002 => (38, Coordinate(90)),
        0x0003 => (39, Hemisphere(*b"EW", ["East", "West"])),
        0x0004 => (40, Coordinate(180)),
        _ => return None,
    })
}

fn text(entry: Entry<'_>, limit: usize) -> Option<Cow<'_, str>> {
    if entry.bytes().len() > limit.saturating_add(1) {
        return None;
    }
    let text = entry.string()?;
    (!text.contains('\0')).then_some(Cow::Borrowed(text))
}

fn tiff_text(entry: Entry<'_>) -> Option<&str> {
    let value = if entry.kind() == Kind::Ascii {
        let bytes = entry.bytes().strip_suffix(&[0])?;
        std::str::from_utf8(bytes.split(|&byte| byte == 0).next()?).ok()?
    } else {
        entry.string()?
    };
    (!value.contains('\0')).then_some(value)
}

fn copyright(entry: Entry<'_>, limit: usize) -> Option<Cow<'_, str>> {
    let bytes = entry.bytes();
    if bytes.len() > limit.saturating_add(2) {
        return None;
    }
    let text = entry.string()?;
    let Some((photographer, editor)) = text.split_once('\0') else {
        return Some(text.into());
    };
    let editor = editor.trim_end_matches('\0');
    if editor.contains('\0') {
        return None;
    }
    Some(match (photographer, editor) {
        (" " | "", editor) => editor.into(),
        (photographer, "") => photographer.into(),
        (photographer, editor) if photographer.len() + 2 + editor.len() <= limit => {
            format!("{photographer}, {editor}").into()
        }
        _ => return None,
    })
}

#[derive(Clone, Copy)]
pub(super) enum UnicodeComment {
    Utf8,
    LegacyUtf16,
}

impl UnicodeComment {
    pub(super) fn from_version(version: Option<Entry<'_>>) -> Self {
        if version.is_some_and(|entry| {
            let version = entry.bytes();
            version.iter().all(u8::is_ascii_digit) && version >= b"0300".as_slice()
        }) {
            Self::Utf8
        } else {
            Self::LegacyUtf16
        }
    }
}

fn user_comment(entry: Entry<'_>, limit: usize, encoding: UnicodeComment) -> Option<Cow<'_, str>> {
    if entry.kind() != Kind::Undefined {
        return None;
    }
    let (code, bytes) = entry.bytes().split_first_chunk::<8>()?;
    match code {
        b"ASCII\0\0\0" | b"\0\0\0\0\0\0\0\0" if bytes.len() <= limit.saturating_add(1) => {
            let bytes = bytes.split(|byte| *byte == 0).next()?;
            if code == b"ASCII\0\0\0" && !bytes.is_ascii() {
                return None;
            }
            std::str::from_utf8(bytes).ok().map(Cow::Borrowed)
        }
        b"UNICODE\0" => match encoding {
            UnicodeComment::Utf8 if bytes.len() <= limit.saturating_add(1) => {
                let bytes = bytes.strip_suffix(&[0]).unwrap_or(bytes);
                if bytes.contains(&0) || bytes.starts_with(b"\xef\xbb\xbf") {
                    return None;
                }
                std::str::from_utf8(bytes).ok().map(Cow::Borrowed)
            }
            UnicodeComment::LegacyUtf16 => {
                unicode_comment(bytes, entry.is_little_endian(), limit).map(Cow::Owned)
            }
            UnicodeComment::Utf8 => None,
        },
        b"JIS\0\0\0\0\0" => jis::decode(bytes, limit),
        _ => None,
    }
}

fn unicode_comment(bytes: &[u8], little_endian: bool, limit: usize) -> Option<String> {
    let (bytes, little_endian) = if let Some(bytes) = bytes.strip_prefix(&[0xff, 0xfe]) {
        (bytes, true)
    } else if let Some(bytes) = bytes.strip_prefix(&[0xfe, 0xff]) {
        (bytes, false)
    } else {
        (bytes, little_endian)
    };
    let (units, tail) = bytes.as_chunks::<2>();
    if !tail.is_empty() || units.len() > limit.saturating_add(1) {
        return None;
    }
    let units = units
        .iter()
        .map(|bytes| {
            if little_endian {
                u16::from_le_bytes(*bytes)
            } else {
                u16::from_be_bytes(*bytes)
            }
        })
        .take_while(|&unit| unit != 0);
    let mut text = String::new();
    text.try_reserve_exact(limit.min(bytes.len().saturating_mul(2)))
        .ok()?;
    for character in char::decode_utf16(units) {
        let character = character.ok()?;
        if character.len_utf8() > limit.saturating_sub(text.len()) {
            return None;
        }
        text.push(character);
    }
    Some(text)
}

fn short(entry: Entry<'_>) -> Option<u32> {
    if entry.kind() != Kind::Short || entry.count() != 1 {
        return None;
    }
    u32::try_from(entry.unsigned(0)?).ok()
}

fn rational(entry: Entry<'_>, kind: Kind) -> Option<Rational> {
    (entry.kind() == kind && entry.count() == 1).then(|| entry.rational(0))?
}

fn exposure_bias(value: Rational) -> String {
    let numerator = value.numerator.unsigned_abs();
    let denominator = value.denominator.get().unsigned_abs();
    let (mut a, mut b) = (numerator, denominator);
    while b != 0 {
        (a, b) = (b, a % b);
    }
    let sign = if numerator != 0 && (value.numerator < 0) != (value.denominator.get() < 0) {
        "-"
    } else {
        ""
    };
    if denominator == a {
        format!("{sign}{} EV", numerator / a)
    } else {
        format!("{sign}{}/{} EV", numerator / a, denominator / a)
    }
}

fn label<'a>(entry: Entry<'_>, base: u32, labels: &[&'a str]) -> Option<Cow<'a, str>> {
    let number = short(entry)?;
    Some(
        match number
            .checked_sub(base)
            .and_then(|index| labels.get(index as usize))
        {
            Some(name) => (*name).into(),
            None => number.to_string().into(),
        },
    )
}

const EXPOSURE_PROGRAM: &[&str] = &[
    "Not defined",
    "Manual",
    "Auto",
    "Aperture priority",
    "Shutter priority",
    "Creative program",
    "Action program",
    "Portrait mode",
    "Landscape mode",
];

fn metering(entry: Entry<'_>) -> Option<Cow<'static, str>> {
    if short(entry)? == 255 {
        return Some("Other".into());
    }
    label(
        entry,
        0,
        &[
            "Unknown",
            "Average",
            "Center weighted average",
            "Spot",
            "Multi-spot",
            "Multi-segment",
            "Partial",
        ],
    )
}

fn flash(entry: Entry<'_>) -> Option<Cow<'static, str>> {
    let value = short(entry)?;
    let red_eye = value & 0x40 != 0;
    let fired = value & 1 != 0;
    let mode = value & 0x38;
    let return_light = match value & 6 {
        0 => "",
        4 => ", return light not detected",
        6 => ", return light detected",
        _ => return Some(format!("0x{value:02x}").into()),
    };
    let base = match (mode, fired, red_eye) {
        (0, false, _) => "No flash",
        (0, true, false) => "Fired",
        (0, true, true) => "Yes",
        (8, false, _) => "Yes, did not fire",
        (8, true, _) => "Yes, compulsory",
        (16, false, true) => "No",
        (16, false, false) => "No, compulsory",
        (24, false, _) => "No, auto",
        (24, true, _) => "Yes, auto",
        (32, false, false) if return_light.is_empty() => "No flash function",
        _ => return Some(format!("0x{value:02x}").into()),
    };
    if value > 0x7f {
        return Some(format!("0x{value:02x}").into());
    }
    let reduction = if red_eye { ", red-eye reduction" } else { "" };
    Some(if reduction.is_empty() && return_light.is_empty() {
        base.into()
    } else {
        format!("{base}{reduction}{return_light}").into()
    })
}

fn coordinate(entry: Entry<'_>, maximum_degrees: i64) -> Option<String> {
    if entry.kind() != Kind::Rational || entry.count() != 3 {
        return None;
    }
    let degrees = entry.rational(0)?;
    let minutes = entry.rational(1)?;
    let mut seconds = entry.rational(2)?;
    if degrees.denominator.get() != 1 || degrees.numerator > maximum_degrees {
        return None;
    }
    let whole_minutes = minutes.numerator / minutes.denominator.get();
    let remaining_minutes = minutes.numerator % minutes.denominator.get();
    if remaining_minutes != 0 {
        if seconds.numerator != 0 {
            return None;
        }
        seconds = Rational {
            numerator: 60 * remaining_minutes,
            denominator: minutes.denominator,
        };
    }
    let second_value = seconds.value();
    if whole_minutes >= 60
        || second_value >= 60.0
        || degrees.numerator == maximum_degrees && (whole_minutes != 0 || second_value != 0.0)
    {
        return None;
    }
    let precision = if seconds.denominator.get() == 1 { 0 } else { 2 };
    Some(format!(
        "{} deg {whole_minutes}' {second_value:.precision$}\"",
        degrees.numerator
    ))
}
