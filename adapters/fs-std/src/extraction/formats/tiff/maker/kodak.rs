//! Camera metadata in Kodak shooting and MakerNote directories.

use super::{
    ByteOrder, DirectoryTail, EXPOSURE_PROGRAM, FLASH, ISO_SPEED, Kind, MAKE, METERING_MODE, MODEL,
    Row, Selection, Tiff, WHITE_BALANCE,
};
use crate::extraction::formats::camera::{APERTURE, EXPOSURE, FOCAL_LENGTH, Rational};
use crate::extraction::formats::tiff::{primary, raw::Compression};
use std::borrow::Cow;

pub(in crate::extraction::formats::tiff) const IFD: u16 = 0x8290;
pub(in crate::extraction::formats::tiff) const KDC_IFD: u16 = 0xfe00;
const VERSION: u16 = 0;
const SHOT_TEXT: u16 = 0x03f1;
const KDC_WHITE_BALANCE: u16 = 0xfa0d;
const MAX_SHOT_TEXT_BYTES: usize = 4096;
const KODAK_MAKE: &[u8] = b"EASTMAN KODAK";
pub(super) const MAX_MODEL_BYTES: usize = 64;

const CAMERA_INFO: u16 = 0xff00;
const CAMERA_F_NUMBER: u16 = 0xfd04;
const CAMERA_EXPOSURE_TIME: u16 = 0xfd05;
const CAMERA_ISO: u16 = 0xfd06;

pub(super) fn is_kodak_make(prefix: &[u8]) -> bool {
    [KODAK_MAKE, b"KODAK"].into_iter().any(|make| {
        prefix
            .get(..make.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(make))
            && prefix
                .get(make.len())
                .is_none_or(|&next| next == 0 || next.is_ascii_whitespace())
    })
}

pub(super) fn is_p_series(model: Option<&[u8]>) -> bool {
    model
        .and_then(|bytes| bytes.strip_suffix(&[0]))
        .and_then(|bytes| str::from_utf8(bytes).ok())
        .is_some_and(|model| {
            model.split_ascii_whitespace().any(|word| {
                ["P712", "P850", "P880"]
                    .into_iter()
                    .any(|name| word.eq_ignore_ascii_case(name))
            })
        })
}

/// Kodak records the classic IFD count in the MakerNote's own byte order.
pub(super) fn bare_order(header: &[u8]) -> Option<ByteOrder> {
    match header.first_chunk()? {
        [0, 1..=127] => Some(ByteOrder::Big),
        [1..=127, 0] => Some(ByteOrder::Little),
        _ => None,
    }
}

/// Standard EXIF values which take precedence over CameraInfo fallbacks.
#[derive(Clone, Copy, Default)]
pub(in crate::extraction::formats::tiff) struct CaptureFields {
    aperture: bool,
    exposure: bool,
    iso: bool,
}

impl CaptureFields {
    pub(in crate::extraction::formats::tiff) fn observe(&mut self, kind: u32) {
        match kind {
            APERTURE => self.aperture = true,
            EXPOSURE => self.exposure = true,
            ISO_SPEED => self.iso = true,
            _ => {}
        }
    }
}

pub(super) fn visit_camera_info<E>(
    tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    note: Row,
    order: ByteOrder,
    observed: CaptureFields,
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    if observed.aperture && observed.exposure && observed.iso {
        return Ok(());
    }
    let Some(note_start) = note.external_offset() else {
        return Ok(());
    };
    let Some(root) = tiff.parent_relative_maker(note, 0, order, DirectoryTail::NextOffset)? else {
        return Ok(());
    };
    let root_end = root.encoded_end();
    let Some(root) = Selection::read_directory(tiff, root, |tag| tag == CAMERA_INFO)? else {
        return Ok(());
    };
    let Some(link) = root.find(CAMERA_INFO).filter(|field| {
        !field.duplicate
            && matches!(field.row.kind(), Kind::Long | Kind::Ifd)
            && field.row.count() == 1
    }) else {
        return Ok(());
    };
    let Some(offset) = tiff
        .read_field(&link.row)?
        .and_then(|entry| entry.unsigned(0))
        .filter(|&offset| offset >= root_end && offset.is_multiple_of(2))
    else {
        return Ok(());
    };
    let Some(directory) =
        tiff.parent_relative_maker(note, offset - note_start, order, DirectoryTail::NextOffset)?
    else {
        return Ok(());
    };
    let Some(fields) = Selection::read_directory(tiff, directory, |tag| {
        matches!(tag, CAMERA_F_NUMBER | CAMERA_EXPOSURE_TIME | CAMERA_ISO)
    })?
    else {
        return Ok(());
    };
    for (tag, kind, output, present) in [
        (CAMERA_F_NUMBER, Kind::Short, APERTURE, observed.aperture),
        (
            CAMERA_EXPOSURE_TIME,
            Kind::Long,
            EXPOSURE,
            observed.exposure,
        ),
        (CAMERA_ISO, Kind::Short, ISO_SPEED, observed.iso),
    ] {
        let Some(field) = fields.find(tag).filter(|field| {
            !present && !field.duplicate && field.row.kind() == kind && field.row.count() == 1
        }) else {
            continue;
        };
        let Some(value) = tiff
            .read_field(&field.row)?
            .and_then(|entry| entry.unsigned(0))
            .filter(|&value| value != 0)
        else {
            continue;
        };
        let text = match tag {
            CAMERA_F_NUMBER => Rational::new(value as i64, 100).and_then(Rational::aperture),
            CAMERA_EXPOSURE_TIME => {
                Rational::new(value as i64, 1_000_000).and_then(Rational::exposure)
            }
            _ => Some(value.to_string()),
        };
        if let Some(text) = text.filter(|text| text.len() <= limit) {
            emit(output, text.as_bytes())?;
        }
    }
    Ok(())
}

pub(in crate::extraction::formats::tiff) struct Shooting {
    version: [u8; 4],
    text: Option<Row>,
}

impl Shooting {
    pub(in crate::extraction::formats::tiff) fn read<E>(
        tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        image: &Selection,
    ) -> Result<Option<Self>, E> {
        let Some(offset) = linked_directory(tiff, image, IFD)? else {
            return Ok(None);
        };
        let Some(kodak) = Selection::read(tiff, offset, |tag| matches!(tag, VERSION | SHOT_TEXT))?
        else {
            return Ok(None);
        };
        let Some(version) = kodak.find(VERSION).filter(|field| {
            !field.duplicate && field.row.kind() == Kind::Byte && field.row.count() == 4
        }) else {
            return Ok(None);
        };
        let Some(version @ [1, ..]) = tiff
            .read_field(&version.row)?
            .and_then(|entry| <[u8; 4]>::try_from(entry.bytes()).ok())
        else {
            return Ok(None);
        };
        let text = kodak.find(SHOT_TEXT).filter(|field| {
            !field.duplicate
                && field.row.kind() == Kind::Ascii
                && field.row.len() <= MAX_SHOT_TEXT_BYTES
        });
        Ok(Some(Self {
            version,
            text: text.map(|field| field.row),
        }))
    }

    pub(in crate::extraction::formats::tiff) fn is_dc120_raw<E>(
        &self,
        tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        root: &Selection,
        sensor: &Selection,
        compression: Compression,
    ) -> Result<bool, E> {
        if self.version != [1, 1, 0, 0]
            || !matches!(compression.value(), Some(1 | 7))
            || primary::photometric(tiff, sensor)? != Some(32803)
            || primary::bits_per_sample(tiff, sensor)? != Some(8)
        {
            return Ok(false);
        }
        let Some(model) = root.find(MODEL).filter(|field| {
            !field.duplicate && field.row.kind() == Kind::Ascii && field.row.len() <= 64
        }) else {
            return Ok(false);
        };
        Ok(tiff
            .read_field(&model.row)?
            .and_then(|entry| entry.string())
            .is_some_and(|model| {
                model
                    .split_ascii_whitespace()
                    .any(|word| word.eq_ignore_ascii_case("DC120"))
            }))
    }

    pub(in crate::extraction::formats::tiff) fn emit<E>(
        self,
        tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        limit: usize,
        emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        if let Some(row) = self.text
            && let Some(text) = tiff.read_field(&row)?.and_then(|entry| entry.string())
        {
            shot_fields(text, limit, emit)?;
        }
        Ok(())
    }
}

pub(in crate::extraction::formats::tiff) struct Kdc(Option<&'static [u8]>);

impl Kdc {
    pub(in crate::extraction::formats::tiff) fn read<E>(
        tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        image: &Selection,
    ) -> Result<Option<Self>, E> {
        let Some(offset) = linked_directory(tiff, image, KDC_IFD)? else {
            return Ok(None);
        };
        let Some(directory) = Selection::read(tiff, offset, |tag| tag == KDC_WHITE_BALANCE)? else {
            return Ok(None);
        };
        let Some(field) = directory.find(KDC_WHITE_BALANCE).filter(|field| {
            !field.duplicate && field.row.kind() == Kind::Byte && field.row.count() == 1
        }) else {
            return Ok(None);
        };
        let Some(balance) = tiff
            .read_field(&field.row)?
            .and_then(|entry| entry.unsigned(0))
        else {
            return Ok(None);
        };
        Ok(Some(Self(match balance {
            0 => Some(b"Auto"),
            1 => Some(b"Fluorescent"),
            2 => Some(b"Tungsten"),
            3 => Some(b"Daylight"),
            6 => Some(b"Shade"),
            _ => None,
        })))
    }

    pub(in crate::extraction::formats::tiff) fn emit<E>(
        self,
        limit: usize,
        emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        if let Some(label) = self.0.filter(|label| label.len() <= limit) {
            emit(WHITE_BALANCE, label)?;
        }
        Ok(())
    }
}

fn linked_directory<E>(
    tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    image: &Selection,
    tag: u16,
) -> Result<Option<u64>, E> {
    let Some(link) = image.find(tag).filter(|field| {
        !field.duplicate && field.row.kind() == Kind::Long && field.row.count() == 1
    }) else {
        return Ok(None);
    };
    let Some(make) = image
        .find(MAKE)
        .filter(|field| !field.duplicate && field.row.kind() == Kind::Ascii)
    else {
        return Ok(None);
    };
    let Some(prefix) =
        tiff.read_field_range(&make.row, 0, make.row.len().min(KODAK_MAKE.len() + 1))?
    else {
        return Ok(None);
    };
    if !is_kodak_make(prefix) {
        return Ok(None);
    }
    let root = tiff.first_offset();
    Ok(tiff
        .read_field(&link.row)?
        .and_then(|entry| entry.unsigned(0))
        .filter(|&offset| offset != 0 && offset != root))
}

#[derive(Clone, Copy, Default)]
enum FieldValue<'a> {
    #[default]
    Missing,
    Value(&'a str),
    Duplicate,
}

#[derive(Clone, Copy)]
enum Setting {
    Iso,
    Aperture,
    Shutter,
    Program,
    Meter,
    Flash,
    FocalLength,
    WhiteBalance,
}

impl Setting {
    const ALL: [Self; 8] = [
        Self::Iso,
        Self::Aperture,
        Self::Shutter,
        Self::Program,
        Self::Meter,
        Self::Flash,
        Self::FocalLength,
        Self::WhiteBalance,
    ];

    fn from_key(key: &str) -> Option<Self> {
        Some(match key {
            "ISO" | "ISO Speed" => Self::Iso,
            "Aperture" => Self::Aperture,
            "Shutter" => Self::Shutter,
            "Exposure Mode" => Self::Program,
            "Meter Mode" => Self::Meter,
            "Flash Fired" => Self::Flash,
            "Focal Length" => Self::FocalLength,
            "White balance" => Self::WhiteBalance,
            _ => return None,
        })
    }

    fn decode(self, text: &str) -> Option<(u32, Cow<'_, str>)> {
        Some(match self {
            Self::Iso => {
                let iso = positive_integer(text)?;
                (ISO_SPEED, iso.to_string().into())
            }
            Self::Aperture => {
                let value = text.strip_prefix(['f', 'F'])?;
                (APERTURE, measure(value)?.aperture()?.into())
            }
            Self::Shutter => (EXPOSURE, measure(text)?.exposure()?.into()),
            Self::FocalLength => (FOCAL_LENGTH, measure(text)?.focal_length()?.into()),
            Self::Program => {
                let label = match text {
                    "A" | "Aperture priority AE (Av)" => "Aperture priority",
                    "M" | "Manual (M)" => "Manual",
                    "B" => "Bulb",
                    "P" => "Auto",
                    "S" => "Shutter priority",
                    _ => return None,
                };
                (EXPOSURE_PROGRAM, label.into())
            }
            Self::Meter => {
                let label = match text {
                    "Matrix metering" => "Multi-segment",
                    "Center-weighted metering" => "Center weighted average",
                    "Spot metering" => "Spot",
                    _ => return None,
                };
                (METERING_MODE, label.into())
            }
            Self::Flash => (
                FLASH,
                match text {
                    "Yes" => "Fired",
                    "No" => "No flash",
                    _ => return None,
                }
                .into(),
            ),
            Self::WhiteBalance => (WHITE_BALANCE, text.into()),
        })
    }
}

fn shot_fields<E>(
    text: &str,
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    let mut fields = [FieldValue::Missing; Setting::ALL.len()];
    let text = text.split('\0').next().unwrap_or_default();
    for line in text.split(['\n', '\r']) {
        if let Some((key, value)) = line.split_once(':')
            && let Some(setting) = Setting::from_key(key)
        {
            let slot = &mut fields[setting as usize];
            *slot = match slot {
                FieldValue::Missing => FieldValue::Value(value.trim_ascii()),
                _ => FieldValue::Duplicate,
            };
        }
    }
    for (setting, stored) in Setting::ALL.into_iter().zip(fields) {
        if let FieldValue::Value(value) = stored
            && !value.is_empty()
            && value
                .bytes()
                .all(|byte| byte == b' ' || byte.is_ascii_graphic())
            && let Some((kind, label)) = setting.decode(value)
            && label.len() <= limit
        {
            emit(kind, label.as_bytes())?;
        }
    }
    Ok(())
}

fn integer(value: &str) -> Option<i64> {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit())
        .then(|| value.parse::<u32>().ok())?
        .map(i64::from)
}

fn positive_integer(value: &str) -> Option<i64> {
    integer(value).filter(|&value| value != 0)
}

fn measure(value: &str) -> Option<Rational> {
    if let Some((top, bottom)) = value.split_once('/') {
        return Rational::new(positive_integer(top)?, positive_integer(bottom)?);
    }
    let Some((whole, fraction)) = value.split_once('.') else {
        return Rational::new(positive_integer(value)?, 1);
    };
    let denominator = 10_i64.checked_pow(u32::try_from(fraction.len()).ok()?)?;
    let numerator = integer(whole)?
        .checked_mul(denominator)?
        .checked_add(integer(fraction)?)?;
    Rational::new(numerator, denominator)
}
