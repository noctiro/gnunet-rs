//! Camera metadata recovered from Sigma SECc sections.

mod decode;

use super::{Dimensions, Input, Properties, Property, Rational, Section, words};
use decode::Encoding;

// Match the expanded metadata ceiling used by other compressed profiles.
const MAX_DECODED_BYTES: usize = 1024 * 1024;
const HEADER_BYTES: usize = 28;
const ENTRY_HEADER_BYTES: usize = 20;

pub(super) const FIELDS: &[Property] = &[
    Property::Make,
    Property::Model,
    Property::Serial,
    Property::Iso,
    Property::Aperture,
    Property::Shutter,
    Property::ExposureCompensation,
    Property::Balance,
];

#[derive(Default)]
pub(super) struct Metadata {
    pub(super) fields: Properties,
    pub(super) dimensions: Option<Dimensions>,
}

impl Metadata {
    pub(super) fn read<E>(
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        section: Section,
        limit: usize,
    ) -> Result<Option<Self>, E> {
        let Ok(payload_length) =
            usize::try_from(section.length().saturating_sub(HEADER_BYTES as u64))
        else {
            return Ok(None);
        };
        if payload_length == 0 {
            return Ok(None);
        }
        let Some(header) = input.range(section.start, HEADER_BYTES)? else {
            return Ok(None);
        };
        if !header.starts_with(b"SECc") {
            return Ok(None);
        }
        let [_, _version, camera_type, decoded_size, bias, columns, rows] = words::<7>(header);
        let (encoding, size) = match camera_type {
            2 => (Encoding::Xor { key: rows }, payload_length),
            4 => (
                Encoding::Packed {
                    bias: bias as u16,
                    columns,
                    rows,
                },
                decoded_size as usize,
            ),
            5 => (Encoding::Bytes { bias: bias as u8 }, decoded_size as usize),
            _ => return Ok(None),
        };
        if !(1..=MAX_DECODED_BYTES).contains(&size) {
            return Ok(None);
        }
        let Some(payload) = input.range(section.start + HEADER_BYTES as u64, payload_length)?
        else {
            return Ok(None);
        };
        let Some(decoded) = encoding.decode(payload, size) else {
            return Ok(None);
        };
        Ok(Some(Self::from_entries(&decoded, limit)))
    }

    fn from_entries(mut entries: &[u8], limit: usize) -> Self {
        let mut metadata = Self::default();
        let mut active = None;
        let mut keep = None;
        while let Some(entry) = Entry::parse(entries) {
            entries = entry.tail;
            if let Some(property) = entry.capture_property() {
                let value = &mut metadata.fields.0[property as usize];
                if value.is_none() {
                    *value = entry.project(property, limit);
                }
            }
            match (entry.kind, entry.name) {
                (b"CMbM", b"ActiveImageArea") if active.is_none() => {
                    active = entry.matrix(4).and_then(Matrix::rectangle);
                }
                (b"CMbM", b"KeepImageArea") if keep.is_none() => {
                    keep = entry.matrix(4).and_then(Matrix::rectangle);
                }
                _ => {}
            }
        }
        if let (
            Some([left, top, right, bottom]),
            Some([keep_left, keep_top, keep_right, keep_bottom]),
        ) = (active, keep)
        {
            let width = right
                .min(keep_right)
                .checked_sub(left.max(keep_left))
                .and_then(|width| width.checked_add(1));
            let height = bottom
                .min(keep_bottom)
                .checked_sub(top.max(keep_top))
                .and_then(|height| height.checked_add(1));
            if let (Some(width), Some(height)) = (width, height) {
                metadata.dimensions = Dimensions::new(width, height);
            }
        }
        metadata
    }
}

struct Entry<'a> {
    kind: &'a [u8; 4],
    name: &'a [u8],
    bytes: &'a [u8],
    values_at: usize,
    tail: &'a [u8],
}

impl<'a> Entry<'a> {
    fn parse(entries: &'a [u8]) -> Option<Self> {
        let kind = entries.first_chunk::<4>()?;
        if !matches!(kind, b"CMbM" | b"CMbP" | b"CMbT") {
            return None;
        }
        let [_, _version, size, name_at, value_at] =
            words::<5>(entries.first_chunk::<ENTRY_HEADER_BYTES>()?);
        let (bytes, tail) = entries.split_at_checked(size as usize)?;
        let values_at = value_at as usize;
        let name_at = name_at as usize;
        if name_at < ENTRY_HEADER_BYTES || values_at > bytes.len() {
            return None;
        }
        let name = bytes.get(name_at..values_at)?;
        let name = &name[..name.iter().position(|&byte| byte == 0)?];
        Some(Self {
            kind,
            name,
            bytes,
            values_at,
            tail,
        })
    }

    fn capture_property(&self) -> Option<Property> {
        Some(match (self.kind, self.name) {
            (b"CMbT", b"Make") => Property::Make,
            (b"CMbT", b"Model") => Property::Model,
            (b"CMbT", b"CameraSerialNumber") => Property::Serial,
            (b"CMbM", b"CaptureISO") => Property::Iso,
            (b"CMbM", b"CaptureAperture") => Property::Aperture,
            (b"CMbM", b"CaptureExpTime") => Property::Shutter,
            (b"CMbM", b"CaptureExpComp") => Property::ExposureCompensation,
            (b"CMbM", b"WhiteBalance") => Property::Balance,
            _ => return None,
        })
    }

    fn project(&self, property: Property, limit: usize) -> Option<String> {
        let value = match property {
            Property::Make | Property::Model | Property::Serial => {
                let text = self.text()?;
                return (text.len() <= limit).then(|| text.to_owned());
            }
            Property::Iso => {
                let iso = self.matrix(1)?.float()?.round();
                if !(1.0..=f64::from(u32::MAX)).contains(&iso) {
                    return None;
                }
                (iso as u32).to_string()
            }
            Property::Aperture => {
                let scaled = self.matrix(1)?.float()? * 1_000_000.0;
                micro_value(scaled)?.aperture()?
            }
            Property::Shutter => micro_value(self.matrix(1)?.float()?)?.exposure()?,
            Property::ExposureCompensation => format!("{:+.2} EV", self.matrix(1)?.float()?),
            Property::Balance => white_balance(self.matrix(1)?.unsigned(0)?)?.to_owned(),
            _ => return None,
        };
        (value.len() <= limit).then_some(value)
    }

    fn text(&self) -> Option<&'a str> {
        let (size, value) = self.bytes.get(self.values_at..)?.split_first_chunk::<4>()?;
        let length = u32::from_le_bytes(*size) as usize;
        let text = str::from_utf8(value.get(..length)?)
            .ok()?
            .trim_end_matches('\0')
            .trim();
        (!text.is_empty() && text.chars().all(|ch| !ch.is_control())).then_some(text)
    }

    fn matrix(&self, length: u32) -> Option<Matrix<'a>> {
        let header = self.bytes.get(self.values_at..)?.first_chunk::<24>()?;
        let [kind, dimensions, offset, count, _dimension_name, _index] = words::<6>(header);
        if dimensions != 1 || count != length || (offset as usize) < self.values_at + header.len() {
            return None;
        }
        let kind = match kind {
            1 | 2 => Values::U32,
            3 => Values::F32,
            5 => Values::U8,
            6 => Values::U16,
            _ => return None,
        };
        let expected = (length as usize) * kind.width();
        let data = self.bytes.get(offset as usize..)?.get(..expected)?;
        Some(Matrix { kind, data })
    }
}

#[derive(Clone, Copy)]
enum Values {
    U8,
    U16,
    U32,
    F32,
}

impl Values {
    fn width(self) -> usize {
        match self {
            Self::U8 => 1,
            Self::U16 => 2,
            Self::U32 | Self::F32 => 4,
        }
    }
}

struct Matrix<'a> {
    kind: Values,
    data: &'a [u8],
}

impl Matrix<'_> {
    fn unsigned(&self, index: usize) -> Option<u32> {
        let bytes = self.data.get(index * self.kind.width()..)?;
        match self.kind {
            Values::U8 => bytes.first().copied().map(u32::from),
            Values::U16 => Some(u32::from(u16::from_le_bytes(*bytes.first_chunk::<2>()?))),
            Values::U32 => Some(u32::from_le_bytes(*bytes.first_chunk::<4>()?)),
            Values::F32 => None,
        }
    }

    fn float(self) -> Option<f64> {
        if !matches!(self.kind, Values::F32) {
            return None;
        }
        let value = f64::from(f32::from_le_bytes(*self.data.first_chunk::<4>()?));
        value.is_finite().then_some(value)
    }

    fn rectangle(self) -> Option<[u32; 4]> {
        let [left, top, right, bottom] = [
            self.unsigned(0)?,
            self.unsigned(1)?,
            self.unsigned(2)?,
            self.unsigned(3)?,
        ];
        (left <= right && top <= bottom).then_some([left, top, right, bottom])
    }
}

fn micro_value(value: f64) -> Option<Rational> {
    let value = value.round();
    if !(1.0..i64::MAX as f64).contains(&value) {
        return None;
    }
    Rational::new(value as i64, 1_000_000)
}

fn white_balance(value: u32) -> Option<&'static str> {
    Some(match value {
        1 => "Auto",
        2 => "Sunlight",
        3 => "Shadow",
        4 => "Overcast",
        5 => "Incandescent",
        6 => "Fluorescent",
        7 => "Flash",
        8 => "Custom",
        11 => "Color temperature",
        12 => "Auto (lighting source priority)",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projects_known_capture_text_and_typed_exposure_values() {
        let entries = [
            text(b"Make", b" SIGMA\0", 7),
            text(b"Model", b"dp2 Quattro", 11),
            text(b"CameraSerialNumber", b"00126037\0", 9),
            float(b"CaptureAperture", 4.0),
            float(b"CaptureExpTime", 8_000.0),
            float(b"CaptureExpComp", -0.5),
        ]
        .concat();
        let metadata = Metadata::from_entries(&entries, 32);
        for (property, expected) in [
            (Property::Make, "SIGMA"),
            (Property::Model, "dp2 Quattro"),
            (Property::Serial, "00126037"),
            (Property::Aperture, "F4"),
            (Property::Shutter, "1/125 s"),
            (Property::ExposureCompensation, "-0.50 EV"),
        ] {
            assert_eq!(
                metadata.fields.0[property as usize].as_deref(),
                Some(expected)
            );
        }
    }

    #[test]
    fn invalid_text_and_private_calibration_do_not_supply_capture_fields() {
        let entries = [
            text(b"Make", b"unexpected", 100),
            text(b"Make", b"longer than the limit", 21),
            record(b"CMbP", b"Make", b"unused calibration data"),
            text(b"Model", b"em\0bedded", 9),
            text(b"Make", b"SIGMA", 5),
            text(b"Make", b"other", 5),
            float(b"CaptureExpTime", f32::NAN),
        ]
        .concat();
        let metadata = Metadata::from_entries(&entries, 16);
        assert_eq!(
            metadata.fields.0[Property::Make as usize].as_deref(),
            Some("SIGMA")
        );
        assert_eq!(metadata.fields.0[Property::Model as usize], None);
        assert_eq!(metadata.fields.0[Property::Shutter as usize], None);
    }

    fn text(name: &[u8], content: &[u8], count: u32) -> Vec<u8> {
        let payload = [count.to_le_bytes().as_slice(), content].concat();
        record(b"CMbT", name, &payload)
    }

    fn float(name: &[u8], value: f32) -> Vec<u8> {
        let data = (ENTRY_HEADER_BYTES + name.len() + 1 + 24) as u32;
        let payload: Vec<_> = [3, 1, data, 1, 0, 0, value.to_bits()]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        record(b"CMbM", name, &payload)
    }

    fn record(kind: &[u8; 4], name: &[u8], payload: &[u8]) -> Vec<u8> {
        let name_offset = ENTRY_HEADER_BYTES as u32;
        let value_offset = name_offset + name.len() as u32 + 1;
        let length = value_offset + payload.len() as u32;
        let mut bytes = kind.to_vec();
        bytes.extend(
            [0x0002_0000_u32, length, name_offset, value_offset]
                .into_iter()
                .flat_map(u32::to_le_bytes),
        );
        bytes.extend_from_slice(name);
        bytes.push(0);
        bytes.extend_from_slice(payload);
        bytes
    }
}
