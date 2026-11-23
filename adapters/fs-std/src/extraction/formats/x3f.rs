//! Foveon FOVb header, property lists and JPEG metadata for Sigma and Polaroid RAW.

mod camf;

use super::{
    Dimensions, IMAGE_DIMENSIONS, IMAGE_ORIENTATION, Input, ORIENTATION_LABELS,
    camera::{self, Rational},
    jpeg,
};
use std::num::NonZeroU32;
use time::OffsetDateTime;

pub(super) const SIGNATURE: &[u8; 4] = b"FOVb";

const VERSION_2_0: u32 = 0x0002_0000;
const WHITE_BALANCE: u32 = 109;

pub(super) fn visit<E>(
    mut input: Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    let Some(header) = Header::read(&mut input)? else {
        return Ok(());
    };
    let Some(sections) = Section::directory(&mut input, header.end)? else {
        return Ok(());
    };
    let mut properties = Properties::default();
    let mut preview = None;
    let mut camf_section = None;
    for section in sections {
        match &section.kind {
            b"PROP" => properties.read(&mut input, section, limit)?,
            b"CAMF" if camf_section.is_none() => camf_section = Some(section),
            b"IMAG" | b"IMA2" => {
                if let Some(candidate) = Preview::read(&mut input, section)?
                    && preview
                        .as_ref()
                        .is_none_or(|old: &Preview| candidate.area > old.area)
                {
                    preview = Some(candidate);
                }
            }
            _ => {}
        }
    }

    if let Some(size) = &header.size {
        size.emit(emit)?;
    }
    let orientation = header.orientation.filter(|label| label.len() <= limit);
    if let Some(label) = orientation {
        emit(IMAGE_ORIENTATION, label.as_bytes())?;
    }
    if properties.white_balance().is_none()
        && let Some(text) = header.balance(&mut input, limit)?
    {
        properties.set_balance(text);
    }
    properties.emit(emit)?;

    let mut observed = properties.observed();
    let mut has_dimensions = header.size.is_some();
    if let Some(preview) = preview
        && let Some(payload) = input.section(preview.start, preview.length)
    {
        jpeg::visit_preview(payload, limit, jpeg::Profiles::All, &mut |kind, value| {
            if (kind == IMAGE_DIMENSIONS && header.size.is_some())
                || (kind == IMAGE_ORIENTATION && orientation.is_some())
                || properties.contains(kind)
            {
                return Ok(());
            }
            if let Some((property, _)) = Property::KEYS.iter().find(|(key, _)| key.kind() == kind) {
                observed[*property as usize] = true;
            }
            has_dimensions |= kind == IMAGE_DIMENSIONS;
            emit(kind, value)
        })?;
    }
    if (!has_dimensions || camf::FIELDS.iter().any(|&field| !observed[field as usize]))
        && let Some(section) = camf_section
        && let Some(metadata) = camf::Metadata::read(&mut input, section, limit)?
    {
        for &property in camf::FIELDS {
            let index = property as usize;
            if !observed[index]
                && let Some(text) = &metadata.fields.0[index]
            {
                emit(property.kind(), text.as_bytes())?;
            }
        }
        if !has_dimensions && let Some(dimensions) = metadata.dimensions {
            dimensions.emit(emit)?;
        }
    }
    Ok(())
}

struct Header {
    end: u64,
    size: Option<Dimensions>,
    orientation: Option<&'static str>,
    has_balance: bool,
}

impl Header {
    fn read<E>(
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    ) -> Result<Option<Self>, E> {
        let Some([b'F', b'O', b'V', b'b', version @ ..]) =
            input.range(0, 8)?.and_then(<[u8]>::first_chunk::<8>)
        else {
            return Ok(None);
        };
        let (end, size_offset, has_balance) = match u32::from_le_bytes(*version) {
            VERSION_2_0 => (40, 28, false),
            0x0002_0001..=0x0002_0002 => (232, 28, true),
            0x0002_0003..=0x0002_ffff => (264, 28, true),
            0x0003_0000..=0x0003_ffff => (424, 28, true),
            0x0004_0000..=0x0005_0000 => (0x300, 40, false),
            _ => return Ok(None),
        };
        let Some([width, height, rotation]) = input.range(size_offset, 12)?.map(words::<3>) else {
            return Ok(None);
        };
        let orientation = match rotation {
            0 => Some(ORIENTATION_LABELS[0]),
            90 => Some(ORIENTATION_LABELS[5]),
            180 => Some(ORIENTATION_LABELS[2]),
            270 => Some(ORIENTATION_LABELS[7]),
            _ => None,
        };
        Ok(Some(Self {
            end,
            size: Dimensions::new(width, height),
            orientation,
            has_balance,
        }))
    }

    fn balance<E>(
        &self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        limit: usize,
    ) -> Result<Option<String>, E> {
        if !self.has_balance {
            return Ok(None);
        }
        Ok(input.range(40, 32)?.and_then(|bytes| {
            let label = bytes.split(|&byte| byte == 0).next()?;
            if label.is_empty()
                || label.len() > limit
                || !label
                    .iter()
                    .all(|&byte| byte == b' ' || byte.is_ascii_graphic())
            {
                return None;
            }
            str::from_utf8(label).ok().map(str::to_owned)
        }))
    }
}

struct Section {
    start: u64,
    end: u64,
    kind: [u8; 4],
    order: usize,
}

impl Section {
    fn directory<E>(
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        header_end: u64,
    ) -> Result<Option<Vec<Self>>, E> {
        let Some(footer) = input.extent.checked_sub(4) else {
            return Ok(None);
        };
        let Some(&offset) = input.range(footer, 4)?.and_then(<[u8]>::first_chunk) else {
            return Ok(None);
        };
        let directory = u64::from(u32::from_le_bytes(offset));
        let start = directory + 12;
        if directory < header_end || start > footer {
            return Ok(None);
        }
        let Some(header) = input.range(directory, 12)? else {
            return Ok(None);
        };
        let [_, version, count] = words::<3>(header);
        if !header.starts_with(b"SECd")
            || version != VERSION_2_0
            || footer - start != 12 * u64::from(count)
        {
            return Ok(None);
        }
        let Ok(length) = usize::try_from(footer - start) else {
            return Ok(None);
        };
        let Some(entries) = input.range(start, length)? else {
            return Ok(None);
        };

        let mut sections = Vec::new();
        if sections.try_reserve_exact(length / 12).is_err() {
            return Ok(None);
        }
        for (order, entry) in entries.as_chunks::<12>().0.iter().enumerate() {
            let [start, length, kind] = words::<3>(entry);
            let start = u64::from(start);
            let end = start + u64::from(length);
            if start < header_end || !start.is_multiple_of(4) || length < 8 || end > directory {
                return Ok(None);
            }
            sections.push(Self {
                start,
                end,
                kind: kind.to_le_bytes(),
                order,
            });
        }
        sections.sort_unstable_by_key(|section| section.start);
        if sections.windows(2).any(|pair| pair[0].end > pair[1].start) {
            return Ok(None);
        }
        sections.sort_unstable_by_key(|section| section.order);
        Ok(Some(sections))
    }

    fn length(&self) -> u64 {
        self.end - self.start
    }
}

struct Preview {
    start: u64,
    length: u64,
    area: u64,
}

impl Preview {
    fn read<E>(
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        section: Section,
    ) -> Result<Option<Self>, E> {
        if section.length() < 30 {
            return Ok(None);
        }
        let Some(header) = input.range(section.start, 28)? else {
            return Ok(None);
        };
        let [_, version, image_type, format, width, height, _] = words::<7>(header);
        let area = u64::from(width) * u64::from(height);
        if header.starts_with(b"SECi")
            && version == VERSION_2_0
            && image_type == 2
            && format == 18
            && area > 0
            && input.range(section.start + 28, 2)? == Some(b"\xff\xd8")
        {
            return Ok(Some(Self {
                start: section.start + 28,
                length: section.length() - 28,
                area,
            }));
        }
        Ok(None)
    }
}

#[derive(Clone, Copy)]
enum Property {
    Make,
    Model,
    Serial,
    Firmware,
    Iso,
    Aperture,
    Shutter,
    FocalLength,
    FocalLength35mm,
    ExposureCompensation,
    ExposureProgram,
    Metering,
    Flash,
    Quality,
    Balance,
    Date,
}

impl Property {
    const KEYS: [(Self, &'static [u8]); 16] = [
        (Self::Make, b"CAMMANUF"),
        (Self::Model, b"CAMMODEL"),
        (Self::Serial, b"CAMSERIAL"),
        (Self::Firmware, b"FIRMVERS"),
        (Self::Iso, b"ISO"),
        (Self::Aperture, b"APERTURE"),
        (Self::Shutter, b"SHUTTER"),
        (Self::FocalLength, b"FLENGTH"),
        (Self::FocalLength35mm, b"FLEQ35MM"),
        (Self::ExposureCompensation, b"EXPCOMP"),
        (Self::ExposureProgram, b"PMODE"),
        (Self::Metering, b"AEMODE"),
        (Self::Flash, b"FLASH"),
        (Self::Quality, b"RESOLUTION"),
        (Self::Balance, b"WB_DESC"),
        (Self::Date, b"TIME"),
    ];

    fn kind(self) -> u32 {
        match self {
            Self::Make => 95,
            Self::Model => 96,
            Self::Serial => 191,
            Self::Firmware => 113,
            Self::Iso => camera::ISO_SPEED,
            Self::Aperture => camera::APERTURE,
            Self::Shutter => camera::EXPOSURE,
            Self::FocalLength => camera::FOCAL_LENGTH,
            Self::FocalLength35mm => 103,
            Self::ExposureCompensation => 99,
            Self::ExposureProgram => 105,
            Self::Metering => 106,
            Self::Flash => 100,
            Self::Quality => 108,
            Self::Balance => WHITE_BALANCE,
            Self::Date => 58,
        }
    }

    fn parse(self, text: String) -> Option<String> {
        Some(match self {
            Self::Make | Self::Model | Self::Serial | Self::Firmware | Self::Balance => text,
            Self::Iso => text.parse::<NonZeroU32>().ok()?.to_string(),
            Self::Aperture => measure(&text)?.aperture()?,
            Self::Shutter => measure(&text)?.exposure()?,
            Self::FocalLength | Self::FocalLength35mm => measure(&text)?.focal_length()?,
            Self::ExposureCompensation => format!("{:+.2} EV", measure(&text)?.value()),
            Self::ExposureProgram => match text.as_str() {
                "P" => "Auto",
                "A" => "Aperture priority",
                "S" => "Shutter priority",
                "M" => "Manual",
                _ => return None,
            }
            .to_owned(),
            Self::Metering => match text.as_str() {
                "8" => "8-segment",
                "C" => "Center weighted average",
                "A" => "Average",
                _ => return None,
            }
            .to_owned(),
            Self::Flash => match text.as_str() {
                "ON" => "On",
                "OFF" => "Off",
                "AUTO" => "Auto",
                _ => return None,
            }
            .to_owned(),
            Self::Quality => match text.as_str() {
                "LOW" => "Low",
                "MED" => "Medium",
                "HI" => "High",
                _ => return None,
            }
            .to_owned(),
            Self::Date => date(text.parse().ok()?)?,
        })
    }
}

#[derive(Default)]
struct Properties([Option<String>; Property::KEYS.len()]);

impl Properties {
    fn observed(&self) -> [bool; Property::KEYS.len()] {
        std::array::from_fn(|index| self.0[index].is_some())
    }

    fn white_balance(&self) -> Option<&str> {
        self.0[Property::Balance as usize].as_deref()
    }

    fn set_balance(&mut self, balance: String) {
        self.0[Property::Balance as usize] = Some(balance);
    }

    fn read<E>(
        &mut self,
        input: &mut Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        section: Section,
        limit: usize,
    ) -> Result<(), E> {
        if section.length() < 24 {
            return Ok(());
        }
        let Some(header) = input.range(section.start, 24)? else {
            return Ok(());
        };
        let [_, version, count, encoding, _, characters] = words::<6>(header);
        if !header.starts_with(b"SECp") || version != VERSION_2_0 || encoding != 0 {
            return Ok(());
        }
        let table_bytes = 8 * u64::from(count);
        let total = table_bytes + 2 * u64::from(characters);
        if total > section.length() - 24 {
            return Ok(());
        }
        let (Ok(total), Ok(table_bytes)) = (usize::try_from(total), usize::try_from(table_bytes))
        else {
            return Ok(());
        };
        let Some(body) = input.range(section.start + 24, total)? else {
            return Ok(());
        };
        let (table, strings) = body.split_at(table_bytes);
        let mut offsets = [None; Property::KEYS.len()];
        for pair in table.as_chunks::<8>().0 {
            let [name, value] = words::<2>(pair);
            if let Some(name) = utf16_at(strings, name)
                && let Some((key, _)) = Property::KEYS
                    .into_iter()
                    .find(|(_, bytes)| matches_ascii(name, bytes))
            {
                offsets[key as usize] = Some(value);
            }
        }

        for (key, _) in Property::KEYS {
            let index = key as usize;
            if let Some(offset) = offsets[index] {
                self.0[index] = utf16_at(strings, offset)
                    .and_then(|units| decode_text(units, limit))
                    .and_then(|text| key.parse(text))
                    .filter(|text| text.len() <= limit);
            }
        }
        Ok(())
    }

    fn emit<E>(&self, emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>) -> Result<(), E> {
        for (property, _) in Property::KEYS {
            if let Some(value) = &self.0[property as usize] {
                emit(property.kind(), value.as_bytes())?;
            }
        }
        Ok(())
    }

    fn contains(&self, kind: u32) -> bool {
        Property::KEYS
            .iter()
            .any(|(property, _)| property.kind() == kind && self.0[*property as usize].is_some())
    }
}

fn words<const N: usize>(bytes: &[u8]) -> [u32; N] {
    let mut values = [0; N];
    for (word, bytes) in values.iter_mut().zip(bytes.as_chunks::<4>().0) {
        *word = u32::from_le_bytes(*bytes);
    }
    values
}

fn utf16_at(strings: &[u8], offset: u32) -> Option<&[[u8; 2]]> {
    strings
        .as_chunks::<2>()
        .0
        .get(usize::try_from(offset).ok()?..)
}

fn matches_ascii(units: &[[u8; 2]], name: &[u8]) -> bool {
    units.get(name.len()) == Some(&[0, 0])
        && units
            .iter()
            .zip(name)
            .all(|(&unit, &letter)| unit == [letter, 0])
}

fn decode_text(units: &[[u8; 2]], limit: usize) -> Option<String> {
    let end = units
        .iter()
        .take(limit.saturating_add(1))
        .position(|&unit| unit == [0, 0])?;
    let mut text = String::new();
    for character in char::decode_utf16(units[..end].iter().copied().map(u16::from_le_bytes)) {
        let character = character.ok()?;
        if character.is_control() || text.len() + character.len_utf8() > limit {
            return None;
        }
        text.push(character);
    }
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(if trimmed.len() == text.len() {
        text
    } else {
        trimmed.to_owned()
    })
}

fn measure(text: &str) -> Option<Rational> {
    let (negative, text) = match text.as_bytes().first()? {
        b'-' => (true, &text[1..]),
        b'+' => (false, &text[1..]),
        _ => (false, text),
    };
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    if whole.is_empty() && fraction.is_empty()
        || !whole
            .bytes()
            .chain(fraction.bytes())
            .all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let scale = 10_i64.checked_pow(fraction.len().try_into().ok()?)?;
    let whole: i64 = if whole.is_empty() {
        0
    } else {
        whole.parse().ok()?
    };
    let fraction: i64 = if fraction.is_empty() {
        0
    } else {
        fraction.parse().ok()?
    };
    let amount = whole.checked_mul(scale)?.checked_add(fraction)?;
    Rational::new(if negative { -amount } else { amount }, scale)
}

fn date(seconds: i64) -> Option<String> {
    let date = OffsetDateTime::from_unix_timestamp(seconds).ok()?;
    Some(format!(
        "{:04}:{:02}:{:02} {:02}:{:02}:{:02}",
        date.year(),
        u8::from(date.month()),
        date.day(),
        date.hour(),
        date.minute(),
        date.second()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extraction::formats::{Format, MIME_TYPE};

    const RAW: u32 = 4096;
    const OLD_PROPERTIES: u32 = 16_384;
    const NEW_PROPERTIES: u32 = 8192;
    const SMALL_PREVIEW: u32 = 32_768;
    const LARGE_PREVIEW: u32 = 65_536;
    const DIRECTORY: u32 = 67_108_864;

    #[test]
    fn reads_only_metadata_regions_and_observes_property_order() -> Result<(), &'static str> {
        let header = header(0x0002_0001, 232, 28);
        let old = properties(&[("CAMMODEL", "Old"), ("WB_DESC", "Cloudy")]);
        let new = properties(&[
            ("CAMMODEL", "Interim"),
            ("CAMMODEL", "Sigma Δ 📷"),
            ("ISO", "400"),
            ("APERTURE", "5.6"),
            ("SHUTTER", "0.008"),
            ("FLENGTH", "18"),
            ("EXPCOMP", "-0.50"),
            ("TIME", "1714650123"),
        ]);
        let mut raw = b"SECi".to_vec();
        write_words([VERSION_2_0, 3, 30, 2500, 1600, 0], &mut raw);
        let small_preview = preview(64, b"Small");
        let large_preview = preview(256, b"Large");
        let mut directory = directory(&[
            (RAW, 4000, b"IMAG"),
            (SMALL_PREVIEW, 8000, b"IMAG"),
            (LARGE_PREVIEW, 16_000, b"IMA2"),
            (OLD_PROPERTIES, old.len() as u32, b"PROP"),
            (NEW_PROPERTIES, new.len() as u32, b"PROP"),
        ]);
        directory.extend_from_slice(&DIRECTORY.to_le_bytes());

        let regions = [
            (RAW, raw.as_slice()),
            (OLD_PROPERTIES, &old),
            (NEW_PROPERTIES, &new),
            (SMALL_PREVIEW, &small_preview),
            (LARGE_PREVIEW, &large_preview),
            (DIRECTORY, &directory),
        ];
        let mut scratch = [0; 1024];
        let read = |start: u64, buffer: &mut [u8]| {
            let bytes = regions.iter().find_map(|(base, bytes)| {
                let at = usize::try_from(start.checked_sub(u64::from(*base))?).ok()?;
                bytes.get(at..at.checked_add(buffer.len())?)
            });
            buffer.copy_from_slice(bytes.ok_or("unexpected image or unowned range read")?);
            Ok(())
        };
        let mut input = Input::new(
            &header[..4],
            u64::from(DIRECTORY) + directory.len() as u64,
            &mut scratch,
            |at, buffer: &mut [u8]| match usize::try_from(at)
                .ok()
                .and_then(|at| header.get(at..at.checked_add(buffer.len())?))
            {
                Some(bytes) => {
                    buffer.copy_from_slice(bytes);
                    Ok(())
                }
                None => read(at, buffer),
            },
        );
        let mut probe = [0; 32];
        let format = input.probe(&mut probe)?.ok_or("X3F magic")?;
        if !matches!(format, Format::X3f) {
            return Err("expected the X3F format");
        }
        let fields = fields(format, input, 128)?;

        assert_field(&fields, MIME_TYPE, "image/x-sigma-x3f");
        assert_field(&fields, IMAGE_DIMENSIONS, "2500x1600");
        assert_field(&fields, IMAGE_ORIENTATION, "right, top");
        assert_field(&fields, 96, "Sigma Δ 📷");
        assert_field(&fields, WHITE_BALANCE, "Cloudy");
        assert_field(&fields, camera::ISO_SPEED, "400");
        assert_field(&fields, camera::APERTURE, "F5.6");
        assert_field(&fields, camera::EXPOSURE, "1/125 s");
        assert_field(&fields, camera::FOCAL_LENGTH, "18.0 mm");
        assert_field(&fields, 99, "-0.50 EV");
        assert_field(&fields, 58, "2024:05:02 11:42:03");
        assert_field(&fields, 3, "Large");
        if fields.iter().any(|(_, value)| value == b"Small") {
            return Err("metadata from the smaller preview was emitted");
        }
        if fields.iter().filter(|(kind, _)| *kind == 96).count() != 1 {
            return Err("expected one camera model");
        }
        Ok(())
    }

    #[test]
    fn handles_version_four_header_and_rejects_overlapping_sections() -> Result<(), &'static str> {
        const DIRECTORY: u32 = 1024;
        let mut bytes = header(0x0004_0000, 0x300, 40);
        bytes.resize(DIRECTORY as usize, 0);
        bytes.extend(directory(&[]));
        bytes.extend(DIRECTORY.to_le_bytes());

        let fields = from_bytes(&bytes, 128)?;
        assert_field(&fields, IMAGE_DIMENSIONS, "2500x1600");
        assert_field(&fields, IMAGE_ORIENTATION, "right, top");

        bytes.truncate(DIRECTORY as usize);
        bytes.extend(directory(&[(768, 60, b"PROP"), (800, 64, b"CAMF")]));
        bytes.extend(DIRECTORY.to_le_bytes());
        if from_bytes(&bytes, 128)? != [(MIME_TYPE, b"image/x-sigma-x3f".to_vec())] {
            return Err("metadata was emitted from overlapping sections");
        }
        Ok(())
    }

    #[test]
    fn accepts_valid_properties_when_another_table_is_malformed() -> Result<(), &'static str> {
        let mut bytes = header(0x0002_0001, 232, 28);
        let good = properties(&[
            ("CAMMANUF", "Sigma"),
            ("CAMMODEL", "Excessively long camera model"),
        ]);
        let mut invalid = properties(&[("CAMMANUF", "Other")]);
        invalid[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
        let good_offset = bytes.len() as u32;
        bytes.extend(&good);
        bytes.resize(bytes.len().next_multiple_of(4), 0);
        let invalid_offset = bytes.len() as u32;
        bytes.extend(&invalid);
        let directory_offset = bytes.len() as u32;
        bytes.extend(directory(&[
            (good_offset, good.len() as u32, b"PROP"),
            (invalid_offset, invalid.len() as u32, b"PROP"),
        ]));
        bytes.extend(directory_offset.to_le_bytes());

        let fields = from_bytes(&bytes, 16)?;
        assert_field(&fields, 95, "Sigma");
        assert_field(&fields, WHITE_BALANCE, "Daylight");
        if fields.iter().any(|(kind, _)| *kind == 96) {
            return Err("the camera model exceeded the text limit");
        }
        Ok(())
    }

    #[test]
    fn camf_fills_capture_iso_when_the_property_list_has_none() -> Result<(), &'static str> {
        // A SECc type-2 block with a single CaptureISO scalar of 640.0.
        const CAMF: &[u8] = b"\
            \x53\x45\x43\x63\x00\x00\x02\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
            \x00\x00\x00\x00\xd2\x04\x00\x00\x02\x0a\xd5\xb9\x9e\xa6\x9f\xe1\x60\x75\xf4\x64\
            \xa0\xbb\x51\x93\x06\xae\x4c\xf1\x49\x77\x57\x80\x59\xec\x9f\x8f\x68\xe6\x1d\xe3\
            \x91\x69\x72\x3e\xe4\xd3\x41\xf0\xe8\x26\x4a\x95\x7c\xa6\xba\xd2\x14\x3e\xb4\xce\
            \x04\xb3\x0b\xef\x5b\x25\xa7";
        for (prop, expected) in [("", "640"), ("320", "320")] {
            let mut bytes = header(0x0004_0000, 0x300, 40);
            let camf_offset = bytes.len() as u32;
            bytes.extend_from_slice(CAMF);
            bytes.resize(bytes.len().next_multiple_of(4), 0);
            let prop_offset = bytes.len() as u32;
            let prop = properties(&[("ISO", prop)]);
            bytes.extend_from_slice(&prop);
            let directory_offset = bytes.len() as u32;
            bytes.extend(directory(&[
                (camf_offset, CAMF.len() as u32, b"CAMF"),
                (prop_offset, prop.len() as u32, b"PROP"),
            ]));
            bytes.extend(directory_offset.to_le_bytes());
            let fields = from_bytes(&bytes, 128)?;
            assert_field(&fields, camera::ISO_SPEED, expected);
        }
        Ok(())
    }

    fn from_bytes(bytes: &[u8], limit: usize) -> Result<Vec<(u32, Vec<u8>)>, &'static str> {
        let format = Format::detect(bytes).ok_or("X3F magic")?;
        fields(
            format,
            Input::new(bytes, bytes.len() as u64, &mut [], |_, _| {
                Err("unexpected read")
            }),
            limit,
        )
    }

    fn fields(
        format: Format,
        input: Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), &'static str>>,
        limit: usize,
    ) -> Result<Vec<(u32, Vec<u8>)>, &'static str> {
        let mut fields = Vec::new();
        format.visit_text(input, limit, &mut |kind, value| {
            fields.push((kind, value.to_vec()));
            Ok(())
        })?;
        Ok(fields)
    }

    fn assert_field(fields: &[(u32, Vec<u8>)], kind: u32, value: &str) {
        assert!(
            fields
                .iter()
                .any(|(field, bytes)| *field == kind && bytes == value.as_bytes()),
            "missing {kind} {value:?} in {fields:?}"
        );
    }

    fn header(version: u32, length: usize, offset: usize) -> Vec<u8> {
        let mut header = SIGNATURE.to_vec();
        write_words([version], &mut header);
        header.resize(offset, 0);
        write_words([2500, 1600, 90], &mut header);
        if version == 0x0002_0001 {
            header.extend_from_slice(b"Daylight\0");
        }
        header.resize(length, 0);
        header
    }

    fn properties(properties: &[(&str, &str)]) -> Vec<u8> {
        let mut table = Vec::new();
        let mut strings = Vec::new();
        for &(name, value) in properties {
            for string in [name, value] {
                write_words([(strings.len() / 2) as u32], &mut table);
                for unit in string.encode_utf16().chain([0]) {
                    strings.extend_from_slice(&unit.to_le_bytes());
                }
            }
        }
        let mut section = b"SECp".to_vec();
        write_words(
            [
                VERSION_2_0,
                properties.len() as u32,
                0,
                0,
                (strings.len() / 2) as u32,
            ],
            &mut section,
        );
        section.extend(table);
        section.extend(strings);
        section
    }

    fn preview(size: u32, comment: &[u8]) -> Vec<u8> {
        let mut bytes = b"SECi".to_vec();
        write_words([VERSION_2_0, 2, 18, size, size, 0], &mut bytes);
        bytes.extend(b"\xff\xd8\xff\xfe");
        bytes.extend(((comment.len() + 2) as u16).to_be_bytes());
        bytes.extend(comment);
        bytes.extend(b"\xff\xda\x00\x08");
        bytes
    }

    fn directory(entries: &[(u32, u32, &[u8; 4])]) -> Vec<u8> {
        let mut bytes = b"SECd".to_vec();
        write_words([VERSION_2_0, entries.len() as u32], &mut bytes);
        for &(offset, length, kind) in entries {
            write_words([offset, length], &mut bytes);
            bytes.extend_from_slice(kind);
        }
        bytes
    }

    fn write_words<const N: usize>(words: [u32; N], bytes: &mut Vec<u8>) {
        for word in words {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
    }
}
