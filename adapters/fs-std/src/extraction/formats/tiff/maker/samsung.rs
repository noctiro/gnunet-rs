//! Samsung Type 2 camera fields and Pentax-compatible MakerNote dispatch.

use super::{
    ByteOrder, FOCAL_LENGTH_35MM, Field, Fields, ISO_SPEED, Kind, NoteLayout, Row, Selection, Tiff,
    emit_selection, pentax,
};
use crate::extraction::formats::{
    camera,
    tiff::{Representation, emit_entry},
};
use std::ops::RangeInclusive;

#[cfg(test)]
mod tests;

const DEVICE_TYPE: u16 = 0x0002;
const MODEL_ID: u16 = 0x0003;
const RAW_VERSION: u16 = 0xa000;
const FIRMWARE_NAME: u16 = 0xa001;
const EXPOSURE_BIAS: u16 = 0xa013;
const EXPOSURE_TIME: u16 = 0xa018;
const F_NUMBER: u16 = 0xa019;
const FOCAL_LENGTH_35MM_TAG: u16 = 0xa01a;

#[derive(Clone, Copy)]
pub(in crate::extraction::formats::tiff) enum Model {
    Unknown,
    Nx5,
    Nx10,
    Nx11,
    Nx100,
    Nx200Platform,
    Nx300Platform,
    Nx500,
    Wb2000,
    Ex2f,
}

impl Model {
    pub(super) fn from_ascii(bytes: Option<&[u8]>) -> Self {
        let Some(model) = bytes
            .and_then(|bytes| bytes.split(|&byte| byte == 0).next())
            .map(<[u8]>::trim_ascii)
        else {
            return Self::Unknown;
        };
        for (name, known) in [
            (b"NX5".as_slice(), Self::Nx5),
            (b"NX10", Self::Nx10),
            (b"NX11", Self::Nx11),
            (b"NX100", Self::Nx100),
            (b"NX20", Self::Nx200Platform),
            (b"NX200", Self::Nx200Platform),
            (b"NX210", Self::Nx200Platform),
            (b"NX1000", Self::Nx200Platform),
            (b"NX1100", Self::Nx200Platform),
            (b"NX300", Self::Nx300Platform),
            (b"NX300M", Self::Nx300Platform),
            (b"NX500", Self::Nx500),
            (b"WB2000", Self::Wb2000),
            (b"EX2F", Self::Ex2f),
        ] {
            if model.eq_ignore_ascii_case(name) {
                return known;
            }
        }
        Self::Unknown
    }

    fn raw_profile(self) -> Option<RawProfile> {
        use FocalLengthScale::{Decimillimetre, Millimetre};
        let (device, ids, firmware, focal): (_, &'static [u64], _, _) = match self {
            Self::Unknown => return None,
            Self::Nx5 => (
                0x2000,
                &[0x0100_101d],
                Firmware::Dated(b"NX5_FW_X_F"),
                Some(Decimillimetre),
            ),
            Self::Nx10 => (
                0x2000,
                &[0x0100_101c, 0x0100_101d],
                Firmware::Dated(b"NX10_FW_X_F"),
                Some(Decimillimetre),
            ),
            Self::Nx11 => (
                0x2000,
                &[0x0100_1327],
                Firmware::Dated(b"NX11_FW_X_F"),
                Some(Decimillimetre),
            ),
            Self::Nx100 => (
                0x2000,
                &[0x0100_130c],
                Firmware::Dated(b"NX100_FW_X_F"),
                Some(Decimillimetre),
            ),
            Self::Nx200Platform => (0x2000, &[0x0500_0000], Firmware::Nx200Version, None),
            Self::Nx300Platform => (
                0x2000,
                &[0x0500_1038],
                Firmware::NxVersion,
                Some(Millimetre),
            ),
            Self::Nx500 => (
                0x2000,
                &[0x0500_1038],
                Firmware::NxVersion,
                Some(Decimillimetre),
            ),
            Self::Wb2000 => (
                0x1000,
                &[0x0500_1038],
                Firmware::CompactVersion,
                Some(Millimetre),
            ),
            Self::Ex2f => (
                0x1000,
                &[0x0500_0000],
                Firmware::CompactVersion,
                Some(Millimetre),
            ),
        };
        Some(RawProfile {
            device,
            ids,
            firmware,
            focal,
        })
    }
}

#[derive(Clone, Copy)]
pub(super) enum FocalLengthScale {
    Millimetre,
    Decimillimetre,
}

#[derive(Clone, Copy)]
enum Firmware {
    Dated(&'static [u8]),
    Nx200Version,
    NxVersion,
    CompactVersion,
}

impl Firmware {
    fn accepts(self, bytes: &[u8]) -> bool {
        let digit = |value: &u8| value.is_ascii_digit();
        let Some(end) = bytes.iter().position(|&byte| byte == 0) else {
            return false;
        };
        let (name, terminator_and_padding) = bytes.split_at(end);
        let padding = &terminator_and_padding[1..];
        match self {
            Self::Dated(prefix) => name.strip_prefix(prefix).is_some_and(|date| {
                date.len() == 7 && date.iter().all(digit) && padding.iter().all(|&byte| byte == 0)
            }),
            Self::Nx200Version => name.strip_prefix(b"NX200_").is_some_and(|version| {
                matches!(version, [a,b,b'.',c,d] if [a,b,c,d].into_iter().all(digit))
                    && padding.iter().all(|&byte| byte == 0xee)
            }),
            Self::NxVersion => matches!(name, [a,b'.',b,c] if [a,b,c].into_iter().all(digit)),
            Self::CompactVersion => name
                .strip_prefix(b"FM1_")
                .is_some_and(|version| version.len() == 6 && version.iter().all(digit)),
        }
    }
}

#[derive(Clone, Copy)]
struct RawProfile {
    device: u64,
    ids: &'static [u64],
    firmware: Firmware,
    focal: Option<FocalLengthScale>,
}

pub(super) struct Note {
    order: ByteOrder,
    model: Model,
}

pub(super) fn layout(header: &[u8], model: Model) -> Option<NoteLayout> {
    if let Some(layout) = pentax::layout(header) {
        return Some(layout);
    }
    // The first IFD row identifies the Samsung Type 2 layout and its order.
    let order = match header {
        [
            0,
            1..=u8::MAX,
            0,
            1,
            0,
            7,
            0,
            0,
            0,
            4,
            b'0',
            b'1',
            b'0',
            b'0',
            ..,
        ] => ByteOrder::Big,
        [
            1..=u8::MAX,
            0,
            1,
            0,
            7,
            0,
            4,
            0,
            0,
            0,
            b'0',
            b'1',
            b'0',
            b'0',
            ..,
        ] => ByteOrder::Little,
        _ => return None,
    };
    Some(NoteLayout::Samsung(Note { order, model }))
}

impl Note {
    pub(super) fn visit<E>(
        self,
        tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        row: Row,
        limit: usize,
        emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        // Supported SRW profiles use MakerNote-relative external offsets.
        let Some(input) = tiff.section_for_field(row) else {
            return Ok(());
        };
        let Some(mut maker) = Tiff::open_classic_ifd(input, self.order, 0, 0) else {
            return Ok(());
        };
        let Some(directory) = maker.directory(0)? else {
            return Ok(());
        };
        let values_start = directory.encoded_end();
        let candidate = self.model.raw_profile();
        let Some(selection) = Selection::read_directory(&mut maker, directory, |tag| {
            matches!(tag, 0xa014 | FOCAL_LENGTH_35MM_TAG)
                || candidate.is_some()
                    && matches!(
                        tag,
                        DEVICE_TYPE
                            | MODEL_ID
                            | RAW_VERSION
                            | FIRMWARE_NAME
                            | EXPOSURE_BIAS
                            | EXPOSURE_TIME
                            | F_NUMBER
                    )
        })?
        else {
            return Ok(());
        };
        let external = ExternalFields {
            selection: &selection,
            values_start,
        };
        let profile = match candidate {
            Some(candidate) if external.qualifies(&mut maker, candidate)? => Some(candidate),
            _ => None,
        };
        let focal = profile.map_or(Some(FocalLengthScale::Decimillimetre), |profile| {
            profile.focal
        });
        emit_selection(&mut maker, &selection, Fields::Samsung(focal), limit, emit)?;
        if let Some(profile) = profile {
            if let Some(row) = external.at(EXPOSURE_BIAS, Kind::SRational, 1..=1)
                && let Some(entry) = maker.read_field(&row)?
                && !(matches!(profile.firmware, Firmware::Nx200Version)
                    && entry
                        .rational(0)
                        .is_some_and(|value| value.numerator == 0 && value.denominator.get() == 1))
            {
                emit_entry(entry, 99, Representation::ExposureBias, limit, emit)?;
            }
            // Some SRW variants store two rationals. The first is the camera's
            // published scalar and the whole row must fit within the note.
            for (tag, kind, format) in [
                (
                    EXPOSURE_TIME,
                    camera::EXPOSURE,
                    camera::Rational::exposure as fn(camera::Rational) -> Option<String>,
                ),
                (F_NUMBER, camera::APERTURE, camera::Rational::aperture),
            ] {
                if let Some(row) = external.at(tag, Kind::Rational, 1..=2)
                    && let Some(value) = maker
                        .read_field(&row)?
                        .and_then(|entry| entry.rational(0))
                        .and_then(format)
                    && value.len() <= limit
                {
                    emit(kind, value.as_bytes())?;
                }
            }
        }
        Ok(())
    }
}

struct ExternalFields<'a> {
    selection: &'a Selection,
    values_start: u64,
}

impl ExternalFields<'_> {
    fn at(&self, tag: u16, kind: Kind, counts: RangeInclusive<u64>) -> Option<Row> {
        let field = self.selection.find(tag)?;
        (!field.duplicate
            && field.row.kind() == kind
            && counts.contains(&field.row.count())
            && field.row.external_at_or_after(self.values_start))
        .then_some(field.row)
    }

    fn qualifies<E>(
        &self,
        maker: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
        profile: RawProfile,
    ) -> Result<bool, E> {
        for (tag, accepted) in [
            (DEVICE_TYPE, std::slice::from_ref(&profile.device)),
            (MODEL_ID, profile.ids),
        ] {
            let Some(field) = self.selection.find(tag).filter(|field| {
                !field.duplicate && field.row.kind() == Kind::Long && field.row.count() == 1
            }) else {
                return Ok(false);
            };
            if !maker
                .read_field(&field.row)?
                .and_then(|entry| entry.unsigned(0))
                .is_some_and(|value| accepted.contains(&value))
            {
                return Ok(false);
            }
        }
        if !matches!(profile.firmware, Firmware::Dated(_)) {
            let Some(row) = self.at(RAW_VERSION, Kind::Rational, 1..=1) else {
                return Ok(false);
            };
            if !maker
                .read_field(&row)?
                .and_then(|entry| entry.rational(0))
                .is_some_and(|value| value.numerator == 100 && value.denominator.get() == 100)
            {
                return Ok(false);
            }
        }
        let Some(firmware) = self.at(FIRMWARE_NAME, Kind::Ascii, 30..=30) else {
            return Ok(false);
        };
        Ok(maker
            .read_field(&firmware)?
            .is_some_and(|entry| profile.firmware.accepts(entry.bytes())))
    }
}

pub(super) fn field(tag: u16, scale: Option<FocalLengthScale>) -> Option<(u32, Field)> {
    Some(match tag {
        0xa014 => (ISO_SPEED, Field::IntegerIso(Kind::Long)),
        FOCAL_LENGTH_35MM_TAG => (FOCAL_LENGTH_35MM, Field::LongFocalLength35mm(scale?)),
        _ => return None,
    })
}
