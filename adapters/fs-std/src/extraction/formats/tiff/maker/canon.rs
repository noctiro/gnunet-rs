//! GNU metadata from the Canon CameraSettings and ShotInfo arrays.

use super::super::{Directory, Selection, Tiff};
use super::{EXPOSURE_PROGRAM, IMAGE_QUALITY, ISO_SPEED, MACRO_MODE, WHITE_BALANCE};
use std::borrow::Cow;

const CAMERA_SETTINGS: u16 = 0x0001;
const SHOT_INFO: u16 = 0x0004;
const FLASH_BIAS: u32 = 101;
const MAX_READ_WORDS: usize = 21;

pub(in super::super) fn visit_directory<E>(
    tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    directory: Directory,
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    let Some(selection) = Selection::read_directory(tiff, directory, |tag| {
        matches!(tag, CAMERA_SETTINGS | SHOT_INFO)
    })?
    else {
        return Ok(());
    };
    for (tag, fields) in [(CAMERA_SETTINGS, SETTINGS_FIELDS), (SHOT_INFO, SHOT_FIELDS)] {
        let Some(selected) = selection.find(tag).filter(|field| !field.duplicate) else {
            continue;
        };
        let mut words = [0; MAX_READ_WORDS];
        let needed = fields.last().map_or(0, |field| field.index + 1);
        let count = selected.row.len() / size_of::<u16>();
        let prefix = &mut words[..needed.min(count)];
        if !tiff.read_short_prefix(&selected.row, prefix)?
            || prefix.first().copied().map(usize::from) != Some(selected.row.len())
        {
            continue;
        }
        for field in fields {
            if let Some(&raw) = prefix.get(field.index)
                && let Some(value) = field.format.decode(raw)
                && value.len() <= limit
            {
                emit(field.kind, value.as_bytes())?;
            }
        }
    }
    Ok(())
}

struct Field {
    index: usize,
    kind: u32,
    format: Format,
}

enum Format {
    Labels(&'static [(u16, &'static str)]),
    Iso,
}

impl Format {
    fn decode(&self, raw: u16) -> Option<Cow<'static, str>> {
        match self {
            Self::Labels(labels) => Some(
                labels
                    .iter()
                    .find_map(|&(code, text)| (code == raw).then_some(Cow::Borrowed(text)))
                    .unwrap_or_else(|| Cow::Owned(format!("({raw})"))),
            ),
            Self::Iso => canon_iso(raw).map(Cow::Owned),
        }
    }
}

fn canon_iso(raw: u16) -> Option<String> {
    let stops = raw / 32;
    let fraction = match (stops, raw % 32) {
        (_, 12) => 1.0 / 3.0,
        (_, 20) => 2.0 / 3.0,
        (5, 8) => 10.0 / 32.0,
        (_, fraction) => f32::from(fraction) / 32.0,
    };
    let iso = (f32::from(stops) + fraction).exp2() * (100.0 / 32.0);
    if !iso.is_finite() {
        return None;
    }
    // Exiv2 prints ISO values with six significant digits in general format.
    let scientific = format!("{iso:.5e}");
    let (digits, exponent) = scientific.split_once('e')?;
    let exponent: usize = exponent.parse().ok()?;
    if exponent >= 6 {
        let digits = digits.trim_end_matches('0').trim_end_matches('.');
        return Some(format!("{digits}e+{exponent:02}"));
    }
    let decimals = 5 - exponent;
    let decimal = format!("{iso:.decimals$}");
    if decimals == 0 {
        Some(decimal)
    } else {
        Some(
            decimal
                .trim_end_matches('0')
                .trim_end_matches('.')
                .to_owned(),
        )
    }
}

const SETTINGS_FIELDS: &[Field] = &[
    Field {
        index: 1,
        kind: MACRO_MODE,
        format: Format::Labels(&[(1, "On"), (2, "Off")]),
    },
    Field {
        index: 3,
        kind: IMAGE_QUALITY,
        format: Format::Labels(&[
            (0xffff, "n/a"),
            (0, "unknown"),
            (1, "Economy"),
            (2, "Normal"),
            (3, "Fine"),
            (4, "RAW"),
            (5, "Superfine"),
            (7, "CRAW"),
            (130, "Normal Movie"),
            (131, "Movie (2)"),
        ]),
    },
    Field {
        index: 20,
        kind: EXPOSURE_PROGRAM,
        format: Format::Labels(&[
            (0, "Easy shooting (Auto)"),
            (1, "Program (P)"),
            (2, "Shutter priority (Tv)"),
            (3, "Aperture priority (Av)"),
            (4, "Manual (M)"),
            (5, "A-DEP"),
            (6, "M-DEP"),
            (7, "Bulb"),
        ]),
    },
];

const SHOT_FIELDS: &[Field] = &[
    Field {
        index: 2,
        kind: ISO_SPEED,
        format: Format::Iso,
    },
    Field {
        index: 7,
        kind: WHITE_BALANCE,
        format: Format::Labels(&[
            (0, "Auto"),
            (1, "Daylight"),
            (2, "Cloudy"),
            (3, "Tungsten"),
            (4, "Fluorescent"),
            (5, "Flash"),
            (6, "Custom"),
            (7, "Black & White"),
            (8, "Shade"),
            (9, "Manual Temperature (Kelvin)"),
            (10, "PC Set 1"),
            (11, "PC Set 2"),
            (12, "PC Set 3"),
            (14, "Daylight Fluorescent"),
            (15, "Custom 1"),
            (16, "Custom 2"),
            (17, "Underwater"),
            (18, "Custom 3"),
            (19, "Custom 3"),
            (20, "PC Set 4"),
            (21, "PC Set 5"),
            (23, "Auto (ambience priority)"),
        ]),
    },
    Field {
        index: 15,
        kind: FLASH_BIAS,
        format: Format::Labels(&[
            (0xffc0, "-2 EV"),
            (0xffcc, "-1.67 EV"),
            (0xffd0, "-1.50 EV"),
            (0xffd4, "-1.33 EV"),
            (0xffe0, "-1 EV"),
            (0xffec, "-0.67 EV"),
            (0xfff0, "-0.50 EV"),
            (0xfff4, "-0.33 EV"),
            (0, "0 EV"),
            (0x000c, "0.33 EV"),
            (0x0010, "0.50 EV"),
            (0x0014, "0.67 EV"),
            (0x0020, "1 EV"),
            (0x002c, "1.33 EV"),
            (0x0030, "1.50 EV"),
            (0x0034, "1.67 EV"),
            (0x0040, "2 EV"),
        ]),
    },
];
