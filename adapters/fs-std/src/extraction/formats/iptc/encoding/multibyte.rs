//! Two-byte ISO 2375 graphic repertoires in their original registered versions.

mod cns11643;
mod jis0213;
mod jis1978;

use encoding_rs::{EUC_JP, EUC_KR, GB18030};

use self::{cns11643::Cns11643, jis0213::Jis0213};
use super::repertoire::{Glyph, scalar};

#[derive(Clone, Copy)]
pub(super) enum DoubleByte94 {
    Gb2312,
    JisC6226,
    JisX0208,
    JisX0208Revision1,
    KsC5601,
    JisX0212,
    Cns11643(Cns11643),
    JisX0213(Jis0213),
}

struct Position94 {
    row: u8,
    cell: u8,
}

impl Position94 {
    fn new(row: u8, cell: u8) -> Option<Self> {
        (matches!(row, 0x21..=0x7e) && matches!(cell, 0x21..=0x7e)).then_some(Self { row, cell })
    }
}

impl DoubleByte94 {
    pub(super) fn designated(final_byte: u8) -> Option<Self> {
        Some(match final_byte {
            b'@' => Self::JisC6226, // ISO-IR 42, JIS C 6226-1978
            b'A' => Self::Gb2312,   // ISO-IR 58, GB 2312-1980
            b'B' => Self::JisX0208, // ISO-IR 87, JIS C 6226-1983
            b'C' => Self::KsC5601,  // ISO-IR 149, KS C 5601-1987
            b'D' => Self::JisX0212, // ISO-IR 159, JIS X 0212-1990
            b'G'..=b'M' => Self::Cns11643(Cns11643::designated(final_byte)?),
            b'O' => Self::JisX0213(Jis0213::First2000), // ISO-IR 228
            b'P' => Self::JisX0213(Jis0213::Second),    // ISO-IR 229
            b'Q' => Self::JisX0213(Jis0213::First2004), // ISO-IR 233
            _ => return None,
        })
    }

    pub(super) fn revised(final_byte: u8, revision: u8) -> Option<Self> {
        // ISO-IR 168, JIS X 0208-1990.
        ((final_byte, revision) == (b'B', b'@')).then_some(Self::JisX0208Revision1)
    }

    pub(super) fn glyph(self, row: u8, cell: u8) -> Option<Glyph> {
        let position = Position94::new(row, cell)?;
        let euc_pair = [row | 0x80, cell | 0x80];
        let character = match self {
            Self::Gb2312 => gb2312(row, cell, euc_pair),
            Self::JisC6226 => return jis1978::glyph(position),
            Self::JisX0208Revision1 if (row, cell) == (0x74, 0x25) => Some('凜'),
            Self::JisX0208Revision1 if (row, cell) == (0x74, 0x26) => Some('熙'),
            Self::JisX0208 | Self::JisX0208Revision1 => {
                if matches!(row, 0x2d | 0x75..=0x7e) || (row, cell) >= (0x74, 0x25) {
                    return None;
                }
                let character = scalar(EUC_JP, &euc_pair)?;
                Some(match character {
                    '～' => '〜',
                    '∥' => '‖',
                    '－' => '−',
                    '￠' => '¢',
                    '￡' => '£',
                    '￢' => '¬',
                    character => character,
                })
            }
            // KS X 1001:1998 added EURO SIGN and REGISTERED SIGN after ISO-IR 149.
            Self::KsC5601 if matches!((row, cell), (0x22, 0x66 | 0x67)) => None,
            Self::KsC5601 => scalar(EUC_KR, &euc_pair),
            // ISO-IR 159 assigns plain tilde here. WHATWG EUC-JP uses fullwidth tilde.
            Self::JisX0212 if (row, cell) == (0x22, 0x37) => Some('~'),
            Self::JisX0212 => scalar(EUC_JP, &[0x8f, euc_pair[0], euc_pair[1]]),
            Self::Cns11643(plane) => plane.character(position),
            Self::JisX0213(edition) => return edition.glyph(position),
        }?;
        Some(character.into())
    }
}

fn gb2312(row: u8, cell: u8, euc_pair: [u8; 2]) -> Option<char> {
    // ISO-IR 58 chart. GB18030 also assigns the gaps between these ranges.
    let assigned = match row {
        0x21 | 0x23 | 0x30..=0x56 | 0x58..=0x77 => true,
        0x22 => matches!(cell, 0x31..=0x62 | 0x65..=0x6e | 0x71..=0x7c),
        0x24 => cell <= 0x73,
        0x25 => cell <= 0x76,
        0x26 => matches!(cell, 0x21..=0x38 | 0x41..=0x58),
        0x27 => matches!(cell, 0x21..=0x41 | 0x51..=0x71),
        0x28 => matches!(cell, 0x21..=0x3a | 0x45..=0x69),
        0x29 => matches!(cell, 0x24..=0x6f),
        0x57 => cell <= 0x79,
        _ => false,
    };
    if !assigned {
        return None;
    }
    // Unicode's GB2312-80 mapping differs from GB18030 at these punctuation cells.
    match (row, cell) {
        (0x21, 0x24) => Some('・'),
        (0x21, 0x2a) => Some('―'),
        _ => scalar(GB18030, &euc_pair),
    }
}
