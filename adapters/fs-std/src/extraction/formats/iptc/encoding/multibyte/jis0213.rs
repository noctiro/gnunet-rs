//! JIS X 0213 registered planes in ISO 2375 row and cell order.

use super::{Glyph, Position94};

const WIDTH: usize = 94;
const FIRST: u8 = 0x21;
const SECOND_ROWS: [u8; 26] = [
    0x21, 0x23, 0x24, 0x25, 0x28, 0x2c, 0x2d, 0x2e, 0x2f, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74,
    0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e,
];

// Attribution and the table layout are recorded in JIS0213-NOTICE.txt.
const TABLE_BYTES: usize = (WIDTH + SECOND_ROWS.len()) * WIDTH * 3;
static TABLE: &[u8; TABLE_BYTES] = include_bytes!("jis0213.bin");
const PAIR_START: u32 = 0x110000;
const PAIRS: [(char, char); 25] = [
    ('か', '\u{309a}'),
    ('き', '\u{309a}'),
    ('く', '\u{309a}'),
    ('け', '\u{309a}'),
    ('こ', '\u{309a}'),
    ('カ', '\u{309a}'),
    ('キ', '\u{309a}'),
    ('ク', '\u{309a}'),
    ('ケ', '\u{309a}'),
    ('コ', '\u{309a}'),
    ('セ', '\u{309a}'),
    ('ツ', '\u{309a}'),
    ('ト', '\u{309a}'),
    ('ㇷ', '\u{309a}'),
    ('æ', '\u{300}'),
    ('ɔ', '\u{300}'),
    ('ɔ', '\u{301}'),
    ('ʌ', '\u{300}'),
    ('ʌ', '\u{301}'),
    ('ə', '\u{300}'),
    ('ə', '\u{301}'),
    ('ɚ', '\u{300}'),
    ('ɚ', '\u{301}'),
    ('˩', '˥'),
    ('˥', '˩'),
];

#[derive(Clone, Copy)]
pub(in super::super) enum Jis0213 {
    First2000,
    Second,
    First2004,
}

impl Jis0213 {
    pub(super) fn glyph(self, Position94 { row, cell }: Position94) -> Option<Glyph> {
        let row_index = match self {
            // ISO-IR 233 adds ten characters to ISO-IR 228.
            Self::First2000
                if matches!(
                    (row, cell),
                    (0x2e, 0x21)
                        | (0x2f, 0x7e)
                        | (0x4f, 0x54 | 0x7e)
                        | (0x74, 0x27)
                        | (0x7e, 0x7a..=0x7e)
                ) =>
            {
                return None;
            }
            Self::First2000 | Self::First2004 => usize::from(row - FIRST),
            Self::Second => WIDTH + SECOND_ROWS.binary_search(&row).ok()?,
        };
        let offset = (row_index * WIDTH + usize::from(cell - FIRST)) * 3;
        let [low, middle, high] = *TABLE.get(offset..)?.first_chunk::<3>()?;
        let encoded = u32::from_le_bytes([low, middle, high, 0]);
        match encoded {
            0 => None,
            PAIR_START.. => {
                let &(first, second) = PAIRS.get((encoded - PAIR_START) as usize)?;
                Some(Glyph::Pair(first, second))
            }
            scalar => char::from_u32(scalar).map(Glyph::from),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::DoubleByte94;
    use super::Glyph;

    #[test]
    fn jis0213_preserves_registered_repertoires_and_scalar_pairs() {
        for (selector, expected_assignments, expected_pairs) in
            [(b'O', 8_787, 25), (b'P', 2_436, 0), (b'Q', 8_797, 25)]
        {
            let plane = DoubleByte94::designated(selector);
            let mut assigned = 0;
            let mut pairs = 0;
            for row in 0x21..=0x7e {
                for cell in 0x21..=0x7e {
                    if let Some(glyph) = plane.and_then(|plane| plane.glyph(row, cell)) {
                        assigned += 1;
                        pairs += usize::from(matches!(glyph, Glyph::Pair(..)));
                    }
                }
            }
            assert_eq!((assigned, pairs), (expected_assignments, expected_pairs));
        }
        let at = |final_byte, row, cell| DoubleByte94::designated(final_byte)?.glyph(row, cell);
        assert_eq!(at(b'O', 0x24, 0x77), Some(Glyph::Pair('か', '\u{309a}')));
        assert_eq!(at(b'Q', 0x2b, 0x66), Some(Glyph::Pair('˥', '˩')));
        assert_eq!(at(b'O', 0x4f, 0x54), None);
        assert_eq!(at(b'Q', 0x4f, 0x54), Some(Glyph::Scalar('\u{20b9f}')));
        assert_eq!(at(b'P', 0x21, 0x21), Some(Glyph::Scalar('\u{20089}')));
        assert_eq!(at(b'P', 0x7d, 0x3b), Some(Glyph::Scalar('\u{9b1d}')));
        assert_eq!(at(b'P', 0x22, 0x21), None);
        assert_eq!(at(b'P', 0x7e, 0x77), None);
    }
}
