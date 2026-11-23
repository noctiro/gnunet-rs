//! Graphic positions of JIS C 6226-1978 from the ISO-IR 42 registration.

use super::{Glyph, Position94};

const ROW_WIDTH: usize = 94;
const NON_KANJI_ROWS: usize = 7;
const KANJI_ROWS: usize = 68;
const SCALAR_BITS: u32 = 21;
const SCALAR_MASK: u32 = (1 << SCALAR_BITS) - 1;

// Source versions, word layout and terms are recorded in JIS-1978-NOTICE.txt.
const TABLE_BYTES: usize = (NON_KANJI_ROWS + KANJI_ROWS) * ROW_WIDTH * 3;
static TABLE: &[u8; TABLE_BYTES] = include_bytes!("jis1978.bin");

pub(super) fn glyph(Position94 { row, cell }: Position94) -> Option<Glyph> {
    let row_index = match row {
        0x21..=0x27 => usize::from(row - 0x21),
        0x30..=0x73 => NON_KANJI_ROWS + usize::from(row - 0x30),
        _ => return None,
    };
    let offset = (row_index * ROW_WIDTH + usize::from(cell - 0x21)) * 3;
    let [low, middle, high] = *TABLE.get(offset..)?.first_chunk::<3>()?;
    let word = u32::from_le_bytes([low, middle, high, 0]);
    let scalar = word & SCALAR_MASK;
    if scalar == 0 {
        return None;
    }
    let character = char::from_u32(scalar)?;
    Some(match word >> SCALAR_BITS {
        0 => Glyph::Scalar(character),
        1 => Glyph::Pair(character, '\u{fe00}'),
        2 => Glyph::Pair(character, '\u{e0100}'),
        3 => Glyph::Pair(character, '\u{e0101}'),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::super::DoubleByte94;
    use super::Glyph;

    #[test]
    fn jis1978_preserves_registered_cells_and_historical_glyphs() {
        let legacy = DoubleByte94::JisC6226;
        let modern = DoubleByte94::JisX0208;
        let mut assigned = 0;
        let mut paired = 0;
        for row in 0x21..=0x7e {
            for cell in 0x21..=0x7e {
                match legacy.glyph(row, cell) {
                    Some(Glyph::Scalar(_)) => assigned += 1,
                    Some(Glyph::Pair(_, _)) => {
                        assigned += 1;
                        paired += 1;
                    }
                    None => {}
                }
            }
        }
        assert_eq!((assigned, paired), (6_802, 161));
        assert_eq!(legacy.glyph(0x22, 0x2f), None);
        assert_eq!(legacy.glyph(0x28, 0x21), None);
        assert_eq!(legacy.glyph(0x74, 0x21), None);
        assert_eq!(legacy.glyph(0x32, 0x2a), Some(Glyph::Scalar('鷗')));
        assert_eq!(modern.glyph(0x32, 0x2a), Some(Glyph::Scalar('鴎')));
        assert_eq!(
            legacy.glyph(0x31, 0x35),
            Some(Glyph::Pair('欝', '\u{e0101}'))
        );
    }
}
