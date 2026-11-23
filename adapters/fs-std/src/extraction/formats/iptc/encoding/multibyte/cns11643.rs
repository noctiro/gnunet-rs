//! CNS 11643-1992 planes registered as ISO-IR 171, 172 and 183–187.

use super::Position94;

const ROW_WIDTH: usize = 94;
const FIRST_CODE: u8 = 0x21;
const SCALAR_BYTES: usize = 3;
const COUNTS: [usize; 7] = [6085, 7650, 6148, 7298, 8603, 6388, 6539];

const fn offsets() -> [usize; COUNTS.len() + 1] {
    let mut offsets = [0; COUNTS.len() + 1];
    let mut plane = 0;
    while plane < COUNTS.len() {
        offsets[plane + 1] = offsets[plane] + COUNTS[plane];
        plane += 1;
    }
    offsets
}

const OFFSETS: [usize; COUNTS.len() + 1] = offsets();
const TABLE_BYTES: usize = OFFSETS[COUNTS.len()] * SCALAR_BYTES;
static TABLE: &[u8; TABLE_BYTES] = include_bytes!("cns11643.bin");

#[derive(Clone, Copy)]
pub(in super::super) struct Cns11643(usize);

impl Cns11643 {
    pub(super) fn designated(final_byte: u8) -> Option<Self> {
        (b'G'..=b'M')
            .contains(&final_byte)
            .then(|| Self(usize::from(final_byte - b'G')))
    }

    pub(super) fn character(self, Position94 { row, cell }: Position94) -> Option<char> {
        let cell = usize::from(cell - FIRST_CODE);
        let index = if self.0 == 0 {
            first_plane_index(row, cell)?
        } else {
            usize::from(row - FIRST_CODE) * ROW_WIDTH + cell
        };
        if index >= COUNTS[self.0] {
            return None;
        }
        let offset = (OFFSETS[self.0] + index) * SCALAR_BYTES;
        let [low, middle, high] = *TABLE.get(offset..)?.first_chunk::<SCALAR_BYTES>()?;
        char::from_u32(u32::from_le_bytes([low, middle, high, 0]))
    }
}

fn first_plane_index(row: u8, cell: usize) -> Option<usize> {
    // ISO-IR 171 assigns 651 symbols in rows 1–9 and 33 control pictures
    // in row 34. Its 5401 ideographs start at row 36.
    const SYMBOL_OFFSETS: [usize; 10] = [0, 94, 188, 234, 328, 408, 438, 532, 626, 651];
    const CONTROL_PICTURES: usize = 33;
    const SYMBOLS: usize = SYMBOL_OFFSETS[9];
    match row {
        0x21..=0x29 => {
            let row = usize::from(row - FIRST_CODE);
            let index = SYMBOL_OFFSETS[row] + cell;
            (index < SYMBOL_OFFSETS[row + 1]).then_some(index)
        }
        0x42 => (cell < CONTROL_PICTURES).then_some(SYMBOLS + cell),
        0x44..=0x7e => {
            Some(SYMBOLS + CONTROL_PICTURES + usize::from(row - 0x44) * ROW_WIDTH + cell)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::super::{DoubleByte94, Glyph};
    use super::COUNTS;

    #[test]
    fn cns11643_planes_keep_the_registered_assignment_boundaries() {
        for (selector, expected) in (b'G'..=b'M').zip(COUNTS) {
            let actual = (0x21..=0x7e)
                .flat_map(|row| (0x21..=0x7e).map(move |cell| (row, cell)))
                .filter_map(|(row, cell)| DoubleByte94::designated(selector)?.glyph(row, cell))
                .count();
            assert_eq!(actual, expected, "designation {}", char::from(selector));
        }
        let decode = |selector, row, cell| DoubleByte94::designated(selector)?.glyph(row, cell);
        assert_eq!(decode(b'G', 0x21, 0x21), Some(Glyph::Scalar('\u{3000}')));
        assert_eq!(decode(b'G', 0x44, 0x21), Some(Glyph::Scalar('一')));
        assert_eq!(decode(b'G', 0x42, 0x41), Some(Glyph::Scalar('\u{2421}')));
        assert_eq!(decode(b'G', 0x23, 0x4f), None);
        assert_eq!(decode(b'H', 0x72, 0x45), None);
        assert_eq!(decode(b'I', 0x62, 0x47), None);
        assert_eq!(decode(b'K', 0x75, 0x6c), Some(Glyph::Scalar('\u{29572}')));
        assert_eq!(decode(b'L', 0x29, 0x63), Some(Glyph::Scalar('\u{2f820}')));
        assert_eq!(decode(b'M', 0x41, 0x59), Some(Glyph::Scalar('繤')));
    }
}
