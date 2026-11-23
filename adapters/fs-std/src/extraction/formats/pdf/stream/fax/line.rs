//! Packed scanlines, T.4 run codes, and T.4/T.6 changing elements.

use ::fax::maps::{self, Mode};

use super::Bits;

pub(super) struct Scanline<'a> {
    row: &'a mut [u8],
    columns: usize,
    at: usize,
    black: bool,
    initial: bool,
}

impl<'a> Scanline<'a> {
    pub(super) fn new(row: &'a mut [u8], columns: usize, black: bool) -> Self {
        Self {
            row,
            columns,
            at: 0,
            black,
            initial: true,
        }
    }

    pub(super) fn one_dimensional(
        &mut self,
        bits: &mut Bits<'_>,
        literal: &mut Literal,
    ) -> Option<()> {
        while self.at < self.columns {
            if bits.marker(12, 15) {
                literal.active = true;
                literal.write(self, bits)?;
            } else {
                let end = self.run_end(bits, self.at, self.black)?;
                if end == self.at && !self.initial {
                    return None;
                }
                self.paint(end)?;
                self.black = !self.black;
            }
        }
        Some(())
    }

    pub(super) fn two_dimensional(
        &mut self,
        bits: &mut Bits<'_>,
        reference: Option<&[u8]>,
        literal: &mut Literal,
    ) -> Option<()> {
        let mut changes = Changes::new(reference, self.columns);
        while self.at < self.columns {
            if literal.active {
                literal.write(self, bits)?;
                continue;
            }
            match maps::mode::decode(bits)? {
                Mode::Pass => {
                    let [_, b2] = changes.edges(self.reference_start(), self.black);
                    if b2 <= self.at {
                        return None;
                    }
                    self.paint(b2)?;
                }
                Mode::Vertical(offset) => {
                    let [b1, _] = changes.edges(self.reference_start(), self.black);
                    let end = b1.checked_add_signed(isize::from(offset))?;
                    if end == self.at && !self.initial {
                        return None;
                    }
                    self.paint(end)?;
                    self.black = !self.black;
                }
                Mode::Horizontal => {
                    let a1 = self.run_end(bits, self.at, self.black)?;
                    let a2 = self.run_end(bits, a1, !self.black)?;
                    if a2 == self.at {
                        return None;
                    }
                    self.paint(a1)?;
                    self.black = !self.black;
                    self.paint(a2)?;
                    self.black = !self.black;
                }
                Mode::Extension if bits.marker(3, 7) => literal.active = true,
                _ => return None,
            }
        }
        Some(())
    }

    fn run_end(&self, bits: &mut Bits<'_>, mut at: usize, black: bool) -> Option<usize> {
        let code = if black {
            maps::black::decode
        } else {
            maps::white::decode
        };
        loop {
            let width = code(bits)?;
            at = at.checked_add(usize::from(width))?;
            if at > self.columns {
                return None;
            }
            if width < 64 {
                return Some(at);
            }
        }
    }

    fn reference_start(&self) -> usize {
        self.at + usize::from(!self.initial)
    }

    fn paint(&mut self, end: usize) -> Option<()> {
        if end < self.at || end > self.columns {
            return None;
        }
        if self.black && end != self.at {
            let first_mask = u8::MAX >> (self.at % 8);
            let last_mask = u8::MAX << (7 - (end - 1) % 8);
            let start = self.at / 8;
            let last = (end - 1) / 8;
            if start == last {
                self.row[start] |= first_mask & last_mask;
            } else {
                self.row[start] |= first_mask;
                self.row[start + 1..last].fill(u8::MAX);
                self.row[last] |= last_mask;
            }
        }
        self.at = end;
        self.initial = false;
        Some(())
    }
}

struct Changes<'a> {
    row: Option<&'a [u8]>,
    columns: usize,
    first_black: bool,
    upcoming: [usize; 3],
}

impl<'a> Changes<'a> {
    fn new(row: Option<&'a [u8]>, columns: usize) -> Self {
        let first = next_change(row, columns, 0, false);
        let second = next_change(row, columns, first, true);
        let third = next_change(row, columns, second, false);
        Self {
            row,
            columns,
            first_black: true,
            upcoming: [first, second, third],
        }
    }

    fn edges(&mut self, from: usize, black: bool) -> [usize; 2] {
        // a0 never goes left. Only discard reference changes that cannot be
        // selected again; retain b2 without advancing the first candidate.
        while self.upcoming[0] < from {
            self.upcoming.rotate_left(1);
            self.first_black = !self.first_black;
            self.upcoming[2] =
                next_change(self.row, self.columns, self.upcoming[1], !self.first_black);
        }
        let first = usize::from(black == self.first_black);
        [self.upcoming[first], self.upcoming[first + 1]]
    }
}

fn next_change(row: Option<&[u8]>, columns: usize, mut at: usize, black: bool) -> usize {
    let Some(row) = row else {
        return columns;
    };
    let invert = if black { u8::MAX } else { 0 };
    while at < columns {
        let colors = (row[at / 8] ^ invert) << (at % 8);
        if colors != 0 {
            return (at + colors.leading_zeros() as usize).min(columns);
        }
        at = (at / 8 + 1) * 8;
    }
    columns
}

// At most one T.6 literal pattern and its optional exit can cross a row.
#[derive(Default)]
pub(super) struct Literal {
    active: bool,
    pending: usize,
    black_last: bool,
    exit: Option<bool>,
}

impl Literal {
    pub(super) fn active(&self) -> bool {
        self.active
    }

    pub(super) fn exit_at_boundary(&mut self, bits: &mut Bits<'_>) -> Option<Option<bool>> {
        if self.active && self.pending == 0 && bits.marker(7, 1) {
            self.active = false;
            return Some(Some(bits.bit()?));
        }
        Some(None)
    }

    pub(super) fn finish_line(&mut self, bits: &mut Bits<'_>) -> Option<()> {
        if self.active && self.exit_at_boundary(bits)?.is_none() {
            return None;
        }
        Some(())
    }

    fn write(&mut self, line: &mut Scanline<'_>, bits: &mut Bits<'_>) -> Option<()> {
        loop {
            if self.pending == 0 {
                if let Some(black) = self.exit.take() {
                    line.black = black;
                    self.active = false;
                    return Some(());
                }
                if line.at == line.columns {
                    return Some(());
                }
                self.pattern(bits)?;
                if self.pending == 0 {
                    continue;
                }
            }
            let written = self.pending.min(line.columns - line.at);
            if written == 0 {
                return Some(());
            }
            self.pending -= written;
            let end = line.at + written;
            if self.pending == 0 && self.black_last {
                let pixel = end - 1;
                line.row[pixel / 8] |= 0x80 >> (pixel % 8);
            }
            line.at = end;
            line.initial = false;
        }
    }

    fn pattern(&mut self, bits: &mut Bits<'_>) -> Option<()> {
        for zeros in 0..=10 {
            if bits.bit()? {
                self.black_last = zeros < 5;
                self.pending = match zeros {
                    0..=4 => zeros + 1,
                    5 => 5,
                    _ => {
                        self.exit = Some(bits.bit()?);
                        zeros - 6
                    }
                };
                return Some(());
            }
        }
        None
    }
}
