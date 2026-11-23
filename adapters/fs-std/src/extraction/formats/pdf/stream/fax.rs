//! PDF row framing for T.4 and T.6 facsimile codes.

mod bits;
mod line;
#[cfg(test)]
mod tests;

use super::Output;
use crate::extraction::formats::pdf::{
    parameters::{ParameterError, Parameters},
    syntax::{Dict, Value},
};
use bits::Bits;
use line::{Literal, Scanline};
use std::num::NonZeroUsize;

#[derive(Clone, Copy)]
enum Scheme {
    Group3,
    Mixed,
    Group4,
}

impl Scheme {
    fn coding(self, bits: &mut Bits<'_>) -> Option<Coding> {
        Some(match self {
            Self::Group3 => Coding::Runs,
            Self::Mixed if bits.bit()? => Coding::Runs,
            Self::Mixed | Self::Group4 => Coding::Changes,
        })
    }
}

#[derive(PartialEq, Eq)]
enum Coding {
    Runs,
    Changes,
}

enum Frame {
    Row(Coding),
    End,
}

pub(super) struct Options {
    scheme: Scheme,
    columns: NonZeroUsize,
    rows: Option<NonZeroUsize>,
    end_of_line: bool,
    byte_align: bool,
    end_of_block: bool,
    black_is_one: bool,
    damaged_rows: usize,
}

impl Options {
    pub(super) fn parse(
        dict: Option<Dict<'_>>,
        objects: &Parameters<'_>,
    ) -> Result<Self, ParameterError> {
        let field = |key: &[u8]| match dict {
            Some(dict) => objects.get(dict, key),
            None => Ok(None),
        };
        let natural = |key: &[u8], default| match field(key)? {
            None | Some(Value::Null) => Ok(default),
            Some(Value::Unsigned(value)) => {
                usize::try_from(value).map_err(|_| ParameterError::Invalid)
            }
            _ => Err(ParameterError::Invalid),
        };
        let boolean = |key: &[u8], default| match field(key)? {
            None | Some(Value::Null) => Ok(default),
            Some(Value::Boolean(value)) => Ok(value),
            _ => Err(ParameterError::Invalid),
        };
        let scheme = match field(b"K")? {
            None | Some(Value::Null | Value::Unsigned(0)) => Scheme::Group3,
            Some(Value::Unsigned(_)) => Scheme::Mixed,
            Some(Value::Signed(k)) if k < 0 => Scheme::Group4,
            _ => return Err(ParameterError::Invalid),
        };
        let end_of_line = boolean(b"EndOfLine", false)?;
        let damaged_rows = natural(b"DamagedRowsBeforeError", 0)?;
        Ok(Self {
            scheme,
            columns: NonZeroUsize::new(natural(b"Columns", 1728)?)
                .ok_or(ParameterError::Invalid)?,
            rows: NonZeroUsize::new(natural(b"Rows", 0)?),
            end_of_line,
            byte_align: boolean(b"EncodedByteAlign", false)?,
            end_of_block: boolean(b"EndOfBlock", true)?,
            black_is_one: boolean(b"BlackIs1", false)?,
            damaged_rows: if end_of_line && !matches!(scheme, Scheme::Group4) {
                damaged_rows
            } else {
                0
            },
        })
    }

    pub(super) fn decode(&self, bytes: &[u8], output: &mut Output) -> Option<()> {
        let columns = self.columns.get();
        let stride = columns.div_ceil(8);
        let mut bits = Bits::new(bytes)?;
        let mut literal = Literal::default();
        let mut previous_damaged = false;
        let mut damaged_left = self.damaged_rows;
        let row_limit = self.rows.filter(|_| !self.end_of_block);
        loop {
            let start = output.bytes.len();
            if row_limit.is_some_and(|rows| start / stride == rows.get()) {
                break;
            }
            let resume = literal.exit_at_boundary(&mut bits)?;
            let frame = if literal.active() {
                Some(Frame::Row(Coding::Changes))
            } else {
                self.next_line(&mut bits)
            };
            if matches!(frame, Some(Frame::End)) {
                break;
            }
            if frame.is_none() && damaged_left == 0 {
                return None;
            }
            let data = bits;
            let end = output.reserve(stride)?;
            output.bytes.resize(end, 0);
            let (prior, row) = output.bytes.split_at_mut(start);
            let reference = start.checked_sub(stride).map(|at| &prior[at..]);
            let mut line = Scanline::new(row, columns, resume.unwrap_or(false));
            let result = match frame {
                Some(Frame::Row(Coding::Changes)) => {
                    line.two_dimensional(&mut bits, reference, &mut literal)
                }
                Some(Frame::Row(Coding::Runs)) => line.one_dimensional(&mut bits, &mut literal),
                _ => None,
            };
            if result.is_some()
                && (matches!(self.scheme, Scheme::Group4)
                    || literal.finish_line(&mut bits).is_some())
            {
                previous_damaged = false;
                continue;
            }
            damaged_left = damaged_left.checked_sub(1)?;
            // The next line owns this marker, including its mixed-mode tag.
            bits = data;
            bits.find_eol()?;
            literal = Literal::default();
            match reference {
                Some(previous) if !previous_damaged => row.copy_from_slice(previous),
                _ => row.fill(0),
            }
            previous_damaged = true;
        }
        if !self.black_is_one {
            for byte in &mut output.bytes {
                *byte = !*byte;
            }
        }
        Some(())
    }

    fn next_line(&self, bits: &mut Bits<'_>) -> Option<Frame> {
        if !self.end_of_block && bits.is_padding() {
            return Some(Frame::End);
        }
        if bits.eol() {
            let mixed = matches!(self.scheme, Scheme::Mixed);
            let tag_starts_byte = mixed && bits.is_aligned();
            let coding = self.scheme.coding(bits)?;
            let mut tail = *bits;
            let markers = if matches!(self.scheme, Scheme::Group4) {
                2
            } else {
                6
            };
            let can_end = !mixed || coding == Coding::Runs;
            if can_end && (1..markers).all(|_| tail.eol() && (!mixed || tail.bit() == Some(true))) {
                *bits = tail;
                return Some(Frame::End);
            }
            if !self.end_of_block && bits.is_padding() {
                return Some(Frame::End);
            }
            // In byte-aligned mixed coding the EOL can end on the byte
            // boundary with its line tag as the first bit of the new row.
            if !tag_starts_byte {
                self.align(bits)?;
            }
            return Some(Frame::Row(coding));
        }
        if self.end_of_line {
            return None;
        }
        self.align(bits)?;
        self.scheme.coding(bits).map(Frame::Row)
    }

    fn align(&self, bits: &mut Bits<'_>) -> Option<()> {
        if self.byte_align {
            bits.align()
        } else {
            Some(())
        }
    }
}
