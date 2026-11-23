//! Lazy cross-reference lookups and bounded compressed object selection.

use std::ops::Range;

use super::stream::{Expansion, Pipeline};
use super::syntax::{Cursor, Dict, ParseError, Value};

const TABLE_ROW_BYTES: usize = 20;
const OBJECT_NUMBERS: u64 = u32::MAX as u64 + 1;

#[derive(Clone, Copy)]
pub(super) enum Entry {
    Free,
    Direct { offset: u64, generation: u16 },
    Compressed { stream: u32, index: u32 },
    Unknown,
}

pub(super) enum TablePart<'a> {
    Rows(TableRows),
    Trailer(Dict<'a>),
}

/// Fixed-width classic rows can be skipped or individually read by offset.
#[derive(Clone, Copy)]
pub(super) struct TableRows {
    first: u32,
    count: u64,
    rows_start: u64,
}

impl TableRows {
    pub(super) fn object_numbers(self) -> Range<u64> {
        let first = u64::from(self.first);
        first..first + self.count
    }

    pub(super) const fn next_offset(self) -> u64 {
        self.rows_start + self.count * TABLE_ROW_BYTES as u64
    }

    pub(super) fn row_offset(self, number: u32) -> Option<u64> {
        let index = u64::from(number.checked_sub(self.first)?);
        (index < self.count).then(|| self.rows_start + index * TABLE_ROW_BYTES as u64)
    }
}

pub(super) fn parse_table_start(bytes: &[u8]) -> Result<usize, ParseError> {
    let mut cursor = Cursor::new(bytes);
    cursor.take_keyword(b"xref")?;
    line_end(bytes, cursor.position())
}

pub(super) fn parse_table_part(bytes: &[u8]) -> Result<TablePart<'_>, ParseError> {
    let mut cursor = Cursor::new(bytes);
    match cursor.take_keyword(b"trailer") {
        Ok(()) => {
            return match cursor.value()? {
                Value::Dict(dict) => Ok(TablePart::Trailer(dict)),
                _ => Err(ParseError::Invalid),
            };
        }
        Err(ParseError::Incomplete) => return Err(ParseError::Incomplete),
        Err(ParseError::Invalid) => {}
    }
    let mut cursor = Cursor::new(bytes);
    let first = u32::try_from(cursor.unsigned()?).map_err(|_| ParseError::Invalid)?;
    let count = cursor.unsigned()?;
    if count > OBJECT_NUMBERS - u64::from(first) {
        return Err(ParseError::Invalid);
    }
    let rows_start = line_end(bytes, cursor.position())? as u64;
    rows_start
        .checked_add(count * TABLE_ROW_BYTES as u64)
        .ok_or(ParseError::Invalid)?;
    Ok(TablePart::Rows(TableRows {
        first,
        count,
        rows_start,
    }))
}

fn line_end(bytes: &[u8], mut at: usize) -> Result<usize, ParseError> {
    loop {
        match bytes.get(at) {
            Some(b' ' | b'\t') => at += 1,
            Some(b'\n') => return Ok(at + 1),
            Some(b'\r') => match bytes.get(at + 1) {
                Some(b'\n') => return Ok(at + 2),
                Some(_) => return Ok(at + 1),
                None => return Err(ParseError::Incomplete),
            },
            Some(_) => return Err(ParseError::Invalid),
            None => return Err(ParseError::Incomplete),
        }
    }
}

pub(super) fn parse_table_entry(bytes: &[u8]) -> Result<Entry, ParseError> {
    let row = bytes
        .first_chunk::<TABLE_ROW_BYTES>()
        .ok_or(ParseError::Incomplete)?;
    if row[10] != b' ' || row[16] != b' ' || !matches!(&row[18..], b"\r\n" | b" \n" | b" \r") {
        return Err(ParseError::Invalid);
    }
    let offset = decimal(&row[..10]).ok_or(ParseError::Invalid)?;
    let generation = decimal(&row[11..16])
        .and_then(|value| u16::try_from(value).ok())
        .ok_or(ParseError::Invalid)?;
    match row[17] {
        b'n' => Ok(Entry::Direct { offset, generation }),
        b'f' => Ok(Entry::Free),
        _ => Err(ParseError::Invalid),
    }
}

fn decimal(bytes: &[u8]) -> Option<u64> {
    bytes.iter().try_fold(0_u64, |value, byte| {
        byte.is_ascii_digit()
            .then(|| value * 10 + u64::from(byte - b'0'))
    })
}

struct IndexRun {
    first: u32,
    count: usize,
    start: usize,
}

/// Keep decoded rows and their sparse ranges. No object index proportional to
/// the trailer's highest object number is allocated.
pub(super) struct XrefStream {
    widths: [usize; 3],
    stride: usize,
    runs: Vec<IndexRun>,
    data: Box<[u8]>,
}

impl XrefStream {
    pub(super) fn decode(
        dict: Dict<'_>,
        payload: &[u8],
        expansion: &mut Expansion,
    ) -> Option<Self> {
        if !matches!(dict.unique(b"Type").ok()?, Some(Value::Name(name)) if name.is(b"XRef")) {
            return None;
        }
        let size = unsigned(&dict, b"Size").filter(|&size| (1..=OBJECT_NUMBERS).contains(&size))?;
        let Value::Array(widths) = dict.unique(b"W").ok()?? else {
            return None;
        };
        let mut values = widths.values();
        let widths = [
            width(values.next()?)?,
            width(values.next()?)?,
            width(values.next()?)?,
        ];
        if values.next().is_some() {
            return None;
        }
        let stride = widths.into_iter().try_fold(0_usize, usize::checked_add)?;
        if stride == 0 || stride > expansion.remaining() {
            return None;
        }
        let mut runs = Vec::<IndexRun>::new();
        let mut expected = 0_usize;
        let mut previous_end = 0;
        let mut add = |first: u64, count: u64| -> Option<()> {
            let end = first.checked_add(count)?;
            if first < previous_end || end > size {
                return None;
            }
            previous_end = end;
            if count != 0 {
                let count = usize::try_from(count).ok()?;
                let start = expected;
                expected = start.checked_add(count.checked_mul(stride)?)?;
                if expected > expansion.remaining() {
                    return None;
                }
                runs.try_reserve(1).ok()?;
                runs.push(IndexRun {
                    first: u32::try_from(first).ok()?,
                    count,
                    start,
                });
            }
            Some(())
        };
        match dict.unique(b"Index").ok()? {
            None | Some(Value::Null) => add(0, size)?,
            Some(Value::Array(index)) => {
                let mut values = index.values();
                while let Some(first) = values.next() {
                    add(number(first)?, number(values.next()?)?)?;
                }
            }
            _ => return None,
        }
        let decoded = expansion.decode(dict, payload, Some(expected))?;
        Some(Self {
            widths,
            stride,
            runs,
            data: decoded.into_owned().into_boxed_slice(),
        })
    }

    pub(super) fn entry(&self, number: u32) -> Option<Entry> {
        let run = self.runs.get(
            self.runs
                .partition_point(|run| run.first <= number)
                .checked_sub(1)?,
        )?;
        let index = (number - run.first) as usize;
        if index >= run.count {
            return None;
        }
        let start = run.start + index * self.stride;
        let row = &self.data[start..start + self.stride];
        let (kind, rest) = row.split_at(self.widths[0]);
        let (first, second) = rest.split_at(self.widths[1]);
        let kind = if kind.is_empty() {
            Some(1)
        } else {
            big_endian(kind)
        };
        Some(match (kind, big_endian(first), big_endian(second)) {
            (Some(0), _, _) => Entry::Free,
            (Some(1), Some(offset), Some(generation)) => {
                u16::try_from(generation).map_or(Entry::Unknown, |generation| Entry::Direct {
                    offset,
                    generation,
                })
            }
            (Some(2), Some(stream), Some(index)) => {
                match (u32::try_from(stream), u32::try_from(index)) {
                    (Ok(stream), Ok(index)) if stream != 0 => Entry::Compressed { stream, index },
                    _ => Entry::Unknown,
                }
            }
            _ => Entry::Unknown,
        })
    }
}

fn width(value: Value<'_>) -> Option<usize> {
    usize::try_from(number(value)?).ok()
}

fn big_endian(bytes: &[u8]) -> Option<u64> {
    let (padding, value) = bytes.split_at(bytes.len().saturating_sub(size_of::<u64>()));
    padding.iter().all(|&byte| byte == 0).then(|| {
        value
            .iter()
            .fold(0_u64, |value, &byte| (value << 8) | u64::from(byte))
    })
}

struct ObjectIndex {
    number: u32,
    offset: u32,
}

pub(super) struct ObjectStream {
    data: Box<[u8]>,
    offsets: Vec<ObjectIndex>,
}

#[derive(Clone, Copy)]
pub(super) struct ObjectStreamIndex {
    first: u32,
    count: usize,
}

impl ObjectStreamIndex {
    pub(super) fn new(first: u64, count: u64) -> Option<Self> {
        let first = u32::try_from(first).ok()?;
        let count = usize::try_from(count).ok()?;
        // Each pair needs two digits and a separator. Neighboring pairs need
        // another separator before the next number starts.
        if count == 0 || count > (first as usize).saturating_add(1) / 4 {
            return None;
        }
        Some(Self { first, count })
    }
}

impl ObjectStream {
    pub(super) fn decode(
        index: ObjectStreamIndex,
        pipeline: &Pipeline,
        payload: &[u8],
        expansion: &mut Expansion,
    ) -> Option<Self> {
        if index.first as usize >= expansion.remaining() {
            return None;
        }
        let decoded = expansion.decode_pipeline(pipeline, payload, None)?;
        let header = decoded.get(..index.first as usize)?;
        let mut cursor = Cursor::complete(header);
        let mut offsets = Vec::<ObjectIndex>::new();
        offsets.try_reserve_exact(index.count).ok()?;
        for _ in 0..index.count {
            let number = u32::try_from(cursor.unsigned().ok()?).ok()?;
            let relative = u32::try_from(cursor.unsigned().ok()?).ok()?;
            let offset = index.first.checked_add(relative)?;
            if number == 0
                || offset as usize >= decoded.len()
                || offsets
                    .last()
                    .map_or(relative != 0, |last| offset <= last.offset)
            {
                return None;
            }
            offsets.push(ObjectIndex { number, offset });
        }
        cursor.finish().ok()?;
        Some(Self {
            data: decoded.into_owned().into_boxed_slice(),
            offsets,
        })
    }

    pub(super) fn object(&self, number: u32, index: u32) -> Option<&[u8]> {
        let index = index as usize;
        let entry = self.offsets.get(index)?;
        if entry.number != number {
            return None;
        }
        let end = self
            .offsets
            .get(index + 1)
            .map_or(self.data.len(), |next| next.offset as usize);
        self.data.get(entry.offset as usize..end)
    }
}

fn number(value: Value<'_>) -> Option<u64> {
    match value {
        Value::Unsigned(number) => Some(number),
        _ => None,
    }
}

fn unsigned(dict: &Dict<'_>, key: &[u8]) -> Option<u64> {
    number(dict.unique(key).ok()??)
}
