//! Structural PDF streams use caller-bounded native decoding.

mod byte_filters;
mod fax;
mod lzw;

use std::borrow::Cow;

use gnunet_fs::metadata::Inflater;
use gnunet_fs_codec::Inflate;

use super::super::compression::decode_pdf_brotli;
use super::parameters::{ParameterError, Parameters};
use super::security::MAX_FILTER_NAME_BYTES;
use super::syntax::{Dict, Name, Value};
use lzw::EarlyChange;

const MAX_FILTERS: usize = 16;

pub(super) struct Expansion {
    remaining: usize,
    inflater: Option<Inflate>,
}

impl Expansion {
    pub(super) fn new(remaining: usize) -> Self {
        Self {
            remaining,
            inflater: None,
        }
    }

    pub(super) fn remaining(&self) -> usize {
        self.remaining
    }

    pub(super) fn decode<'a>(
        &mut self,
        dict: Dict<'_>,
        payload: &'a [u8],
        exact: Option<usize>,
    ) -> Option<Cow<'a, [u8]>> {
        let objects = Parameters::direct();
        if !matches!(objects.get(dict, b"F").ok()?, None | Some(Value::Null)) {
            return None;
        }
        let pipeline = Pipeline::parse_inline(dict, &objects).ok()?;
        if pipeline.crypt_filter().is_some() {
            return None;
        }
        self.decode_pipeline(&pipeline, payload, exact)
    }

    pub(super) fn decode_pipeline<'a>(
        &mut self,
        pipeline: &Pipeline,
        payload: &'a [u8],
        exact: Option<usize>,
    ) -> Option<Cow<'a, [u8]>> {
        if pipeline.filters.is_empty() {
            if exact.is_some_and(|len| len != payload.len()) {
                return None;
            }
            self.remaining = self.remaining.checked_sub(payload.len())?;
            return Some(Cow::Borrowed(payload));
        }
        let (final_filter, intermediate) = pipeline.filters.split_last()?;
        let mut data = Cow::Borrowed(payload);
        for filter in intermediate {
            data = Cow::Owned(self.apply(filter, &data, None)?);
        }
        self.apply(final_filter, &data, exact).map(Cow::Owned)
    }

    fn apply(&mut self, filter: &Filter, input: &[u8], exact: Option<usize>) -> Option<Vec<u8>> {
        let capacity = match (filter.prediction(), exact) {
            (Some(prediction), Some(plain)) => prediction.encoded_len(plain)?,
            (None, Some(plain)) => plain,
            (_, None) => self.remaining,
        };
        if capacity > self.remaining {
            return None;
        }
        let mut output = Output::new(capacity);
        let result = match filter {
            Filter::AsciiHex => byte_filters::ascii_hex(input, &mut output),
            Filter::Ascii85 => byte_filters::ascii85(input, &mut output),
            Filter::RunLength => byte_filters::run_length(input, &mut output),
            Filter::Fax(options) => options.decode(input, &mut output),
            Filter::Lzw(_, change) => lzw::decode(input, &mut output, *change),
            Filter::Flate(_) => {
                let inflater = self.inflater.get_or_insert_with(Inflate::new);
                let produced = inflater
                    .inflate(input, output.fill(capacity, 0)?)
                    .ok()
                    .map(|progress| progress.produced);
                output.complete(produced)
            }
            Filter::Brotli(_) => {
                let produced = decode_pdf_brotli(input, output.fill(capacity, 0)?);
                output.complete(produced)
            }
        };
        let mut output = output.bytes;
        self.remaining -= output.len();
        result?;
        if let Some(prediction) = filter.prediction() {
            prediction.undo(&mut output)?;
        }
        exact
            .is_none_or(|len| len == output.len())
            .then_some(output)
    }
}

/// A filter can write only through the output limit decided before decoding.
struct Output {
    bytes: Vec<u8>,
    limit: usize,
}

impl Output {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }

    fn reserve(&mut self, count: usize) -> Option<usize> {
        let end = self
            .bytes
            .len()
            .checked_add(count)
            .filter(|&end| end <= self.limit)?;
        if end > self.bytes.capacity() {
            let capacity = end
                .max(self.bytes.capacity().saturating_mul(2))
                .min(self.limit);
            self.bytes
                .try_reserve_exact(capacity - self.bytes.len())
                .ok()?;
        }
        Some(end)
    }

    fn append(&mut self, bytes: &[u8]) -> Option<()> {
        self.reserve(bytes.len())?;
        self.bytes.extend_from_slice(bytes);
        Some(())
    }

    fn fill(&mut self, count: usize, byte: u8) -> Option<&mut [u8]> {
        let start = self.bytes.len();
        let end = self.reserve(count)?;
        self.bytes.resize(end, byte);
        self.bytes.get_mut(start..end)
    }

    fn complete(&mut self, produced: Option<usize>) -> Option<()> {
        // A decoder that failed might have filled its entire buffer.
        self.bytes.truncate(produced?);
        Some(())
    }
}

pub(super) struct Pipeline {
    filters: Vec<Filter>,
    crypt: Option<Box<[u8]>>,
}

impl Pipeline {
    pub(super) fn crypt_filter(&self) -> Option<&[u8]> {
        self.crypt.as_deref()
    }

    pub(super) fn parse_inline(
        dict: Dict<'_>,
        objects: &Parameters<'_>,
    ) -> Result<Self, ParameterError> {
        Self::parse_fields(dict, objects, b"Filter", b"DecodeParms")
    }

    pub(super) fn parse_external(
        dict: Dict<'_>,
        objects: &Parameters<'_>,
    ) -> Result<Self, ParameterError> {
        let pipeline = Self::parse_fields(dict, objects, b"FFilter", b"FDecodeParms")?;
        // PDF crypt filters protect bytes in this document's stream objects.
        if pipeline
            .crypt_filter()
            .is_some_and(|name| name != b"Identity")
        {
            return Err(ParameterError::Invalid);
        }
        Ok(pipeline)
    }

    fn parse_fields(
        dict: Dict<'_>,
        objects: &Parameters<'_>,
        filter_key: &[u8],
        options_key: &[u8],
    ) -> Result<Self, ParameterError> {
        let filters = objects.get(dict, filter_key)?.unwrap_or(Value::Null);
        let options = objects.get(dict, options_key)?.unwrap_or(Value::Null);
        let mut pipeline = Self {
            filters: Vec::new(),
            crypt: None,
        };
        match filters {
            Value::Null if matches!(options, Value::Null) => {}
            Value::Name(name) => {
                let options = match options {
                    Value::Array(entries) => {
                        let mut entries = entries.values();
                        let first = entries.next().unwrap_or(Value::Null);
                        if entries.next().is_some() {
                            return Err(ParameterError::Invalid);
                        }
                        objects.resolve(first)?
                    }
                    value => value,
                };
                pipeline.push(name, parameter_dict(options)?, objects)?;
            }
            Value::Array(names) => {
                let mut per_stage = match options {
                    Value::Array(entries) => Some(entries.values()),
                    _ => None,
                };
                let mut count = 0;
                for (index, name) in names.values().enumerate() {
                    if index == MAX_FILTERS {
                        return Err(ParameterError::Invalid);
                    }
                    count += 1;
                    let Value::Name(name) = objects.resolve(name)? else {
                        return Err(ParameterError::Invalid);
                    };
                    let options = match &mut per_stage {
                        Some(parameters) => {
                            objects.resolve(parameters.next().ok_or(ParameterError::Invalid)?)?
                        }
                        None => options,
                    };
                    pipeline.push(name, parameter_dict(options)?, objects)?;
                }
                if per_stage.is_some_and(|mut entries| entries.next().is_some())
                    || !matches!(options, Value::Null | Value::Array(_)) && count != 1
                {
                    return Err(ParameterError::Invalid);
                }
            }
            _ => return Err(ParameterError::Invalid),
        }
        Ok(pipeline)
    }

    fn push(
        &mut self,
        name: Name<'_>,
        options: Option<Dict<'_>>,
        objects: &Parameters<'_>,
    ) -> Result<(), ParameterError> {
        if !name.is(b"Crypt") {
            self.filters.push(Filter::parse(name, options, objects)?);
            return Ok(());
        }
        if self.crypt.is_some() || !self.filters.is_empty() {
            return Err(ParameterError::Invalid);
        }
        let selection = match options {
            Some(options) => objects.get(options, b"Name")?,
            None => None,
        };
        self.crypt = Some(match selection {
            None | Some(Value::Null) => Box::from(b"Identity".as_slice()),
            Some(Value::Name(name)) => name
                .bytes(MAX_FILTER_NAME_BYTES)
                .ok_or(ParameterError::Invalid)?,
            _ => return Err(ParameterError::Invalid),
        });
        Ok(())
    }
}

fn parameter_dict(value: Value<'_>) -> Result<Option<Dict<'_>>, ParameterError> {
    match value {
        Value::Null => Ok(None),
        Value::Dict(dict) => Ok(Some(dict)),
        _ => Err(ParameterError::Invalid),
    }
}

enum Filter {
    AsciiHex,
    Ascii85,
    RunLength,
    Fax(fax::Options),
    Lzw(Prediction, EarlyChange),
    Flate(Prediction),
    Brotli(Prediction),
}

impl Filter {
    fn parse(
        name: Name<'_>,
        options: Option<Dict<'_>>,
        objects: &Parameters<'_>,
    ) -> Result<Self, ParameterError> {
        let prediction = || match options {
            Some(options) => Prediction::from_options(options, objects),
            None => Ok(Prediction::None),
        };
        if name.is(b"FlateDecode") || name.is(b"Fl") {
            return Ok(Self::Flate(prediction()?));
        }
        if name.is(b"BrotliDecode") {
            return Ok(Self::Brotli(prediction()?));
        }
        if name.is(b"LZWDecode") || name.is(b"LZW") {
            let change = match options {
                Some(options) => objects.get(options, b"EarlyChange")?,
                None => None,
            };
            let change = match change {
                Some(Value::Unsigned(0)) => EarlyChange::Late,
                None | Some(Value::Null | Value::Unsigned(1)) => EarlyChange::Early,
                _ => return Err(ParameterError::Invalid),
            };
            return Ok(Self::Lzw(prediction()?, change));
        }
        if name.is(b"CCITTFaxDecode") {
            return Ok(Self::Fax(fax::Options::parse(options, objects)?));
        }
        if options.is_some_and(|options| options.entries().next().is_some()) {
            return Err(ParameterError::Invalid);
        }
        if name.is(b"ASCIIHexDecode") || name.is(b"AHx") {
            Ok(Self::AsciiHex)
        } else if name.is(b"ASCII85Decode") || name.is(b"A85") {
            Ok(Self::Ascii85)
        } else if name.is(b"RunLengthDecode") || name.is(b"RL") {
            Ok(Self::RunLength)
        } else {
            Err(ParameterError::Invalid)
        }
    }

    fn prediction(&self) -> Option<&Prediction> {
        match self {
            Self::Lzw(prediction, _) | Self::Flate(prediction) | Self::Brotli(prediction) => {
                Some(prediction)
            }
            _ => None,
        }
    }
}

enum Prediction {
    None,
    Tiff {
        row: usize,
        colors: usize,
        samples: usize,
        bits: usize,
    },
    Png {
        row: usize,
        pixel: usize,
    },
}

impl Prediction {
    fn from_options(options: Dict<'_>, objects: &Parameters<'_>) -> Result<Self, ParameterError> {
        let field = |key: &[u8], default| match objects.get(options, key)? {
            None | Some(Value::Null) => Ok(default),
            Some(Value::Unsigned(value)) => {
                usize::try_from(value).map_err(|_| ParameterError::Invalid)
            }
            _ => Err(ParameterError::Invalid),
        };
        let predictor = field(b"Predictor", 1)?;
        if predictor == 1 {
            return Ok(Self::None);
        }
        let columns = field(b"Columns", 1)?;
        let colors = field(b"Colors", 1)?;
        let bits = field(b"BitsPerComponent", 8)?;
        if columns == 0 || colors == 0 || !matches!(bits, 1 | 2 | 4 | 8 | 16) {
            return Err(ParameterError::Invalid);
        }
        let samples = columns.checked_mul(colors).ok_or(ParameterError::Invalid)?;
        let row = samples
            .checked_mul(bits)
            .ok_or(ParameterError::Invalid)?
            .div_ceil(8);
        match predictor {
            2 => Ok(Self::Tiff {
                row,
                colors,
                samples,
                bits,
            }),
            10..=15 => Ok(Self::Png {
                row,
                pixel: colors
                    .checked_mul(bits)
                    .ok_or(ParameterError::Invalid)?
                    .div_ceil(8),
            }),
            _ => Err(ParameterError::Invalid),
        }
    }

    fn encoded_len(&self, plain: usize) -> Option<usize> {
        match *self {
            Self::None => Some(plain),
            Self::Tiff { row, .. } => plain.is_multiple_of(row).then_some(plain),
            Self::Png { row, .. } if plain.is_multiple_of(row) => plain.checked_add(plain / row),
            Self::Png { .. } => None,
        }
    }

    fn undo(&self, output: &mut Vec<u8>) -> Option<()> {
        match *self {
            Self::None => Some(()),
            Self::Tiff {
                row,
                colors,
                samples,
                bits,
            } => {
                if !output.len().is_multiple_of(row) {
                    return None;
                }
                for line in output.chunks_exact_mut(row) {
                    undo_tiff_line(line, colors, samples, bits);
                }
                Some(())
            }
            Self::Png { row, pixel } => undo_png(output, row, pixel),
        }
    }
}

fn undo_tiff_line(line: &mut [u8], colors: usize, samples: usize, bits: usize) {
    if bits == 16 {
        for index in colors..samples {
            let at = index * 2;
            let before = (index - colors) * 2;
            let delta = u16::from_be_bytes([line[at], line[at + 1]]);
            let last = u16::from_be_bytes([line[before], line[before + 1]]);
            line[at..at + 2].copy_from_slice(&last.wrapping_add(delta).to_be_bytes());
        }
        return;
    }
    let mask = ((1_u16 << bits) - 1) as u8;
    for index in colors..samples {
        let at = index * bits;
        let before = (index - colors) * bits;
        let shift = 8 - bits - at % 8;
        let delta = (line[at / 8] >> shift) & mask;
        let last = (line[before / 8] >> (8 - bits - before % 8)) & mask;
        let sample = delta.wrapping_add(last) & mask;
        let byte = &mut line[at / 8];
        *byte = (*byte & !(mask << shift)) | (sample << shift);
    }
}

enum PngFilter {
    None,
    Sub,
    Up,
    Average,
    Paeth,
}

fn undo_png(output: &mut Vec<u8>, row: usize, pixel: usize) -> Option<()> {
    let stride = row.checked_add(1)?;
    if !output.len().is_multiple_of(stride) {
        return None;
    }
    let lines = output.len() / stride;
    for index in 0..lines {
        let source = index * stride;
        let target = index * row;
        let filter = match output[source] {
            0 => PngFilter::None,
            1 => PngFilter::Sub,
            2 => PngFilter::Up,
            3 => PngFilter::Average,
            4 => PngFilter::Paeth,
            _ => return None,
        };
        // Read the tagged row ahead of its destination. The previous row and
        // any reconstructed bytes of this row already occupy their final bytes.
        for column in 0..row {
            let at = target + column;
            let left = if column >= pixel {
                output[at - pixel]
            } else {
                0
            };
            let above = if index != 0 { output[at - row] } else { 0 };
            let corner = if index != 0 && column >= pixel {
                output[at - row - pixel]
            } else {
                0
            };
            let base = match filter {
                PngFilter::None => 0,
                PngFilter::Sub => left,
                PngFilter::Up => above,
                PngFilter::Average => left.midpoint(above),
                PngFilter::Paeth => paeth(left, above, corner),
            };
            output[at] = output[source + column + 1].wrapping_add(base);
        }
    }
    output.truncate(lines * row);
    Some(())
}

fn paeth(left: u8, above: u8, corner: u8) -> u8 {
    let (a, b, c) = (i32::from(left), i32::from(above), i32::from(corner));
    let estimate = a + b - c;
    let distances = [
        (estimate - a).abs(),
        (estimate - b).abs(),
        (estimate - c).abs(),
    ];
    if distances[0] <= distances[1] && distances[0] <= distances[2] {
        left
    } else if distances[1] <= distances[2] {
        above
    } else {
        corner
    }
}

#[cfg(test)]
mod tests {
    use super::{Expansion, Value};
    use crate::extraction::formats::pdf::syntax::Cursor;

    #[test]
    fn intermediate_and_final_filter_output_share_one_allowance() -> Result<(), &'static str> {
        let Ok(Value::Dict(dict)) = Cursor::complete(
            b"<< /Filter [/RunLengthDecode /ASCIIHexDecode] /DecodeParms [null null] >>",
        )
        .one_value() else {
            return Err("expected a stream dictionary");
        };
        let input = b"\x044142>\x80";
        let mut exact = Expansion::new(7);
        if exact.decode(dict, input, None).as_deref() != Some(b"AB") || exact.remaining() != 0 {
            return Err("expected both filter stages to charge their decoded bytes");
        }
        let mut short = Expansion::new(6);
        if short.decode(dict, input, None).is_some() || short.remaining() != 0 {
            return Err("the failed final stage must charge its partial output");
        }
        Ok(())
    }

    #[test]
    fn brotli_extension_accepts_large_windows_and_png_predictors() -> Result<(), &'static str> {
        let Ok(Value::Dict(dict)) = Cursor::complete(
            b"<< /Filter [/ASCIIHexDecode /BrotliDecode]\
                 /DecodeParms [null << /Predictor 12 /Columns 3 >>] >>",
        )
        .one_value() else {
            return Err("expected a stream dictionary");
        };
        // A raw large-window member holding two PNG Up rows: ABC, then DEF.
        let input = b"111e0e0002024142430203030303>";
        let mut exact = Expansion::new(22);
        if exact.decode(dict, input, Some(6)).as_deref() != Some(&b"ABCDEF"[..])
            || exact.remaining() != 0
        {
            return Err("ordered Brotli pipeline did not decode within its exact budget");
        }
        let mut short = Expansion::new(21);
        if short.decode(dict, input, Some(6)).is_some() || short.remaining() != 7 {
            return Err("Brotli pipeline accepted a short budget");
        }
        Ok(())
    }
}
