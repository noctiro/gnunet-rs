//! Bounded annex E.4 decoding of the original, entropy-coded ICC profile.

use super::super::{Field, icc};
use jpxl_bitstream::{BitReader, BitstreamError, read_u64};
use jpxl_core::limits::{AllocGuard, Limits};
use jpxl_decode::{
    DecodeError,
    headers::decode_image_headers_metered,
    icc::{NUM_ICC_CONTEXTS, icc_context, reconstruct, stream::ByteStream},
};
use jpxl_entropy::{EntropyError, SymbolDecoder};

const INITIAL_PREFIX: usize = 256;
// Leave room for the command stream even when the result fits just within the sink.
const COMMAND_ALLOWANCE: usize = 1 << 16;
// Includes the library's 4 MiB LZ77 window and entropy/header tables.
const CODEC_WORKSPACE: u64 = 6 * 1024 * 1024;

pub(super) struct Probe {
    bytes: Vec<u8>,
    next: usize,
    cap: usize,
    output: usize,
}

impl Probe {
    pub(super) fn new(probe_bytes: usize, output: usize) -> Option<Self> {
        if output < icc::MIN_BYTES {
            return None;
        }
        let cap = probe_bytes;
        (cap >= super::header::MAX_BYTES).then_some(Self {
            bytes: Vec::new(),
            next: INITIAL_PREFIX.min(cap),
            cap,
            output,
        })
    }

    pub(super) fn remaining(&self) -> usize {
        self.next - self.bytes.len()
    }

    pub(super) fn unbuffered(&self) -> usize {
        self.cap - self.bytes.len()
    }

    pub(super) fn push(&mut self, bytes: &[u8]) -> Option<()> {
        let remaining = self.remaining();
        if bytes.len() > remaining {
            return None;
        }
        self.bytes.try_reserve_exact(remaining).ok()?;
        self.bytes.extend_from_slice(bytes);
        Some(())
    }

    /// Returns true when this probe has reached a terminal result.
    pub(super) fn advance<E>(
        &mut self,
        last: bool,
        emit: &mut impl FnMut(Field<'_>) -> Result<(), E>,
    ) -> Result<bool, E> {
        if !last && self.remaining() != 0 {
            return Ok(false);
        }
        match decode(&self.bytes, self.output) {
            Ok(Some(bytes)) => {
                if let Some(profile) = icc::Profile::parse(&bytes, self.output) {
                    emit(Field::ColorProfile(profile))?;
                }
            }
            Err(Failure::NeedMore) if !last && self.next < self.cap => {
                self.next = (self.next * 2).min(self.cap);
                return Ok(false);
            }
            Ok(None) | Err(_) => {}
        }
        Ok(true)
    }
}

enum Failure {
    NeedMore,
    Invalid,
}

impl From<BitstreamError> for Failure {
    fn from(error: BitstreamError) -> Self {
        match error {
            BitstreamError::OutOfBounds { .. } => Self::NeedMore,
            _ => Self::Invalid,
        }
    }
}

impl From<EntropyError> for Failure {
    fn from(error: EntropyError) -> Self {
        match error {
            EntropyError::Bitstream(error) => error.into(),
            _ => Self::Invalid,
        }
    }
}

fn decode(bytes: &[u8], output_limit: usize) -> Result<Option<Vec<u8>>, Failure> {
    let encoded_limit = output_limit.saturating_add(COMMAND_ALLOWANCE);
    let limits = Limits {
        max_pixels: u64::MAX,
        max_alloc_bytes: CODEC_WORKSPACE + encoded_limit as u64 + output_limit as u64,
        ..Limits::default()
    };
    let mut guard = AllocGuard::new(&limits);
    let mut reader = BitReader::new(bytes);
    let headers = decode_image_headers_metered(&mut reader, &limits, &mut guard).map_err(
        |error| match error {
            DecodeError::Bitstream(error) => error.into(),
            _ => Failure::Invalid,
        },
    )?;
    if !headers.metadata.colour_encoding.want_icc {
        return Ok(None);
    }

    // E.4.1 has a size distinct from the eventual profile's E.4.2 size.
    let size = usize::try_from(read_u64(&mut reader)?)
        .ok()
        .filter(|size| (1..=encoded_limit).contains(size))
        .ok_or(Failure::Invalid)?;
    guard.charge(size as u64).map_err(|_| Failure::Invalid)?;
    let mut symbols = SymbolDecoder::open(&mut reader, NUM_ICC_CONTEXTS, &mut guard)?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(size)
        .map_err(|_| Failure::Invalid)?;
    let mut previous = [0, 0];
    let mut has_size = false;
    for index in 0..size {
        let context = icc_context(index as u64, previous[0], previous[1]);
        let byte =
            u8::try_from(symbols.read_uint(&mut reader, context)?).map_err(|_| Failure::Invalid)?;
        encoded.push(byte);
        previous = [byte, previous[0]];
        if !has_size {
            if byte < 0x80 {
                let output = ByteStream::new(&encoded, "ICC output size")
                    .varint()
                    .map_err(|_| Failure::Invalid)?;
                if !(icc::MIN_BYTES as u64..=output_limit as u64).contains(&output) {
                    return Err(Failure::Invalid);
                }
                has_size = true;
            } else if encoded.len() == 9 {
                return Err(Failure::Invalid);
            }
        }
    }
    symbols.finish()?;
    drop(symbols);
    reconstruct(&encoded, &mut guard)
        .map(Some)
        .map_err(|_| Failure::Invalid)
}
