//! Real Rust complete-member zlib with bounded caller output and reusable state.
use gnunet_types::Error;
use miniz_oxide::{
    DataFormat,
    deflate::{
        CompressionLevel,
        core::{CompressorOxide, TDEFLFlush, TDEFLStatus, compress},
    },
    inflate::{
        TINFLStatus,
        core::{DecompressorOxide, decompress, inflate_flags},
    },
};
/// Explicit allocation-backed compression state and fixed inflater state. This
/// capability is caller-owned/shared across sequential pure operations, not per peer.
pub struct Zlib {
    compressor: CompressorOxide,
    inflater: DecompressorOxide,
}
impl Zlib {
    /// Allocate miniz's fixed local state once. No input/output allocation or IO.
    #[must_use]
    pub fn new() -> Self {
        Self {
            compressor: CompressorOxide::with_format_and_level(
                DataFormat::Zlib,
                CompressionLevel::BestCompression,
            ),
            inflater: DecompressorOxide::new(),
        }
    }
}
impl Default for Zlib {
    fn default() -> Self {
        Self::new()
    }
}
impl Zlib {
    /// Compress one complete zlib member into explicitly bounded caller storage.
    /// Capacity failure does not create a partial successful member.
    pub fn compress(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Error> {
        self.compressor.reset();
        let (mut consumed, mut produced) = (0, 0);
        loop {
            let (status, read, written) = compress(
                &mut self.compressor,
                &input[consumed..],
                &mut output[produced..],
                TDEFLFlush::Finish,
            );
            if read > input.len() - consumed || written > output.len() - produced {
                return Err(Error::Malformed);
            }
            consumed += read;
            produced += written;
            match status {
                TDEFLStatus::Done => {
                    return if consumed == input.len() {
                        Ok(produced)
                    } else {
                        Err(Error::Malformed)
                    };
                }
                TDEFLStatus::Okay => {
                    if produced == output.len() {
                        return Err(Error::Capacity);
                    }
                    if read == 0 && written == 0 {
                        return Err(Error::Malformed);
                    }
                }
                TDEFLStatus::PutBufFailed => return Err(Error::Capacity),
                TDEFLStatus::BadParam => return Err(Error::InvalidInput),
            }
        }
    }
    /// Decode exactly one whole zlib member; reject trailing and truncated data.
    /// The returned length never exceeds the caller-provided output.
    pub fn decompress(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Error> {
        self.inflater.init();
        let flags = inflate_flags::TINFL_FLAG_PARSE_ZLIB_HEADER
            | inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF
            | inflate_flags::TINFL_FLAG_COMPUTE_ADLER32;
        let (status, read, written) = decompress(&mut self.inflater, input, output, 0, flags);
        match status {
            TINFLStatus::Done if read == input.len() => Ok(written),
            TINFLStatus::Done => Err(Error::Malformed),
            TINFLStatus::HasMoreOutput => Err(Error::Capacity),
            TINFLStatus::NeedsMoreInput | TINFLStatus::FailedCannotMakeProgress => {
                Err(Error::Truncated)
            }
            _ => Err(Error::Malformed),
        }
    }
}
