//! Pure Rust DEFLATE providers for GNUnet metadata's explicit codec boundary.
//!
//! Inflation uses caller-owned state/output without selecting an allocator.
//! Compression is available only with `alloc`: constructing its reusable state
//! performs real heap allocations. Neither path invokes C, libgnunet or zlib FFI.
//! Output is scratch on failure; the metadata core applies its own wipe policy.
#![no_std]
#![forbid(unsafe_code)]

use gnunet_fs::metadata::{CodecError, Inflater, Progress};
use miniz_oxide::inflate::{
    TINFLStatus,
    core::{DecompressorOxide, decompress, inflate_flags},
};

/// Framing of a complete DEFLATE member.
#[derive(Clone, Copy)]
pub enum DeflateFormat {
    /// RFC 1950 header and Adler-32 trailer.
    Zlib,
    /// RFC 1951 stream.
    Raw,
}

/// Reusable complete-member inflater with no allocator in its state.
/// The caller owns this value and the full non-wrapping output workspace.
/// Stream state is reset before each operation, including retries after errors.
pub struct Inflate {
    state: DecompressorOxide,
}
impl Inflate {
    /// Construct bounded inline decompression state; no allocation is selected.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: DecompressorOxide::new(),
        }
    }

    /// Inflate one complete member into the supplied non-wrapping workspace.
    pub fn inflate_member(
        &mut self,
        format: DeflateFormat,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<Progress, CodecError> {
        let progress = self.inflate_prefix(format, input, output)?;
        if progress.consumed != input.len() {
            return Err(CodecError::Trailing);
        }
        Ok(progress)
    }

    /// Inflate the first complete member and report where its enclosing format resumes.
    /// Use [`Self::inflate_member`] when the input must contain exactly one member.
    pub fn inflate_prefix(
        &mut self,
        format: DeflateFormat,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<Progress, CodecError> {
        self.state.init();
        let flags = inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF
            | match format {
                DeflateFormat::Zlib => {
                    inflate_flags::TINFL_FLAG_PARSE_ZLIB_HEADER
                        | inflate_flags::TINFL_FLAG_COMPUTE_ADLER32
                }
                DeflateFormat::Raw => 0,
            };
        let (status, consumed, produced) = decompress(&mut self.state, input, output, 0, flags);
        if consumed > input.len() || produced > output.len() {
            return Err(CodecError::Invalid);
        }
        match status {
            TINFLStatus::Done => Ok(Progress { consumed, produced }),
            TINFLStatus::HasMoreOutput => Err(CodecError::Capacity),
            TINFLStatus::FailedCannotMakeProgress | TINFLStatus::NeedsMoreInput => {
                Err(CodecError::Truncated)
            }
            _ => Err(CodecError::Invalid),
        }
    }
}

impl Default for Inflate {
    fn default() -> Self {
        Self::new()
    }
}

impl Inflater for Inflate {
    fn inflate(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, CodecError> {
        self.inflate_member(DeflateFormat::Zlib, input, output)
    }
}

#[cfg(feature = "alloc")]
mod compression {
    use gnunet_fs::metadata::{CodecError, Deflater, Progress};
    use miniz_oxide::{
        DataFormat,
        deflate::{
            CompressionLevel,
            core::{CompressorOxide, TDEFLFlush, TDEFLStatus, compress},
        },
    };

    /// Reusable pure Rust zlib compressor requiring the explicit `alloc` feature.
    /// Construction allocates miniz's boxed Huffman/local state. Each operation
    /// resets that existing state rather than constructing a replacement codec.
    /// Output remains caller-owned; this is not a noalloc-compression claim.
    pub struct Compressor {
        state: CompressorOxide,
    }
    impl Compressor {
        /// Allocate reusable zlib compression state at the reference's level9.
        /// Level choice does not promise bit-identical output to C zlib.
        #[must_use]
        pub fn new() -> Self {
            Self {
                state: CompressorOxide::with_format_and_level(
                    DataFormat::Zlib,
                    CompressionLevel::BestCompression,
                ),
            }
        }
    }
    impl Default for Compressor {
        fn default() -> Self {
            Self::new()
        }
    }
    impl Deflater for Compressor {
        fn deflate(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, CodecError> {
            self.state.reset();
            let mut consumed = 0;
            let mut produced = 0;
            loop {
                let (status, read, written) = compress(
                    &mut self.state,
                    &input[consumed..],
                    &mut output[produced..],
                    TDEFLFlush::Finish,
                );
                if read > input.len() - consumed || written > output.len() - produced {
                    return Err(CodecError::Invalid);
                }
                consumed += read;
                produced += written;
                match status {
                    TDEFLStatus::Done => {
                        if consumed != input.len() {
                            return Err(CodecError::Invalid);
                        }
                        return Ok(Progress { consumed, produced });
                    }
                    TDEFLStatus::Okay => {
                        if produced == output.len() {
                            return Err(CodecError::Capacity);
                        }
                        if read == 0 && written == 0 {
                            return Err(CodecError::Invalid);
                        }
                    }
                    TDEFLStatus::PutBufFailed => return Err(CodecError::Capacity),
                    TDEFLStatus::BadParam => return Err(CodecError::Invalid),
                }
            }
        }
    }
}

/// Allocation-backed complete-member zlib compression capability.
#[cfg(feature = "alloc")]
pub use compression::Compressor;
