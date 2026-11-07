//! Pure Rust zlib providers for GNUnet metadata's explicit codec boundary.
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

/// Reusable complete-member zlib inflater with no allocator in its state.
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
}
impl Default for Inflate {
    fn default() -> Self {
        Self::new()
    }
}
impl Inflater for Inflate {
    fn inflate(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, CodecError> {
        self.state.init();
        // Full input is supplied; HAS_MORE_INPUT is deliberately absent.
        // PARSE_ZLIB_HEADER also makes miniz verify the stream's Adler32.
        let flags = inflate_flags::TINFL_FLAG_PARSE_ZLIB_HEADER
            | inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF
            | inflate_flags::TINFL_FLAG_COMPUTE_ADLER32;
        let (status, consumed, produced) = decompress(&mut self.state, input, output, 0, flags);
        if consumed > input.len() || produced > output.len() {
            return Err(CodecError::Invalid);
        }
        match status {
            TINFLStatus::Done => {
                if consumed != input.len() {
                    return Err(CodecError::Trailing);
                }
                // Actual output length is returned. The metadata envelope core
                // separately requires that it equal the declared plain length.
                Ok(Progress { consumed, produced })
            }
            TINFLStatus::HasMoreOutput => Err(CodecError::Capacity),
            TINFLStatus::FailedCannotMakeProgress | TINFLStatus::NeedsMoreInput => {
                Err(CodecError::Truncated)
            }
            _ => Err(CodecError::Invalid),
        }
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
