use gnunet_types::Error;
use miniz_oxide::inflate::{
    TINFLStatus,
    core::{DecompressorOxide, decompress, decompress_with_limit, inflate_flags},
};

/// DEFLATE history needed to decode every standard zlib window size.
pub const INFLATE_WINDOW_BYTES: usize = 32_768;
const MEMBER_FLAGS: u32 =
    inflate_flags::TINFL_FLAG_PARSE_ZLIB_HEADER | inflate_flags::TINFL_FLAG_COMPUTE_ADLER32;
const LINEAR: u32 = inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF;

pub(crate) struct Inflater(Option<DecompressorOxide>);

impl Inflater {
    pub(crate) const fn new() -> Self {
        Self(None)
    }

    pub(crate) fn member(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Error> {
        let state = self.0.get_or_insert_with(DecompressorOxide::new);
        state.init();
        let (status, read, written) = decompress(state, input, output, 0, MEMBER_FLAGS | LINEAR);
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

    pub(crate) fn visit_member(
        &mut self,
        input: &[u8],
        workspace: &mut [u8],
        limit: usize,
        visit: &mut dyn FnMut(&[u8]) -> Result<(), Error>,
    ) -> Result<usize, Error> {
        let history = workspace
            .get_mut(..INFLATE_WINDOW_BYTES)
            .ok_or(Error::Capacity)?;
        let state = self.0.get_or_insert_with(DecompressorOxide::new);
        state.init();
        let (mut read, mut produced) = (0, 0usize);
        loop {
            let position = produced % INFLATE_WINDOW_BYTES;
            // Before the first wrap, a match cannot reference history before
            // this member's first byte, including data left by an older member.
            let flags = MEMBER_FLAGS
                | if produced < INFLATE_WINDOW_BYTES {
                    LINEAR
                } else {
                    0
                };
            let (status, consumed, written) = decompress_with_limit(
                state,
                &input[read..],
                history,
                position,
                (limit - produced).saturating_add(1),
                flags,
            );
            read += consumed;
            if written > limit - produced {
                return Err(Error::Capacity);
            }
            match status {
                TINFLStatus::Done if read == input.len() => {}
                TINFLStatus::HasMoreOutput if written != 0 => {}
                TINFLStatus::NeedsMoreInput | TINFLStatus::FailedCannotMakeProgress => {
                    return Err(Error::Truncated);
                }
                _ => return Err(Error::Malformed),
            }
            if written != 0 {
                visit(&history[position..position + written])?;
                produced += written;
            }
            if status == TINFLStatus::Done {
                return Ok(produced);
            }
        }
    }
}
