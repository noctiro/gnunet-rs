//! Raw Brotli decoding with bounded history storage and caller-owned output.

use brotli_decompressor::{
    Allocator, BrotliDecompressStream, BrotliResult, BrotliState, SliceWrapper, SliceWrapperMut,
};

// At most 256 literal block types, each with 64 contexts.
const MAX_CONTEXT_BYTES: usize = 256 * 64;
// The decoder reserves write-ahead space beyond its power-of-two history.
const HISTORY_SLACK: usize = 1024;

pub(super) enum Window {
    Standard,
    Large,
}

pub(super) fn decode(input: &[u8], output: &mut [u8], window: Window) -> Option<usize> {
    let history = output
        .len()
        .max(MAX_CONTEXT_BYTES)
        .checked_next_power_of_two()?;
    let constructor = match window {
        Window::Standard => BrotliState::new_strict,
        Window::Large => BrotliState::new,
    };
    let mut state = constructor(
        FallibleAlloc {
            max_bytes: history.checked_add(HISTORY_SLACK)?,
        },
        // Standard Brotli bounds these codebook allocations by their alphabets.
        FallibleAlloc {
            max_bytes: usize::MAX,
        },
        FallibleAlloc {
            max_bytes: usize::MAX,
        },
    );
    let mut available_in = input.len();
    let mut input_offset = 0;
    let mut available_out = output.len();
    let mut produced = 0;
    let result = BrotliDecompressStream(
        &mut available_in,
        &mut input_offset,
        input,
        &mut available_out,
        &mut produced,
        output,
        &mut 0,
        &mut state,
    );
    (matches!(result, BrotliResult::ResultSuccess)
        && available_in == 0
        && input_offset == input.len()
        && produced <= output.len())
    .then_some(produced)
}

struct FallibleAlloc {
    max_bytes: usize,
}

impl<T: Default> Allocator<T> for FallibleAlloc {
    type AllocatedMemory = Memory<T>;

    fn alloc_cell(&mut self, len: usize) -> Self::AllocatedMemory {
        let mut memory = Vec::new();
        if len
            .checked_mul(std::mem::size_of::<T>())
            .is_some_and(|bytes| bytes <= self.max_bytes)
            && memory.try_reserve_exact(len).is_ok()
        {
            memory.resize_with(len, T::default);
        }
        Memory(memory)
    }

    fn free_cell(&mut self, _memory: Self::AllocatedMemory) {}
}

#[derive(Default)]
struct Memory<T>(Vec<T>);

impl<T> SliceWrapper<T> for Memory<T> {
    fn slice(&self) -> &[T] {
        &self.0
    }
}

impl<T> SliceWrapperMut<T> for Memory<T> {
    fn slice_mut(&mut self) -> &mut [T] {
        &mut self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{Window, decode};

    #[test]
    fn accepts_standard_window_without_ignoring_output_or_member_end() {
        const RFC_WINDOW_24: &[u8] = b"\x8f\x03\x80metadata\x03";
        let mut output = [0; 8];
        assert_eq!(
            decode(RFC_WINDOW_24, &mut output, Window::Standard),
            Some(8)
        );
        assert_eq!(&output, b"metadata");
        assert_eq!(
            decode(RFC_WINDOW_24, &mut output[..7], Window::Standard),
            None
        );
        let trailing = [RFC_WINDOW_24, &[0]].concat();
        assert_eq!(decode(&trailing, &mut output, Window::Standard), None);
    }

    #[test]
    fn accepts_a_small_large_window_member_only_in_pdf_mode() {
        // Raw RFC 9841 window bits 30, one uncompressed metablock,
        // then the empty final block.
        const LARGE_WINDOW: &[u8] = b"\x11\x1e\x0e\0\x02metadata\x03";
        let mut output = [0; 8];
        assert_eq!(decode(LARGE_WINDOW, &mut output, Window::Standard), None);
        assert_eq!(decode(LARGE_WINDOW, &mut output, Window::Large), Some(8));
        assert_eq!(&output, b"metadata");
        assert_eq!(decode(LARGE_WINDOW, &mut output[..7], Window::Large), None);
    }
}
