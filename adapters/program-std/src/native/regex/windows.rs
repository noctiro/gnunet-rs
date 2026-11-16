//! Rust BRE policy over lossless local symbols and retained Windows locale readers.
use super::bre::{self, Comparison, CompileError, Context, Limits, Program};
use gnunet_native::{
    locale::{
        CharacterClass,
        regex::{Locale, Strength},
    },
    os_bytes,
};
use std::{cmp::Ordering, io, os::windows::ffi::OsStrExt};

pub(crate) enum RegexCompileFailure {
    InvalidPattern,
    Boundary(io::Error),
}
impl From<io::Error> for RegexCompileFailure {
    fn from(error: io::Error) -> Self {
        Self::Boundary(error)
    }
}
struct NativeContext(Locale);
impl Context for NativeContext {
    fn classify(&self, symbol: u32, class: CharacterClass) -> io::Result<bool> {
        if let Some(value) = char::from_u32(symbol) {
            self.0.classify(value, class)
        } else {
            Ok(false)
        }
    }
    fn compare(&self, left: &[u32], right: &[u32], kind: Comparison) -> io::Result<Ordering> {
        // Isolated local UTF-16 units remain exact literals and never enter NLS.
        if left
            .iter()
            .chain(right)
            .any(|unit| char::from_u32(*unit).is_none())
        {
            return Ok(left.cmp(right));
        }
        let mut a = [0; 128];
        let mut b = [0; 128];
        let a = wide(left, &mut a)?;
        let b = wide(right, &mut b)?;
        self.0.compare(
            a,
            b,
            match kind {
                Comparison::Collation => Strength::Ordering,
                Comparison::Primary => Strength::Primary,
            },
        )
    }
    fn collating_symbol(&self, value: &[u32]) -> io::Result<bool> {
        if value.is_empty() {
            return Ok(false);
        }
        if value.iter().any(|unit| char::from_u32(*unit).is_none()) {
            return Ok(self.0.is_classic_collation() && value.len() == 1);
        }
        let mut storage = [0; 128];
        self.0.collating_symbol(wide(value, &mut storage)?)
    }
    fn element_width(&self) -> usize {
        self.0.element_width()
    }
    fn element_width_at(&self, first: u32) -> usize {
        char::from_u32(first).map_or(1, |first| self.0.element_width_for(first))
    }
}
fn wide<'a>(input: &[u32], storage: &'a mut [u16; 128]) -> io::Result<&'a [u16]> {
    let mut length = 0;
    for unit in input {
        let value = char::from_u32(*unit).ok_or(io::ErrorKind::InvalidInput)?;
        let remaining = storage
            .get_mut(length..)
            .filter(|slice| slice.len() >= value.len_utf16())
            .ok_or(io::ErrorKind::InvalidInput)?;
        length += value.encode_utf16(remaining).len();
    }
    Ok(&storage[..length])
}
fn symbols(bytes: &[u8], maximum: usize, kind: &'static str) -> io::Result<Vec<u32>> {
    let bytes = &bytes[..bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len())];
    if bytes.len() > maximum.saturating_mul(4) {
        return Err(bre::limit(kind));
    }
    let input = os_bytes::decode(bytes)?;
    let mut result = Vec::new();
    for value in char::decode_utf16(input.encode_wide()) {
        if result.len() == maximum {
            return Err(bre::limit(kind));
        }
        result
            .try_reserve(1)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        result.push(
            value
                .map(u32::from)
                .unwrap_or_else(|error| u32::from(error.unpaired_surrogate())),
        );
    }
    Ok(result)
}
pub(crate) struct Regex {
    program: Program,
    context: NativeContext,
}
impl Regex {
    pub(crate) fn new(pattern: &[u8]) -> Result<Self, RegexCompileFailure> {
        #[expect(
            unsafe_code,
            reason = "PROGRAM's native-locale capability excludes foreign mutation throughout independent classification/collation capture"
        )]
        // SAFETY: capture invokes no user callbacks and all following readers own snapshots.
        let context = NativeContext(unsafe { Locale::capture_current_thread()? });
        let limits = Limits::default();
        let pattern = symbols(pattern, limits.pattern, "pattern")?;
        let program =
            Program::compile(&pattern, &context, limits).map_err(|error| match error {
                CompileError::Syntax(_syntax) => RegexCompileFailure::InvalidPattern,
                CompileError::Boundary(error) => RegexCompileFailure::Boundary(error),
            })?;
        Ok(Self { program, context })
    }
    pub(crate) fn matches(&self, value: &[u8]) -> io::Result<bool> {
        let input = symbols(value, Limits::default().input, "input")?;
        self.program.matches(&input, &self.context)
    }
}
