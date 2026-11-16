//! Fixed-capacity helper protocol lines and diagnostics.
use std::fmt;
/// Fixed text storage for official endpoint lines and bounded diagnostics.
pub(crate) struct Text<const N: usize> {
    bytes: [u8; N],
    len: usize,
}
impl<const N: usize> Text<N> {
    pub fn new() -> Self {
        Self {
            bytes: [0; N],
            len: 0,
        }
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
impl<const N: usize> fmt::Write for Text<N> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let end = self.len.checked_add(s.len()).ok_or(fmt::Error)?;
        if end > N {
            return Err(fmt::Error);
        }
        self.bytes[self.len..end].copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}
