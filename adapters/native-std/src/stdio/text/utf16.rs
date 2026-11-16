//! Fixed console conversion storage, including split surrogate pairs and reads.
use std::io;
pub(super) const UNITS: usize = 512;
pub(super) struct Buffer {
    bytes: [u8; UNITS * 4],
    start: usize,
    end: usize,
    high: Option<u16>,
    malformed: bool,
    eof: bool,
    line_start: bool,
}
impl Buffer {
    pub(super) fn new() -> Self {
        Self {
            bytes: [0; UNITS * 4],
            start: 0,
            end: 0,
            high: None,
            malformed: false,
            eof: false,
            line_start: true,
        }
    }
    pub(super) fn copy(&mut self, output: &mut [u8]) -> io::Result<Option<usize>> {
        if self.start < self.end {
            let count = output.len().min(self.end - self.start);
            output[..count].copy_from_slice(&self.bytes[self.start..self.start + count]);
            self.start += count;
            return Ok(Some(count));
        }
        if self.malformed {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid console UTF-16",
            ));
        }
        Ok(self.eof.then_some(0))
    }
    pub(super) fn feed(&mut self, input: &[u16]) -> io::Result<()> {
        if input.len() > UNITS || self.start != self.end || self.eof || self.malformed {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "console conversion state is not ready",
            ));
        }
        self.start = 0;
        self.end = 0;
        if input.is_empty() {
            self.eof = true;
            self.malformed = self.high.is_some();
            return Ok(());
        }
        for &unit in input {
            let scalar = if let Some(high) = self.high.take() {
                if !(0xdc00..=0xdfff).contains(&unit) {
                    self.malformed = true;
                    break;
                }
                0x10000 + ((u32::from(high) - 0xd800) << 10) + u32::from(unit) - 0xdc00
            } else if (0xd800..=0xdbff).contains(&unit) {
                self.high = Some(unit);
                self.line_start = false;
                continue;
            } else if (0xdc00..=0xdfff).contains(&unit) {
                self.malformed = true;
                break;
            } else {
                u32::from(unit)
            };
            if self.line_start && scalar == 0x1a {
                self.eof = true;
                break;
            }
            self.line_start = matches!(scalar, 10 | 13);
            let scalar = char::from_u32(scalar).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid console scalar")
            })?;
            let mut encoded = [0; 4];
            let bytes = scalar.encode_utf8(&mut encoded).as_bytes();
            let end = self
                .end
                .checked_add(bytes.len())
                .ok_or(io::ErrorKind::InvalidData)?;
            self.bytes
                .get_mut(self.end..end)
                .ok_or(io::ErrorKind::InvalidData)?
                .copy_from_slice(bytes);
            self.end = end;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn split_surrogates_small_reads_and_control_z_keep_original_prefix() -> io::Result<()> {
        let mut buffer = Buffer::new();
        buffer.feed(&[0x65e5, 0xd83d])?;
        let mut bytes = [0; 8];
        let mut result = Vec::new();
        while let Some(count) = buffer.copy(&mut bytes[..1])? {
            result.extend_from_slice(&bytes[..count]);
        }
        buffer.feed(&[0xde00, 13, 10, 26, 13, 10])?;
        while let Some(count) = buffer.copy(&mut bytes[..1])? {
            if count == 0 {
                break;
            }
            result.extend_from_slice(&bytes[..count]);
        }
        if result != "日😀\r\n".as_bytes() || buffer.copy(&mut bytes)? != Some(0) {
            return Err(io::Error::other(
                "console conversion changed the original Unicode/EOF prefix",
            ));
        }
        Ok(())
    }
    #[test]
    fn malformed_suffix_preserves_positive_prefix_and_never_becomes_eof() -> io::Result<()> {
        let mut buffer = Buffer::new();
        buffer.feed(&[65, 0xdc00])?;
        let mut bytes = [0; 4];
        if buffer.copy(&mut bytes)? != Some(1) || bytes[0] != b'A' {
            return Err(io::Error::other("valid console prefix was discarded"));
        }
        if buffer.copy(&mut bytes).is_ok() {
            return Err(io::Error::other("malformed console input became EOF"));
        }
        let mut pending = Buffer::new();
        pending.feed(&[0xd800])?;
        pending.feed(&[])?;
        if pending.copy(&mut bytes).is_ok() {
            return Err(io::Error::other("incomplete surrogate became EOF"));
        }
        Ok(())
    }
}
