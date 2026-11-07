//! Bounded byte cursors used only by the official DHT codecs.
use gnunet_types::Error;

pub(super) struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> Reader<'a> {
    pub(super) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }
    pub(super) const fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }
    pub(super) fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        let end = self.position.checked_add(length).ok_or(Error::Overflow)?;
        let value = self.bytes.get(self.position..end).ok_or(Error::Truncated)?;
        self.position = end;
        Ok(value)
    }
    pub(super) fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().map_err(|_| Error::Truncated)?,
        ))
    }
    pub(super) fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| Error::Truncated)?,
        ))
    }
    pub(super) fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| Error::Truncated)?,
        ))
    }
}

pub(super) struct Writer<'a> {
    bytes: &'a mut [u8],
    position: usize,
}
impl<'a> Writer<'a> {
    pub(super) fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, position: 0 }
    }
    pub(super) fn put(&mut self, value: &[u8]) -> Result<(), Error> {
        let end = self
            .position
            .checked_add(value.len())
            .ok_or(Error::Overflow)?;
        self.bytes
            .get_mut(self.position..end)
            .ok_or(Error::Capacity)?
            .copy_from_slice(value);
        self.position = end;
        Ok(())
    }
    pub(super) fn u16(&mut self, value: u16) -> Result<(), Error> {
        self.put(&value.to_be_bytes())
    }
    pub(super) fn u32(&mut self, value: u32) -> Result<(), Error> {
        self.put(&value.to_be_bytes())
    }
    pub(super) fn u64(&mut self, value: u64) -> Result<(), Error> {
        self.put(&value.to_be_bytes())
    }
}
