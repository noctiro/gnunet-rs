//! Incremental standard GNUnet frame stream; never a private length envelope.
use gnunet_types::Error;
use gnunet_wire::official::{Frame, MessageHeader};
use zeroize::Zeroize;
/// Exact progress on the caller's original input suffix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Progress {
    /// Bytes copied from this input; every remaining byte remains caller-owned.
    pub consumed: usize,
    /// One complete original frame is held until explicit release.
    pub ready: bool,
}
/// One bounded caller-buffer frame. It admits no following frame while held,
/// letting actual communicator/QUIC flow control propagate downstream pressure.
pub struct Decoder<'buf> {
    buffer: &'buf mut [u8],
    used: usize,
    expected: Option<usize>,
    limit: usize,
}
impl<'buf> Decoder<'buf> {
    /// Buffer must hold a whole admitted frame. Failure changes no input.
    pub fn new(buffer: &'buf mut [u8], limit: usize) -> Result<Self, Error> {
        Self::validate(buffer.len(), limit)?;
        Ok(Self::validated(buffer, limit))
    }
    pub(crate) fn validate(bytes: usize, limit: usize) -> Result<(), Error> {
        if !(4..=65535).contains(&limit) {
            return Err(Error::InvalidInput);
        }
        if bytes < limit {
            return Err(Error::Capacity);
        }
        Ok(())
    }
    pub(crate) fn validated(buffer: &'buf mut [u8], limit: usize) -> Self {
        Self {
            buffer,
            used: 0,
            expected: None,
            limit,
        }
    }
    /// Retain the caller's original loan on every admission failure. Validate
    /// before the last take; assembly after successful take cannot fail.
    pub fn new_in(loan: &mut Option<&'buf mut [u8]>, limit: usize) -> Result<Self, Error> {
        let bytes = loan.as_ref().ok_or(Error::InvalidInput)?.len();
        Self::validate(bytes, limit)?;
        match loan.take() {
            Some(buffer) => Ok(Self::validated(buffer, limit)),
            None => Err(Error::InvalidInput),
        }
    }
    /// Consume at most the current frame; arbitrary transport segmentation and
    /// multiple frames per read are supported without dropping the suffix.
    pub fn push(&mut self, input: &[u8]) -> Result<Progress, Error> {
        if self.ready() {
            return Ok(Progress {
                consumed: 0,
                ready: true,
            });
        }
        let mut consumed = 0;
        while consumed < input.len() && !self.ready() {
            let target = self.expected.unwrap_or(4);
            let count = (target - self.used).min(input.len() - consumed);
            self.buffer[self.used..self.used + count]
                .copy_from_slice(&input[consumed..consumed + count]);
            self.used += count;
            consumed += count;
            if self.used == 4 && self.expected.is_none() {
                let size = MessageHeader::decode(&self.buffer[..4])?.size();
                if size > self.limit {
                    return Err(Error::TooLarge);
                }
                self.expected = Some(size);
            }
        }
        Ok(Progress {
            consumed,
            ready: self.ready(),
        })
    }
    /// Exact original complete frame, not proof of peer authenticity.
    pub fn frame(&self) -> Result<&[u8], Error> {
        if !self.ready() {
            return Err(Error::NotReady);
        }
        let bytes = &self.buffer[..self.used];
        Frame::decode(bytes)?;
        Ok(bytes)
    }
    /// Actual consumer copied/admitted the original frame; release its bytes.
    /// Returned byte count is local reclamation, not a remote FC/ACK receipt.
    pub fn release(&mut self) -> Result<usize, Error> {
        if !self.ready() {
            return Err(Error::NotReady);
        }
        let len = self.used;
        self.clear();
        Ok(len)
    }
    /// Stream FIN is valid only at a complete frame boundary. A held full frame
    /// can still be delivered after FIN; truncated bytes are never promoted.
    pub fn finish(&self) -> Result<(), Error> {
        if self.used != 0 && !self.ready() {
            Err(Error::Truncated)
        } else {
            Ok(())
        }
    }
    /// Consume this local parser, wipe the entire original loan, and return it
    /// for caller reuse. No stream/IO close or consumer completion is implied.
    pub fn recycle(mut self) -> &'buf mut [u8] {
        self.buffer.zeroize();
        self.used = 0;
        self.expected = None;
        core::mem::take(&mut self.buffer)
    }
    /// Exact local held bytes, including an incomplete header.
    pub const fn buffered(&self) -> usize {
        self.used
    }
    /// True only when all declared original bytes are present.
    pub fn ready(&self) -> bool {
        self.expected == Some(self.used)
    }
    /// Clock-free source retirement, with no invented consumer completion.
    pub fn clear(&mut self) {
        self.buffer[..self.used].zeroize();
        self.used = 0;
        self.expected = None;
    }
}
impl Drop for Decoder<'_> {
    fn drop(&mut self) {
        self.buffer.zeroize()
    }
}
