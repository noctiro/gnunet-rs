//! One bounded native TCP read; oversize completion fails without truncation.
use super::super::sdk;
use objc2_foundation::{NSData, NSError};
use std::io;
use zeroize::Zeroizing;

/// One owned stream chunk or the original read direction's end.
pub enum TcpRead {
    /// Original bytes, automatically wiped when discarded.
    Data(Zeroizing<Vec<u8>>),
    /// Empty native read; no later stream bytes can be read.
    End,
}
pub(super) struct Reservation {
    bytes: Zeroizing<Vec<u8>>,
    maximum: usize,
}
impl Reservation {
    pub fn new(maximum: usize) -> io::Result<Self> {
        if !(1..=super::MAX_TCP_CHUNK_BYTES).contains(&maximum) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid TCP read bound",
            ));
        }
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(maximum)
            .map_err(|_| io::Error::other("TCP read allocation refused"))?;
        if bytes.capacity() > maximum {
            return Err(io::Error::other("TCP read allocation exceeds bound"));
        }
        Ok(Self { bytes, maximum })
    }
    pub fn complete(mut self, data: *mut NSData, error: *mut NSError) -> io::Result<TcpRead> {
        sdk::error_result(error)?;
        if !super::sdk::copy_read(data, self.maximum, &mut self.bytes)? {
            return Ok(TcpRead::End);
        }
        Ok(TcpRead::Data(self.bytes))
    }
}

impl std::fmt::Debug for TcpRead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Data(bytes) => f
                .debug_struct("TcpReadData")
                .field("bytes", &bytes.len())
                .finish(),
            Self::End => f.write_str("TcpReadEnd"),
        }
    }
}
