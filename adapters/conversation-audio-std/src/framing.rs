//! Exact incremental helper730 input/output; it grants no media/peer receipt.
use crate::{Error, Limits};
use gnunet_types::Error as Fault;
use gnunet_wire::official::{MessageHeader, message_type as mt};
use std::io::{self, Read, Write};
use zeroize::Zeroizing;
/// One original helper pipe reader. The payload need not align with an Ogg page.
pub struct Input<R> {
    reader: R,
    bytes: Zeroizing<Vec<u8>>,
    limit: usize,
}
impl<R: Read> Input<R> {
    /// Prepare bounded storage without reading a byte or opening a device.
    pub fn new(reader: R, limits: Limits) -> Result<Self, Error> {
        let limits = limits.validate()?;
        Ok(Self {
            reader,
            bytes: Zeroizing::new(Vec::new()),
            limit: limits.frame_bytes,
        })
    }
    /// Read one real whole730. Only EOF before a new header returns None;
    /// truncated header/body and native errors keep their original prefix facts.
    pub fn next_frame(&mut self) -> Result<Option<&[u8]>, Error> {
        let mut header = [0; 4];
        if !read_exact(&mut self.reader, &mut header, "helper header", true)? {
            return Ok(None);
        }
        let n = usize::from(u16::from_be_bytes([header[0], header[1]]));
        if n < 4 || n > self.limit || u16::from_be_bytes([header[2], header[3]]) != 730 {
            return Err(Fault::Malformed.into());
        }
        let payload = n - 4;
        if payload > self.bytes.capacity() {
            let additional = payload - self.bytes.len();
            self.bytes
                .try_reserve_exact(additional)
                .map_err(|_| Fault::Capacity)?;
        }
        if self.bytes.capacity() > self.limit - 4 {
            return Err(Fault::Capacity.into());
        }
        if payload < self.bytes.len() {
            self.bytes[payload..].fill(0);
        }
        self.bytes.resize(payload, 0);
        read_exact(&mut self.reader, &mut self.bytes, "helper payload", false)?;
        Ok(Some(&self.bytes))
    }
}
fn read_exact(
    reader: &mut impl Read,
    out: &mut [u8],
    operation: &'static str,
    clean_eof: bool,
) -> Result<bool, Error> {
    let mut at = 0;
    while at < out.len() {
        match reader.read(&mut out[at..]) {
            Ok(0) if at == 0 && clean_eof => return Ok(false),
            Ok(0) => {
                return Err(Error::Truncated {
                    operation,
                    actual: at,
                    expected: out.len(),
                });
            }
            Ok(n) => at = at.checked_add(n).ok_or(Fault::Overflow)?,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(source) => {
                return Err(Error::Io {
                    operation,
                    completed: at,
                    source,
                });
            }
        }
    }
    Ok(true)
}
/// Write the original complete730 header/payload with exact partial-write
/// cursors. A successful local flush proves neither playback nor remote receipt.
pub fn write_frame(
    writer: &mut impl Write,
    payload: &[u8],
    limits: Limits,
) -> Result<usize, Error> {
    let n = payload.len().checked_add(4).ok_or(Fault::Overflow)?;
    if n > limits.frame_bytes {
        return Err(Fault::TooLarge.into());
    }
    let mut header = [0; 4];
    MessageHeader::from_total_size(mt::CONVERSATION_AUDIO, n)?.encode(&mut header)?;
    let mut completed = 0;
    for part in [&header[..], payload] {
        let mut at = 0;
        while at < part.len() {
            match writer.write(&part[at..]) {
                Ok(0) => {
                    return Err(Error::Io {
                        operation: "helper stdout",
                        completed,
                        source: io::Error::new(
                            io::ErrorKind::WriteZero,
                            "audio pipe made no progress",
                        ),
                    });
                }
                Ok(wrote) => {
                    at += wrote;
                    completed += wrote;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(source) => {
                    return Err(Error::Io {
                        operation: "helper stdout",
                        completed,
                        source,
                    });
                }
            }
        }
    }
    writer.flush().map_err(|source| Error::Io {
        operation: "helper stdout flush",
        completed,
        source,
    })?;
    Ok(completed)
}
