//! Pure Rust Ogg version0 framing/checksum. No codec/device/library is invoked.
use crate::{Error, Limits};
use gnunet_types::Error as Fault;
use zeroize::Zeroizing;
const fn table() -> [u32; 256] {
    let mut t = [0; 256];
    let mut i = 0;
    while i < 256 {
        let mut r = (i as u32) << 24;
        let mut j = 0;
        while j < 8 {
            r = if r & 0x80000000 != 0 {
                (r << 1) ^ 0x04c11db7
            } else {
                r << 1
            };
            j += 1;
        }
        t[i] = r;
        i += 1;
    }
    t
}
const CRC: [u32; 256] = table();
/// Actual non-reflected Ogg CRC, initial0/no final xor, with bytes22..26 zeroed.
/// This is an integrity checksum, never authentication or GNUnet's CRC32_N.
pub fn checksum(page: &[u8]) -> u32 {
    let mut crc = 0u32;
    for (at, b) in page.iter().enumerate() {
        let byte = if (22..26).contains(&at) { 0 } else { *b };
        crc = (crc << 8) ^ CRC[usize::from(((crc >> 24) as u8) ^ byte)];
    }
    crc
}
fn le32(b: &[u8], at: usize) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(
        b.get(at..at + 4)
            .ok_or(Fault::Truncated)?
            .try_into()
            .map_err(|_| Fault::Truncated)?,
    ))
}
fn le64(b: &[u8], at: usize) -> Result<u64, Error> {
    Ok(u64::from_le_bytes(
        b.get(at..at + 8)
            .ok_or(Fault::Truncated)?
            .try_into()
            .map_err(|_| Fault::Truncated)?,
    ))
}
/// An exact checksum-checked borrowed original Ogg page.
pub struct Page<'a> {
    bytes: &'a [u8],
    header: usize,
}
impl<'a> Page<'a> {
    /// Validate one whole original page before exposing its lacing/body.
    pub fn decode(bytes: &'a [u8], limits: Limits) -> Result<Self, Error> {
        if bytes.len() < 27 {
            return Err(Fault::Truncated.into());
        }
        if bytes.get(..4) != Some(b"OggS") || bytes[4] != 0 || bytes[5] & !7 != 0 {
            return Err(Error::Ogg("capture/version/flags"));
        }
        let header = 27usize
            .checked_add(usize::from(bytes[26]))
            .ok_or(Fault::Overflow)?;
        let laces = bytes.get(27..header).ok_or(Fault::Truncated)?;
        let len = laces.iter().try_fold(header, |n, b| {
            n.checked_add(usize::from(*b)).ok_or(Fault::Overflow)
        })?;
        if len > limits.page_bytes {
            return Err(Fault::Capacity.into());
        }
        if len != bytes.len() {
            return Err(Fault::Malformed.into());
        }
        if checksum(bytes) != le32(bytes, 22)? {
            return Err(Error::Checksum);
        }
        Ok(Self { bytes, header })
    }
    /// Exact actual header flags (continued1/BOS2/EOS4).
    pub const fn flags(&self) -> u8 {
        self.bytes[5]
    }
    /// Actual little-endian original stream serial.
    pub fn serial(&self) -> Result<u32, Error> {
        le32(self.bytes, 14)
    }
    /// Original modulo32-bit page sequence number.
    pub fn sequence(&self) -> Result<u32, Error> {
        le32(self.bytes, 18)
    }
    /// Original48k samples per channel; u64::MAX means no completed packet.
    pub fn granule(&self) -> Result<u64, Error> {
        le64(self.bytes, 6)
    }
    /// Actual original lacing values.
    pub fn laces(&self) -> &'a [u8] {
        &self.bytes[27..self.header]
    }
    /// Exact original page body.
    pub fn body(&self) -> &'a [u8] {
        &self.bytes[self.header..]
    }
}
/// Actual bounded framing progress; resync never fabricates audio or headers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Status {
    /// More bytes are required for this same original page.
    NeedInput,
    /// One exact verified page can now be borrowed and consumed.
    Ready,
    /// One bad capture-prefix byte was discarded within the finite budget.
    Resynchronized,
}
/// Incremental byte-stream page owner, independent of helper-frame boundaries.
pub struct Pages {
    bytes: Zeroizing<Vec<u8>>,
    limits: Limits,
    ready: bool,
    skipped: usize,
}
impl Pages {
    /// Construct empty page storage; no input is parsed or provider called.
    pub fn new(limits: Limits) -> Result<Self, Error> {
        Ok(Self {
            bytes: Zeroizing::new(Vec::new()),
            limits: limits.validate()?,
            ready: false,
            skipped: 0,
        })
    }
    /// Consume only the needed prefix. Re-enter with remaining input, including
    /// empty input when internal header/lacing state can advance. A Ready page
    /// must be consumed before any more bytes are admitted.
    pub fn feed(&mut self, input: &[u8]) -> Result<(usize, Status), Error> {
        if self.ready {
            return Err(Fault::NotReady.into());
        }
        let target = if self.bytes.len() < 4 {
            4
        } else if self.bytes.len() < 27 {
            27
        } else {
            let header = 27 + usize::from(self.bytes[26]);
            if self.bytes.len() < header {
                header
            } else {
                self.bytes[27..header].iter().try_fold(header, |n, b| {
                    n.checked_add(usize::from(*b)).ok_or(Fault::Overflow)
                })?
            }
        };
        if target > self.limits.page_bytes {
            return Err(Fault::Capacity.into());
        }
        let used = (target - self.bytes.len()).min(input.len());
        if target > self.bytes.capacity() {
            let additional = target - self.bytes.len();
            self.bytes
                .try_reserve_exact(additional)
                .map_err(|_| Fault::Capacity)?;
        }
        if self.bytes.capacity() > self.limits.page_bytes {
            return Err(Fault::Capacity.into());
        }
        self.bytes.extend_from_slice(&input[..used]);
        if self.bytes.len() >= 4 && self.bytes.get(..4) != Some(b"OggS") {
            self.bytes.copy_within(1.., 0);
            let n = self.bytes.len() - 1;
            self.bytes[n] = 0;
            self.bytes.truncate(n);
            self.skipped = self.skipped.checked_add(1).ok_or(Fault::Overflow)?;
            if self.skipped > self.limits.resync_bytes {
                return Err(Error::Ogg("capture resynchronization budget"));
            }
            return Ok((used, Status::Resynchronized));
        }
        if self.bytes.len() >= 27 {
            let header = 27 + usize::from(self.bytes[26]);
            if self.bytes.len() >= header {
                let n = self.bytes[27..header].iter().try_fold(header, |n, b| {
                    n.checked_add(usize::from(*b)).ok_or(Fault::Overflow)
                })?;
                if n == self.bytes.len() {
                    Page::decode(&self.bytes, self.limits)?;
                    self.ready = true;
                    self.skipped = 0;
                    return Ok((used, Status::Ready));
                }
            }
        }
        Ok((used, Status::NeedInput))
    }
    /// Borrow the actual original verified page until consume.
    pub fn page(&self) -> Result<Page<'_>, Error> {
        if !self.ready {
            return Err(Fault::NotReady.into());
        }
        // Ready was established by exact decode/CRC over this immutable buffer.
        Ok(Page {
            bytes: &self.bytes,
            header: 27 + usize::from(self.bytes[26]),
        })
    }
    /// Release exactly the original handled page and erase its retained bytes.
    pub fn consume(&mut self) -> Result<(), Error> {
        if !self.ready {
            return Err(Fault::NotReady.into());
        }
        self.bytes.fill(0);
        self.bytes.clear();
        self.ready = false;
        Ok(())
    }
    /// EOF is clean only at a real page boundary, never at a partial capture.
    pub fn finish(&self) -> Result<(), Error> {
        if !self.bytes.is_empty() {
            return Err(Error::Truncated {
                operation: "Ogg page",
                actual: self.bytes.len(),
                expected: 27,
            });
        }
        Ok(())
    }
}
/// Actual one-packet-per-page muxer, matching the selected ordinary recorder.
pub struct Mux {
    serial: u32,
    sequence: u32,
    bytes: Zeroizing<Vec<u8>>,
    limits: Limits,
}
impl Mux {
    /// Start one actual stream serial; the caller owns real serial selection.
    pub fn new(serial: u32, limits: Limits) -> Result<Self, Error> {
        Ok(Self {
            serial,
            sequence: 0,
            bytes: Zeroizing::new(Vec::new()),
            limits: limits.validate()?,
        })
    }
    /// Encode one whole original packet/page; no audio/codec result is invented.
    pub fn packet(&mut self, packet: &[u8], flags: u8, granule: u64) -> Result<&[u8], Error> {
        if flags & !6 != 0 {
            return Err(Fault::InvalidInput.into());
        }
        let segments = packet
            .len()
            .checked_div(255)
            .and_then(|n| n.checked_add(1))
            .ok_or(Fault::Overflow)?;
        if segments > 255 {
            return Err(Fault::TooLarge.into());
        }
        let header = 27 + segments;
        let total = header.checked_add(packet.len()).ok_or(Fault::Overflow)?;
        if total > self.limits.page_bytes
            || total.checked_add(4).ok_or(Fault::Overflow)? > self.limits.frame_bytes
        {
            return Err(Fault::TooLarge.into());
        }
        let next = self.sequence.checked_add(1).ok_or(Fault::Overflow)?;
        self.bytes.fill(0);
        self.bytes.clear();
        if total > self.bytes.capacity() {
            self.bytes
                .try_reserve_exact(total)
                .map_err(|_| Fault::Capacity)?;
        }
        if self.bytes.capacity() > self.limits.page_bytes {
            return Err(Fault::Capacity.into());
        }
        self.bytes.resize(total, 0);
        self.bytes[..4].copy_from_slice(b"OggS");
        self.bytes[5] = flags;
        self.bytes[6..14].copy_from_slice(&granule.to_le_bytes());
        self.bytes[14..18].copy_from_slice(&self.serial.to_le_bytes());
        self.bytes[18..22].copy_from_slice(&self.sequence.to_le_bytes());
        self.bytes[26] = u8::try_from(segments).map_err(|_| Fault::TooLarge)?;
        for value in &mut self.bytes[27..header - 1] {
            *value = 255;
        }
        self.bytes[header - 1] = u8::try_from(packet.len() % 255).map_err(|_| Fault::Overflow)?;
        self.bytes[header..].copy_from_slice(packet);
        let crc = checksum(&self.bytes);
        self.bytes[22..26].copy_from_slice(&crc.to_le_bytes());
        self.sequence = next;
        Ok(&self.bytes)
    }
}
