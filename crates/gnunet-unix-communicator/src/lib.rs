//! Installed testing-only GNUnet UNIX communicator packet/address formats.
//! A claimed sender is not authenticated by a local datagram or this codec.
#![no_std]
#![forbid(unsafe_code)]
use gnunet_types::Error;
use gnunet_wire::official::{
    Frame,
    communicator::{INCOMING_PREFIX, SEND_PREFIX},
};
/// Actual outer UNIXMessage prefix, GNUnet header4 and claimed sender32.
pub const PREFIX: usize = 36;
/// Actual communicator address family prefix, without dash or NUL.
pub const ADDRESS_PREFIX: &[u8] = b"unix";
/// Official GNUNET_NT_LOOPBACK category; not peer authentication.
pub const NETWORK_LOOPBACK: u32 = 1;
/// Default C Darwin datagram cap, including outer36.
pub const DARWIN_DATAGRAM_CAP: usize = 2048;
/// Current 16-bit outer-size cap, including outer36.
pub const MAX_DATAGRAM_CAP: usize = u16::MAX as usize;
/// Maximum complete inner GNUnet frame fitting each separate actual envelope.
/// Independent encapsulation limits are min'ed, never subtracted twice.
pub const fn payload_mtu(datagram_cap: usize) -> Result<usize, Error> {
    if datagram_cap < PREFIX + 4 {
        return Err(Error::InvalidInput);
    }
    let datagram = if datagram_cap > MAX_DATAGRAM_CAP {
        MAX_DATAGRAM_CAP
    } else {
        datagram_cap
    };
    let mut payload = datagram - PREFIX;
    let incoming = u16::MAX as usize - INCOMING_PREFIX;
    let send = u16::MAX as usize - SEND_PREFIX;
    if incoming < payload {
        payload = incoming
    }
    if send < payload {
        payload = send
    }
    Ok(payload)
}
/// Received packet view preserving the official receiver's ignored type/tail.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Datagram<'a> {
    /// Public asserted sender; neither signature nor credentials authenticated it.
    pub claimed_sender: [u8; 32],
    /// Actual ignored outer type value, useful for compatibility diagnostics.
    pub outer_type: u16,
    /// Exactly one complete nested GNUnet message.
    pub message: &'a [u8],
    /// Bytes after declared outer size. C ignores these; producers omit them.
    pub trailing: &'a [u8],
}
impl<'a> Datagram<'a> {
    /// Decode the complete received datagram after a native truncation check.
    /// It does not accept a truncated native prefix as a complete datagram.
    pub fn decode(input: &'a [u8], mtu: usize) -> Result<Self, Error> {
        if input.len() < PREFIX {
            return Err(Error::Truncated);
        }
        let n = usize::from(u16::from_be_bytes([input[0], input[1]]));
        if n < PREFIX + 4 {
            return Err(Error::Malformed);
        }
        if n > input.len() {
            return Err(Error::Truncated);
        }
        let message = &input[PREFIX..n];
        if message.len() > mtu {
            return Err(Error::TooLarge);
        }
        Frame::decode(message)?;
        let mut sender = [0; 32];
        sender.copy_from_slice(&input[4..36]);
        Ok(Self {
            claimed_sender: sender,
            outer_type: u16::from_be_bytes([input[2], input[3]]),
            message,
            trailing: &input[n..],
        })
    }
}
/// Canonical packet byte count after validating the complete inner frame.
pub fn encoded_len(message: &[u8], mtu: usize) -> Result<usize, Error> {
    Frame::decode(message)?;
    if message.len() > mtu {
        return Err(Error::TooLarge);
    }
    PREFIX
        .checked_add(message.len())
        .filter(|n| *n <= u16::MAX as usize)
        .ok_or(Error::Overflow)
}
/// Canonical official producer: outer type0, literal actual public sender and one
/// exact inner frame. No hidden identity/hash/key generation or extra header.
pub fn encode(
    claimed_sender: [u8; 32],
    message: &[u8],
    mtu: usize,
    out: &mut [u8],
) -> Result<usize, Error> {
    let n = encoded_len(message, mtu)?;
    let b = out.get_mut(..n).ok_or(Error::Capacity)?;
    b[..2].copy_from_slice(&(n as u16).to_be_bytes());
    b[2..4].fill(0);
    b[4..36].copy_from_slice(&claimed_sender);
    b[36..].copy_from_slice(message);
    Ok(n)
}
/// Borrowed canonical communicator address without a C terminator. A leading
/// at-sign denotes the C full-width abstract-name convention on Linux only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Address<'a> {
    path: &'a [u8],
}
impl<'a> Address<'a> {
    /// Validate a literal non-NUL path, with no silently truncated pathname/alias.
    pub fn from_path(path: &'a [u8]) -> Result<Self, Error> {
        if path.is_empty() || path.contains(&0) {
            return Err(Error::InvalidInput);
        }
        Ok(Self { path })
    }
    /// Parse the official `unix-<path>` address, preserving raw path bytes.
    pub fn decode(address: &'a [u8]) -> Result<Self, Error> {
        let path = address.strip_prefix(b"unix-").ok_or(Error::Unsupported)?;
        Self::from_path(path)
    }
    /// Exact path including an original leading at-sign, without a final NUL.
    pub const fn path(self) -> &'a [u8] {
        self.path
    }
    /// Whether the C representation asks for an abstract socket address.
    pub fn is_abstract(self) -> bool {
        self.path.first() == Some(&b'@')
    }
    /// Validate the original OS sun_path capacity, including the C final NUL.
    /// Overlong paths are refused rather than truncated onto another endpoint.
    pub fn check_capacity(self, sun_path: usize) -> Result<(), Error> {
        if self.path.len() >= sun_path {
            Err(Error::TooLarge)
        } else {
            Ok(())
        }
    }
    /// Canonical URI byte count, excluding final NUL handled by standard IPC.
    pub fn encoded_len(self) -> Result<usize, Error> {
        5usize.checked_add(self.path.len()).ok_or(Error::Overflow)
    }
    /// Encode official address bytes atomically into caller storage, without NUL.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len()?;
        let b = out.get_mut(..n).ok_or(Error::Capacity)?;
        b[..5].copy_from_slice(b"unix-");
        b[5..].copy_from_slice(self.path);
        Ok(n)
    }
}

impl core::fmt::Debug for Datagram<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UnixDatagram")
            .field("claimed_sender", &self.claimed_sender)
            .field("outer_type", &self.outer_type)
            .field("message_bytes", &self.message.len())
            .field("ignored_trailing_bytes", &self.trailing.len())
            .finish()
    }
}
