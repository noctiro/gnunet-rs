//! Common GNUnet headers; no unaligned references or allocation.
use super::{HEADER_LEN, MAX_MESSAGE_SIZE, SIGNATURE_PURPOSE_LEN};
use gnunet_types::Error;

/// A raw GANA GNUnet message code; unknown assignments are retained losslessly.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MessageType(u16);
impl MessageType {
    /// Preserve any 16-bit code, including future or private assignments.
    #[must_use]
    pub const fn new(value: u16) -> Self {
        Self(value)
    }
    /// Numeric message type in host byte order.
    #[must_use]
    pub const fn value(self) -> u16 {
        self.0
    }
}
impl From<u16> for MessageType {
    fn from(value: u16) -> Self {
        Self(value)
    }
}
impl From<MessageType> for u16 {
    fn from(value: MessageType) -> Self {
        value.0
    }
}

/// Official `GNUNET_MessageHeader`: total size BE16, then message type BE16.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MessageHeader {
    size: u16,
    message_type: MessageType,
}
impl MessageHeader {
    /// Construct for a payload size; total size includes the four-byte header.
    pub fn new(message_type: MessageType, payload_len: usize) -> Result<Self, Error> {
        let size = HEADER_LEN.checked_add(payload_len).ok_or(Error::Overflow)?;
        Self::from_total_size(message_type, size)
    }
    /// Construct for a complete frame size, rejecting sizes below four or above 65535.
    pub fn from_total_size(message_type: MessageType, size: usize) -> Result<Self, Error> {
        if size < HEADER_LEN {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            size: u16::try_from(size).map_err(|_| Error::TooLarge)?,
            message_type,
        })
    }
    /// Decode the first four bytes. This does not establish that a payload is present.
    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        let bytes: &[u8; HEADER_LEN] = input
            .get(..HEADER_LEN)
            .ok_or(Error::Truncated)?
            .try_into()
            .map_err(|_| Error::Truncated)?;
        Self::from_total_size(
            MessageType::new(u16::from_be_bytes([bytes[2], bytes[3]])),
            usize::from(u16::from_be_bytes([bytes[0], bytes[1]])),
        )
    }
    /// Encode only the header. A capacity error leaves the output unchanged.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let destination = output.get_mut(..HEADER_LEN).ok_or(Error::Capacity)?;
        destination[..2].copy_from_slice(&self.size.to_be_bytes());
        destination[2..].copy_from_slice(&self.message_type.0.to_be_bytes());
        Ok(HEADER_LEN)
    }
    /// Total frame size, including this header.
    #[must_use]
    pub const fn size(self) -> usize {
        self.size as usize
    }
    /// Type assignment, preserved even if this implementation has no handler for it.
    #[must_use]
    pub const fn message_type(self) -> MessageType {
        self.message_type
    }
    /// Size of the payload after the header.
    #[must_use]
    pub const fn payload_len(self) -> usize {
        self.size() - HEADER_LEN
    }
}

/// One complete borrowed official GNUnet message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Frame<'a> {
    header: MessageHeader,
    payload: &'a [u8],
}
impl<'a> Frame<'a> {
    /// Borrow a payload after checking that its complete frame fits BE16 size.
    pub fn new(message_type: MessageType, payload: &'a [u8]) -> Result<Self, Error> {
        Ok(Self {
            header: MessageHeader::new(message_type, payload.len())?,
            payload,
        })
    }
    /// Decode exactly one frame, rejecting concatenated frames and trailing bytes.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let (frame, remainder) = Self::decode_prefix(input)?;
        if !remainder.is_empty() {
            return Err(Error::InvalidInput);
        }
        Ok(frame)
    }
    /// Decode one frame and return every trailing byte to the caller.
    /// Failure consumes no input; the caller can retain a truncated prefix for more I/O.
    pub fn decode_prefix(input: &'a [u8]) -> Result<(Self, &'a [u8]), Error> {
        let header = MessageHeader::decode(input)?;
        let complete = input.get(..header.size()).ok_or(Error::Truncated)?;
        Ok((
            Self {
                header,
                payload: &complete[HEADER_LEN..],
            },
            &input[header.size()..],
        ))
    }
    /// Encode a full message. Capacity rejection leaves all output bytes unchanged.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        if output.len() < self.header.size() {
            return Err(Error::Capacity);
        }
        self.header.encode(output)?;
        output[HEADER_LEN..self.header.size()].copy_from_slice(self.payload);
        Ok(self.header.size())
    }
    /// The validated common header.
    #[must_use]
    pub const fn header(self) -> MessageHeader {
        self.header
    }
    /// The original borrowed payload, without the common header.
    #[must_use]
    pub const fn payload(self) -> &'a [u8] {
        self.payload
    }
    /// Total encoded message size.
    #[must_use]
    pub const fn encoded_len(self) -> usize {
        self.header.size()
    }
}

/// Borrowed frames from a stream buffer. An incomplete or invalid suffix is reported once.
/// After an error, `remaining()` retains that complete suffix; no partial message is swallowed.
#[derive(Clone, Debug)]
pub struct Frames<'a> {
    remaining: &'a [u8],
    failed: bool,
}
impl<'a> Frames<'a> {
    /// Start with all bytes supplied by the stream owner.
    #[must_use]
    pub const fn new(input: &'a [u8]) -> Self {
        Self {
            remaining: input,
            failed: false,
        }
    }
    /// Unconsumed bytes, including a malformed or truncated frame after failure.
    #[must_use]
    pub const fn remaining(&self) -> &'a [u8] {
        self.remaining
    }
}
impl<'a> Iterator for Frames<'a> {
    type Item = Result<Frame<'a>, Error>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.remaining.is_empty() {
            return None;
        }
        match Frame::decode_prefix(self.remaining) {
            Ok((frame, remaining)) => {
                self.remaining = remaining;
                Some(Ok(frame))
            }
            Err(error) => {
                self.failed = true;
                Some(Err(error))
            }
        }
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.failed {
            (0, Some(0))
        } else {
            (0, Some(self.remaining.len() / HEADER_LEN + 1))
        }
    }
}
impl core::iter::FusedIterator for Frames<'_> {}

/// Official signed-region prefix: size BE32 includes this eight-byte prefix, purpose BE32.
/// Its presence is not proof that the signature or the purpose is authorized.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignaturePurpose {
    size: u32,
    purpose: u32,
}
impl SignaturePurpose {
    /// Construct a purpose prefix for the specified signed body length.
    pub fn new(purpose: u32, signed_body_len: usize) -> Result<Self, Error> {
        let size = SIGNATURE_PURPOSE_LEN
            .checked_add(signed_body_len)
            .ok_or(Error::Overflow)?;
        Ok(Self {
            size: u32::try_from(size).map_err(|_| Error::TooLarge)?,
            purpose,
        })
    }
    /// Decode exactly the eight-byte header; `validate_signed_size` checks its enclosing bytes.
    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        if input.len() < SIGNATURE_PURPOSE_LEN {
            return Err(Error::Truncated);
        }
        if input.len() != SIGNATURE_PURPOSE_LEN {
            return Err(Error::InvalidInput);
        }
        let size = u32::from_be_bytes(input[..4].try_into().map_err(|_| Error::Truncated)?);
        if size < SIGNATURE_PURPOSE_LEN as u32 {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            size,
            purpose: u32::from_be_bytes(input[4..].try_into().map_err(|_| Error::Truncated)?),
        })
    }
    /// Encode the header. Capacity rejection leaves output unchanged.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let destination = output
            .get_mut(..SIGNATURE_PURPOSE_LEN)
            .ok_or(Error::Capacity)?;
        destination[..4].copy_from_slice(&self.size.to_be_bytes());
        destination[4..].copy_from_slice(&self.purpose.to_be_bytes());
        Ok(SIGNATURE_PURPOSE_LEN)
    }
    /// Require exactly the signed-region length advertised by this purpose header.
    pub fn validate_signed_size(self, signed_region_len: usize) -> Result<(), Error> {
        if usize::try_from(self.size).map_err(|_| Error::TooLarge)? != signed_region_len {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
    /// Number of signed bytes including this header.
    #[must_use]
    pub const fn size(self) -> u32 {
        self.size
    }
    /// Uninterpreted official purpose assignment.
    #[must_use]
    pub const fn purpose(self) -> u32 {
        self.purpose
    }
}

// Keep the wire-width assertion independent from host word size.
const _: () = assert!(MAX_MESSAGE_SIZE == 65535);
