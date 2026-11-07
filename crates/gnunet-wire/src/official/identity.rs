//! Official v0.29.1 IDENTITY IPC. There is no request identifier, cancel record,
//! default-ego operation, or create acknowledgement distinct from RESULT_CODE.
//! Private-key fields are sensitive even though the local protocol carries them.
use super::{Frame, MessageHeader, MessageType, message_type as mt};
use core::fmt;
use gnunet_types::Error;

/// Serialized blindable private/public key: BE32 type followed by 32 key bytes.
pub const KEY_LEN: usize = 36;
/// START frame size.
pub const START_LEN: usize = 4;
/// RESULT_CODE frame size.
pub const RESULT_LEN: usize = 8;
/// UPDATE fixed prefix, including the message header.
pub const UPDATE_PREFIX: usize = 12;
/// CREATE fixed prefix, including the message header.
pub const CREATE_PREFIX: usize = 8;
/// RENAME fixed prefix, including the message header.
pub const RENAME_PREFIX: usize = 8;
/// DELETE fixed prefix, including the message header.
pub const DELETE_PREFIX: usize = 8;
/// LOOKUP and LOOKUP_BY_SUFFIX fixed prefix.
pub const LOOKUP_PREFIX: usize = 4;

/// The two private/public key tags accepted by the pinned IDENTITY service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyType {
    /// GNUNET_PUBLIC_KEY_TYPE_ECDSA.
    Ecdsa,
    /// GNUNET_PUBLIC_KEY_TYPE_EDDSA.
    Eddsa,
}
impl KeyType {
    /// Official numeric tag, encoded as BE32 on the wire.
    pub const fn value(self) -> u32 {
        match self {
            Self::Ecdsa => 65536,
            Self::Eddsa => 65556,
        }
    }
    /// Reject an unknown key family rather than guessing its serialized length.
    pub fn from_value(value: u32) -> Result<Self, Error> {
        match value {
            65536 => Ok(Self::Ecdsa),
            65556 => Ok(Self::Eddsa),
            _ => Err(Error::Unsupported),
        }
    }
}

/// A validated borrowed serialized private key. This wrapper owns no memory;
/// the owner must erase the frame/key storage when its lifetime ends.
#[derive(Clone, Copy)]
pub struct SecretKeyView<'a> {
    bytes: &'a [u8; KEY_LEN],
    kind: KeyType,
}
impl<'a> SecretKeyView<'a> {
    /// Check the exact official encoding and supported tag. As in the C service,
    /// this is structural validation, not scalar or public-key validation.
    pub fn new(bytes: &'a [u8]) -> Result<Self, Error> {
        let bytes: &'a [u8; KEY_LEN] = bytes.try_into().map_err(|_| Error::Malformed)?;
        let kind =
            KeyType::from_value(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))?;
        Ok(Self { bytes, kind })
    }
    /// Supported official key family.
    pub const fn key_type(self) -> KeyType {
        self.kind
    }
    /// Explicit sensitive borrow, never an identifier, diagnostic, or log value.
    pub const fn expose_serialized(self) -> &'a [u8; KEY_LEN] {
        self.bytes
    }
}
impl fmt::Debug for SecretKeyView<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKeyView([REDACTED])")
    }
}
fn string(bytes: &[u8]) -> Result<&[u8], Error> {
    if bytes.last() != Some(&0) || bytes[..bytes.len() - 1].contains(&0) {
        return Err(Error::Malformed);
    }
    Ok(&bytes[..bytes.len() - 1])
}
fn string_len(bytes: &[u8]) -> Result<usize, Error> {
    if bytes.contains(&0) {
        return Err(Error::InvalidInput);
    }
    let len = bytes.len().checked_add(1).ok_or(Error::Overflow)?;
    u16::try_from(len).map_err(|_| Error::TooLarge)?;
    Ok(len)
}
fn be16(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}
fn total(kind: MessageType, prefix: usize, a: usize, b: usize) -> Result<usize, Error> {
    let len = prefix
        .checked_add(a)
        .and_then(|n| n.checked_add(b))
        .ok_or(Error::Overflow)?;
    MessageHeader::from_total_size(kind, len)?;
    Ok(len)
}
fn put_string(out: &mut [u8], bytes: &[u8]) {
    out[..bytes.len()].copy_from_slice(bytes);
    out[bytes.len()] = 0;
}

/// One original service request. Names exclude their final wire NUL; no UTF-8
/// or case conversion is imposed by the codec. The service applies that policy.
#[derive(Clone, Copy, Debug)]
pub enum Request<'a> {
    /// Subscribe to current egos, an end marker, and subsequent updates.
    Start,
    /// Import/create a name with its supplied private key.
    Create {
        /// Name without its final NUL.
        name: &'a [u8],
        /// Supplied sensitive serialized private key.
        key: SecretKeyView<'a>,
    },
    /// Rename one ego.
    Rename {
        /// Existing name without NUL.
        old: &'a [u8],
        /// New name without NUL.
        new: &'a [u8],
    },
    /// Delete one ego.
    Delete {
        /// Requested name without its final NUL.
        name: &'a [u8],
    },
    /// One exact lookup; the official service compares names case insensitively.
    Lookup {
        /// Requested name without its final NUL.
        name: &'a [u8],
    },
    /// Longest suffix lookup on a whole-name or dot boundary, case sensitive.
    LookupSuffix {
        /// Requested name without its final NUL.
        name: &'a [u8],
    },
}
impl<'a> Request<'a> {
    /// Decode exactly one frame, checking every length before indexing.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let frame = Frame::decode(input)?;
        let kind = frame.header().message_type();
        match kind {
            mt::IDENTITY_START if input.len() == START_LEN => Ok(Self::Start),
            mt::IDENTITY_CREATE => {
                let p = input.get(..CREATE_PREFIX).ok_or(Error::Truncated)?;
                let name_len = usize::from(be16(p, 4));
                let key_len = usize::from(be16(p, 6));
                if total(kind, CREATE_PREFIX, name_len, key_len)? != input.len() {
                    return Err(Error::Malformed);
                }
                let key = SecretKeyView::new(&input[CREATE_PREFIX..CREATE_PREFIX + key_len])?;
                let name = string(&input[CREATE_PREFIX + key_len..])?;
                Ok(Self::Create { name, key })
            }
            mt::IDENTITY_RENAME => {
                let p = input.get(..RENAME_PREFIX).ok_or(Error::Truncated)?;
                let old_len = usize::from(be16(p, 4));
                let new_len = usize::from(be16(p, 6));
                if total(kind, RENAME_PREFIX, old_len, new_len)? != input.len() {
                    return Err(Error::Malformed);
                }
                let old = string(&input[RENAME_PREFIX..RENAME_PREFIX + old_len])?;
                let new = string(&input[RENAME_PREFIX + old_len..])?;
                Ok(Self::Rename { old, new })
            }
            mt::IDENTITY_DELETE => {
                let p = input.get(..DELETE_PREFIX).ok_or(Error::Truncated)?;
                if total(kind, DELETE_PREFIX, usize::from(be16(p, 4)), 0)? != input.len() {
                    return Err(Error::Malformed);
                }
                Ok(Self::Delete {
                    name: string(&input[DELETE_PREFIX..])?,
                })
            }
            mt::IDENTITY_LOOKUP => Ok(Self::Lookup {
                name: string(&input[LOOKUP_PREFIX..])?,
            }),
            mt::IDENTITY_LOOKUP_BY_SUFFIX => Ok(Self::LookupSuffix {
                name: string(&input[LOOKUP_PREFIX..])?,
            }),
            mt::IDENTITY_START => Err(Error::Malformed),
            _ => Err(Error::Unsupported),
        }
    }
    /// Official message type.
    pub const fn message_type(self) -> MessageType {
        match self {
            Self::Start => mt::IDENTITY_START,
            Self::Create { .. } => mt::IDENTITY_CREATE,
            Self::Rename { .. } => mt::IDENTITY_RENAME,
            Self::Delete { .. } => mt::IDENTITY_DELETE,
            Self::Lookup { .. } => mt::IDENTITY_LOOKUP,
            Self::LookupSuffix { .. } => mt::IDENTITY_LOOKUP_BY_SUFFIX,
        }
    }
    /// Entire frame length; interior NULs and BE16 overflows fail.
    pub fn encoded_len(self) -> Result<usize, Error> {
        let (p, a, b) = match self {
            Self::Start => (START_LEN, 0, 0),
            Self::Create { name, .. } => (CREATE_PREFIX, KEY_LEN, string_len(name)?),
            Self::Rename { old, new } => (RENAME_PREFIX, string_len(old)?, string_len(new)?),
            Self::Delete { name } => (DELETE_PREFIX, string_len(name)?, 0),
            Self::Lookup { name } | Self::LookupSuffix { name } => {
                (LOOKUP_PREFIX, string_len(name)?, 0)
            }
        };
        total(self.message_type(), p, a, b)
    }
    /// Encode after checking all sizes. Failure leaves caller storage unchanged.
    /// Successful local writing does not imply the service committed a mutation.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let len = self.encoded_len()?;
        if output.len() < len {
            return Err(Error::Capacity);
        }
        MessageHeader::from_total_size(self.message_type(), len)?.encode(output)?;
        match self {
            Self::Start => {}
            Self::Create { name, key } => {
                output[4..6].copy_from_slice(&((name.len() + 1) as u16).to_be_bytes());
                output[6..8].copy_from_slice(&(KEY_LEN as u16).to_be_bytes());
                output[8..8 + KEY_LEN].copy_from_slice(key.expose_serialized());
                put_string(&mut output[8 + KEY_LEN..len], name);
            }
            Self::Rename { old, new } => {
                output[4..6].copy_from_slice(&((old.len() + 1) as u16).to_be_bytes());
                output[6..8].copy_from_slice(&((new.len() + 1) as u16).to_be_bytes());
                put_string(&mut output[8..8 + old.len() + 1], old);
                put_string(&mut output[8 + old.len() + 1..len], new);
            }
            Self::Delete { name } => {
                output[4..6].copy_from_slice(&((name.len() + 1) as u16).to_be_bytes());
                output[6..8].fill(0);
                put_string(&mut output[8..len], name);
            }
            Self::Lookup { name } | Self::LookupSuffix { name } => {
                put_string(&mut output[4..len], name)
            }
        }
        Ok(len)
    }
}

/// One service reply/update. A deletion retains the private key and has no name;
/// an empty present name has a one-byte NUL string and is a distinct valid value.
#[derive(Clone, Copy, Debug)]
pub enum Response<'a> {
    /// Actual official result code, including unknown future numeric codes.
    ResultCode {
        /// Actual official service status.
        code: u32,
    },
    /// Current name/key or deletion of this key from the subscribed inventory.
    Update {
        /// Current name, or None for deletion.
        name: Option<&'a [u8]>,
        /// Ego key, retained even on deletion.
        key: SecretKeyView<'a>,
    },
    /// Initial START enumeration complete. A failed lookup instead returns
    /// RESULT_CODE with IDENTITY_NOT_FOUND (200).
    EndOfList,
}
impl<'a> Response<'a> {
    /// Decode one complete reply. Ignored reserved fields are accepted; encoding
    /// always emits the official API's canonical zero values.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let frame = Frame::decode(input)?;
        match frame.header().message_type() {
            mt::IDENTITY_RESULT_CODE if input.len() == RESULT_LEN => Ok(Self::ResultCode {
                code: u32::from_be_bytes([input[4], input[5], input[6], input[7]]),
            }),
            mt::IDENTITY_RESULT_CODE => Err(Error::Malformed),
            mt::IDENTITY_UPDATE => {
                let p = input.get(..UPDATE_PREFIX).ok_or(Error::Truncated)?;
                let n = usize::from(be16(p, 4));
                let end = be16(p, 6);
                let k = usize::from(be16(p, 8));
                if total(mt::IDENTITY_UPDATE, UPDATE_PREFIX, n, k)? != input.len() {
                    return Err(Error::Malformed);
                }
                match end {
                    1 if n == 0 && k == 0 => Ok(Self::EndOfList),
                    0 => {
                        let name = if n == 0 {
                            None
                        } else {
                            Some(string(&input[12..12 + n])?)
                        };
                        let key = SecretKeyView::new(&input[12 + n..])?;
                        Ok(Self::Update { name, key })
                    }
                    _ => Err(Error::Malformed),
                }
            }
            _ => Err(Error::Unsupported),
        }
    }
    /// Complete frame length, including names' final wire NULs.
    pub fn encoded_len(self) -> Result<usize, Error> {
        match self {
            Self::ResultCode { .. } => Ok(RESULT_LEN),
            Self::EndOfList => Ok(UPDATE_PREFIX),
            Self::Update { name, .. } => total(
                mt::IDENTITY_UPDATE,
                UPDATE_PREFIX,
                KEY_LEN,
                match name {
                    Some(n) => string_len(n)?,
                    None => 0,
                },
            ),
        }
    }
    /// Encode into caller-owned sensitive storage. Capacity failure is atomic.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let len = self.encoded_len()?;
        if output.len() < len {
            return Err(Error::Capacity);
        }
        let kind = if matches!(self, Self::ResultCode { .. }) {
            mt::IDENTITY_RESULT_CODE
        } else {
            mt::IDENTITY_UPDATE
        };
        MessageHeader::from_total_size(kind, len)?.encode(output)?;
        match self {
            Self::ResultCode { code } => output[4..8].copy_from_slice(&code.to_be_bytes()),
            Self::EndOfList => {
                output[4..12].fill(0);
                output[6..8].copy_from_slice(&1u16.to_be_bytes());
            }
            Self::Update { name, key } => {
                let n = name.map_or(0, |n| n.len() + 1);
                output[4..6].copy_from_slice(&(n as u16).to_be_bytes());
                output[6..8].fill(0);
                output[8..10].copy_from_slice(&(KEY_LEN as u16).to_be_bytes());
                output[10..12].fill(0);
                if let Some(name) = name {
                    put_string(&mut output[12..12 + n], name);
                }
                output[12 + n..len].copy_from_slice(key.expose_serialized());
            }
        }
        Ok(len)
    }
}
