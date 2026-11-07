use crate::{ClientId, PERSIST_BIT, SET_PERSISTENT, Selector, Set, Statistic};
use gnunet_types::Error;
use gnunet_wire::official::{Frame, MessageHeader, message_type};

/// A checked, complete official service request, borrowing the input names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Request<'a> {
    /// Absolute or relative update.
    Set(Set<'a>),
    /// Enumeration with empty-string wildcards.
    Get(Selector<'a>),
    /// Exact-name watch; empty names are literal here.
    Watch(Selector<'a>),
    /// Processing barrier acknowledged with DISCONNECT_CONFIRM.
    ///
    /// The upstream handler only acknowledges this message. Actual connection
    /// cleanup, and persistence on service shutdown, are separate operations.
    Disconnect,
}

impl<'a> Request<'a> {
    /// Validate framing and exactly two NUL-terminated names.
    ///
    /// Unknown SET flags are retained, as in the upstream C service.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let frame = Frame::decode(input)?;
        let body = frame.payload();
        match frame.header().message_type() {
            message_type::STATISTICS_SET => {
                let fixed = body.get(..12).ok_or(Error::Truncated)?;
                Ok(Self::Set(Set {
                    selector: read_names(&body[12..])?,
                    flags: u32::from_be_bytes(fixed[..4].try_into().map_err(|_| Error::Truncated)?),
                    value: u64::from_be_bytes(fixed[4..].try_into().map_err(|_| Error::Truncated)?),
                }))
            }
            message_type::STATISTICS_GET => Ok(Self::Get(read_names(body)?)),
            message_type::STATISTICS_WATCH => Ok(Self::Watch(read_names(body)?)),
            message_type::STATISTICS_DISCONNECT if body.is_empty() => Ok(Self::Disconnect),
            message_type::STATISTICS_DISCONNECT => Err(Error::InvalidInput),
            _ => Err(Error::Unsupported),
        }
    }
}

fn read_names(bytes: &[u8]) -> Result<Selector<'_>, Error> {
    let first = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(Error::InvalidInput)?;
    let rest = &bytes[first + 1..];
    let second = rest
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(Error::InvalidInput)?;
    if second + 1 != rest.len() {
        return Err(Error::InvalidInput);
    }
    Ok(Selector {
        subsystem: &bytes[..first],
        name: &rest[..second],
    })
}

pub(crate) fn names_len(selector: Selector<'_>) -> Result<usize, Error> {
    let len = selector
        .subsystem
        .len()
        .checked_add(selector.name.len())
        .and_then(|len| len.checked_add(2))
        .ok_or(Error::Overflow)?;
    // Check the smallest official frame before scanning caller-supplied bytes.
    MessageHeader::new(message_type::STATISTICS_GET, len)?;
    if selector.subsystem.contains(&0) || selector.name.contains(&0) {
        return Err(Error::InvalidInput);
    }
    Ok(len)
}

/// One complete GET reply. END is emitted once even for an empty result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reply<'a> {
    /// Official VALUE, including the persistence bit in its UID.
    Value(Statistic<'a>),
    /// Official header-only END.
    End,
}

impl Reply<'_> {
    /// Encode one official response; rejection preserves the destination.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        match self {
            Self::End => Frame::new(message_type::STATISTICS_END, &[])?.encode(output),
            Self::Value(value) => {
                let name_bytes = names_len(value.selector)?;
                let header = MessageHeader::new(message_type::STATISTICS_VALUE, 12 + name_bytes)?;
                if output.len() < header.size() {
                    return Err(Error::Capacity);
                }
                header.encode(output)?;
                output[4..8].copy_from_slice(&value.raw_uid.to_be_bytes());
                output[8..16].copy_from_slice(&value.value.to_be_bytes());
                let first = 16 + value.selector.subsystem.len();
                output[16..first].copy_from_slice(value.selector.subsystem);
                output[first] = 0;
                output[first + 1..header.size() - 1].copy_from_slice(value.selector.name);
                output[header.size() - 1] = 0;
                Ok(header.size())
            }
        }
    }
}

/// An owned, queued WATCH_VALUE effect, addressed to a live connection generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Notification {
    /// Connection that owns this watch. This is never a wire peer identity.
    pub client: ClientId,
    /// Connection-local watch number, starting at zero.
    pub wid: u32,
    /// Current unsigned value.
    pub value: u64,
    /// Persistence marker when this notification was generated.
    pub persistent: bool,
}

impl Notification {
    /// Encode the official 24-byte WATCH_VALUE; the reserved field is zero.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let header = MessageHeader::new(message_type::STATISTICS_WATCH_VALUE, 20)?;
        if output.len() < header.size() {
            return Err(Error::Capacity);
        }
        header.encode(output)?;
        output[4..8]
            .copy_from_slice(&(if self.persistent { SET_PERSISTENT } else { 0 }).to_be_bytes());
        output[8..12].copy_from_slice(&self.wid.to_be_bytes());
        output[12..16].fill(0);
        output[16..24].copy_from_slice(&self.value.to_be_bytes());
        Ok(24)
    }
}

/// Encode the upstream processing-barrier acknowledgement.
///
/// This confirms prior request processing, not a durable filesystem commit.
pub fn encode_disconnect_confirmation(output: &mut [u8]) -> Result<usize, Error> {
    Frame::new(message_type::STATISTICS_DISCONNECT_CONFIRM, &[])?.encode(output)
}

pub(crate) const fn raw_uid(uid: u32, persistent: bool) -> u32 {
    uid | if persistent { PERSIST_BIT } else { 0 }
}
