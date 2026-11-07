//! Official v0.29.1 REGEX capability announcement/search IPC.
//! Each C search or announcement owns its own connection; there is no request id,
//! cancel frame, submission acknowledgement or search-completion record here.
use super::{Frame, MessageHeader, MessageType, RelativeTime, message_type as mt};
use gnunet_types::Error;

/// ANNOUNCE prefix before its final-NUL-terminated expression, including header.
pub const ANNOUNCE_PREFIX: usize = 16;
/// SEARCH prefix before its final-NUL-terminated string, including header.
pub const SEARCH_PREFIX: usize = 4;
/// RESULT prefix before GET-path then PUT-path identities, including header.
pub const RESULT_PREFIX: usize = 40;

/// Borrowed C-string wire payload without its required final terminating NUL.
/// Public construction is canonical. SEARCH decoding retains bytes after an early
/// NUL because its official handler checks only the final NUL and uses C strlen
/// semantics. ANNOUNCE instead rejects an early NUL, as its official MQ macro does.
/// Retained suffix bytes are never silently reinterpreted as part of the search.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StringBytes<'a>(&'a [u8]);
impl<'a> StringBytes<'a> {
    /// Borrow one canonical string. Empty strings are representable; REGEX syntax
    /// and whether a service accepts an expression are separate from this codec.
    pub fn new(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.contains(&0) {
            return Err(Error::InvalidInput);
        }
        Ok(Self(bytes))
    }
    fn from_wire(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.last() != Some(&0) {
            return Err(Error::Malformed);
        }
        Ok(Self(&bytes[..bytes.len() - 1]))
    }
    /// Actual bytes interpreted by the official C-string consumer, without NUL.
    #[must_use]
    pub fn bytes(self) -> &'a [u8] {
        &self.0[..self.0.iter().position(|b| *b == 0).unwrap_or(self.0.len())]
    }
    /// All original payload bytes before the final wire NUL, including a decoded
    /// noncanonical early NUL and its original suffix. Encoding preserves them.
    #[must_use]
    pub const fn wire_bytes(self) -> &'a [u8] {
        self.0
    }
    /// Whether a normal public C API producer can emit this exact string body.
    #[must_use]
    pub fn is_canonical(self) -> bool {
        !self.0.contains(&0)
    }
}

/// One original REGEX service request. Normal announcement producers set reserved
/// to zero; decoding retains the field ignored by the pinned official handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Request<'a> {
    /// Announce one expression until this original MQ is physically disconnected.
    Announce {
        /// Official maximum characters compressed per automaton edge.
        compression: u16,
        /// Original reserved field, zero in official API output.
        reserved: u16,
        /// Reannouncement interval in official microseconds, including FOREVER.
        refresh_delay: RelativeTime,
        /// Original expression interpreted as a C string.
        regex: StringBytes<'a>,
    },
    /// Search indefinitely until this original MQ is physically disconnected.
    Search {
        /// Original search string, without a synthetic protocol/version suffix.
        string: StringBytes<'a>,
    },
}
impl<'a> Request<'a> {
    /// Decode exactly one request; a missing final NUL and truncated fields fail.
    /// No Rust UTF-8 or regular-expression grammar is imposed on C byte strings.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let frame = Frame::decode(input)?;
        match frame.header().message_type() {
            mt::REGEX_ANNOUNCE => {
                let fixed = input.get(..ANNOUNCE_PREFIX).ok_or(Error::Truncated)?;
                let regex = StringBytes::from_wire(&input[ANNOUNCE_PREFIX..])?;
                if !regex.is_canonical() {
                    return Err(Error::Malformed);
                }
                Ok(Self::Announce {
                    compression: u16::from_be_bytes([fixed[4], fixed[5]]),
                    reserved: u16::from_be_bytes([fixed[6], fixed[7]]),
                    refresh_delay: RelativeTime::decode(&fixed[8..16])?,
                    regex,
                })
            }
            mt::REGEX_SEARCH => Ok(Self::Search {
                string: StringBytes::from_wire(&input[SEARCH_PREFIX..])?,
            }),
            _ => Err(Error::Unsupported),
        }
    }
    /// Actual official message number, without performing service submission.
    #[must_use]
    pub const fn message_type(self) -> MessageType {
        match self {
            Self::Announce { .. } => mt::REGEX_ANNOUNCE,
            Self::Search { .. } => mt::REGEX_SEARCH,
        }
    }
    fn body(self) -> (usize, StringBytes<'a>) {
        match self {
            Self::Announce { regex, .. } => (ANNOUNCE_PREFIX, regex),
            Self::Search { string } => (SEARCH_PREFIX, string),
        }
    }
    /// Complete frame size, including the final NUL and official BE16 header.
    pub fn encoded_len(self) -> Result<usize, Error> {
        if matches!(self, Self::Announce { regex, .. } if !regex.is_canonical()) {
            return Err(Error::InvalidInput);
        }
        let (prefix, string) = self.body();
        let size = prefix
            .checked_add(string.wire_bytes().len())
            .and_then(|n| n.checked_add(1))
            .ok_or(Error::Overflow)?;
        MessageHeader::from_total_size(self.message_type(), size)?;
        Ok(size)
    }
    /// Encode the original request. Capacity or size failure leaves output intact.
    /// A whole local write alone is neither a REGEX acknowledgement nor a result.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let size = self.encoded_len()?;
        if output.len() < size {
            return Err(Error::Capacity);
        }
        MessageHeader::from_total_size(self.message_type(), size)?.encode(output)?;
        if let Self::Announce {
            compression,
            reserved,
            refresh_delay,
            ..
        } = self
        {
            output[4..6].copy_from_slice(&compression.to_be_bytes());
            output[6..8].copy_from_slice(&reserved.to_be_bytes());
            output[8..16].copy_from_slice(&refresh_delay.to_be_bytes());
        }
        let (prefix, string) = self.body();
        output[prefix..size - 1].copy_from_slice(string.wire_bytes());
        output[size - 1] = 0;
        Ok(size)
    }
}

/// One service result. Paths are only predecessor peer identities, not complete
/// DHT path elements or signatures. This codec authenticates no match or peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SearchResult<'a> {
    /// Peer the source REGEX service reported as providing the matching expression.
    pub peer: [u8; 32],
    /// GET path in original wire order, borrowed without allocation or alignment.
    pub get_path: &'a [[u8; 32]],
    /// PUT path in original wire order, borrowed without allocation or alignment.
    pub put_path: &'a [[u8; 32]],
}
impl<'a> SearchResult<'a> {
    /// Decode exactly one result and validate both path counts against every byte.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let frame = Frame::decode(input)?;
        if frame.header().message_type() != mt::REGEX_RESULT {
            return Err(Error::Unsupported);
        }
        let fixed = input.get(..RESULT_PREFIX).ok_or(Error::Truncated)?;
        let get = usize::from(u16::from_be_bytes([fixed[4], fixed[5]]));
        let put = usize::from(u16::from_be_bytes([fixed[6], fixed[7]]));
        let (peers, remainder) = input[RESULT_PREFIX..].as_chunks::<32>();
        if !remainder.is_empty() || get.checked_add(put) != Some(peers.len()) {
            return Err(Error::Malformed);
        }
        let (get_path, put_path) = peers.split_at(get);
        Ok(Self {
            peer: fixed[8..40].try_into().map_err(|_| Error::Truncated)?,
            get_path,
            put_path,
        })
    }
    /// Complete bounded frame size, including the peer and both original paths.
    pub fn encoded_len(self) -> Result<usize, Error> {
        u16::try_from(self.get_path.len()).map_err(|_| Error::TooLarge)?;
        u16::try_from(self.put_path.len()).map_err(|_| Error::TooLarge)?;
        let size = self
            .get_path
            .len()
            .checked_add(self.put_path.len())
            .and_then(|n| n.checked_mul(32))
            .and_then(|n| n.checked_add(RESULT_PREFIX))
            .ok_or(Error::Overflow)?;
        MessageHeader::from_total_size(mt::REGEX_RESULT, size)?;
        Ok(size)
    }
    /// Encode in official GET-then-PUT path order. Capacity failure writes nothing.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let size = self.encoded_len()?;
        if output.len() < size {
            return Err(Error::Capacity);
        }
        MessageHeader::from_total_size(mt::REGEX_RESULT, size)?.encode(output)?;
        output[4..6].copy_from_slice(&(self.get_path.len() as u16).to_be_bytes());
        output[6..8].copy_from_slice(&(self.put_path.len() as u16).to_be_bytes());
        output[8..40].copy_from_slice(&self.peer);
        for (slot, peer) in output[RESULT_PREFIX..size]
            .as_chunks_mut::<32>()
            .0
            .iter_mut()
            .zip(self.get_path.iter().chain(self.put_path))
        {
            slot.copy_from_slice(peer);
        }
        Ok(size)
    }
}
