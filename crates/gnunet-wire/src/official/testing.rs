//! Active TESTING command-helper messages over the original helper pipes.
use super::{Frame, HEADER_LEN, MessageHeader, message_type as mt};
use core::ffi::CStr;
use gnunet_types::Error;

/// The first 32 bytes of the SHA-512 hash of the barrier name, without its NUL.
pub type BarrierKey = [u8; 32];

const COUNT_LEN: usize = size_of::<u32>();

/// Borrowed initialization inputs, checked to fit one GNUnet message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Init<'a> {
    barriers: &'a [BarrierKey],
    topology: &'a CStr,
    header: MessageHeader,
}

impl<'a> Init<'a> {
    /// Bind the original barrier hashes and NUL-terminated topology text.
    pub fn new(barriers: &'a [BarrierKey], topology: &'a CStr) -> Result<Self, Error> {
        let payload_len = core::mem::size_of_val(barriers)
            .checked_add(COUNT_LEN)
            .and_then(|size| size.checked_add(topology.to_bytes_with_nul().len()))
            .ok_or(Error::Overflow)?;
        let header = MessageHeader::new(mt::CMDS_HELPER_INIT, payload_len)?;
        Ok(Self {
            barriers,
            topology,
            header,
        })
    }

    /// Barrier hashes in their original order and byte representation.
    pub const fn barriers(self) -> &'a [BarrierKey] {
        self.barriers
    }

    /// The complete original topology text, without normalization.
    pub const fn topology(self) -> &'a CStr {
        self.topology
    }

    fn decode(frame: Frame<'a>) -> Result<Self, Error> {
        let payload = frame.payload();
        let (count, rest) = payload
            .split_first_chunk::<COUNT_LEN>()
            .ok_or(Error::Truncated)?;
        let barrier_bytes = usize::try_from(u32::from_be_bytes(*count))
            .ok()
            .and_then(|count| count.checked_mul(size_of::<BarrierKey>()))
            .ok_or(Error::Malformed)?;
        let (raw, topology) = rest
            .split_at_checked(barrier_bytes)
            .ok_or(Error::Malformed)?;
        let (barriers, _) = raw.as_chunks::<{ size_of::<BarrierKey>() }>();
        let topology = CStr::from_bytes_with_nul(topology).map_err(|_| Error::Malformed)?;
        Ok(Self {
            barriers,
            topology,
            header: frame.header(),
        })
    }

    fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let size = self.header.size();
        let out = output.get_mut(..size).ok_or(Error::Capacity)?;
        let count = u32::try_from(self.barriers.len()).map_err(|_| Error::TooLarge)?;
        self.header.encode(out)?;
        let (count_out, rest) = out[HEADER_LEN..].split_at_mut(COUNT_LEN);
        count_out.copy_from_slice(&count.to_be_bytes());
        let raw = self.barriers.as_flattened();
        let (barrier_out, topology_out) = rest.split_at_mut(raw.len());
        barrier_out.copy_from_slice(raw);
        topology_out.copy_from_slice(self.topology.to_bytes_with_nul());
        Ok(size)
    }
}

/// Messages sent by the interpreter to an enrolled command helper.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToHelper<'a> {
    /// Establish the topology and inherited barriers (1700).
    Init(Init<'a>),
    /// Release one inherited barrier (1709).
    BarrierCrossable(BarrierKey),
}

impl<'a> ToHelper<'a> {
    /// Decode exactly one complete parent-to-helper message.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let frame = Frame::decode(input)?;
        match frame.header().message_type() {
            mt::CMDS_HELPER_INIT => Ok(Self::Init(Init::decode(frame)?)),
            mt::CMDS_HELPER_BARRIER_CROSSABLE => Ok(Self::BarrierCrossable(fixed_payload(frame)?)),
            _ => Err(Error::Unsupported),
        }
    }

    /// Complete original wire length.
    pub const fn encoded_len(self) -> usize {
        match self {
            Self::Init(init) => init.header.size(),
            Self::BarrierCrossable(_) => HEADER_LEN + size_of::<BarrierKey>(),
        }
    }

    /// Encode one message into caller-owned storage.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        match self {
            Self::Init(init) => init.encode(output),
            Self::BarrierCrossable(key) => {
                Frame::new(mt::CMDS_HELPER_BARRIER_CROSSABLE, &key)?.encode(output)
            }
        }
    }
}

/// Messages sent by a command helper to its interpreter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FromHelper {
    /// Finish with the original GNUnet result code (1706). Success is `1`.
    Finished(i32),
    /// Report one reach of an inherited barrier (1707).
    BarrierReached(BarrierKey),
}

impl FromHelper {
    /// Decode exactly one complete helper-to-parent message.
    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        let frame = Frame::decode(input)?;
        match frame.header().message_type() {
            mt::CMDS_HELPER_LOCAL_FINISHED => {
                Ok(Self::Finished(i32::from_be_bytes(fixed_payload(frame)?)))
            }
            mt::CMDS_HELPER_BARRIER_REACHED => Ok(Self::BarrierReached(fixed_payload(frame)?)),
            _ => Err(Error::Unsupported),
        }
    }

    /// Encode one message into caller-owned storage.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        match self {
            Self::Finished(result) => {
                Frame::new(mt::CMDS_HELPER_LOCAL_FINISHED, &result.to_be_bytes())?.encode(output)
            }
            Self::BarrierReached(key) => {
                Frame::new(mt::CMDS_HELPER_BARRIER_REACHED, &key)?.encode(output)
            }
        }
    }
}

fn fixed_payload<const N: usize>(frame: Frame<'_>) -> Result<[u8; N], Error> {
    frame.payload().try_into().map_err(|_| Error::Malformed)
}

#[cfg(test)]
mod tests;
