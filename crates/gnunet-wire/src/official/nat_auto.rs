//! Active NAT-auto configuration IPC. The payload is the actual GNUnet
//! configuration serialization, without invented compression/envelopes.
use super::{Frame, MessageHeader, message_type as mt};
use gnunet_types::Error;
/// Actual GNUNET_NAT_StatusCode value, including unknown future/raw values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Status(pub i32);
impl Status {
    /// GNUNET_OK=1, not a Unix process exit status.
    pub const SUCCESS: Self = Self(1);
    /// IPC disconnected or could not be established.
    pub const IPC_FAILURE: Self = Self(2);
    /// Could not create/bind/use the test network socket.
    pub const INTERNAL_NETWORK_ERROR: Self = Self(3);
    /// Original operation timed out.
    pub const TIMEOUT: Self = Self(4);
    /// No online interface.
    pub const NOT_ONLINE: Self = Self(5);
    /// Official external upnpc utility unavailable.
    pub const UPNPC_NOT_FOUND: Self = Self(6);
    /// UPnP operation failed.
    pub const UPNPC_FAILED: Self = Self(7);
    /// UPnP operation timed out.
    pub const UPNPC_TIMEOUT: Self = Self(8);
    /// UPnP port mapping failed.
    pub const UPNPC_PORTMAP_FAILED: Self = Self(9);
    /// External-address utility unavailable.
    pub const EXTERNAL_IP_UTILITY_NOT_FOUND: Self = Self(10);
    /// External-address utility failed.
    pub const EXTERNAL_IP_UTILITY_FAILED: Self = Self(11);
    /// External-address utility output malformed.
    pub const EXTERNAL_IP_UTILITY_OUTPUT_INVALID: Self = Self(12);
    /// External-address utility returned invalid address.
    pub const EXTERNAL_IP_UTILITY_ADDRESS_INVALID: Self = Self(13);
    /// No usable interface/address combination.
    pub const NO_VALID_IF_IP_COMBO: Self = Self(14);
    /// Reversal server helper unavailable.
    pub const HELPER_NAT_SERVER_NOT_FOUND: Self = Self(15);
    /// Could not start external reachability test.
    pub const NAT_TEST_START_FAILED: Self = Self(16);
    /// Original external reachability test timed out.
    pub const NAT_TEST_TIMEOUT: Self = Self(17);
    /// NAT registration could not be admitted.
    pub const NAT_REGISTER_FAILED: Self = Self(18);
    /// Reversal client helper unavailable.
    pub const HELPER_NAT_CLIENT_NOT_FOUND: Self = Self(19);
}
/// Actual GNUNET_NAT_Type, retaining raw0 returned by this pin's active daemon.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NatType(pub i32);
impl NatType {
    /// Direct external connectivity established.
    pub const NO_NAT: Self = Self(1);
    /// NAT detected without successful traversal.
    pub const UNREACHABLE_NAT: Self = Self(2);
    /// Successful STUN/hole-punch traversal.
    pub const STUN_PUNCHED_NAT: Self = Self(3);
    /// Successful UPnP traversal.
    pub const UPNP_NAT: Self = Self(4);
    /// Classification unavailable.
    pub const UNKNOWN: Self = Self(5);
}
/// Original serialized configuration proposal.
#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    /// GNUNET_CONFIGURATION_serialize output.
    pub configuration: &'a [u8],
}
impl<'a> Request<'a> {
    /// Decode one exact request frame.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let f = Frame::decode(input)?;
        if f.header().message_type() != mt::NAT_AUTO_REQUEST_CFG {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            configuration: &input[4..],
        })
    }
    /// Checked full size.
    pub fn encoded_len(self) -> Result<usize, Error> {
        let n = 4usize
            .checked_add(self.configuration.len())
            .ok_or(Error::Overflow)?;
        MessageHeader::from_total_size(mt::NAT_AUTO_REQUEST_CFG, n)?;
        Ok(n)
    }
    /// Encode the actual serialization unchanged.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len()?;
        if out.len() < n {
            return Err(Error::Capacity);
        }
        MessageHeader::from_total_size(mt::NAT_AUTO_REQUEST_CFG, n)?.encode(out)?;
        out[4..n].copy_from_slice(self.configuration);
        Ok(n)
    }
}
/// Result reflects actual observed status/type and proposed diff, not a receipt
/// that system configuration or port mappings have been installed.
#[derive(Clone, Copy, Debug)]
pub struct Response<'a> {
    /// Original status code.
    pub status: Status,
    /// Original reported NAT type.
    pub nat_type: NatType,
    /// Actual serialized configuration diff.
    pub configuration_diff: &'a [u8],
}
impl<'a> Response<'a> {
    /// Decode one exact result, preserving all raw signed words.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let f = Frame::decode(input)?;
        if f.header().message_type() != mt::NAT_AUTO_CFG_RESULT {
            return Err(Error::Unsupported);
        }
        let b = input.get(..12).ok_or(Error::Truncated)?;
        Ok(Self {
            status: Status(i32::from_be_bytes([b[4], b[5], b[6], b[7]])),
            nat_type: NatType(i32::from_be_bytes([b[8], b[9], b[10], b[11]])),
            configuration_diff: &input[12..],
        })
    }
    /// Checked full size.
    pub fn encoded_len(self) -> Result<usize, Error> {
        let n = 12usize
            .checked_add(self.configuration_diff.len())
            .ok_or(Error::Overflow)?;
        MessageHeader::from_total_size(mt::NAT_AUTO_CFG_RESULT, n)?;
        Ok(n)
    }
    /// Encode actual codes and original serialization.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len()?;
        if out.len() < n {
            return Err(Error::Capacity);
        }
        MessageHeader::from_total_size(mt::NAT_AUTO_CFG_RESULT, n)?.encode(out)?;
        out[4..8].copy_from_slice(&self.status.0.to_be_bytes());
        out[8..12].copy_from_slice(&self.nat_type.0.to_be_bytes());
        out[12..n].copy_from_slice(self.configuration_diff);
        Ok(n)
    }
}
