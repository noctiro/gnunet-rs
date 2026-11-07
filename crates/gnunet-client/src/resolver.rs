//! Official v0.29.1 resolver messages 4/5, without allocation or native FFI.
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use gnunet_types::Error;
use gnunet_wire::official::{Frame, MessageHeader, message_type};

/// Total fixed part of an official resolver request.
pub const REQUEST_LEN: usize = 16;
/// Total fixed part of a response, including the opaque ID; also END size.
pub const RESPONSE_LEN: usize = 8;
/// Largest hostname byte length admitted by the official C forward API.
pub const MAX_HOSTNAME_LEN: usize = 65_518;

/// Host-native local IPC address-family values, encoded in network byte order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FamilyProfile {
    inet: i32,
    inet6: i32,
}
impl FamilyProfile {
    /// Native Linux AF_INET/AF_INET6, not a portable wire standard.
    pub const LINUX: Self = Self { inet: 2, inet6: 10 };
    /// Native Darwin AF_INET/AF_INET6.
    pub const DARWIN: Self = Self { inet: 2, inet6: 30 };
    /// Explicit native profile. AF_UNSPEC is zero in this supported profile.
    pub const fn new(inet: i32, inet6: i32) -> Result<Self, Error> {
        if inet <= 0 || inet6 <= 0 || inet == inet6 {
            Err(Error::InvalidInput)
        } else {
            Ok(Self { inet, inet6 })
        }
    }
    /// Map semantic family to the host's actual local ABI value.
    #[must_use]
    pub const fn encode(self, family: Family) -> i32 {
        match family {
            Family::Any => 0,
            Family::V4 => self.inet,
            Family::V6 => self.inet6,
        }
    }
    /// Validate a family value supplied by a local IPC peer.
    pub const fn decode(self, value: i32) -> Result<Family, Error> {
        if value == 0 {
            Ok(Family::Any)
        } else if value == self.inet {
            Ok(Family::V4)
        } else if value == self.inet6 {
            Ok(Family::V6)
        } else {
            Err(Error::Unsupported)
        }
    }
}
/// Desired IP address family, independent of a native socket ABI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Family {
    /// Either address family.
    Any,
    /// IPv4 only.
    V4,
    /// IPv6 only.
    V6,
}
impl Family {
    /// Family of one raw IP address.
    #[must_use]
    pub const fn of(address: IpAddr) -> Self {
        match address {
            IpAddr::V4(_) => Self::V4,
            IpAddr::V6(_) => Self::V6,
        }
    }
    /// Whether a numeric address matches this requested family.
    #[must_use]
    pub const fn accepts(self, address: IpAddr) -> bool {
        matches!(
            (self, address),
            (Self::Any, _) | (Self::V4, IpAddr::V4(_)) | (Self::V6, IpAddr::V6(_))
        )
    }
}
/// Four unchanged echoed bytes. C sends its native ID without htonl.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WireId(pub [u8; 4]);
impl WireId {
    /// Generate the normal native-endian C counter representation on this host.
    #[must_use]
    pub const fn from_native(value: u32) -> Self {
        Self(value.to_ne_bytes())
    }
}
/// Borrowed request data. Reverse addresses contain no port or sockaddr padding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Query<'a> {
    /// Raw hostname bytes before the final NUL. A decoded C string may have interior NULs.
    Forward {
        /// Requested family.
        family: Family,
        /// Borrowed raw hostname bytes.
        hostname: &'a [u8],
    },
    /// Reverse query for a raw IP address.
    Reverse(IpAddr),
}
/// One complete official request. Decoding retains nonzero reverse directions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Request<'a> {
    id: WireId,
    query: Query<'a>,
    direction: i32,
}
impl<'a> Request<'a> {
    /// Construct an ordinary public forward request. Names cannot contain NUL.
    pub fn forward(id: WireId, family: Family, hostname: &'a [u8]) -> Result<Self, Error> {
        if hostname.contains(&0) {
            return Err(Error::InvalidInput);
        }
        if hostname.len() > MAX_HOSTNAME_LEN {
            return Err(Error::TooLarge);
        }
        Ok(Self {
            id,
            query: Query::Forward { family, hostname },
            direction: 0,
        })
    }
    /// Construct an ordinary public reverse request, whose direction is one.
    #[must_use]
    pub const fn reverse(id: WireId, address: IpAddr) -> Self {
        Self {
            id,
            query: Query::Reverse(address),
            direction: 1,
        }
    }
    /// Decode and borrow exactly one request frame using the explicit native profile.
    pub fn decode(frame: Frame<'a>, profile: FamilyProfile) -> Result<Self, Error> {
        if frame.header().message_type() != message_type::RESOLVER_REQUEST {
            return Err(Error::Unsupported);
        }
        let fixed = frame.payload().get(..12).ok_or(Error::Truncated)?;
        let direction = i32::from_be_bytes(fixed[..4].try_into().map_err(|_| Error::Truncated)?);
        let family = profile.decode(i32::from_be_bytes(
            fixed[4..8].try_into().map_err(|_| Error::Truncated)?,
        ))?;
        let id = WireId(fixed[8..12].try_into().map_err(|_| Error::Truncated)?);
        let bytes = &frame.payload()[12..];
        let query = if direction == 0 {
            if bytes.last() != Some(&0) {
                return Err(Error::Malformed);
            }
            Query::Forward {
                family,
                hostname: &bytes[..bytes.len() - 1],
            }
        } else {
            let address = decode_ip(bytes)?.ok_or(Error::Malformed)?;
            if family == Family::Any || family != Family::of(address) {
                return Err(Error::Malformed);
            }
            Query::Reverse(address)
        };
        Ok(Self {
            id,
            query,
            direction,
        })
    }
    /// Original opaque request identity.
    #[must_use]
    pub const fn id(self) -> WireId {
        self.id
    }
    /// Borrowed/owned semantic payload.
    #[must_use]
    pub const fn query(self) -> Query<'a> {
        self.query
    }
    /// Original direction field, zero forward and nonzero reverse in C.
    #[must_use]
    pub const fn raw_direction(self) -> i32 {
        self.direction
    }
    /// Exact complete frame length, bounded to the BE16 framing maximum.
    pub fn encoded_len(self) -> Result<usize, Error> {
        let payload = match self.query {
            Query::Forward { hostname, .. } => {
                hostname.len().checked_add(1).ok_or(Error::Overflow)?
            }
            Query::Reverse(IpAddr::V4(_)) => 4,
            Query::Reverse(IpAddr::V6(_)) => 16,
        };
        let len = REQUEST_LEN.checked_add(payload).ok_or(Error::Overflow)?;
        if len > u16::MAX as usize {
            Err(Error::TooLarge)
        } else {
            Ok(len)
        }
    }
    /// Encode after complete validation. Rejection leaves all destination bytes unchanged.
    pub fn encode(self, profile: FamilyProfile, output: &mut [u8]) -> Result<usize, Error> {
        let len = self.encoded_len()?;
        if output.len() < len {
            return Err(Error::Capacity);
        }
        let family = match self.query {
            Query::Forward { family, .. } => family,
            Query::Reverse(address) => Family::of(address),
        };
        MessageHeader::from_total_size(message_type::RESOLVER_REQUEST, len)?.encode(output)?;
        output[4..8].copy_from_slice(&self.direction.to_be_bytes());
        output[8..12].copy_from_slice(&profile.encode(family).to_be_bytes());
        output[12..16].copy_from_slice(&self.id.0);
        match self.query {
            Query::Forward { hostname, .. } => {
                output[16..len - 1].copy_from_slice(hostname);
                output[len - 1] = 0;
            }
            Query::Reverse(IpAddr::V4(address)) => {
                output[16..len].copy_from_slice(&address.octets())
            }
            Query::Reverse(IpAddr::V6(address)) => {
                output[16..len].copy_from_slice(&address.octets())
            }
        }
        Ok(len)
    }
}
/// Borrowed raw response; the pending request determines the payload's interpretation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Response<'a> {
    id: WireId,
    bytes: &'a [u8],
}
impl<'a> Response<'a> {
    /// Decode type and fixed header, without guessing forward versus reverse.
    pub fn decode(frame: Frame<'a>) -> Result<Self, Error> {
        if frame.header().message_type() != message_type::RESOLVER_RESPONSE {
            return Err(Error::Unsupported);
        }
        let fixed = frame.payload().get(..4).ok_or(Error::Truncated)?;
        Ok(Self {
            id: WireId(fixed.try_into().map_err(|_| Error::Truncated)?),
            bytes: &frame.payload()[4..],
        })
    }
    /// Exact opaque echoed ID.
    #[must_use]
    pub const fn id(self) -> WireId {
        self.id
    }
    /// Uninterpreted data after the echoed ID.
    #[must_use]
    pub const fn payload(self) -> &'a [u8] {
        self.bytes
    }
    /// Whether this is the exact eight-byte END response.
    #[must_use]
    pub const fn is_end(self) -> bool {
        self.bytes.is_empty()
    }
    /// Interpret forward raw bytes, or None for END. Does not filter the requested AF.
    pub fn address(self) -> Result<Option<IpAddr>, Error> {
        decode_ip(self.bytes)
    }
    /// Interpret reverse C-string bytes, or None for END. Interior NUL terminates
    /// the visible callback name just as in the normal C library.
    pub fn hostname(self) -> Result<Option<&'a [u8]>, Error> {
        if self.is_end() {
            return Ok(None);
        }
        if self.bytes.last() != Some(&0) {
            return Err(Error::Malformed);
        }
        let end = self
            .bytes
            .iter()
            .position(|v| *v == 0)
            .ok_or(Error::Malformed)?;
        Ok(Some(&self.bytes[..end]))
    }
}
/// Typed response constructor for normal service/test callers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reply<'a> {
    /// Final response, containing no payload.
    End,
    /// One forward raw IP address.
    Address(IpAddr),
    /// One reverse hostname, without any NUL byte.
    Hostname(&'a [u8]),
}
/// Encode an official response with no mutation on capacity/validation rejection.
pub fn encode_response(id: WireId, reply: Reply<'_>, output: &mut [u8]) -> Result<usize, Error> {
    let payload = match reply {
        Reply::End => 0,
        Reply::Address(IpAddr::V4(_)) => 4,
        Reply::Address(IpAddr::V6(_)) => 16,
        Reply::Hostname(name) => {
            if name.contains(&0) {
                return Err(Error::InvalidInput);
            }
            name.len().checked_add(1).ok_or(Error::Overflow)?
        }
    };
    let len = RESPONSE_LEN.checked_add(payload).ok_or(Error::Overflow)?;
    let header = MessageHeader::from_total_size(message_type::RESOLVER_RESPONSE, len)?;
    if output.len() < len {
        return Err(Error::Capacity);
    }
    header.encode(output)?;
    output[4..8].copy_from_slice(&id.0);
    match reply {
        Reply::End => {}
        Reply::Address(IpAddr::V4(address)) => output[8..len].copy_from_slice(&address.octets()),
        Reply::Address(IpAddr::V6(address)) => output[8..len].copy_from_slice(&address.octets()),
        Reply::Hostname(name) => {
            output[8..len - 1].copy_from_slice(name);
            output[len - 1] = 0;
        }
    }
    Ok(len)
}
fn decode_ip(bytes: &[u8]) -> Result<Option<IpAddr>, Error> {
    match bytes.len() {
        0 => Ok(None),
        4 => Ok(Some(IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(bytes).map_err(|_| Error::Malformed)?,
        )))),
        16 => Ok(Some(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(bytes).map_err(|_| Error::Malformed)?,
        )))),
        _ => Err(Error::Malformed),
    }
}
