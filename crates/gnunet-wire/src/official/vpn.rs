//! Official v0.29.1 VPN IPC, helper framing and EXIT CADET application messages.
//! AF values are the original C platform constants; request ids are opaque native
//! bytes in the active C producer/echo path, not invented network-order integers.
use super::{Frame, MessageHeader, MessageType, message_type as mt};
use gnunet_types::Error;
/// Internet address family independent of a host's AF_* integer assignments.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Family {
    /// IPv4.
    V4,
    /// IPv6.
    V6,
}
/// Exact native C AF profile used by an IPC/peer endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AfProfile {
    /// AF_INET.
    pub ipv4: u32,
    /// AF_INET6.
    pub ipv6: u32,
}
impl AfProfile {
    /// Linux AF values.
    pub const LINUX: Self = Self { ipv4: 2, ipv6: 10 };
    /// Darwin AF values, including the pinned macOS C producer.
    pub const DARWIN: Self = Self { ipv4: 2, ipv6: 30 };
    /// Current Linux/Darwin native profile. Other platforms should supply their
    /// actual constants explicitly, rather than silently guessing peer fields.
    #[must_use]
    pub const fn native() -> Self {
        if cfg!(target_vendor = "apple") {
            Self::DARWIN
        } else {
            Self::LINUX
        }
    }
    /// Check an actual nonzero distinct native AF profile before using it.
    pub fn validate(self) -> Result<(), Error> {
        if self.ipv4 == 0 || self.ipv6 == 0 || self.ipv4 == self.ipv6 {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
    /// Decode a supported raw AF value.
    pub fn family(self, value: u32) -> Result<Family, Error> {
        self.validate()?;
        if value == self.ipv4 {
            Ok(Family::V4)
        } else if value == self.ipv6 {
            Ok(Family::V6)
        } else {
            Err(Error::Unsupported)
        }
    }
    /// Encode the actual configured AF value.
    #[must_use]
    pub const fn value(self, family: Family) -> u32 {
        match family {
            Family::V4 => self.ipv4,
            Family::V6 => self.ipv6,
        }
    }
}
/// Complete IP address without a synthetic wire tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Address {
    /// Four network-order address bytes.
    V4([u8; 4]),
    /// Sixteen network-order address bytes.
    V6([u8; 16]),
}
impl Address {
    /// Address family.
    #[must_use]
    pub const fn family(self) -> Family {
        match self {
            Self::V4(_) => Family::V4,
            Self::V6(_) => Family::V6,
        }
    }
    /// Exact address byte count.
    #[must_use]
    pub const fn len(self) -> usize {
        match self {
            Self::V4(_) => 4,
            Self::V6(_) => 16,
        }
    }
    /// Addresses are never empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        false
    }
    /// Borrow original network-order address bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::V4(v) => v,
            Self::V6(v) => v,
        }
    }
}
/// Actual client requests. There is no VPN CANCEL IPC assignment; the public
/// cancel operation only suppresses its local callback and may leave a lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Request {
    /// Redirect a leased IP through a discovered Internet exit.
    Internet {
        /// Raw reserved field.
        reserved: u32,
        /// Absolute microsecond deadline, network order on wire.
        expires: u64,
        /// Desired actual AF value, zero means AF_UNSPEC.
        result_af: u32,
        /// Actual remote Internet address.
        destination: Address,
        /// Opaque original C-native id bytes, echoed unchanged.
        request_id: [u8; 8],
    },
    /// Redirect to the named peer/service; protocol is raw C IPPROTO_*.
    Service {
        /// Raw reserved field.
        reserved: u32,
        /// Absolute microsecond deadline.
        expires: u64,
        /// IPPROTO_TCP(6) or UDP(17), not an authentication claim.
        protocol: u32,
        /// Desired actual AF value or zero.
        result_af: u32,
        /// Actual expected peer.
        peer: [u8; 32],
        /// Shared service descriptor, not endpoint authentication.
        service: [u8; 64],
        /// Original opaque id bytes.
        request_id: [u8; 8],
    },
}
/// One actual allocation result. None uses AF_UNSPEC and does not claim a route,
/// a connected exit, a TUN write, or successful remote application delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Response {
    /// Original opaque request id echoed byte-for-byte.
    pub request_id: [u8; 8],
    /// Allocated address, absent on actual allocation failure.
    pub address: Option<Address>,
}
/// Original helper message185; actual native raw TUN owners may use raw IP bytes
/// directly instead of creating a helper process or private wrapper protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Helper<'a> {
    /// Original unused flags, retained in network order.
    pub flags: u16,
    /// ETH_P_IP(0x0800) or ETH_P_IPV6(0x86dd), not AF_*.
    pub protocol: u16,
    /// Entire raw IP packet.
    pub packet: &'a [u8],
}
/// Exact active EXIT/VPN application message set. TCP skeletons are exactly20
/// bytes; their tail includes original TCP options followed by payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerMessage<'a> {
    /// Original TCP service connection start.
    TcpService {
        /// Reserved NBO word.
        reserved: u32,
        /// Raw complete fixed TCP header.
        header: [u8; 20],
        /// Options and payload.
        tail: &'a [u8],
    },
    /// Original TCP Internet connection start.
    TcpInternet {
        /// Actual Internet destination.
        destination: Address,
        /// Raw fixed TCP header.
        header: [u8; 20],
        /// Options and payload.
        tail: &'a [u8],
    },
    /// Subsequent TCP traffic, exact official directional message numbers.
    Tcp {
        /// True for VPN→EXIT(197), false for EXIT→VPN(198).
        to_exit: bool,
        /// Raw reserved NBO word.
        reserved: u32,
        /// Fixed TCP header.
        header: [u8; 20],
        /// Options and payload.
        tail: &'a [u8],
    },
    /// UDP to a named peer service.
    UdpService {
        /// Source port, zero requests random NAT choice.
        source: u16,
        /// Desired destination port.
        destination: u16,
        /// Opaque UDP payload, without its eight-byte UDP header.
        payload: &'a [u8],
    },
    /// UDP to the Internet.
    UdpInternet {
        /// Actual destination address.
        address: Address,
        /// Source port, zero requests random NAT choice.
        source: u16,
        /// Destination port.
        destination: u16,
        /// Opaque UDP payload.
        payload: &'a [u8],
    },
    /// Reply from either kind of exit. Zero ports preserve original VPN tuple.
    UdpReply {
        /// Source port or zero.
        source: u16,
        /// Destination port or zero.
        destination: u16,
        /// Opaque payload.
        payload: &'a [u8],
    },
    /// ICMP to a named peer service.
    IcmpService {
        /// Actual original AF describing ICMP version.
        af: u32,
        /// Fixed ICMP header.
        header: [u8; 8],
        /// Echo payload; supported errors omit their quoted IP bytes.
        payload: &'a [u8],
    },
    /// ICMP to the Internet after any source-family translation.
    IcmpInternet {
        /// Destination and its actual ICMP family.
        destination: Address,
        /// Fixed ICMP header.
        header: [u8; 8],
        /// Original echo payload or omitted error quote.
        payload: &'a [u8],
    },
    /// ICMP reply/error to the VPN.
    IcmpReply {
        /// Actual AF describing the ICMP header version.
        af: u32,
        /// Fixed ICMP header.
        header: [u8; 8],
        /// Echo payload or omitted error quote.
        payload: &'a [u8],
    },
    /// Independent official DNS gateway messages, not used as VPN-IP flow IDs.
    Dns {
        /// True for EXIT→requester(194), false for requester→EXIT(193).
        reply: bool,
        /// Complete raw DNS packet, including its twelve-byte DNS header.
        packet: &'a [u8],
    },
}
fn array<const N: usize>(b: &[u8], at: usize) -> Result<[u8; N], Error> {
    b.get(at..at.checked_add(N).ok_or(Error::Overflow)?)
        .ok_or(Error::Truncated)?
        .try_into()
        .map_err(|_| Error::Truncated)
}
fn word(b: &[u8], at: usize) -> Result<u32, Error> {
    Ok(u32::from_be_bytes(array(b, at)?))
}
fn short(b: &[u8], at: usize) -> Result<u16, Error> {
    Ok(u16::from_be_bytes(array(b, at)?))
}
fn address(b: &[u8], at: usize, af: u32, p: AfProfile) -> Result<Address, Error> {
    match p.family(af)? {
        Family::V4 => Ok(Address::V4(array(b, at)?)),
        Family::V6 => Ok(Address::V6(array(b, at)?)),
    }
}
fn size(n: usize) -> Result<usize, Error> {
    MessageHeader::from_total_size(MessageType::new(0), n)?;
    Ok(n)
}
fn output(out: &mut [u8], n: usize, kind: MessageType) -> Result<&mut [u8], Error> {
    let b = out.get_mut(..n).ok_or(Error::Capacity)?;
    b.fill(0);
    MessageHeader::from_total_size(kind, n)?.encode(b)?;
    Ok(b)
}
impl Request {
    /// Decode the native supported C AF profile.
    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        Self::decode_with_profile(b, AfProfile::native())
    }
    /// Decode exactly one official request using actual endpoint AF assignments.
    pub fn decode_with_profile(b: &[u8], p: AfProfile) -> Result<Self, Error> {
        p.validate()?;
        let k = Frame::decode(b)?.header().message_type();
        match k {
            mt::VPN_CLIENT_REDIRECT_TO_IP if b.len() >= 32 => {
                let destination = address(b, 32, word(b, 20)?, p)?;
                if b.len() != 32 + destination.len() {
                    return Err(Error::Malformed);
                }
                Ok(Self::Internet {
                    reserved: word(b, 4)?,
                    expires: u64::from_be_bytes(array(b, 8)?),
                    result_af: word(b, 16)?,
                    destination,
                    request_id: array(b, 24)?,
                })
            }
            mt::VPN_CLIENT_REDIRECT_TO_SERVICE if b.len() == 128 => Ok(Self::Service {
                reserved: word(b, 4)?,
                expires: u64::from_be_bytes(array(b, 8)?),
                protocol: word(b, 16)?,
                result_af: word(b, 20)?,
                peer: array(b, 24)?,
                service: array(b, 56)?,
                request_id: array(b, 120)?,
            }),
            mt::VPN_CLIENT_REDIRECT_TO_IP | mt::VPN_CLIENT_REDIRECT_TO_SERVICE => {
                Err(Error::Malformed)
            }
            _ => Err(Error::Unsupported),
        }
    }
    /// Exact bounded official frame size.
    pub fn encoded_len(self) -> Result<usize, Error> {
        size(match self {
            Self::Internet { destination, .. } => 32 + destination.len(),
            Self::Service { .. } => 128,
        })
    }
    /// Encode using the current native AF profile, atomically on refusal.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        self.encode_with_profile(out, AfProfile::native())
    }
    /// Encode original fields and opaque request-id bytes with explicit AF values.
    pub fn encode_with_profile(self, out: &mut [u8], p: AfProfile) -> Result<usize, Error> {
        p.validate()?;
        let n = self.encoded_len()?;
        let k = match self {
            Self::Internet { .. } => mt::VPN_CLIENT_REDIRECT_TO_IP,
            Self::Service { .. } => mt::VPN_CLIENT_REDIRECT_TO_SERVICE,
        };
        let b = output(out, n, k)?;
        match self {
            Self::Internet {
                reserved,
                expires,
                result_af,
                destination,
                request_id,
            } => {
                b[4..8].copy_from_slice(&reserved.to_be_bytes());
                b[8..16].copy_from_slice(&expires.to_be_bytes());
                b[16..20].copy_from_slice(&result_af.to_be_bytes());
                b[20..24].copy_from_slice(&p.value(destination.family()).to_be_bytes());
                b[24..32].copy_from_slice(&request_id);
                b[32..].copy_from_slice(destination.bytes());
            }
            Self::Service {
                reserved,
                expires,
                protocol,
                result_af,
                peer,
                service,
                request_id,
            } => {
                b[4..8].copy_from_slice(&reserved.to_be_bytes());
                b[8..16].copy_from_slice(&expires.to_be_bytes());
                b[16..20].copy_from_slice(&protocol.to_be_bytes());
                b[20..24].copy_from_slice(&result_af.to_be_bytes());
                b[24..56].copy_from_slice(&peer);
                b[56..120].copy_from_slice(&service);
                b[120..128].copy_from_slice(&request_id);
            }
        }
        Ok(n)
    }
}
impl Response {
    /// Decode native-profile allocation result.
    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        Self::decode_with_profile(b, AfProfile::native())
    }
    /// Decode exact result; opaque id remains untouched.
    pub fn decode_with_profile(b: &[u8], p: AfProfile) -> Result<Self, Error> {
        p.validate()?;
        if Frame::decode(b)?.header().message_type() != mt::VPN_CLIENT_USE_IP {
            return Err(Error::Unsupported);
        }
        if b.len() < 16 {
            return Err(Error::Truncated);
        }
        let af = word(b, 4)?;
        let a = if af == 0 {
            None
        } else {
            Some(address(b, 16, af, p)?)
        };
        if b.len() != 16 + a.map_or(0, Address::len) {
            return Err(Error::Malformed);
        }
        Ok(Self {
            request_id: array(b, 8)?,
            address: a,
        })
    }
    /// Exact native-independent frame length.
    pub fn encoded_len(self) -> Result<usize, Error> {
        size(16 + self.address.map_or(0, Address::len))
    }
    /// Encode native-profile result.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        self.encode_with_profile(out, AfProfile::native())
    }
    /// Encode correct explicit AF plus original id; capacity failure is atomic.
    pub fn encode_with_profile(self, out: &mut [u8], p: AfProfile) -> Result<usize, Error> {
        p.validate()?;
        let n = self.encoded_len()?;
        let b = output(out, n, mt::VPN_CLIENT_USE_IP)?;
        b[8..16].copy_from_slice(&self.request_id);
        if let Some(a) = self.address {
            b[4..8].copy_from_slice(&p.value(a.family()).to_be_bytes());
            b[16..].copy_from_slice(a.bytes())
        }
        Ok(n)
    }
}
impl<'a> Helper<'a> {
    /// Decode one original helper185 frame; IP semantics remain packet-owner work.
    pub fn decode(b: &'a [u8]) -> Result<Self, Error> {
        if Frame::decode(b)?.header().message_type() != mt::VPN_HELPER {
            return Err(Error::Unsupported);
        }
        if b.len() < 8 {
            return Err(Error::Truncated);
        }
        Ok(Self {
            flags: short(b, 4)?,
            protocol: short(b, 6)?,
            packet: &b[8..],
        })
    }
    /// Exact helper frame length.
    pub fn encoded_len(self) -> Result<usize, Error> {
        size(8 + self.packet.len())
    }
    /// Encode original helper framing with no implicit native TUN operation.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len()?;
        let b = output(out, n, mt::VPN_HELPER)?;
        b[4..6].copy_from_slice(&self.flags.to_be_bytes());
        b[6..8].copy_from_slice(&self.protocol.to_be_bytes());
        b[8..].copy_from_slice(self.packet);
        Ok(n)
    }
}
impl<'a> PeerMessage<'a> {
    /// Decode actual native AF profile.
    pub fn decode(b: &'a [u8]) -> Result<Self, Error> {
        Self::decode_with_profile(b, AfProfile::native())
    }
    /// Decode exact peer framing. TCP/ICMP and IP policy are explicit core checks.
    pub fn decode_with_profile(b: &'a [u8], p: AfProfile) -> Result<Self, Error> {
        p.validate()?;
        let k = Frame::decode(b)?.header().message_type();
        Ok(match k {
            mt::VPN_TCP_TO_SERVICE_START if b.len() >= 28 => Self::TcpService {
                reserved: word(b, 4)?,
                header: array(b, 8)?,
                tail: &b[28..],
            },
            mt::VPN_TCP_TO_INTERNET_START if b.len() >= 28 => {
                let destination = address(b, 28, word(b, 4)?, p)?;
                Self::TcpInternet {
                    destination,
                    header: array(b, 8)?,
                    tail: &b[28 + destination.len()..],
                }
            }
            mt::VPN_TCP_DATA_TO_EXIT | mt::VPN_TCP_DATA_TO_VPN if b.len() >= 28 => Self::Tcp {
                to_exit: k == mt::VPN_TCP_DATA_TO_EXIT,
                reserved: word(b, 4)?,
                header: array(b, 8)?,
                tail: &b[28..],
            },
            mt::VPN_UDP_TO_SERVICE if b.len() >= 8 => Self::UdpService {
                source: short(b, 4)?,
                destination: short(b, 6)?,
                payload: &b[8..],
            },
            mt::VPN_UDP_TO_INTERNET if b.len() >= 12 => {
                let address = address(b, 12, word(b, 4)?, p)?;
                Self::UdpInternet {
                    address,
                    source: short(b, 8)?,
                    destination: short(b, 10)?,
                    payload: &b[12 + address.len()..],
                }
            }
            mt::VPN_UDP_REPLY if b.len() >= 8 => Self::UdpReply {
                source: short(b, 4)?,
                destination: short(b, 6)?,
                payload: &b[8..],
            },
            mt::VPN_ICMP_TO_SERVICE if b.len() >= 16 => Self::IcmpService {
                af: word(b, 4)?,
                header: array(b, 8)?,
                payload: &b[16..],
            },
            mt::VPN_ICMP_TO_INTERNET if b.len() >= 16 => {
                let destination = address(b, 16, word(b, 4)?, p)?;
                Self::IcmpInternet {
                    destination,
                    header: array(b, 8)?,
                    payload: &b[16 + destination.len()..],
                }
            }
            mt::VPN_ICMP_TO_VPN if b.len() >= 16 => Self::IcmpReply {
                af: word(b, 4)?,
                header: array(b, 8)?,
                payload: &b[16..],
            },
            mt::VPN_DNS_TO_INTERNET | mt::VPN_DNS_FROM_INTERNET if b.len() >= 16 => Self::Dns {
                reply: k == mt::VPN_DNS_FROM_INTERNET,
                packet: &b[4..],
            },
            mt::VPN_TCP_TO_SERVICE_START
            | mt::VPN_TCP_TO_INTERNET_START
            | mt::VPN_TCP_DATA_TO_EXIT
            | mt::VPN_TCP_DATA_TO_VPN
            | mt::VPN_UDP_TO_SERVICE
            | mt::VPN_UDP_TO_INTERNET
            | mt::VPN_UDP_REPLY
            | mt::VPN_ICMP_TO_SERVICE
            | mt::VPN_ICMP_TO_INTERNET
            | mt::VPN_ICMP_TO_VPN
            | mt::VPN_DNS_TO_INTERNET
            | mt::VPN_DNS_FROM_INTERNET => return Err(Error::Malformed),
            _ => return Err(Error::Unsupported),
        })
    }
    /// Exact peer frame length, with no implicit CADET capacity claim.
    pub fn encoded_len(self) -> Result<usize, Error> {
        size(match self {
            Self::TcpService { tail, .. } | Self::Tcp { tail, .. } => 28 + tail.len(),
            Self::TcpInternet {
                destination, tail, ..
            } => 28 + destination.len() + tail.len(),
            Self::UdpService { payload, .. } | Self::UdpReply { payload, .. } => 8 + payload.len(),
            Self::UdpInternet {
                address, payload, ..
            } => 12 + address.len() + payload.len(),
            Self::IcmpService { payload, .. } | Self::IcmpReply { payload, .. } => {
                16 + payload.len()
            }
            Self::IcmpInternet {
                destination,
                payload,
                ..
            } => 16 + destination.len() + payload.len(),
            Self::Dns { packet, .. } => {
                if packet.len() < 12 {
                    return Err(Error::Truncated);
                }
                4 + packet.len()
            }
        })
    }
    /// Encode actual native AF profile atomically on capacity failure.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        self.encode_with_profile(out, AfProfile::native())
    }
    /// Encode explicit AF profile; raw skeleton/reserved fields are not forged.
    pub fn encode_with_profile(self, out: &mut [u8], p: AfProfile) -> Result<usize, Error> {
        p.validate()?;
        let n = self.encoded_len()?;
        let k = match self {
            Self::TcpService { .. } => mt::VPN_TCP_TO_SERVICE_START,
            Self::TcpInternet { .. } => mt::VPN_TCP_TO_INTERNET_START,
            Self::Tcp { to_exit: true, .. } => mt::VPN_TCP_DATA_TO_EXIT,
            Self::Tcp { to_exit: false, .. } => mt::VPN_TCP_DATA_TO_VPN,
            Self::UdpService { .. } => mt::VPN_UDP_TO_SERVICE,
            Self::UdpInternet { .. } => mt::VPN_UDP_TO_INTERNET,
            Self::UdpReply { .. } => mt::VPN_UDP_REPLY,
            Self::IcmpService { .. } => mt::VPN_ICMP_TO_SERVICE,
            Self::IcmpInternet { .. } => mt::VPN_ICMP_TO_INTERNET,
            Self::IcmpReply { .. } => mt::VPN_ICMP_TO_VPN,
            Self::Dns { reply: true, .. } => mt::VPN_DNS_FROM_INTERNET,
            Self::Dns { reply: false, .. } => mt::VPN_DNS_TO_INTERNET,
        };
        let b = output(out, n, k)?;
        match self {
            Self::TcpService {
                reserved,
                header,
                tail,
            }
            | Self::Tcp {
                reserved,
                header,
                tail,
                ..
            } => {
                b[4..8].copy_from_slice(&reserved.to_be_bytes());
                b[8..28].copy_from_slice(&header);
                b[28..].copy_from_slice(tail)
            }
            Self::TcpInternet {
                destination,
                header,
                tail,
            } => {
                b[4..8].copy_from_slice(&p.value(destination.family()).to_be_bytes());
                b[8..28].copy_from_slice(&header);
                let e = 28 + destination.len();
                b[28..e].copy_from_slice(destination.bytes());
                b[e..].copy_from_slice(tail)
            }
            Self::UdpService {
                source,
                destination,
                payload,
            }
            | Self::UdpReply {
                source,
                destination,
                payload,
            } => {
                b[4..6].copy_from_slice(&source.to_be_bytes());
                b[6..8].copy_from_slice(&destination.to_be_bytes());
                b[8..].copy_from_slice(payload)
            }
            Self::UdpInternet {
                address,
                source,
                destination,
                payload,
            } => {
                b[4..8].copy_from_slice(&p.value(address.family()).to_be_bytes());
                b[8..10].copy_from_slice(&source.to_be_bytes());
                b[10..12].copy_from_slice(&destination.to_be_bytes());
                let e = 12 + address.len();
                b[12..e].copy_from_slice(address.bytes());
                b[e..].copy_from_slice(payload)
            }
            Self::IcmpService {
                af,
                header,
                payload,
            }
            | Self::IcmpReply {
                af,
                header,
                payload,
            } => {
                b[4..8].copy_from_slice(&af.to_be_bytes());
                b[8..16].copy_from_slice(&header);
                b[16..].copy_from_slice(payload)
            }
            Self::IcmpInternet {
                destination,
                header,
                payload,
            } => {
                b[4..8].copy_from_slice(&p.value(destination.family()).to_be_bytes());
                b[8..16].copy_from_slice(&header);
                let e = 16 + destination.len();
                b[16..e].copy_from_slice(destination.bytes());
                b[e..].copy_from_slice(payload)
            }
            Self::Dns { packet, .. } => b[4..].copy_from_slice(packet),
        }
        Ok(n)
    }
}
