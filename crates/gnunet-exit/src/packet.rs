//! Convert one packet at a time. Callers own authorization, tuple selection,
//! channel lookup, and native I/O; a successful conversion grants none of them.

use crate::{
    AfProfile, Family,
    policy::{Endpoint, Protocol, Tuple},
};
use gnunet_types::Error;
use gnunet_vpn::packet::{self, Packet, Quoted};
use gnunet_wire::official::vpn::PeerMessage;

#[derive(Debug)]
enum ForwardSegment<'a> {
    Tcp([u8; 20], &'a [u8]),
    Udp([u8; 8], &'a [u8]),
    IcmpEcho([u8; 8], &'a [u8]),
    IcmpError([u8; 8]),
}

/// A validated peer request to encode using one already selected physical tuple.
#[derive(Debug)]
pub struct Forward<'a> {
    tuple: Tuple,
    segment: ForwardSegment<'a>,
    packet_len: usize,
}

impl<'a> Forward<'a> {
    /// Validate the request and its packet length without allocating or copying
    /// its tail. The caller must resolve Internet and named targets and enforce
    /// all policy before supplying the selected tuple.
    pub fn from_peer(
        tuple: Tuple,
        message: PeerMessage<'a>,
        profile: AfProfile,
    ) -> Result<Self, Error> {
        tuple.validate()?;
        let family = tuple.local.address.family();
        let ip_len = ip_header_len(family);
        let segment = match message {
            PeerMessage::TcpInternet { header, tail, .. }
            | PeerMessage::TcpService { header, tail, .. }
            | PeerMessage::Tcp {
                to_exit: true,
                header,
                tail,
                ..
            } => {
                if tuple.protocol != Protocol::Tcp {
                    return Err(Error::Conflict);
                }
                let options = (usize::from(header[12] >> 4) * 4)
                    .checked_sub(header.len())
                    .ok_or(Error::Malformed)?;
                if options > tail.len() {
                    return Err(Error::Malformed);
                }
                ForwardSegment::Tcp(with_ports(tuple, header), tail)
            }
            PeerMessage::UdpInternet { payload, .. } | PeerMessage::UdpService { payload, .. } => {
                if tuple.protocol != Protocol::Udp {
                    return Err(Error::Conflict);
                }
                ForwardSegment::Udp(with_ports(tuple, [0; 8]), payload)
            }
            PeerMessage::IcmpInternet {
                destination,
                header,
                payload,
            } => Self::icmp(destination.family(), family, header, payload)?,
            PeerMessage::IcmpService {
                af,
                header,
                payload,
            } => Self::icmp(profile.family(af)?, family, header, payload)?,
            _ => return Err(Error::Unsupported),
        };
        let (header_len, tail_len) = match &segment {
            ForwardSegment::Tcp(header, tail) => (header.len(), tail.len()),
            ForwardSegment::Udp(header, tail) | ForwardSegment::IcmpEcho(header, tail) => {
                (header.len(), tail.len())
            }
            ForwardSegment::IcmpError(header) => (header.len(), ip_len + 8),
        };
        let transport_len = header_len.checked_add(tail_len).ok_or(Error::Overflow)?;
        let packet_len = ip_len.checked_add(transport_len).ok_or(Error::Overflow)?;
        if transport_len > usize::from(u16::MAX)
            || (family == Family::V4 && packet_len > usize::from(u16::MAX))
        {
            return Err(Error::TooLarge);
        }
        Ok(Self {
            tuple,
            segment,
            packet_len,
        })
    }

    fn icmp(
        from: Family,
        to: Family,
        header: [u8; 8],
        payload: &'a [u8],
    ) -> Result<ForwardSegment<'a>, Error> {
        let header = packet::translate_icmp_header(from, to, header)?;
        if packet::icmp_error(to, header[0]) {
            if !payload.is_empty() {
                return Err(Error::Malformed);
            }
            Ok(ForwardSegment::IcmpError(header))
        } else {
            Ok(ForwardSegment::IcmpEcho(header, payload))
        }
    }

    /// Exact raw IP packet length, including its transport header and payload.
    #[must_use]
    pub const fn packet_len(&self) -> usize {
        self.packet_len
    }

    /// Original peer echo identifier, independent of the physical tuple.
    #[must_use]
    pub fn echo_id(&self) -> Option<u16> {
        match &self.segment {
            ForwardSegment::IcmpEcho(header, _) => {
                packet::echo_id(self.tuple.local.address.family(), header)
            }
            _ => None,
        }
    }

    /// Install the identifier owned by the native route before encoding.
    /// Encoding recomputes the physical transport checksum.
    pub fn set_echo_id(&mut self, id: u16) -> Result<(), Error> {
        let ForwardSegment::IcmpEcho(header, _) = &mut self.segment else {
            return Err(Error::InvalidInput);
        };
        header[4..6].copy_from_slice(&id.to_be_bytes());
        Ok(())
    }

    /// Write one complete raw IP packet. An insufficient buffer is unchanged.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let tuple = self.tuple;
        let source = tuple.local.address;
        let destination = tuple.remote.address;
        let control = match source.family() {
            Family::V4 => Protocol::Icmp,
            Family::V6 => Protocol::Icmp6,
        };
        let mut quote = [0; 48];
        let (protocol, header, tail): (_, &[u8], _) = match &self.segment {
            ForwardSegment::Tcp(header, tail) => (Protocol::Tcp, header, *tail),
            ForwardSegment::Udp(header, payload) => (Protocol::Udp, header, *payload),
            ForwardSegment::IcmpEcho(header, payload) => (control, header, *payload),
            ForwardSegment::IcmpError(header) => {
                let ports =
                    (!tuple.protocol.is_icmp()).then_some((tuple.remote.port, tuple.local.port));
                let len = packet::quote(
                    destination,
                    source,
                    tuple.protocol.number(),
                    ports,
                    &mut quote,
                )?;
                (control, header, &quote[..len])
            }
        };
        packet::build_parts(source, destination, protocol.number(), header, tail, out)
    }

    #[cfg(feature = "alloc")]
    pub(crate) fn tcp(&self) -> Option<(&[u8; 20], usize)> {
        match &self.segment {
            ForwardSegment::Tcp(header, tail) => {
                let offset = usize::from(header[12] >> 4) * 4;
                Some((header, header.len() + tail.len() - offset))
            }
            _ => None,
        }
    }
}

fn with_ports<const N: usize>(tuple: Tuple, mut header: [u8; N]) -> [u8; N] {
    header[..2].copy_from_slice(&tuple.local.port.to_be_bytes());
    header[2..4].copy_from_slice(&tuple.remote.port.to_be_bytes());
    header
}

const fn ip_header_len(family: Family) -> usize {
    match family {
        Family::V4 => 20,
        Family::V6 => 40,
    }
}

#[derive(Debug)]
enum Reply<'a> {
    Tcp([u8; 20], &'a [u8]),
    Udp(&'a [u8]),
    Icmp([u8; 8], &'a [u8]),
}

/// A verified raw IP packet and the physical tuple it addresses.
#[derive(Debug)]
pub struct Returned<'a> {
    tuple: Tuple,
    reply: Reply<'a>,
    quoted_echo: Option<u16>,
}

impl<'a> Returned<'a> {
    /// Check structural bounds and checksums before extracting a reply. For
    /// ICMP errors, the quoted original packet identifies the flow, regardless of
    /// the outer source address. Neither form authenticates the packet's sender.
    pub fn parse(raw: &'a [u8]) -> Result<Self, Error> {
        let packet = Packet::parse(raw)?;
        packet.validate_checksums()?;
        let family = packet.source().family();
        let protocol = Protocol::from_number(family, packet.protocol())?;
        let segment = packet.segment();
        let (source_port, destination_port) = packet.ports()?;
        let mut tuple = Tuple {
            remote: Endpoint {
                address: packet.source(),
                port: source_port,
            },
            local: Endpoint {
                address: packet.destination(),
                port: destination_port,
            },
            protocol,
        };
        let mut quoted_echo = None;
        let reply = match protocol {
            Protocol::Tcp => {
                let (mut header, tail) = fixed_header::<20>(segment)?;
                header[..4].fill(0);
                header[16..18].fill(0);
                Reply::Tcp(header, tail)
            }
            Protocol::Udp => Reply::Udp(&segment[8..]),
            Protocol::Icmp | Protocol::Icmp6 => {
                let (header, payload) = fixed_header::<8>(segment)?;
                let header = packet::translate_icmp_header(family, family, header)?;
                let payload = if packet::icmp_error(family, header[0]) {
                    let (quoted, echo) = Quoted::parse_with_echo_id(payload)?;
                    quoted_echo = echo;
                    if quoted.source.family() != family || quoted.destination.family() != family {
                        return Err(Error::Malformed);
                    }
                    tuple = Tuple {
                        remote: Endpoint {
                            address: quoted.destination,
                            port: quoted.destination_port,
                        },
                        local: Endpoint {
                            address: quoted.source,
                            port: quoted.source_port,
                        },
                        protocol: Protocol::from_number(family, quoted.protocol)?,
                    };
                    &[]
                } else {
                    payload
                };
                Reply::Icmp(header, payload)
            }
        };
        Ok(Self {
            tuple,
            reply,
            quoted_echo,
        })
    }

    /// Physical return tuple for the owner's existing flow lookup.
    #[must_use]
    pub const fn tuple(&self) -> Tuple {
        self.tuple
    }

    /// Native identifier recovered from an echo or an error's original quote.
    #[must_use]
    pub fn echo_id(&self) -> Option<u16> {
        self.quoted_echo.or_else(|| match &self.reply {
            Reply::Icmp(header, _) => packet::echo_id(self.tuple.local.address.family(), header),
            _ => None,
        })
    }

    /// Restore the peer's original identifier in a returned echo. For a
    /// matched ICMP error, the official reply contains no quote to rewrite.
    pub fn restore_echo_id(&mut self, id: u16) -> Result<(), Error> {
        let family = self.tuple.local.address.family();
        match &mut self.reply {
            Reply::Icmp(header, _) if packet::echo_id(family, header).is_some() => {
                header[4..6].copy_from_slice(&id.to_be_bytes());
                Ok(())
            }
            Reply::Icmp(..) if self.quoted_echo.is_some() => Ok(()),
            _ => Err(Error::InvalidInput),
        }
    }

    /// Official reply skeleton, borrowing the unchanged tail. Transport ports
    /// are inherited by the VPN, and ICMP errors omit their raw quote.
    #[must_use]
    pub fn message(&self, profile: AfProfile) -> PeerMessage<'a> {
        match self.reply {
            Reply::Tcp(header, tail) => PeerMessage::Tcp {
                to_exit: false,
                reserved: 0,
                header,
                tail,
            },
            Reply::Udp(payload) => PeerMessage::UdpReply {
                source: 0,
                destination: 0,
                payload,
            },
            Reply::Icmp(header, payload) => PeerMessage::IcmpReply {
                af: profile.value(self.tuple.local.address.family()),
                header,
                payload,
            },
        }
    }
}

fn fixed_header<const N: usize>(bytes: &[u8]) -> Result<([u8; N], &[u8]), Error> {
    let (header, tail) = bytes.split_at_checked(N).ok_or(Error::Truncated)?;
    Ok((header.try_into().map_err(|_| Error::Truncated)?, tail))
}
