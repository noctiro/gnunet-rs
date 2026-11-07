//! Official local NAT-service messages and clear TCP reversal probe. Native
//! sockaddr layouts are explicit host profiles, not an added network protocol.
use core::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use gnunet_crypto::EddsaPublicKey;
use gnunet_types::Error;
use gnunet_wire::official::message_type as mt;
/// Native Unix-domain IPC ABI used by the actual NAT service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Profile {
    /// Darwin sockaddr has length8/family8, AF_INET6=30.
    Darwin,
    /// Linux sockaddr has native-endian family16, AF_INET6=10.
    Linux,
}
impl Profile {
    fn family(self, bytes: &[u8]) -> Result<u16, Error> {
        let first: &[u8; 2] = bytes
            .get(..2)
            .ok_or(Error::Truncated)?
            .try_into()
            .map_err(|_| Error::Truncated)?;
        Ok(match self {
            Self::Darwin => first[1] as u16,
            Self::Linux => u16::from_ne_bytes(*first),
        })
    }
    fn v6(self) -> u16 {
        match self {
            Self::Darwin => 30,
            Self::Linux => 10,
        }
    }
}
/// One actual native address, retaining all original padding and scope bytes for
/// C's exact app-context removal matching. Parsing conveys no public-address trust.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Native<'a> {
    bytes: &'a [u8],
    socket: SocketAddr,
}
impl<'a> Native<'a> {
    /// Validate exactly one source-supported native IPv4 or IPv6 address.
    pub fn parse(profile: Profile, bytes: &'a [u8]) -> Result<Self, Error> {
        let family = profile.family(bytes)?;
        let port = u16::from_be_bytes(
            bytes
                .get(2..4)
                .ok_or(Error::Truncated)?
                .try_into()
                .map_err(|_| Error::Truncated)?,
        );
        let socket = if family == 2 && bytes.len() == 16 {
            SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[4..8]).map_err(|_| Error::Malformed)?),
                port,
            ))
        } else if family == profile.v6() && bytes.len() == 28 {
            SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24]).map_err(|_| Error::Malformed)?),
                port,
                u32::from_be_bytes(bytes[4..8].try_into().map_err(|_| Error::Malformed)?),
                u32::from_ne_bytes(bytes[24..28].try_into().map_err(|_| Error::Malformed)?),
            ))
        } else {
            return Err(Error::Malformed);
        };
        Ok(Self { bytes, socket })
    }
    /// Borrow exact original sockaddr bytes, including padding used by C equality.
    #[must_use]
    pub const fn bytes(self) -> &'a [u8] {
        self.bytes
    }
    /// Numeric endpoint; this is not a DNS lookup or a validated NAT advertisement.
    #[must_use]
    pub const fn socket(self) -> SocketAddr {
        self.socket
    }
}
/// Encode a real native IPv4/IPv6 endpoint into caller backing. The output uses
/// the selected source ABI and no unsafe transmute or platform guessing.
pub fn address(profile: Profile, socket: SocketAddr, out: &mut [u8]) -> Result<usize, Error> {
    let n = if socket.is_ipv4() { 16 } else { 28 };
    let b = out.get_mut(..n).ok_or(Error::Capacity)?;
    b.fill(0);
    let family = if socket.is_ipv4() { 2 } else { profile.v6() };
    match profile {
        Profile::Darwin => {
            b[0] = n as u8;
            b[1] = family as u8;
        }
        Profile::Linux => b[..2].copy_from_slice(&family.to_ne_bytes()),
    };
    b[2..4].copy_from_slice(&socket.port().to_be_bytes());
    match socket {
        SocketAddr::V4(v) => b[4..8].copy_from_slice(&v.ip().octets()),
        SocketAddr::V6(v) => {
            b[4..8].copy_from_slice(&v.flowinfo().to_be_bytes());
            b[8..24].copy_from_slice(&v.ip().octets());
            b[24..28].copy_from_slice(&v.scope_id().to_ne_bytes());
        }
    }
    Ok(n)
}
fn prepare(out: &mut [u8], n: usize, k: u16) -> Result<&mut [u8], Error> {
    if n > u16::MAX as usize {
        return Err(Error::Overflow);
    }
    let b = out.get_mut(..n).ok_or(Error::Capacity)?;
    b.fill(0);
    b[..2].copy_from_slice(&(n as u16).to_be_bytes());
    b[2..4].copy_from_slice(&k.to_be_bytes());
    Ok(b)
}
/// Register actual bound TCP addresses and official communicator-tcp configsection,
/// requesting address/reversal callbacks (flags3), protocol TCP6.
pub fn register(addresses: &[Native<'_>], out: &mut [u8]) -> Result<usize, Error> {
    if addresses.len() > u16::MAX as usize {
        return Err(Error::Overflow);
    }
    let section = b"communicator-tcp\0";
    let mut n = 10 + section.len();
    for a in addresses {
        n = n.checked_add(a.bytes.len()).ok_or(Error::Overflow)?;
    }
    let b = prepare(out, n, mt::NAT_REGISTER.value())?;
    b[4] = 3;
    b[5] = 6;
    b[6..8].copy_from_slice(&(section.len() as u16).to_be_bytes());
    b[8..10].copy_from_slice(&(addresses.len() as u16).to_be_bytes());
    let mut offset = 10;
    for a in addresses {
        b[offset..offset + a.bytes.len()].copy_from_slice(a.bytes);
        offset += a.bytes.len();
    }
    b[offset..].copy_from_slice(section);
    Ok(n)
}
/// Ask the actual NAT service to reverse IPv4. Native request admission and timer
/// setup must be acknowledged separately; this function performs no network IO.
pub fn reversal(local: Native<'_>, remote: Native<'_>, out: &mut [u8]) -> Result<usize, Error> {
    if !local.socket.is_ipv4() || !remote.socket.is_ipv4() {
        return Err(Error::InvalidInput);
    }
    let b = prepare(out, 40, mt::NAT_REQUEST_CONNECTION_REVERSAL.value())?;
    b[4..6].copy_from_slice(&16u16.to_be_bytes());
    b[6..8].copy_from_slice(&16u16.to_be_bytes());
    b[8..24].copy_from_slice(local.bytes);
    b[24..40].copy_from_slice(remote.bytes);
    Ok(40)
}
/// Actual registered NAT callback. Its app-context handle is host registry state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Notice<'a> {
    /// Add/remove(boolean), raw address class, exact native address.
    Address(bool, u32, Native<'a>),
    /// Real NAT request to connect back to this IPv4 endpoint.
    Reverse(Native<'a>),
    /// Unregistered MQ type, ignored by the source dispatcher.
    Unknown(u16),
}
impl<'a> Notice<'a> {
    /// Parse one complete registered frame and explicit native sockaddr profile.
    pub fn decode(profile: Profile, input: &'a [u8]) -> Result<Self, Error> {
        if input.len() < 4 {
            return Err(Error::Truncated);
        }
        if u16::from_be_bytes([input[0], input[1]]) as usize != input.len() {
            return Err(Error::Malformed);
        }
        let k = u16::from_be_bytes([input[2], input[3]]);
        if k == mt::NAT_ADDRESS_CHANGE.value() {
            if input.len() < 12 {
                return Err(Error::Truncated);
            }
            return Ok(Self::Address(
                i32::from_be_bytes(input[4..8].try_into().map_err(|_| Error::Truncated)?) == 1,
                u32::from_be_bytes(input[8..12].try_into().map_err(|_| Error::Truncated)?),
                Native::parse(profile, &input[12..])?,
            ));
        }
        if k == mt::NAT_CONNECTION_REVERSAL_REQUESTED.value() {
            if input.len() != 20 {
                return Err(Error::Malformed);
            }
            let native = Native::parse(profile, &input[4..])?;
            if !native.socket.is_ipv4() {
                return Err(Error::Malformed);
            }
            return Ok(Self::Reverse(native));
        }
        Ok(Self::Unknown(k))
    }
}
/// Official clear TCP NAT probe: common header36 followed by claimed identity32.
/// This claimed identity acquires no authority before the subsequent signed KX.
pub fn probe(peer: EddsaPublicKey, out: &mut [u8]) -> Result<usize, Error> {
    let b = prepare(out, 36, mt::TRANSPORT_TCP_NAT_PROBE.value())?;
    b[4..].copy_from_slice(peer.as_bytes());
    Ok(36)
}
/// Whether exactly four original clear bytes identify the official 36-byte
/// NAT probe. A matching header is only a framing hint, never authentication.
#[must_use]
pub const fn is_probe_header(header: &[u8; 4]) -> bool {
    u16::from_be_bytes([header[0], header[1]]) == 36
        && u16::from_be_bytes([header[2], header[3]]) == mt::TRANSPORT_TCP_NAT_PROBE.value()
}
/// Complete initial stream preamble, not a peer/identity admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Preamble<'a> {
    /// Exact officially typed probe, whose claimed peer still needs KX verification.
    Probe(EddsaPublicKey),
    /// Full168-byte ordinary Elligator confirmation.
    Handshake(&'a [u8]),
}
/// Bounded first-byte collector. A legitimate handshake fragmented at36bytes
/// remains a handshake unless its actual official header identifies a NAT probe.
pub struct Reader {
    bytes: [u8; 168],
    filled: usize,
    probe: bool,
}
impl Reader {
    /// Empty caller-stored preamble; source proto deadline remains a separate port.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bytes: [0; 168],
            filled: 0,
            probe: false,
        }
    }
    /// Consume only enough for this original preamble, retaining later input at host.
    pub fn push(&mut self, input: &[u8]) -> usize {
        let mut used = 0;
        while used < input.len() && !self.complete() {
            let end = if self.filled < 36 { 36 } else { 168 };
            let n = (end - self.filled).min(input.len() - used);
            self.bytes[self.filled..self.filled + n].copy_from_slice(&input[used..used + n]);
            self.filled += n;
            used += n;
            if self.filled == 36 {
                self.probe =
                    is_probe_header(&[self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3]]);
            }
        }
        used
    }
    /// Structural completion, without any native success or authenticated sender.
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.probe || self.filled == 168
    }
    /// Borrow one original complete preamble; no reset or mutable alias is exposed.
    pub fn view(&self) -> Result<Preamble<'_>, Error> {
        if self.probe {
            return Ok(Preamble::Probe(EddsaPublicKey::from_bytes(
                self.bytes[4..36].try_into().map_err(|_| Error::Malformed)?,
            )));
        }
        if self.filled == 168 {
            return Ok(Preamble::Handshake(&self.bytes));
        }
        Err(Error::WouldBlock)
    }
}
impl Default for Reader {
    fn default() -> Self {
        Self::new()
    }
}
