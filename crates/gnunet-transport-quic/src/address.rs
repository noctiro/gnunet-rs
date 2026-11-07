//! Literal communicator addresses, independent of TLS/PID authentication.
//! This layer contains neither DNS nor a default port. The original IPC string
//! codec owns the terminating NUL; these byte slices never contain that NUL.
use core::{
    fmt::{self, Write},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    str,
};
use gnunet_types::Error;
/// Longest canonical address: http3- + [eight IPv6 groups]:65535.
pub const MAX_ENCODED_LEN: usize = 53;
/// Exact distinct production address prefix, not evidence of ALPN or identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Profile {
    /// Raw GNUnet frames over the raw QUIC application profile.
    Raw,
    /// Actual HTTP/3 application profile.
    Http3,
}
impl Profile {
    /// Exact registered communicator prefix, without its following hyphen.
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::Raw => crate::raw::ADDRESS_PREFIX,
            Self::Http3 => crate::h3::ADDRESS_PREFIX,
        }
    }
}
/// Checked literal IP/port. No URL, hostname, private envelope, flowinfo or
/// interface scope is inferred from an advertisement or queue request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Address {
    profile: Profile,
    socket: SocketAddr,
}
impl Address {
    /// A numeric port including0 is preserved explicitly; this codec does not
    /// claim that port0 is usable as a remote destination. Reject non-wire IPv6
    /// routing metadata rather than silently discarding the caller's selection.
    pub fn new(profile: Profile, socket: SocketAddr) -> Result<Self, Error> {
        if matches!(socket,SocketAddr::V6(v6) if v6.scope_id()!=0 || v6.flowinfo()!=0) {
            return Err(Error::Unsupported);
        }
        Ok(Self { profile, socket })
    }
    /// Parse the actual peer-address form quic-IP:port or http3-IP:port, with
    /// mandatory IPv6 brackets and explicit unsigned decimal0..65535. No NUL
    /// is accepted, even a final one. Native MQ codecs validate/remove their own
    /// terminator before this call. Bind-only wildcard/portless syntax is not a
    /// peer address and is deliberately separate from this codec.
    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        if input.contains(&0) {
            return Err(Error::Malformed);
        }
        let (profile, body) = if let Some(body) = input.strip_prefix(b"quic-") {
            (Profile::Raw, body)
        } else if let Some(body) = input.strip_prefix(b"http3-") {
            (Profile::Http3, body)
        } else {
            return Err(Error::Unsupported);
        };
        let text = str::from_utf8(body).map_err(|_| Error::Malformed)?;
        let socket = if let Some(ip) = text.strip_prefix('[') {
            let (ip, port) = ip.split_once("]:").ok_or(Error::Malformed)?;
            let ip: Ipv6Addr = ip.parse().map_err(|_| Error::Malformed)?;
            SocketAddr::V6(SocketAddrV6::new(ip, parse_port(port.as_bytes())?, 0, 0))
        } else {
            let (ip, port) = text.split_once(':').ok_or(Error::Malformed)?;
            let ip: Ipv4Addr = ip.parse().map_err(|_| Error::Malformed)?;
            SocketAddr::new(ip.into(), parse_port(port.as_bytes())?)
        };
        Self::new(profile, socket)
    }
    /// Exact selected syntax profile; not actual negotiated TLS/HTTP state.
    pub const fn profile(self) -> Profile {
        self.profile
    }
    /// Direct original numeric socket endpoint for the actual network provider.
    /// Taking this value adds no resolution, authentication or route authority.
    pub const fn socket(self) -> SocketAddr {
        self.socket
    }
    /// Format once into a bounded stack-owned value. Its borrowed bytes may be
    /// passed directly to the original IPC codec without formatting again.
    pub fn canonical(self) -> Result<Canonical, Error> {
        let mut encoded = Writer(Canonical {
            bytes: [0; MAX_ENCODED_LEN],
            used: 0,
        });
        write!(&mut encoded, "{}-{}", self.profile.prefix(), self.socket)
            .map_err(|_| Error::Capacity)?;
        Ok(encoded.0)
    }
    /// Exact canonical bytes, without NUL. On any error the caller's output is
    /// unchanged; formatting first occurs only in the small local stack value.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let canonical = self.canonical()?;
        let bytes = canonical.as_bytes();
        let destination = output.get_mut(..bytes.len()).ok_or(Error::Capacity)?;
        destination.copy_from_slice(bytes);
        Ok(bytes.len())
    }
}
/// One stack-owned canonical string, never a private key or wire envelope.
/// Trailing storage is private; only the checked initialized prefix is exposed.
#[derive(Clone, Copy)]
pub struct Canonical {
    bytes: [u8; MAX_ENCODED_LEN],
    used: usize,
}
impl Canonical {
    /// Borrow the exact original formatted prefix with no terminating NUL.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.used]
    }
}
// Only this private construction writer can mutate formatted bytes. Public
// Canonical values cannot be appended with unchecked text or embedded NUL.
struct Writer(Canonical);
impl Write for Writer {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self.0.used.checked_add(text.len()).ok_or(fmt::Error)?;
        let output = self.0.bytes.get_mut(self.0.used..end).ok_or(fmt::Error)?;
        output.copy_from_slice(text.as_bytes());
        self.0.used = end;
        Ok(())
    }
}
fn parse_port(input: &[u8]) -> Result<u16, Error> {
    if input.is_empty() {
        return Err(Error::Malformed);
    }
    input.iter().try_fold(0u16, |port, byte| {
        if !byte.is_ascii_digit() {
            return Err(Error::Malformed);
        }
        port.checked_mul(10)
            .and_then(|port| port.checked_add(u16::from(*byte - b'0')))
            .ok_or(Error::Malformed)
    })
}
