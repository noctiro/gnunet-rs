//! Official active NAT IPC and NAT-test messages. Native sockaddr layout is
//! explicit: an IPC frame is not portable between unlike host ABIs. There is
//! no request id, reply ACK, unregister message or wire cancellation.
use super::{Frame, MessageHeader, MessageType, message_type as mt};
use gnunet_types::Error;

/// Native integer byte order, distinct from the network-order message header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Endian {
    /// Little-endian producer.
    Little,
    /// Big-endian producer.
    Big,
}
impl Endian {
    /// Read a native u16.
    pub const fn u16(self, b: [u8; 2]) -> u16 {
        match self {
            Self::Little => u16::from_le_bytes(b),
            Self::Big => u16::from_be_bytes(b),
        }
    }
    /// Read a native u32.
    pub const fn u32(self, b: [u8; 4]) -> u32 {
        match self {
            Self::Little => u32::from_le_bytes(b),
            Self::Big => u32::from_be_bytes(b),
        }
    }
    /// Write a native u16.
    pub const fn put16(self, n: u16) -> [u8; 2] {
        match self {
            Self::Little => n.to_le_bytes(),
            Self::Big => n.to_be_bytes(),
        }
    }
    /// Write a native u32.
    pub const fn put32(self, n: u32) -> [u8; 4] {
        match self {
            Self::Little => n.to_le_bytes(),
            Self::Big => n.to_be_bytes(),
        }
    }
}
/// A supported native sockaddr ABI. IP layouts and family values must come
/// from the actual producer, never be inferred from attacker-controlled bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Profile {
    endian: Endian,
    len_byte: bool,
    ipv6: u16,
    unix_len: u16,
}
impl Profile {
    /// Linux sockaddr ABI; AF_INET6=10, sockaddr_un=110.
    pub const fn linux(endian: Endian) -> Self {
        Self {
            endian,
            len_byte: false,
            ipv6: 10,
            unix_len: 110,
        }
    }
    /// Darwin sockaddr ABI; first byte is length, AF_INET6=30, sockaddr_un=106.
    pub const fn darwin(endian: Endian) -> Self {
        Self {
            endian,
            len_byte: true,
            ipv6: 30,
            unix_len: 106,
        }
    }
    /// FreeBSD sockaddr ABI; AF_INET6=28, sockaddr_un=106.
    pub const fn freebsd(endian: Endian) -> Self {
        Self {
            endian,
            len_byte: true,
            ipv6: 28,
            unix_len: 106,
        }
    }
    /// Actual producer integer order.
    pub const fn endian(self) -> Endian {
        self.endian
    }
    fn family(self, b: &[u8]) -> Result<u16, Error> {
        let b = b.get(..2).ok_or(Error::Truncated)?;
        Ok(if self.len_byte {
            u16::from(b[1])
        } else {
            self.endian.u16([b[0], b[1]])
        })
    }
    fn address_len(self, b: &[u8]) -> Result<usize, Error> {
        match self.family(b)? {
            2 => Ok(16),
            1 => Ok(usize::from(self.unix_len)),
            n if n == self.ipv6 => Ok(28),
            _ => Err(Error::Unsupported),
        }
    }
    fn write_family(self, b: &mut [u8], family: u16, n: usize) {
        if self.len_byte {
            b[0] = n as u8;
            b[1] = family as u8;
        } else {
            b[..2].copy_from_slice(&self.endian.put16(family));
        }
    }
}
/// Portable address fields. IPv6 scope/flow are preserved; Unix carries its
/// entire fixed-size native sun_path, including zeros or an abstract prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Address<'a> {
    /// IPv4 network address and host-order port.
    V4 {
        /// Four network address bytes.
        ip: [u8; 4],
        /// Host-order port.
        port: u16,
    },
    /// IPv6 network address and native flow/scope values.
    V6 {
        /// Sixteen network address bytes.
        ip: [u8; 16],
        /// Host-order port.
        port: u16,
        /// Original native flow information.
        flow: u32,
        /// Original native interface scope.
        scope: u32,
    },
    /// Fixed native Unix address payload (not necessarily a C string).
    Unix(&'a [u8]),
}
impl Address<'_> {
    /// Exact native size, validating the fixed Unix payload length.
    pub fn encoded_len(self, profile: Profile) -> Result<usize, Error> {
        match self {
            Self::V4 { .. } => Ok(16),
            Self::V6 { .. } => Ok(28),
            Self::Unix(path) if path.len() == usize::from(profile.unix_len) - 2 => {
                Ok(usize::from(profile.unix_len))
            }
            _ => Err(Error::Malformed),
        }
    }
    /// Canonical native encoding with zeroed C padding.
    pub fn encode(self, profile: Profile, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len(profile)?;
        if out.len() < n {
            return Err(Error::Capacity);
        }
        out[..n].fill(0);
        match self {
            Self::V4 { ip, port } => {
                profile.write_family(out, 2, n);
                out[2..4].copy_from_slice(&port.to_be_bytes());
                out[4..8].copy_from_slice(&ip);
            }
            Self::V6 {
                ip,
                port,
                flow,
                scope,
            } => {
                profile.write_family(out, profile.ipv6, n);
                out[2..4].copy_from_slice(&port.to_be_bytes());
                out[4..8].copy_from_slice(&profile.endian.put32(flow));
                out[8..24].copy_from_slice(&ip);
                out[24..28].copy_from_slice(&profile.endian.put32(scope));
            }
            Self::Unix(path) => {
                profile.write_family(out, 1, n);
                out[2..n].copy_from_slice(path);
            }
        }
        Ok(n)
    }
}
/// Sealed exact native-address view. Encoding it preserves the original C
/// padding/length byte instead of changing identity during IPC round trips.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawAddress<'a> {
    bytes: &'a [u8],
    profile: Profile,
}
impl<'a> RawAddress<'a> {
    /// Decode one exact sockaddr, rejecting inconsistent length/family.
    pub fn decode(bytes: &'a [u8], profile: Profile) -> Result<Self, Error> {
        if bytes.len() != profile.address_len(bytes)? {
            return Err(Error::Malformed);
        }
        Ok(Self { bytes, profile })
    }
    /// Original native bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }
    /// Original ABI profile.
    pub const fn profile(self) -> Profile {
        self.profile
    }
    /// Portable fields after structural validation.
    pub fn address(self) -> Address<'a> {
        let b = self.bytes;
        match self.profile.family(b) {
            Ok(2) => Address::V4 {
                ip: [b[4], b[5], b[6], b[7]],
                port: u16::from_be_bytes([b[2], b[3]]),
            },
            Ok(1) => Address::Unix(&b[2..]),
            _ => {
                let mut ip = [0; 16];
                ip.copy_from_slice(&b[8..24]);
                Address::V6 {
                    ip,
                    port: u16::from_be_bytes([b[2], b[3]]),
                    flow: self.profile.endian.u32([b[4], b[5], b[6], b[7]]),
                    scope: self.profile.endian.u32([b[24], b[25], b[26], b[27]]),
                }
            }
        }
    }
}
/// Validated packed native sockaddr array.
#[derive(Clone, Copy, Debug)]
pub struct Addresses<'a> {
    bytes: &'a [u8],
    count: u16,
    profile: Profile,
}
impl<'a> Addresses<'a> {
    /// Validate exactly count entries; unused trailing bytes are rejected.
    pub fn decode(bytes: &'a [u8], count: u16, profile: Profile) -> Result<Self, Error> {
        let mut at = 0usize;
        for _ in 0..count {
            at = at
                .checked_add(profile.address_len(bytes.get(at..).ok_or(Error::Truncated)?)?)
                .ok_or(Error::Overflow)?;
            if at > bytes.len() {
                return Err(Error::Truncated);
            }
        }
        if at != bytes.len() {
            return Err(Error::Malformed);
        }
        Ok(Self {
            bytes,
            count,
            profile,
        })
    }
    /// Address count on the original connection.
    pub const fn len(self) -> usize {
        self.count as usize
    }
    /// Whether no addresses were registered.
    pub const fn is_empty(self) -> bool {
        self.count == 0
    }
    /// Exact packed bytes.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }
    /// Allocation-free iterator over checked entries.
    pub fn iter(self) -> AddressIter<'a> {
        AddressIter {
            rest: self.bytes,
            left: self.count,
            profile: self.profile,
        }
    }
}
/// Iterator over validated addresses, with no unchecked user-supplied lengths.
#[derive(Clone, Debug)]
pub struct AddressIter<'a> {
    rest: &'a [u8],
    left: u16,
    profile: Profile,
}
impl<'a> Iterator for AddressIter<'a> {
    type Item = RawAddress<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.left == 0 {
            return None;
        }
        let n = self.profile.address_len(self.rest).ok()?;
        let (head, tail) = self.rest.split_at(n);
        self.rest = tail;
        self.left -= 1;
        Some(RawAddress {
            bytes: head,
            profile: self.profile,
        })
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = usize::from(self.left);
        (n, Some(n))
    }
}
impl ExactSizeIterator for AddressIter<'_> {}
/// Caller-owned native-address array builder; failed append writes nothing.
pub struct AddressWriter<'a> {
    bytes: &'a mut [u8],
    used: usize,
    count: u16,
    profile: Profile,
}
impl<'a> AddressWriter<'a> {
    /// Start an empty array in a caller buffer.
    pub fn new(bytes: &'a mut [u8], profile: Profile) -> Self {
        Self {
            bytes,
            used: 0,
            count: 0,
            profile,
        }
    }
    /// Append a canonical native address.
    pub fn push(&mut self, address: Address<'_>) -> Result<(), Error> {
        let count = self.count.checked_add(1).ok_or(Error::Capacity)?;
        let n = address.encoded_len(self.profile)?;
        let end = self.used.checked_add(n).ok_or(Error::Overflow)?;
        if end > self.bytes.len() {
            return Err(Error::Capacity);
        }
        address.encode(self.profile, &mut self.bytes[self.used..end])?;
        self.used = end;
        self.count = count;
        Ok(())
    }
    /// Borrow the validated produced array.
    pub fn addresses(&self) -> Addresses<'_> {
        Addresses {
            bytes: &self.bytes[..self.used],
            count: self.count,
            profile: self.profile,
        }
    }
}
/// Subscribe to address notifications.
pub const ADDRESSES: u8 = 1;
/// Subscribe to traversal reversal observations.
pub const REVERSAL: u8 = 2;
/// Address-class bit flags; retain unknown bits on the wire.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AddressClass(pub u32);
impl AddressClass {
    /// Unspecified class.
    pub const NONE: Self = Self(0);
    /// Other local interface.
    pub const OTHER: Self = Self(1);
    /// Highly sensitive address modifier (for example a MAC-derived IPv6 IID).
    pub const PRIVATE: Self = Self(2);
    /// Global address.
    pub const GLOBAL: Self = Self(4);
    /// LAN interface.
    pub const LAN: Self = Self(8);
    /// WLAN interface.
    pub const WLAN: Self = Self(16);
    /// Bluetooth interface.
    pub const BT: Self = Self(32);
    /// Loopback interface.
    pub const LOOPBACK: Self = Self(64);
    /// Externally learned address modifier.
    pub const EXTERN: Self = Self(128);
    /// Manual configuration modifier.
    pub const MANUAL: Self = Self(256);
    /// Any declared official class.
    pub const ANY: Self = Self(65535);
}
fn word(input: &[u8], at: usize) -> Result<u16, Error> {
    let b = input.get(at..at + 2).ok_or(Error::Truncated)?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}
fn dword(input: &[u8], at: usize) -> Result<u32, Error> {
    let b = input.get(at..at + 4).ok_or(Error::Truncated)?;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}
fn size(kind: MessageType, prefix: usize, tail: usize) -> Result<usize, Error> {
    let n = prefix.checked_add(tail).ok_or(Error::Overflow)?;
    MessageHeader::from_total_size(kind, n)?;
    Ok(n)
}
/// Active client messages. REGISTER section preserves the exact original bytes;
/// a canonical producer appends one NUL, while bounded C strndup accepts others.
#[derive(Clone, Copy, Debug)]
pub enum Request<'a> {
    /// Register once on this actual service connection.
    Register {
        /// Original notification flags.
        flags: u8,
        /// Original IP protocol.
        protocol: u8,
        /// Packed native bindings.
        addresses: Addresses<'a>,
        /// Configuration section bytes, normally final-NUL.
        section: &'a [u8],
    },
    /// Forward a received STUN packet; it does not by itself prove a transaction.
    Stun {
        /// Original datagram sender.
        sender: RawAddress<'a>,
        /// Whole STUN datagram.
        payload: &'a [u8],
    },
    /// Request the official ICMP traversal helper operation (IPv4 only).
    Reverse {
        /// Local IPv4 address/advertised port.
        local: RawAddress<'a>,
        /// Remote external IPv4 address.
        remote: RawAddress<'a>,
    },
    /// Submit a textual global IPv4 address, without NUL.
    AddGlobal {
        /// Raw literal, constrained to INET_ADDRSTRLEN-1 bytes.
        address: &'a [u8],
    },
}
impl<'a> Request<'a> {
    /// Decode exactly one official frame for the actual producer ABI.
    pub fn decode(input: &'a [u8], profile: Profile) -> Result<Self, Error> {
        let f = Frame::decode(input)?;
        match f.header().message_type() {
            mt::NAT_REGISTER => {
                input.get(..10).ok_or(Error::Truncated)?;
                let sl = usize::from(word(input, 6)?);
                let end = input.len().checked_sub(sl).ok_or(Error::Malformed)?;
                if end < 10 {
                    return Err(Error::Truncated);
                }
                Ok(Self::Register {
                    flags: input[4],
                    protocol: input[5],
                    addresses: Addresses::decode(&input[10..end], word(input, 8)?, profile)?,
                    section: &input[end..],
                })
            }
            mt::NAT_HANDLE_STUN => {
                let sn = usize::from(word(input, 4)?);
                let pn = usize::from(word(input, 6)?);
                if input.len() != 8 + sn + pn {
                    return Err(Error::Malformed);
                }
                Ok(Self::Stun {
                    sender: RawAddress::decode(&input[8..8 + sn], profile)?,
                    payload: &input[8 + sn..],
                })
            }
            mt::NAT_REQUEST_CONNECTION_REVERSAL => {
                let ln = usize::from(word(input, 4)?);
                let rn = usize::from(word(input, 6)?);
                if input.len() != 8 + ln + rn {
                    return Err(Error::Malformed);
                }
                let local = RawAddress::decode(&input[8..8 + ln], profile)?;
                let remote = RawAddress::decode(&input[8 + ln..], profile)?;
                if !matches!(
                    (local.address(), remote.address()),
                    (Address::V4 { .. }, Address::V4 { .. })
                ) {
                    return Err(Error::Unsupported);
                }
                Ok(Self::Reverse { local, remote })
            }
            mt::NAT_ADD_GLOBAL_ADDRESS => {
                let raw = dword(input, 4)?; // C assigns htons16 into a native uint32_t, then calls ntohs16 on it.
                let n = match profile.endian {
                    Endian::Little => (raw >> 16) as usize,
                    Endian::Big => raw as usize,
                };
                if n >= 16 || input.len() != 8 + n {
                    return Err(Error::Malformed);
                }
                Ok(Self::AddGlobal {
                    address: &input[8..],
                })
            }
            _ => Err(Error::Unsupported),
        }
    }
    /// Official message type.
    pub const fn message_type(self) -> MessageType {
        match self {
            Self::Register { .. } => mt::NAT_REGISTER,
            Self::Stun { .. } => mt::NAT_HANDLE_STUN,
            Self::Reverse { .. } => mt::NAT_REQUEST_CONNECTION_REVERSAL,
            Self::AddGlobal { .. } => mt::NAT_ADD_GLOBAL_ADDRESS,
        }
    }
    /// Entire frame size before any mutation of output.
    pub fn encoded_len(self, profile: Profile) -> Result<usize, Error> {
        match self {
            Self::Register {
                addresses, section, ..
            } => {
                if addresses.profile != profile || section.len() > u16::MAX as usize {
                    return Err(Error::InvalidInput);
                }
                size(
                    self.message_type(),
                    10,
                    addresses
                        .bytes
                        .len()
                        .checked_add(section.len())
                        .ok_or(Error::Overflow)?,
                )
            }
            Self::Stun { sender, payload } => {
                if sender.profile != profile
                    || payload.len() > u16::MAX as usize
                    || matches!(sender.address(), Address::Unix(_))
                {
                    return Err(Error::InvalidInput);
                }
                size(
                    self.message_type(),
                    8,
                    sender
                        .bytes
                        .len()
                        .checked_add(payload.len())
                        .ok_or(Error::Overflow)?,
                )
            }
            Self::Reverse { local, remote } => {
                if local.profile != profile
                    || remote.profile != profile
                    || !matches!(
                        (local.address(), remote.address()),
                        (Address::V4 { .. }, Address::V4 { .. })
                    )
                {
                    return Err(Error::InvalidInput);
                }
                Ok(40)
            }
            Self::AddGlobal { address } => {
                if address.len() >= 16 {
                    return Err(Error::TooLarge);
                }
                size(self.message_type(), 8, address.len())
            }
        }
    }
    /// Encode exact original native fields, including the active C global-length quirk.
    pub fn encode(self, profile: Profile, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len(profile)?;
        if out.len() < n {
            return Err(Error::Capacity);
        }
        MessageHeader::from_total_size(self.message_type(), n)?.encode(out)?;
        match self {
            Self::Register {
                flags,
                protocol,
                addresses,
                section,
            } => {
                out[4] = flags;
                out[5] = protocol;
                out[6..8].copy_from_slice(&(section.len() as u16).to_be_bytes());
                out[8..10].copy_from_slice(&addresses.count.to_be_bytes());
                let a = 10 + addresses.bytes.len();
                out[10..a].copy_from_slice(addresses.bytes);
                out[a..n].copy_from_slice(section);
            }
            Self::Stun { sender, payload } => {
                out[4..6].copy_from_slice(&(sender.bytes.len() as u16).to_be_bytes());
                out[6..8].copy_from_slice(&(payload.len() as u16).to_be_bytes());
                let a = 8 + sender.bytes.len();
                out[8..a].copy_from_slice(sender.bytes);
                out[a..n].copy_from_slice(payload);
            }
            Self::Reverse { local, remote } => {
                out[4..6].copy_from_slice(&16u16.to_be_bytes());
                out[6..8].copy_from_slice(&16u16.to_be_bytes());
                out[8..24].copy_from_slice(local.bytes);
                out[24..40].copy_from_slice(remote.bytes);
            }
            Self::AddGlobal { address } => {
                let len = address.len() as u32;
                let raw = match profile.endian {
                    Endian::Little => len << 16,
                    Endian::Big => len,
                };
                out[4..8].copy_from_slice(&raw.to_be_bytes());
                out[8..n].copy_from_slice(address);
            }
        }
        Ok(n)
    }
}
/// Actual asynchronous service notifications; none acknowledges a submitted job.
#[derive(Clone, Copy, Debug)]
pub enum Response<'a> {
    /// Add/remove an address and its class. Preserve unknown signed values;
    /// official clients interpret exactly1 as add and every other value as remove.
    AddressChange {
        /// Original signed add/remove word.
        add_remove: i32,
        /// Original class bits.
        class: AddressClass,
        /// Exact original native sockaddr.
        address: RawAddress<'a>,
    },
    /// A real observed request to reverse-connect to this remote IPv4 endpoint.
    Reverse {
        /// Remote endpoint from helper observation.
        remote: RawAddress<'a>,
    },
}
impl<'a> Response<'a> {
    /// Decode for the actual producing service ABI.
    pub fn decode(input: &'a [u8], profile: Profile) -> Result<Self, Error> {
        let f = Frame::decode(input)?;
        match f.header().message_type() {
            mt::NAT_ADDRESS_CHANGE => {
                input.get(..12).ok_or(Error::Truncated)?;
                let address = RawAddress::decode(&input[12..], profile)?;
                if matches!(address.address(), Address::Unix(_)) {
                    return Err(Error::Unsupported);
                }
                Ok(Self::AddressChange {
                    add_remove: dword(input, 4)? as i32,
                    class: AddressClass(dword(input, 8)?),
                    address,
                })
            }
            mt::NAT_CONNECTION_REVERSAL_REQUESTED => {
                let remote = RawAddress::decode(&input[4..], profile)?;
                if !matches!(remote.address(), Address::V4 { .. }) {
                    return Err(Error::Unsupported);
                }
                Ok(Self::Reverse { remote })
            }
            _ => Err(Error::Unsupported),
        }
    }
    /// Exact response size, validating the selected native ABI.
    pub fn encoded_len(self, profile: Profile) -> Result<usize, Error> {
        let (prefix, a) = match self {
            Self::AddressChange { address, .. } => (12, address),
            Self::Reverse { remote } => (4, remote),
        };
        if a.profile != profile
            || matches!(a.address(), Address::Unix(_))
            || matches!(self, Self::Reverse { .. }) && !matches!(a.address(), Address::V4 { .. })
        {
            return Err(Error::InvalidInput);
        }
        size(self.message_type(), prefix, a.bytes.len())
    }
    /// Official response type.
    pub const fn message_type(self) -> MessageType {
        match self {
            Self::AddressChange { .. } => mt::NAT_ADDRESS_CHANGE,
            Self::Reverse { .. } => mt::NAT_CONNECTION_REVERSAL_REQUESTED,
        }
    }
    /// Encode after all bounds/ABI checks.
    pub fn encode(self, profile: Profile, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len(profile)?;
        if out.len() < n {
            return Err(Error::Capacity);
        }
        MessageHeader::from_total_size(self.message_type(), n)?.encode(out)?;
        match self {
            Self::AddressChange {
                add_remove,
                class,
                address,
            } => {
                out[4..8].copy_from_slice(&add_remove.to_be_bytes());
                out[8..12].copy_from_slice(&class.0.to_be_bytes());
                out[12..n].copy_from_slice(address.bytes);
            }
            Self::Reverse { remote } => out[4..n].copy_from_slice(remote.bytes),
        }
        Ok(n)
    }
}
/// Official external gnunet-nat-server test request. `data` is two exact bytes:
/// its test producer treats it as an opaque challenge, not a host-order number.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TestRequest {
    /// Destination IPv4.
    pub destination: [u8; 4],
    /// Destination port; zero requests the ICMP technique.
    pub port: u16,
    /// Exact challenge bytes / BE16 advertised reversal port.
    pub data: [u8; 2],
    /// Original signed TCP selector (official1=TCP,0=UDP).
    pub is_tcp: i32,
}
impl TestRequest {
    /// Fixed official message size.
    pub const LEN: usize = 16;
    /// Decode exactly one test message, without fabricating a reply protocol.
    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        let f = Frame::decode(input)?;
        if f.header().message_type() != mt::NAT_TEST {
            return Err(Error::Unsupported);
        }
        if input.len() != Self::LEN {
            return Err(Error::Malformed);
        }
        Ok(Self {
            destination: [input[4], input[5], input[6], input[7]],
            port: word(input, 8)?,
            data: [input[10], input[11]],
            is_tcp: dword(input, 12)? as i32,
        })
    }
    /// Encode exact challenge bytes.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        if out.len() < Self::LEN {
            return Err(Error::Capacity);
        }
        MessageHeader::from_total_size(mt::NAT_TEST, Self::LEN)?.encode(out)?;
        out[4..8].copy_from_slice(&self.destination);
        out[8..10].copy_from_slice(&self.port.to_be_bytes());
        out[10..12].copy_from_slice(&self.data);
        out[12..16].copy_from_slice(&self.is_tcp.to_be_bytes());
        Ok(Self::LEN)
    }
}
