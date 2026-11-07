//! Standard RFC5389/8489 STUN, not a new GNUnet message dialect. The public
//! mapped address is a server claim, not authenticated identity or reachability.
//! The pinned C parser accidentally uses AF_INET(2) instead of STUN's family1
//! and skips required attribute padding; these defects are not a private mode.
use crate::address::SocketAddress;
use gnunet_types::Error;
/// Standard magic cookie.
pub const MAGIC: u32 = 0x2112_a442;
/// Header length (the length word excludes it).
pub const HEADER_LEN: usize = 20;
/// Standard Binding method.
pub const BINDING: u16 = 1;
/// MAPPED-ADDRESS attribute.
pub const MAPPED_ADDRESS: u16 = 0x0001;
/// Standard preferred XOR-MAPPED-ADDRESS attribute.
pub const XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// Legacy Microsoft XOR attribute recognized by official GNUnet.
pub const MS_XOR_MAPPED_ADDRESS: u16 = 0x8020;
/// Actual STUN message class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Class {
    /// Client request.
    Request,
    /// One-way indication.
    Indication,
    /// Success response.
    Success,
    /// Error response.
    Error,
}
impl Class {
    const fn value(self) -> u16 {
        match self {
            Self::Request => 0,
            Self::Indication => 1,
            Self::Success => 2,
            Self::Error => 3,
        }
    }
}
/// Sealed whole message; attributes are validated before exposing the view.
#[derive(Clone, Copy, Debug)]
pub struct Message<'a> {
    bytes: &'a [u8],
    transaction: &'a [u8; 12],
    method: u16,
    class: Class,
}
fn word(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}
fn type_word(method: u16, class: Class) -> Result<u16, Error> {
    if method > 0x0fff {
        return Err(Error::InvalidInput);
    }
    let c = class.value();
    Ok((method & 0x000f)
        | ((method & 0x0070) << 1)
        | ((method & 0x0f80) << 2)
        | ((c & 1) << 4)
        | ((c & 2) << 7))
}
impl<'a> Message<'a> {
    /// Parse exactly one complete STUN datagram. All attribute lengths and
    ///4-byte padding boundaries are checked once, without heap allocation.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        let h = bytes.get(..HEADER_LEN).ok_or(Error::Truncated)?;
        let t = word(h);
        if t & 0xc000 != 0 || h[4..8] != MAGIC.to_be_bytes() {
            return Err(Error::Malformed);
        }
        let n = usize::from(word(&h[2..]));
        if n & 3 != 0 || bytes.len() != HEADER_LEN + n {
            return Err(Error::Malformed);
        }
        let mut rest = &bytes[HEADER_LEN..];
        while !rest.is_empty() {
            if rest.len() < 4 {
                return Err(Error::Truncated);
            }
            let len = usize::from(word(&rest[2..]));
            let padded = len.checked_add(3).ok_or(Error::Overflow)? & !3;
            let total = 4usize.checked_add(padded).ok_or(Error::Overflow)?;
            if total > rest.len() {
                return Err(Error::Truncated);
            }
            rest = &rest[total..];
        }
        let method = (t & 15) | ((t & 0xe0) >> 1) | ((t & 0x3e00) >> 2);
        let class = match ((t & 0x10) >> 4) | ((t & 0x100) >> 7) {
            0 => Class::Request,
            1 => Class::Indication,
            2 => Class::Success,
            _ => Class::Error,
        };
        let transaction = h[8..20].try_into().map_err(|_| Error::Malformed)?;
        Ok(Self {
            bytes,
            transaction,
            method,
            class,
        })
    }
    /// Actual encoded method, without the class bits.
    pub const fn method(self) -> u16 {
        self.method
    }
    /// Actual message class.
    pub const fn class(self) -> Class {
        self.class
    }
    /// Original whole datagram.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }
    /// Original96-bit transaction id.
    pub const fn transaction(self) -> &'a [u8; 12] {
        self.transaction
    }
    /// Padded attribute iterator after validation.
    pub fn attributes(self) -> Attributes<'a> {
        Attributes {
            rest: &self.bytes[HEADER_LEN..],
        }
    }
    /// Extract the preferred advertised endpoint (standard XOR, then Microsoft
    /// XOR, then plain MAPPED), including standard IPv6 XOR with cookie+txid.
    /// This validates framing only and does not authorize the server claim.
    pub fn mapped_address(self) -> Result<Option<SocketAddress>, Error> {
        if self.method != BINDING || self.class != Class::Success {
            return Ok(None);
        }
        let mut best = None;
        let mut rank = 0u8;
        for a in self.attributes() {
            let r = match a.kind {
                MAPPED_ADDRESS => 1,
                MS_XOR_MAPPED_ADDRESS => 2,
                XOR_MAPPED_ADDRESS => 3,
                _ => continue,
            };
            if r < rank {
                continue;
            }
            let Some(address) = mapped(a.value, a.kind != MAPPED_ADDRESS, self.transaction())?
            else {
                continue;
            };
            rank = r;
            best = Some(address);
        }
        Ok(best)
    }
    /// Error code/reason attributes remain borrowed raw payloads; this helper
    /// parses the standard class/number field without claiming success.
    pub fn error_code(self) -> Result<Option<u16>, Error> {
        for a in self.attributes() {
            if a.kind == 9 {
                if a.value.len() < 4 {
                    return Err(Error::Malformed);
                }
                let class = a.value[2] & 7;
                let number = a.value[3];
                if !(3..=6).contains(&class) || number > 99 {
                    return Err(Error::Malformed);
                }
                return Ok(Some(u16::from(class) * 100 + u16::from(number)));
            }
        }
        Ok(None)
    }
}
/// Borrowed unpadded STUN attribute.
#[derive(Clone, Copy, Debug)]
pub struct Attribute<'a> {
    /// Actual standard attribute number.
    pub kind: u16,
    /// Exact payload; padding is outside this slice.
    pub value: &'a [u8],
}
/// Iterator over a sealed, validated attribute section.
#[derive(Clone, Debug)]
pub struct Attributes<'a> {
    rest: &'a [u8],
}
impl<'a> Iterator for Attributes<'a> {
    type Item = Attribute<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        let kind = word(self.rest);
        let n = usize::from(word(&self.rest[2..]));
        let value = &self.rest[4..4 + n];
        self.rest = &self.rest[4 + ((n + 3) & !3)..];
        Some(Attribute { kind, value })
    }
}
fn mapped(value: &[u8], xor: bool, transaction: &[u8; 12]) -> Result<Option<SocketAddress>, Error> {
    if value.len() < 4 {
        return Err(Error::Malformed);
    }
    if value[0] != 0 {
        return Err(Error::Malformed);
    }
    let port = word(&value[2..]) ^ if xor { (MAGIC >> 16) as u16 } else { 0 };
    match value[1] {
        1 => {
            if value.len() != 8 {
                return Err(Error::Malformed);
            }
            let mut ip = [0; 4];
            ip.copy_from_slice(&value[4..8]);
            if xor {
                for (a, b) in ip.iter_mut().zip(MAGIC.to_be_bytes()) {
                    *a ^= b;
                }
            }
            Ok(Some(SocketAddress::V4 { ip, port }))
        }
        2 => {
            if value.len() != 20 {
                return Err(Error::Malformed);
            }
            let mut ip = [0; 16];
            ip.copy_from_slice(&value[4..20]);
            if xor {
                let cookie = MAGIC.to_be_bytes();
                for i in 0..16 {
                    ip[i] ^= if i < 4 { cookie[i] } else { transaction[i - 4] };
                }
            }
            Ok(Some(SocketAddress::V6 {
                ip,
                port,
                scope: 0,
                flow: 0,
            }))
        }
        _ => Ok(None),
    }
}
/// Encode the actual20-byte public Binding request. The caller must supply
/// a fresh96-bit transaction from a real entropy source; this function creates none.
pub fn binding_request(transaction: &[u8; 12], out: &mut [u8]) -> Result<usize, Error> {
    if out.len() < HEADER_LEN {
        return Err(Error::Capacity);
    }
    out[..20].fill(0);
    out[..2].copy_from_slice(&1u16.to_be_bytes());
    out[4..8].copy_from_slice(&MAGIC.to_be_bytes());
    out[8..20].copy_from_slice(transaction);
    Ok(20)
}
/// Bounded caller-owned message builder for real STUN attributes.
pub struct Writer<'a> {
    out: &'a mut [u8],
    used: usize,
}
impl<'a> Writer<'a> {
    /// Start an actual standard STUN message in caller storage.
    pub fn new(
        out: &'a mut [u8],
        method: u16,
        class: Class,
        transaction: &[u8; 12],
    ) -> Result<Self, Error> {
        let t = type_word(method, class)?;
        if out.len() < 20 {
            return Err(Error::Capacity);
        }
        out[..20].fill(0);
        out[..2].copy_from_slice(&t.to_be_bytes());
        out[4..8].copy_from_slice(&MAGIC.to_be_bytes());
        out[8..20].copy_from_slice(transaction);
        Ok(Self { out, used: 20 })
    }
    /// Append an attribute atomically after complete capacity/length checks.
    pub fn push(&mut self, kind: u16, value: &[u8]) -> Result<(), Error> {
        let n = u16::try_from(value.len()).map_err(|_| Error::TooLarge)?;
        let padded = value.len().checked_add(3).ok_or(Error::Overflow)? & !3;
        let end = self
            .used
            .checked_add(4)
            .and_then(|n| n.checked_add(padded))
            .ok_or(Error::Overflow)?;
        let len = u16::try_from(end - 20).map_err(|_| Error::TooLarge)?;
        if end > self.out.len() {
            return Err(Error::Capacity);
        }
        self.out[self.used..self.used + 2].copy_from_slice(&kind.to_be_bytes());
        self.out[self.used + 2..self.used + 4].copy_from_slice(&n.to_be_bytes());
        self.out[self.used + 4..self.used + 4 + value.len()].copy_from_slice(value);
        self.out[self.used + 4 + value.len()..end].fill(0);
        self.out[2..4].copy_from_slice(&len.to_be_bytes());
        self.used = end;
        Ok(())
    }
    /// Borrow the actual encoded datagram.
    pub fn as_bytes(&self) -> &[u8] {
        &self.out[..self.used]
    }
}
/// Original transaction/source/deadline correlation. Construction is an intent;
/// `written` is called only after the real complete UDP datagram send succeeds.
#[derive(Clone, Copy, Debug)]
pub struct Transaction {
    id: [u8; 12],
    server: SocketAddress,
    expires: u64,
    state: TransactionState,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransactionState {
    Prepared,
    Written,
    Complete,
    Cancelled,
}
impl Transaction {
    /// Prepare a finite original transaction, without claiming any datagram IO.
    pub fn new(id: [u8; 12], server: SocketAddress, expires: u64, now: u64) -> Result<Self, Error> {
        if server.port() == 0 || server.is_unspecified() || expires <= now {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            id,
            server,
            expires,
            state: TransactionState::Prepared,
        })
    }
    /// Whole-datagram successful write on the original socket.
    pub fn written(&mut self, now: u64) -> Result<(), Error> {
        if now >= self.expires {
            return Err(Error::Deadline);
        }
        if self.state != TransactionState::Prepared {
            return Err(Error::Conflict);
        }
        self.state = TransactionState::Written;
        Ok(())
    }
    /// Validate the original sender, transaction, deadline and successful
    /// response before consuming this one-shot result. No remote reachability
    /// proof or authentication is inferred from a public STUN claim.
    pub fn receive(
        &mut self,
        sender: SocketAddress,
        bytes: &[u8],
        now: u64,
    ) -> Result<Option<SocketAddress>, Error> {
        if now >= self.expires {
            return Err(Error::Deadline);
        }
        if self.state != TransactionState::Written {
            return Err(Error::Stale);
        }
        if sender != self.server {
            return Ok(None);
        }
        let message = Message::decode(bytes)?;
        if message.transaction() != &self.id {
            return Ok(None);
        }
        if message.method() != BINDING {
            return Ok(None);
        }
        if message.class() == Class::Error {
            self.state = TransactionState::Complete;
            return Err(Error::Unavailable);
        }
        let Some(address) = message.mapped_address()? else {
            return Ok(None);
        };
        self.state = TransactionState::Complete;
        Ok(Some(address))
    }
    /// Original native cancellation suppresses any late result; no wire cancel.
    pub fn cancel(&mut self) {
        self.state = TransactionState::Cancelled;
    }
    /// Original absolute caller-clock deadline, never refreshed by traffic.
    pub const fn expires(&self) -> u64 {
        self.expires
    }
    /// Original expected server endpoint.
    pub const fn server(&self) -> SocketAddress {
        self.server
    }
    /// Original public transaction id.
    pub const fn id(&self) -> &[u8; 12] {
        &self.id
    }
}
