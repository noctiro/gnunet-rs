use crate::{AbsoluteTime, Arena, Error, Name, Type, expiration_ttl};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Native MX preference and exchanger name.
pub struct Mx<'a> {
    /// MX preference, in host byte order.
    pub preference: u16,
    /// Uncompressed mail exchanger name.
    pub host: Name<'a>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Native SRV numeric fields and target name.
pub struct Srv<'a> {
    /// Unsigned priority in host byte order.
    pub priority: u16,
    /// Unsigned relative weight in host byte order.
    pub weight: u16,
    /// Service port, in host byte order.
    pub port: u16,
    /// Complete target name or opaque URI bytes, according to the surrounding type.
    pub target: Name<'a>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Native SOA names and all five scalar fields.
pub struct Soa<'a> {
    /// Primary zone name server.
    pub mname: Name<'a>,
    /// Responsible mailbox in DNS name form.
    pub rname: Name<'a>,
    /// Zone serial number.
    pub serial: u32,
    /// Refresh interval in seconds.
    pub refresh: u32,
    /// Retry interval in seconds.
    pub retry: u32,
    /// Zone expiry interval in seconds.
    pub expire: u32,
    /// SOA minimum TTL in seconds.
    pub minimum_ttl: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// RFC7553 priority, weight and complete target octets.
pub struct Uri<'a> {
    /// Unsigned priority in host byte order.
    pub priority: u16,
    /// Unsigned relative weight in host byte order.
    pub weight: u16,
    /// Complete target name or opaque URI bytes, according to the surrounding type.
    pub target: &'a [u8],
}
/// RFC4398 uses exactly five metadata octets; no native padding is serialized.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// RFC4398 certificate metadata and complete certificate octets.
pub struct Cert<'a> {
    /// Certificate type number; unknown16-bit values are retained.
    pub cert_type: u16,
    /// Certificate key tag.
    pub key_tag: u16,
    /// Certificate algorithm number; unknown8-bit values are retained.
    pub algorithm: u8,
    /// Complete typed or opaque record payload.
    pub data: &'a [u8],
}
/// Public native certificate type assignments; other in-width values remain representable.
pub mod cert_type {
    /// Numeric public DNS assignment RESERVED=0.
    pub const RESERVED: u16 = 0;
    /// Numeric public DNS assignment PKIX=1.
    pub const PKIX: u16 = 1;
    /// Numeric public DNS assignment SKPI=2.
    pub const SKPI: u16 = 2;
    /// Numeric public DNS assignment PGP=3.
    pub const PGP: u16 = 3;
    /// Numeric public DNS assignment IPKIX=4.
    pub const IPKIX: u16 = 4;
    /// Numeric public DNS assignment ISKPI=5.
    pub const ISKPI: u16 = 5;
    /// Numeric public DNS assignment IPGP=6.
    pub const IPGP: u16 = 6;
    /// Numeric public DNS assignment ACPKIX=7.
    pub const ACPKIX: u16 = 7;
    /// Numeric public DNS assignment IACKPIX=8.
    pub const IACKPIX: u16 = 8;
}
/// Public native certificate algorithm assignments; other in-width values remain representable.
pub mod cert_algorithm {
    /// Numeric public DNS assignment UNDEFINED=0.
    pub const UNDEFINED: u8 = 0;
    /// Numeric public DNS assignment RSAMD5=1.
    pub const RSAMD5: u8 = 1;
    /// Numeric public DNS assignment DH=2.
    pub const DH: u8 = 2;
    /// Numeric public DNS assignment DSASHA=3.
    pub const DSASHA: u8 = 3;
    /// Numeric public DNS assignment RSRVD4=4.
    pub const RSRVD4: u8 = 4;
    /// Numeric public DNS assignment RSASHA=5.
    pub const RSASHA: u8 = 5;
    /// Numeric public DNS assignment DSANSEC3=6.
    pub const DSANSEC3: u8 = 6;
    /// Numeric public DNS assignment RSANSEC3=7.
    pub const RSANSEC3: u8 = 7;
    /// Numeric public DNS assignment RSASHA256=8.
    pub const RSASHA256: u8 = 8;
    /// Numeric public DNS assignment RSRVD9=9.
    pub const RSRVD9: u8 = 9;
    /// Numeric public DNS assignment RSASHA512=10.
    pub const RSASHA512: u8 = 10;
    /// Numeric public DNS assignment GOST_R34=12.
    pub const GOST_R34: u8 = 12;
    /// Numeric public DNS assignment ECDSA_P256SHA256=13.
    pub const ECDSA_P256SHA256: u8 = 13;
    /// Numeric public DNS assignment ECDSA_P384SHA384=14.
    pub const ECDSA_P384SHA384: u8 = 14;
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Public CAA flags and tag-length view; record bodies otherwise remain raw.
pub struct CaaHeader {
    /// Lossless native DNS/CAA flag bits.
    pub flags: u8,
    /// Number of CAA tag octets following the header.
    pub tag_len: u8,
}
impl CaaHeader {
    /// Parse a bounded input into caller-owned storage; return no partial typed result.
    pub fn parse(rdata: &[u8]) -> Result<Self, Error> {
        let h = Self {
            flags: *rdata.first().ok_or(Error::Truncated)?,
            tag_len: *rdata.get(1).ok_or(Error::Truncated)?,
        };
        if usize::from(h.tag_len) > rdata.len() - 2 {
            return Err(Error::Truncated);
        }
        Ok(h)
    }
    /// Borrow the complete CAA tag after checking its declared bound.
    pub fn tag(self, rdata: &[u8]) -> Result<&[u8], Error> {
        rdata
            .get(2..2 + usize::from(self.tag_len))
            .ok_or(Error::Truncated)
    }
    /// Borrow the CAA value following the declared tag.
    pub fn value(self, rdata: &[u8]) -> Result<&[u8], Error> {
        rdata
            .get(2 + usize::from(self.tag_len)..)
            .ok_or(Error::Truncated)
    }
    /// Preflight and encode the complete value; errors preserve the complete output slice.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        if output.len() < 2 {
            return Err(Error::Capacity);
        }
        output[..2].copy_from_slice(&[self.flags, self.tag_len]);
        Ok(2)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Complete native structured variants plus lossless opaque RDATA.
pub enum RData<'a> {
    /// NS/CNAME/PTR/DNAME uncompressed target name.
    Hostname(Name<'a>),
    /// Both SOA names and five32-bit scalars.
    Soa(Soa<'a>),
    /// MX preference and exchanger.
    Mx(Mx<'a>),
    /// SRV priority, weight, port and target.
    Srv(Srv<'a>),
    /// Complete URI target octets and both scalars.
    Uri(Uri<'a>),
    /// Certificate fields with a five-byte wire prefix.
    Cert(Cert<'a>),
    /// Opaque RDATA for every unstructured or unknown type.
    Raw(&'a [u8]),
}
impl<'a> RData<'a> {
    /// Arena bytes needed for a deep payload copy, excluding scalar metadata.
    pub fn copied_bytes(self) -> Result<usize, Error> {
        Ok(match self {
            Self::Hostname(name) => name.wire_len(),
            Self::Mx(mx) => mx.host.wire_len(),
            Self::Srv(srv) => srv.target.wire_len(),
            Self::Soa(soa) => soa
                .mname
                .wire_len()
                .checked_add(soa.rname.wire_len())
                .ok_or(Error::Overflow)?,
            Self::Cert(cert) => cert.data.len(),
            Self::Uri(uri) => uri.target.len(),
            Self::Raw(bytes) => bytes.len(),
        })
    }

    /// Compute checked encoded byte length before any output mutation.
    pub fn encoded_len(self) -> Result<usize, Error> {
        let n = match self {
            Self::Hostname(n) => n.wire_len(),
            Self::Mx(m) => 2 + m.host.wire_len(),
            Self::Srv(s) => 6 + s.target.wire_len(),
            Self::Soa(s) => s.mname.wire_len() + s.rname.wire_len() + 20,
            Self::Cert(c) => 5_usize.checked_add(c.data.len()).ok_or(Error::Overflow)?,
            Self::Uri(u) => {
                if u.target.is_empty() {
                    return Err(Error::Malformed);
                }
                4_usize.checked_add(u.target.len()).ok_or(Error::Overflow)?
            }
            Self::Raw(b) => b.len(),
        };
        u16::try_from(n).map_err(|_| Error::TooLarge)?;
        Ok(n)
    }
    /// Preflight and encode the complete value; errors preserve the complete output slice.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len()?;
        if output.len() < n {
            return Err(Error::Capacity);
        }
        let mut w = Write::new(output);
        self.write(&mut w);
        Ok(n)
    }
    /// Append atomically; unlike unsafe C partial writers, refusal preserves both
    /// cursor and the entire destination. The encoded success bytes are identical.
    /// Append atomically; errors preserve the complete destination and cursor.
    pub fn encode_at(self, output: &mut [u8], offset: &mut usize) -> Result<usize, Error> {
        let n = self.encoded_len()?;
        let end = offset.checked_add(n).ok_or(Error::Overflow)?;
        if end > output.len() {
            return Err(Error::Capacity);
        }
        self.encode(&mut output[*offset..end])?;
        *offset = end;
        Ok(n)
    }
    pub(crate) fn write(self, w: &mut Write<'_>) {
        match self {
            Self::Hostname(n) => w.bytes(n.wire()),
            Self::Mx(m) => {
                w.u16(m.preference);
                w.bytes(m.host.wire());
            }
            Self::Srv(s) => {
                w.u16(s.priority);
                w.u16(s.weight);
                w.u16(s.port);
                w.bytes(s.target.wire());
            }
            Self::Soa(s) => {
                w.bytes(s.mname.wire());
                w.bytes(s.rname.wire());
                for n in [s.serial, s.refresh, s.retry, s.expire, s.minimum_ttl] {
                    w.u32(n);
                }
            }
            Self::Uri(u) => {
                w.u16(u.priority);
                w.u16(u.weight);
                w.bytes(u.target);
            }
            Self::Cert(c) => {
                w.u16(c.cert_type);
                w.u16(c.key_tag);
                w.byte(c.algorithm);
                w.bytes(c.data);
            }
            Self::Raw(b) => w.bytes(b),
        }
    }
    /// Deep-copy every borrowed name/payload into independent caller arena storage.
    pub fn duplicate_into<'b>(self, a: &mut Arena<'b>) -> Result<RData<'b>, Error> {
        Ok(match self {
            Self::Hostname(n) => RData::Hostname(n.duplicate_into(a)?),
            Self::Mx(m) => RData::Mx(Mx {
                preference: m.preference,
                host: m.host.duplicate_into(a)?,
            }),
            Self::Srv(s) => RData::Srv(Srv {
                priority: s.priority,
                weight: s.weight,
                port: s.port,
                target: s.target.duplicate_into(a)?,
            }),
            Self::Soa(s) => RData::Soa(Soa {
                mname: s.mname.duplicate_into(a)?,
                rname: s.rname.duplicate_into(a)?,
                serial: s.serial,
                refresh: s.refresh,
                retry: s.retry,
                expire: s.expire,
                minimum_ttl: s.minimum_ttl,
            }),
            Self::Uri(u) => RData::Uri(Uri {
                priority: u.priority,
                weight: u.weight,
                target: a.copy(u.target)?,
            }),
            Self::Cert(c) => RData::Cert(Cert {
                cert_type: c.cert_type,
                key_tag: c.key_tag,
                algorithm: c.algorithm,
                data: a.copy(c.data)?,
            }),
            Self::Raw(b) => RData::Raw(a.copy(b)?),
        })
    }
}
macro_rules! data_methods {
    ($name:ident,$variant:ident) => {
        impl<'a> $name<'a> {
            /// Compute checked encoded byte length before any output mutation.
            pub fn encoded_len(self) -> Result<usize, Error> {
                RData::$variant(self).encoded_len()
            }
            /// Preflight and encode the complete value; errors preserve the complete output slice.
            pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
                RData::$variant(self).encode(out)
            }
            /// Deep-copy every borrowed name/payload into independent caller arena storage.
            pub fn duplicate_into<'b>(self, a: &mut Arena<'b>) -> Result<$name<'b>, Error> {
                match RData::$variant(self).duplicate_into(a)? {
                    RData::$variant(v) => Ok(v),
                    _ => Err(Error::Malformed),
                }
            }
        }
    };
}
data_methods!(Mx, Mx);
data_methods!(Srv, Srv);
data_methods!(Soa, Soa);
data_methods!(Uri, Uri);
data_methods!(Cert, Cert);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// DNS resource record with explicit absolute expiration.
pub struct Record<'a> {
    /// Record owner or query name, retaining original wire label octets.
    pub name: Name<'a>,
    /// Lossless DNS type number.
    pub kind: Type,
    /// Lossless DNS class number.
    pub class: u16,
    /// Caller-clock absolute microsecond expiration.
    pub expiration: AbsoluteTime,
    /// Complete typed or opaque record payload.
    pub data: RData<'a>,
}
impl<'a> Record<'a> {
    /// Empty placeholder for caller-owned object slots.
    pub const EMPTY: Self = Self {
        name: Name::ROOT,
        kind: Type(0),
        class: 0,
        expiration: AbsoluteTime::UNIX_EPOCH,
        data: RData::Raw(&[]),
    };
    /// Validate type/payload consistency and compute the16-bit RDATA length.
    pub fn data_len(self) -> Result<usize, Error> {
        let valid = match self.data {
            RData::Hostname(_) => self.kind.is_hostname(),
            RData::Soa(_) => self.kind == Type::SOA,
            RData::Mx(_) => self.kind == Type::MX,
            RData::Srv(_) => self.kind == Type::SRV,
            RData::Cert(_) => self.kind == Type::CERT,
            RData::Uri(_) => self.kind == Type::URI,
            RData::Raw(_) => !self.kind.is_structured(),
        };
        if !valid {
            return Err(Error::InvalidInput);
        }
        self.data.encoded_len()
    }
    /// Compute checked encoded byte length before any output mutation.
    pub fn encoded_len(self) -> Result<usize, Error> {
        let data = self.data_len()?;
        self.name
            .wire_len()
            .checked_add(10)
            .and_then(|n| n.checked_add(data))
            .ok_or(Error::Overflow)
    }
    /// Preflight and encode the complete value; errors preserve the complete output slice.
    pub fn encode(self, now: AbsoluteTime, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len()?;
        if out.len() < n {
            return Err(Error::Capacity);
        }
        let mut w = Write::new(out);
        self.write(now, &mut w)?;
        Ok(n)
    }
    pub(crate) fn write(self, now: AbsoluteTime, w: &mut Write<'_>) -> Result<(), Error> {
        let data_len = self.data_len()?;
        w.bytes(self.name.wire());
        w.u16(self.kind.0);
        w.u16(self.class);
        w.u32(expiration_ttl(self.expiration, now));
        w.u16(data_len as u16);
        self.data.write(w);
        Ok(())
    }
    /// Deep-copy every borrowed name/payload into independent caller arena storage.
    pub fn duplicate_into<'b>(self, a: &mut Arena<'b>) -> Result<Record<'b>, Error> {
        Ok(Record {
            name: self.name.duplicate_into(a)?,
            kind: self.kind,
            class: self.class,
            expiration: self.expiration,
            data: self.data.duplicate_into(a)?,
        })
    }
}
pub(crate) struct Write<'a> {
    pub(crate) out: &'a mut [u8],
    pub(crate) pos: usize,
}
impl<'a> Write<'a> {
    pub(crate) fn new(out: &'a mut [u8]) -> Self {
        Self { out, pos: 0 }
    }
    pub(crate) fn bytes(&mut self, b: &[u8]) {
        self.out[self.pos..self.pos + b.len()].copy_from_slice(b);
        self.pos += b.len();
    }
    pub(crate) fn byte(&mut self, b: u8) {
        self.out[self.pos] = b;
        self.pos += 1;
    }
    pub(crate) fn u16(&mut self, n: u16) {
        self.bytes(&n.to_be_bytes());
    }
    pub(crate) fn u32(&mut self, n: u32) {
        self.bytes(&n.to_be_bytes());
    }
}
