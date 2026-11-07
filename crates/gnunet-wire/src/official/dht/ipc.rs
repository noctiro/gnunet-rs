//! Official DHT application IPC, independent of service and block authority.
//!
//! Local request IDs are opaque eight bytes. They never appear in P2P RESULT.
//! PUT has no service acknowledgement. Message152 is a registry TODO, not an ACK.
use super::{Path, Reader, array, start, total_len};
use crate::official::{AbsoluteTime, Frame, message_type};
use gnunet_types::Error;

/// Opaque local-MQ GET correlation bytes, copied unchanged by the C API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestId(pub [u8; 8]);
/// Complete local GET fixed-header length.
pub const GET_FIXED_LEN: usize = 88;
/// Complete local PUT fixed-header length.
pub const PUT_FIXED_LEN: usize = 88;
/// Complete local result fixed-header length.
pub const RESULT_FIXED_LEN: usize = 104;
/// Complete GET stop / known-results fixed-header length.
pub const CONTROL_FIXED_LEN: usize = 80;
/// Complete monitor registration length.
pub const MONITOR_LEN: usize = 80;

/// Local PUT request. Block validation and replication remain separate decisions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Put<'a> {
    /// Official block type.
    pub block_type: u32,
    /// Full32-bit application route flags.
    pub options: u32,
    /// Requested replication, before routing policy bounds it.
    pub replication: u32,
    /// Absolute expiration in microseconds.
    pub expiration: AbsoluteTime,
    /// Caller-selected storage key.
    pub key: &'a [u8; 64],
    /// Original block bytes.
    pub payload: &'a [u8],
}
impl Put<'_> {
    /// Size of the original official frame.
    pub fn encoded_len(self) -> Result<usize, Error> {
        total_len(PUT_FIXED_LEN, &[self.payload])
    }
    /// Encode atomically with respect to length/resource refusal.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len()?;
        let mut w = start(out, n, message_type::DHT_CLIENT_PUT)?;
        w.u32(self.block_type)?;
        w.u32(self.options)?;
        w.u32(self.replication)?;
        w.u64(self.expiration.as_micros())?;
        w.put(self.key)?;
        w.put(self.payload)?;
        Ok(n)
    }
}
/// Original local GET. Multiple operations may use the same key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Get<'a> {
    /// Full application route flags.
    pub options: u32,
    /// Requested replication level.
    pub replication: u32,
    /// Block type, including ANY0.
    pub block_type: u32,
    /// Query key.
    pub key: &'a [u8; 64],
    /// Correlation confined to the original local MQ.
    pub id: RequestId,
    /// Plugin-specific query bytes, not interpreted by this codec.
    pub extended_query: &'a [u8],
}
impl Get<'_> {
    /// Original frame extent.
    pub fn encoded_len(self) -> Result<usize, Error> {
        total_len(GET_FIXED_LEN, &[self.extended_query])
    }
    /// Encode without treating request bytes as a network identifier.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len()?;
        let mut w = start(out, n, message_type::DHT_CLIENT_GET)?;
        w.u32(self.options)?;
        w.u32(self.replication)?;
        w.u32(self.block_type)?;
        w.put(self.key)?;
        w.put(&self.id.0)?;
        w.put(self.extended_query)?;
        Ok(n)
    }
}
/// Stop only the matching key/ID on the original client connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stop<'a> {
    /// Original opaque correlation bytes.
    pub id: RequestId,
    /// Original query key.
    pub key: &'a [u8; 64],
}
impl Stop<'_> {
    /// Fixed official80-byte request.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = start(out, CONTROL_FIXED_LEN, message_type::DHT_CLIENT_GET_STOP)?;
        w.u32(0)?;
        w.put(&self.id.0)?;
        w.put(self.key)?;
        Ok(CONTROL_FIXED_LEN)
    }
}
/// Structurally validated consecutive64-byte result hashes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Hashes<'a>(&'a [u8]);
impl<'a> Hashes<'a> {
    /// Validate complete hash extents; no result is marked authoritative.
    pub fn new(bytes: &'a [u8]) -> Result<Self, Error> {
        if !bytes.len().is_multiple_of(64) {
            return Err(Error::Malformed);
        }
        Ok(Self(bytes))
    }
    /// Original serialized bytes.
    #[must_use]
    pub const fn as_bytes(self) -> &'a [u8] {
        self.0
    }
    /// Iterate original hashes without allocation.
    pub fn iter(self) -> impl ExactSizeIterator<Item = &'a [u8; 64]> {
        self.0.as_chunks::<64>().0.iter()
    }
}
/// Caller-known results are filters, not validation or completion proofs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Known<'a> {
    /// Original query key.
    pub key: &'a [u8; 64],
    /// Original MQ-local ID.
    pub id: RequestId,
    /// Hashes of complete block payloads.
    pub hashes: Hashes<'a>,
}
impl Known<'_> {
    /// Exact original frame extent.
    pub fn encoded_len(self) -> Result<usize, Error> {
        total_len(CONTROL_FIXED_LEN, &[self.hashes.as_bytes()])
    }
    /// Encode the original identity and hashes.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len()?;
        let mut w = start(out, n, message_type::DHT_CLIENT_GET_RESULTS_KNOWN)?;
        w.u32(0)?;
        w.put(self.key)?;
        w.put(&self.id.0)?;
        w.put(self.hashes.as_bytes())?;
        Ok(n)
    }
}
/// Original monitor selectors. Nonzero flags retain their original16-bit values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Monitor<'a> {
    /// Block type, including ANY0.
    pub block_type: u32,
    /// GET notifications requested when nonzero.
    pub get: u16,
    /// RESULT notifications requested when nonzero.
    pub get_response: u16,
    /// PUT notifications requested when nonzero.
    pub put: u16,
    /// Optional exact key; an all-zero key is not silently changed to None.
    pub key: Option<&'a [u8; 64]>,
}
impl Monitor<'_> {
    /// Encode START153 or STOP154, preserving selector fields.
    pub fn encode(self, stop: bool, out: &mut [u8]) -> Result<usize, Error> {
        let kind = if stop {
            message_type::DHT_MONITOR_STOP
        } else {
            message_type::DHT_MONITOR_START
        };
        let mut w = start(out, MONITOR_LEN, kind)?;
        w.u32(self.block_type)?;
        w.u16(self.get)?;
        w.u16(self.get_response)?;
        w.u16(self.put)?;
        w.u16(u16::from(self.key.is_some()))?;
        w.put(self.key.unwrap_or(&[0; 64]))?;
        Ok(MONITOR_LEN)
    }
}
/// One complete local client request, without any successful-service assertion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Request<'a> {
    /// Publish a block; no service acknowledgement exists.
    Put(Put<'a>),
    /// Start an original GET.
    Get(Get<'a>),
    /// Cancel original GET correlation.
    Stop(Stop<'a>),
    /// Extend its known-result filter.
    Known(Known<'a>),
    /// Register a monitor.
    MonitorStart(Monitor<'a>),
    /// Remove one original matching monitor.
    MonitorStop(Monitor<'a>),
    /// Request current HELLO URL.
    HelloGet,
    /// Offer an original URL. None is valid only as a service reply.
    HelloUrl(Option<&'a [u8]>),
}
impl<'a> Request<'a> {
    /// Parse exactly one complete official frame. No allocation or block checking.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let frame = Frame::decode(input)?;
        let mut r = Reader::new(frame.payload());
        let value = match frame.header().message_type() {
            message_type::DHT_CLIENT_PUT => Self::Put(Put {
                block_type: r.u32()?,
                options: r.u32()?,
                replication: r.u32()?,
                expiration: AbsoluteTime::from_micros(r.u64()?),
                key: array(&mut r)?,
                payload: r.take(r.remaining())?,
            }),
            message_type::DHT_CLIENT_GET => Self::Get(Get {
                options: r.u32()?,
                replication: r.u32()?,
                block_type: r.u32()?,
                key: array(&mut r)?,
                id: RequestId(*array(&mut r)?),
                extended_query: r.take(r.remaining())?,
            }),
            message_type::DHT_CLIENT_GET_STOP => {
                reserved(&mut r)?;
                Self::Stop(Stop {
                    id: RequestId(*array(&mut r)?),
                    key: array(&mut r)?,
                })
            }
            message_type::DHT_CLIENT_GET_RESULTS_KNOWN => {
                reserved(&mut r)?;
                Self::Known(Known {
                    key: array(&mut r)?,
                    id: RequestId(*array(&mut r)?),
                    hashes: Hashes::new(r.take(r.remaining())?)?,
                })
            }
            message_type::DHT_MONITOR_START | message_type::DHT_MONITOR_STOP => {
                let kind = r.u32()?;
                let get = r.u16()?;
                let get_response = r.u16()?;
                let put = r.u16()?;
                let filter = r.u16()?;
                let key = array(&mut r)?;
                let monitor = Monitor {
                    block_type: kind,
                    get,
                    get_response,
                    put,
                    key: (filter != 0).then_some(key),
                };
                if frame.header().message_type() == message_type::DHT_MONITOR_START {
                    Self::MonitorStart(monitor)
                } else {
                    Self::MonitorStop(monitor)
                }
            }
            message_type::DHT_CLIENT_HELLO_GET => Self::HelloGet,
            message_type::DHT_CLIENT_HELLO_URL => {
                let bytes = r.take(r.remaining())?;
                Self::HelloUrl(url(bytes)?)
            }
            _ => return Err(Error::Unsupported),
        };
        if r.remaining() != 0 {
            return Err(Error::InvalidInput);
        }
        Ok(value)
    }
}
/// A result for one original local GET, never a network request identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResultMessage<'a> {
    /// Concrete returned block type.
    pub block_type: u32,
    /// Full route metadata flags.
    pub options: u32,
    /// Original PUT path.
    pub put_path: Path<'a>,
    /// Original GET path.
    pub get_path: Path<'a>,
    /// Original local-MQ GET correlation.
    pub id: RequestId,
    /// Block expiration.
    pub expiration: AbsoluteTime,
    /// Query key, which may differ from an approximate block's own key.
    pub key: &'a [u8; 64],
    /// Present exactly when TRUNCATED is set.
    pub truncated_peer: Option<&'a [u8; 32]>,
    /// Complete block bytes, still unvalidated by this codec.
    pub payload: &'a [u8],
}
impl<'a> ResultMessage<'a> {
    /// Decode exact official local result145.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let frame = Frame::decode(input)?;
        if frame.header().message_type() != message_type::DHT_CLIENT_RESULT {
            return Err(Error::Unsupported);
        }
        let mut r = Reader::new(frame.payload());
        let block_type = r.u32()?;
        reserved(&mut r)?;
        let options = r.u32()?;
        let pn = r.u32()?;
        let gn = r.u32()?;
        let id = RequestId(*array(&mut r)?);
        let expiration = AbsoluteTime::from_micros(r.u64()?);
        let key = array(&mut r)?;
        let truncated_peer = if options & 8 != 0 {
            Some(array(&mut r)?)
        } else {
            None
        };
        let put_path = path32(pn, &mut r)?;
        let get_path = path32(gn, &mut r)?;
        let payload = r.take(r.remaining())?;
        Ok(Self {
            block_type,
            options,
            put_path,
            get_path,
            id,
            expiration,
            key,
            truncated_peer,
            payload,
        })
    }
    /// Validate flags and all original frame extents before modifying output.
    pub fn encoded_len(self) -> Result<usize, Error> {
        if (self.options & 8 != 0) != self.truncated_peer.is_some() {
            return Err(Error::InvalidInput);
        }
        total_len(
            RESULT_FIXED_LEN,
            &[
                self.truncated_peer.map_or(&[][..], |p| &p[..]),
                self.put_path.as_bytes(),
                self.get_path.as_bytes(),
                self.payload,
            ],
        )
    }
    /// Encode the original local ID bytes and official fields.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len()?;
        let mut w = start(out, n, message_type::DHT_CLIENT_RESULT)?;
        w.u32(self.block_type)?;
        w.u32(0)?;
        w.u32(self.options)?;
        w.u32(u32::try_from(self.put_path.len()).map_err(|_| Error::TooLarge)?)?;
        w.u32(u32::try_from(self.get_path.len()).map_err(|_| Error::TooLarge)?)?;
        w.put(&self.id.0)?;
        w.u64(self.expiration.as_micros())?;
        w.put(self.key)?;
        if let Some(peer) = self.truncated_peer {
            w.put(peer)?;
        }
        w.put(self.put_path.as_bytes())?;
        w.put(self.get_path.as_bytes())?;
        w.put(self.payload)?;
        Ok(n)
    }
}
/// Encode HELLO request161 or URL159, where None is a valid empty service reply.
pub fn encode_hello(url: Option<&[u8]>, request: bool, out: &mut [u8]) -> Result<usize, Error> {
    if request {
        if url.is_some() {
            return Err(Error::InvalidInput);
        }
        start(out, 4, message_type::DHT_CLIENT_HELLO_GET)?;
        return Ok(4);
    }
    if url.is_some_and(|u| u.contains(&0)) {
        return Err(Error::InvalidInput);
    }
    let n = total_len(
        4,
        &[url.unwrap_or(&[]), if url.is_some() { &[0] } else { &[] }],
    )?;
    let mut w = start(out, n, message_type::DHT_CLIENT_HELLO_URL)?;
    if let Some(u) = url {
        w.put(u)?;
        w.put(&[0])?;
    }
    Ok(n)
}
fn url(bytes: &[u8]) -> Result<Option<&[u8]>, Error> {
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.last() != Some(&0) || bytes[..bytes.len() - 1].contains(&0) {
        return Err(Error::Malformed);
    }
    Ok(Some(&bytes[..bytes.len() - 1]))
}
fn reserved(r: &mut Reader<'_>) -> Result<(), Error> {
    if r.u32()? != 0 {
        return Err(Error::InvalidInput);
    }
    Ok(())
}
fn path32<'a>(count: u32, r: &mut Reader<'a>) -> Result<Path<'a>, Error> {
    let n = usize::try_from(count)
        .map_err(|_| Error::TooLarge)?
        .checked_mul(super::PATH_ELEMENT_LEN)
        .ok_or(Error::Overflow)?;
    Path::new(r.take(n)?)
}

/// Actual fixed-size GET monitor149; it contains no serialized GET path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MonitorGet<'a> {
    /// Application route flags.
    pub options: u32,
    /// Requested type, including ANY.
    pub block_type: u32,
    /// Actual hop count.
    pub hop_count: u32,
    /// Requested replication.
    pub replication: u32,
    /// Original query key.
    pub key: &'a [u8; 64],
}
impl<'a> MonitorGet<'a> {
    /// Parse one exact monitor GET frame.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let f = Frame::decode(input)?;
        if f.header().message_type() != message_type::DHT_MONITOR_GET {
            return Err(Error::Unsupported);
        }
        let mut r = Reader::new(f.payload());
        let options = r.u32()?;
        let block_type = r.u32()?;
        let hop_count = r.u32()?;
        let replication = r.u32()?;
        reserved(&mut r)?;
        let key = array(&mut r)?;
        if r.remaining() != 0 {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            options,
            block_type,
            hop_count,
            replication,
            key,
        })
    }
    /// Encode the exact88-byte notification.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let mut w = start(out, 88, message_type::DHT_MONITOR_GET)?;
        w.u32(self.options)?;
        w.u32(self.block_type)?;
        w.u32(self.hop_count)?;
        w.u32(self.replication)?;
        w.u32(0)?;
        w.put(self.key)?;
        Ok(88)
    }
}
/// Monitor PUT151, with official optional truncation predecessor and path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MonitorPut<'a> {
    /// Actual route metadata.
    pub options: u32,
    /// Concrete block type.
    pub block_type: u32,
    /// Actual hops.
    pub hop_count: u32,
    /// Requested replication.
    pub replication: u32,
    /// Block expiration.
    pub expiration: AbsoluteTime,
    /// Storage key.
    pub key: &'a [u8; 64],
    /// Truncated predecessor, exactly when flag8 is present.
    pub truncated_peer: Option<&'a [u8; 32]>,
    /// Original signed PUT path, structurally checked only.
    pub put_path: Path<'a>,
    /// Original block data.
    pub payload: &'a [u8],
}
impl<'a> MonitorPut<'a> {
    /// Parse complete official151 without validating the block.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let f = Frame::decode(input)?;
        if f.header().message_type() != message_type::DHT_MONITOR_PUT {
            return Err(Error::Unsupported);
        }
        let mut r = Reader::new(f.payload());
        let options = r.u32()?;
        let block_type = r.u32()?;
        let hop_count = r.u32()?;
        let replication = r.u32()?;
        let n = r.u32()?;
        let expiration = AbsoluteTime::from_micros(r.u64()?);
        let key = array(&mut r)?;
        let truncated_peer = if options & 8 != 0 {
            Some(array(&mut r)?)
        } else {
            None
        };
        let put_path = path32(n, &mut r)?;
        let payload = r.take(r.remaining())?;
        Ok(Self {
            options,
            block_type,
            hop_count,
            replication,
            expiration,
            key,
            truncated_peer,
            put_path,
            payload,
        })
    }
    /// Check all metadata and frame extents before output mutation.
    pub fn encoded_len(self) -> Result<usize, Error> {
        if (self.options & 8 != 0) != self.truncated_peer.is_some() {
            return Err(Error::InvalidInput);
        }
        total_len(
            96,
            &[
                self.truncated_peer.map_or(&[][..], |p| &p[..]),
                self.put_path.as_bytes(),
                self.payload,
            ],
        )
    }
    /// Encode original PUT metadata, with no put-ack interpretation.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len()?;
        let mut w = start(out, n, message_type::DHT_MONITOR_PUT)?;
        w.u32(self.options)?;
        w.u32(self.block_type)?;
        w.u32(self.hop_count)?;
        w.u32(self.replication)?;
        w.u32(u32::try_from(self.put_path.len()).map_err(|_| Error::TooLarge)?)?;
        w.u64(self.expiration.as_micros())?;
        w.put(self.key)?;
        if let Some(p) = self.truncated_peer {
            w.put(p)?;
        }
        w.put(self.put_path.as_bytes())?;
        w.put(self.payload)?;
        Ok(n)
    }
}
/// Monitor result150. There is deliberately no local operation ID here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MonitorResult<'a> {
    /// Concrete block type.
    pub block_type: u32,
    /// Original metadata flags.
    pub options: u32,
    /// Original PUT path.
    pub put_path: Path<'a>,
    /// Original GET path.
    pub get_path: Path<'a>,
    /// Block expiration.
    pub expiration: AbsoluteTime,
    /// Result's block key.
    pub key: &'a [u8; 64],
    /// Original truncated predecessor.
    pub truncated_peer: Option<&'a [u8; 32]>,
    /// Complete block bytes.
    pub payload: &'a [u8],
}
impl<'a> MonitorResult<'a> {
    /// Parse official150 without inventing a network/local correlation.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let f = Frame::decode(input)?;
        if f.header().message_type() != message_type::DHT_MONITOR_GET_RESP {
            return Err(Error::Unsupported);
        }
        let mut r = Reader::new(f.payload());
        let block_type = r.u32()?;
        reserved(&mut r)?;
        let options = r.u32()?;
        let pn = r.u32()?;
        let gn = r.u32()?;
        let expiration = AbsoluteTime::from_micros(r.u64()?);
        let key = array(&mut r)?;
        let truncated_peer = if options & 8 != 0 {
            Some(array(&mut r)?)
        } else {
            None
        };
        let put_path = path32(pn, &mut r)?;
        let get_path = path32(gn, &mut r)?;
        let payload = r.take(r.remaining())?;
        Ok(Self {
            block_type,
            options,
            put_path,
            get_path,
            expiration,
            key,
            truncated_peer,
            payload,
        })
    }
    /// Preflight every variable extent and flag-dependent field.
    pub fn encoded_len(self) -> Result<usize, Error> {
        if (self.options & 8 != 0) != self.truncated_peer.is_some() {
            return Err(Error::InvalidInput);
        }
        total_len(
            96,
            &[
                self.truncated_peer.map_or(&[][..], |p| &p[..]),
                self.put_path.as_bytes(),
                self.get_path.as_bytes(),
                self.payload,
            ],
        )
    }
    /// Encode one original monitor result with zero reserved field.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len()?;
        let mut w = start(out, n, message_type::DHT_MONITOR_GET_RESP)?;
        w.u32(self.block_type)?;
        w.u32(0)?;
        w.u32(self.options)?;
        w.u32(u32::try_from(self.put_path.len()).map_err(|_| Error::TooLarge)?)?;
        w.u32(u32::try_from(self.get_path.len()).map_err(|_| Error::TooLarge)?)?;
        w.u64(self.expiration.as_micros())?;
        w.put(self.key)?;
        if let Some(p) = self.truncated_peer {
            w.put(p)?;
        }
        w.put(self.put_path.as_bytes())?;
        w.put(self.get_path.as_bytes())?;
        w.put(self.payload)?;
        Ok(n)
    }
}
