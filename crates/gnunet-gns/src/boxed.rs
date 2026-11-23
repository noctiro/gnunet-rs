//! Shared underscore-prefix selection and original BOX/SBOX wire projection.

use crate::{Error, RecordData, RecordType, assigned::Registry};
use core::num::NonZeroU16;

/// Host-order protocol number and service port for an official BOX selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoxSelector {
    protocol: NonZeroU16,
    port: NonZeroU16,
}

impl BoxSelector {
    /// Create a selector from a nonzero protocol number and service port.
    #[must_use]
    pub const fn new(protocol: NonZeroU16, port: NonZeroU16) -> Self {
        Self { protocol, port }
    }

    /// Protocol number in host order.
    #[must_use]
    pub const fn protocol(self) -> NonZeroU16 {
        self.protocol
    }

    /// Service port in host order.
    #[must_use]
    pub const fn port(self) -> NonZeroU16 {
        self.port
    }
}

/// Caller-supplied bounded protocol and service registry for fixed GNS.
/// Implementations can use validated native settings or an immutable table.
/// GNS checks the assigned-number fallback after an absent native mapping.
pub trait BoxRegistry {
    /// Resolve the original protocol name without the underscore.
    fn protocol(&self, name: &str) -> Option<NonZeroU16>;

    /// Resolve the original service name within the named protocol.
    fn service(&self, name: &str, protocol: &str) -> Option<NonZeroU16>;
}

#[derive(Clone, Copy)]
pub(crate) struct Prefix<'a>(&'a str);

impl<'a> Prefix<'a> {
    pub(crate) fn new(original: &'a str) -> Option<Self> {
        original
            .rsplit('.')
            .next()
            .filter(|rightmost| rightmost.starts_with('_'))?;
        Some(Self(original))
    }

    pub(crate) fn service_names(self) -> Option<(&'a str, &'a str)> {
        let (service, protocol) = self.0.split_once('.')?;
        if protocol.contains('.') {
            return None;
        }
        let service = service.strip_prefix('_')?;
        let protocol = protocol.strip_prefix('_')?;
        (!service.is_empty() && !protocol.is_empty()).then_some((service, protocol))
    }

    pub(crate) fn resolve(self, registry: Option<&dyn BoxRegistry>) -> Option<BoxSelector> {
        let (service, protocol) = self.service_names()?;
        let number = registry
            .and_then(|native| native.protocol(protocol))
            .or_else(|| {
                Registry::Protocols
                    .number(protocol)
                    .and_then(NonZeroU16::new)
            })?;
        let port = registry
            .and_then(|native| native.service(service, protocol))
            .or_else(|| {
                Registry::ServicePorts
                    .number(service)
                    .and_then(NonZeroU16::new)
            })
            .or_else(|| service.parse().ok())?;
        Some(BoxSelector::new(number, port))
    }

    pub(crate) fn select<'data>(
        self,
        selector: Option<BoxSelector>,
        record: RecordData<'data>,
    ) -> Result<Option<RecordData<'data>>, Error> {
        if record.record_type == RecordType::BOX && selector.is_none() {
            return Ok(None);
        }
        let Some(boxed) = decode(record)? else {
            return Ok(None);
        };
        let matches = match boxed.key {
            Key::Service { protocol, port } => selector.is_some_and(|original| {
                original.protocol().get() == protocol && original.port().get() == port
            }),
            Key::Literal(prefix) => self.0 == prefix.0,
        };
        Ok(matches.then_some(boxed.inner))
    }
}

enum Key<'a> {
    Service { protocol: u16, port: u16 },
    Literal(Prefix<'a>),
}

struct Boxed<'a> {
    key: Key<'a>,
    inner: RecordData<'a>,
}

fn decode(record: RecordData<'_>) -> Result<Option<Boxed<'_>>, Error> {
    let (key, kind, data) = match record.record_type {
        RecordType::BOX => {
            let (header, data) = record
                .data
                .split_first_chunk::<8>()
                .ok_or(Error::Malformed)?;
            (
                Key::Service {
                    protocol: u16::from_be_bytes([header[0], header[1]]),
                    port: u16::from_be_bytes([header[2], header[3]]),
                },
                [header[4], header[5], header[6], header[7]],
                data,
            )
        }
        RecordType::SBOX => {
            let (kind, body) = record
                .data
                .split_first_chunk::<4>()
                .ok_or(Error::Malformed)?;
            let end = body
                .iter()
                .position(|byte| *byte == 0)
                .ok_or(Error::Malformed)?;
            let literal = core::str::from_utf8(&body[..end]).map_err(|_| Error::Malformed)?;
            let prefix = Prefix::new(literal).ok_or(Error::Malformed)?;
            (Key::Literal(prefix), *kind, &body[end + 1..])
        }
        _ => return Ok(None),
    };
    Ok(Some(Boxed {
        key,
        inner: RecordData {
            record_type: RecordType::new(u32::from_be_bytes(kind)),
            data,
            ..record
        },
    }))
}

pub(crate) fn validate(record: RecordData<'_>) -> Result<(), Error> {
    decode(record).map(|_| ())
}
