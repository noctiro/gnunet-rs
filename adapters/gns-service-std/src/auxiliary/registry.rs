//! Prepared OS files plus the published GNS-specific GANA fallback.
use gnunet_gns::assigned::Registry as Assigned;
use gnunet_types::Error as Fault;
use std::{
    io::{self, Read},
    path::Path,
};

/// Bounded input/text/row resources for the files profile.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Combined actual protocol/service file contents.
    pub bytes: usize,
    /// Protocol aliases retained.
    pub protocols: usize,
    /// Service aliases retained.
    pub services: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            bytes: 1_048_576,
            protocols: 4096,
            services: 65_536,
        }
    }
}
/// Actual preparation failure, not a guessed mapping or successful empty table.
#[derive(Debug)]
pub enum Error {
    /// Actual prepared registry capacity or parse refusal.
    Protocol(Fault),
    /// Original registry file read error.
    Io(io::Error),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "GNS files registry: {error}"),
            Self::Io(error) => write!(f, "GNS files registry IO: {error}"),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::Io(error) => Some(error),
        }
    }
}
impl From<Fault> for Error {
    fn from(error: Fault) -> Self {
        Self::Protocol(error)
    }
}
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
struct Protocol {
    name: String,
    number: u16,
}
struct Service {
    name: String,
    protocol: String,
    port: u16,
}
/// No native lookup occurs at query time. Unknown names genuinely return None,
/// allowing the existing resolver's literal SBOX semantics without guessed IDs.
pub struct Files {
    protocols: Vec<Protocol>,
    services: Vec<Service>,
}
impl Files {
    /// Explicit ordinary files profile. No libc NSS call, GANA-completeness
    /// assertion or hidden fallback is introduced.
    pub fn system(limits: Limits) -> Result<Self, Error> {
        Self::from_files(
            Path::new("/etc/protocols"),
            Path::new("/etc/services"),
            limits,
        )
    }
    /// Synchronously prepare bounded files before live native service owners.
    /// These OS reads may block; no false asynchronous cancellation is claimed.
    pub fn from_files(protocols: &Path, services: &Path, limits: Limits) -> Result<Self, Error> {
        validate(limits)?;
        let protocols = read(std::fs::File::open(protocols)?, limits.bytes)?;
        let services = read(
            std::fs::File::open(services)?,
            limits.bytes - protocols.len(),
        )?;
        Self::from_bytes(&protocols, &services, limits)
    }
    /// Parse actual caller-provided contents with independent row/byte bounds.
    /// Malformed/unassigned entries are skipped as this explicit files profile;
    /// resource exhaustion is an error, not a partial successful table.
    pub fn from_bytes(protocols: &[u8], services: &[u8], limits: Limits) -> Result<Self, Error> {
        validate(limits)?;
        if protocols
            .len()
            .checked_add(services.len())
            .ok_or(Fault::Overflow)?
            > limits.bytes
        {
            return Err(Fault::Capacity.into());
        }
        if protocols.contains(&0) || services.contains(&0) {
            return Err(Fault::Malformed.into());
        }
        let protocols = std::str::from_utf8(protocols).map_err(|_| Fault::Malformed)?;
        let services = std::str::from_utf8(services).map_err(|_| Fault::Malformed)?;
        let mut table = Self {
            protocols: Vec::new(),
            services: Vec::new(),
        };
        for line in protocols.lines() {
            let mut fields = line.split('#').next().unwrap_or("").split_whitespace();
            let Some(name) = fields.next() else {
                continue;
            };
            let Some(number) = fields.next().and_then(|value| value.parse::<u16>().ok()) else {
                continue;
            };
            for alias in std::iter::once(name).chain(fields) {
                if table.protocols.len() == limits.protocols {
                    return Err(Fault::Capacity.into());
                }
                table
                    .protocols
                    .try_reserve(1)
                    .map_err(|_| Fault::Capacity)?;
                table.protocols.push(Protocol {
                    name: owned(alias)?,
                    number,
                });
            }
        }
        for line in services.lines() {
            let mut fields = line.split('#').next().unwrap_or("").split_whitespace();
            let Some(name) = fields.next() else {
                continue;
            };
            let Some((port, protocol)) = fields.next().and_then(|value| value.split_once('/'))
            else {
                continue;
            };
            let Ok(port) = port.parse::<u16>() else {
                continue;
            };
            if protocol.is_empty() {
                continue;
            }
            for alias in std::iter::once(name).chain(fields) {
                if table.services.len() == limits.services {
                    return Err(Fault::Capacity.into());
                }
                table.services.try_reserve(1).map_err(|_| Fault::Capacity)?;
                table.services.push(Service {
                    name: owned(alias)?,
                    protocol: owned(protocol)?,
                    port,
                });
            }
        }
        Ok(table)
    }
    /// First actual file mapping wins, followed independently by the published
    /// GNS protocol and service-port assignments. A numeric service is the final
    /// choice. Names use ASCII case folding without rewriting their namespace.
    pub fn lookup(&self, service: &str, protocol: &str) -> Option<(u16, u16)> {
        let number = self
            .protocols
            .iter()
            .find(|entry| entry.name.eq_ignore_ascii_case(protocol))
            .map(|entry| entry.number)
            .or_else(|| Assigned::Protocols.number(protocol))?;
        let port = self
            .services
            .iter()
            .find(|entry| {
                entry.name.eq_ignore_ascii_case(service)
                    && entry.protocol.eq_ignore_ascii_case(protocol)
            })
            .map(|entry| entry.port)
            .or_else(|| Assigned::ServicePorts.number(service))
            .or_else(|| service.parse::<u16>().ok())?;
        (number != 0 && port != 0).then_some((number, port))
    }
}

/// Resolve an independently available GANA mapping while OS files are unavailable.
/// An unknown name is not evidence that the unavailable OS database has no entry.
pub(super) fn assigned(service: &str, protocol: &str) -> Option<(u16, u16)> {
    let protocol = Assigned::Protocols.number(protocol)?;
    let port = Assigned::ServicePorts
        .number(service)
        .or_else(|| service.parse::<u16>().ok())?;
    (port != 0).then_some((protocol, port))
}
fn validate(limits: Limits) -> Result<(), Fault> {
    if limits.bytes == 0
        || limits.bytes > 16 * 1024 * 1024
        || limits.protocols == 0
        || limits.services == 0
    {
        return Err(Fault::InvalidInput);
    }
    Ok(())
}
fn owned(input: &str) -> Result<String, Fault> {
    let mut output = String::new();
    output
        .try_reserve_exact(input.len())
        .map_err(|_| Fault::Capacity)?;
    output.push_str(input);
    Ok(output)
}
fn read(mut input: impl Read, maximum: usize) -> Result<Vec<u8>, Error> {
    let mut output = Vec::new();
    let mut chunk = [0; 4096];
    loop {
        let remaining = maximum - output.len();
        let count = input.read(&mut chunk[..remaining.saturating_add(1).min(4096)])?;
        if count == 0 {
            return Ok(output);
        }
        if count > remaining {
            return Err(Fault::Capacity.into());
        }
        output.try_reserve(count).map_err(|_| Fault::Capacity)?;
        output.extend_from_slice(&chunk[..count]);
    }
}
