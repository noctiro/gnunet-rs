//! Native protocol and service lookups, explicit files, and published GANA assignments.
use crate::Bounds;
use gnunet_gns::{BoxSelector, assigned::Registry as Assigned};
use gnunet_native::internet_registry::Database;
use gnunet_types::Error as Fault;
use std::{
    ffi::CStr,
    io::{self, Read},
    num::NonZeroU16,
    path::Path,
    sync::Arc,
    task::{Context, Poll},
};

mod operation;
mod worker;
pub(super) use operation::Lookup;

#[cfg(test)]
mod tests;

type LookupResult = Result<Option<BoxSelector>, Error>;

/// Actual result of the original registry operation after its work retired.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// The selected backend completed the lookup. None is a real miss.
    Resolved(Option<BoxSelector>),
    /// This lookup stopped before a mapping or a miss was observed.
    Cancelled,
    /// The original lookup failed and its error was reported separately.
    Failed,
}

pub(super) enum Source {
    Prepared(Result<Files, Arc<Error>>),
    Native(worker::Worker),
}

impl Source {
    pub(super) fn native() -> Self {
        match worker::Worker::spawn() {
            Ok(worker) => Self::Native(worker),
            Err(error) => Self::Prepared(Err(Arc::new(error.into()))),
        }
    }

    pub(super) fn preparation_error(&self) -> Option<&Arc<Error>> {
        match self {
            Self::Prepared(Err(error)) => Some(error),
            _ => None,
        }
    }

    pub(super) fn start(
        &mut self,
        service: &str,
        protocol: &str,
        bounds: Bounds,
    ) -> Result<Lookup, Arc<Error>> {
        match self {
            Self::Prepared(profile) => {
                let value = match profile {
                    Ok(files) => files.lookup(service, protocol),
                    Err(error) => Some(assigned(service, protocol).ok_or_else(|| error.clone())?),
                };
                Ok(Lookup::prepared(value, bounds))
            }
            Self::Native(worker) => worker
                .start(service, protocol, bounds)
                .map(|query| Lookup::native(query, bounds))
                .map_err(Arc::new),
        }
    }

    pub(super) fn begin_close(&mut self) {
        if let Self::Native(worker) = self {
            worker.begin_close();
        }
    }

    pub(super) fn poll_stopped(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            Self::Native(worker) => worker.poll_stopped(cx),
            Self::Prepared(_) => Poll::Pending,
        }
    }

    pub(super) fn is_stopped(&self) -> bool {
        match self {
            Self::Native(worker) => worker.is_stopped(),
            Self::Prepared(_) => true,
        }
    }
}

fn native_lookup(
    database: &mut Database,
    service: &CStr,
    protocol: &CStr,
    guard: impl Fn() -> Result<(), Error>,
) -> LookupResult {
    let protocol_name = protocol.to_str().map_err(|_| Fault::Malformed)?;
    guard()?;
    let Some(number) = database
        .protocol(protocol)?
        .or_else(|| Assigned::Protocols.number(protocol_name))
        .and_then(NonZeroU16::new)
    else {
        return Ok(None);
    };
    let service_name = service.to_str().map_err(|_| Fault::Malformed)?;
    guard()?;
    let port = database
        .service(service, protocol)?
        .or_else(|| Assigned::ServicePorts.number(service_name))
        .and_then(NonZeroU16::new)
        .or_else(|| service_name.parse().ok());
    Ok(port.map(|port| BoxSelector::new(number, port)))
}

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
/// Actual registry preparation, lookup, or retirement failure.
#[derive(Debug)]
pub enum Error {
    /// Actual prepared registry capacity or parse refusal.
    Protocol(Fault),
    /// Original registry file or native operation error.
    Io(io::Error),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "GNS registry: {error}"),
            Self::Io(error) => write!(f, "GNS registry I/O: {error}"),
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
        Self::from_paths(None, None, limits)
    }
    /// Select explicit files or native system defaults. Windows uses its native
    /// system directory's drivers/etc files; Unix uses /etc. Discovery/read
    /// failures remain errors, and no environment-derived fallback is added.
    pub fn from_paths(
        protocols: Option<&Path>,
        services: Option<&Path>,
        limits: Limits,
    ) -> Result<Self, Error> {
        if let (Some(protocols), Some(services)) = (protocols, services) {
            return Self::from_files(protocols, services, limits);
        }
        #[cfg(unix)]
        let (default_protocols, default_services) = (
            std::path::PathBuf::from("/etc/protocols"),
            std::path::PathBuf::from("/etc/services"),
        );
        #[cfg(windows)]
        let (default_protocols, default_services) = {
            let directory = gnunet_native::paths::internet_database_directory()?;
            (directory.join("protocol"), directory.join("services"))
        };
        Self::from_files(
            protocols.unwrap_or(&default_protocols),
            services.unwrap_or(&default_services),
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
    pub fn lookup(&self, service: &str, protocol: &str) -> Option<BoxSelector> {
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
        Some(BoxSelector::new(
            NonZeroU16::new(number)?,
            NonZeroU16::new(port)?,
        ))
    }
}

/// Resolve an independently available GANA mapping while OS files are unavailable.
/// An unknown name is not evidence that the unavailable OS database has no entry.
pub(super) fn assigned(service: &str, protocol: &str) -> Option<BoxSelector> {
    let protocol = NonZeroU16::new(Assigned::Protocols.number(protocol)?)?;
    let port = Assigned::ServicePorts
        .number(service)
        .or_else(|| service.parse::<u16>().ok())?;
    Some(BoxSelector::new(protocol, NonZeroU16::new(port)?))
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
