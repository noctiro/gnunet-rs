//! Bounded read-only IGD selection, before one original Add can be admitted.
use super::{Device, Error, Limits, action, descriptor, external_ipv4};
use crate::{
    Error as HostError,
    deadline::Gate,
    http::{self, Url, Written},
};
use gnunet_client_host::resolution::{PortError, SharedResolution};
use gnunet_types::Error as Fault;
use std::{
    cell::{Cell, RefCell},
    error::Error as StdError,
    fmt, io,
    net::Ipv4Addr,
    rc::Rc,
    sync::Arc,
};

/// Read operation which produced an actual candidate failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadStage {
    /// Device description HTTP/XML/URL parsing.
    Description,
    /// Standard GetStatusInfo read.
    Status,
    /// Standard GetExternalIPAddress read.
    ExternalAddress,
}
/// Original bounded read target; none of these facts authorize a mutation.
#[derive(Debug)]
pub enum ReadTarget {
    /// Actual SSDP/caller-supplied description URL.
    Description(Url),
    /// Actual descriptor-derived service/control pair.
    Service(Device),
}
/// A failed read retained independently from eventual selection or failure.
#[derive(Debug)]
pub struct ReadFailure {
    /// Actual read stage.
    pub stage: ReadStage,
    /// Original target, never a replacement source.
    pub target: ReadTarget,
    /// Original typed error, shared without copying or changing its cause.
    pub error: Arc<Error>,
}
impl fmt::Display for ReadFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IGD {:?} at {:?}: {}",
            self.stage, self.target, self.error
        )
    }
}
impl StdError for ReadFailure {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(self.error.as_ref())
    }
}
/// One selected connected service. Its external address is a router claim, not
/// proof of public reachability or of a successful port mapping.
pub struct Selected {
    device: Device,
    external: Option<Ipv4Addr>,
}
impl Selected {
    /// Actual selected service/control pair.
    pub fn device(&self) -> &Device {
        &self.device
    }
    /// Actual valid address read during selection, if one was returned.
    pub const fn external(&self) -> Option<Ipv4Addr> {
        self.external
    }
    /// Transfer the selected service to its one original mapping attempt.
    pub fn into_device(self) -> Device {
        self.device
    }
}
/// Complete original read-only selection result and its earlier read failures.
/// A connected fallback may coexist with a failed external-address read, as in
/// the normal upnpc selection policy. No Add or cleanup has been performed.
pub struct SelectionReport {
    /// Selected connected candidate, or the original terminating read/source cause.
    pub result: Result<Selected, Arc<Error>>,
    observations: ReadObservations,
}
impl SelectionReport {
    /// Move the actual result and all earlier failed reads after selection has
    /// physically stopped. Neither the report nor its facts authorize an Add.
    pub fn into_parts(self) -> (Result<Selected, Arc<Error>>, Vec<ReadFailure>) {
        (self.result, self.observations.take())
    }
}
struct ReadState {
    limits: Limits,
    started: Cell<bool>,
    failures: RefCell<Vec<ReadFailure>>,
}
/// One finite original selection's read observations. Clones share its single
/// allocation, so cancellation can retire its future without losing prior reads.
#[derive(Clone)]
pub struct ReadObservations(Rc<ReadState>);
impl ReadObservations {
    /// Reserve the original failure bound before any HTTP/SSDP IO. One location
    /// can fail description parsing once; one service can fail status OR, only
    /// after a successful status read, external-address reading once.
    pub fn new(limits: Limits) -> Result<Self, Error> {
        if limits.devices == 0 || limits.services == 0 {
            return Err(Fault::InvalidInput.into());
        }
        let count = limits
            .devices
            .checked_add(limits.services)
            .ok_or(Fault::Overflow)?;
        let mut failures = Vec::new();
        failures
            .try_reserve_exact(count)
            .map_err(|_| Fault::Capacity)?;
        Ok(Self(Rc::new(ReadState {
            limits,
            started: Cell::new(false),
            failures: RefCell::new(failures),
        })))
    }
    pub(super) fn limits(&self) -> Limits {
        self.0.limits
    }
    pub(super) fn begin(&self) -> Result<(), Error> {
        if self.0.started.replace(true) {
            Err(Fault::StaleGeneration.into())
        } else {
            Ok(())
        }
    }
    pub(crate) fn take(&self) -> Vec<ReadFailure> {
        std::mem::take(&mut *self.0.failures.borrow_mut())
    }
}
fn failed(error: Error, observations: ReadObservations) -> SelectionReport {
    SelectionReport {
        result: Err(Arc::new(error)),
        observations,
    }
}
fn record(
    observations: &ReadObservations,
    target: ReadTarget,
    stage: ReadStage,
    error: Error,
) -> Arc<Error> {
    let error = Arc::new(error);
    // Reserved before any HTTP read. Each location can fail once and each
    // distinct service can fail only its status OR its external-address read.
    observations.0.failures.borrow_mut().push(ReadFailure {
        target,
        stage,
        error: error.clone(),
    });
    error
}
fn endpoint_io(error: &io::Error) -> bool {
    error.raw_os_error().is_some()
        && matches!(
            error.kind(),
            io::ErrorKind::ConnectionRefused
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::BrokenPipe
                | io::ErrorKind::NotConnected
                | io::ErrorKind::HostUnreachable
                | io::ErrorKind::NetworkUnreachable
                | io::ErrorKind::AddrNotAvailable
        )
}
fn http_endpoint(error: &gnunet_http_host::Error) -> bool {
    match error {
        gnunet_http_host::Error::Url(_) => true,
        gnunet_http_host::Error::Http(error) => {
            // A typed caller port refusal must never be mistaken for a native
            // endpoint error, even if its nested errno happens to match.
            let mut source = error.source();
            let mut endpoint = false;
            while let Some(cause) = source {
                if cause.downcast_ref::<PortError>().is_some() {
                    return false;
                }
                if let Some(error) = cause.downcast_ref::<io::Error>() {
                    if PortError::from_io(error).is_some() {
                        return false;
                    }
                    if !endpoint_io(error) {
                        return false;
                    }
                    endpoint = true;
                }
                source = cause.source();
            }
            endpoint || error.is_parse() || error.is_incomplete_message()
        }
        _ => false,
    }
}
fn scope_failure(error: &Error) -> bool {
    match error {
        Error::Xml(_) | Error::Attribute(_) | Error::Http(_) | Error::Soap { .. } => false,
        Error::Host(HostError::Protocol(
            Fault::Malformed | Fault::Unsupported | Fault::NotFound | Fault::Unavailable,
        )) => false,
        Error::Host(HostError::Io(error)) => {
            PortError::from_io(error).is_some() || !endpoint_io(error)
        }
        Error::Host(HostError::Http(error)) => !http_endpoint(error),
        // Clock, opaque Other/TimedOut IO, resource refusals and every original
        // post-response guard failure stop this same scope without retry.
        _ => true,
    }
}
// miniupnpc's address preference, separate from GNUnet address-class flags.
fn reserved(ip: Ipv4Addr) -> bool {
    const BLOCKS: [([u8; 4], u32); 18] = [
        ([0, 0, 0, 0], 8),
        ([10, 0, 0, 0], 8),
        ([100, 64, 0, 0], 10),
        ([127, 0, 0, 0], 8),
        ([169, 254, 0, 0], 16),
        ([172, 16, 0, 0], 12),
        ([192, 0, 0, 0], 24),
        ([192, 0, 2, 0], 24),
        ([192, 31, 196, 0], 24),
        ([192, 52, 193, 0], 24),
        ([192, 88, 99, 0], 24),
        ([192, 168, 0, 0], 16),
        ([192, 175, 48, 0], 24),
        ([198, 18, 0, 0], 15),
        ([198, 51, 100, 0], 24),
        ([203, 0, 113, 0], 24),
        ([224, 0, 0, 0], 4),
        ([240, 0, 0, 0], 4),
    ];
    let address = u32::from(ip);
    BLOCKS.iter().any(|(prefix, bits)| {
        address >> (32 - *bits) == u32::from_be_bytes(*prefix) >> (32 - *bits)
    })
}
async fn connected(
    resolver: &SharedResolution,
    gate: &mut Gate,
    device: &Device,
    limits: Limits,
) -> Result<bool, Error> {
    let result = action(
        resolver,
        gate,
        device,
        "GetStatusInfo",
        &[],
        &Written::default(),
        limits,
    )
    .await?;
    let status = result
        .field("NewConnectionStatus")?
        .ok_or(Fault::Malformed)?;
    // Connected is the standard value; Up is the normal miniupnpc alias.
    Ok(matches!(status, "Connected" | "Up"))
}
/// Fetch bounded actual descriptions and select a connected service using only
/// read operations, under the caller's unchanged original Gate/Resolver.
/// This explicit-location entry performs no SSDP, Add, delete or native fallback
/// DNS. Connected nonreserved addresses are preferred; the first connected
/// fallback is retained even if its external-address read was locally rejected.
pub async fn select_from_locations(
    resolver: &SharedResolution,
    gate: &mut Gate,
    locations: Vec<Url>,
    observations: ReadObservations,
) -> Result<SelectionReport, Error> {
    observations.begin()?;
    Ok(select_locations(resolver, gate, locations, observations).await)
}
pub(super) async fn select_locations(
    resolver: &SharedResolution,
    gate: &mut Gate,
    locations: Vec<Url>,
    observations: ReadObservations,
) -> SelectionReport {
    let limits = observations.limits();
    if locations.len() > limits.devices {
        return failed(Fault::TooLarge.into(), observations);
    }
    if locations.is_empty() {
        return failed(Fault::NotFound.into(), observations);
    }
    let mut candidates = Vec::new();
    if candidates.try_reserve_exact(limits.services).is_err() {
        return failed(Fault::Capacity.into(), observations);
    }
    for location in locations {
        if let Err(error) = gate.check() {
            return failed(error.into(), observations);
        }
        let result = async {
            let response = http::exchange(
                resolver,
                gate,
                &location,
                None,
                &Written::default(),
                limits.http,
            )
            .await?;
            if response.status != 200 {
                return Err(Error::Http(response.status));
            }
            descriptor(location.clone(), &response.body, limits)
        }
        .await;
        match result {
            Ok(devices) => {
                for device in devices {
                    if candidates.iter().any(|old: &Device| {
                        old.control == device.control && old.service == device.service
                    }) {
                        continue;
                    }
                    if candidates.len() >= limits.services {
                        return failed(Fault::TooLarge.into(), observations);
                    }
                    candidates.push(device);
                }
            }
            Err(error) => {
                let stop = scope_failure(&error);
                let error = record(
                    &observations,
                    ReadTarget::Description(location),
                    ReadStage::Description,
                    error,
                );
                if stop {
                    return SelectionReport {
                        result: Err(error),
                        observations,
                    };
                }
                if let Err(error) = gate.check() {
                    return failed(error.into(), observations);
                }
            }
        }
    }
    let mut fallback = None;
    for device in candidates {
        if let Err(error) = gate.check() {
            return failed(error.into(), observations);
        }
        match connected(resolver, gate, &device, limits).await {
            Ok(false) => continue,
            Ok(true) => {}
            Err(error) => {
                let stop = scope_failure(&error);
                let error = record(
                    &observations,
                    ReadTarget::Service(device),
                    ReadStage::Status,
                    error,
                );
                if stop {
                    return SelectionReport {
                        result: Err(error),
                        observations,
                    };
                }
                if let Err(error) = gate.check() {
                    return failed(error.into(), observations);
                }
                continue;
            }
        }
        let external = match external_ipv4(resolver, gate, &device, limits).await {
            Ok(ip) => Some(ip),
            Err(error) => {
                let stop = scope_failure(&error);
                let error = record(
                    &observations,
                    ReadTarget::Service(device.clone()),
                    ReadStage::ExternalAddress,
                    error,
                );
                if stop {
                    return SelectionReport {
                        result: Err(error),
                        observations,
                    };
                }
                if let Err(error) = gate.check() {
                    return failed(error.into(), observations);
                }
                None
            }
        };
        if external.is_some_and(|ip| !reserved(ip)) {
            if let Err(error) = gate.check() {
                return failed(error.into(), observations);
            }
            return SelectionReport {
                result: Ok(Selected { device, external }),
                observations,
            };
        }
        if fallback.is_none() {
            fallback = Some(Selected { device, external });
        }
    }
    if let Err(error) = gate.check() {
        return failed(error.into(), observations);
    }
    let result = fallback.ok_or_else(|| {
        observations.0.failures.borrow().first().map_or_else(
            || Arc::new(Fault::NotFound.into()),
            |failure| failure.error.clone(),
        )
    });
    SelectionReport {
        result,
        observations,
    }
}
