//! Original VPN allocation ownership for the proxy's explicit VPN consumer.
//!
//! This module does not reinterpret GNS IPC records or create a Resolver. The
//! caller selects the exact original service, address family and lease target.
//! No returned address authenticates the peer or proves forwarding. Stopping
//! local interest and physically closing this MQ never revokes a remote lease.
use crate::budget::Budget;
use gnunet_client_host::EndpointSource;
use gnunet_types::Error as Fault;
use gnunet_vpn_client_host as vpn;
use std::{
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

/// A selected actual peer service, not an allocation receipt.
#[derive(Clone, Copy, Debug)]
pub struct Need {
    /// Actual peer, official service descriptor and supported TCP/UDP protocol.
    pub target: vpn::Service,
    /// Explicit result family; the endpoint's AF encoding stays in its profile.
    pub family: vpn::Family,
    /// Original requested lease expiration. This may be FOREVER; the original
    /// response/native budget remains finite and independent.
    pub requested_until: u64,
}
/// Address observed in the original matching USE_IP callback.
#[derive(Clone, Copy, Debug)]
pub struct Allocation {
    /// Actual returned address of the requested family.
    pub address: IpAddr,
    /// Same submitted lease target, not a service-confirmed lease duration.
    pub requested_until: u64,
}
/// Independent actual operation failure. Payload/key bytes are never retained.
#[derive(Debug)]
pub enum Failure {
    /// Original parent Stop/native/canonical/clock error. The indirection breaks
    /// the proxy Error -> VPN Failure -> proxy Error ownership cycle.
    Budget(Box<crate::Error>),
    /// Actual endpoint, configuration, clock or native CLIENT refusal.
    Client(vpn::Error),
    /// Bounded local/source-family or original-token contract refusal.
    Protocol(Fault),
    /// Actual original source loss; its owned cause stays in Report::loss.
    Lost,
    /// Actual callback was not an address allocation of the requested family.
    Outcome(vpn::Outcome),
    /// The original owner closed without an allocation result.
    Closed,
    /// Actual original cleanup did not settle; its cause/remaining debt stays
    /// independently owned by the returned Report.
    Retirement,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Budget(error) => write!(f, "proxy VPN original budget: {error}"),
            Self::Client(error) => write!(f, "proxy VPN client: {error}"),
            Self::Protocol(error) => write!(f, "proxy VPN protocol/resource: {error}"),
            Self::Lost => f.write_str("proxy VPN original source lost"),
            Self::Outcome(_) => {
                f.write_str("proxy VPN allocation did not return the requested family")
            }
            Self::Closed => f.write_str("proxy VPN original owner closed without allocation"),
            Self::Retirement => f.write_str("proxy VPN original retirement incomplete"),
        }
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Budget(error) => Some(error.as_ref()),
            Self::Client(error) => Some(error),
            Self::Protocol(error) => Some(error),
            _ => None,
        }
    }
}
/// Actual terminal metadata after consuming the original lifetime-bound token.
/// These numeric labels never reconstruct an operation or source capability.
#[derive(Clone, Copy, Debug)]
pub struct Terminal {
    /// Original operation's diagnostic serial.
    pub operation: u64,
    /// Original physical MQ, if the operation was ever attached.
    pub epoch: Option<u64>,
    /// Actual matching allocation or local Unsent/Unknown outcome.
    pub outcome: vpn::Outcome,
}
/// Bounded independent actual native facts. A whole local request write is not
/// an allocation acknowledgement; physical close is not a lease-revocation ACK.
#[derive(Debug, Default)]
pub struct Report {
    /// Admitted original operation, if construction reached admission.
    pub operation: Option<u64>,
    /// Actually observed original physical source.
    pub epoch: Option<u64>,
    /// Actually whole-written original immutable physical frame.
    pub write: Option<u64>,
    /// Original request was locally written in full, not remotely acknowledged.
    pub written: bool,
    /// Actual bytes reported by incomplete native write progress. The final
    /// whole-write step has no byte count in the client API; see written/write.
    pub written_prefix_bytes: u64,
    /// Actual bytes reported by incomplete native read progress. This is not
    /// the complete response length and never includes a synthetic estimate.
    pub read_prefix_bytes: u64,
    /// Actual matching callback consumed before retirement, if any.
    pub terminal: Option<Terminal>,
    /// First actual physical loss before cleanup, retaining the original cause.
    pub loss: Option<vpn::LossCause>,
    /// First actual failed connection attempt; it does not authorize replay.
    pub connect_error: Option<io::Error>,
    /// Actual connection-failure count, with later causes explicitly bounded.
    pub connect_failures: u64,
    /// Clock-free physical close was invoked once on this same original client.
    pub close_invoked: bool,
    /// That actual close's original physical loss, including expected Closed.
    pub close_loss: Option<vpn::LossCause>,
    /// Actual close error, independent of the business/budget failure.
    pub close_error: Option<vpn::Error>,
    /// Actual terminal settlement consumed after physical close. An exposed
    /// original allocation remains Unknown even though local interest ended.
    pub retired: Option<Terminal>,
    /// Unexpected terminal retained for diagnostics; never relabeled as ours.
    pub other_terminal: Option<Terminal>,
    /// Number of other actual events, not an unbounded diagnostic queue.
    pub other_events: u64,
    /// Actual original operation/debt slots remaining after close and take.
    pub remaining: usize,
    /// True only when original close succeeded and all original slots settled.
    pub closed: bool,
}
impl Report {
    /// Nonfatal recovered connection errors and independent cleanup failures
    /// remain visible even if a real address was already allocated.
    pub fn has_diagnostics(&self) -> bool {
        self.loss.is_some()
            || self.connect_error.is_some()
            || self.close_error.is_some()
            || self.other_terminal.is_some()
            || self.remaining != 0
            || (self.close_invoked && !self.closed)
    }
}
fn check(budget: &Budget) -> Result<(), Failure> {
    budget
        .check()
        .map_err(|error| Failure::Budget(Box::new(error)))
}
fn terminal(
    epoch: Option<vpn::Epoch<'_>>,
    operation: vpn::Operation<'_>,
    outcome: vpn::Outcome,
) -> Terminal {
    Terminal {
        operation: operation.diagnostic(),
        epoch: epoch.map(vpn::Epoch::diagnostic),
        outcome,
    }
}

/// Drive exactly one actual allocation under the caller's original budget.
///
/// The caller must retain/poll this future through its terminal result when
/// stopping; dropping the whole future does not produce a retirement Report.
/// Budget::wait may drop only the borrowed drive future: this function still
/// owns the same Client and always enters clock-free physical cleanup below.
/// No old request is resubmitted after loss, timeout, cancellation or Unknown.
/// A caller may reuse Allocation::requested_until only as its submitted bound,
/// never as evidence of an acknowledged future lease lifetime.
pub(crate) async fn allocate(
    source: EndpointSource,
    budget: Budget,
    need: Need,
    profile: vpn::AfProfile,
    limits: vpn::Limits,
) -> (Result<Allocation, Failure>, Report) {
    let mut report = Report::default();
    if let Err(error) = check(&budget) {
        return (Err(error), report);
    }
    if !Arc::ptr_eq(&source.clock(), &budget.clock()) {
        return (Err(Failure::Protocol(Fault::InvalidInput)), report);
    }
    let mut instance = vpn::Instance::new();
    let mut owner = match vpn::Client::new(&mut instance, source, profile, limits) {
        Ok(owner) => owner,
        Err(error) => return (Err(Failure::Client(error)), report),
    };
    let mut operation = None;
    let result = async {
        check(&budget)?;
        let original = owner
            .service(
                need.target,
                Some(need.family),
                need.requested_until,
                budget.until(),
            )
            .map_err(Failure::Client)?;
        operation = Some(original);
        report.operation = Some(original.diagnostic());
        loop {
            // A synchronous admission or previous poll cannot renew either
            // original target or authorize another capability after Stop.
            check(&budget)?;
            let progress = budget
                .wait(owner.drive(Some(budget.hard())))
                .await
                .map_err(|error| Failure::Budget(Box::new(error)))?
                .map_err(Failure::Client)?;
            match progress {
                vpn::Progress::Connected(epoch) => report.epoch = Some(epoch.diagnostic()),
                vpn::Progress::Written {
                    epoch,
                    operation: actual,
                    write,
                } if actual == original => {
                    report.epoch = Some(epoch.diagnostic());
                    report.write = Some(write.diagnostic());
                    report.written = true;
                }
                vpn::Progress::Completed {
                    epoch,
                    operation: actual,
                    outcome,
                } if actual == original => {
                    // Consume the real terminal fact before another clock/Stop
                    // check. A later guard failure must not erase this receipt.
                    report.terminal = Some(terminal(epoch, actual, outcome));
                    if let Some(epoch) = epoch {
                        report.epoch = Some(epoch.diagnostic());
                    }
                    check(&budget)?;
                    let address = match (need.family, outcome) {
                        (
                            vpn::Family::V4,
                            vpn::Outcome::Allocation(Some(vpn::Address::V4(bytes))),
                        ) => IpAddr::V4(Ipv4Addr::from(bytes)),
                        (
                            vpn::Family::V6,
                            vpn::Outcome::Allocation(Some(vpn::Address::V6(bytes))),
                        ) => IpAddr::V6(Ipv6Addr::from(bytes)),
                        (_, other) => return Err(Failure::Outcome(other)),
                    };
                    return Ok(Allocation {
                        address,
                        requested_until: need.requested_until,
                    });
                }
                vpn::Progress::Activity {
                    epoch,
                    read_bytes,
                    written_bytes,
                } => {
                    report.epoch = Some(epoch.diagnostic());
                    report.read_prefix_bytes =
                        report.read_prefix_bytes.saturating_add(read_bytes as u64);
                    report.written_prefix_bytes = report
                        .written_prefix_bytes
                        .saturating_add(written_bytes as u64);
                }
                vpn::Progress::Lost { epoch, cause } => {
                    report.epoch = epoch.map(vpn::Epoch::diagnostic).or(report.epoch);
                    report.loss = Some(cause);
                    return Err(Failure::Lost);
                }
                vpn::Progress::ConnectRetry { error, .. } => {
                    report.connect_failures = report.connect_failures.saturating_add(1);
                    if report.connect_error.is_none() {
                        report.connect_error = Some(error);
                    }
                }
                vpn::Progress::Unavailable(error) => return Err(Failure::Client(error)),
                vpn::Progress::WaitDeadline => {
                    return Err(Failure::Budget(Box::new(crate::Error::Deadline)));
                }
                vpn::Progress::Closed => return Err(Failure::Closed),
                vpn::Progress::Completed {
                    epoch,
                    operation: actual,
                    outcome,
                } => {
                    report.other_terminal = Some(terminal(epoch, actual, outcome));
                    return Err(Failure::Protocol(Fault::Stale));
                }
                vpn::Progress::Written { .. } => return Err(Failure::Protocol(Fault::Stale)),
                vpn::Progress::Ignored(_) => {
                    report.other_events = report.other_events.saturating_add(1)
                }
            }
        }
    }
    .await;
    // This single-operation MQ can be physically retired immediately. Do not
    // call cancel(): it samples canonical time and may fail when that same
    // port has died. Actual close detaches first, then creates original local
    // Unsent/Unknown completions. No close outcome claims a lease revocation.
    report.close_invoked = true;
    let closed = match owner.close() {
        Ok(progress) => {
            if let Some(vpn::Progress::Lost { epoch, cause }) = progress {
                report.epoch = epoch.map(vpn::Epoch::diagnostic).or(report.epoch);
                report.close_loss = Some(cause);
            }
            true
        }
        Err(error) => {
            report.close_error = Some(error);
            false
        }
    };
    // This is the actual original retained completion queue, not a fabricated
    // allocation/cancel result. next_event is clock-free and performs no IO.
    while let Some(progress) = owner.next_event() {
        match progress {
            vpn::Progress::Completed {
                epoch,
                operation: actual,
                outcome,
            } => {
                let fact = terminal(epoch, actual, outcome);
                if Some(actual) == operation && report.retired.is_none() {
                    report.retired = Some(fact);
                } else if report.other_terminal.is_none() {
                    report.other_terminal = Some(fact);
                } else {
                    report.other_events = report.other_events.saturating_add(1);
                }
            }
            vpn::Progress::Lost { epoch, cause } if report.loss.is_none() => {
                report.epoch = epoch.map(vpn::Epoch::diagnostic).or(report.epoch);
                report.loss = Some(cause);
            }
            _ => report.other_events = report.other_events.saturating_add(1),
        }
    }
    report.remaining = owner.pending();
    let settled = operation.is_none() || report.terminal.is_some() || report.retired.is_some();
    report.closed = closed && report.remaining == 0 && settled;
    let result = if result.is_ok() && !report.closed {
        Err(Failure::Retirement)
    } else {
        result
    };
    (result, report)
}
