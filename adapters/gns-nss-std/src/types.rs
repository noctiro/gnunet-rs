//! Bounded per-call policy and owned native resolution/retirement facts.
use gnunet_gns_host::tld;
use std::{fmt, io, net::IpAddr, time::Duration};
/// Explicit host-address family; this is not a guessed native AF integer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Family {
    /// Actual A records.
    V4,
    /// Actual AAAA records.
    V6,
}
/// One independently bounded NSS lookup. No source/worker is cached forever.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Original whole-call duration, captured before the worker is started.
    pub timeout: Duration,
    /// Actual address results retained, from1 through official16.
    pub addresses: usize,
    /// Original input DNS-compatible bytes, bounded independently of libc buffer.
    pub name_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            addresses: 16,
            name_bytes: 1024,
        }
    }
}
/// Genuine classification. Only an actual missing IDENTITY suffix is NotGns.
#[derive(Debug)]
pub enum Outcome {
    /// Actual matching family IP records from the original GNS Answer.
    Addresses(Vec<IpAddr>),
    /// Actual GNS Answer had no useful record of this requested family.
    NoData,
    /// Actual IDENTITY missing result: let the next NSS module try.
    NotGns,
    /// Native/query/privilege/admission failure, never an invented DNS negative.
    Unavailable,
}
/// Original failure with owned causes and without private lookup/key bytes.
#[derive(Debug)]
pub enum Error {
    /// Explicit resource/input/source contract failure.
    Protocol(gnunet_types::Error),
    /// Actual configuration load/copy failure.
    Configuration(gnunet_config::Error),
    /// Actual ordinary CLIENT endpoint/clock refusal.
    Endpoint(gnunet_client_host::ConnectError),
    /// Actual with-TLD query/source failure.
    Lookup(tld::Cause),
    /// Actual shared Resolver failure.
    Resolver(gnunet_resolver_broker::BrokerError),
    /// Actual original source clock failure.
    Clock(gnunet_types::Error),
    /// Actual thread/reactor/native operating-system cause.
    Io(io::Error),
    /// Bounded synchronous IDNA conversion refusal.
    Idna(gnunet_idna::Error),
    /// Original native or canonical target elapsed.
    Deadline,
    /// Process-local concurrency admission refused before starting a worker.
    Busy,
    /// Same thread reentered NSS before its original call returned.
    Reentered,
    /// Explicit privileged-process bypass, matching the official root boundary.
    Privileged,
    /// A worker actually terminated by panic; no panic payload is echoed.
    WorkerPanicked,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(e) => write!(f, "GNS NSS protocol/resource: {e}"),
            Self::Configuration(e) => write!(f, "GNS NSS configuration: {e}"),
            Self::Endpoint(e) => write!(f, "GNS NSS endpoint: {e}"),
            Self::Lookup(e) => write!(f, "GNS NSS lookup: {e}"),
            Self::Resolver(e) => write!(f, "GNS NSS Resolver: {e}"),
            Self::Clock(e) => write!(f, "GNS NSS clock: {e}"),
            Self::Io(e) => write!(f, "GNS NSS native IO: {e}"),
            Self::Idna(e) => write!(f, "GNS NSS IDNA: {e:?}"),
            Self::Deadline => f.write_str("GNS NSS original deadline"),
            Self::Busy => f.write_str("GNS NSS bounded worker capacity"),
            Self::Reentered => f.write_str("GNS NSS same-thread reentry"),
            Self::Privileged => f.write_str("GNS NSS privileged caller bypass"),
            Self::WorkerPanicked => f.write_str("GNS NSS worker terminated by panic"),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(e) | Self::Clock(e) => Some(e),
            Self::Configuration(e) => Some(e),
            Self::Endpoint(e) => Some(e),
            Self::Lookup(e) => Some(e),
            Self::Resolver(e) => Some(e),
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}
impl From<gnunet_types::Error> for Error {
    fn from(e: gnunet_types::Error) -> Self {
        Self::Protocol(e)
    }
}
/// Actual callback and independent cleanup facts from the original per-call scope.
#[derive(Debug, Default)]
pub struct Report {
    /// Original principal failure, if any.
    pub error: Option<Error>,
    /// Actual original with-TLD retirement, with borrowed authority consumed.
    pub lookup: Option<tld::Diagnostics>,
    /// Actual original GNS source loss cause.
    pub gns_loss: Option<gnunet_gns_client_host::LossCause>,
    /// Actual original IDENTITY source loss cause.
    pub identity_loss: Option<gnunet_identity_client_host::LossCause>,
    /// First genuine native lookup connection failure.
    pub connect_error: Option<io::Error>,
    /// First genuine endpoint selection refusal during native progress.
    pub endpoint_error: Option<gnunet_client_host::ConnectError>,
    /// Explicit later original native causes omitted after bounded slots.
    pub omitted_errors: u64,
    /// Actual Resolver driver poll failure.
    pub resolver_error: Option<gnunet_resolver_broker::BrokerError>,
    /// Actual original Resolver native IO failure.
    pub resolver_io: Option<io::Error>,
    /// Actual original Resolver construction failure.
    pub resolver_connect: Option<gnunet_resolver_broker::BrokerError>,
    /// Actual shared source retirement category, not a name END.
    pub resolver_loss: Option<gnunet_types::Error>,
    /// Original retained physical envelopes before actual disconnect.
    pub queued_before_close: Option<usize>,
    /// Independent error reading original queue metadata.
    pub queue_error: Option<gnunet_resolver_broker::BrokerError>,
    /// Independent actual original driver disconnect failure.
    pub disconnect_error: Option<gnunet_resolver_broker::BrokerError>,
    /// Actual original Resolver disconnect returned successfully.
    pub resolver_disconnected: bool,
    /// Original driver was physically relinquished after disconnect attempt.
    pub driver_dropped: bool,
    /// The private current-thread runtime was constructed.
    pub runtime_created: bool,
    /// Original runtime was actually dropped after its native owners retired.
    pub runtime_dropped: bool,
    /// A bounded owned worker was successfully started.
    pub worker_started: bool,
    /// Original worker was actually joined, not inferred from timeout.
    pub worker_joined: bool,
}
/// One actual lookup outcome with independent original causes.
#[derive(Debug)]
pub struct Completion {
    /// Actual GNS/IP/missing classification.
    pub outcome: Outcome,
    /// Original native and cleanup facts.
    pub report: Report,
}
impl Completion {
    pub(crate) fn failed(error: Error) -> Self {
        Self {
            outcome: Outcome::Unavailable,
            report: Report {
                error: Some(error),
                ..Report::default()
            },
        }
    }
}

impl Report {
    /// Principal/terminal cleanup errors, without treating a recovered connection
    /// retry as a failed lookup. Actual successful address data remains owned.
    #[must_use]
    pub fn failed(&self) -> bool {
        self.error.is_some()
            || self.resolver_error.is_some()
            || self.resolver_loss.is_some()
            || self.queue_error.is_some()
            || self.disconnect_error.is_some()
            || self
                .lookup
                .as_ref()
                .is_some_and(|r| r.gns_cancel_error.is_some() || r.identity_cancel_error.is_some())
    }
}
