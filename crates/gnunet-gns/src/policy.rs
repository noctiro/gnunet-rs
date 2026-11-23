//! Shared resolution intent, policy and record capabilities.

use crate::{Error, RecordType, ZoneKey};
use core::net::IpAddr;

/// Security provenance of returned records. DNS and system answers never
/// acquire GNS authentication by sharing the same record format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Origin {
    /// The owning resolver verified the signature for this zone and label.
    Gns(ZoneKey),
    /// Recursive DNS result from the explicitly selected server.
    Dns(IpAddr),
    /// Result of the explicit default-system redirection port.
    System,
    /// Optional numeric-address application convenience; no GNS lookup occurred.
    Literal,
}

/// Where authenticated zone records may be obtained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Policy {
    /// Local authenticated cache first, remote storage on miss/invalid data.
    CacheThenRemote,
    /// Every authority, including DNS-server GNS children, stays cache-only.
    LocalOnly,
    /// Initial authority cache-only; subsequent authority lookups may be remote.
    LocalMaster,
}
impl Policy {
    /// Interpret the pinned GNS IPC enum without mistaking it for combinable
    /// bit flags. The client codec may preserve unknown bits; domain policy
    /// rejects an option value it cannot enforce.
    pub fn from_local_options(value: u16) -> Result<Self, Error> {
        match value {
            0 => Ok(Self::CacheThenRemote),
            1 => Ok(Self::LocalOnly),
            2 => Ok(Self::LocalMaster),
            _ => Err(Error::Unsupported),
        }
    }
}

/// Whether a GNS lookup may leave GNS for recursive DNS or system resolution.
/// Direct reads of GNS2DNS records do not require this permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsPolicy {
    /// Allow externally resolved names and DNS delegations.
    Allow,
    /// Restrict resolution to GNS and refuse external dependency effects.
    Deny,
}

impl DnsPolicy {
    pub(crate) const fn check(self) -> Result<(), Failure> {
        match self {
            Self::Allow => Ok(()),
            Self::Deny => Err(Failure::DnsDisabled),
        }
    }
}

impl From<bool> for DnsPolicy {
    fn from(enabled: bool) -> Self {
        if enabled { Self::Allow } else { Self::Deny }
    }
}

/// Explicit-zone lookup intent. Raw original name is copied on admission.
#[derive(Clone, Copy, Debug)]
pub struct Lookup<'a> {
    /// Initial authoritative zone.
    pub zone: ZoneKey,
    /// Relative name; empty means apex.
    pub name: &'a str,
    /// Full32-bit requested type; zero requests any type.
    pub record_type: RecordType,
    /// Cache/remote policy propagated to nested GNS dependencies.
    pub policy: Policy,
    /// Global work ceiling, further restricted by Resolver limits.
    pub recursion_limit: u16,
}
/// Semantic terminal failure; never an invented successful record set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Failure {
    /// No usable records or no applicable continuation.
    NotFound,
    /// Authoritative zone is revoked, including cache hits.
    Revoked,
    /// Unknown critical record type.
    Critical(RecordType),
    /// Malformed or mutually exclusive authoritative records.
    Records,
    /// Delegation or redirection illegally stored at apex.
    Apex,
    /// DNS transition disabled by configuration.
    DnsDisabled,
    /// Recursion or aggregate work budget exhausted.
    Recursion,
    /// Original logical query explicitly canceled.
    Cancelled,
    /// Dependency, validation or resource failure.
    Fault(Error),
}
pub(crate) fn supported(kind: RecordType) -> bool {
    matches!(
        kind.value(),
        1 | 2
            | 5
            | 6
            | 12
            | 15
            | 16
            | 28
            | 33
            | 37
            | 39
            | 43
            | 44
            | 46
            | 47
            | 48
            | 50
            | 51
            | 52
            | 53
            | 59
            | 60
            | 61
            | 63
            | 64
            | 65
            | 99
            | 108
            | 109
            | 249
            | 250
            | 255
            | 256
            | 257
            | 65536..=65545 | 65547..=65561 | 65563 | 65564 | 4294901760
    )
}
