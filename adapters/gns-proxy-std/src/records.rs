//! Exact GNS result projection for one SOCKS TCP destination.
use crate::{Error, budget::Budget, tls, vpn};
use gnunet_gnsrecord::{RecordFlags, RecordSet, RecordType};
use gnunet_types::Error as Fault;
use gnunet_vpn_client_host::{Family, Protocol, Service};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
/// Explicit bounded record projection policy, not a DNS record schema.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Useful address candidates retained in source order.
    pub addresses: usize,
    /// Matching TCP/port TLSA rows retained.
    pub tlsa: usize,
    /// Actual GNS serialized record bytes, without a DNS-name service cap.
    pub bytes: usize,
    /// Raw VPN intents retained; each requires a genuine allocation callback.
    pub vpn: usize,
    /// Requested lease ceiling from actual observation, not confirmed lease duration.
    pub vpn_lease: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            addresses: 16,
            tlsa: 32,
            bytes: 65535,
            vpn: 8,
            vpn_lease: Duration::from_secs(1800),
        }
    }
}
/// Bounded source/projection observations. These counts do not authenticate an IP.
#[derive(Clone, Copy, Debug, Default)]
pub struct Summary {
    /// Actual GNS source rows, including nonprojectable types.
    pub source_records: usize,
    /// Actual useful native IP rows retained before VPN allocation.
    pub addresses: usize,
    /// Explicitly omitted unsupported/irrelevant records.
    pub skipped: usize,
    /// Expired source records, not a native lookup failure.
    pub expired: usize,
    /// Matching TLSA bodies shorter than the three-octet header, ignored.
    pub malformed_tlsa: usize,
    /// Original raw VPN records selected as allocation intents.
    pub vpn_intents: usize,
}
/// Original target facts. No pending VPN intent can create an address by itself.
pub(crate) struct Plan {
    pub browser_host: String,
    pub upstream_host: String,
    pub port: u16,
    pub tls: bool,
    pub addresses: Vec<SocketAddr>,
    pub tlsa: Option<tls::AuthenticatedTlsa>,
    pub vpn: Vec<vpn::Need>,
    pub expires: u64,
    pub summary: Summary,
}
fn copy(input: &str) -> Result<String, Error> {
    let mut s = String::new();
    s.try_reserve_exact(input.len())
        .map_err(Error::Allocation)?;
    s.push_str(input);
    Ok(s)
}
/// Use the existing complete IDNA backend for an actual HTTP/TLS hostname.
pub(crate) fn hostname(input: &str) -> Result<String, Error> {
    if input.is_empty()
        || input.contains(['\0', '/', '\\', ':', '@', '#', '?'])
        || input.chars().any(char::is_control)
    {
        return Err(Fault::InvalidInput.into());
    }
    let mut work = gnunet_idna::Workspace::new();
    let mut output = [0; 255];
    let len = gnunet_idna::to_ascii(
        input.as_bytes(),
        &mut output,
        &mut work,
        gnunet_idna::Limits::GNUNET,
        gnunet_idna::NativeProfile::Libunistring1_5Unicode18_0,
    )
    .map_err(Error::Idna)?;
    let out = std::str::from_utf8(&output[..len])
        .map_err(|_| Fault::Malformed)?
        .trim_end_matches('.');
    if out.is_empty() || out.len() > 253 {
        return Err(Fault::TooLarge.into());
    }
    copy(out)
}
fn expiration(value: u64, flags: RecordFlags, now: u64) -> u64 {
    if flags.contains(RecordFlags::RELATIVE_EXPIRATION) {
        now.saturating_add(value)
    } else {
        value
    }
}
pub(crate) fn system_time(value: u64) -> Result<SystemTime, Error> {
    UNIX_EPOCH
        .checked_add(Duration::from_micros(value))
        .ok_or(Fault::Overflow.into())
}
fn push_address(plan: &mut Plan, address: IpAddr, limits: Limits) -> Result<(), Error> {
    let address = SocketAddr::new(address, plan.port);
    if plan.addresses.contains(&address) {
        return Ok(());
    }
    if plan.addresses.len() == limits.addresses {
        return Err(Fault::Capacity.into());
    }
    plan.addresses.try_reserve(1).map_err(Error::Allocation)?;
    plan.addresses.push(address);
    Ok(())
}
impl Plan {
    pub(crate) fn numeric(address: SocketAddr, disable_ipv6: bool) -> Result<Self, Error> {
        if disable_ipv6 && address.is_ipv6() {
            return Err(Fault::Unsupported.into());
        }
        let host = address.ip().to_string();
        Ok(Self {
            browser_host: host.clone(),
            upstream_host: host,
            port: address.port(),
            tls: address.port() == 443,
            addresses: vec![address],
            tlsa: None,
            vpn: Vec::new(),
            expires: u64::MAX,
            summary: Summary::default(),
        })
    }
    pub(crate) fn dns(name: &str, port: u16) -> Result<Self, Error> {
        let host = hostname(name)?;
        Ok(Self {
            browser_host: host.clone(),
            upstream_host: host,
            port,
            tls: port == 443,
            addresses: Vec::new(),
            tlsa: None,
            vpn: Vec::new(),
            expires: u64::MAX,
            summary: Summary::default(),
        })
    }
    /// Consume only the original actual GNS Answer. GNS service/transport failures
    /// never enter this function as empty or non-GNS records.
    pub(crate) fn gns(
        name: &str,
        port: u16,
        records: RecordSet<'_>,
        disable_ipv6: bool,
        limits: Limits,
        budget: &Budget,
    ) -> Result<Self, Error> {
        budget.check()?;
        if limits.addresses == 0
            || limits.addresses > 256
            || limits.tlsa == 0
            || limits.tlsa > 256
            || limits.vpn > 64
            || limits.bytes == 0
            || limits.bytes > 65535
            || records.record_bytes().len() > limits.bytes
            || limits.vpn_lease.is_zero()
        {
            return Err(Fault::Capacity.into());
        }
        let mut plan = Self::dns(name, port)?;
        let now = budget.now()?;
        let lease_delta =
            u64::try_from(limits.vpn_lease.as_micros()).map_err(|_| Fault::Overflow)?;
        let mut tlsa = Vec::new();
        let mut tlsa_expiry = u64::MAX;
        for row in records.iter() {
            budget.check()?;
            let row = row?;
            plan.summary.source_records += 1;
            let expires = expiration(row.expiration_time, row.flags, now);
            if expires <= now {
                plan.summary.expired += 1;
                continue;
            }
            match row.record_type {
                RecordType::A => {
                    let bytes: [u8; 4] = row.data.try_into().map_err(|_| Fault::Malformed)?;
                    push_address(&mut plan, IpAddr::V4(Ipv4Addr::from(bytes)), limits)?;
                    plan.expires = plan.expires.min(expires);
                }
                RecordType::AAAA if !disable_ipv6 => {
                    let bytes: [u8; 16] = row.data.try_into().map_err(|_| Fault::Malformed)?;
                    push_address(&mut plan, IpAddr::V6(Ipv6Addr::from(bytes)), limits)?;
                    plan.expires = plan.expires.min(expires);
                }
                RecordType::LEHO => {
                    let raw = row.data.strip_suffix(&[0]).unwrap_or(row.data);
                    if raw.contains(&0) {
                        return Err(Fault::Malformed.into());
                    }
                    let value = std::str::from_utf8(raw).map_err(|_| Fault::Malformed)?;
                    plan.upstream_host = hostname(value)?;
                    plan.expires = plan.expires.min(expires);
                }
                RecordType::BOX => {
                    let head = row.data.get(..8).ok_or(Fault::Truncated)?;
                    let protocol = u16::from_be_bytes([head[0], head[1]]);
                    let service = u16::from_be_bytes([head[2], head[3]]);
                    let kind =
                        u32::from_be_bytes(head[4..8].try_into().map_err(|_| Fault::Truncated)?);
                    if protocol != 6 || service != port || kind != RecordType::TLSA.value() {
                        plan.summary.skipped += 1;
                        continue;
                    }
                    plan.tls = true;
                    let Some(head) = row.data.get(8..11) else {
                        plan.summary.malformed_tlsa += 1;
                        continue;
                    };
                    if tlsa.len() == limits.tlsa {
                        return Err(Fault::Capacity.into());
                    }
                    let data = &row.data[11..];
                    let mut association = Vec::new();
                    association
                        .try_reserve_exact(data.len())
                        .map_err(Error::Allocation)?;
                    association.extend_from_slice(data);
                    tlsa.try_reserve(1).map_err(Error::Allocation)?;
                    // Unknown values remain original data. The TLS verifier
                    // applies RFC usable-RRset selection, never a whole-set veto.
                    tlsa.push(tls::TlsaRecord {
                        usage: head[0],
                        selector: head[1],
                        matching: head[2],
                        association,
                    });
                    tlsa_expiry = tlsa_expiry.min(expires);
                    plan.expires = plan.expires.min(expires);
                }
                RecordType::VPN => {
                    let head = row.data.get(..34).ok_or(Fault::Truncated)?;
                    let protocol = u16::from_be_bytes([head[32], head[33]]);
                    if protocol != 6 {
                        plan.summary.skipped += 1;
                        continue;
                    } // SOCKS CONNECT is TCP
                    let service = &row.data[34..];
                    if service.last() != Some(&0)
                        || service[..service.len().saturating_sub(1)].contains(&0)
                    {
                        return Err(Fault::Malformed.into());
                    }
                    if plan.vpn.len() == limits.vpn {
                        return Err(Fault::Capacity.into());
                    }
                    budget.check()?;
                    let descriptor = gnunet_vpn::service_descriptor(&service[..service.len() - 1]);
                    budget.check()?;
                    let need = vpn::Need {
                        target: Service {
                            peer: head[..32].try_into().map_err(|_| Fault::Truncated)?,
                            descriptor,
                            protocol: Protocol::Tcp,
                        },
                        family: Family::V4,
                        requested_until: expires.min(now.saturating_add(lease_delta)),
                    };
                    plan.vpn.try_reserve(1).map_err(Error::Allocation)?;
                    plan.vpn.push(need);
                    plan.summary.vpn_intents += 1;
                }
                _ => plan.summary.skipped += 1,
            }
        }
        plan.summary.addresses = plan.addresses.len();
        if !tlsa.is_empty() {
            plan.tlsa = Some(tls::AuthenticatedTlsa {
                hostname: plan.upstream_host.clone(),
                port,
                expires_at: system_time(tlsa_expiry)?,
                records: tlsa,
            });
        }
        budget.check()?;
        Ok(plan)
    }
    /// Only a genuine matching VPN callback may append its actual address.
    pub(crate) fn allocated(
        &mut self,
        allocation: vpn::Allocation,
        limits: Limits,
    ) -> Result<(), Error> {
        push_address(self, allocation.address, limits)?;
        self.expires = self.expires.min(allocation.requested_until);
        Ok(())
    }
}
