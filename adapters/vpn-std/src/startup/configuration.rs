//! Common official VPN and bounded local owner configuration.
use crate::{
    coordinator::{ConfiguredExit, DiscoveryMode, Limits as Coordination, Network},
    server,
};
use gnunet_config::Configuration;
use gnunet_service_runtime::{
    credentials::UnixAccess,
    service::{ServiceOptions, ShutdownMode},
    service_options,
};
use gnunet_vpn::{self as core, Address, AfProfile, PeerProfiles, Prefix};
use std::{
    error::Error,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use super::Pools;

type Failure = Box<dyn Error>;

const LOCAL: &[u8] = b"vpn-rust";
fn text<'a>(c: &'a Configuration, section: &[u8], key: &[u8]) -> Result<Option<&'a str>, Failure> {
    c.get(section, key)
        .map(std::str::from_utf8)
        .transpose()
        .map_err(Into::into)
}
fn n(c: &Configuration, section: &[u8], key: &[u8], default: usize) -> Result<usize, Failure> {
    Ok(c.get(section, key)
        .map(|_| c.get_number(section, key))
        .transpose()?
        .map(usize::try_from)
        .transpose()?
        .unwrap_or(default))
}
fn size(c: &Configuration, key: &[u8], default: usize) -> Result<usize, Failure> {
    Ok(c.get(LOCAL, key)
        .map(|_| c.get_size(LOCAL, key))
        .transpose()?
        .map(usize::try_from)
        .transpose()?
        .unwrap_or(default))
}
fn yes(c: &Configuration, section: &[u8], key: &[u8], default: bool) -> Result<bool, Failure> {
    Ok(c.get(section, key)
        .map(|_| c.get_yesno(section, key))
        .transpose()?
        .unwrap_or(default))
}
fn micros(c: &Configuration, key: &[u8], default: u64) -> Result<u64, Failure> {
    let v = c
        .get(LOCAL, key)
        .map(|_| c.get_time(LOCAL, key))
        .transpose()?
        .unwrap_or(default);
    if v == 0
        || v == u64::MAX
        || std::time::Instant::now()
            .checked_add(Duration::from_micros(v))
            .is_none()
    {
        return Err("VPN timer must be finite, nonzero and representable".into());
    }
    Ok(v)
}
fn duration(c: &Configuration, key: &[u8], default: u64) -> Result<Duration, Failure> {
    Ok(Duration::from_micros(micros(c, key, default)?))
}
fn af(s: &str) -> Result<AfProfile, Failure> {
    s.parse()
        .map_err(|_| "AF profile must be native, linux, darwin, freebsd or windows".into())
}
fn address(a: IpAddr) -> Address {
    match a {
        IpAddr::V4(a) => Address::V4(a.octets()),
        IpAddr::V6(a) => Address::V6(a.octets()),
    }
}
/// Validated resource, wire codec and exit policy for the local VPN owners.
/// Desktop and application starts share this policy; device selection is separate.
pub struct ServiceSettings {
    pub(super) clients: usize,
    pub(super) requests: usize,
    pub(super) leases: usize,
    pub(super) flows: usize,
    pub(super) small_count: usize,
    pub(super) small_bytes: usize,
    pub(super) large_count: usize,
    pub(super) large_bytes: usize,
    backing_bytes: usize,
    /// Effective pure VPN limits and device plan.
    pub core: core::Limits,
    /// Native local VPN IPC bounds.
    pub native: server::Limits,
    /// Native CADET client framing and credit limits.
    pub cadet: gnunet_cadet_host::Limits,
    /// Native VPN coordination and discovery bounds.
    pub coordinator: Coordination,
    /// Actual REGEX search bounds when automatic Internet-exit discovery is enabled.
    pub regex: Option<crate::discovery::Limits>,
    /// Caller-configured fixed Internet gateways in policy order.
    pub exits: Vec<ConfiguredExit>,
    /// Configured address-family profiles for named peers.
    pub peer_profiles: PeerProfiles,
    /// Official service admission and unknown-message behavior.
    pub options: ServiceOptions,
    /// Optional stricter local credential checks.
    pub unix: UnixAccess,
    /// Absolute startup budget before initial route and CADET readiness.
    pub startup: Duration,
}

impl ServiceSettings {
    /// Read the official `[vpn]` address/lease/flow settings and `[vpn-rust]`
    /// resource and exit policy. The composition supplies a discovery default
    /// for configurations without an explicit `[vpn-rust] EXIT_DISCOVERY`.
    pub fn read(c: &Configuration, default_discovery: DiscoveryMode) -> Result<Self, Failure> {
        let ipv4 = if yes(c, LOCAL, b"ENABLE_IPV4", true)? {
            let a: Ipv4Addr = text(c, b"vpn", b"IPV4ADDR")?
                .unwrap_or("10.11.10.1")
                .parse()?;
            let m: Ipv4Addr = text(c, b"vpn", b"IPV4MASK")?
                .unwrap_or("255.255.0.0")
                .parse()?;
            let bits = u32::from(m).leading_ones() as u8;
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits)
            };
            if u32::from(m) != mask || bits > 30 {
                return Err("IPV4MASK must be contiguous with lease-address capacity".into());
            }
            Some(Prefix {
                network: Address::V4((u32::from(a) & mask).to_be_bytes()),
                bits,
                interface: Address::V4(a.octets()),
            })
        } else {
            None
        };
        let ipv6 = if yes(c, LOCAL, b"ENABLE_IPV6", true)? {
            let a: Ipv6Addr = text(c, b"vpn", b"IPV6ADDR")?.unwrap_or("1234::1").parse()?;
            let bits = u8::try_from(n(c, b"vpn", b"IPV6PREFIX", 32)?)?;
            if bits >= 127 {
                return Err("IPV6PREFIX must be below127 as in the pinned official service".into());
            }
            let mask = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - bits)
            };
            Some(Prefix {
                network: Address::V6((u128::from(a) & mask).to_be_bytes()),
                bits,
                interface: Address::V6(a.octets()),
            })
        } else {
            None
        };
        if ipv4.is_none() && ipv6.is_none() {
            return Err("VPN requires at least one configured TUN family".into());
        }
        let clients = n(c, LOCAL, b"MAX_CLIENTS", 8)?;
        let per_client = n(c, LOCAL, b"REQUESTS_PER_CLIENT", 32)?;
        let requests = n(
            c,
            LOCAL,
            b"REQUEST_SLOTS",
            clients
                .checked_mul(per_client)
                .ok_or("request capacity overflow")?,
        )?;
        let leases = n(c, b"vpn", b"MAX_MAPPING", 200)?;
        let flows = n(c, b"vpn", b"MAX_TUNNELS", 200)?;
        let packet_bytes = size(c, b"PACKET_BYTES", 65535)?;
        let small_count = n(c, LOCAL, b"PACKET_SLOTS", 16)?;
        let small_bytes = size(c, b"PACKET_SLOT_BYTES", 2048)?;
        let large_count = n(c, LOCAL, b"LARGE_PACKET_SLOTS", 4)?;
        let large_bytes = size(c, b"LARGE_PACKET_BYTES", 65575)?;
        let backing_bytes = small_count
            .checked_mul(small_bytes)
            .and_then(|n| {
                large_count
                    .checked_mul(large_bytes)
                    .and_then(|m| n.checked_add(m))
            })
            .ok_or("VPN shared backing overflow")?;
        let minimum = packet_bytes.max(
            packet_bytes
                .checked_add(4)
                .ok_or("packet length overflow")?
                .min(gnunet_wire::official::cadet::MAX_APPLICATION_MESSAGE_SIZE),
        );
        if !(1..=256).contains(&clients)
            || !(1..=1024).contains(&per_client)
            || !(1..=65536).contains(&requests)
            || !(1..=4096).contains(&leases)
            || !(1..=4096).contains(&flows)
            || !(48..=gnunet_tun_host::Limits::MAX_PACKET_BYTES).contains(&packet_bytes)
            || small_count > 4096
            || large_count > 4096
            || large_count == 0
            || small_bytes == 0
            || small_bytes > 65575
            || large_bytes < minimum
            || large_bytes > 65575
            || backing_bytes > 64 * 1024 * 1024
        {
            return Err("invalid bounded VPN pool sizes (shared payload ceiling64MiB)".into());
        }
        let mtu = u32::try_from(n(c, LOCAL, b"MTU", 1280)?)?;
        if !(68..=65535).contains(&mtu)
            || (ipv6.is_some() && mtu < 1280)
            || mtu as usize > packet_bytes
        {
            return Err("MTU does not fit enabled TUN families and raw packet bound".into());
        }
        let peer_profiles = peer_profiles(c)?;
        let ipc_af = af(text(c, LOCAL, b"IPC_AF_PROFILE")?.unwrap_or("native"))?;
        let shutdown = duration(c, b"SHUTDOWN_GRACE", 10_000_000)?;
        let d = server::Limits::default();
        let native = server::Limits {
            clients,
            requests_per_client: per_client,
            frame_bytes: 128,
            io_slice_bytes: n(c, LOCAL, b"IO_SLICE_BYTES", d.io_slice_bytes)?,
            input_timeout: duration(c, b"IPC_INPUT_TIMEOUT", 5_000_000)?,
            send_timeout: duration(c, b"IPC_SEND_TIMEOUT", 5_000_000)?,
            shutdown_grace: shutdown,
            maintenance_interval: duration(c, b"MAINTENANCE_INTERVAL", 100_000)?,
        };
        if native.io_slice_bytes == 0
            || native.maintenance_interval < Duration::from_millis(1)
            || native.maintenance_interval > Duration::from_secs(1)
        {
            return Err("invalid native VPN IO/tick bounds".into());
        }
        let core = core::Limits {
            ipv4,
            ipv6,
            ipc_af,
            packet_bytes,
            idle_micros: micros(c, b"IDLE_TIMEOUT", 300_000_000)?,
        };
        let coordinator = Coordination {
            flows,
            mtu,
            control_timeout: duration(c, b"CONFIGURE_TIMEOUT", 10_000_000)?,
            input_timeout: duration(c, b"PEER_INPUT_TIMEOUT", 5_000_000)?,
            tun_send_timeout: duration(c, b"TUN_SEND_TIMEOUT", 5_000_000)?,
            cadet_send_timeout: duration(c, b"CADET_SEND_TIMEOUT", 10_000_000)?,
            shutdown_grace: shutdown,
            monitor_timeout: duration(c, b"ADDRESS_WATCH_TIMEOUT", 3_000_000)?,
            discovery: discovery(c, default_discovery)?,
            ..Coordination::default()
        };
        let regex = match coordinator.discovery {
            DiscoveryMode::Configured => None,
            DiscoveryMode::External => {
                let defaults = crate::discovery::Limits::default();
                let limits = crate::discovery::Limits {
                    searches: n(c, LOCAL, b"REGEX_SEARCHES", defaults.searches)?,
                    send_micros: micros(c, b"REGEX_SEND_TIMEOUT", defaults.send_micros)?,
                    first_result_micros: micros(
                        c,
                        b"REGEX_FIRST_RESULT_TIMEOUT",
                        defaults.first_result_micros,
                    )?,
                    lifetime_micros: micros(c, b"REGEX_SEARCH_TIMEOUT", defaults.lifetime_micros)?,
                    native: gnunet_regex_client_host::Limits {
                        io_slice_bytes: n(
                            c,
                            LOCAL,
                            b"REGEX_IO_SLICE_BYTES",
                            defaults.native.io_slice_bytes,
                        )?,
                        ..defaults.native
                    },
                };
                limits.validate()?;
                Some(limits)
            }
        };
        let cadet = gnunet_cadet_host::Limits {
            io_slice_bytes: n(c, LOCAL, b"CADET_IO_SLICE_BYTES", 65535)?,
            ..gnunet_cadet_host::Limits::default()
        };
        if cadet.io_slice_bytes == 0 {
            return Err("CADET_IO_SLICE_BYTES must be nonzero".into());
        }
        let exits = policies(c)?;
        if coordinator.discovery == DiscoveryMode::External && !exits.is_empty() {
            return Err("CONFIGURED_EXITS requires explicit EXIT_DISCOVERY=configured".into());
        }
        Ok(Self {
            clients,
            requests,
            leases,
            flows,
            small_count,
            small_bytes,
            large_count,
            large_bytes,
            backing_bytes,
            core,
            native,
            cadet,
            coordinator,
            regex,
            exits,
            peer_profiles,
            options: service_options(c, b"vpn", ShutdownMode::Immediate)?,
            unix: UnixAccess::from_config(c, b"vpn")?.unwrap_or_default(),
            startup: duration(c, b"STARTUP_TIMEOUT", 30_000_000)?,
        })
    }

    /// Reserve fixed raw packet backing and original VPN/CADET slot pools.
    pub fn allocate(&self) -> Result<Pools, std::collections::TryReserveError> {
        Pools::new(self)
    }

    /// Total reserved raw packet backing in bytes.
    #[must_use]
    pub const fn backing_bytes(&self) -> usize {
        self.backing_bytes
    }
}

fn discovery(c: &Configuration, default: DiscoveryMode) -> Result<DiscoveryMode, Failure> {
    match text(c, LOCAL, b"EXIT_DISCOVERY")? {
        None => Ok(default),
        Some("regex") => Ok(DiscoveryMode::External),
        Some("configured") => Ok(DiscoveryMode::Configured),
        Some(_) => Err("EXIT_DISCOVERY must be regex or configured".into()),
    }
}

fn policies(c: &Configuration) -> Result<Vec<ConfiguredExit>, Failure> {
    let mut out = Vec::new();
    out.try_reserve_exact(64)?;
    for entry in text(c, LOCAL, b"CONFIGURED_EXITS")?
        .unwrap_or("")
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if out.len() == 64 {
            return Err("more than64 configured exit policies".into());
        }
        let mut fields = entry.split_ascii_whitespace();
        let (Some(p), Some(net), Some(protocol), Some(ports), Some(profile), None) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            return Err("CONFIGURED_EXITS entry is: PEER prefix|any tcp|udp|icmp|icmp6|any first-last native|linux|darwin|freebsd|windows".into());
        };
        let network = if net == "any" {
            None
        } else {
            let (a, b) = net.split_once('/').ok_or("exit prefix needs /bits")?;
            let n = Network {
                address: address(a.parse()?),
                bits: b.parse()?,
            };
            n.validate()?;
            Some(n)
        };
        let protocol = match protocol {
            "any" => None,
            "tcp" => Some(6),
            "udp" => Some(17),
            "icmp" => Some(1),
            "icmp6" => Some(58),
            _ => return Err("unknown configured exit protocol".into()),
        };
        let (a, b) = ports
            .split_once('-')
            .ok_or("exit port range needs first-last")?;
        let ports = (a.parse()?, b.parse()?);
        if ports.0 > ports.1 {
            return Err("reversed exit port range".into());
        }
        out.push(ConfiguredExit {
            network,
            protocol,
            ports,
            peer: core::parse_peer_identity(p)?,
            af: af(profile)?,
        });
    }
    Ok(out)
}
fn peer_profiles(config: &Configuration) -> Result<PeerProfiles, Failure> {
    let fallback = text(config, LOCAL, b"PEER_AF_PROFILE")?
        .map(af)
        .transpose()?;
    let value = text(config, LOCAL, b"PEER_AF_PROFILES")?.unwrap_or("");
    PeerProfiles::parse_with_optional_fallback(fallback, value)
        .map_err(|error| format!("invalid PEER_AF_PROFILES: {error}").into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use gnunet_vpn::AfProfile;

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Check normalized peer identity and the configured AF profile"
    )]
    fn profiles_select_by_identity_and_reject_alias_duplicates() -> Result<(), Failure> {
        let mut config = Configuration::default();
        let empty = peer_profiles(&config)?;
        assert_eq!(empty.gateway_profile(&[1; 32]), AfProfile::LINUX);
        assert_eq!(empty.profile(&[1; 32]), AfProfile::native());
        let zero = "0".repeat(64);
        let one = "01".repeat(32);
        let value = format!("{one} freebsd; {zero} darwin");
        config.set_value(LOCAL, b"PEER_AF_PROFILES", Some(value.as_bytes()))?;
        let profiles = peer_profiles(&config)?;
        assert_eq!(profiles.profile(&[0; 32]), AfProfile::DARWIN);
        assert_eq!(profiles.profile(&[1; 32]), AfProfile::FREEBSD);
        assert_eq!(profiles.gateway_profile(&[1; 32]), AfProfile::FREEBSD);
        assert_eq!(profiles.gateway_profile(&[2; 32]), AfProfile::LINUX);
        assert_eq!(profiles.profile(&[2; 32]), AfProfile::native());
        config.set_value(LOCAL, b"PEER_AF_PROFILE", Some(b"windows"))?;
        let profiles = peer_profiles(&config)?;
        assert_eq!(profiles.gateway_profile(&[1; 32]), AfProfile::FREEBSD);
        assert_eq!(profiles.gateway_profile(&[2; 32]), AfProfile::WINDOWS);

        let base32 = "0".repeat(52);
        let duplicate = format!("{zero} darwin; {base32} linux");
        config.set_value(LOCAL, b"PEER_AF_PROFILES", Some(duplicate.as_bytes()))?;
        assert!(peer_profiles(&config).is_err());
        Ok(())
    }
}
