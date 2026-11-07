//! Official VPN keys plus explicit bounded local resource/exit selection policy.
use crate::Failure;
use gnunet_config::Configuration;
use gnunet_service_runtime::{
    credentials::UnixAccess,
    service::{ServiceOptions, ShutdownMode},
    service_options,
};
use gnunet_vpn::{self as core, Address, AfProfile, Prefix};
use gnunet_vpn_host::{
    coordinator::{ConfiguredExit, DiscoveryMode, Limits as Coordination, Network},
    server,
};
#[cfg(target_os = "linux")]
use std::path::PathBuf;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};
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
    match s {
        "native" => Ok(AfProfile::native()),
        "linux" => Ok(AfProfile::LINUX),
        "darwin" => Ok(AfProfile::DARWIN),
        _ => Err("AF profile must be native, linux or darwin".into()),
    }
}
fn address(a: IpAddr) -> Address {
    match a {
        IpAddr::V4(a) => Address::V4(a.octets()),
        IpAddr::V6(a) => Address::V6(a.octets()),
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TunMode {
    Fresh,
    Preopened,
}
pub(super) struct Settings {
    pub mode: TunMode,
    pub ifname: String,
    #[cfg(target_os = "linux")]
    pub helper: Option<PathBuf>,
    #[cfg(target_os = "linux")]
    pub helper_mtu: Option<u32>,
    #[cfg(target_os = "linux")]
    pub helper_partial: Duration,
    pub clients: usize,
    pub requests: usize,
    pub leases: usize,
    pub flows: usize,
    pub small_count: usize,
    pub small_bytes: usize,
    pub large_count: usize,
    pub large_bytes: usize,
    pub backing_bytes: usize,
    pub core: core::Limits,
    pub native: server::Limits,
    pub coordinator: Coordination,
    pub cadet: gnunet_cadet_host::Limits,
    pub resolver: gnunet_resolver_broker::Limits,
    pub exits: Vec<ConfiguredExit>,
    pub regex: Option<crate::discovery::Limits>,
    pub options: ServiceOptions,
    pub unix: UnixAccess,
    pub startup: Duration,
}
impl Settings {
    pub fn read(c: &Configuration) -> Result<Self, Failure> {
        let mode=match text(c,LOCAL,b"TUN_MODE")?.unwrap_or("fresh"){"fresh"=>TunMode::Fresh,"preopened"=>TunMode::Preopened,_=>return Err("TUN_MODE must be fresh or preopened; no unavailable mode is presented as forwarding".into())};
        let ifname = text(c, b"vpn", b"IFNAME")?
            .unwrap_or("vpn-gnunet")
            .to_owned();
        if ifname.is_empty()
            || ifname.len() >= libc::IFNAMSIZ
            || !ifname
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        {
            return Err("invalid official [vpn] IFNAME".into());
        }
        #[cfg(target_os = "macos")]
        if mode == TunMode::Fresh
            && ifname
                .strip_prefix("utun")
                .and_then(|s| s.parse::<u32>().ok())
                .is_none()
        {
            return Err("macOS fresh mode requires [vpn] IFNAME=utunN; arbitrary interface renaming is unsupported".into());
        }
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
                .min(64348),
        );
        if !(1..=256).contains(&clients)
            || !(1..=1024).contains(&per_client)
            || !(1..=65536).contains(&requests)
            || !(1..=4096).contains(&leases)
            || !(1..=4096).contains(&flows)
            || !(48..=65575).contains(&packet_bytes)
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
        let peer_af = af(text(c, LOCAL, b"PEER_AF_PROFILE")?.unwrap_or("native"))?;
        let ipc_af = af(text(c, LOCAL, b"IPC_AF_PROFILE")?.unwrap_or("native"))?;
        let regex_mode = match text(c, LOCAL, b"EXIT_DISCOVERY")?.unwrap_or("regex") {
            "regex" => true,
            "configured" => false,
            _ => return Err("EXIT_DISCOVERY must be regex or configured".into()),
        };
        let rd = crate::discovery::Limits::default();
        let regex = if regex_mode {
            let limits = crate::discovery::Limits {
                searches: n(c, LOCAL, b"REGEX_SEARCHES", rd.searches)?,
                send_micros: micros(c, b"REGEX_SEND_TIMEOUT", rd.send_micros)?,
                first_result_micros: micros(
                    c,
                    b"REGEX_FIRST_RESULT_TIMEOUT",
                    rd.first_result_micros,
                )?,
                lifetime_micros: micros(c, b"REGEX_SEARCH_TIMEOUT", rd.lifetime_micros)?,
                peer_af,
                native: gnunet_regex_client_host::Limits {
                    io_slice_bytes: n(c, LOCAL, b"REGEX_IO_SLICE_BYTES", rd.native.io_slice_bytes)?,
                    ..rd.native
                },
            };
            if !(1..=256).contains(&limits.searches)
                || limits.native.io_slice_bytes == 0
                || limits.send_micros > limits.first_result_micros
                || limits.first_result_micros > limits.lifetime_micros
            {
                return Err("invalid bounded REGEX search slots/IO/original deadline order".into());
            }
            Some(limits)
        } else {
            None
        };
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
            peer_af,
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
            service_af: peer_af,
            discovery: if regex_mode {
                DiscoveryMode::External
            } else {
                DiscoveryMode::Configured
            },
            ..Coordination::default()
        };
        let cadet = gnunet_cadet_host::Limits {
            io_slice_bytes: n(c, LOCAL, b"CADET_IO_SLICE_BYTES", 65535)?,
            ..gnunet_cadet_host::Limits::default()
        };
        if cadet.io_slice_bytes == 0 {
            return Err("CADET_IO_SLICE_BYTES must be nonzero".into());
        }
        let resolver = gnunet_resolver_broker::Limits::default();
        let exits = policies(c)?;
        Ok(Self {
            mode,
            ifname,
            #[cfg(target_os = "linux")]
            helper: if mode == TunMode::Fresh {
                Some(c.suid_binary_path(b"gnunet-helper-vpn")?)
            } else {
                None
            },
            #[cfg(target_os = "linux")]
            helper_mtu: c.get(LOCAL, b"MTU").map(|_| mtu),
            #[cfg(target_os = "linux")]
            helper_partial: duration(c, b"HELPER_INPUT_TIMEOUT", 5_000_000)?,
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
            coordinator,
            cadet,
            resolver,
            exits,
            regex,
            options: service_options(c, b"vpn", ShutdownMode::Immediate)?,
            unix: UnixAccess {
                match_uid: yes(c, b"vpn", b"UNIX_MATCH_UID", false)?,
                match_gid: yes(c, b"vpn", b"UNIX_MATCH_GID", false)?,
            },
            startup: duration(c, b"STARTUP_TIMEOUT", 30_000_000)?,
        })
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
            return Err("CONFIGURED_EXITS entry is: PEER prefix|any tcp|udp|icmp|icmp6|any first-last native|linux|darwin".into());
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
            peer: peer(p.as_bytes())?,
            af: af(profile)?,
        });
    }
    Ok(out)
}
fn peer(text: &[u8]) -> Result<[u8; 32], Failure> {
    let mut out = [0; 32];
    if text.len() == 64 {
        let hex = |b| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        };
        for (dst, pair) in out.iter_mut().zip(text.as_chunks::<2>().0) {
            *dst = hex(pair[0]).ok_or("invalid hex exit identity")? << 4
                | hex(pair[1]).ok_or("invalid hex exit identity")?;
        }
    } else if text.len() == 52 {
        let (mut accumulator, mut bits, mut at) = (0u16, 0, 0usize);
        for b in text {
            let b = match b.to_ascii_uppercase() {
                b'O' => b'0',
                b'I' | b'L' => b'1',
                b'U' => b'V',
                b => b,
            };
            let n = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ"
                .iter()
                .position(|x| *x == b)
                .ok_or("invalid official exit identity")?;
            accumulator = ((accumulator & ((1 << bits) - 1)) << 5) | n as u16;
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                *out.get_mut(at).ok_or("invalid exit identity length")? =
                    (accumulator >> bits) as u8;
                at += 1;
            }
        }
    } else {
        return Err("exit peer must be52 official GNUnet characters or64 hex digits".into());
    }
    Ok(out)
}
pub(super) fn filled<T>(count: usize, mut make: impl FnMut() -> T) -> Result<Vec<T>, Failure> {
    let mut v = Vec::new();
    v.try_reserve_exact(count)?;
    for _ in 0..count {
        v.push(make());
    }
    Ok(v)
}
pub(super) fn bytes(count: usize) -> Result<Vec<u8>, Failure> {
    filled(count, || 0)
}
