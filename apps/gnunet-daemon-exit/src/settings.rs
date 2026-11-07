//! Official EXIT keys and explicit local resource/provisioning policy.
use crate::Failure;
use gnunet_config::Configuration;
use gnunet_exit::{
    Address, AfProfile,
    engine::{self, Service},
    nat::Pool,
    policy::{Endpoint, InternetRules, Policy, Prefix, Protocol},
};
use gnunet_exit_host::runtime::{Binding, Resolver};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};
const LOCAL: &[u8] = b"exit-rust";
fn text<'a>(c: &'a Configuration, section: &[u8], key: &[u8]) -> Result<Option<&'a str>, Failure> {
    c.get(section, key)
        .map(std::str::from_utf8)
        .transpose()
        .map_err(Into::into)
}
fn flag(c: &Configuration, section: &[u8], key: &[u8], default: bool) -> Result<bool, Failure> {
    Ok(if c.get(section, key).is_some() {
        c.get_yesno(section, key)?
    } else {
        default
    })
}
fn number(c: &Configuration, key: &[u8], default: usize) -> Result<usize, Failure> {
    Ok(c.get(LOCAL, key)
        .map(|_| c.get_number(LOCAL, key))
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
        return Err("EXIT time bound must be finite, nonzero and representable".into());
    }
    Ok(v)
}
fn duration(c: &Configuration, key: &[u8], default: u64) -> Result<Duration, Failure> {
    Ok(Duration::from_micros(micros(c, key, default)?))
}
pub(super) fn address(ip: IpAddr) -> Address {
    match ip {
        IpAddr::V4(v) => Address::V4(v.octets()),
        IpAddr::V6(v) => Address::V6(v.octets()),
    }
}
fn prefix(text: &str) -> Result<Prefix, Failure> {
    let (a, b) = text
        .split_once('/')
        .ok_or("expected numeric address/prefix")?;
    let p = Prefix {
        address: address(a.parse()?),
        bits: b.parse()?,
    };
    p.validate()?;
    Ok(p)
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TunMode {
    None,
    Preopened,
    Fresh,
    Direct,
}
#[derive(Clone, Debug)]
pub(super) struct Redirect {
    pub hash: [u8; 64],
    pub host: String,
    pub port: u16,
    pub protocol: Protocol,
}
pub(super) struct Settings {
    pub pils_profile: gnunet_pils::Profile,
    pub mode: TunMode,
    pub helper: Option<std::path::PathBuf>,
    pub helper_mtu: Option<u32>,
    pub helper_partial: Duration,
    pub egress: Option<String>,
    pub name: Option<String>,
    pub unit: Option<u32>,
    pub packet_information: bool,
    pub mtu: u32,
    pub ipv4: Option<(Ipv4Addr, Ipv4Addr, u8)>,
    pub ipv6: Option<(Ipv6Addr, u8)>,
    pub exit4: bool,
    pub exit6: bool,
    pub dns: Option<Resolver>,
    pub redirects: Vec<Redirect>,
    pub routes: Vec<gnunet_tun_host::Action>,
    pub advertising: crate::announcement::Definitions,
    pub core: engine::Limits,
    pub native: gnunet_exit_host::runtime::Limits,
    pub cadet: gnunet_cadet_host::Limits,
    pub resolver: gnunet_resolver_broker::Limits,
    pub startup: Duration,
    pub shutdown: Duration,
    pub configuration: Duration,
    pub dad: Duration,
    pub watch: Duration,
    pub lookup: Duration,
    pub af: AfProfile,
}
impl Settings {
    pub fn read(c: &Configuration) -> Result<Self, Failure> {
        let pils_profile = gnunet_pils::Profile::configured(c.get(b"PILS", b"PROFILE"), None)?;
        let exit4 = flag(c, b"exit", b"EXIT_IPV4", false)?;
        let exit6 = flag(c, b"exit", b"EXIT_IPV6", false)?;
        let enable4 = exit4 || flag(c, b"exit", b"ENABLE_IPV4", false)?;
        let enable6 = exit6 || flag(c, b"exit", b"ENABLE_IPV6", false)?;
        let mode = match text(c, LOCAL, b"TUN_MODE")?.unwrap_or(if enable4 || enable6 {
            "fresh"
        } else {
            "none"
        }) {
            "none" => TunMode::None,
            "preopened" => TunMode::Preopened,
            "fresh" => TunMode::Fresh,
            "direct" => TunMode::Direct,
            _ => return Err("TUN_MODE must be none, preopened, fresh or direct".into()),
        };
        let egress = if enable4 || exit6 {
            let value = text(c, b"exit", b"EXIT_IFNAME")?.ok_or("missing [exit] EXIT_IFNAME")?;
            if value == "%" || value == "-" {
                None
            } else {
                if value.is_empty()
                    || value.len() >= libc::IFNAMSIZ
                    || !value
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
                {
                    return Err("invalid [exit] EXIT_IFNAME".into());
                }
                Some(value.to_owned())
            }
        } else {
            None
        };
        let ipv4 = if enable4 {
            let a: Ipv4Addr = text(c, b"exit", b"IPV4ADDR")?
                .ok_or("missing [exit] IPV4ADDR")?
                .parse()?;
            let m: Ipv4Addr = text(c, b"exit", b"IPV4MASK")?
                .ok_or("missing [exit] IPV4MASK")?
                .parse()?;
            let bits = u32::from(m).leading_ones() as u8;
            let expected = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits)
            };
            if u32::from(m) != expected {
                return Err("IPV4MASK must be contiguous".into());
            }
            Some((a, m, bits))
        } else {
            None
        };
        let ipv6 = if enable6 {
            let a: Ipv6Addr = text(c, b"exit", b"IPV6ADDR")?
                .ok_or("missing [exit] IPV6ADDR")?
                .parse()?;
            let n = c.get_number(b"exit", b"IPV6PREFIX")?;
            if n >= 127 {
                return Err("IPV6PREFIX must be below127 in the pinned official profile".into());
            }
            Some((a, n as u8))
        } else {
            None
        };
        let dns = if flag(c, b"exit", b"EXIT_DNS", false)? {
            let ip: IpAddr = text(c, b"exit", b"DNS_RESOLVER")?
                .ok_or("missing [exit] DNS_RESOLVER numeric address")?
                .parse()?;
            let port = u16::try_from(number(c, b"DNS_RESOLVER_PORT", 53)?)?;
            if port == 0 {
                return Err("DNS resolver port must be nonzero".into());
            }
            Some(Resolver {
                server: SocketAddr::new(ip, port),
                retry: duration(c, b"DNS_RETRY", 1_000_000)?,
            })
        } else {
            None
        };
        let mut redirects = Vec::new();
        redirects.try_reserve_exact(256)?;
        for section in c.sections() {
            let Some(name) = section.name().strip_suffix(b".gnunet.") else {
                continue;
            };
            let descriptor = gnunet_vpn::service_descriptor(name);
            for (key, protocol) in [
                (b"TCP_REDIRECTS".as_slice(), Protocol::Tcp),
                (b"UDP_REDIRECTS".as_slice(), Protocol::Udp),
            ] {
                let Some(v) = text(c, section.name(), key)? else {
                    continue;
                };
                for entry in v.split([' ', ';']).filter(|s| !s.is_empty()) {
                    if redirects.len() == 256 {
                        return Err("more than256 configured EXIT redirects".into());
                    }
                    let (local, rest) = entry
                        .split_once(':')
                        .ok_or("redirect must be local:host:remote")?;
                    let (host, remote) = rest
                        .rsplit_once(':')
                        .ok_or("redirect must be local:host:remote")?;
                    let local: u16 = local.parse()?;
                    let remote: u16 = remote.parse()?;
                    let host = host
                        .strip_prefix('[')
                        .and_then(|s| s.strip_suffix(']'))
                        .unwrap_or(host);
                    if local == 0 || remote == 0 || host.is_empty() || host.len() > 255 {
                        return Err("invalid redirect port or hostname".into());
                    }
                    let hash = gnunet_vpn::service_port(descriptor, local);
                    // One official CADET port may carry independently configured TCP/UDP targets.
                    if redirects
                        .iter()
                        .any(|r: &Redirect| r.hash == hash && r.protocol == protocol)
                    {
                        return Err("duplicate service CADET hash and protocol".into());
                    }
                    redirects.push(Redirect {
                        hash,
                        host: host.to_owned(),
                        port: remote,
                        protocol,
                    });
                }
            }
        }
        if mode == TunMode::None && (enable4 || enable6 || !redirects.is_empty()) {
            return Err(
                "enabled IP families/services require an explicit verified or fresh TUN".into(),
            );
        }
        if mode != TunMode::None && !enable4 && !enable6 {
            return Err("TUN requires at least one enabled configured IP family".into());
        }
        if !exit4 && !exit6 && dns.is_none() && redirects.is_empty() {
            return Err("no EXIT application port is enabled".into());
        }
        let mut routes = Vec::new();
        routes.try_reserve_exact(32)?;
        if let Some(v) = text(c, LOCAL, b"ROUTES")? {
            for item in v.split(';').map(str::trim).filter(|s| !s.is_empty()) {
                if routes.len() == 32 {
                    return Err("more than32 explicit EXIT routes".into());
                }
                let (net, gw) = item
                    .split_once('@')
                    .map_or((item, None), |(a, b)| (a, Some(b)));
                let p = prefix(net.trim())?;
                let destination = match p.address {
                    Address::V4(v) => IpAddr::V4(v.into()),
                    Address::V6(v) => IpAddr::V6(v.into()),
                };
                let gateway = gw.map(str::trim).map(str::parse::<IpAddr>).transpose()?;
                if gateway.is_some_and(|g| g.is_ipv4() != destination.is_ipv4())
                    || (destination.is_ipv4() && !enable4)
                    || (destination.is_ipv6() && !enable6)
                {
                    return Err("route family does not match enabled TUN family".into());
                }
                routes.push(gnunet_tun_host::Action::Route {
                    add: true,
                    destination,
                    prefix: p.bits,
                    gateway,
                });
            }
        }
        if mode == TunMode::None && !routes.is_empty() {
            return Err("DNS-only mode cannot configure interface routes".into());
        }
        let advertising = crate::announcement::Definitions::read(c, exit4, exit6)?;
        let d = engine::Limits::default();
        let core = engine::Limits {
            flows: number(c, b"MAX_FLOWS", d.flows)?,
            processing_receipts: number(c, b"MAX_PROCESSING_RECEIPTS", d.processing_receipts)?,
            output_frames: number(c, b"MAX_OUTPUT_FRAMES", d.output_frames)?,
            output_bytes: size(c, b"MAX_OUTPUT_BYTES", d.output_bytes)?,
            packet_bytes: size(c, b"PACKET_BYTES", d.packet_bytes)?,
            peer_bytes: size(c, b"PEER_BYTES", d.peer_bytes)?,
            dns_bytes: size(c, b"DNS_BYTES", d.dns_bytes)?,
            entropy_draws: u16::try_from(number(
                c,
                b"ENTROPY_DRAWS",
                usize::from(d.entropy_draws),
            )?)?,
            idle: micros(c, b"IDLE", d.idle)?,
            input_lifetime: micros(c, b"INPUT_LIFETIME", d.input_lifetime)?,
            quarantine: micros(c, b"QUARANTINE", d.quarantine)?,
        };
        let n = gnunet_exit_host::runtime::Limits::default();
        let native = gnunet_exit_host::runtime::Limits {
            ports: number(c, b"MAX_CADET_PORTS", n.ports)?,
            channels: number(c, b"MAX_CADET_CHANNELS", n.channels)?,
            inner_frames: number(c, b"MAX_INNER_FRAMES", n.inner_frames)?,
            dns_jobs: number(c, b"MAX_DNS_JOBS", n.dns_jobs)?,
            dns_bytes: core.dns_bytes,
            dns_questions: number(c, b"MAX_DNS_QUESTIONS", n.dns_questions)?,
            io_grace: duration(c, b"IO_GRACE", 5_000_000)?,
            first_input: duration(c, b"FIRST_INPUT", 30_000_000)?,
            tun_input: duration(c, b"TUN_INPUT", 5_000_000)?,
        };
        if !(1..=4096).contains(&core.flows)
            || !(1..=4096).contains(&native.channels)
            || !(1..=1024).contains(&native.ports)
            || !(1..=4096).contains(&native.dns_jobs)
            || native
                .channels
                .checked_mul(native.inner_frames)
                .is_none_or(|n| n > core.processing_receipts)
        {
            return Err("invalid EXIT bounded slot capacities".into());
        }
        let cd = gnunet_cadet_host::Limits::default();
        let cadet = gnunet_cadet_host::Limits {
            frame_bytes: size(c, b"CADET_FRAME_BYTES", cd.frame_bytes)?,
            io_slice_bytes: size(c, b"CADET_IO_SLICE_BYTES", cd.io_slice_bytes)?,
            max_payload_bytes: size(c, b"CADET_PAYLOAD_BYTES", cd.max_payload_bytes)?,
            max_send_credit: u32::try_from(number(
                c,
                b"CADET_SEND_CREDIT",
                cd.max_send_credit as usize,
            )?)?,
        };
        let rd = gnunet_resolver_broker::Limits::default();
        let resolver = gnunet_resolver_broker::Limits {
            max_frame_bytes: size(c, b"RESOLVER_FRAME_BYTES", rd.max_frame_bytes)?,
            io_chunk_bytes: size(c, b"RESOLVER_IO_SLICE_BYTES", rd.io_chunk_bytes)?,
            max_queued_frames: number(c, b"RESOLVER_QUEUE", rd.max_queued_frames)?,
        };
        let af = match text(c, LOCAL, b"PEER_AF_PROFILE")? {
            None | Some("native") => AfProfile::native(),
            Some("linux") => AfProfile::LINUX,
            Some("darwin") => AfProfile::DARWIN,
            _ => return Err("PEER_AF_PROFILE must be native, linux or darwin".into()),
        };
        let mtu = u32::try_from(number(c, b"MTU", 1400)?)?;
        if mtu == 0 || mtu > 65535 || (enable6 && mtu < 1280) {
            return Err("invalid MTU for enabled address families".into());
        }
        Ok(Self {
            pils_profile,
            mode,
            helper: if cfg!(target_os = "linux") && mode == TunMode::Fresh {
                Some(c.suid_binary_path(b"gnunet-helper-exit")?)
            } else {
                None
            },
            helper_mtu: c.get(LOCAL, b"MTU").map(|_| mtu),
            helper_partial: duration(c, b"HELPER_INPUT_TIMEOUT", 5_000_000)?,
            egress,
            name: text(c, b"exit", b"TUN_IFNAME")?
                .filter(|v| !v.is_empty())
                .map(str::to_owned),
            unit: c
                .get(LOCAL, b"UTUN_UNIT")
                .map(|_| c.get_number(LOCAL, b"UTUN_UNIT"))
                .transpose()?
                .map(u32::try_from)
                .transpose()?,
            packet_information: flag(c, LOCAL, b"LINUX_TUN_PI", false)?,
            mtu,
            ipv4,
            ipv6,
            exit4,
            exit6,
            dns,
            redirects,
            routes,
            advertising,
            core,
            native,
            cadet,
            resolver,
            startup: duration(c, b"STARTUP_TIMEOUT", 30_000_000)?,
            shutdown: duration(c, b"SHUTDOWN_GRACE", 5_000_000)?,
            configuration: duration(c, b"CONFIGURE_TIMEOUT", 10_000_000)?,
            dad: duration(c, b"DAD_TIMEOUT", 10_000_000)?,
            watch: duration(c, b"ADDRESS_WATCH_LIFETIME", 60_000_000)?,
            lookup: duration(c, b"SERVICE_LOOKUP_TIMEOUT", 10_000_000)?,
            af,
        })
    }
    pub fn enabled(&self, ip: IpAddr) -> bool {
        if ip.is_ipv4() {
            self.ipv4.is_some()
        } else {
            self.ipv6.is_some()
        }
    }
    pub fn config<'a>(&'a self, services: &'a [Service]) -> engine::Config<'a> {
        engine::Config {
            policy: Policy {
                ipv4: self.exit4,
                ipv6: self.exit6,
                rules: InternetRules::Official(&self.advertising.rules),
            },
            ipv4: self.ipv4.map(|(a, _, bits)| Pool {
                subnet: Prefix {
                    address: Address::V4(a.octets()),
                    bits,
                },
            }),
            ipv6: self.ipv6.map(|(a, bits)| Pool {
                subnet: Prefix {
                    address: Address::V6(a.octets()),
                    bits,
                },
            }),
            services,
            dns: self.dns.is_some(),
            af: self.af,
        }
    }
    pub fn bindings(&self, services: &[Service]) -> Result<Vec<Binding>, Failure> {
        let mut v = Vec::new();
        v.try_reserve_exact(services.len() + 3)?;
        if self.exit4 {
            v.push(Binding::internet(gnunet_vpn::Family::V4));
        }
        if self.exit6 {
            v.push(Binding::internet(gnunet_vpn::Family::V6));
        }
        if self.dns.is_some() {
            v.push(Binding::dns());
        }
        for s in services {
            if !v.iter().any(|b| b.hash == s.port) {
                v.push(Binding::service(s.port));
            }
        }
        if v.len() > self.native.ports {
            return Err("enabled application ports exceed MAX_CADET_PORTS".into());
        }
        Ok(v)
    }
    pub fn service(&self, r: &Redirect, ip: IpAddr) -> Result<Service, Failure> {
        if !self.enabled(ip) {
            return Err("redirect address family is not enabled".into());
        }
        Ok(Service {
            port: r.hash,
            target: Endpoint {
                address: address(ip),
                port: r.port,
            },
            protocol: r.protocol,
        })
    }
}

#[cfg(test)]
mod profile_tests {
    use super::*;
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Compare actual EXIT startup selection independently of AF layout"
    )]
    fn dns_advertisement_inherits_node_profile_before_native_setup() -> Result<(), Failure> {
        let mut config = Configuration::default();
        config.set_value(b"exit", b"EXIT_DNS", Some(b"YES"))?;
        config.set_value(b"exit", b"DNS_RESOLVER", Some(b"127.0.0.1"))?;
        assert_eq!(
            Settings::read(&config)?.pils_profile,
            gnunet_pils::Profile::Reference029
        );
        config.set_value(b"PILS", b"PROFILE", Some(b"deterministic"))?;
        assert_eq!(
            Settings::read(&config)?.pils_profile,
            gnunet_pils::Profile::ReferenceDeterministic
        );
        config.set_value(b"PILS", b"PROFILE", Some(b"unknown"))?;
        let error = Settings::read(&config)
            .err()
            .ok_or("unknown DNS advertisement profile admitted")?;
        assert_eq!(
            error.downcast_ref::<gnunet_types::Error>(),
            Some(&gnunet_types::Error::InvalidInput)
        );
        Ok(())
    }
}
