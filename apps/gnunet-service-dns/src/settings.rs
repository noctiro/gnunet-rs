//! Official DNS/helper keys and explicit bounded Rust resource policy.
use crate::{Failure, statistics};
use gnunet_config::Configuration;
#[cfg(unix)]
use gnunet_dns_service_host::HelperOptions;
use gnunet_dns_service_host::{GatewayLimits, Limits, core};
use gnunet_service_runtime::{
    credentials::UnixAccess,
    service::{ServiceOptions, ShutdownMode},
    service_options,
};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};
const LOCAL: &[u8] = b"dns-rust";
fn number(c: &Configuration, key: &[u8], default: usize) -> Result<usize, Failure> {
    Ok(c.get(LOCAL, key)
        .map(|_| c.get_number(LOCAL, key))
        .transpose()?
        .map(usize::try_from)
        .transpose()?
        .unwrap_or(default))
}
fn duration(c: &Configuration, key: &[u8], default: Duration) -> Result<Duration, Failure> {
    let d = c
        .get(LOCAL, key)
        .map(|_| c.get_time(LOCAL, key))
        .transpose()?
        .map(Duration::from_micros)
        .unwrap_or(default);
    if d.is_zero()
        || d == Duration::MAX
        || u64::try_from(d.as_micros()).is_err()
        || tokio::time::Instant::now().checked_add(d).is_none()
    {
        return Err("DNS timers must be finite, positive and representable".into());
    }
    Ok(d)
}
fn text<'a>(c: &'a Configuration, key: &[u8], default: &'a str) -> Result<&'a str, Failure> {
    c.get(b"dns", key)
        .map(std::str::from_utf8)
        .transpose()
        .map(|v| v.unwrap_or(default))
        .map_err(Into::into)
}
fn yes(c: &Configuration, key: &[u8], default: bool) -> Result<bool, Failure> {
    Ok(c.get(b"dns", key)
        .map(|_| c.get_yesno(b"dns", key))
        .transpose()?
        .unwrap_or(default))
}
pub(super) struct Settings {
    pub core: core::Limits,
    pub native: Limits,
    pub gateway: GatewayLimits,
    pub packets: crate::packet_source::Settings,
    pub exit: IpAddr,
    pub options: ServiceOptions,
    pub unix: UnixAccess,
    pub resolver: gnunet_resolver_broker::Limits,
    pub grace: Duration,
    pub statistics: statistics::Limits,
}
impl Settings {
    pub fn read(c: &Configuration) -> Result<Self, Failure> {
        let clients = number(c, b"MAX_CLIENTS", 16)?;
        let requests = number(c, b"MAX_REQUESTS", 128)?;
        let payload = number(c, b"DNS_BYTES", core::MAX_DNS_BYTES)?;
        let bytes = number(c, b"PAYLOAD_POOL_BYTES", 4 * 1024 * 1024)?;
        let slice = number(c, b"IO_SLICE_BYTES", 65535)?;
        if !(1..=64).contains(&clients)
            || requests == 0
            || requests > 4096
            || !(12..=core::MAX_DNS_BYTES).contains(&payload)
            || bytes < payload
            || bytes > 256 * 1024 * 1024
            || slice == 0
            || slice > 65535
        {
            return Err("invalid bounded DNS interception resource policy".into());
        }
        let native = Limits {
            clients,
            frame_bytes: 65535,
            io_slice_bytes: slice,
            input_lifetime: duration(c, b"INPUT_LIFETIME", Duration::from_secs(10))?,
            callback_lifetime: duration(c, b"CALLBACK_LIFETIME", Duration::from_secs(30))?,
            maintenance: duration(c, b"MAINTENANCE_INTERVAL", Duration::from_millis(50))?,
        };
        let gateway = GatewayLimits {
            request_lifetime: duration(c, b"REQUEST_LIFETIME", Duration::from_secs(30))?,
            request_hard_lifetime: duration(c, b"REQUEST_HARD_LIFETIME", Duration::from_secs(45))?,
            resolver_sockets: number(c, b"DNSSTUB_SOCKETS", 16)?,
        };
        if gateway.request_hard_lifetime < gateway.request_lifetime
            || !(1..=16).contains(&gateway.resolver_sockets)
        {
            return Err("invalid original DNS resolver/deadline bounds".into());
        }
        let ipv4: Ipv4Addr = text(c, b"IPV4ADDR", "169.254.1.1")?.parse()?;
        let mask: Ipv4Addr = text(c, b"IPV4MASK", "255.255.0.0")?.parse()?;
        let ipv6: Ipv6Addr = text(c, b"IPV6ADDR", "2001:db8::1")?.parse()?;
        let prefix: u8 = text(c, b"IPV6PREFIX", "126")?.parse()?;
        if prefix > 128 {
            return Err("DNS IPV6PREFIX exceeds128".into());
        }
        let exit: IpAddr = text(c, b"DNS_EXIT", "8.8.8.8")?.parse()?;
        if exit.is_unspecified()
            || exit.is_multicast()
            || exit == IpAddr::V4(ipv4)
            || exit == IpAddr::V6(ipv6)
        {
            return Err("DNS_EXIT must be a numeric usable resolver distinct from interception TUN addresses".into());
        }
        let interface = text(
            c,
            b"IFNAME",
            if cfg!(target_os = "macos") {
                "utun"
            } else {
                "gnunet-dns"
            },
        )?
        .to_owned();
        #[cfg(unix)]
        if interface.is_empty()
            || interface.len() >= 16
            || !interface
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        {
            return Err("invalid DNS IFNAME".into());
        }
        #[cfg(windows)]
        if interface.is_empty()
            || interface.encode_utf16().count() > 128
            || interface.contains('\0')
        {
            return Err("invalid Windows DNS IFNAME".into());
        }
        #[cfg(unix)]
        let binary = if c.get(LOCAL, b"HELPER_BINARY").is_some() {
            c.get_filename(LOCAL, b"HELPER_BINARY", &gnunet_config::ProcessEnvironment)?
        } else {
            std::env::current_exe()?.with_file_name(if cfg!(windows) {
                "gnunet-helper-dns.exe"
            } else {
                "gnunet-helper-dns"
            })
        };
        #[cfg(unix)]
        if !binary.is_absolute() {
            return Err("DNS Rust helper path must be absolute".into());
        }
        #[cfg(windows)]
        for key in [b"UNIX_MATCH_UID".as_slice(), b"UNIX_MATCH_GID".as_slice()] {
            if c.get(b"dns", key).is_some() && yes(c, key, false)? {
                return Err("Windows DNS uses native endpoint ACLs; Unix UID/GID peer matching is unavailable".into());
            }
        }
        let grace = duration(c, b"SHUTDOWN_GRACE", Duration::from_secs(60))?;
        Ok(Self {
            core: core::Limits {
                clients,
                requests,
                bytes,
                payload_bytes: payload,
            },
            native,
            gateway,
            #[cfg(unix)]
            packets: crate::packet_source::Settings::Helper(HelperOptions {
                program: binary,
                interface,
                ipv6,
                prefix,
                ipv4,
                mask,
                skip_routing: yes(c, b"SKIP_ROUTING_SETUP", false)?,
                frame_bytes: 65535,
                io_slice_bytes: slice,
                input_lifetime: duration(c, b"HELPER_INPUT_LIFETIME", Duration::from_secs(10))?,
                stop_grace: grace,
            }),
            #[cfg(windows)]
            packets: crate::packet_source::Settings::Windows(
                crate::packet_source::windows::Settings::read(
                    c,
                    crate::packet_source::windows::Addresses {
                        interface,
                        ipv4,
                        mask,
                        ipv6,
                        prefix,
                    },
                    yes(c, b"SKIP_ROUTING_SETUP", false)?,
                )?,
            ),
            exit,
            options: service_options(c, b"dns", ShutdownMode::Immediate)?,
            unix: UnixAccess {
                match_uid: yes(c, b"UNIX_MATCH_UID", cfg!(unix))?,
                match_gid: yes(c, b"UNIX_MATCH_GID", cfg!(unix))?,
            },
            resolver: gnunet_resolver_broker::Limits {
                max_frame_bytes: 65535,
                io_chunk_bytes: slice,
                max_queued_frames: 4,
            },
            grace,
            statistics: statistics::Limits {
                operation: duration(c, b"STATISTICS_TIMEOUT", Duration::from_secs(5))?,
                max_frame_bytes: 512,
                write_chunk_bytes: slice.min(512),
            },
        })
    }
}
