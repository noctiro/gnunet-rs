//! Official DNS/helper keys and explicit bounded Rust resource policy.
use crate::{Failure, statistics};
use gnunet_config::Configuration;
use gnunet_dns_service_host::{GatewayLimits, Limits, core};
use gnunet_service_runtime::{
    credentials::UnixAccess,
    service::{ServiceOptions, ShutdownMode},
    service_options,
};
use std::{net::SocketAddr, time::Duration};
mod exit;
pub(super) const LOCAL: &[u8] = b"dns-rust";
pub(super) fn number(c: &Configuration, key: &[u8], default: usize) -> Result<usize, Failure> {
    Ok(c.get(LOCAL, key)
        .map(|_| c.get_number(LOCAL, key))
        .transpose()?
        .map(usize::try_from)
        .transpose()?
        .unwrap_or(default))
}

#[cfg(all(
    test,
    any(target_os = "macos", target_os = "ios"),
    feature = "apple-dns-proxy"
))]
mod tests {
    use super::*;
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Provider configuration must remain independent of helper/interface fields while the ordinary source still validates them"
    )]
    fn provider_profile_ignores_helper_only_configuration() -> Result<(), Failure> {
        let mut config = Configuration::new(Default::default());
        config.set_value(b"dns", b"DNS_EXIT", Some(b"192.0.2.53"))?;
        config.set_value(b"dns", b"IPV4ADDR", Some(b"not-an-address"))?;
        config.set_value(b"dns", b"IFNAME", Some(b"not a valid interface"))?;
        config.set_value(LOCAL, b"HELPER_BINARY", Some(b"relative-helper"))?;
        let provider = Settings::read_provider(&config)?;
        assert!(matches!(
            provider.packets,
            crate::packet_source::Settings::ApplicationFlows(_)
        ));
        assert!(Settings::read(&config).is_err());
        Ok(())
    }

    #[test]
    fn multicast_is_explicit_and_uses_the_original_request_lifetime() -> Result<(), Failure> {
        fn multicast(c: &Configuration) -> Result<Option<Duration>, Failure> {
            match Settings::read_provider(c)?.packets {
                crate::packet_source::Settings::ApplicationFlows(limits) => {
                    Ok(limits.multicast_timeout)
                }
                _ => Err("provider did not select application flows".into()),
            }
        }
        let mut config = Configuration::new(Default::default());
        config.set_value(b"dns", b"DNS_EXIT", Some(b"192.0.2.53"))?;
        if multicast(&config)?.is_some() {
            return Err("native multicast was enabled without configuration".into());
        }
        config.set_value(LOCAL, b"NATIVE_MULTICAST_RELAY", Some(b"YES"))?;
        config.set_value(LOCAL, b"REQUEST_HARD_LIFETIME", Some(b"60 s"))?;
        if multicast(&config)? != Some(Duration::from_secs(60)) {
            return Err("native multicast did not use the configured hard lifetime".into());
        }
        Ok(())
    }
}

#[cfg(all(test, windows))]
#[test]
fn windows_settings_retain_local_owner_and_group_policy() -> Result<(), Failure> {
    let mut config = Configuration::default();
    config.set_value(b"dns", b"DNS_EXIT", Some(b"192.0.2.53"))?;
    config.set_value(LOCAL, b"WINDOWS_BACKEND", Some(b"WFP"))?;
    config.set_value(b"dns", b"UNIX_MATCH_GID", Some(b"YES"))?;
    let group = Settings::read(&config)?.unix;
    if group.match_uid || !group.match_gid {
        return Err("DNS settings did not retain Windows group access".into());
    }
    config.set_value(b"dns", b"UNIX_MATCH_UID", Some(b"YES"))?;
    let owner = Settings::read(&config)?.unix;
    if !owner.match_uid || !owner.match_gid {
        return Err("DNS settings did not retain Windows owner access".into());
    }
    Ok(())
}

pub(super) fn duration(
    c: &Configuration,
    key: &[u8],
    default: Duration,
) -> Result<Duration, Failure> {
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
pub(super) fn text<'a>(
    c: &'a Configuration,
    key: &[u8],
    default: &'a str,
) -> Result<&'a str, Failure> {
    c.get(b"dns", key)
        .map(std::str::from_utf8)
        .transpose()
        .map(|v| v.unwrap_or(default))
        .map_err(Into::into)
}
pub(super) fn yes(c: &Configuration, key: &[u8], default: bool) -> Result<bool, Failure> {
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
    pub exit: SocketAddr,
    pub options: ServiceOptions,
    pub unix: UnixAccess,
    pub resolver: gnunet_resolver_broker::Limits,
    pub grace: Duration,
    pub statistics: statistics::Limits,
}
impl Settings {
    pub fn read(c: &Configuration) -> Result<Self, Failure> {
        Self::read_with(c, crate::packet_source::Profile::Service)
    }
    #[cfg(all(
        any(target_os = "macos", target_os = "ios"),
        feature = "apple-dns-proxy"
    ))]
    pub fn read_provider(c: &Configuration) -> Result<Self, Failure> {
        Self::read_with(c, crate::packet_source::Profile::Provider)
    }
    fn read_with(
        c: &Configuration,
        profile: crate::packet_source::Profile,
    ) -> Result<Self, Failure> {
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
        let exit = exit::read(c, profile)?;
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
            packets: crate::packet_source::read(c, slice, grace, exit.ip(), profile)?,
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
