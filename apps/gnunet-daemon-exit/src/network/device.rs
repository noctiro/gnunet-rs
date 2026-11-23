//! Original native allocation/adoption, separate from route and DAD scheduling.
#[cfg(target_os = "linux")]
use super::target;
use super::{Settings, Stop, TunMode};
use crate::{Failure, lifecycle::Stage};
#[cfg(unix)]
use gnunet_tun_host::OwnedTun;
#[cfg(unix)]
use std::os::fd::OwnedFd;
use tokio::time::Instant;
#[cfg(windows)]
pub(crate) mod windows;
pub(crate) async fn open(
    settings: &Settings,
    #[cfg(unix)] inherited: Option<OwnedFd>,
    stop: &mut Stop,
    startup: Instant,
) -> Result<(Option<gnunet_exit_host::runtime::PacketSource>, String), Failure> {
    let limits = gnunet_tun_host::Limits {
        packet_bytes: settings.core.packet_bytes,
    };
    stop.check_now().await?;
    if Instant::now() >= startup {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "EXIT startup deadline before device admission",
        )
        .into());
    }
    #[cfg(target_os = "linux")]
    if settings.mode == TunMode::Fresh {
        if inherited.is_some() {
            return Err("fresh helper refuses transferred TUN descriptor".into());
        }
        if settings.unit.is_some() {
            return Err("UTUN_UNIT is not a Linux helper option".into());
        }
        let name = settings
            .name
            .clone()
            .ok_or("official EXIT TUN_IFNAME required for helper")?;
        let ipv4 = settings.ipv4.map(|(address, mask, _)| (address, mask));
        let options = gnunet_tun_host::helper::Options {
            executable: settings
                .helper
                .clone()
                .ok_or("official EXIT helper path unavailable")?,
            interface: name.clone(),
            ipv4,
            ipv6: settings.ipv6,
            mtu: settings.helper_mtu,
            until: target(settings.configuration)?.min(startup),
            partial_lifetime: settings.helper_partial,
        };
        stop.check()?;
        let link =
            gnunet_tun_host::helper::Link::spawn_exit(options, settings.egress.clone(), limits)?;
        return Ok((
            Some(gnunet_exit_host::runtime::PacketSource::helper(link)),
            format!(
                "{name} helper-pipes; kernel identity pending; helper-ownership/NAT-ACK=unasserted"
            ),
        ));
    }
    let device = match settings.mode {
        TunMode::None => {
            #[cfg(unix)]
            if inherited.is_some() {
                return Err("TUN_MODE=none refuses a transferred TUN descriptor".into());
            }
            return Ok((None, "none (DNS-only)".to_owned()));
        }
        #[cfg(unix)]
        TunMode::Preopened => OwnedTun::from_fd(
            inherited
                .ok_or("preopened mode requires GNUNET_EXIT_TUN_FD parent ownership transfer")?,
            limits,
        )?,
        TunMode::Fresh | TunMode::Direct => {
            #[cfg(unix)]
            if inherited.is_some() {
                return Err("fresh mode refuses a transferred TUN descriptor".into());
            }
            if settings.packet_information && !cfg!(target_os = "linux") {
                return Err("LINUX_TUN_PI requires Linux TUN".into());
            }
            #[cfg(target_os = "linux")]
            {
                if settings.unit.is_some() {
                    return Err("UTUN_UNIT is not a Linux TUN option".into());
                }
                OwnedTun::open_linux_exclusive(
                    settings.name.as_deref(),
                    settings.packet_information,
                    limits,
                )?
            }
            #[cfg(target_os = "macos")]
            {
                OwnedTun::open_utun(settings.unit, limits)?
            }
            #[cfg(target_os = "freebsd")]
            {
                if settings.unit.is_some() {
                    return Err("UTUN_UNIT requires macOS".into());
                }
                let checkpoint = settings
                    .checkpoint
                    .as_ref()
                    .ok_or("missing native FreeBSD TUN recovery checkpoint")?;
                gnunet_service_runtime::private_parents(checkpoint)?;
                OwnedTun::open_freebsd_recoverable(settings.name.as_deref(), checkpoint, limits)?
            }
            #[cfg(windows)]
            {
                windows::open(settings, limits, false)?
            }
        }
        #[cfg(windows)]
        TunMode::Existing => windows::open(settings, limits, true)?,
    };
    #[cfg(unix)]
    let check_name = true;
    #[cfg(windows)]
    let check_name = settings.mode != TunMode::Existing;
    if check_name
        && settings
            .name
            .as_ref()
            .is_some_and(|name| *name != device.info().name)
    {
        let observed = device.info().name.clone();
        if let Err(error) = device.close() {
            stop.cleanup.retain(Stage::Tun, Box::new(error));
        }
        return Err(format!(
            "verified interface {} differs from configured TUN_IFNAME",
            observed
        )
        .into());
    }
    let description = format!(
        "{} index={} verified mode={:?} configured-egress={:?} operator-network-policy=required",
        device.info().name,
        device.info().index,
        settings.mode,
        settings.egress
    );
    #[cfg(target_os = "freebsd")]
    let source = {
        let mut io = gnunet_tun_host::AsyncTun::new(device)?;
        if matches!(settings.mode, TunMode::Fresh | TunMode::Direct)
            && let Err(error) = io.enable_freebsd_recovery()
        {
            crate::foreground::observe(
                gnunet_exit_host::runtime::Event::TunLost(io.close()),
                &stop.reports,
                &stop.cleanup,
            );
            return Err(error.into());
        }
        gnunet_exit_host::runtime::PacketSource::Native(io)
    };
    #[cfg(not(target_os = "freebsd"))]
    let source = gnunet_exit_host::runtime::PacketSource::native(device)?;
    Ok((Some(source), description))
}
