//! Native provisioning and unchanged-owner qualification, separate from scheduling.
use crate::{
    Failure,
    lifecycle::{self, Cleanup},
    settings::{Settings, TunMode},
};
use gnunet_tun_host as tun;
use gnunet_vpn_host::coordinator::Device;
#[cfg(unix)]
use std::os::fd::OwnedFd;
#[cfg(windows)]
pub(super) mod windows;
pub(super) async fn open(
    settings: &Settings,
    #[cfg(unix)] inherited: Option<OwnedFd>,
    cleanup: &Cleanup,
) -> Result<Device, Failure> {
    #[cfg(windows)]
    let _ = cleanup;
    let limits = tun::Limits {
        packet_bytes: settings.core.packet_bytes,
    };
    let device = match settings.mode {
        #[cfg(unix)]
        TunMode::Preopened => {
            let fd = inherited.ok_or(
                "preopened mode requires GNUNET_VPN_TUN_FD exclusively transferred by the parent",
            )?;
            Device::borrow_existing(tun::AsyncTun::new(tun::OwnedTun::from_fd(fd, limits)?)?)
        }
        TunMode::Fresh => {
            #[cfg(unix)]
            if inherited.is_some() {
                return Err(
                    "fresh mode refuses GNUNET_VPN_TUN_FD; choose explicit preopened mode".into(),
                );
            }
            #[cfg(target_os = "linux")]
            {
                let ipv4 = settings
                    .core
                    .ipv4
                    .map(|prefix| match prefix.interface {
                        gnunet_vpn::Address::V4(address) => {
                            let mask = if prefix.bits == 0 {
                                0
                            } else {
                                u32::MAX << (32 - prefix.bits)
                            };
                            Ok((address.into(), std::net::Ipv4Addr::from(mask)))
                        }
                        _ => Err(gnunet_types::Error::InvalidInput),
                    })
                    .transpose()?;
                let ipv6 = settings
                    .core
                    .ipv6
                    .map(|prefix| match prefix.interface {
                        gnunet_vpn::Address::V6(address) => Ok((address.into(), prefix.bits)),
                        _ => Err(gnunet_types::Error::InvalidInput),
                    })
                    .transpose()?;
                Device::start_helper(
                    tun::helper::Options {
                        executable: settings
                            .helper
                            .clone()
                            .ok_or("fresh Linux helper path missing")?,
                        interface: settings.ifname.clone(),
                        ipv4,
                        ipv6,
                        mtu: settings.helper_mtu,
                        until: tokio::time::Instant::now()
                            .checked_add(settings.coordinator.control_timeout)
                            .ok_or("VPN native configure deadline overflow")?,
                        partial_lifetime: settings.helper_partial,
                    },
                    limits,
                )?
            }
            #[cfg(target_os = "macos")]
            {
                let unit = settings
                    .ifname
                    .strip_prefix("utun")
                    .ok_or("macOS IFNAME must be utunN")?
                    .parse()?;
                Device::open_utun_unit(Some(unit), limits)?
            }
            #[cfg(target_os = "freebsd")]
            {
                let checkpoint = settings
                    .checkpoint
                    .as_deref()
                    .ok_or("missing native FreeBSD VPN recovery checkpoint")?;
                gnunet_service_runtime::private_parents(checkpoint)?;
                Device::open_freebsd_recoverable(Some(&settings.ifname), checkpoint, limits)?
            }
            #[cfg(windows)]
            {
                windows::open(settings, limits)?
            }
        }
        #[cfg(windows)]
        TunMode::Existing => windows::open(settings, limits)?,
    };
    #[cfg(unix)]
    let selected = device.info().name == settings.ifname;
    #[cfg(windows)]
    let selected = settings.mode == TunMode::Existing || device.info().name == settings.ifname;
    if !selected {
        let observed = device.info().name.clone();
        let mut io = device.into_io();
        let loss = io.close();
        #[cfg(unix)]
        if let Some(report) = io.reap_helper().await {
            cleanup.helper(report);
        }
        return Err(Box::new(lifecycle::Qualification {
            expected: settings.ifname.clone(),
            observed,
            loss,
        }));
    }
    Ok(device)
}
