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
        packet_bytes: settings.service.core.packet_bytes,
    };
    let device = match &settings.mode {
        #[cfg(unix)]
        TunMode::Preopened { .. } => {
            let fd = inherited.ok_or(
                "preopened mode requires GNUNET_VPN_TUN_FD exclusively transferred by the parent",
            )?;
            Device::borrow_existing(tun::AsyncTun::new(tun::OwnedTun::from_fd(fd, limits)?)?)
        }
        TunMode::Fresh(fresh) => {
            #[cfg(unix)]
            if inherited.is_some() {
                return Err(
                    "fresh mode refuses GNUNET_VPN_TUN_FD; choose explicit preopened mode".into(),
                );
            }
            #[cfg(target_os = "linux")]
            {
                let ipv4 = settings
                    .service
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
                    .service
                    .core
                    .ipv6
                    .map(|prefix| match prefix.interface {
                        gnunet_vpn::Address::V6(address) => Ok((address.into(), prefix.bits)),
                        _ => Err(gnunet_types::Error::InvalidInput),
                    })
                    .transpose()?;
                Device::start_helper(
                    tun::helper::Options {
                        executable: fresh.helper.clone(),
                        interface: fresh.name.clone(),
                        ipv4,
                        ipv6,
                        mtu: fresh
                            .override_mtu
                            .then_some(settings.service.coordinator.mtu),
                        until: tokio::time::Instant::now()
                            .checked_add(settings.service.coordinator.control_timeout)
                            .ok_or("VPN native configure deadline overflow")?,
                        partial_lifetime: fresh.helper_partial,
                    },
                    limits,
                )?
            }
            #[cfg(target_os = "macos")]
            {
                Device::open_utun_unit(fresh.utun_unit(), limits)?
            }
            #[cfg(target_os = "freebsd")]
            {
                gnunet_service_runtime::private_parents(&fresh.checkpoint)?;
                Device::open_freebsd_recoverable(Some(&fresh.name), &fresh.checkpoint, limits)?
            }
            #[cfg(windows)]
            {
                windows::open(
                    &settings.wintun,
                    windows::Selection::Create(&fresh.name),
                    limits,
                )?
            }
        }
        #[cfg(windows)]
        TunMode::Existing { name } => {
            windows::open(&settings.wintun, windows::Selection::Open(name), limits)?
        }
    };
    let info = device
        .info()
        .ok_or("VPN system service requires a native device")?;
    if let Some(expected) = settings.mode.expected_name()
        && expected != info.name
    {
        let observed = info.name.clone();
        let mut io = device.into_io();
        let loss = io
            .close_native()
            .ok_or("VPN system service lost its native device")?;
        #[cfg(unix)]
        if let Some(report) = io.reap_helper().await {
            cleanup.helper(report);
        }
        return Err(Box::new(lifecycle::Qualification {
            expected: expected.to_owned(),
            observed,
            loss,
        }));
    }
    Ok(device)
}
