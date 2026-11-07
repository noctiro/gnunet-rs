//! Actual Linux DNS helper setup/pump/cleanup. This is the Rust helper source,
//! never a wrapper around gnunet-helper-dns or production libgnunet FFI.
use gnunet_tun_host::{Action, AsyncTun, OwnedTun, Timing};
use nix::unistd::{Uid, getegid, geteuid, getuid, seteuid};
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};
mod control;
mod pump;
/// Fixed official six-argument helper configuration, validated before privilege IO.
pub struct Options {
    /// Actual exclusive requested Linux TUN name.
    pub interface: String,
    /// Configured actual address.
    pub ipv6: Ipv6Addr,
    /// Actual native prefix.
    pub prefix: u8,
    /// Configured actual IPv4 address.
    pub ipv4: Ipv4Addr,
    /// Configured actual contiguous IPv4 mask.
    pub mask: Ipv4Addr,
    /// Official SKIP_ROUTING_SETUP, addresses/TUN still real.
    pub skip_routing: bool,
}
fn validate(options: &Options) -> io::Result<()> {
    let mask = u32::from(options.mask);
    let prefix = mask.leading_ones();
    let expected = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    if options.interface.is_empty()
        || options.interface.len() >= 16
        || !options
            .interface
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        || options.prefix > 128
        || mask != expected
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid DNS helper interface/address mask",
        ));
    }
    Ok(())
}
/// Real helper execution; caller supplies current-thread Tokio runtime. Normal
/// zero exit is available only after original controls and source close succeed.
/// No signal/process/key/network setup is executed by merely compiling this API.
pub async fn run(options: Options) -> io::Result<()> {
    validate(&options)?;
    if !geteuid().is_root() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "DNS helper requires actual effective root",
        ));
    }
    // Validate the actual post-exec parent/group before enabling interception.
    // The mark exemption must cover the daemon's real DNSSTUB sockets.
    let parent = u32::try_from(nix::unistd::getppid().as_raw())
        .map_err(|_| io::Error::other("DNS helper original parent PID"))?;
    crate::transport::check_group(parent)?;
    let real_uid = getuid();
    let gid = getegid().as_raw();
    let pump = pump::Pump::new()?;
    let mut tun = OwnedTun::open_linux_exclusive(
        Some(&options.interface),
        true,
        gnunet_tun_host::Limits {
            packet_bytes: 65527,
        },
    )?;
    let mut controls = if options.skip_routing {
        None
    } else {
        match control::Controls::acquire(&tun.info().name, gid).await {
            Ok(c) => Some(c),
            Err(e) => {
                let close = tun.close();
                return match close {
                    Ok(()) => Err(e),
                    Err(cleanup) => Err(io::Error::other(format!(
                        "{e}; independent TUN close: {cleanup}"
                    ))),
                };
            }
        }
    };
    let startup = (|| -> io::Result<()> {
        for action in [
            Action::Mtu(65527),
            Action::Ipv4Address(options.ipv4),
            Action::Ipv4Netmask(options.mask),
            Action::Ipv6Address {
                address: options.ipv6,
                prefix: options.prefix,
            },
            Action::LinkUp(true),
        ] {
            let effect = tun.plan(action, tokio::time::Instant::now() + Duration::from_secs(5))?;
            let applied = tun.apply(effect).map_err(|e| e.error)?;
            if applied.timing() != Timing::Timely {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "DNS original TUN configuration completed late",
                ));
            }
        }
        Ok(())
    })();
    let startup = match startup {
        Err(e) => Err(e),
        Ok(()) => {
            if let Some(control) = controls.as_mut() {
                control.install().await
            } else {
                Ok(())
            }
        }
    };
    let mut first = startup.err();
    let mut native = match AsyncTun::new(tun) {
        Ok(t) => Some(t),
        Err(e) => {
            if first.is_none() {
                first = Some(e);
            }
            None
        }
    };
    if first.is_none() {
        match seteuid(real_uid) {
            Ok(()) => {
                if let Some(tun) = native.as_mut() {
                    let report = pump.run(tun).await;
                    let _diagnostic = std::io::Write::write_fmt(
                        &mut std::io::stderr().lock(),
                        format_args!(
                            "DNS helper original pump captured={} tun-written={} pipe-bytes={} discarded={} pending-prefix={:?} input-prefix={:?} native-loss={:?}\n",
                            report.captured,
                            report.tun_written,
                            report.pipe_written,
                            report.discarded,
                            report.pending_prefix,
                            report.input_prefix,
                            report.native_loss
                        ),
                    );
                    first = report.first;
                }
            }
            Err(e) => first = Some(io::Error::from(e)),
        }
    }
    // Physical source stays owned while original policy rules are removed. Every
    // independent cleanup is attempted even after the first one fails.
    let privilege = seteuid(Uid::from_raw(0)).err().map(io::Error::from);
    let cleanup = if let Some(control) = controls.as_mut() {
        control.cleanup().await
    } else {
        control::Cleanup::default()
    };
    let loss = native.as_mut().map(AsyncTun::close);
    let close = loss.and_then(|l| l.close_error);
    let cleanup_count = cleanup.len();
    if first.is_none() && privilege.is_none() && cleanup_count == 0 && close.is_none() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "DNS helper failure original={first:?} regain-root={privilege:?} control-cleanup={cleanup:?} TUN-close={close:?}"
        )))
    }
}
