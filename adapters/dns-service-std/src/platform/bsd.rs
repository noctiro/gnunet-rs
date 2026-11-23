//! Exclusive macOS/FreeBSD TUN pumping under administrator-owned routing policy.
use super::{Options, pf, pump, validate};
use gnunet_tun_host::{Action, AsyncTun, OwnedTun, Timing};
use nix::unistd::{Uid, getegid, geteuid, getgid, getuid, seteuid};
use std::{error::Error, fmt, io, time::Duration};
#[derive(Debug)]
struct Failure {
    original: Option<io::Error>,
    pump: Option<pump::PumpReport>,
    privilege: Option<io::Error>,
    close: Option<io::Error>,
    policy: pf::Cleanup,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DNS helper original={:?}; pump={:?}; regain-root={:?}; TUN-close={:?}; PF-cleanup={:?}",
            self.original, self.pump, self.privilege, self.close, self.policy
        )
    }
}
impl Error for Failure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original
            .as_ref()
            .or_else(|| self.pump.as_ref().and_then(|report| report.first.as_ref()))
            .or(self.privilege.as_ref())
            .or(self.close.as_ref())
            .or(self.policy.retirement.as_ref())
            .or(self.policy.policy.as_ref())
            .map(|error| error as &(dyn Error + 'static))
            .or_else(|| {
                self.pump
                    .as_ref()
                    .and_then(|report| report.native_loss.as_ref())
                    .map(|error| error as _)
            })
    }
}
impl Failure {
    fn finish(self) -> io::Result<()> {
        if self.original.is_none()
            && self.privilege.is_none()
            && self.close.is_none()
            && self.policy.is_empty()
            && self
                .pump
                .as_ref()
                .is_none_or(|report| report.first.is_none() && report.native_loss.is_none())
        {
            Ok(())
        } else {
            Err(io::Error::other(self))
        }
    }
}
#[cfg(target_os = "macos")]
fn open(options: &Options) -> io::Result<OwnedTun> {
    let unit = match options.interface.strip_prefix("utun") {
        Some("") => None,
        Some(number) if number.bytes().all(|byte| byte.is_ascii_digit()) => {
            Some(number.parse::<u32>().map_err(io::Error::other)?)
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "macOS DNS IFNAME must be utun or utunN",
            ));
        }
    };
    OwnedTun::open_utun(
        unit,
        gnunet_tun_host::Limits {
            packet_bytes: 65527,
        },
    )
}
#[cfg(target_os = "freebsd")]
fn open(options: &Options) -> io::Result<OwnedTun> {
    use gnunet_native::filesystem::Directory;
    use std::{ffi::OsStr, path::Path};
    let parent = Directory::open(Path::new("/var/run"))?;
    let directory = parent.ensure_private_directory(OsStr::new("gnunet-dns-rust"))?;
    // The private checkpoint directory must be named durably before allocation.
    parent.as_file().sync_all()?;
    directory.validate_private()?;
    let checkpoint =
        Path::new("/var/run/gnunet-dns-rust").join(format!("{}.tun", options.interface));
    OwnedTun::open_freebsd_recoverable(
        Some(&options.interface),
        &checkpoint,
        gnunet_tun_host::Limits {
            packet_bytes: 65527,
        },
    )
    .map_err(io::Error::other)
}
fn configure(tun: &mut OwnedTun, options: &Options) -> io::Result<()> {
    for action in [
        Action::Ipv4Address(options.ipv4),
        Action::Ipv4Netmask(options.mask),
        Action::Ipv6Address {
            address: options.ipv6,
            prefix: options.prefix,
        },
        Action::Mtu(1280),
        Action::LinkUp(true),
    ] {
        let until = tokio::time::Instant::now()
            .checked_add(Duration::from_secs(5))
            .ok_or_else(|| io::Error::other("DNS helper configuration deadline overflow"))?;
        let effect = tun.plan(action, until)?;
        let applied = tun.apply(effect).map_err(|error| error.error)?;
        if applied.timing() != Timing::Timely {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "DNS helper original TUN configuration completed late",
            ));
        }
    }
    Ok(())
}
/// Provision one exclusive native interface and pump official helper framing.
/// Automatic routing uses an enabled PF instance with the dedicated DNS anchor
/// delegated first by the administrator. `SKIP_ROUTING_SETUP` instead leaves
/// interception policy outside this helper. Requires effective root and an
/// entered current-thread Tokio runtime.
///
/// # Errors
/// Retains independent setup, policy, packet, privilege-restoration and device
/// close failures. Saved FreeBSD ownership is physically recovered before a new
/// allocation. Foreign interfaces/rules and unresolved intents fence startup.
pub async fn run(options: Options) -> io::Result<()> {
    validate(&options)?;
    if !geteuid().is_root() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "DNS helper requires effective root",
        ));
    }
    if !options.skip_routing && getgid() != getegid() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "DNS helper requires unchanged real/effective group for the daemon exemption",
        ));
    }
    let real_uid = getuid();
    let mut pump = pump::Pump::new()?;
    let mut controls = if options.skip_routing {
        None
    } else {
        Some(pf::Controls::reserve()?)
    };
    if let Some(control) = &mut controls {
        let prepared = preparing(&mut pump, control.prepare()).await;
        match prepared {
            Ok(Preparation::Ready(())) => {}
            outcome => {
                let original = outcome.err();
                return Failure {
                    original,
                    pump: None,
                    privilege: None,
                    close: None,
                    policy: cleanup(controls.as_mut()).await,
                }
                .finish();
            }
        }
    }
    let mut tun = match open(&options) {
        Ok(tun) => tun,
        Err(original) => {
            return Failure {
                original: Some(original),
                pump: None,
                privilege: None,
                close: None,
                policy: cleanup(controls.as_mut()).await,
            }
            .finish();
        }
    };
    let interface = tun.info().name.clone();
    if let Err(original) = configure(&mut tun, &options) {
        let policy = cleanup(controls.as_mut()).await;
        return Failure {
            original: Some(original),
            pump: None,
            privilege: None,
            close: tun.close().err(),
            policy,
        }
        .finish();
    }
    let mut tun = match AsyncTun::new(tun) {
        Ok(tun) => tun,
        Err(original) => {
            return Failure {
                original: Some(original),
                pump: None,
                privilege: None,
                close: None,
                policy: cleanup(controls.as_mut()).await,
            }
            .finish();
        }
    };
    let setup = if let Some(controls) = &mut controls {
        preparing(&mut pump, async {
            // Subscribe before the original state retirement selects its
            // addresses. The first packet turn drains this exact socket.
            let topology = pf::Topology::subscribe()?;
            let scope = controls
                .install(&options, &interface, getegid().as_raw())
                .await?;
            Ok(Some((scope, topology)))
        })
        .await
    } else {
        Ok(Preparation::Ready(None))
    };
    let (original, pump) = match setup {
        Err(error) => (Some(error), None),
        Ok(Preparation::Stopped) => (None, None),
        Ok(Preparation::Ready(policy)) => match seteuid(real_uid) {
            Ok(()) => match (controls.as_mut(), policy) {
                (Some(controls), Some((scope, mut topology))) => {
                    let watch = controls.watch(&interface, &scope);
                    let report = pump
                        .run_guarded(&mut tun, watch, |cx| topology.poll(cx, &scope))
                        .await;
                    (None, Some(report))
                }
                (None, None) => (None, Some(pump.run(&mut tun).await)),
                _ => (
                    Some(io::Error::other("PF original observation owner missing")),
                    None,
                ),
            },
            Err(error) => (Some(error.into()), None),
        },
    };
    let privilege = seteuid(Uid::from_raw(0)).err().map(io::Error::from);
    let policy = cleanup(controls.as_mut()).await;
    let close = tun.close().close_error;
    Failure {
        original,
        pump,
        privilege,
        close,
        policy,
    }
    .finish()
}
async fn cleanup(controls: Option<&mut pf::Controls>) -> pf::Cleanup {
    match controls {
        Some(controls) => controls.cleanup().await,
        None => pf::Cleanup::default(),
    }
}

enum Preparation<T> {
    Ready(T),
    Stopped,
}
async fn preparing<T>(
    pump: &mut pump::Pump,
    work: impl std::future::Future<Output = io::Result<T>>,
) -> io::Result<Preparation<T>> {
    let mut work = std::pin::pin!(work);
    std::future::poll_fn(|cx| {
        if let std::task::Poll::Ready(stop) = pump.poll_stop(cx) {
            return std::task::Poll::Ready(stop.map(|()| Preparation::Stopped));
        }
        work.as_mut().poll(cx).map_ok(Preparation::Ready)
    })
    .await
}
