//! Explicit trusted Wintun provisioning, separate from DNS interception policy.
use crate::Failure;
use gnunet_config::{Configuration, ProcessEnvironment};
use gnunet_dns_service_host::PacketSource;
use gnunet_tun_host::{
    Action, AsyncTun, OwnedTun, Timing, Version,
    wintun::{Driver, RingCapacity},
};
use std::{
    error::Error,
    ffi::OsStr,
    fmt, io,
    net::{Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    time::Duration,
};
const LOCAL: &[u8] = b"dns-rust";
pub(crate) struct Addresses {
    pub interface: String,
    pub ipv4: Ipv4Addr,
    pub mask: Ipv4Addr,
    pub ipv6: Ipv6Addr,
    pub prefix: u8,
}
#[derive(Clone, Copy)]
enum Mode {
    Create,
    Existing,
}
struct Wintun {
    dll: PathBuf,
    capacity: RingCapacity,
    mode: Mode,
    addresses: Addresses,
}
pub(crate) struct Settings(Backend);
enum Backend {
    Capture { dll: PathBuf },
    Tun(Wintun),
}
impl Settings {
    pub fn label(&self) -> &'static str {
        match &self.0 {
            Backend::Capture { .. } => "windivert",
            Backend::Tun(_) => "wintun",
        }
    }
    pub fn read(
        config: &Configuration,
        addresses: Addresses,
        skip_routing: bool,
    ) -> Result<Self, Failure> {
        if config.get(LOCAL, b"HELPER_BINARY").is_some() {
            return Err("HELPER_BINARY is only supported on Unix".into());
        }
        if !skip_routing {
            if config.get(LOCAL, b"WINDIVERT_DLL").is_none() {
                return Err("Automatic Windows DNS interception requires an explicit trusted official WINDIVERT_DLL and an already installed WinDivert 2.2 driver".into());
            }
            if config.get(LOCAL, b"WINTUN_DLL").is_some() {
                return Err("Automatic interception uses WINDIVERT_DLL; WINTUN_DLL requires SKIP_ROUTING_SETUP=YES".into());
            }
            let dll = config.get_filename(LOCAL, b"WINDIVERT_DLL", &ProcessEnvironment)?;
            if !dll.is_absolute() {
                return Err("WINDIVERT_DLL must expand to an absolute path".into());
            }
            return Ok(Self(Backend::Capture { dll }));
        }
        if config.get(LOCAL, b"WINDIVERT_DLL").is_some() {
            return Err("WINDIVERT_DLL requires SKIP_ROUTING_SETUP=NO".into());
        }
        if config.get(LOCAL, b"WINTUN_DLL").is_none() {
            return Err("Windows DNS requires an explicit trusted official WINTUN_DLL".into());
        }
        let dll = config.get_filename(LOCAL, b"WINTUN_DLL", &ProcessEnvironment)?;
        if !dll.is_absolute() {
            return Err("WINTUN_DLL must expand to an absolute path".into());
        }
        let capacity = config
            .get(LOCAL, b"WINTUN_RING_BYTES")
            .map(|_| config.get_size(LOCAL, b"WINTUN_RING_BYTES"))
            .transpose()?
            .map(u32::try_from)
            .transpose()?
            .map(RingCapacity::new)
            .transpose()?
            .unwrap_or(RingCapacity::MIN);
        let mode = match config.get(LOCAL, b"WINTUN_MODE").unwrap_or(b"create") {
            b"create" => Mode::Create,
            b"existing" => Mode::Existing,
            _ => return Err("WINTUN_MODE must be create or existing".into()),
        };
        let mask = u32::from(addresses.mask);
        if mask != 0 && !(!mask).wrapping_add(1).is_power_of_two() {
            return Err("DNS IPv4 mask must be contiguous".into());
        }
        Ok(Self(Backend::Tun(Wintun {
            dll,
            capacity,
            mode,
            addresses,
        })))
    }
}
#[derive(Debug)]
struct SetupFailure {
    original: io::Error,
    close: Option<io::Error>,
}
impl fmt::Display for SetupFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DNS Wintun setup: {}; independent close: {:?}",
            self.original, self.close
        )
    }
}
impl Error for SetupFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.original)
    }
}
fn configure(tun: &mut OwnedTun, addresses: &Addresses) -> io::Result<()> {
    let until = tokio::time::Instant::now()
        .checked_add(Duration::from_secs(5))
        .ok_or_else(|| io::Error::other("DNS Wintun setup deadline overflow"))?;
    for action in [
        Action::Ipv4Address(addresses.ipv4),
        Action::Ipv4Netmask(addresses.mask),
        Action::Ipv6Address {
            address: addresses.ipv6,
            prefix: addresses.prefix,
        },
        Action::IpMtu {
            version: Version::V4,
            bytes: 1280,
        },
        Action::IpMtu {
            version: Version::V6,
            bytes: 1280,
        },
        Action::LinkUp(true),
    ] {
        let effect = tun.plan(action, until)?;
        let receipt = tun.apply(effect).map_err(|error| error.error)?;
        if receipt.timing() != Timing::Timely {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "DNS Wintun configuration completed late",
            ));
        }
    }
    Ok(())
}
#[expect(
    unsafe_code,
    reason = "The operator selects an absolute official Wintun or WinDivert provider and trusts its ABI, dependencies and documented thread safety"
)]
pub(super) fn open<'id>(
    settings: Settings,
    upstream: &mut gnunet_dns_service_host::Upstream,
    exit: std::net::IpAddr,
) -> Result<PacketSource<'id>, Failure> {
    let settings = match settings.0 {
        Backend::Capture { dll } => {
            let family = match exit {
                std::net::IpAddr::V4(_) => gnunet_dnsstub_host::Family::V4,
                std::net::IpAddr::V6(_) => gnunet_dnsstub_host::Family::V6,
            };
            let reservations = upstream.reserve_sockets(family)?;
            // SAFETY: WINDIVERT_DLL explicitly selects the trusted official
            // thread-safe C ABI, including dependencies and callback destruction.
            let driver = unsafe { gnunet_native::windivert::Driver::load(&dll) }?;
            return Ok(PacketSource::capture(
                &driver,
                reservations,
                gnunet_native::windivert::Limits::default(),
            )?);
        }
        Backend::Tun(settings) => settings,
    };
    // SAFETY: WINTUN_DLL is an explicit operator trust decision; no provider
    // search, implicit DLL filename, download or alternate ABI is selected.
    let driver = unsafe { Driver::load(&settings.dll) }?;
    let name = OsStr::new(&settings.addresses.interface);
    let adapter = match settings.mode {
        Mode::Create => driver.create(name, OsStr::new("GNUnet DNS"), None)?,
        Mode::Existing => driver.open(name)?,
    };
    let session = adapter.start(settings.capacity)?;
    let mut tun = OwnedTun::from_wintun(
        session,
        gnunet_tun_host::Limits {
            packet_bytes: 65527,
        },
    )?;
    // Existing adapters are borrowed unchanged. Only a newly created adapter
    // may receive addresses, family MTUs and administrative-state changes.
    if matches!(settings.mode, Mode::Create)
        && let Err(original) = configure(&mut tun, &settings.addresses)
    {
        return Err(Box::new(SetupFailure {
            original,
            close: tun.close().err(),
        }));
    }
    Ok(PacketSource::device(AsyncTun::new(tun)?))
}
