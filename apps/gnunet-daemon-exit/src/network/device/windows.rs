//! Explicit caller-trusted Wintun provisioning, with no implicit provider search.
use crate::{Failure, settings::Settings as ServiceSettings};
use gnunet_config::{Configuration, ProcessEnvironment};
use gnunet_tun_host::{
    Limits, OwnedTun,
    wintun::{Driver, RingCapacity},
};
use std::{ffi::OsStr, path::PathBuf};
const LOCAL: &[u8] = b"exit-rust";
pub(crate) struct Settings {
    dll: PathBuf,
    capacity: RingCapacity,
}
impl Settings {
    pub(crate) fn read(config: &Configuration, required: bool) -> Result<Option<Self>, Failure> {
        if config.get(LOCAL, b"WINTUN_DLL").is_none() {
            return if required {
                Err("Windows EXIT TUN requires an explicit trusted official WINTUN_DLL".into())
            } else {
                Ok(None)
            };
        }
        let dll = config.get_absolute_filename(LOCAL, b"WINTUN_DLL", &ProcessEnvironment)?;
        let bytes = config
            .get(LOCAL, b"WINTUN_RING_BYTES")
            .map(|_| config.get_size(LOCAL, b"WINTUN_RING_BYTES"))
            .transpose()?
            .unwrap_or(4 * 1024 * 1024);
        Ok(Some(Self {
            dll,
            capacity: RingCapacity::new(u32::try_from(bytes)?)?,
        }))
    }
}
#[expect(
    unsafe_code,
    reason = "The explicit operator-selected WINTUN_DLL contract requires the trusted official Wintun ABI and dependencies; this is the sole EXIT provider loader"
)]
pub(super) fn open(
    settings: &ServiceSettings,
    limits: Limits,
    existing: bool,
) -> Result<OwnedTun, Failure> {
    if settings.unit.is_some() || settings.packet_information {
        return Err("Windows Wintun does not use UTUN_UNIT or LINUX_TUN_PI".into());
    }
    let name = settings
        .name
        .as_deref()
        .filter(|name| !name.is_empty())
        .ok_or("Windows EXIT TUN requires [exit] TUN_IFNAME")?;
    if name.contains('\0') || name.encode_utf16().count() > 256 {
        return Err("invalid Windows TUN_IFNAME".into());
    }
    let native = settings
        .wintun
        .as_ref()
        .ok_or("missing Windows Wintun provider configuration")?;
    // SAFETY: this explicit absolute operator trust selection is documented to
    // require the official Wintun DLL, dependencies and ABI. No fallback search,
    // download or untrusted network artifact can choose a native provider.
    let driver = unsafe { Driver::load(&native.dll) }?;
    let adapter = if existing {
        driver.open(OsStr::new(name))?
    } else {
        driver.create_exclusive(OsStr::new(name), OsStr::new("GNUnet"), None)?
    };
    let session = adapter.start(native.capacity)?;
    OwnedTun::from_wintun(session, limits).map_err(Into::into)
}
