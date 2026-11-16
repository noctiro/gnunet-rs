//! Explicit configured official Wintun provider and original creation provenance.
use crate::{
    Failure,
    settings::{Settings as ServiceSettings, TunMode},
};
use gnunet_config::{Configuration, ProcessEnvironment};
use gnunet_tun_host::{
    Limits,
    wintun::{Driver, RingCapacity},
};
use gnunet_vpn_host::coordinator::Device;
use std::{ffi::OsStr, path::PathBuf};
const LOCAL: &[u8] = b"vpn-rust";
pub(crate) struct Settings {
    dll: PathBuf,
    capacity: RingCapacity,
}
impl Settings {
    pub(crate) fn read(config: &Configuration) -> Result<Self, Failure> {
        if config.get(LOCAL, b"WINTUN_DLL").is_none() {
            return Err("Windows VPN requires an explicit trusted official WINTUN_DLL".into());
        }
        let dll = config.get_filename(LOCAL, b"WINTUN_DLL", &ProcessEnvironment)?;
        if !dll.is_absolute() {
            return Err("WINTUN_DLL must expand to an absolute path".into());
        }
        let bytes = config
            .get(LOCAL, b"WINTUN_RING_BYTES")
            .map(|_| config.get_size(LOCAL, b"WINTUN_RING_BYTES"))
            .transpose()?
            .unwrap_or(4 * 1024 * 1024);
        let capacity = RingCapacity::new(u32::try_from(bytes)?)?;
        Ok(Self { dll, capacity })
    }
}
#[expect(
    unsafe_code,
    reason = "The explicit operator-selected WINTUN_DLL contract requires the trusted official Wintun ABI and dependencies; this is the sole provider loader"
)]
pub(super) fn open(settings: &ServiceSettings, limits: Limits) -> Result<Device, Failure> {
    // SAFETY: WINTUN_DLL is an explicit absolute operator trust selection, never
    // an inferred DLL name, network source or automatic dependency download.
    // The documented configuration contract requires the official trusted ABI.
    let driver = unsafe { Driver::load(&settings.wintun.dll) }?;
    let name = OsStr::new(&settings.ifname);
    let adapter = match settings.mode {
        TunMode::Fresh => driver.create_exclusive(name, OsStr::new("GNUnet"), None)?,
        TunMode::Existing => driver.open(name)?,
    };
    let session = adapter.start(settings.wintun.capacity)?;
    Device::from_wintun(session, limits).map_err(Into::into)
}
