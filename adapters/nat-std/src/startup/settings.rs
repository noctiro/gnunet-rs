//! Configuration for native listeners, service bounds and provider composition.
use super::HelperPrograms;
use crate::{
    manager::Failure,
    server::{self, Mode},
};
use gnunet_config::Configuration;
use gnunet_service_runtime::{credentials::UnixAccess, service::ShutdownMode, service_options};
use std::time::Duration;
use tokio::time::Instant;
/// Effective bounded foreground policy, using each actual official service section.
pub struct Settings {
    /// Actual NAT/per-source policy and real provider budgets.
    pub discovery: crate::settings::Settings,
    /// Actual bounded business core.
    pub core: gnunet_nat::state::Limits,
    /// Actual original native source bounds.
    pub native: server::Limits,
    /// Official SERVICE listener/access/shutdown policy.
    pub options: gnunet_service_runtime::service::ServiceOptions,
    /// Actual Unix credential admission policy.
    pub unix: UnixAccess,
    /// Same process Resolver resources.
    pub resolver: gnunet_resolver_broker::Limits,
    /// Original finite process drain bound.
    pub grace: Duration,
}
fn number(c: &Configuration, section: &[u8], key: &[u8], default: usize) -> Result<usize, Failure> {
    Ok(if c.have_value(section, key) {
        usize::try_from(c.get_number(section, key)?)?
    } else {
        default
    })
}
fn duration(
    c: &Configuration,
    section: &[u8],
    key: &[u8],
    default: Duration,
) -> Result<Duration, Failure> {
    let d = if c.have_value(section, key) {
        Duration::from_micros(c.get_time(section, key)?)
    } else {
        default
    };
    if d.is_zero()
        || d.as_micros() > u128::from(u64::MAX)
        || Instant::now().checked_add(d).is_none()
    {
        return Err("NAT foreground requires finite nonzero timer".into());
    }
    Ok(d)
}
impl Settings {
    /// Read actual service/NAT keys; this does not open listeners or helpers.
    pub fn read(c: &Configuration, mode: Mode) -> Result<Self, Failure> {
        Self::read_with(c, mode, crate::settings::Settings::read)
    }

    pub(super) fn embedded(
        c: &Configuration,
        helper_programs: Option<HelperPrograms>,
    ) -> Result<Self, Failure> {
        Self::read_with(c, Mode::Nat, |c| {
            crate::settings::Settings::read_embedded(
                c,
                helper_programs.map(|programs| programs.paths),
            )
        })
    }

    fn read_with(
        c: &Configuration,
        mode: Mode,
        discovery: impl FnOnce(
            &Configuration,
        )
            -> Result<crate::settings::Settings, crate::settings::ConfigError>,
    ) -> Result<Self, Failure> {
        let section = mode.service();
        let d = server::Limits::default();
        let native = server::Limits {
            clients: number(c, b"nat-rust", b"MAX_CLIENTS", d.clients)?,
            frame_bytes: number(c, b"nat-rust", b"FRAME_BYTES", d.frame_bytes)?,
            output_frames: number(c, b"nat-rust", b"OUTPUT_FRAMES", d.output_frames)?,
            output_bytes: number(c, b"nat-rust", b"OUTPUT_BYTES", d.output_bytes)?,
            io_slice_bytes: number(c, b"nat-rust", b"IO_SLICE_BYTES", d.io_slice_bytes)?,
            first_input: duration(c, b"nat-rust", b"FIRST_INPUT_TIMEOUT", d.first_input)?,
            input_lifetime: duration(c, b"nat-rust", b"INPUT_LIFETIME", d.input_lifetime)?,
            output_lifetime: duration(c, b"nat-rust", b"OUTPUT_LIFETIME", d.output_lifetime)?,
            transient_lifetime: duration(
                c,
                b"nat-rust",
                b"TRANSIENT_LIFETIME",
                d.transient_lifetime,
            )?,
        };
        let core = gnunet_nat::state::Limits {
            sources: native.clients,
            providers: number(c, b"nat-rust", b"MAX_PROVIDERS", 1024)?,
            events: number(c, b"nat-rust", b"MAX_EVENTS", 4096)?,
            ..gnunet_nat::state::Limits::default()
        };
        let flag = |key: &[u8]| -> Result<bool, Failure> {
            Ok(c.get(section, key)
                .map(|_| c.get_yesno(section, key))
                .transpose()?
                .unwrap_or(false))
        };
        Ok(Self {
            discovery: discovery(c)?,
            core,
            native,
            options: service_options(c, section, ShutdownMode::Soft)?,
            unix: UnixAccess {
                match_uid: flag(b"UNIX_MATCH_UID")?,
                match_gid: flag(b"UNIX_MATCH_GID")?,
            },
            resolver: gnunet_resolver_broker::Limits {
                max_frame_bytes: 65535,
                io_chunk_bytes: native.io_slice_bytes,
                max_queued_frames: 64,
            },
            grace: duration(c, b"nat-rust", b"SHUTDOWN_GRACE", Duration::from_secs(10))?,
        })
    }
}
