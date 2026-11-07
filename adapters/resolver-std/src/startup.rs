//! Foreground assembly using official service configuration and literal files.
use crate::{
    Host, Limits, MachineFiles, Ports, Report,
    storage::{Geometry, Store},
};
use gnunet_client::resolver::FamilyProfile;
use gnunet_config::{Configuration, Environment, ProcessEnvironment, ProjectData};
use gnunet_idna::{Backend, NativeProfile, Workspace};
use gnunet_resolver_service_core::{owner::Resolver, storage::Limits as CoreLimits};
use gnunet_service_runtime::{Activation, BoundListeners, service_options};
use gnunet_service_runtime::{
    clock::{RuntimeClock, SystemClock},
    credentials::UnixAccess,
    service::ShutdownMode,
};
use gnunet_service_startup::{Identity, configured_user, resolve_user};
use std::{
    error::Error,
    future::{Future, poll_fn},
    io,
    net::SocketAddr,
    path::Path,
    sync::Arc,
    task::Poll,
};
/// Select the supported actual host IPC family ABI explicitly.
pub fn native_family() -> Result<FamilyProfile, gnunet_types::Error> {
    if cfg!(target_os = "macos") {
        Ok(FamilyProfile::DARWIN)
    } else if cfg!(target_os = "linux") {
        Ok(FamilyProfile::LINUX)
    } else {
        Err(gnunet_types::Error::Unsupported)
    }
}
/// Read official configuration defaults plus the selected user configuration.
/// No private upstream/path keys are introduced.
pub fn configuration(selected: Option<&Path>) -> Result<Configuration, Box<dyn Error>> {
    let project = Arc::new(ProjectData::default());
    let mut cfg = Configuration::create(project.clone(), Default::default())?;
    let user = if let Some(p) = selected {
        Some(p.to_path_buf())
    } else {
        let raw = match ProcessEnvironment.variable(b"XDG_CONFIG_HOME") {
            Some(mut b) => {
                b.push(b'/');
                b.extend_from_slice(&project.config_file);
                b
            }
            None => project.user_config_file.clone(),
        };
        let p = cfg.expand_filename(&raw, &ProcessEnvironment)?;
        p.is_file().then_some(p)
    };
    cfg.load(user.as_deref())?;
    Ok(cfg)
}
/// Explicit current-account mismatch; checking does not change process IDs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfiguredIdentityMismatch {
    /// Configured native account's actual UID.
    pub expected_uid: u32,
    /// Configured native account's actual primary GID.
    pub expected_gid: u32,
    /// Actual real/effective IDs at this service construction boundary.
    pub actual: Identity,
}
impl std::fmt::Display for ConfiguredIdentityMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Resolver USERNAME requires uid={} gid={} before target-account listeners/machine files/host; actual={:?}",
            self.expected_uid, self.expected_gid, self.actual
        )
    }
}
impl Error for ConfiguredIdentityMismatch {}
/// Require the selected account's actual current real/effective IDs. Generic
/// async embedding never changes the whole process identity behind its caller.
pub fn verify_configured_identity(config: &Configuration) -> Result<(), Box<dyn Error>> {
    if let Some(name) = configured_user(config, b"resolver")? {
        let user = resolve_user(&name)?;
        let actual = Identity::current();
        if actual.uid != user.uid()
            || actual.euid != user.uid()
            || actual.gid != user.gid()
            || actual.egid != user.gid()
        {
            return Err(Box::new(ConfiguredIdentityMismatch {
                expected_uid: user.uid(),
                expected_gid: user.gid(),
                actual,
            }));
        }
    }
    Ok(())
}
/// Read this same Resolver section's kernel and Unix-filesystem matching intent.
/// Absent fields are false. The process entry uses these exact booleans for
/// finish_with_access; the Host applies them to original accepted credentials.
pub fn unix_access(config: &Configuration) -> Result<UnixAccess, Box<dyn Error>> {
    let flag = |key: &[u8]| {
        config
            .get(b"resolver", key)
            .map(|_| config.get_yesno(b"resolver", key))
            .transpose()
            .map(|value| value.unwrap_or(false))
    };
    Ok(UnixAccess {
        match_uid: flag(b"UNIX_MATCH_UID")?,
        match_gid: flag(b"UNIX_MATCH_GID")?,
    })
}
/// Run the same real owner under an already selected process identity. This
/// embedding path uses actual native UTC and introduces no daemonization or
/// process-wide privilege mutation; standard binaries prepare listeners before
/// USERNAME and call foreground_listening_with_clock with their original source.
pub async fn foreground(
    config: &Configuration,
    activation: Activation,
    files: MachineFiles,
    endpoints: &[SocketAddr],
    ready: impl FnOnce(&BoundListeners) -> io::Result<()>,
    shutdown: impl Future<Output = io::Result<()>>,
    observe: impl FnMut(crate::SocketEvent),
) -> Result<Report, Box<dyn Error>> {
    verify_configured_identity(config)?;
    let unix = unix_access(config)?;
    let listeners = BoundListeners::prepare_before_identity(config, b"resolver", activation)?;
    let bound = listeners
        .finish_with_access(gnunet_service_runtime::UnixListenerAccess {
            match_uid: unix.match_uid,
            match_gid: unix.match_gid,
        })
        .await?;
    foreground_listening_with_clock(
        config,
        bound,
        files,
        endpoints,
        ready,
        shutdown,
        observe,
        Arc::new(SystemClock),
    )
    .await
}
#[derive(Debug)]
struct ForegroundFailure {
    original: Option<Box<dyn Error>>,
    cleanup: Option<crate::HostError>,
    report: Report,
}
impl std::fmt::Display for ForegroundFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Resolver foreground did not settle")?;
        if let Some(error) = &self.original {
            write!(f, ": {error}")?;
        }
        if let Some(error) = &self.cleanup {
            write!(f, "; independent cleanup: {error}")?;
        }
        write!(f, "; actual report: {:?}", self.report)
    }
}
impl Error for ForegroundFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original.as_deref().or_else(|| {
            self.cleanup
                .as_ref()
                .map(|error| error as &(dyn Error + 'static))
        })
    }
}
/// Consume actual inherited/prebound listeners finished by the selected account.
/// The Host receives its one shared UTC source/subscription before any data or
/// lookup is enabled. Ready follows real core/stub/IDNA/policy/file construction;
/// it is not a bound-only promise or proof of remote DNS/GNUnet availability.
/// Every post-construction exit, including Ready/clock/control/logging failure,
/// performs original clock-free Immediate physical cleanup and retains errors.
#[expect(
    clippy::too_many_arguments,
    reason = "Original config/listeners/files, embedding endpoints and exact process callbacks/source remain separate"
)]
pub async fn foreground_listening_with_clock(
    config: &Configuration,
    bound: BoundListeners,
    files: MachineFiles,
    endpoints: &[SocketAddr],
    ready: impl FnOnce(&BoundListeners) -> io::Result<()>,
    shutdown: impl Future<Output = io::Result<()>>,
    mut observe: impl FnMut(crate::SocketEvent),
    clock: Arc<dyn RuntimeClock>,
) -> Result<Report, Box<dyn Error>> {
    verify_configured_identity(config)?;
    let unix = unix_access(config)?;
    let options = service_options(config, b"resolver", ShutdownMode::Immediate)?;
    let mut backing = Store::new(Geometry::default())?;
    let mut staging = Store::new(Geometry::default())?;
    let core = Resolver::new(
        backing.buffers(),
        CoreLimits {
            max_name_bytes: 65535,
            max_record_bytes: 65535,
            cname_hops: 32,
        },
        1,
    )?;
    let stage = core.make_scratch(staging.buffers())?;
    let mut work = Workspace::new();
    let idna = Backend::new(
        &mut work,
        gnunet_idna::Limits::GNUNET,
        NativeProfile::Libunistring1_5Unicode18_0,
    );
    let mut host = Host::<_, 128, 271, 128>::new(
        core,
        stage,
        &idna,
        Ports::system(),
        native_family()?,
        Limits::default(),
        options,
        128,
    )?;
    let result = async {
        host.set_runtime_clock(clock)?;
        host.set_unix_access(unix)?;
        host.load_machine_bytes(&files.hosts, &files.resolv)?;
        // Literal inputs are already copied into the bounded core/stub. Do not
        // retain a second maximum-size pair of raw files for service lifetime.
        drop(files);
        for address in endpoints {
            host.add_dns_endpoint(*address)?;
        }
        ready(&bound)?;
        let listeners = bound.listeners();
        let mut drive = std::pin::pin!(host.drive(&listeners, None, &mut observe));
        let mut shutdown = std::pin::pin!(shutdown);
        poll_fn(|cx| {
            if let Poll::Ready(result) = shutdown.as_mut().poll(cx) {
                return Poll::Ready(result.map_err(|error| Box::new(error) as Box<dyn Error>));
            }
            drive.as_mut().poll(cx).map(|result| {
                result
                    .map(|_| ())
                    .map_err(|error| Box::new(error) as Box<dyn Error>)
            })
        })
        .await
    }
    .await;
    let cleanup = host.shutdown(ShutdownMode::Immediate).err();
    let report = host.report();
    drop(host);
    drop(bound);
    if result.is_err() || cleanup.is_some() {
        return Err(Box::new(ForegroundFailure {
            original: result.err(),
            cleanup,
            report,
        }));
    }
    Ok(report)
}
