//! Pinned SERVICE command options over the existing GETOPT and logging owners.
//! Configuration selection is shared; listener preparation, daemonization,
//! process identity and runtime ownership stay explicit with the service caller.
use crate::{
    config_observer,
    getopt::Options,
    helpers::{self, Filename, Target},
    logging::{Logger, Stamp},
    policy::{CallSite, Level},
    program::{Environment, Failure},
    shared_clock::SharedClock,
};
use gnunet_config::{Configuration, Environment as _, ProcessEnvironment, ProjectData};
use std::{
    ffi::OsString,
    fmt,
    io::{self, Write},
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    sync::Arc,
};

/// Successfully parsed actual options. No service, file configuration, listener
/// or runtime is opened by this value. A daemon request is never silently run
/// in the foreground; the caller must provide the real mode or reject it.
pub struct Selected {
    config: Option<PathBuf>,
    daemonize: bool,
}
impl Selected {
    /// Explicit -c/--config, expanded by the same standard filename callback.
    /// None retains SERVICE's optional-default-file then load(None) selection.
    pub fn configuration(&self) -> Option<&Path> {
        self.config.as_deref()
    }
    /// Actual -d/--daemonize request, not a detach or readiness receipt.
    pub const fn daemonize_requested(&self) -> bool {
        self.daemonize
    }
}
/// Terminal help/version/parser result is distinct from permission to start.
pub enum Preparation {
    /// Actual parsed configuration/logging selection, ready for caller startup.
    Ready(Selected),
    /// Parser diagnostics already emitted. True is help/version, false failure.
    Stopped {
        /// Help/version completed successfully rather than a parser failure.
        successful: bool,
    },
}

/// Load the explicit SERVICE file or the optional XDG/user entrypoint, then the
/// installed defaults. SERVICE does not use PROGRAM's `/etc` entrypoint search.
/// Call after the daemon fork and before applying the configured identity.
pub fn load_configuration(
    project: Arc<ProjectData>,
    selected: Option<&Path>,
) -> Result<Configuration, Failure> {
    let mut config = Configuration::create(project.clone(), Default::default())?;
    let path = match selected {
        Some(path) => {
            if !path.is_file() {
                return Err(gnunet_config::Error::InvalidInput.into());
            }
            Some(path.to_path_buf())
        }
        None => {
            let raw = match ProcessEnvironment.variable(b"XDG_CONFIG_HOME") {
                Some(mut base) => {
                    base.push(b'/');
                    base.extend_from_slice(&project.config_file);
                    base
                }
                None => project.user_config_file.clone(),
            };
            match config.expand_filename(&raw, &ProcessEnvironment) {
                Ok(path) => path.is_file().then_some(path),
                // An unexpandable home candidate is absent. SERVICE still loads
                // its installed defaults, without trying PROGRAM's /etc files.
                Err(gnunet_config::Error::Missing) => None,
                Err(error) => return Err(error.into()),
            }
        }
    };
    config.load(path.as_deref())?;
    Ok(config)
}

/// Exact active SERVICE option table: c,d,h,L,l,v. In particular -v is version;
/// SERVICE does not register the separately available -V/--verbose helper.
/// GNUNET_ARGS is a PROGRAM wrapper feature and is not appended by SERVICE.
#[expect(
    clippy::too_many_arguments,
    reason = "Explicit parser/output/logger/clock owners preserve original SERVICE startup effects"
)]
pub fn prepare(
    service: &[u8],
    project: &ProjectData,
    arguments: impl IntoIterator<Item = OsString>,
    environment: &Environment,
    logger: &mut Logger<'_>,
    clock: &SharedClock,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<Preparation, Failure> {
    logger.bind_clock(clock.clone());
    let config = Target::new(Filename {
        path: None,
        error: None,
    });
    let logfile = Target::new(Filename {
        path: None,
        error: None,
    });
    let loglevel = Target::new(None);
    let daemonize = Target::new(0);
    let mut options = Options::new();
    options.add(helpers::cfgfile(config.clone()));
    options.add(helpers::flag(
        b'd',
        b"daemonize",
        b"do daemonize (detach from terminal)",
        daemonize.clone(),
    ));
    options.add(helpers::help(project, None));
    options.add(helpers::loglevel(loglevel.clone()));
    options.add(helpers::logfile(logfile.clone()));
    options.add(helpers::version(&project.version));
    let translations = logger.translations();
    let mut parsed = config_observer::operation(logger, clock, stderr, |observer| {
        Ok::<_, std::convert::Infallible>(options.run_translated_observed(
            service,
            arguments,
            environment.posixly_correct,
            translations,
            Some(observer),
        ))
    })?
    .unwrap_or_else(|never| match never {});
    stdout.write_all(&parsed.output.stdout)?;
    stdout.flush()?;
    stderr.write_all(&parsed.output.stderr)?;
    stderr.flush()?;
    if let Some(error) = parsed.output.failure.take() {
        return Err(error.into());
    }
    if parsed.code <= 0 {
        return Ok(Preparation::Stopped {
            successful: parsed.code == 0,
        });
    }
    let loglevel = loglevel.get()?;
    let logfile = logfile.get()?;
    logger.setup_routed(
        service,
        loglevel.as_deref(),
        logfile.path.as_deref().map(|p| p.as_os_str().as_bytes()),
        &environment.logging,
        &Stamp::setup_now()?,
        stderr,
    )?;
    Ok(Preparation::Ready(Selected {
        config: config.get()?.path,
        daemonize: daemonize.get()? != 0,
    }))
}

/// Emit an actual entry-point diagnostic through the selected policy and owned
/// destination. Formatting/time/file rotation occur only after level admission.
/// This does not replace process fd2 or install a global/background logger.
#[track_caller]
pub fn diagnostic(
    logger: &mut Logger<'_>,
    clock: &SharedClock,
    site: &'static str,
    level: Level,
    message: fmt::Arguments<'_>,
) -> io::Result<()> {
    let caller = std::panic::Location::caller();
    diagnostic_body(logger, clock, site, level, caller, || {
        Ok(format!("{message}\n").into_bytes())
    })
}

pub(crate) fn diagnostic_body(
    logger: &mut Logger<'_>,
    clock: &SharedClock,
    site: &'static str,
    level: Level,
    caller: &std::panic::Location<'_>,
    message: impl FnOnce() -> io::Result<Vec<u8>>,
) -> io::Result<()> {
    let line = i32::try_from(caller.line()).map_err(io::Error::other)?;
    logger.source_lazy(
        site,
        level,
        CallSite {
            component: None,
            file: caller.file().as_bytes(),
            function: site.as_bytes(),
            line,
        },
        message,
        || Stamp::now(clock.offset().map_err(io::Error::other)?),
        &mut io::stderr().lock(),
    )
}

/// Original service failure plus an independent failed diagnostic. Display
/// retains both facts; a logging failure never replaces the original error.
#[derive(Debug)]
pub struct DiagnosticFailure {
    original: Box<dyn std::error::Error>,
    diagnostic: io::Error,
}
impl fmt::Display for DiagnosticFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}; independent logging failure: {}",
            self.original, self.diagnostic
        )
    }
}
impl std::error::Error for DiagnosticFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.original.as_ref())
    }
}
/// Retain a real diagnostic error independently when original service work also
/// failed. No success or cleanup receipt is manufactured by this combination.
pub fn retain_diagnostic<T>(
    original: Result<T, Box<dyn std::error::Error>>,
    diagnostic: Option<io::Error>,
) -> Result<T, Box<dyn std::error::Error>> {
    match (original, diagnostic) {
        (result, None) => result,
        (Ok(_), Some(error)) => Err(Box::new(error)),
        (Err(original), Some(diagnostic)) => Err(Box::new(DiagnosticFailure {
            original,
            diagnostic,
        })),
    }
}
