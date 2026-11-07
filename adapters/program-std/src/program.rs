//! Source-ordered PROGRAM preparation and explicit main-call authority.
//! A successful integer return alone never proves that main was invoked: the C
//! API returns the positive GETOPT index even when log_setup fails.
use crate::format::{Argument as Value, Message};
use crate::{
    getopt::{self, Options, Output},
    helpers::{self, Filename, Target},
    logging::{Environment as LogEnvironment, Logger, Stamp},
    policy::{CallSite, Level},
    shared_clock::SharedClock,
};
use gnunet_config::{Configuration, ProjectData};
use std::{
    ffi::OsString,
    io::{self, Write},
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    sync::Arc,
};
/// The native normal reference's PROGRAM preprocessor profile has ENABLE_NLS
/// undefined. An enabled build must provide a real locale installer, never this
/// explicitly disabled profile.
pub trait LocaleSetup {
    /// Called after configuration creation and before building/running options.
    fn configure(&mut self, project: &ProjectData) -> Result<(), Failure>;
    /// Actual selected NLS backend, or explicit source ENABLE_NLS=0 profile.
    fn translations(&self) -> std::rc::Rc<dyn crate::locale::Translations>;
    /// Explicit shared comparison/ctype selection if this installer changes the
    /// effective native locale. None means it performs no locale transition.
    fn case_context(&self) -> Option<gnunet_config::CaseContext>;
}
/// Explicit build profile for source code compiled without ENABLE_NLS.
pub struct NlsDisabled;
impl LocaleSetup for NlsDisabled {
    fn case_context(&self) -> Option<gnunet_config::CaseContext> {
        None
    }
    fn translations(&self) -> std::rc::Rc<dyn crate::locale::Translations> {
        crate::locale::disabled()
    }
    fn configure(&mut self, _: &ProjectData) -> Result<(), Failure> {
        Ok(())
    }
}
/// Host-bound preparation failure, separate from the source's integer return.
#[derive(Debug)]
pub enum Failure {
    /// Configuration/storage/installation boundary failure.
    Configuration(gnunet_config::Error),
    /// Native logging, locale, clock or output failure.
    Io(io::Error),
    /// A host lifecycle or capacity condition, never fabricated source success.
    State(gnunet_types::Error),
    /// Actual shared resolver broker failure, including retired driver authority.
    #[cfg(feature = "resolver-broker")]
    Broker(gnunet_resolver_broker::BrokerError),
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Configuration(e) => write!(f, "PROGRAM configuration: {e}"),
            Self::Io(e) => write!(f, "PROGRAM native IO: {e}"),
            Self::State(e) => write!(f, "PROGRAM state: {e}"),
            #[cfg(feature = "resolver-broker")]
            Self::Broker(e) => write!(f, "PROGRAM resolver: {e}"),
        }
    }
}
impl std::error::Error for Failure {}
impl From<gnunet_config::Error> for Failure {
    fn from(e: gnunet_config::Error) -> Self {
        Self::Configuration(e)
    }
}
impl From<io::Error> for Failure {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<gnunet_types::Error> for Failure {
    fn from(e: gnunet_types::Error) -> Self {
        Self::State(e)
    }
}
/// Native environment captured before preparation; no environment is mutated.
pub struct Environment {
    /// Literal space-tokenized GNUNET_ARGS, appended after native argv.
    pub arguments: Option<Vec<u8>>,
    /// Presence of POSIXLY_CORRECT.
    pub posixly_correct: bool,
    /// Dynamic logging setup inputs.
    pub logging: LogEnvironment,
}
impl Environment {
    /// Read process environment without mutating process-global state.
    #[must_use]
    pub fn capture() -> Self {
        Self {
            arguments: std::env::var_os("GNUNET_ARGS").map(|v| v.as_os_str().as_bytes().to_vec()),
            posixly_correct: std::env::var_os("POSIXLY_CORRECT").is_some(),
            logging: LogEnvironment::capture(),
        }
    }
}
/// Optional explicit defaults location for embedding and isolated tests. Native
/// mode performs the official project's installation/base-config discovery.
#[derive(Clone, Copy)]
pub enum Defaults<'a> {
    /// GNUNET_CONFIGURATION_load's normal process/installation selection.
    Native,
    /// An explicitly supplied defaults directory; None means no defaults files.
    Explicit(Option<&'a Path>),
}
/// Static invocation metadata, retaining source NULL-vs-present help semantics.
pub struct Invocation<'a> {
    /// PROGRAM's binaryName, used for parser usage and logging prefix.
    pub binary_name: &'a [u8],
    /// PROGRAM binaryHelp, including a possible source NULL value.
    pub help: Option<&'a [u8]>,
    /// False represents a project with either nullable config filename unset.
    /// ProjectData's nonoptional Vec fields otherwise represent present strings.
    pub select_default_filename: bool,
    /// Defaults discovery profile.
    pub defaults: Defaults<'a>,
}
/// Terminal preparation reason. None of these grants main-call authority.
#[derive(Debug)]
pub enum StoppedReason {
    /// GETOPT returned zero/help/version or a negative parser/callback failure.
    Options,
    /// Source log_setup failed, but PROGRAM still returns its positive GETOPT index.
    Logging(io::Error),
    /// Required selected config was not an existing regular file.
    Unreadable(PathBuf),
    /// Configuration loading failed; no partially loaded config escapes.
    Malformed(gnunet_config::Error),
}
/// Source integer return plus output and the exact reason main was not called.
#[derive(Debug)]
pub struct Stopped {
    /// Original PROGRAM return, including the positive log_setup failure quirk.
    pub code: i32,
    /// Parser diagnostics/output already emitted during preparation.
    pub output: Output<'static>,
    /// Explicit non-invocation reason.
    pub reason: StoppedReason,
}
/// A successfully prepared call. Consuming this owner releases configuration and
/// callback data only after the supplied task finishes.
pub struct Prepared {
    config: Configuration,
    arguments: Vec<Vec<u8>>,
    filename: Option<PathBuf>,
    output: Output<'static>,
}
/// Preparation preserves the source's early-stop return behavior without
/// confusing a positive return from failed logging with an executable main.
pub enum Preparation {
    /// May be passed to a direct/scheduled runtime.
    Ready(Box<Prepared>),
    /// Main must not be invoked.
    Stopped(Stopped),
}
/// Main's synchronous borrowed input. Retaining any field after main requires an
/// explicit owned copy; the configuration cannot be destroyed through this view.
#[derive(Clone, Copy)]
pub struct Main<'a> {
    /// Arguments after the final positive GETOPT index, including GNUNET_ARGS.
    pub arguments: &'a [Vec<u8>],
    /// Selected explicit/default configuration entrypoint or original NULL.
    pub filename: Option<&'a Path>,
    /// Prepared immutable configuration.
    pub config: &'a Configuration,
}
/// Actual resolver selection port. Implementations must own/retain the supplied
/// snapshot and reset the shared client's backoff without replacing existing MQ.
pub trait ResolverConnect {
    /// Execute the GNUNET_RESOLVER_connect read point before main.
    fn connect(&mut self, config: Configuration) -> Result<(), Failure>;
}
impl Prepared {
    /// Borrow the prepared source callback view without claiming invocation.
    #[must_use]
    pub fn main(&self) -> Main<'_> {
        Main {
            arguments: &self.arguments,
            filename: self.filename.as_deref(),
            config: &self.config,
        }
    }
    /// Parser bytes already emitted in the source startup order; retained for inspection.
    #[must_use]
    pub fn output(&self) -> &Output<'static> {
        &self.output
    }
    /// Take the observation of already emitted parser bytes exactly once.
    pub fn take_output(&mut self) -> Output<'static> {
        std::mem::take(&mut self.output)
    }
    /// Official run_without_scheduler path: no SPEEDUP start/stop, then resolver
    /// connect and one task call. The result 1 means the task actually returned.
    pub fn run_direct(
        self,
        resolver: &mut impl ResolverConnect,
        task: impl FnOnce(Main<'_>),
    ) -> Result<i32, Failure> {
        resolver.connect(self.config.duplicate()?)?;
        task(self.main());
        Ok(1)
    }
}
fn bytes(path: &Path) -> &[u8] {
    path.as_os_str().as_bytes()
}
fn prefix(v: &[u8]) -> &[u8] {
    &v[..v.iter().position(|&b| b == 0).unwrap_or(v.len())]
}
fn filename_target() -> Target<Filename> {
    Target::new(Filename {
        path: None,
        error: None,
    })
}
fn file_test(
    path: &Path,
    logger: &mut Logger<'_>,
    clock: &SharedClock,
    stderr: &mut impl Write,
) -> Result<bool, Failure> {
    Ok(crate::config_observer::operation(
        logger,
        clock,
        stderr,
        |observer| {
            Configuration::default().test_file(
                path,
                false,
                &gnunet_config::ProcessEnvironment,
                Some(observer),
            )
        },
    )??)
}
fn add_default<'a>(options: &mut Options<'a>, definition: getopt::Definition<'a>) {
    let candidate = &definition.spec;
    if !options
        .specs()
        .iter()
        .any(|s| (s.short != 0 && s.short == candidate.short) || s.name == candidate.name)
    {
        options.add(definition);
    }
}
fn program_log(
    logger: &mut Logger<'_>,
    level: Level,
    source_site: &'static str,
    body: Message<'_>,
    clock: &SharedClock,
    stderr: &mut impl Write,
) -> Result<(), Failure> {
    let translations = logger.translations();
    logger.source_lazy(
        source_site,
        level,
        CallSite {
            component: None,
            file: b"program.c",
            function: if source_site.starts_with("conf.") {
                b"GNUNET_PROGRAM_conf_and_options"
            } else {
                b"GNUNET_PROGRAM_run2"
            },
            line: match source_site {
                "run.unreadable.explicit" => 294,
                "run.unreadable.default" => 321,
                "run.malformed.explicit" => 306,
                "run.malformed.default" => 335,
                "run.load.explicit" => 288,
                "run.load.default" => 329,
                "conf.malformed.explicit" => 502,
                "conf.malformed.default" => 517,
                "conf.malformed.none" => 529,
                _ => 0,
            },
        },
        || body.render(translations.as_ref()),
        || Stamp::now(clock.offset().map_err(io::Error::other)?),
        stderr,
    )?;
    Ok(())
}
/// Prepare an already-created configuration. This makes configuration creation,
/// locale installation and option callbacks separately reviewable while retaining
/// their source order. No main, scheduler task, DNS or resolver socket is started.
#[expect(
    clippy::too_many_arguments,
    reason = "Explicit native initialization ports preserve caller ownership and the official startup read points"
)]
pub fn prepare<'a>(
    mut config: Configuration,
    invocation: Invocation<'a>,
    mut options: Options<'a>,
    arguments: impl IntoIterator<Item = OsString>,
    environment: &Environment,
    locale: &mut impl LocaleSetup,
    logger: &mut Logger<'_>,
    clock: &SharedClock,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<Preparation, Failure> {
    logger.bind_clock(clock.clone());
    // Keep project metadata independent of the config borrow across loading.
    let project = Arc::new(config.project_data().clone());
    if let Some(context) = locale.case_context() {
        config.set_case_context(context.clone());
        logger.set_case_context(context);
    }
    locale.configure(&project)?;
    let translations = locale.translations();
    logger.set_translations(std::rc::Rc::clone(&translations));
    let cfgfile = filename_target();
    let logfile = filename_target();
    let loglevel = Target::new(None);
    add_default(&mut options, helpers::cfgfile(cfgfile.clone()));
    for kind in *b"hv" {
        let (name, description) = if kind == b'h' {
            (b"help".as_slice(), b"print this help".as_slice())
        } else {
            (
                b"version".as_slice(),
                b"print the version number".as_slice(),
            )
        };
        if options
            .specs()
            .iter()
            .any(|s| (s.short != 0 && s.short == kind) || s.name == name)
        {
            continue;
        }
        let project = Arc::clone(&project);
        let about = invocation.help;
        let spec = getopt::Spec {
            short: kind,
            name,
            argument_help: if kind == b'h' { about } else { None },
            description: Some(description),
            argument: getopt::Argument::None,
            mandatory: false,
            exclusive: true,
        };
        options.push(
            spec,
            move |ctx: getopt::Context<'_>, name: &[u8], value: Option<&[u8]>, out: &mut Output| {
                let mut one = if kind == b'h' {
                    helpers::help(&project, about)
                } else {
                    helpers::version(&project.version)
                };
                one.process(ctx, name, value, out)
            },
        );
    }
    add_default(&mut options, helpers::loglevel(loglevel.clone()));
    add_default(&mut options, helpers::logfile(logfile.clone()));
    options.sort_program();
    let selected_default = if invocation.select_default_filename {
        crate::config_observer::operation(logger, clock, stderr, |observer| {
            project.default_filename_observed(&gnunet_config::ProcessEnvironment, Some(observer))
        })??
    } else {
        None
    };
    let arguments = arguments.into_iter().collect::<Vec<_>>();
    let arguments = getopt::append_environment(arguments, environment.arguments.as_deref());
    let mut parsed = crate::config_observer::operation(logger, clock, stderr, |observer| {
        Ok::<_, std::convert::Infallible>(options.run_translated_observed(
            invocation.binary_name,
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
    if parsed.code < 1 {
        return Ok(Preparation::Stopped(Stopped {
            code: parsed.code,
            output: parsed.output,
            reason: StoppedReason::Options,
        }));
    }
    let loglevel = loglevel.get()?;
    let logfile = logfile.get()?;
    let cfgfile = cfgfile.get()?;
    let component = prefix(invocation.binary_name)
        .split(|&b| b == b' ')
        .next()
        .unwrap_or_default();
    if let Err(error) = logger.setup_routed(
        component,
        loglevel.as_deref(),
        logfile.path.as_deref().map(bytes),
        &environment.logging,
        &Stamp::setup_now()?,
        stderr,
    ) {
        return Ok(Preparation::Stopped(Stopped {
            code: parsed.code,
            output: parsed.output,
            reason: StoppedReason::Logging(error),
        }));
    }
    let explicit = cfgfile.path.is_some();
    let filename = cfgfile.path.or(selected_default);
    if explicit {
        let mut body = b"Loading configuration from entry point specified as option (".to_vec();
        if let Some(path) = &filename {
            body.extend_from_slice(bytes(path));
        }
        body.extend_from_slice(b")\n");
        program_log(
            logger,
            Level::DEBUG,
            "run.load.explicit",
            Message::Literal(&body),
            clock,
            stderr,
        )?;
    }
    if let Some(path) = &filename
        && !file_test(path, logger, clock, stderr)?
    {
        program_log(
            logger,
            Level::ERROR,
            if explicit {
                "run.unreadable.explicit"
            } else {
                "run.unreadable.default"
            },
            Message::Translated {
                domain: Some(b"gnunet"),
                template: b"Unreadable configuration file `%s', exiting ...\n",
                arguments: &[Value::Bytes(bytes(path))],
            },
            clock,
            stderr,
        )?;
        return Ok(Preparation::Stopped(Stopped {
            code: -1,
            output: parsed.output,
            reason: StoppedReason::Unreadable(path.clone()),
        }));
    }
    if !explicit {
        // Source passes NULL to %s in this DEBUG-only notice. Rust preserves the
        // common observed literal safely; no undefined C comparison is executed.
        program_log(
            logger,
            Level::DEBUG,
            "run.load.default",
            Message::Literal(b"Loading configuration from entry point `(null)'\n"),
            clock,
            stderr,
        )?;
    }
    let load =
        crate::config_observer::operation(logger, clock, stderr, |observer| {
            match invocation.defaults {
                Defaults::Native => config.load_observed(filename.as_deref(), Some(observer)),
                Defaults::Explicit(directory) => {
                    config.load_explicit_observed(directory, filename.as_deref(), Some(observer))
                }
            }
        })?;
    if let Err(error) = load {
        let site = if explicit {
            "run.malformed.explicit"
        } else {
            "run.malformed.default"
        };
        if explicit {
            let path = filename
                .as_deref()
                .ok_or(gnunet_types::Error::InvalidInput)?;
            program_log(
                logger,
                Level::ERROR,
                site,
                Message::Translated {
                    domain: Some(b"gnunet"),
                    template: b"Malformed configuration file `%s', exiting ...\n",
                    arguments: &[Value::Bytes(bytes(path))],
                },
                clock,
                stderr,
            )?;
        } else {
            program_log(
                logger,
                Level::ERROR,
                site,
                Message::Translated {
                    domain: Some(b"gnunet"),
                    template: b"Malformed configuration. Exiting ...\n",
                    arguments: &[],
                },
                clock,
                stderr,
            )?;
        }
        return Ok(Preparation::Stopped(Stopped {
            code: -1,
            output: parsed.output,
            reason: StoppedReason::Malformed(error),
        }));
    }
    crate::config_observer::operation(logger, clock, stderr, |observer| {
        clock.testing_skew_observed(&config, Some(observer))
    })??;
    let have_arm_config = crate::config_observer::operation(logger, clock, stderr, |observer| {
        Ok::<_, std::convert::Infallible>(
            config
                .get_observed(b"arm", b"CONFIG", Some(observer))
                .is_some(),
        )
    })?
    .unwrap_or_else(|never| match never {});
    if !have_arm_config && let Some(path) = &filename {
        crate::config_observer::operation(logger, clock, stderr, |observer| {
            config.set_value_observed(b"arm", b"CONFIG", Some(bytes(path)), Some(observer))
        })??;
    }
    let remaining = parsed
        .remaining()
        .ok_or(gnunet_types::Error::InvalidInput)?
        .to_vec();
    Ok(Preparation::Ready(Box::new(Prepared {
        config,
        arguments: remaining,
        filename,
        output: parsed.output,
    })))
}

/// Successful conf_and_options ownership decomposition. The native function
/// leaks a newly created cfg on success; Rust returns that real owner instead.
pub struct ConfigurationReady {
    /// Caller-supplied or actually created configuration; provided cfg is not loaded.
    pub config: Configuration,
    /// True only when this call created the configuration after log setup.
    pub created: bool,
    /// Parsed -d flag. Source parses it but never daemonizes here.
    pub daemonize_requested: i32,
    /// Already emitted parser output retained for inspection.
    pub output: Output<'static>,
}
/// Source success/failure of conf_and_options, retaining safe cfg ownership.
pub enum ConfigurationPreparation {
    /// Original return1; caller owns the cfg even in the source's leaked case.
    Ready(Box<ConfigurationReady>),
    /// Original return-1, including help/version's original zero parser result.
    Stopped(Stopped),
}
/// Original service-oriented conf_and_options path: no GNUNET_ARGS, no option
/// sorting, forced DEBUG despite -L, and no reload when cfg was supplied. Errors
/// consume the supplied cfg just as source destroys it, without dangling aliases.
#[expect(
    clippy::too_many_arguments,
    reason = "The source operation has distinct project/cfg ownership and explicit startup diagnostic/clock ports"
)]
pub fn conf_and_options(
    project: Arc<ProjectData>,
    provided: Option<Configuration>,
    arguments: impl IntoIterator<Item = OsString>,
    defaults: Defaults<'_>,
    environment: &Environment,
    logger: &mut Logger<'_>,
    clock: &SharedClock,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<ConfigurationPreparation, Failure> {
    logger.bind_clock(clock.clone());
    let cfgfile = filename_target();
    let logfile = filename_target();
    let loglevel = Target::new(None);
    let daemonize = Target::new(0);
    let mut options = Options::new();
    options.add(helpers::cfgfile(cfgfile.clone()));
    options.add(helpers::flag(
        b'd',
        b"daemonize",
        b"do daemonize (detach from terminal)",
        daemonize.clone(),
    ));
    options.add(helpers::help(&project, None));
    options.add(helpers::loglevel(loglevel));
    options.add(helpers::logfile(logfile.clone()));
    options.add(helpers::version(&project.version));
    let default_filename = if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        let mut bytes = xdg.as_os_str().as_bytes().to_vec();
        bytes.push(b'/');
        bytes.extend_from_slice(&project.config_file);
        PathBuf::from(std::ffi::OsStr::from_bytes(&bytes))
    } else {
        PathBuf::from(std::ffi::OsStr::from_bytes(&project.user_config_file))
    };
    let translations = logger.translations();
    let mut parsed = crate::config_observer::operation(logger, clock, stderr, |observer| {
        Ok::<_, std::convert::Infallible>(options.run_translated_observed(
            b"libgnunet",
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
        clock.stop()?;
        return Ok(ConfigurationPreparation::Stopped(Stopped {
            code: -1,
            output: parsed.output,
            reason: StoppedReason::Options,
        }));
    }
    let logfile = logfile.get()?;
    if let Err(error) = logger.setup_routed(
        b"libgnunet",
        Some(b"DEBUG"),
        logfile.path.as_deref().map(bytes),
        &environment.logging,
        &Stamp::setup_now()?,
        stderr,
    ) {
        clock.stop()?;
        return Ok(ConfigurationPreparation::Stopped(Stopped {
            code: -1,
            output: parsed.output,
            reason: StoppedReason::Logging(error),
        }));
    }
    let created = provided.is_none();
    let config = if let Some(config) = provided {
        config
    } else {
        let mut config = Configuration::create(project, gnunet_config::Limits::default())?;
        let explicit = cfgfile.get()?.path;
        let main = if explicit.is_some() {
            explicit.as_deref()
        } else if file_test(&default_filename, logger, clock, stderr)? {
            Some(default_filename.as_path())
        } else {
            None
        };
        let load = if let Some(path) = explicit.as_deref()
            && !file_test(path, logger, clock, stderr)?
        {
            Err(gnunet_config::Error::Missing)
        } else {
            crate::config_observer::operation(logger, clock, stderr, |observer| match defaults {
                Defaults::Native => config.load_observed(main, Some(observer)),
                Defaults::Explicit(directory) => {
                    config.load_explicit_observed(directory, main, Some(observer))
                }
            })?
        };
        if let Err(error) = load {
            if let Some(path) = main {
                program_log(
                    logger,
                    Level::ERROR,
                    if explicit.is_some() {
                        "conf.malformed.explicit"
                    } else {
                        "conf.malformed.default"
                    },
                    Message::Translated {
                        domain: Some(b"gnunet"),
                        template: b"Malformed configuration file `%s', exit ...\n",
                        arguments: &[Value::Bytes(bytes(path))],
                    },
                    clock,
                    stderr,
                )?;
            } else {
                program_log(
                    logger,
                    Level::ERROR,
                    "conf.malformed.none",
                    Message::Translated {
                        domain: Some(b"gnunet"),
                        template: b"Malformed configuration, exit ...\n",
                        arguments: &[],
                    },
                    clock,
                    stderr,
                )?;
            }
            clock.stop()?;
            return Ok(ConfigurationPreparation::Stopped(Stopped {
                code: -1,
                output: parsed.output,
                reason: StoppedReason::Malformed(error),
            }));
        }
        config
    };
    Ok(ConfigurationPreparation::Ready(Box::new(
        ConfigurationReady {
            config,
            created,
            daemonize_requested: daemonize.get()?,
            output: parsed.output,
        },
    )))
}
