//! Persistent actual ARM owners and source CLI phase orchestration.
use crate::{
    diagnostics::Selection,
    options::Options,
    state::{Action, Kind, State},
};
use gnunet_arm_core::{
    FrameSlot,
    client::{
        Client, ConnectionStatus, Event, Inbound, OperationId, OperationSlot, StdioInheritance,
    },
    monitor::Monitor,
    wire::{ArmAbi, ServiceInfo},
};
use gnunet_arm_host::{
    ChildRegistry, ClientHost, Clock, LaunchLimits, Limits, LocalLauncher, MonitorEvent,
    MonitorHost,
};
use gnunet_config::{Configuration, ProcessEnvironment, ProjectData};
use std::{
    error::Error,
    ffi::{OsStr, OsString},
    future::{Future, poll_fn},
    io::{self, Write},
    os::unix::{ffi::OsStrExt, fs::PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    task::Poll,
    time::Duration,
};
use tokio::time::Instant;
type Result<T> = std::result::Result<T, Box<dyn Error>>;
/// Explicit auxiliary deployment and actual C ABI profile. No private argv or
/// GNUnet configuration option is introduced for this Rust helper port.
#[derive(Clone, Debug)]
pub struct Ports {
    /// Explicit reviewed fresh-helper executable.
    pub helper: PathBuf,
    /// Actual native C struct alignment profile.
    pub abi: ArmAbi,
}
impl Ports {
    /// Resolve the reviewed native deployment. A colocated Rust helper is preferred
    /// for this standalone candidate; formal ProjectData libexec discovery is used
    /// otherwise. Untested align4 native ABIs are not guessed from pointer width.
    pub fn native() -> Result<Self> {
        if std::mem::align_of::<u64>() != 8 {
            return Err(
                "untested native ARM ABI; supply an explicit validated Ports profile".into(),
            );
        }
        let executable = std::env::current_exe()?;
        let sibling = executable
            .parent()
            .ok_or("no executable directory")?
            .join("gnunet-arm-spawn-helper");
        let helper = if sibling.is_file() {
            sibling
        } else {
            ProjectData::default().libexec_binary_path(b"gnunet-arm-spawn-helper")?
        };
        Ok(Self {
            helper,
            abi: ArmAbi::U64Align8,
        })
    }
}
// Exact native owners survive future cancellation. Drop does not kill/reap a
// launched service; the caller's original ChildRegistry retains that authority.
struct ControlOwner<'a, 'r> {
    inner: ClientHost<'a, 'r>,
    logs: Selection,
    closed: bool,
}
impl<'a, 'r> std::ops::Deref for ControlOwner<'a, 'r> {
    type Target = ClientHost<'a, 'r>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
impl std::ops::DerefMut for ControlOwner<'_, '_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
impl ControlOwner<'_, '_> {
    fn close(&mut self) -> std::result::Result<(), gnunet_arm_host::HostError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        self.inner.disconnect(|_, _| {})
    }
}
impl Drop for ControlOwner<'_, '_> {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            self.logs.retain_cleanup(error);
        }
    }
}
struct MonitorOwner<'a> {
    inner: MonitorHost<'a>,
    closed: bool,
}
impl<'a> std::ops::Deref for MonitorOwner<'a> {
    type Target = MonitorHost<'a>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
impl std::ops::DerefMut for MonitorOwner<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
impl MonitorOwner<'_> {
    fn close(&mut self) {
        if !self.closed {
            self.closed = true;
            self.inner.stop();
        }
    }
}
impl Drop for MonitorOwner<'_> {
    fn drop(&mut self) {
        self.close();
    }
}
#[derive(Debug, Default)]
struct OutputErrors {
    stdout: Option<io::Error>,
    stderr: Option<io::Error>,
    stdout_flush: Option<io::Error>,
    stderr_flush: Option<io::Error>,
}
impl std::fmt::Display for OutputErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ARM CLI output stdout={:?}; stderr={:?}; stdout-flush={:?}; stderr-flush={:?}",
            self.stdout, self.stderr, self.stdout_flush, self.stderr_flush
        )
    }
}
impl Error for OutputErrors {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.stdout
            .as_ref()
            .or(self.stderr.as_ref())
            .or(self.stdout_flush.as_ref())
            .or(self.stderr_flush.as_ref())
            .map(|e| e as &dyn Error)
    }
}
fn emit(
    state: &mut State,
    out: &mut impl Write,
    err: &mut impl Write,
    logs: &Selection,
) -> Result<()> {
    // A failed write_all can have exposed a prefix. Clear each original buffer
    // immediately after its attempt, before any fallible return; cleanup never
    // replays bytes and the bounded allocation is reused on the next callback.
    let stdout = out.write_all(&state.stdout).err();
    state.stdout.clear();
    let stderr = err.write_all(&state.stderr).err();
    state.stderr.clear();
    let mut errors = OutputErrors {
        stdout,
        stderr,
        ..Default::default()
    };
    for warning in state.warnings.drain(..) {
        logs.warning("arm.cli.action_loop", &warning);
    }
    errors.stdout_flush = out.flush().err();
    errors.stderr_flush = err.flush().err();
    if errors.stdout.is_none()
        && errors.stderr.is_none()
        && errors.stdout_flush.is_none()
        && errors.stderr_flush.is_none()
    {
        Ok(())
    } else {
        Err(Box::new(errors))
    }
}
/// Load the actual PROGRAM entrypoint/defaults and arm.CONFIG fallback. No home,
/// config or endpoint is created or removed by configuration preparation.
pub fn configuration(options: &Options) -> Result<Configuration> {
    let mut config = Configuration::default();
    let path = if let Some(value) = &options.config {
        Some(config.expand_filename(value, &ProcessEnvironment)?)
    } else {
        ProjectData::default().default_filename(&ProcessEnvironment)?
    };
    if let Some(path) = &path
        && !std::fs::metadata(path).is_ok_and(|m| m.is_file())
    {
        return Err(io::Error::other(format!(
            "Unreadable configuration file `{}`",
            path.display()
        ))
        .into());
    }
    config.load(path.as_deref())?;
    if !config.have_value(b"arm", b"CONFIG")
        && let Some(path) = path
    {
        config.set_value(b"arm", b"CONFIG", Some(path.as_os_str().as_bytes()))?;
    }
    Ok(config)
}
/// Original disk remove semantics: chmod700 (including symlink target), unlink
/// first, then recursively remove a directory. Test paths must be owned tmp.
fn remove_tree(path: &Path) -> io::Result<bool> {
    if std::fs::symlink_metadata(path).is_err() {
        return Ok(false);
    }
    drop(std::fs::set_permissions(
        path,
        std::fs::Permissions::from_mode(0o700),
    ));
    if std::fs::remove_file(path).is_ok() {
        return Ok(true);
    }
    if !std::fs::metadata(path)?.is_dir() {
        return Err(io::Error::other("not a removable directory"));
    }
    for entry in std::fs::read_dir(path)? {
        remove_tree(&entry?.path())?;
    }
    std::fs::remove_dir(path)?;
    Ok(true)
}
fn delete_files(config: &Configuration, state: &State, logs: &Selection) {
    if !state.should_delete() {
        return;
    }
    logs.reporter().debug(
        "arm.cli.delete",
        format_args!("Will attempt to remove original ARM configuration and service directory"),
    );
    if logs.reporter().failed() {
        return;
    }
    if let Ok(path) = config.get_filename(b"arm", b"CONFIG", &ProcessEnvironment)
        && std::fs::remove_file(&path).is_err()
    {
        let mut warning = b"Failed to remove configuration file ".to_vec();
        warning.extend_from_slice(path.as_os_str().as_bytes());
        warning.push(b'\n');
        logs.warning("arm.cli.delete.config", &warning);
    }
    if logs.reporter().failed() {
        return;
    }
    if let Some(dir) = config.get(b"PATHS", b"GNUNET_HOME")
        && !remove_tree(Path::new(OsStr::from_bytes(dir))).unwrap_or(false)
    {
        let mut warning = b"Failed to remove servicehome directory ".to_vec();
        warning.extend_from_slice(dir);
        warning.push(b'\n');
        logs.warning("arm.cli.delete.directory", &warning);
    }
}
/// Original caller-selected command and actual shared diagnostic/clock owners.
/// Resolver must use this exact source; no default runtime or task is installed.
pub struct Invocation {
    /// Original loaded configuration, including explicit arm.CONFIG fallback.
    pub config: Configuration,
    /// Original source CLI business/options state.
    pub options: Options,
    /// Actual reviewed helper/ABI deployment.
    pub ports: Ports,
    /// One already selected native Logger/clock, reused through final cleanup.
    pub diagnostics: Selection,
}
#[derive(Debug, Default)]
struct Failures {
    original: Option<Box<dyn Error>>,
    outcome: Option<Box<dyn Error>>,
    clock: Option<gnunet_types::Error>,
    output: Option<Box<dyn Error>>,
    callback: Option<Box<dyn Error>>,
    cancel: Option<gnunet_arm_host::HostError>,
    disconnect: Option<gnunet_arm_host::HostError>,
    resolver: Option<Box<dyn Error>>,
}
impl std::fmt::Display for Failures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ARM CLI original={:?}; outcome={:?}; clock={:?}; final-output={:?}; callback={:?}; cancel={:?}; disconnect={:?}; Resolver cleanup={:?}",
            self.original,
            self.outcome,
            self.clock,
            self.output,
            self.callback,
            self.cancel,
            self.disconnect,
            self.resolver
        )
    }
}
impl Error for Failures {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.clock
            .as_ref()
            .map(|e| e as &dyn Error)
            .or(self.original.as_deref())
            .or(self.outcome.as_deref())
            .or(self.output.as_deref())
            .or(self.callback.as_deref())
            .or(self.cancel.as_ref().map(|e| e as &dyn Error))
            .or(self.disconnect.as_ref().map(|e| e as &dyn Error))
            .or(self.resolver.as_deref())
    }
}
impl Failures {
    fn finish(self, code: u8) -> Result<u8> {
        if self.original.is_none()
            && self.outcome.is_none()
            && self.clock.is_none()
            && self.output.is_none()
            && self.callback.is_none()
            && self.cancel.is_none()
            && self.disconnect.is_none()
            && self.resolver.is_none()
        {
            Ok(code)
        } else {
            Err(Box::new(self))
        }
    }
}
/// Execute source CLI behavior using original caller-owned process wait authority.
/// Returning leaves the same registry available to the embedding caller. The
/// standalone CLI retains it until process exit; live services are never killed
/// or synchronously waited just because this command finishes.
pub async fn run<const R: usize, const N: usize>(
    input: Invocation,
    resolver_driver: &mut gnunet_resolver_broker::Driver<R, N>,
    registry: &mut ChildRegistry,
    out: &mut impl Write,
    err: &mut impl Write,
) -> Result<u8> {
    let Invocation {
        config,
        options,
        ports,
        diagnostics: logs,
    } = input;
    let reports = logs.reporter().clone();
    let resolver = resolver_driver.context().resolution_context();
    if !Arc::ptr_eq(&logs.source(), &resolver.clock()) {
        return Err("ARM CLI Resolver must retain the selected original clock".into());
    }
    let mut state = State::new(options);
    if reports.failed() {
        return logs.finish(Err(
            "selected ARM Logger is permanently failed; original cause may be held by caller"
                .into(),
        ));
    }
    if config.get(b"PATHS", b"GNUNET_HOME").is_none() {
        reports.message_bytes(
            gnunet_program_host::policy::Level::ERROR,
            "arm.cli.config.missing",
            b"Missing configuration value [PATHS] GNUNET_HOME\n",
        );
        return logs.finish(Ok(0));
    }
    let mut operations = [OperationSlot::EMPTY; 4];
    let mut frames = [FrameSlot::EMPTY; 16];
    let mut bytes = vec![0; 2 * 65535];
    let mut mframes = [FrameSlot::EMPTY; 2];
    let mut mpool = [0; 16];
    // Establish caller-buffer loans before a future can move the monitor into
    // its original owner; no native or self-referential loan is constructed.
    let mut monitor_core = if state.options.monitor {
        Some(Monitor::new(&mut mframes, &mut mpool, 2)?)
    } else {
        None
    };
    let core = Client::new(&mut operations, &mut frames, &mut bytes, 1, ports.abi)?;
    let launcher = LocalLauncher::new(
        config.duplicate()?,
        ports.helper,
        LaunchLimits::default(),
        registry,
    )?;
    let mut initial_error = false;
    let mut host = match ClientHost::connect(
        core,
        config.duplicate()?,
        resolver.clone(),
        launcher,
        Limits::default(),
        Clock::new(logs.source())?,
        |status| initial_error = status == ConnectionStatus::Error,
    ) {
        Ok(host) => ControlOwner {
            inner: host,
            logs: logs.clone(),
            closed: false,
        },
        Err(error) => {
            if initial_error {
                reports.message_bytes(
                    gnunet_program_host::policy::Level::ERROR,
                    "arm.cli.conn_status",
                    b"Fatal error initializing ARM API.\n",
                );
            }
            reports.debug(
                "arm.cli.connect.failed",
                format_args!("Original ARM host initialization: {error}"),
            );
            logs.initial_control(error);
            // Source conn_status/failed initial connect does not change ret0.
            // A concurrent logging failure still returns both real causes.
            return logs.finish(Ok(0));
        }
    };
    let mut failures = Failures::default();
    let mut monitor = None;
    let mut active: Option<(OperationId, Kind)> = None;
    let outcome: Result<()> = async {
        monitor = if let Some(core) = monitor_core.take() {
            let mut unavailable = false;
            match MonitorHost::start(
                core,
                config.duplicate()?,
                resolver.clone(),
                Limits::default(),
                Clock::new(logs.source())?,
                |_| unavailable = true,
            ) {
                Ok(m) => Some(MonitorOwner {
                    inner: m,
                    closed: false,
                }),
                Err(error) => {
                    if unavailable {
                        state.monitor(b"(null)", 1);
                    }
                    reports.debug(
                        "arm.cli.monitor.failed",
                        format_args!("Original ARM monitor initialization: {error}"),
                    );
                    logs.initial_monitor(error);
                    None
                }
            }
        } else {
            None
        };
        let deadline = if state.options.timeout == 0 || state.options.timeout == u64::MAX {
            None
        } else {
            Some(
                Instant::now()
                    .checked_add(Duration::from_micros(state.options.timeout))
                    .ok_or("timeout overflow")?,
            )
        };
        let mut alarm = deadline.map(|at| Box::pin(tokio::time::sleep_until(at)));
        let mut interrupt =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let mut hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
        let mut quit = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::quit())?;
        // The official scheduler catches SIGPIPE with a no-op handler. Installing
        // this port also ensures a launched child's caught disposition becomes DFL
        // at native exec, instead of inheriting Rust entry's default IGN behavior.
        let mut pipe = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::pipe())?;
        let mut once = false;
        let mut first = true;
        let mut prefer_monitor = false;
        loop {
            if reports.failed() {
                break;
            }
            if !first && deadline.is_some_and(|at| Instant::now() >= at) {
                state.timeout();
            }
            first = false;
            if state.done {
                break;
            }
            if let Some(action) = state.next(|| {
                matches!(
                    gnunet_client_host::presence::test(&config, b"arm"),
                    Ok(gnunet_client_host::presence::ServicePresence::LikelyUp)
                )
            }) {
                match action {
                    Action::Stop(service, kind) => {
                        active = Some((host.request_service_stop(&service)?, kind))
                    }
                    Action::Start(service, stdio, kind) => {
                        active = Some((
                            host.request_service_start(&service, StdioInheritance(stdio))?,
                            kind,
                        ))
                    }
                    Action::List => active = Some((host.request_service_list()?, Kind::List)),
                    Action::Finish => {}
                    Action::MonitorOnly => {}
                }
            }
            emit(&mut state, out, err, &logs)?;
            if state.done || reports.failed() {
                break;
            }
            let mut callback_error = None;
            {
                let mut control = Box::pin(host.drive(None, |inbound, _port| match inbound {
                    Inbound::Event(Event::Connection(status)) => {
                        if status == ConnectionStatus::Error && !once {
                            reports.message_bytes(
                                gnunet_program_host::policy::Level::ERROR,
                                "arm.cli.conn_status",
                                b"Fatal error initializing ARM API.\n",
                            );
                            state.done = true;
                        }
                        once = true;
                    }
                    Inbound::Event(Event::Result {
                        operation,
                        status,
                        result,
                    }) => match active.take() {
                        Some((expected, kind)) if expected == operation => {
                            state.result(kind, status, result)
                        }
                        _ => callback_error = Some("wrong original ARM operation"),
                    },
                    Inbound::Event(Event::ListDisconnected { operation }) => match active.take() {
                        Some((expected, Kind::List)) if expected == operation => {
                            state.list_disconnected()
                        }
                        _ => callback_error = Some("wrong original ARM list operation"),
                    },
                    Inbound::List { operation, list } => match active.take() {
                        Some((expected, Kind::List)) if expected == operation => {
                            let rows = (0..list.len())
                                .map(|i| list.get(i))
                                .collect::<std::result::Result<Vec<_>, _>>();
                            match rows {
                                Ok(rows) => {
                                    let rows: Vec<ServiceInfo<'_>> =
                                        rows.into_iter().flatten().collect();
                                    match logs.clock().sample() {
                                        Ok(sample) => state.list(&rows, sample.now.as_micros()),
                                        Err(error) => {
                                            failures.clock = Some(error);
                                            state.done = true;
                                            state.ret = 1;
                                        }
                                    }
                                }
                                Err(_) => callback_error = Some("invalid checked ARM list"),
                            }
                        }
                        _ => callback_error = Some("wrong original ARM list operation"),
                    },
                }));
                // Disjoint status staging prevents simultaneously borrowing State through two
                // live closures. Monitor bytes are copied only until this callback completes.
                let mut statuses: Vec<(Vec<u8>, u32)> = Vec::new();
                let mut monitoring = monitor.as_mut().map(|monitor| {
                    Box::pin(monitor.drive(None, |event, _| match event {
                        MonitorEvent::Status(status) => {
                            statuses.push((status.service.to_vec(), status.status.0))
                        }
                        MonitorEvent::Unavailable(_) => statuses.push((b"(null)".to_vec(), 1)),
                    }))
                });
                let mut resolving = Box::pin(resolver_driver.drive_waiting(None, |event| {
                    reports.debug(
                        "arm.cli.resolver",
                        format_args!("ARM CLI Resolver={event:?}"),
                    );
                }));
                let progress = poll_fn(|cx| {
                    reports.register(cx);
                    if reports.failed() {
                        return Poll::Ready(Ok(6u8));
                    }
                    if let Some(alarm) = &mut alarm
                        && alarm.as_mut().poll(cx).is_ready()
                    {
                        return Poll::Ready(Ok(2u8));
                    }
                    if interrupt.poll_recv(cx).is_ready()
                        || terminate.poll_recv(cx).is_ready()
                        || hangup.poll_recv(cx).is_ready()
                        || quit.poll_recv(cx).is_ready()
                    {
                        return Poll::Ready(Ok(3u8));
                    }
                    if let Poll::Ready(Some(())) = pipe.poll_recv(cx) {
                        return Poll::Ready(Ok(4u8));
                    }
                    if prefer_monitor
                        && let Some(monitor) = &mut monitoring
                        && let Poll::Ready(result) = monitor.as_mut().poll(cx)
                    {
                        return Poll::Ready(result.map(|_| 1));
                    }
                    if reports.failed() {
                        return Poll::Ready(Ok(6u8));
                    }
                    if let Poll::Ready(result) = control.as_mut().poll(cx) {
                        return Poll::Ready(result.map(|_| 0));
                    }
                    if reports.failed() {
                        return Poll::Ready(Ok(6u8));
                    }
                    if !prefer_monitor
                        && let Some(monitor) = &mut monitoring
                        && let Poll::Ready(result) = monitor.as_mut().poll(cx)
                    {
                        return Poll::Ready(result.map(|_| 1));
                    }
                    if reports.failed() {
                        return Poll::Ready(Ok(6u8));
                    }
                    if let Poll::Ready(result) = resolving.as_mut().poll(cx) {
                        return Poll::Ready(
                            result
                                .map(|_| 5)
                                .map_err(|e| gnunet_arm_host::HostError::Io(io::Error::other(e))),
                        );
                    }
                    Poll::Pending
                })
                .await;
                drop(control);
                drop(monitoring);
                for (service, status) in statuses {
                    state.monitor(&service, status);
                }
                match progress {
                    Ok(2) => state.timeout(),
                    Ok(3 | 6) => state.done = true,
                    Ok(which) => prefer_monitor = which == 0,
                    Err(error) => {
                        logs.error(
                            "arm.cli.native.failed",
                            format_args!("Original ARM native boundary: {error}"),
                        );
                        failures.original = Some(Box::new(error));
                        state.done = true;
                        state.ret = 1;
                    }
                }
            }
            emit(&mut state, out, err, &logs)?;
            if let Some(message) = callback_error {
                logs.error("arm.cli.callback.failed", format_args!("{message}"));
                failures.callback = Some(message.into());
                state.done = true;
                state.ret = 1;
            }
            if failures.original.is_some() || failures.clock.is_some() {
                state.done = true;
                state.ret = 1;
            }
        }
        Ok(())
    }
    .await;
    failures.outcome = outcome.err();
    // The exact original operation/source closes even when logging or another
    // provider failed. Cancellation does not kill/reap an already launched ARM.
    if let Some((id, _)) = active
        && host.owns_operation(id)
    {
        failures.cancel = host.operation_cancel(id).err();
    }
    failures.disconnect = host.close().err();
    if let Some(monitor) = &mut monitor {
        monitor.close();
    }
    drop(monitor);
    drop(host);
    failures.output = emit(&mut state, out, err, &logs).err();
    // Preserve the actual source -d condition; a logging failure must not start
    // new destructive file work after its permanent gate has closed.
    if !reports.failed() {
        delete_files(&config, &state, &logs);
    }
    logs.finish(failures.finish(state.ret))
}
/// Standalone source argv entry, using real selected PROGRAM logging while
/// retaining the source ARM-specific parser, business phases and status bytes.
pub fn main_from(args: impl IntoIterator<Item = OsString>) -> u8 {
    let parsed = crate::options::parse(
        args,
        std::env::var_os("GNUNET_ARGS").as_deref(),
        std::env::var_os("POSIXLY_CORRECT").is_some(),
        b"0.29.1",
    );
    // Immediate parser/help/version output precedes logging/file/runtime setup,
    // matching PROGRAM's early-exit boundary. No product path runs after it.
    if io::stdout()
        .write_all(&parsed.stdout)
        .and_then(|()| io::stdout().flush())
        .is_err()
        || io::stderr()
            .write_all(&parsed.stderr)
            .and_then(|()| io::stderr().flush())
            .is_err()
    {
        return 255;
    }
    if let Some(code) = parsed.exit {
        return code;
    }
    let clock = match gnunet_program_host::shared_clock::SharedClock::native(128) {
        Ok(clock) => clock,
        Err(error) => {
            let _original = writeln!(io::stderr(), "gnunet-arm logging clock: {error}");
            return 255;
        }
    };
    let logs = match Selection::new(
        &parsed.options,
        clock,
        &gnunet_program_host::logging::Environment::capture(),
        &mut io::stderr(),
    ) {
        Ok(logs) => logs,
        Err(error) => {
            // Selected setup did not succeed. Bootstrap diagnostics stay on the
            // original stderr, never a fake substitute for an established sink.
            let _original = writeln!(io::stderr(), "gnunet-arm logging setup: {error}");
            return 255;
        }
    };
    let config = match configuration(&parsed.options) {
        Ok(config) => config,
        Err(error) => {
            logs.error("arm.cli.configuration.failed", format_args!("{error}"));
            let _original = logs.finish::<()>(Err(error));
            return 255;
        }
    };
    if let Err(error) = logs.clock().testing_skew(&config) {
        logs.error("arm.cli.clock.failed", format_args!("{error}"));
        let _original = logs.finish::<()>(Err(Box::new(error)));
        return 1;
    }
    let ports = match Ports::native() {
        Ok(ports) => ports,
        Err(error) => {
            logs.error("arm.cli.deployment.failed", format_args!("{error}"));
            let _original = logs.finish::<()>(Err(error));
            return 1;
        }
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            logs.error("arm.cli.runtime.failed", format_args!("{error}"));
            let _original = logs.finish::<()>(Err(Box::new(error)));
            return 1;
        }
    };
    let mut registry = match ChildRegistry::new(64) {
        Ok(registry) => registry,
        Err(error) => {
            logs.error("arm.cli.children.failed", format_args!("{error}"));
            let _original = logs.finish::<()>(Err(Box::new(error)));
            return 1;
        }
    };
    let result: Result<u8> = runtime.block_on(async {
        if logs.reporter().failed() {
            return logs.finish(Ok(1));
        }
        let (context, mut resolver_driver) = gnunet_resolver_broker::broker::<8, 65518>(
            gnunet_resolver_broker::LiveConfiguration::new(config.duplicate()?),
            Default::default(),
            gnunet_resolver_broker::native_profile()?,
            logs.source(),
        )?;
        let original: Result<u8> = async {
            context.connect(config.duplicate()?)?;
            run(
                Invocation {
                    config,
                    options: parsed.options,
                    ports,
                    diagnostics: logs.clone(),
                },
                &mut resolver_driver,
                &mut registry,
                &mut io::stdout(),
                &mut io::stderr(),
            )
            .await
        }
        .await;
        let resolver = resolver_driver.disconnect();
        drop(context);
        match resolver {
            Ok(()) => original,
            Err(error) => Err(Box::new(Failures {
                original: original.err(),
                resolver: Some(Box::new(error)),
                ..Default::default()
            })),
        }
    });
    if let Err(error) = &result {
        logs.error("arm.cli.failed", format_args!("gnunet-arm: {error}"));
    }
    logs.finish(result).unwrap_or(1)
}
