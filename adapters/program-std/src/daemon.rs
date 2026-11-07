//! Explicit registration owner for PROGRAM's DAEMON/monolith helper operations.
//! These callbacks are in-process tasks; no process, service or detached task is
//! started by registration. New registrations retain source newest-first order.
use crate::{
    logging::Logger,
    program::{self, ConfigurationPreparation, Defaults, Environment, Failure, Stopped},
    runtime::{Scope, TaskId, Work},
    shared_clock::SharedClock,
};
use gnunet_config::{Configuration, ProjectData};
use gnunet_types::Error;
use std::{cell::RefCell, ffi::OsString, io::Write, rc::Rc, sync::Arc};
/// Actual DAEMON callback inputs. Source always supplies NULL args/cfgfile;
/// configuration can also be NULL in its cfg==NULL ownership-leak path.
#[derive(Clone, Copy)]
pub struct Main<'a> {
    /// Original nullable config; never silently replaced with the leaked new cfg.
    pub config: Option<&'a Configuration>,
}
type Callback<'a> = Rc<RefCell<Box<dyn for<'b> FnMut(Main<'b>) + 'a>>>;
struct Registration<'a> {
    name: Vec<u8>,
    callback: Callback<'a>,
}
struct State<'a> {
    limit: usize,
    registrations: Vec<Registration<'a>>,
    closed: bool,
}
/// Restricted registration authority. It can be captured by a daemon callback:
/// registering there affects the next launch, exactly as the source global DLL.
/// It owns no scheduler, config, socket or thread. Dropping Registry retires it.
pub struct Context<'a> {
    state: Rc<RefCell<State<'a>>>,
}
impl Clone for Context<'_> {
    fn clone(&self) -> Self {
        Self {
            state: Rc::clone(&self.state),
        }
    }
}
impl<'a> Context<'a> {
    /// Source registration from ordinary code or a currently running callback.
    /// No callback is invoked here. Help remains unused by the official body.
    pub fn register(
        &self,
        name: &[u8],
        _help: &[u8],
        callback: impl for<'b> FnMut(Main<'b>) + 'a,
    ) -> Result<i32, Error> {
        let mut state = self.state.borrow_mut();
        if state.closed {
            return Err(Error::Closed);
        }
        if state.registrations.len() >= state.limit {
            return Err(Error::Capacity);
        }
        state
            .registrations
            .try_reserve(1)
            .map_err(|_| Error::Capacity)?;
        let name = prefix(name);
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(name.len())
            .map_err(|_| Error::Capacity)?;
        owned.extend_from_slice(name);
        state.registrations.insert(
            0,
            Registration {
                name: owned,
                callback: Rc::new(RefCell::new(Box::new(callback))),
            },
        );
        Ok(1)
    }
    /// Registration with the same source diagnostic as Registry::register_logged.
    pub fn register_logged(
        &self,
        name: &[u8],
        help: &[u8],
        callback: impl for<'b> FnMut(Main<'b>) + 'a,
        diagnostics: &mut impl Diagnostics,
    ) -> Result<i32, Failure> {
        diagnostics.notice(Notice::Register(name))?;
        Ok(self.register(name, help, callback)?)
    }
}
/// Caller-owned counterpart of source's global registration DLL. The owner is
/// unique; cloned Context ports share its registration state, never closures.
pub struct Registry<'a> {
    state: Rc<RefCell<State<'a>>>,
}
impl<'a> Registry<'a> {
    /// Empty bounded owner, without IO or a hidden scheduler task.
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            state: Rc::new(RefCell::new(State {
                limit,
                registrations: Vec::new(),
                closed: false,
            })),
        }
    }
    /// Restricted same-owner registration capability, valid until owner Drop.
    #[must_use]
    pub fn context(&self) -> Context<'a> {
        Context {
            state: Rc::clone(&self.state),
        }
    }
    /// GNUNET_DAEMON_register; the closure remains registered for later launches.
    pub fn register(
        &mut self,
        name: &[u8],
        help: &[u8],
        callback: impl for<'b> FnMut(Main<'b>) + 'a,
    ) -> Result<i32, Error> {
        self.context().register(name, help, callback)
    }
    fn snapshot(&self) -> Result<Vec<Registration<'a>>, Error> {
        let state = self.state.borrow();
        if state.closed {
            return Err(Error::Closed);
        }
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(state.registrations.len())
            .map_err(|_| Error::Capacity)?;
        for entry in &state.registrations {
            entries.push(Registration {
                name: entry.name.clone(),
                callback: Rc::clone(&entry.callback),
            });
        }
        Ok(entries)
    }
    fn admit<'b>(
        &'b self,
        entries: Vec<Registration<'a>>,
        config: Option<&'b Configuration>,
        scope: &Scope<'b>,
    ) -> Result<Launch, Error> {
        let mut names = Vec::new();
        names
            .try_reserve_exact(entries.len())
            .map_err(|_| Error::Capacity)?;
        let mut works: Vec<Work<'b>> = Vec::new();
        works
            .try_reserve_exact(entries.len())
            .map_err(|_| Error::Capacity)?;
        for entry in entries {
            names.push(entry.name);
            let callback = entry.callback;
            let state = Rc::clone(&self.state);
            works.push(Box::pin(async move {
                let closed = state.borrow().closed;
                if !closed {
                    // State is not borrowed while synchronous user code runs.
                    // The private callback cell is never lent through Context.
                    (callback.borrow_mut())(Main { config });
                }
            }));
        }
        let tasks = scope.batch(works)?;
        Ok(Launch { names, tasks })
    }
    /// Snapshot the current newest-first DLL and admit its whole callback batch.
    /// Callback-time registrations affect the next launch, never this snapshot.
    pub fn launch<'b>(
        &'b mut self,
        config: Option<&'b Configuration>,
        scope: &Scope<'b>,
    ) -> Result<Launch, Error> {
        self.admit(self.snapshot()?, config, scope)
    }
}
impl Drop for Registry<'_> {
    fn drop(&mut self) {
        let registrations = {
            let mut state = self.state.borrow_mut();
            state.closed = true;
            std::mem::take(&mut state.registrations)
        };
        // User-owned closure destructors may use a retired Context; no shared
        // RefCell borrow spans their execution and no new registration succeeds.
        drop(registrations);
    }
}
/// Actually admitted launch batch; no callback completion is inferred from it.
pub struct Launch {
    /// Source newest-first diagnostic names.
    pub names: Vec<Vec<u8>>,
    /// Original scheduler task ownership, for explicit cancellation if required.
    pub tasks: Vec<TaskId>,
}
/// Prepared daemon helper owner. In the source cfg==NULL case, the allocated cfg
/// is retained for cleanup but callbacks still receive NULL; no pointer is leaked.
pub struct Prepared {
    config: Configuration,
    callback_has_config: bool,
}
impl Prepared {
    /// Original configuration view for Service_main/DAEMON callbacks.
    #[must_use]
    pub fn callback_config(&self) -> Option<&Configuration> {
        self.callback_has_config.then_some(&self.config)
    }
    /// Retained safe owner, including the otherwise unreachable cfg allocated by C.
    #[must_use]
    pub fn retained_configuration(&self) -> &Configuration {
        &self.config
    }
    /// Recover the real owned configuration after all borrowed scoped launches
    /// have returned. In the source NULL path this safely recovers the otherwise
    /// leaked handle; it does not change callback_config's nullable semantics.
    #[must_use]
    pub fn into_configuration(self) -> Configuration {
        self.config
    }
}
/// Distinct conf_and_options result; source helper returns void after failure.
pub enum Preparation {
    /// May launch callbacks with original nullable configuration semantics.
    Ready(Box<Prepared>),
    /// Source preparation failed and no service/daemon main may be called.
    Stopped(Stopped),
}
/// Prepare the with_scheduler=true DAEMON path. Source cfg ownership is
/// consumed, no task runs, and the parsed -d option still does not daemonize.
#[expect(
    clippy::too_many_arguments,
    reason = "The helper preserves project/cfg ownership and explicit native initialization ports"
)]
pub fn prepare(
    project: Arc<ProjectData>,
    config: Option<Configuration>,
    arguments: impl IntoIterator<Item = OsString>,
    defaults: Defaults<'_>,
    environment: &Environment,
    logger: &mut Logger<'_>,
    clock: &SharedClock,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<Preparation, Failure> {
    LoggingDiagnostics {
        logger,
        clock,
        stderr,
    }
    .notice(Notice::Enter)?;
    let callback_has_config = config.is_some();
    Ok(
        match program::conf_and_options(
            project,
            config,
            arguments,
            defaults,
            environment,
            logger,
            clock,
            stdout,
            stderr,
        )? {
            ConfigurationPreparation::Ready(ready) => Preparation::Ready(Box::new(Prepared {
                config: ready.config,
                callback_has_config,
            })),
            ConfigurationPreparation::Stopped(stopped) => Preparation::Stopped(stopped),
        },
    )
}
/// Source PROGRAM_monolith_main preparation: parse/configure first, without
/// entering DAEMON_main. Service registration and the sole DAEMON Enter happen
/// only inside the successfully prepared monolith scheduler scope.
#[expect(
    clippy::too_many_arguments,
    reason = "Explicit native ports and consumed original config preserve monolith startup ordering"
)]
pub fn prepare_monolith(
    project: Arc<ProjectData>,
    config: Option<Configuration>,
    arguments: impl IntoIterator<Item = OsString>,
    defaults: Defaults<'_>,
    environment: &Environment,
    logger: &mut Logger<'_>,
    clock: &SharedClock,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<Preparation, Failure> {
    let callback_has_config = config.is_some();
    Ok(
        match program::conf_and_options(
            project,
            config,
            arguments,
            defaults,
            environment,
            logger,
            clock,
            stdout,
            stderr,
        )? {
            ConfigurationPreparation::Ready(ready) => Preparation::Ready(Box::new(Prepared {
                config: ready.config,
                callback_has_config,
            })),
            ConfigurationPreparation::Stopped(stopped) => Preparation::Stopped(stopped),
        },
    )
}
/// Service_main port used by monolith. Implementations must perform their actual
/// in-process registration; success here never asserts that services are running.
pub trait ServiceMain {
    /// Original monolith passes argc0/argvNULL and with_scheduler=false. Those
    /// constants are represented by this narrow operation, rather than fake argv.
    fn register<'a>(
        &'a mut self,
        project: &'a ProjectData,
        config: Option<&'a Configuration>,
        scope: &Scope<'a>,
    ) -> Result<(), Failure>;
}
impl Prepared {
    /// DAEMON_main's actual scheduler=true path after preparation. Registration
    /// callbacks are polled by this owned run; no Resolver or SPEEDUP is started.
    pub async fn run_daemons<'a>(
        &'a self,
        registry: &'a mut Registry<'_>,
        clock: SharedClock,
        capacity: usize,
    ) -> Result<(), Failure> {
        crate::runtime::run_tasks_fallible(clock, capacity, |scope| {
            registry.launch(self.callback_config(), &scope)?;
            Ok(())
        })
        .await
    }
    /// Source monolith ordering: Service_main registers first, then DAEMON_main
    /// queues its registered tasks into the same scheduler. Both retain the
    /// original nullable cfg view rather than receiving C's unreachable leaked cfg.
    pub async fn run_monolith<'a>(
        &'a self,
        project: &'a ProjectData,
        services: &'a mut impl ServiceMain,
        registry: &'a mut Registry<'_>,
        clock: SharedClock,
        capacity: usize,
    ) -> Result<(), Failure> {
        crate::runtime::run_tasks_fallible(clock, capacity, |scope| {
            services.register(project, self.callback_config(), &scope)?;
            registry.launch(self.callback_config(), &scope)?;
            Ok(())
        })
        .await
    }
}
/// Source logging read points, distinct from task admission/completion.
pub enum Notice<'a> {
    /// GNUNET_DAEMON_register before allocation/insertion.
    Register(&'a [u8]),
    /// GNUNET_DAEMON_main before optional conf_and_options.
    Enter,
    /// launch_daemons before the callback tasks can run.
    Launch(&'a [u8]),
}
/// Synchronous diagnostics port. A caller can borrow a shared logger inside each
/// call; no RefCell/Mutex borrow is held across scheduler awaits.
pub trait Diagnostics {
    /// Execute a real diagnostic operation or report its actual output failure.
    fn notice(&mut self, notice: Notice<'_>) -> Result<(), Failure>;
}
/// Actual common logger adapter for source DAEMON helper diagnostics.
pub struct LoggingDiagnostics<'a, 'log, W> {
    /// Original caller-owned logger, retaining first-call source-site caches.
    pub logger: &'a mut Logger<'log>,
    /// Same adjustable process clock used by PROGRAM and Resolver.
    pub clock: &'a SharedClock,
    /// Actual stderr/diagnostic writer; no external process is contacted.
    pub stderr: &'a mut W,
}
impl<W: Write> Diagnostics for LoggingDiagnostics<'_, '_, W> {
    fn notice(&mut self, notice: Notice<'_>) -> Result<(), Failure> {
        let (id, function, line, body) = match notice {
            Notice::Enter => (
                "daemon.enter",
                b"GNUNET_DAEMON_main".as_slice(),
                664,
                b"Entering GNUNET_DAEMON_main\n".to_vec(),
            ),
            Notice::Register(name) => {
                let mut body = b"registering daemon ".to_vec();
                body.extend_from_slice(prefix(name));
                body.push(b'\n');
                (
                    "daemon.register",
                    b"GNUNET_DAEMON_register".as_slice(),
                    690,
                    body,
                )
            }
            Notice::Launch(name) => {
                let mut body = b"Launching daemon ".to_vec();
                body.extend_from_slice(prefix(name));
                body.push(b'\n');
                ("daemon.launch", b"launch_daemons".as_slice(), 648, body)
            }
        };
        self.logger.source_lazy(
            id,
            crate::policy::Level::DEBUG,
            crate::policy::CallSite {
                component: Some(b"util-program"),
                file: b"program.c",
                function,
                line,
            },
            || Ok(body),
            || crate::logging::Stamp::now(self.clock.offset().map_err(std::io::Error::other)?),
            self.stderr,
        )?;
        Ok(())
    }
}
fn prefix(name: &[u8]) -> &[u8] {
    &name[..name.iter().position(|&v| v == 0).unwrap_or(name.len())]
}
impl<'a> Registry<'a> {
    /// Complete registration operation with its source diagnostic read point.
    pub fn register_logged(
        &mut self,
        name: &[u8],
        help: &[u8],
        task: impl for<'b> FnMut(Main<'b>) + 'a,
        diagnostics: &mut impl Diagnostics,
    ) -> Result<i32, Failure> {
        diagnostics.notice(Notice::Register(name))?;
        Ok(self.register(name, help, task)?)
    }
    /// GNUNET_DAEMON_main with_scheduler=false: emit Enter and enqueue in the
    /// supplied already-running scope. It parses no options, selects no Resolver
    /// and starts no SPEEDUP/task owner of its own.
    pub fn main_without_scheduler<'b>(
        &'b mut self,
        config: Option<&'b Configuration>,
        scope: &Scope<'b>,
        diagnostics: &mut impl Diagnostics,
    ) -> Result<Launch, Failure> {
        diagnostics.notice(Notice::Enter)?;
        self.launch_logged(config, scope, diagnostics)
    }
    /// Logged launch batch. Names are emitted newest-first before any callback is
    /// polled; finite scheduler capacity still rejects atomically at admission.
    pub fn launch_logged<'b>(
        &'b mut self,
        config: Option<&'b Configuration>,
        scope: &Scope<'b>,
        diagnostics: &mut impl Diagnostics,
    ) -> Result<Launch, Failure> {
        let entries = self.snapshot()?;
        for entry in &entries {
            diagnostics.notice(Notice::Launch(&entry.name))?;
        }
        Ok(self.admit(entries, config, scope)?)
    }
}
impl Prepared {
    /// Full source helper launch including common logger diagnostics. It still
    /// creates no process: registered tasks run in this exact caller-owned scope.
    pub async fn run_daemons_logged<'a>(
        &'a self,
        registry: &'a mut Registry<'_>,
        clock: SharedClock,
        capacity: usize,
        diagnostics: &mut impl Diagnostics,
    ) -> Result<(), Failure> {
        crate::runtime::run_tasks_fallible(clock, capacity, |scope| {
            registry.launch_logged(self.callback_config(), &scope, diagnostics)?;
            Ok(())
        })
        .await
    }
    /// Logged monolith's actual service registration and daemon launch ordering.
    pub async fn run_monolith_logged<'a>(
        &'a self,
        project: &'a ProjectData,
        services: &'a mut impl ServiceMain,
        registry: &'a mut Registry<'_>,
        clock: SharedClock,
        capacity: usize,
        diagnostics: &mut impl Diagnostics,
    ) -> Result<(), Failure> {
        crate::runtime::run_tasks_fallible(clock, capacity, |scope| {
            services.register(project, self.callback_config(), &scope)?;
            diagnostics.notice(Notice::Enter)?;
            registry.launch_logged(self.callback_config(), &scope, diagnostics)?;
            Ok(())
        })
        .await
    }
}
