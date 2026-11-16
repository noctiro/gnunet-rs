//! Actual Owner/reactor/native composition. No fixture or placeholder port.
use super::{
    Failure, Failures, Unreaped, control::Control, readiness::Readiness, reporting::Reports,
    settings::Settings, usage::Usage,
};
use crate::{
    listeners::ManagedListeners,
    process::{self, ChildRegistry, EnvironmentSnapshot},
    reactor::{self, Activity, Driver, State},
    registry::Registry,
};
use gnunet_arm_core::wire::{ServiceInfo, ServiceStatus};
use gnunet_arm_service_core as core;
use gnunet_config::{Configuration, ProcessEnvironment};
use gnunet_program_host::{policy::Level, shared_clock::SharedClock};
use gnunet_service_runtime::{BoundListeners, clock::RuntimeClock};
use gnunet_service_startup::ControlReceiver;
use std::{
    future::{Future, poll_fn},
    io,
    sync::Arc,
    task::Poll,
    time::Duration,
};
use tokio::time::Instant;
struct Clock {
    source: Arc<dyn RuntimeClock>,
}
impl reactor::Clock for Clock {
    fn utc(&mut self) -> io::Result<u64> {
        self.source
            .sample()
            .map(|s| s.now.as_micros())
            .map_err(io::Error::other)
    }
}
struct Bounds {
    term: Option<Instant>,
    kill: Option<Instant>,
}
impl Bounds {
    fn new() -> Self {
        Self {
            term: None,
            kill: None,
        }
    }
    fn start(&mut self, s: &Settings) -> Result<(), Failure> {
        if self.term.is_none() {
            let term = Instant::now()
                .checked_add(s.shutdown_grace)
                .ok_or("ARM shutdown grace overflow")?;
            let kill = term
                .checked_add(s.kill_grace)
                .ok_or("ARM kill grace overflow")?;
            self.term = Some(term);
            self.kill = Some(kill)
        }
        Ok(())
    }
}
pub(super) struct Inputs<'a, 'route, 'log> {
    pub(super) bound: BoundListeners,
    pub(super) parent: Option<ControlReceiver>,
    pub(super) settings: &'a Settings,
    pub(super) config: &'a Configuration,
    pub(super) clock: &'a SharedClock,
    pub(super) reports: &'a Reports<'route, 'log>,
    pub(super) ready: &'a mut dyn Readiness,
}
pub(super) async fn run(input: Inputs<'_, '_, '_>) -> Result<(), Failure> {
    let Inputs {
        bound,
        parent,
        settings,
        config,
        clock,
        reports,
        ready,
    } = input;
    let mut children = ChildRegistry::new(process::child_capacity(settings.native.process))?;
    process::prepare(&mut children)?;
    // The actual original SIGCHLD port is installed before registry enumeration.
    let mut usage = if let Some(path) = &settings.resource {
        match Usage::open(path) {
            Ok(file) => file,
            Err(error) => {
                reports.warning(
                    "arm.usage.open",
                    format_args!("ARM resource file {}: {error}", path.display()),
                );
                Usage::disabled()
            }
        }
    } else {
        Usage::disabled()
    };
    if usage.enabled() {
        children.enable_resource_usage()?
    }
    let mut cache = gnunet_config::BinaryPathCache::default();
    let project = gnunet_config::ProjectData::default();
    let registry = Registry::from_config(
        config,
        &ProcessEnvironment,
        &project,
        &mut cache,
        settings.registry,
    )?;
    for d in registry.diagnostics() {
        reports.warning(
            "arm.registry",
            format_args!(
                "ARM service {:?} config stat {}: {:?}",
                String::from_utf8_lossy(&d.service),
                d.config_path.display(),
                d.error
            ),
        )
    }
    reports.startup_check()?;
    let mut specs = Vec::new();
    specs.try_reserve_exact(registry.services().len())?;
    for s in registry.services() {
        specs.push(core::ServiceSpec {
            name: &s.name,
            binary: &s.binary,
            command: s.recipe.core_bytes(),
            immediate: s.immediate,
            pipe_control: s.pipe_control,
        })
    }
    let mut services = Vec::new();
    services.try_reserve_exact(specs.len())?;
    services.resize_with(specs.len(), core::ServiceSlot::new);
    let mut clients = Vec::new();
    clients.try_reserve_exact(settings.native.clients)?;
    clients.resize_with(settings.native.clients, core::ClientSlot::new);
    let mut listeners = Vec::new();
    listeners.try_reserve_exact(settings.listeners)?;
    listeners.resize_with(settings.listeners, core::ListenerSlot::new);
    let list_bytes = specs
        .iter()
        .try_fold(settings.abi.list_bytes(), |n, s| {
            n.checked_add(30)
                .and_then(|n| n.checked_add(s.name.len()))
                .and_then(|n| n.checked_add(s.binary.len()))
                .ok_or("ARM list size overflow")
        })?
        .max(settings.abi.result_bytes());
    if list_bytes > settings.native.frame_bytes || list_bytes > 65535 {
        return Err("ARM configured LIST exceeds complete frame budget".into());
    }
    let mut slabs = Vec::new();
    slabs.try_reserve_exact(settings.frames)?;
    for _ in 0..settings.frames {
        let mut slab = Vec::new();
        slab.try_reserve_exact(list_bytes)?;
        slab.resize(list_bytes, 0);
        slabs.push(slab)
    }
    let mut frames = Vec::new();
    frames.try_reserve_exact(settings.frames)?;
    for slab in &mut slabs {
        frames.push(core::FrameSlot::new(slab))
    }
    let mut rows = Vec::new();
    rows.try_reserve_exact(specs.len())?;
    rows.resize_with(specs.len(), || ServiceInfo {
        name: b"",
        binary: b"",
        status: ServiceStatus(0),
        last_exit_status: 0,
        restart_at: 0,
        last_started_at: 0,
    });
    let mut scope = core::OwnerScope::new();
    let mut owner = core::Owner::new(
        &mut scope,
        &specs,
        &mut services,
        &mut clients,
        &mut listeners,
        &mut frames,
        settings.abi,
    )
    .map_err(reactor::Error::from)?;
    let mut managed = ManagedListeners::new(settings.listeners);
    managed
        .bind_registry(config, &registry, &ProcessEnvironment, settings.addresses)
        .await?;
    for failure in managed.failures() {
        reports.warning(
            "arm.listener",
            format_args!("ARM managed listener: {failure:?}"),
        )
    }
    let mut state = State::new(bound, settings.native)?;
    state.set_unix_access(settings.access)?;
    #[cfg(unix)]
    let environment = bounded_environment(settings.native.process.launch.max_environment_bytes)?;
    #[cfg(windows)]
    let environment = EnvironmentSnapshot::from_values(
        std::env::vars_os(),
        std::env::current_dir()?,
        settings.native.process.native,
    )?;
    let source: Arc<dyn RuntimeClock> = Arc::new(clock.clone());
    let mut subscription = source.subscribe()?;
    let mut revision = source.sample()?.revision;
    let mut time = Clock { source };
    let mut control = Control::new(parent)?;
    let mut bounds = Bounds::new();
    let mut started = false;
    let mut announced = false;
    // Pre-reserve original child capabilities for both TERM and KILL passes. No
    // fallible child-list allocation occurs after an actual termination request.
    let mut originals = Vec::new();
    originals.try_reserve_exact(process::child_capacity(settings.native.process))?;
    let mut retained = Vec::new();
    retained.try_reserve_exact(settings.native.services)?;
    let mut cleanup = Vec::new();
    cleanup.try_reserve_exact(
        process::child_capacity(settings.native.process)
            .saturating_mul(3)
            .saturating_add(16),
    )?;
    let outcome = {
        let mut driver = Driver::new(
            &mut owner,
            &registry,
            &mut managed,
            &mut children,
            &mut state,
            {
                #[cfg(unix)]
                {
                    process::LaunchContext {
                        config,
                        helper: &settings.helper,
                        environment: &environment,
                    }
                }
                #[cfg(windows)]
                {
                    process::LaunchContext {
                        environment: &environment,
                    }
                }
            },
            &settings.options,
            &mut rows,
            &mut time,
        )?;
        let mut deadline = None;
        let mut killed = false;
        loop {
            let mut alarm = deadline.map(|at| Box::pin(tokio::time::sleep_until(at)));
            let selected = poll_fn(|cx| {
                // Original native shutdown target precedes clock/provider polling.
                if driver.phase() == core::Phase::Closed {
                    return Poll::Ready(Ok(Activity::Closed));
                }
                if deadline.is_some_and(|at| Instant::now() >= at) {
                    if killed {
                        return Poll::Ready(Err("ARM original KILL/reap grace elapsed".into()));
                    }
                    driver.kill_remaining();
                    killed = true;
                    deadline = bounds.kill;
                    alarm = deadline.map(|at| Box::pin(tokio::time::sleep_until(at)));
                    if deadline.is_some_and(|at| Instant::now() >= at) {
                        return Poll::Ready(Err("ARM original KILL/reap grace elapsed".into()));
                    }
                }
                if let Some(alarm) = &mut alarm {
                    let _registered = alarm.as_mut().poll(cx);
                }
                match subscription.poll_changed(cx, revision) {
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(Box::new(e) as Failure)),
                    Poll::Ready(Ok(s)) => revision = s.revision,
                    Poll::Pending => {}
                }
                match control.poll(cx, reports) {
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {
                        if let Err(error) = bounds.start(settings) {
                            return Poll::Ready(Err(error));
                        }
                        deadline = if killed { bounds.kill } else { bounds.term };
                        driver.shutdown();
                        // Same immutable target; registering it here avoids a new source wait.
                        if alarm.is_none() {
                            alarm = deadline.map(|at| Box::pin(tokio::time::sleep_until(at)));
                            if let Some(a) = &mut alarm {
                                let _registered = a.as_mut().poll(cx);
                            }
                        }
                    }
                    Poll::Pending => {}
                }
                let result = driver.poll_drive(cx);
                let mut local = false;
                if let Some(event) = driver.take_resource_event() {
                    local = true;
                    if let Err(e) = record(
                        &mut usage,
                        &registry,
                        event.service,
                        &event.event,
                        event.usage,
                    ) {
                        if let Poll::Ready(Err(original)) = result {
                            cleanup.push(e);
                            return Poll::Ready(Err(Box::new(original) as Failure));
                        }
                        return Poll::Ready(Err(e));
                    }
                }
                while let Some(diagnostic) = driver.take_diagnostic() {
                    local = true;
                    reports.warning(
                        "arm.native",
                        format_args!("ARM native reactor: {diagnostic:?}"),
                    )
                }
                if !started
                    && driver.phase() == core::Phase::Serving
                    && !matches!(&result, Poll::Ready(Err(_)))
                {
                    if !announced {
                        announced = true;
                        reports.message(
                            Level::INFO,
                            "arm.ready",
                            format_args!("ARM service started"),
                        );
                    }
                    if reports.failed() {
                        cx.waker().wake_by_ref();
                        return Poll::Ready(Ok(Activity::Progress));
                    }
                    match ready.poll_ready(cx) {
                        Poll::Ready(Ok(())) => started = true,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => {}
                    }
                }
                match result {
                    Poll::Ready(r) => Poll::Ready(r.map_err(|e| Box::new(e) as Failure)),
                    Poll::Pending if local => Poll::Ready(Ok(Activity::Progress)),
                    Poll::Pending => Poll::Pending,
                }
            })
            .await;
            match selected {
                Err(error) => break Err(error),
                Ok(Activity::Closed) => break Ok(()),
                Ok(Activity::Progress) => {}
            }
        }
    };
    // All real IO owners are retired independently of clock health. Normal
    // Closed was reached only by actual child/listener/timer acknowledgments.
    if let Some(event) = state.take_resource_event()
        && let Err(error) = record(
            &mut usage,
            &registry,
            event.service,
            &event.event,
            event.usage,
        )
    {
        cleanup.push(error)
    }
    let _retired = state.retire_io();
    drop(managed);
    if children.pending_children() != 0 {
        if let Err(e) = bounds.start(settings) {
            cleanup.push(e)
        }
        originals.clear();
        originals.extend(children.children().cloned());
        for child in &originals {
            if children.owns(child)
                && let Err(error) = process::force_stop(&mut children, child)
            {
                cleanup.push(Box::new(error) as Failure)
            }
        }
        let term = bounds.term.unwrap_or_else(Instant::now);
        collect(
            &mut children,
            &state,
            &registry,
            &mut usage,
            term,
            &mut cleanup,
        )
        .await;
        if children.pending_children() != 0 {
            originals.clear();
            originals.extend(children.children().cloned());
            for child in &originals {
                if children.owns(child)
                    && let Err(error) = process::kill(&mut children, child)
                {
                    cleanup.push(Box::new(error) as Failure)
                }
            }
            collect(
                &mut children,
                &state,
                &registry,
                &mut usage,
                bounds.kill.unwrap_or(term),
                &mut cleanup,
            )
            .await;
        }
    }
    if let Err(error) = drain_records(&mut children, &state, &registry, &mut usage) {
        cleanup.push(error)
    }
    if let Err(error) = usage.finish() {
        cleanup.push(Box::new(error))
    }
    let remaining = children.pending_children();
    if remaining != 0 {
        // The backing was reserved before admission. No scoped core token escapes;
        // original provider/control owners follow the same native registry.
        state.retain_native(&children, &mut retained);
    }
    // Persisted requester sockets close after the actual normal drain. Pending
    // native dependents have moved into the recoverable debt above.
    drop(state);
    if remaining != 0 {
        return Err(Box::new(Unreaped::new(
            children,
            retained,
            outcome.err(),
            cleanup,
        )));
    }
    if cleanup.is_empty() {
        outcome
    } else {
        Err(Box::new(Failures {
            original: outcome.err(),
            cleanup,
        }))
    }
}
fn record(
    usage: &mut Usage,
    registry: &Registry,
    service: usize,
    event: &gnunet_service_runtime::process::Reaped,
    resource: gnunet_service_runtime::process::ResourceUsage,
) -> Result<(), Failure> {
    let entry = registry
        .services()
        .get(service)
        .ok_or("ARM resource service mapping mismatch")?;
    usage.write(&entry.binary, event, resource)
}
fn drain_records(
    children: &mut ChildRegistry,
    state: &State<'_, '_>,
    registry: &Registry,
    usage: &mut Usage,
) -> Result<(), Failure> {
    let mut first = None;
    while let Some((event, resource)) = children.take_completed_with_usage() {
        if let Some(resource) = resource {
            let result = match state.service_for_child(&event.child) {
                Some(service) => record(usage, registry, service, &event, resource),
                None => Err("ARM original cleanup resource mapping unavailable".into()),
            };
            if let Err(error) = result
                && first.is_none()
            {
                first = Some(error)
            }
        }
    }
    match first {
        None => Ok(()),
        Some(error) => Err(error),
    }
}
async fn collect(
    children: &mut ChildRegistry,
    state: &State<'_, '_>,
    registry: &Registry,
    usage: &mut Usage,
    until: Instant,
    errors: &mut Vec<Failure>,
) {
    // A bounded retry timer is also registered: EINTR or a coalesced SIGCHLD must
    // not strand original wait authority, and no actual syscall is treated as reap.
    let mut retry = Box::pin(tokio::time::sleep_until(Instant::now()));
    poll_fn(|cx| {
        let wait_error = children.reap_completed().err();
        let usage_error = drain_records(children, state, registry, usage).err();
        if wait_error.is_some() || usage_error.is_some() {
            if let Some(error) = wait_error {
                errors.push(Box::new(error) as Failure)
            }
            if let Some(error) = usage_error {
                errors.push(error)
            }
            return Poll::Ready(());
        }
        if children.pending_children() == 0 || Instant::now() >= until {
            return Poll::Ready(());
        }
        match children.poll_child_signal(cx) {
            Poll::Ready(Err(e)) => {
                errors.push(Box::new(e));
                return Poll::Ready(());
            }
            Poll::Ready(Ok(())) => cx.waker().wake_by_ref(),
            Poll::Pending => {}
        }
        if retry.as_mut().poll(cx).is_ready() {
            let next = Instant::now()
                .checked_add(Duration::from_millis(10))
                .unwrap_or(until)
                .min(until);
            retry.as_mut().reset(next);
            let _registered = retry.as_mut().poll(cx);
        }
        Poll::Pending
    })
    .await;
}

#[cfg(unix)]
fn bounded_environment(maximum: usize) -> Result<EnvironmentSnapshot, Failure> {
    use std::os::unix::ffi::OsStrExt;
    let mut total = 0usize;
    let mut values = Vec::new();
    for (name, value) in std::env::vars_os() {
        total = total
            .checked_add(name.as_bytes().len())
            .and_then(|n| n.checked_add(value.as_bytes().len()))
            .and_then(|n| n.checked_add(2))
            .ok_or("ARM environment byte overflow")?;
        if total > maximum {
            return Err("ARM original environment exceeds explicit byte quota".into());
        }
        values.try_reserve(1)?;
        values.push((name, value));
    }
    Ok(EnvironmentSnapshot::from_values(
        values,
        std::env::current_dir()?,
    )?)
}
