//! Actual Owner/reactor/native composition. No fixture or placeholder port.
use super::{
    Failure, Failures, Unreaped, control::Control, reporting::Reports, settings::Settings,
    usage::Usage,
};
use crate::{
    listeners::ManagedListeners,
    reactor::{self, Activity, Driver, State},
    registry::Registry,
};
use gnunet_arm_core::wire::{ServiceInfo, ServiceStatus};
use gnunet_arm_service_core as core;
use gnunet_config::{Configuration, ProcessEnvironment};
use gnunet_program_host::{policy::Level, shared_clock::SharedClock};
use gnunet_service_runtime::{
    BoundListeners,
    clock::RuntimeClock,
    process::{ChildRegistry, EnvironmentSnapshot},
};
use gnunet_service_startup::{ParentControl, daemon::ChildReady};
use std::{
    future::{Future, poll_fn},
    io::{self, Write},
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
    pub(super) parent: Option<ParentControl>,
    pub(super) settings: &'a Settings,
    pub(super) config: &'a Configuration,
    pub(super) clock: &'a SharedClock,
    pub(super) reports: &'a Reports<'route, 'log>,
    pub(super) ready: &'a mut ChildReady,
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
    let mut children = ChildRegistry::new(settings.native.process.launch.max_children)?;
    children.prepare()?;
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
    managed.bind_registry(config, &registry, &ProcessEnvironment, settings.addresses)?;
    for failure in managed.failures() {
        reports.warning(
            "arm.listener",
            format_args!("ARM managed listener: {failure:?}"),
        )
    }
    let mut state = State::new(bound, settings.native)?;
    state.set_unix_access(settings.access)?;
    let environment = bounded_environment(settings.native.process.launch.max_environment_bytes)?;
    let source: Arc<dyn RuntimeClock> = Arc::new(clock.clone());
    let mut subscription = source.subscribe()?;
    let mut revision = source.sample()?.revision;
    let mut time = Clock { source };
    let mut control = Control::new(parent)?;
    let mut bounds = Bounds::new();
    let mut started = false;
    // Pre-reserve original child capabilities for both TERM and KILL passes. No
    // fallible child-list allocation occurs after an actual termination request.
    let mut originals = Vec::new();
    originals.try_reserve_exact(settings.native.process.launch.max_children)?;
    let mut cleanup = Vec::new();
    cleanup.try_reserve_exact(
        settings
            .native
            .process
            .launch
            .max_children
            .saturating_mul(3)
            .saturating_add(16),
    )?;
    let managed_count = managed.len();
    let outcome = {
        let mut driver = Driver::new(
            &mut owner,
            &registry,
            &mut managed,
            &mut children,
            &mut state,
            config,
            &settings.helper,
            &environment,
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
                Ok(Activity::Progress) => {
                    if !started && driver.phase() == core::Phase::Serving {
                        reports.message(Level::INFO,"arm.ready",format_args!("ARM configured control/managed listeners and actual startup attempts settled"));
                        if reports.failed() {
                            driver.shutdown();
                            if let Err(error) = bounds.start(settings) {
                                break Err(error);
                            }
                            deadline = if killed { bounds.kill } else { bounds.term };
                            continue;
                        }
                        let output = {
                            let mut out = io::stdout().lock();
                            writeln!(out,"READY arm wire=0.29.1 services={} managed-listeners={} child-readiness=not-claimed",registry.services().len(),managed_count).and_then(|()|out.flush()).and_then(|()|ready.ready())
                        };
                        if let Err(error) = output {
                            break Err(Box::new(error) as Failure);
                        }
                        started = true;
                    }
                }
            }
        }
    };
    // All real IO owners are retired independently of clock health. Normal
    // Closed was reached only by actual child/listener/timer acknowledgments.
    let counters = state.counters();
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
    let normal = owner.phase() == core::Phase::Closed;
    let retired = state.retire_io();
    drop(managed);
    if children.pending_children() != 0 {
        if let Err(e) = bounds.start(settings) {
            cleanup.push(e)
        }
        originals.clear();
        originals.extend(children.children().cloned());
        for child in &originals {
            if children.owns(child)
                && let Err(error) = children.signal_native(child, libc::SIGTERM)
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
                    && let Err(error) = children.signal_native(child, libc::SIGKILL)
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
    // Persisted stop-request sockets close here, after actual normal draining.
    drop(state);
    let remaining = children.pending_children();
    let output = {
        let mut out = io::stdout().lock();
        writeln!(out,"STOPPED arm normal-core-closed={normal} counters={counters:?} retired={retired:?} unreaped={remaining}").and_then(|()|out.flush())
    };
    if let Err(error) = output {
        cleanup.push(Box::new(error))
    }
    if remaining != 0 {
        return Err(Box::new(Unreaped::new(children, outcome.err(), cleanup)));
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
