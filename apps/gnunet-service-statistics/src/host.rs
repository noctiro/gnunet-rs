//! Actual STATISTICS protocol/store assembly; no private readiness/control files.
use crate::{Failure, aggregate, control::Control, reporting::Reports, settings::Settings};
use gnunet::{
    ipc::{
        IpcError,
        server::{ServeContext, serve_statistics_controlled},
    },
    statistics::AllocatedStatistics,
    statistics_store::Store,
};
use gnunet_program_host::policy::Level;
use gnunet_service_runtime::{BoundListeners, clock::RuntimeClock, private_parents};
use gnunet_service_startup::{ParentControl, daemon::ChildReady};
use std::{
    cell::RefCell,
    future::poll_fn,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::Arc,
};
type Core = AllocatedStatistics;
fn normalized(path: &Path) -> io::Result<PathBuf> {
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "expected file/socket path"))?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    Ok(parent.canonicalize()?.join(name))
}
pub(crate) struct Inputs<'a, 'route, 'log> {
    pub(crate) bound: &'a BoundListeners,
    pub(crate) parent: Option<ParentControl>,
    pub(crate) settings: &'a Settings,
    pub(crate) clock: Arc<dyn RuntimeClock>,
    pub(crate) reports: &'a Reports<'route, 'log>,
    pub(crate) child: &'a mut ChildReady,
}
pub(crate) async fn run(input: Inputs<'_, '_, '_>) -> Result<(), Failure> {
    let Inputs {
        bound,
        parent,
        settings,
        clock,
        reports,
        child,
    } = input;
    let database = settings
        .database
        .as_deref()
        .map(|p| {
            private_parents(p)?;
            normalized(p)
        })
        .transpose()?;
    for path in bound.unix_paths() {
        if database.as_ref() == Some(&normalized(path)?) {
            return Err("statistics socket and DATABASE must differ".into());
        }
    }
    let store = database
        .map(|path| Store::new(path, settings.store))
        .transpose()?;
    let mut core: Core = if let Some(store) = &store {
        // The actual bounded loader builds a fresh unpublished core. Invalid
        // existing data fails startup and is never replaced by an empty image.
        let (core, loaded) = store.load_with(|| Core::with_limits(settings.core))?;
        reports.message(
            Level::INFO,
            "statistics.database.loaded",
            format_args!("statistics actual database load: {loaded:?}"),
        );
        core
    } else {
        reports.warning(
            "statistics.database.memory",
            format_args!("statistics DATABASE absent: memory-only values"),
        );
        Core::with_limits(settings.core)?
    };
    reports.startup_check()?;
    // Preallocate the actual shutdown snapshot scratch before client admission.
    let mut scratch = Vec::new();
    scratch.try_reserve_exact(65535)?;
    scratch.resize(65535, 0);
    // Keep the actual saving buffer charged while the same core is serving.
    core.set_external_retained_bytes(scratch.capacity())?;
    let mut control = Control::new(parent)?;
    let control_error = RefCell::new(None);
    let shutdown = poll_fn(|cx| {
        control.poll(cx, reports).map(|r| {
            if let Err(error) = r {
                *control_error.borrow_mut() = Some(error);
            }
        })
    });
    let listeners = bound.listeners();
    let result = serve_statistics_controlled(
        &listeners,
        &mut core,
        settings.host,
        ServeContext {
            options: &settings.options,
            unix_access: settings.access,
            clock: Some(clock),
            shutdown_grace: Some(settings.shutdown_grace),
        },
        shutdown,
        || {
            reports.message(
                Level::INFO,
                "statistics.ready",
                format_args!("statistics actual initialized host and database ready"),
            );
            if let Some(error) = reports.take_failure() {
                return Err(IpcError::Io(error));
            }
            let mut output = io::stdout().lock();
            writeln!(
                output,
                "READY statistics wire=0.29.1 persistence={} authentication=kernel-unix",
                if store.is_some() {
                    "official-set-snapshot"
                } else {
                    "memory-only"
                }
            )?;
            output.flush()?;
            // Only the actual initialized source (and successful selected
            // logger/stdout) may produce the original daemon-ready byte.
            child.ready()?;
            Ok(())
        },
        |event| reports.observe(event),
    )
    .await;
    // Returned/dropped serving state physically released all original MQs and
    // retired their core generations before this one real snapshot save.
    let report = result.as_ref().ok().copied();
    let mut cleanup = Vec::new();
    let outcome = match (control_error.into_inner(), result) {
        (Some(original), Err(error)) => {
            cleanup.push(Box::new(error) as Failure);
            Err(original)
        }
        (Some(original), Ok(_)) => Err(original),
        (None, result) => result.map(|_| ()).map_err(|e| Box::new(e) as Failure),
    };
    let saved = store.as_ref().map(|s| s.save(&core, &mut scratch));
    match &saved {
        Some(Ok(actual)) => reports.message(
            Level::INFO,
            "statistics.database.saved",
            format_args!("statistics actual shutdown snapshot: {actual:?}"),
        ),
        Some(Err(error)) => reports.warning(
            "statistics.database.failed",
            format_args!("statistics actual shutdown save failed: {error}"),
        ),
        None => {}
    }
    let stopped = {
        let mut out = io::stdout().lock();
        writeln!(out, "STOPPED statistics local={report:?} store={saved:?}")
            .and_then(|()| out.flush())
    };
    if let Some(Err(error)) = saved {
        cleanup.push(Box::new(error));
    }
    if let Err(error) = stopped {
        cleanup.push(Box::new(error));
    }
    aggregate(outcome, cleanup)
}
