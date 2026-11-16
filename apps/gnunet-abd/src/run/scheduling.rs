//! PROGRAM scope and original native startup ownership.
use super::{Bounds, Facts, Failed, Failure, Inputs, Resolver, run};
use crate::options::{Selection, Settings};
use gnunet_program_host::{program::Prepared, reporting::Reporter, shared_clock::SharedClock};
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_service_startup::{ClientStartup, StopSignals};
use std::{cell::RefCell, rc::Rc, sync::Arc};

/// Single explicit PROGRAM work task, using the standard scheduler/Resolver.
pub(crate) async fn scheduled(
    prepared: Prepared,
    clock: SharedClock,
    settings: Settings,
    selection: Selection,
    reporter: Reporter,
    startup: ClientStartup,
) -> Result<(), Failure> {
    let canonical: Arc<dyn RuntimeClock> = Arc::new(clock.clone());
    let original = Bounds::new(canonical.as_ref(), selection.lifetime)?;
    let signals = StopSignals::for_client(startup.parent)?;
    let config = prepared.main().config.duplicate()?;
    let live = gnunet_resolver_broker::LiveConfiguration::new(config);
    let (mut context, driver) = gnunet_resolver_broker::broker::<16, 1024>(
        live.clone(),
        settings.resolver,
        gnunet_resolver_broker::native_profile()?,
        canonical.clone(),
    )?;
    let retirement = Rc::new(RefCell::new(None));
    let facts = Rc::new(RefCell::new(Facts::default()));
    let resolver = Resolver {
        driver,
        closed: false,
        retirement: retirement.clone(),
    };
    let result = Rc::new(RefCell::new(None::<Result<(), Failure>>));
    let receiving = result.clone();
    let history = facts.clone();
    let program = prepared
        .run_scheduled(&mut context, clock, 1, move |_main, scope| {
            let destination = receiving.clone();
            let stop = scope.clone();
            let aborted = history.clone();
            let task_facts = aborted.clone();
            if let Err(e) = scope.spawn(async move {
                *destination.borrow_mut() = Some(
                    run(Inputs {
                        resolver,
                        live,
                        clock: canonical,
                        settings,
                        selection,
                        reporter,
                        facts: history,
                        signals,
                        original,
                    })
                    .await,
                );
                if let Err(e) = stop.shutdown() {
                    let original = destination.borrow_mut().take().and_then(Result::err);
                    *destination.borrow_mut() = Some(Err(Box::new(Failed {
                        original,
                        cleanup: vec![Box::new(e)],
                        facts: task_facts,
                    })));
                }
            }) {
                let cleanup: Vec<Failure> = scope
                    .shutdown()
                    .err()
                    .map(|e| Box::new(e) as Failure)
                    .into_iter()
                    .collect();
                *receiving.borrow_mut() = Some(Err(Box::new(Failed {
                    original: Some(Box::new(e)),
                    cleanup,
                    facts: aborted,
                })));
            }
        })
        .await;
    let task = result
        .borrow_mut()
        .take()
        .unwrap_or_else(|| Err("PROGRAM ended without the original ABD action result".into()));
    let mut cleanup: Vec<Failure> = Vec::new();
    match program {
        Ok(1) => {}
        Ok(code) => cleanup.push(format!("ABD PROGRAM returned {code}").into()),
        Err(e) => cleanup.push(Box::new(e) as Failure),
    }
    if let Some(e) = retirement.borrow_mut().take() {
        cleanup.push(e);
    }
    match task {
        Ok(()) if cleanup.is_empty() => Ok(()),
        task => Err(Box::new(Failed {
            original: task.err(),
            cleanup,
            facts,
        })),
    }
}
