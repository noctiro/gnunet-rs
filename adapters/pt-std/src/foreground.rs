//! Actual PROGRAM, same process Resolver/clock, original signal ownership and
//! finite PT shutdown. No PT listener, TUN or C helper is created by this daemon.
use crate::{
    Failure, Identities, Owner, Sources, discovery,
    owner::{Event, Failures},
    settings::Settings,
};
use gnunet_program_host::{program::Prepared, reporting::Reporter, shared_clock::SharedClock};
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_service_startup::{ClientStartup, StopSignals};
use std::{
    cell::RefCell,
    future::{Future, poll_fn},
    rc::Rc,
    sync::Arc,
    task::Poll,
};
/// Run the configured PRE/DHT/CADET and POST/VPN paths under one shared PROGRAM
/// scheduler, Resolver and canonical clock. Disabled sources start no native IO.
pub async fn scheduled(
    prepared: Prepared,
    clock: SharedClock,
    settings: Settings,
    startup: ClientStartup,
    reports: Reporter,
) -> Result<(), Failure> {
    if reports.failed() {
        return Ok(());
    }
    if !settings.families.ipv4 && !settings.families.ipv6 && !settings.tunnel_dns {
        reports.warning(
            "pt.disabled",
            format_args!("PT: no useful service enabled; exiting"),
        );
        return Ok(());
    }
    let config = prepared.main().config.duplicate()?;
    let runtime_clock: Arc<dyn RuntimeClock> = Arc::new(clock.clone());
    let live = gnunet_resolver_broker::LiveConfiguration::new(config.duplicate()?);
    let (mut context, resolver) = gnunet_resolver_broker::broker::<64, 1024>(
        live.clone(),
        settings.resolver,
        gnunet_resolver_broker::native_profile()?,
        runtime_clock.clone(),
    )?;
    let result = Rc::new(RefCell::new(None));
    let receiving = Rc::clone(&result);
    let task_reports = reports.clone();
    let program = prepared
        .run_scheduled(&mut context, clock, 1, move |_main, scope| {
            let destination = Rc::clone(&receiving);
            let stop = scope.clone();
            if let Err(e) = scope.spawn(async move {
                let outcome = run(
                    config,
                    live,
                    settings,
                    startup,
                    resolver,
                    runtime_clock,
                    task_reports,
                )
                .await;
                *destination.borrow_mut() = Some(outcome);
                if let Err(e) = stop.shutdown() {
                    let original = destination.borrow_mut().take().and_then(Result::err);
                    *destination.borrow_mut() = Some(Err(Box::new(Failures {
                        original,
                        cleanup: vec![Box::new(e)],
                    })))
                }
            }) {
                *receiving.borrow_mut() = Some(Err(Box::new(e) as Failure));
                if let Err(e) = scope.shutdown() {
                    let original = receiving.borrow_mut().take().and_then(Result::err);
                    *receiving.borrow_mut() = Some(Err(Box::new(Failures {
                        original,
                        cleanup: vec![Box::new(e)],
                    })));
                }
            }
        })
        .await;
    let task = result
        .borrow_mut()
        .take()
        .unwrap_or_else(|| Err("PROGRAM ended without PT task completion".into()));
    let program = match program {
        Ok(1) => None,
        Ok(code) => Some(format!("PT PROGRAM returned {code}").into()),
        Err(e) => Some(Box::new(e) as Failure),
    };
    match (task, program) {
        (Ok(()), None) => Ok(()),
        (task, program) => Err(Box::new(Failures {
            original: task.err(),
            cleanup: program.into_iter().collect(),
        })),
    }
}
async fn run(
    config: gnunet_config::Configuration,
    live: gnunet_client_host::LiveConfiguration,
    settings: Settings,
    startup: ClientStartup,
    mut resolver: gnunet_resolver_broker::Driver<64, 1024>,
    clock: Arc<dyn RuntimeClock>,
    reports: Reporter,
) -> Result<(), Failure> {
    let stats_resolution = resolver.context().resolution_context();
    let initialized = (|| -> Result<_, Failure> {
        let signals = StopSignals::for_client(startup.parent)?;
        let resolution = resolver.context().resolution_context();
        let endpoint = |service: &'static [u8]| -> Result<_, Failure> {
            Ok(gnunet_client_host::EndpointSource::configuration(
                config.duplicate()?,
                service,
                resolution.clone(),
            ))
        };
        let post = settings.families.ipv4 || settings.families.ipv6;
        // The immutable PROGRAM config supplies every enabled selector. No
        // disabled VPN/CADET/DHT endpoint is selected or parsed.
        let pre = settings.tunnel_dns.then(|| endpoint(b"dns")).transpose()?;
        let post_dns = post.then(|| endpoint(b"dns")).transpose()?;
        let vpn = post.then(|| endpoint(b"vpn")).transpose()?;
        let cadet = settings
            .tunnel_dns
            .then(|| endpoint(b"cadet"))
            .transpose()?;
        let dht = settings.tunnel_dns.then(|| endpoint(b"dht")).transpose()?;
        Ok((signals, pre, post_dns, vpn, cadet, dht))
    })();
    let (mut signals, pre, post, vpn, cadet, dht) = match initialized {
        Ok(v) => v,
        Err(original) => {
            let cleanup = resolver
                .disconnect()
                .err()
                .map(|e| Box::new(e) as Failure)
                .into_iter()
                .collect();
            return Err(Box::new(Failures {
                original: Some(original),
                cleanup,
            }));
        }
    };
    let core = gnunet_pt::core::Instance::new();
    let dns_id = gnunet_dns_client_host::Instance::new();
    let mut vpn_id = gnunet_vpn_client_host::Instance::new();
    let mut cadet_id = gnunet_cadet_host::Instance::new();
    let mut dht_id = gnunet_dht_client_host::Instance::new();
    let mut discovery = setup_result(
        dht.map(|source| discovery::Native::new(&mut dht_id, source))
            .transpose(),
        &mut resolver,
    )?;
    let mut ports: [gnunet_cadet_host::PortSlot; 0] = [];
    let mut channels = Vec::new();
    let channel_count = if cadet.is_some() {
        settings.core.tunnels
    } else {
        0
    };
    setup_result(
        channels
            .try_reserve_exact(channel_count)
            .map_err(|_| gnunet_types::Error::Capacity.into()),
        &mut resolver,
    )?;
    channels.resize_with(channel_count, gnunet_cadet_host::ChannelSlot::new);
    let owner = Owner::new(
        Identities {
            core: &core,
            dns: &dns_id,
            vpn: &mut vpn_id,
            cadet: &mut cadet_id,
            ports: &mut ports,
            channels: &mut channels,
        },
        Sources {
            pre,
            post,
            vpn,
            cadet,
            discovery: discovery
                .as_mut()
                .map(|port| port as &mut dyn discovery::Port<'_>),
        },
        clock,
        settings.core,
        settings.families,
        settings.native,
        gnunet_vpn_client_host::AfProfile::native(),
    );
    let mut owner = match owner {
        Ok(o) => o,
        Err(original) => {
            let cleanup = resolver
                .disconnect()
                .err()
                .map(|e| Box::new(e) as Failure)
                .into_iter()
                .collect();
            return Err(Box::new(Failures {
                original: Some(original),
                cleanup,
            }));
        }
    };
    let mut stats_instance = gnunet_ipc_unix::handle::Instance::new();
    let mut stats =
        match crate::statistics::Publisher::new(&mut stats_instance, live, stats_resolution) {
            Ok(v) => v,
            Err(original) => {
                let mut cleanup = owner.stop();
                drop(owner);
                if let Err(e) = resolver.disconnect() {
                    cleanup.push(Box::new(e));
                }
                return Err(Box::new(Failures {
                    original: Some(original),
                    cleanup,
                }));
            }
        };
    let mut stats_errors = Vec::new();
    if stats_errors.try_reserve_exact(2).is_err() {
        let mut cleanup = owner.stop();
        drop(owner);
        if let Err(error) = stats.abort() {
            cleanup.push(error);
        }
        if let Err(error) = resolver.disconnect() {
            cleanup.push(Box::new(error));
        }
        return Err(Box::new(Failures {
            original: Some(gnunet_types::Error::Capacity.into()),
            cleanup,
        }));
    }
    let outcome = loop {
        enum Turn {
            Stop,
            Activity,
            Owner(Event),
        }
        let result = {
            let mut resolving = std::pin::pin!(resolver.drive_waiting(None, |e| {
                reports.debug("pt.resolver.event", format_args!("PT Resolver: {e:?}"))
            }));
            poll_fn(|cx| {
                reports.register(cx);
                if reports.failed() {
                    return Poll::Ready(Ok(Turn::Stop));
                }
                if let Poll::Ready(r) = signals.poll_stop(cx) {
                    return Poll::Ready(
                        r.map(|()| Turn::Stop)
                            .map_err(|error| Box::new(error) as Failure),
                    );
                }
                // Always check/drive the actual PT owner's original native hard
                // targets before any statistics admission, clock wait or IO.
                let owning = match owner.poll(cx) {
                    Poll::Ready(Err(original)) => return Poll::Ready(Err(original)),
                    Poll::Ready(Ok(Event::CleanupFailure(error))) => {
                        return Poll::Ready(Ok(Turn::Owner(Event::CleanupFailure(error))));
                    }
                    other => other,
                };
                if reports.failed() {
                    return Poll::Ready(Ok(Turn::Stop));
                }
                if let Err(error) = stats.admit(owner.metrics()) {
                    stats_errors.push(error);
                }
                let statistics = match stats.poll(cx, None) {
                    Poll::Ready(Err(error)) => {
                        stats_errors.push(error);
                        true
                    }
                    Poll::Ready(Ok(())) => true,
                    Poll::Pending => false,
                };
                let resolving = resolving.as_mut().poll(cx);
                if let Poll::Ready(Err(error)) = resolving {
                    return Poll::Ready(Err(Box::new(Failures {
                        original: Some(Box::new(error)),
                        cleanup: Vec::new(),
                    }) as Failure));
                }
                if reports.failed() {
                    return Poll::Ready(Ok(Turn::Stop));
                }
                if let Poll::Ready(result) = owning {
                    return Poll::Ready(result.map(Turn::Owner));
                }
                if let Poll::Ready(result) = resolving {
                    return Poll::Ready(
                        result
                            .map(|_| Turn::Activity)
                            .map_err(|e| Box::new(e) as Failure),
                    );
                }
                if statistics {
                    return Poll::Ready(Ok(Turn::Activity));
                }
                if reports.failed() {
                    return Poll::Ready(Ok(Turn::Stop));
                }
                Poll::Pending
            })
            .await
        };
        match result {
            Ok(Turn::Stop) => break Ok(()),
            Err(e) => break Err(e),
            Ok(Turn::Owner(Event::Stopped)) => break Err("PT owner stopped unexpectedly".into()),
            Ok(Turn::Owner(Event::CleanupFailure(e))) => {
                reports.warning(
                    "pt.provider.cleanup",
                    format_args!("PT original provider/cleanup: {e}"),
                );
                if reports.failed() {
                    break Err(e);
                }
            }
            Ok(_) => {}
        }
    };
    let metrics = owner.metrics();
    let mut cleanup = owner.stop();
    cleanup.extend(stats_errors);
    drop(owner);
    // Failure never creates new statistics work or samples a clock to drain it.
    // The original mutation source retires without replaying attempted deltas.
    if (outcome.is_err() || reports.failed())
        && let Err(error) = stats.abort()
    {
        cleanup.push(error);
    }
    let native = tokio::time::Instant::now();
    let hard = match native.checked_add(settings.native.control_timeout) {
        Some(hard) => hard,
        None => {
            cleanup.push(gnunet_types::Error::Overflow.into());
            native
        }
    };
    // Three signed i64 chunks cover a complete u64 delta for each of nine names.
    // The same original hard bound includes final admission and destruction.
    if !stats.closed() {
        for _ in 0..27 {
            if reports.failed() || tokio::time::Instant::now() >= hard {
                break;
            }
            match stats.admit(metrics) {
                Ok(true) => {}
                Ok(false) => break,
                Err(e) => {
                    cleanup.push(e);
                    break;
                }
            }
        }
        if tokio::time::Instant::now() >= hard {
            cleanup.push(gnunet_types::Error::Deadline.into());
        }
        if reports.failed() || tokio::time::Instant::now() >= hard {
            if let Err(error) = stats.abort() {
                cleanup.push(error);
            }
        } else if let Err(original) = stats.destroy(hard) {
            cleanup.push(original);
            if let Err(error) = stats.abort() {
                cleanup.push(error);
            }
        }
    }
    let mut hard_alarm = Box::pin(tokio::time::sleep_until(hard));
    while !stats.closed() {
        let result = {
            let mut resolving =
                std::pin::pin!(resolver.drive_waiting(Some(hard), |e| reports.debug(
                    "pt.resolver.shutdown",
                    format_args!("PT shutdown Resolver: {e:?}")
                )));
            poll_fn(|cx| {
                reports.register(cx);
                if reports.failed() {
                    return Poll::Ready(stats.abort());
                }
                if tokio::time::Instant::now() >= hard || hard_alarm.as_mut().poll(cx).is_ready() {
                    let cleanup = stats.abort().err().into_iter().collect();
                    return Poll::Ready(Err(Box::new(Failures {
                        original: Some(Box::new(gnunet_types::Error::Deadline)),
                        cleanup,
                    }) as Failure));
                }
                if let Poll::Ready(r) = stats.poll(cx, Some(hard)) {
                    return Poll::Ready(r);
                }
                let resolving = resolving.as_mut().poll(cx);
                if let Poll::Ready(Err(error)) = resolving {
                    return Poll::Ready(Err(Box::new(error) as Failure));
                }
                if reports.failed() {
                    return Poll::Ready(stats.abort());
                }
                if let Poll::Ready(Ok(_)) = resolving {
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending
            })
            .await
        };
        if let Err(e) = result {
            cleanup.push(e);
            if let Err(e) = stats.abort() {
                cleanup.push(e);
            }
            break;
        }
    }
    if let Err(e) = stats.check_report() {
        cleanup.push(e);
    }
    if let Err(e) = stats.abort() {
        cleanup.push(e);
    }
    drop(stats);
    if let Err(e) = resolver.disconnect() {
        cleanup.push(Box::new(e));
    }
    if outcome.is_ok() && cleanup.is_empty() {
        Ok(())
    } else {
        Err(Box::new(Failures {
            original: outcome.err(),
            cleanup,
        }))
    }
}

// A refused constructor has started no PT IO, but the one original shared
// Resolver still needs its explicit physical disconnect on every startup exit.
fn setup_result<T>(
    result: Result<T, Failure>,
    resolver: &mut gnunet_resolver_broker::Driver<64, 1024>,
) -> Result<T, Failure> {
    result.map_err(|original| {
        Box::new(Failures {
            original: Some(original),
            cleanup: resolver
                .disconnect()
                .err()
                .map(|e| Box::new(e) as Failure)
                .into_iter()
                .collect(),
        }) as Failure
    })
}
