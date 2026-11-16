//! Original HOSTLIST providers, finite stop grace and physical retirement.
use crate::{
    Failure,
    failure::{Failures, ShutdownFailures},
    foreground::ResolverOwner,
    reporting::{Cleanup, Reports},
    settings::Settings,
};
use gnunet_client_host::{EndpointSource, LiveConfiguration};
use gnunet_hostlist_host::{Event, Progress, Runtime};
use gnunet_service_startup::{ClientStartup, StopSignals};
use std::{
    cell::Cell,
    future::{Future, poll_fn},
    io::{self, Write},
    rc::Rc,
    task::Poll,
};
use tokio::time::Instant;
fn observe(reports: &Reports, event: Event<'_>) {
    use gnunet_hostlist_host::{DurableEvent, HttpEvent, PeerstoreEvent, StatisticsEvent};
    match event {
        Event::Cleanup(owner, error) => reports.provider_cleanup(owner, Box::new(error)),
        Event::Peerstore(PeerstoreEvent::Cleanup(error)) => {
            reports.provider_cleanup("PEERSTORE native cleanup", Box::new(error));
        }
        Event::CoreLost { .. }
        | Event::CoreRetry(_)
        | Event::AdvertisementRejected { .. }
        | Event::HelloRejected { .. }
        | Event::SocketDiagnostic { .. }
        | Event::Capacity(_)
        | Event::DownloadFinished {
            failure: Some(_), ..
        }
        | Event::Peerstore(
            PeerstoreEvent::Lost { .. }
            | PeerstoreEvent::Retry { .. }
            | PeerstoreEvent::Rejected { .. },
        )
        | Event::Statistics(StatisticsEvent::Retry(_))
        | Event::Durable(DurableEvent::Failed(_))
        | Event::Http(HttpEvent::Closed {
            failure: Some(_), ..
        }) => reports.warning(
            "hostlist.provider.event",
            format_args!("hostlist actual event={event:?}"),
        ),
        _ => reports.debug(
            "hostlist.provider.event",
            format_args!("hostlist actual event={event:?}"),
        ),
    }
}
struct Owners<'id> {
    runtime: Runtime<'id>,
    resolver: ResolverOwner,
    reports: Reports,
}
impl Drop for Owners<'_> {
    fn drop(&mut self) {
        if let Err(error) = self
            .runtime
            .close(&mut |event| observe(&self.reports, event))
        {
            self.reports.cleanup(Cleanup::Runtime, Box::new(error));
        }
        if let Some(error) = self.resolver.close() {
            self.reports.cleanup(Cleanup::Resolver, error);
        }
    }
}
fn bind(address: std::net::SocketAddr) -> io::Result<tokio::net::TcpListener> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(address),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    if address.is_ipv6() {
        socket.set_only_v6(true)?
    }
    #[cfg(unix)]
    socket.set_reuse_address(true)?;
    #[cfg(windows)]
    {
        use std::os::windows::io::AsSocket;
        gnunet_native::network::set_exclusive_address_use(socket.as_socket())?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&socket2::SockAddr::from(address))?;
    socket.listen(128)?;
    let socket: std::net::TcpListener = socket.into();
    tokio::net::TcpListener::from_std(socket)
}
pub(super) async fn run(
    settings: Settings,
    inherited: ClientStartup,
    resolver: ResolverOwner,
    live: LiveConfiguration,
    resolution: gnunet_client_host::resolution::SharedResolution,
    reports: Reports,
    stop: Rc<Cell<bool>>,
) -> Result<(), Failure> {
    use gnunet_hostlist_host::{Core, Durable, Instances, Options, Sources, Tls};
    use gnunet_snapshot_host::backend::{Namespace, Store};
    let mut signals = StopSignals::for_client(inherited.parent)?;
    if stop.get() || reports.failed() {
        return Ok(());
    }
    if let Poll::Ready(result) = poll_fn(|cx| Poll::Ready(signals.poll_stop(cx))).await {
        return result.map_err(|error| Box::new(error) as Failure);
    }
    let mut core_instance = gnunet_core_client_host::Instance::new();
    let mut peerstore = gnunet_peerstore_client_host::Instance::new();
    let mut monitor = gnunet_peerstore_client_host::Instance::new();
    let clock = resolution.clock();
    let now = clock.sample()?.now.as_micros();
    let mut core = Core::new(settings.state, settings.modes, &settings.servers, now)?;
    let mut listeners = Vec::new();
    listeners.try_reserve_exact(settings.binds.len())?;
    let mut first_bind = None;
    for address in &settings.binds {
        if reports.failed() {
            break;
        }
        match bind(*address) {
            Ok(listener) => listeners.push(listener),
            Err(error) => {
                reports.warning(
                    "hostlist.http.alternate-bind",
                    format_args!(
                        "hostlist actual alternate bind failure address={address} cause={error}"
                    ),
                );
                if first_bind.is_none() {
                    first_bind = Some(error)
                }
            }
        }
    }
    if settings.modes.provide && listeners.is_empty() {
        return Err(first_bind.map_or_else(
            || "HOSTLIST no bound HTTP listener".into(),
            |error| Box::new(error) as Failure,
        ));
    }
    if reports.failed() {
        return Ok(());
    }
    let advertised = if settings.modes.provide && settings.modes.advertise {
        let host = match settings.external.as_deref() {
            Some(bytes) => bytes.to_vec(),
            None => gnunet_resolver_broker::local_fqdn_get()?
                .into_string()
                .map_err(|_| "HOSTLIST local hostname is not valid Unicode")?
                .into_bytes(),
        };
        let host = std::str::from_utf8(&host)?;
        let host = if host.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{host}]")
        } else {
            host.to_owned()
        };
        let uri = format!("http://{host}:{}/", settings.port);
        let parsed = gnunet_hostlist_host::http::validate_uri(uri.as_bytes())?;
        if !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.path() != "/"
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err("HOSTLIST EXTERNAL_DNS_NAME must contain only a hostname or IP".into());
        }
        Some(gnunet_hostlist::Uri::copy_from(uri.as_bytes())?)
    } else {
        None
    };
    let durable = if let Some(directory) = &settings.store {
        let parent = directory
            .parent()
            .ok_or("HOSTLIST qualified store has no parent")?;
        std::fs::create_dir_all(parent)?;
        let (store, loaded) = Store::open(
            Namespace::Hostlist,
            directory,
            gnunet_snapshot_host::backend::Limits {
                body_bytes: settings.store_bytes,
            },
        )?;
        Some(Durable::recover(
            store,
            loaded,
            &mut core,
            settings.store_bytes,
            settings.state.learned,
        )?)
    } else {
        None
    };
    let source = |name: &'static [u8]| EndpointSource::live(live.clone(), name, resolution.clone());
    let runtime = Runtime::new(
        Instances {
            core: &mut core_instance,
            peerstore: &mut peerstore,
            monitor: &mut monitor,
        },
        Sources {
            core: source(b"core"),
            peerstore: source(b"peerstore"),
            statistics: source(b"statistics"),
        },
        resolution,
        core,
        Options {
            listeners,
            advertised,
            tls: Tls::new()?,
            proxy: settings.proxy,
        },
        settings.limits,
        durable,
    )?;
    let mut owners = Owners {
        runtime,
        resolver,
        reports: reports.clone(),
    };
    let start = Instant::now();
    let startup = start
        .checked_add(settings.startup)
        .ok_or("HOSTLIST startup bound overflow")?;
    let mut stop_at = None;
    let mut ready = false;
    let mut native = None;
    let mut resolver_failure = None;
    let mut report = None;
    let mut turn = false;
    loop {
        if reports.failed() {
            break;
        }
        if stop_at.is_some_and(|until| Instant::now() >= until) {
            break;
        }
        if !ready && stop_at.is_none() && Instant::now() >= startup {
            native = Some("HOSTLIST actual source startup deadline".into());
            break;
        }
        enum Wake {
            Signal,
            Resolver,
            Runtime(Progress),
            Logging,
        }
        let result = {
            let wait = if let Some(stop) = stop_at {
                Some(stop)
            } else if !ready {
                Some(startup)
            } else {
                None
            };
            let (runtime, resolver) = (&mut owners.runtime, &mut owners.resolver.driver);
            let mut resolving = std::pin::pin!(resolver.drive_waiting(wait, |event| {
                reports.debug(
                    "hostlist.resolver.event",
                    format_args!("hostlist Resolver={event:?}"),
                );
            }));
            poll_fn(|cx| {
                reports.register(cx);
                if reports.failed() {
                    return Poll::Ready(Ok(Wake::Logging));
                }
                if stop.get() && stop_at.is_none() {
                    return Poll::Ready(Ok(Wake::Signal));
                }
                match signals.poll_stop(cx) {
                    Poll::Ready(Ok(())) => {
                        return Poll::Ready(Ok::<_, (Failure, bool)>(Wake::Signal));
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err((Box::new(error), false))),
                    Poll::Pending => {}
                }
                // Both original drivers retain their cursors when this borrowed
                // wait future is dropped after the other direction makes progress.
                for direction in [turn, !turn] {
                    if reports.failed() {
                        return Poll::Ready(Ok(Wake::Logging));
                    }
                    if direction {
                        if let Poll::Ready(result) = resolving.as_mut().poll(cx) {
                            turn = false;
                            return Poll::Ready(
                                result
                                    .map(|_| Wake::Resolver)
                                    .map_err(|error| (Box::new(error) as Failure, true)),
                            );
                        }
                    } else if let Poll::Ready(result) =
                        runtime.poll(cx, wait, &mut |event| observe(&reports, event))
                    {
                        turn = true;
                        return Poll::Ready(
                            result
                                .map(Wake::Runtime)
                                .map_err(|error| (Box::new(error) as Failure, false)),
                        );
                    }
                }
                if reports.failed() {
                    Poll::Ready(Ok(Wake::Logging))
                } else {
                    Poll::Pending
                }
            })
            .await
        };
        match result {
            Ok(Wake::Logging) => break,
            Ok(Wake::Signal) => {
                if stop_at.is_none() {
                    stop_at = Some(
                        Instant::now()
                            .checked_add(settings.limits.grace)
                            .ok_or("HOSTLIST shutdown bound overflow")?,
                    );
                    if let Err(error) = owners
                        .runtime
                        .request_stop(&mut |event| observe(&reports, event))
                    {
                        native = Some(Box::new(error) as Failure);
                        break;
                    }
                } else {
                    break;
                }
            }
            Ok(Wake::Runtime(Progress::Stopped)) => break,
            Ok(Wake::Runtime(Progress::WaitDeadline)) => {
                if stop_at.is_some() {
                    break;
                } else if !ready {
                    native = Some("HOSTLIST actual source startup deadline".into());
                    break;
                }
            }
            Ok(Wake::Runtime(Progress::Activity)) | Ok(Wake::Resolver) => {}
            Err((error, is_resolver)) => {
                if is_resolver {
                    resolver_failure = Some(error)
                } else {
                    native = Some(error)
                }
                break;
            }
        }
        if reports.failed() {
            break;
        }
        if !ready && stop_at.is_none() {
            let observed = owners.runtime.readiness();
            if observed.complete() {
                let message = format!(
                    "READY hostlist wire=0.29.1 bootstrap={} learning={} provide={} advertise={} http-listeners={} hello-profile={:?} network-ack=not-claimed\n",
                    settings.modes.bootstrap,
                    settings.modes.learning,
                    settings.modes.provide,
                    settings.modes.advertise,
                    observed.http_listeners,
                    settings.limits.profile
                );
                let output = {
                    let mut out = io::stdout().lock();
                    out.write_all(message.as_bytes()).and_then(|()| out.flush())
                };
                if let Err(error) = output {
                    report = Some(error);
                    break;
                }
                ready = true;
            }
        }
    }
    // All native network owners close first. The actual disk worker is then
    // drained/joined rather than declared canceled by the network grace timeout.
    let network = owners
        .runtime
        .close(&mut |event| observe(&reports, event))
        .err()
        .map(|e| Box::new(e) as Failure);
    let has_durable = owners.runtime.has_durable();
    let durable_result = owners
        .runtime
        .shutdown_durable(|event| observe(&reports, event))
        .await;
    let durable_state = match &durable_result {
        Ok(()) if has_durable => "joined",
        Ok(()) => "absent",
        Err(_) => "failed-or-unknown",
    };
    let durable = durable_result.err().map(|e| Box::new(e) as Failure);
    let resolver_cleanup = owners.resolver.close();
    let cleanup = if network.is_some() || durable.is_some() || resolver_cleanup.is_some() {
        Some(Box::new(ShutdownFailures {
            network,
            durable,
            resolver: resolver_cleanup,
        }) as Failure)
    } else {
        None
    };
    let stopped = {
        let mut out = io::stdout().lock();
        writeln!(out,
            "STOPPED hostlist network-owners=retired durable-worker={durable_state} remote-processing=not-claimed"
        ).and_then(|()| out.flush())
    };
    let stopped_report = stopped.err();
    Failures {
        native,
        resolver: resolver_failure,
        cleanup,
        report,
        stopped_report,
    }
    .finish()
}
