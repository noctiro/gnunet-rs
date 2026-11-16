//! Explicit original client/Resolver ownership, finite stdio and signal waits.
use super::{Failure, Failures, Mode, Reporter, Settings, diagnostic};
use crate::lifecycle::{Cleanup, Resolver};
use crate::stdio::Io;
use gnunet_client_host::EndpointSource;
use gnunet_hello::Limits as HelloLimits;
use gnunet_peerstore_client_host as ps;
use gnunet_pils_host::client as pils;
use gnunet_program_host::logging::base32;
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_service_startup::StopSignals as Signals;
use std::{
    future::{Future, poll_fn},
    io,
    sync::Arc,
    task::Poll,
    time::Duration,
};
use tokio::time::Instant;
use zeroize::Zeroizing;
mod hello;
const MESSAGE_BYTES: usize = 65535;
const ADDRESS_BYTES: usize = 65423;
const URL_BYTES: usize = 3 * 65535 + 256;
enum Wake<T> {
    Provider(T),
    Resolver,
    Signal,
    Deadline,
}
async fn choose<P: Future>(
    provider: P,
    resolver: &mut Resolver,
    mut signals: Option<&mut Signals>,
    until: Instant,
    resolver_first: bool,
) -> Result<Wake<P::Output>, Failure> {
    let mut provider = std::pin::pin!(provider);
    let reports = resolver.reports.clone();
    let mut resolving = std::pin::pin!(resolver.driver.drive_waiting(Some(until), |event| {
        let _actual = event;
    }));
    let mut alarm = std::pin::pin!(tokio::time::sleep_until(until));
    poll_fn(|cx| {
        reports.register(cx);
        if reports.failed() {
            return Poll::Ready(Err("selected public-peer Logger failed".into()));
        }
        if let Some(signals) = signals.as_mut()
            && let Poll::Ready(signal) = signals.poll_stop(cx)
        {
            return Poll::Ready(signal.map(|()| Wake::Signal).map_err(Into::into));
        }
        if alarm.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Ok(Wake::Deadline));
        }
        for i in 0..2 {
            if reports.failed() {
                return Poll::Ready(Err("selected public-peer Logger failed".into()));
            }
            if (i == 0) == resolver_first {
                if let Poll::Ready(result) = resolving.as_mut().poll(cx) {
                    return Poll::Ready(result.map(|_| Wake::Resolver).map_err(Into::into));
                }
            } else if let Poll::Ready(value) = provider.as_mut().poll(cx) {
                return Poll::Ready(Ok(Wake::Provider(value)));
            }
        }
        Poll::Pending
    })
    .await
}
fn buffer(size: usize) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let mut b = Vec::new();
    b.try_reserve_exact(size)?;
    b.resize(size, 0);
    Ok(Zeroizing::new(b))
}
async fn output(
    io: &mut Io,
    bytes: &[u8],
    resolver: &mut Resolver,
    signals: &mut Signals,
    until: Instant,
) -> Result<(), Failure> {
    let mut at = 0;
    let mut first = false;
    loop {
        let flushing = at == bytes.len();
        let operation = poll_fn(|cx| {
            if flushing {
                Poll::Ready(io.flush().map(|()| 0))
            } else {
                io.write(cx, &bytes[at..bytes.len().min(at + 4096)])
            }
        });
        match choose(operation, resolver, Some(signals), until, first).await? {
            Wake::Provider(Ok(n)) => {
                if !flushing {
                    if n == 0 {
                        return Err(
                            io::Error::new(io::ErrorKind::WriteZero, "public stdout").into()
                        );
                    }
                    at = at
                        .checked_add(n)
                        .filter(|at| *at <= bytes.len())
                        .ok_or("invalid public output byte count")?;
                }
                if Instant::now() >= until || resolver.reports.failed() {
                    return Err(format!("public output guard failed after {at}/{} stdio-accepted bytes; flush-completed={flushing}", bytes.len()).into());
                }
                if flushing {
                    return Ok(());
                }
            }
            Wake::Provider(Err(error)) => return Err(error.into()),
            Wake::Resolver => {}
            Wake::Signal => {
                return Err(format!(
                    "public output interrupted after {at}/{} stdio-accepted bytes",
                    bytes.len()
                )
                .into());
            }
            Wake::Deadline => {
                return Err(format!(
                    "public output expired after {at}/{} stdio-accepted bytes",
                    bytes.len()
                )
                .into());
            }
        }
        first = !first;
    }
}

async fn input(
    resolver: &mut Resolver,
    signals: &mut Signals,
    until: Instant,
) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let mut io = Io::input();
    let mut bytes = buffer(4096)?;
    let mut at = 0;
    let mut first = false;
    loop {
        let limit = if at < 15 || bytes[..15].eq_ignore_ascii_case(b"gnunet://hello/") {
            URL_BYTES
        } else {
            MESSAGE_BYTES
        };
        let end = (at + 4096).min(limit + 1);
        if bytes.len() < end {
            let length = bytes.len().saturating_mul(2).max(end).min(limit + 1);
            let additional = length - bytes.len();
            bytes.try_reserve_exact(additional)?;
            if bytes.capacity() > URL_BYTES + 1 {
                return Err("public input retained capacity exceeds its bound".into());
            }
            bytes.resize(length, 0);
        }
        match choose(
            poll_fn(|cx| io.read(cx, &mut bytes[at..end])),
            resolver,
            Some(signals),
            until,
            first,
        )
        .await?
        {
            Wake::Provider(Ok(0)) => {
                if Instant::now() >= until || resolver.reports.failed() {
                    return Err(format!("public input guard failed after {at} stdio bytes").into());
                }
                bytes.truncate(at);
                return Ok(bytes);
            }
            Wake::Provider(Ok(n)) => {
                at += n;
                if at > limit {
                    return Err("public HELLO input exceeds its binary/URL bound".into());
                }
                if Instant::now() >= until || resolver.reports.failed() {
                    return Err(format!("public input guard failed after {at} stdio bytes").into());
                }
            }
            Wake::Provider(Err(e)) => return Err(e.into()),
            Wake::Resolver => {}
            Wake::Signal => return Err("public HELLO input interrupted".into()),
            Wake::Deadline => {
                return Err("public HELLO input incomplete before original deadline".into());
            }
        }
        first = !first;
    }
}
fn hello_limits() -> HelloLimits {
    HelloLimits {
        maximum_input_bytes: URL_BYTES,
        maximum_address_bytes: ADDRESS_BYTES,
        maximum_addresses: 1024,
    }
}
fn peer_text(peer: &[u8; 32]) -> Result<Vec<u8>, Failure> {
    let mut text = base32(peer);
    text.try_reserve_exact(1)?;
    text.push(b'\n');
    Ok(text)
}
fn print_pils(reports: &Reporter, progress: &pils::Progress<'_, 2>) {
    match progress {
        pils::Progress::Connected(epoch) => diagnostic(
            reports,
            format_args!("actual PILS MQ attached {epoch:?}; public identity pending"),
        ),
        pils::Progress::Written(written) => diagnostic(
            reports,
            format_args!(
                "actual PILS whole local write operation={:?} kind={:?} canceled={}; signature result still required",
                written.operation, written.kind, written.canceled
            ),
        ),
        pils::Progress::Lost {
            epoch,
            cause,
            report,
        } => diagnostic(
            reports,
            format_args!(
                "actual PILS original loss epoch={epoch:?} cause={cause:?} retained-ops={} lost-feeds={}; no local key substitute",
                report.retained(),
                report.feeds().count()
            ),
        ),
        pils::Progress::ConnectRetry {
            epoch,
            retry_after,
            error,
        } => diagnostic(
            reports,
            format_args!(
                "PILS original connect retry epoch={epoch:?} after={retry_after:?}: {error}"
            ),
        ),
        pils::Progress::Unavailable(error) => diagnostic(
            reports,
            format_args!("PILS actual endpoint unavailable: {error}"),
        ),
        pils::Progress::Activity {
            read_bytes,
            written_bytes,
        } => {
            let _actual = (read_bytes, written_bytes);
        }
        pils::Progress::Inbound(_) | pils::Progress::WaitDeadline | pils::Progress::Closed => {}
    }
}
fn print_ps(reports: &Reporter, progress: &ps::Progress<'_>) {
    match progress {
        ps::Progress::Connected(epoch) => diagnostic(
            reports,
            format_args!("actual PEERSTORE MQ attached {epoch:?}"),
        ),
        ps::Progress::Written {
            epoch,
            operation,
            write,
            command,
        } => diagnostic(
            reports,
            format_args!(
                "PEERSTORE original whole local write epoch={epoch:?} operation={operation:?} write={write:?} command={command:?}; no saved ACK inferred"
            ),
        ),
        ps::Progress::Completed {
            epoch,
            operation,
            kind,
            outcome,
        } => diagnostic(
            reports,
            format_args!(
                "PEERSTORE original result epoch={epoch:?} operation={operation:?} kind={kind:?} outcome={outcome:?}"
            ),
        ),
        ps::Progress::Lost {
            epoch,
            cause,
            monitor_retained,
        } => diagnostic(
            reports,
            format_args!(
                "PEERSTORE original source loss epoch={epoch:?} cause={cause:?} monitor-retained={monitor_retained}; original writes not replayed"
            ),
        ),
        ps::Progress::ConnectRetry { error, retry_after } => diagnostic(
            reports,
            format_args!("PEERSTORE actual connect retry after={retry_after:?}: {error}"),
        ),
        ps::Progress::Unavailable(error) => diagnostic(
            reports,
            format_args!("PEERSTORE actual endpoint unavailable: {error}"),
        ),
        ps::Progress::Capacity(epoch) => diagnostic(
            reports,
            format_args!("PEERSTORE exact RX retained for original epoch={epoch:?}"),
        ),
        ps::Progress::Ignored(epoch) => {
            let _actual = epoch;
        }
        ps::Progress::Activity {
            epoch,
            read_bytes,
            written_bytes,
        } => {
            let _actual = (epoch, read_bytes, written_bytes);
        }
        ps::Progress::Sync { epoch, operation } => {
            let _unexpected = (epoch, operation);
        }
        ps::Progress::Record(_) | ps::Progress::WaitDeadline | ps::Progress::Closed => {}
    }
}
struct Owners<'id> {
    pils: Option<pils::Client<'id, 2>>,
    peerstore: Option<ps::Client<'id>>,
    resolver: Resolver,
    closed: bool,
    cleanup: Cleanup,
}
impl Owners<'_> {
    fn close(&mut self) -> (Option<Failure>, Option<Failure>) {
        if self.closed {
            return (None, None);
        }
        self.closed = true;
        let reports = &self.resolver.reports;
        if let Some(pils) = self.pils.as_mut() {
            let retired = pils.close();
            diagnostic(
                reports,
                format_args!(
                    "actual PILS physical close, original retired operations={}",
                    retired.iter().flatten().count()
                ),
            );
        }
        let client = match self.peerstore.as_mut().map(ps::Client::close) {
            Some(Ok(Some(event))) => {
                print_ps(reports, &event);
                None
            }
            Some(Err(e)) => Some(Box::new(e) as Failure),
            _ => None,
        };
        let resolver = self.resolver.close().err().map(|e| Box::new(e) as Failure);
        (client, resolver)
    }
}
impl Drop for Owners<'_> {
    fn drop(&mut self) {
        let (client, resolver) = self.close();
        if let Some(error) = client {
            self.cleanup.client(error);
        }
        if let Some(error) = resolver {
            self.cleanup.resolver(error);
        }
    }
}
pub(super) async fn run(
    source: EndpointSource,
    resolver: Resolver,
    clock: Arc<dyn RuntimeClock>,
    settings: Settings,
    mut signals: Signals,
    cleanup: Cleanup,
) -> Result<(), Failure> {
    let mut pi = pils_instance();
    let mut ps = ps::Instance::new();
    // Clients retire first; canceled output retains its unconfirmed flush fact.
    let mut stdout = Io::output(cleanup.clone());
    let mut owners = Owners {
        pils: None,
        peerstore: None,
        resolver,
        closed: false,
        cleanup,
    };
    let result = async {
        let until = Instant::now() + settings.duration;
        match settings.mode {
            Mode::Export | Mode::Identity => {
                owners.pils = Some(pils::Client::new(
                    &mut pi,
                    source,
                    settings.profile,
                    pils::Limits {
                        pending_operations: 2,
                        frame_bytes: 65535,
                        io_slice_bytes: settings.slice,
                    },
                    hello_limits(),
                )?);
                hello::observe_pils(
                    &mut owners,
                    &mut signals,
                    &mut stdout,
                    &clock,
                    &settings,
                    until,
                )
                .await
            }
            Mode::Import | Mode::Dump => {
                owners.peerstore = Some(ps::Client::new(
                    &mut ps,
                    source,
                    ps::Limits {
                        operations: 4,
                        source_bytes: 256 * 1024,
                        output: gnunet_service_runtime::framing::Budget {
                            frames: 4,
                            bytes: 256 * 1024,
                        },
                        io_slice_bytes: settings.slice,
                        ..Default::default()
                    },
                )?);
                if settings.mode == Mode::Import {
                    hello::import(
                        &mut owners,
                        &mut signals,
                        &mut stdout,
                        &clock,
                        &settings,
                        until,
                    )
                    .await
                } else {
                    hello::dump(
                        &mut owners,
                        &mut signals,
                        &mut stdout,
                        &clock,
                        &settings,
                        until,
                    )
                    .await
                }
            }
        }
    }
    .await;
    let (client, resolver) = owners.close();
    drop(owners);
    drop(stdout);
    Failures {
        task: result.err(),
        client,
        resolver,
        ..Default::default()
    }
    .finish()
}
fn pils_instance() -> gnunet_pils::client::Instance {
    gnunet_pils::client::Instance::new()
}
