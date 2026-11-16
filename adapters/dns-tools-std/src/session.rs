//! Original DNS callback ownership, fair Resolver polling and bounded reply drain.
use crate::{
    Action,
    control::Control,
    execution::{Failure, Failures},
    packet,
    program::Settings,
};
use gnunet_dns_client_host::{Client, EndpointSource, Instance, Progress, Request, ipc};
use gnunet_program_host::{policy::Level, reporting::Reporter};
use gnunet_resolver_broker::Driver;
use gnunet_service_startup::ParentControl;
use std::{
    cell::Cell,
    future::{Future, poll_fn},
    io,
    pin::Pin,
    rc::Rc,
    task::Poll,
    time::Duration,
};
use tokio::time::{Instant, Sleep};
use zeroize::Zeroizing;

struct Owner<'a> {
    dns: Client<'a>,
    resolver: Driver<8, 256>,
    reporter: Reporter,
    closed: bool,
}
impl Owner<'_> {
    fn close(&mut self) -> Option<Failure> {
        if self.closed {
            return None;
        }
        self.closed = true;
        if let Progress::Lost {
            epoch,
            cause,
            requests,
        } = self.dns.close()
        {
            self.reporter.debug(
                "dns.utility.retired",
                format_args!("source={epoch:?} cause={cause:?} callbacks={requests}"),
            );
        }
        self.resolver
            .disconnect()
            .err()
            .map(|error| Box::new(error) as Failure)
    }
}
impl Drop for Owner<'_> {
    fn drop(&mut self) {
        if let Some(error) = self.close() {
            self.reporter
                .warning("dns.utility.cleanup", format_args!("{error}"));
        }
    }
}
#[derive(Clone, Copy, Debug)]
enum Choice {
    Forward,
    Answer { records: usize },
    TimeoutDrop,
}
struct Pending<'a> {
    token: Request<'a>,
    choice: Choice,
}
enum Turn<'a> {
    Stop,
    Dns(Progress<'a>),
    Resolver,
    Deadline,
}
async fn next<'a>(
    owner: &mut Owner<'a>,
    control: &mut Control,
    alarm: &mut Pin<Box<Sleep>>,
    until: Instant,
    resolver_first: bool,
) -> Result<Turn<'a>, Failure> {
    let (dns, resolver) = (&mut owner.dns, &mut owner.resolver);
    let mut resolving = std::pin::pin!(resolver.drive_waiting(Some(until), |_event| {}));
    poll_fn(|cx| {
        if let Poll::Ready(signal) = control.poll(cx) {
            return Poll::Ready(signal.map(|()| Turn::Stop).map_err(Into::into));
        }
        if alarm.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Ok(Turn::Deadline));
        }
        for first in [true, false] {
            if first == resolver_first {
                if let Poll::Ready(result) = resolving.as_mut().poll(cx) {
                    return Poll::Ready(result.map(|_| Turn::Resolver).map_err(Into::into));
                }
            } else if let Poll::Ready(result) = dns.poll(cx, Some(until)) {
                return Poll::Ready(result.map(Turn::Dns).map_err(Into::into));
            }
        }
        Poll::Pending
    })
    .await
}
fn admit(reporter: &Reporter) -> Result<(), Failure> {
    if reporter.failed() {
        Err(io::Error::other("selected DNS utility logger failed").into())
    } else {
        Ok(())
    }
}
pub(super) async fn run(
    source: EndpointSource,
    resolver: Driver<8, 256>,
    settings: Settings,
    reporter: Reporter,
    stop: Rc<Cell<bool>>,
    parent: Option<ParentControl>,
) -> Result<(), Failure> {
    let instance = Instance::new();
    let mut owner = match Client::new(&instance, source, settings.flags, settings.limits) {
        Ok(dns) => Owner {
            dns,
            resolver,
            reporter: reporter.clone(),
            closed: false,
        },
        Err(original) => {
            let mut resolver = resolver;
            return Failures {
                task: Some(Box::new(original)),
                resolver: resolver
                    .disconnect()
                    .err()
                    .map(|error| Box::new(error) as Failure),
                ..Default::default()
            }
            .finish();
        }
    };
    let outcome = async {
        let mut control = Control::new(parent, stop, reporter.clone())?;
        let mut arena = Vec::new();
        arena.try_reserve_exact(packet::ARENA_BYTES)?;
        arena.resize(packet::ARENA_BYTES, 0);
        let mut arena = Zeroizing::new(arena);
        let mut output = Vec::new();
        output.try_reserve_exact(packet::MAX_PACKET)?;
        output.resize(packet::MAX_PACKET, 0);
        let mut output = Zeroizing::new(output);
        let mut pending = Vec::<Pending<'_>>::new();
        pending.try_reserve_exact(settings.limits.requests)?;
        let until = Instant::now()
            .checked_add(settings.duration)
            .ok_or("DNS utility native deadline overflow")?;
        let mut alarm = Box::pin(tokio::time::sleep_until(until));
        let mut draining = None;
        let mut packets = 0u64;
        let mut writes = 0u64;
        let mut resolver_first = false;
        loop {
            let wait = draining.unwrap_or(until);
            alarm.as_mut().reset(wait);
            match next(&mut owner, &mut control, &mut alarm, wait, resolver_first).await? {
                Turn::Stop | Turn::Deadline => break,
                Turn::Resolver => {}
                Turn::Dns(Progress::Request(notification)) => {
                    if draining.is_some() {
                        drop(notification);
                        continue;
                    }
                    let token = notification.request();
                    if pending.len() == settings.limits.requests {
                        return Err("DNS original callback metadata capacity".into());
                    }
                    let choice = match settings.action {
                        Action::Monitor => {
                            match packet::display(
                                notification.dns(),
                                &mut arena,
                                settings.bounds,
                                &mut io::stdout().lock(),
                            ) {
                                Ok(()) => {}
                                Err(error) if error.is::<gnunet_dns::Error>() => reporter.warning(
                                    "dns.utility.packet",
                                    format_args!(
                                        "malformed/bounded callback forwarded unchanged: {error}"
                                    ),
                                ),
                                Err(error) => return Err(error),
                            }
                            admit(&reporter)?;
                            owner.dns.reply(token, ipc::Decision::Forward)?;
                            Choice::Forward
                        }
                        Action::Redirect => match packet::redirect(
                            notification.dns(),
                            settings.ipv4,
                            settings.ipv6,
                            &mut arena,
                            &mut output,
                            settings.bounds,
                        ) {
                            Ok((bytes, changed)) if changed != 0 => {
                                admit(&reporter)?;
                                owner.dns.reply(token, ipc::Decision::Answer(bytes))?;
                                Choice::Answer { records: changed }
                            }
                            Ok(_) => {
                                admit(&reporter)?;
                                owner.dns.reply(token, ipc::Decision::Forward)?;
                                Choice::Forward
                            }
                            Err(error) => {
                                reporter.warning(
                                    "dns.utility.redirect",
                                    format_args!("original packet forwarded unchanged: {error}"),
                                );
                                admit(&reporter)?;
                                owner.dns.reply(token, ipc::Decision::Forward)?;
                                Choice::Forward
                            }
                        },
                    };
                    if settings.verbosity != 0 {
                        reporter.message(
                            Level::INFO,
                            "dns.utility.admitted",
                            format_args!("request={token:?} decision={choice:?}"),
                        );
                    }
                    pending.push(Pending { token, choice });
                    packets = packets.saturating_add(1);
                    if settings.packets != 0 && packets >= u64::from(settings.packets) {
                        let drain = Instant::now()
                            .checked_add(Duration::from_secs(5))
                            .ok_or("DNS utility drain deadline overflow")?;
                        draining = Some(until.min(drain));
                    }
                }
                Turn::Dns(Progress::Written(token)) => {
                    let row = pending
                        .iter()
                        .position(|row| row.token == token)
                        .map(|at| pending.swap_remove(at));
                    writes = writes.saturating_add(1);
                    if let Some(row) = row {
                        match row.choice {
                            Choice::Forward if settings.verbosity > 0 => reporter.message(
                                Level::INFO,
                                "dns.utility.written",
                                format_args!("Forward request={token:?}"),
                            ),
                            Choice::Answer { records } if settings.verbosity > 0 => reporter
                                .message(
                                    Level::INFO,
                                    "dns.utility.written",
                                    format_args!("Answer request={token:?} records={records}"),
                                ),
                            Choice::TimeoutDrop => reporter.warning(
                                "dns.utility.written",
                                format_args!("timeout Drop request={token:?}"),
                            ),
                            _ => {}
                        }
                    }
                    if draining.is_some() && pending.is_empty() {
                        break;
                    }
                }
                Turn::Dns(Progress::Dropping(token)) => {
                    if let Some(row) = pending.iter_mut().find(|row| row.token == token) {
                        row.choice = Choice::TimeoutDrop;
                    }
                    reporter.warning(
                        "dns.utility.expired",
                        format_args!("original callback Drop admitted: {token:?}"),
                    );
                }
                Turn::Dns(Progress::Lost {
                    epoch,
                    cause,
                    requests,
                }) => {
                    reporter.warning(
                        "dns.utility.lost",
                        format_args!("source={epoch:?} cause={cause:?} callbacks={requests}"),
                    );
                    pending.clear();
                    if draining.is_some() {
                        break;
                    }
                    owner.dns.reconnect()?;
                }
                Turn::Dns(Progress::Connected(epoch)) => {
                    if settings.verbosity > 0 {
                        reporter.message(
                            Level::INFO,
                            "dns.utility.connected",
                            format_args!("{epoch:?}"),
                        );
                    }
                }
                Turn::Dns(Progress::InitWritten(epoch)) => reporter.debug(
                    "dns.utility.initialized",
                    format_args!("INIT whole local write: {epoch:?}"),
                ),
                Turn::Dns(Progress::Retry { error, delay }) => reporter.warning(
                    "dns.utility.retry",
                    format_args!("delay={delay:?}: {error}"),
                ),
                Turn::Dns(Progress::Unavailable(error)) => {
                    reporter.warning("dns.utility.unavailable", format_args!("{error}"))
                }
                Turn::Dns(Progress::Activity { .. } | Progress::Wait) => {}
                Turn::Dns(Progress::Closed) => break,
            }
            resolver_first = !resolver_first;
        }
        reporter.message(
            Level::INFO,
            "dns.utility.stopped",
            format_args!(
                "callbacks={packets} whole-local-replies={writes} pending={}",
                pending.len()
            ),
        );
        Ok::<(), Failure>(())
    }
    .await;
    let resolver = owner.close();
    Failures {
        task: outcome.err(),
        resolver,
        ..Default::default()
    }
    .finish()
}
