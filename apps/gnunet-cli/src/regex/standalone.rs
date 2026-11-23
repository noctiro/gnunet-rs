//! Configured REGEX PROGRAM with official text and continuous subscriptions.
use super::{
    Announcement, AnnouncementRequest, Deadlines, EndCause, EndpointSource, Instance, Limits,
    Owner, Progress, RelativeTime, Result, Search, exact, ipc,
};
use gnunet_program_host::{
    getopt::Options,
    helpers::{self, Target},
};
use gnunet_service_runtime::clock::{Deadline, RuntimeClock};
use gnunet_service_startup::StopSignals;
use std::{
    collections::HashSet,
    future::{Future, poll_fn},
    io::{self, Write},
    pin::Pin,
    sync::Arc,
    task::Poll,
    time::Duration,
};

const MAX_MATCHES: usize = 65_536;
const SEND_MICROS: u64 = 10_000_000;

#[derive(Clone, Copy)]
enum Action {
    Search,
    Announce {
        refresh: RelativeTime,
        compression: u16,
    },
}

struct Settings {
    action: Action,
    expression: Vec<u8>,
}

struct Arguments {
    announcing: Target<i32>,
    refresh: Target<u64>,
    compression: Target<u16>,
}

impl Arguments {
    fn new() -> Self {
        Self {
            announcing: Target::new(0),
            refresh: Target::new(0),
            compression: Target::new(0),
        }
    }

    fn options(&self) -> Options<'static> {
        let mut options = Options::new();
        options.add(helpers::flag(
            b'a',
            b"announce",
            b"Flag to announce an expression",
            self.announcing.clone(),
        ));
        options.add(helpers::relative_time(
            b'r',
            b"refresh",
            b"DELAY",
            b"Refresh delay of announcement",
            self.refresh.clone(),
        ));
        options.add(helpers::uint16(
            b'c',
            b"compression",
            b"AMOUNT",
            b"Amount of characters per edge to squeeze",
            self.compression.clone(),
        ));
        options
    }

    fn settings(&self, args: &[Vec<u8>]) -> Result<Settings> {
        let action = if self.announcing.get()? != 0 {
            Action::Announce {
                refresh: RelativeTime::from_micros(self.refresh.get()?),
                compression: self.compression.get()?,
            }
        } else {
            Action::Search
        };
        if let Action::Announce { refresh, .. } = action
            && refresh != RelativeTime::ZERO
            && refresh != RelativeTime::FOREVER
        {
            std::time::Instant::now()
                .checked_add(Duration::from_micros(refresh.as_micros()))
                .ok_or("REGEX refresh timer cannot be represented by this host")?;
        }
        let expression = expression(&action, args)?;
        Ok(Settings { action, expression })
    }
}

fn expression(action: &Action, args: &[Vec<u8>]) -> Result<Vec<u8>> {
    let expression_size = args
        .iter()
        .try_fold(args.len().saturating_sub(1), |size, arg| {
            size.checked_add(arg.len())
                .ok_or("REGEX expression size overflow")
        })?;
    let maximum = Limits::default().frame_bytes;
    let base = ipc::StringBytes::new(b"")?;
    let prefix = match action {
        Action::Search => ipc::Request::Search { string: base }.encoded_len()?,
        Action::Announce {
            refresh,
            compression,
        } => ipc::Request::Announce {
            compression: *compression,
            reserved: 0,
            refresh_delay: *refresh,
            regex: base,
        }
        .encoded_len()?,
    };
    if expression_size > maximum.saturating_sub(prefix) {
        return Err("REGEX expression exceeds official frame bound".into());
    }
    let mut value = Vec::new();
    value.try_reserve_exact(expression_size)?;
    for (index, arg) in args.iter().enumerate() {
        if index != 0 {
            value.push(b' ');
        }
        value.extend_from_slice(arg);
    }
    ipc::StringBytes::new(&value)?;
    Ok(value)
}

fn print_peer(out: &mut impl Write, peer: &[u8; 32]) -> Result<()> {
    let mut encoded = [0; 52];
    let size = gnunet::gnsrecord::encode_base32(peer, &mut encoded)?;
    out.write_all(&encoded[..size])?;
    Ok(())
}

fn print_match(out: &mut impl Write, result: ipc::SearchResult<'_>) -> Result<()> {
    print_peer(out, &result.peer)?;
    writeln!(
        out,
        " ( get: {}, put: {} )",
        result.get_path.len(),
        result.put_path.len()
    )?;
    for peer in result.get_path {
        out.write_all(b" - get: ")?;
        print_peer(out, peer)?;
        writeln!(out)?;
    }
    for peer in result.put_path {
        out.write_all(b" - put: ")?;
        print_peer(out, peer)?;
        writeln!(out)?;
    }
    out.flush()?;
    Ok(())
}

fn publish_match(
    out: &mut impl Write,
    seen: &mut HashSet<[u8; 64]>,
    result: ipc::SearchResult<'_>,
) -> Result<()> {
    let mut key = [0; 64];
    gnunet::crypto::hkdf_gnunet(
        b"regex_match",
        &result.peer,
        &[
            result.get_path.as_flattened(),
            result.put_path.as_flattened(),
        ],
        &mut key,
    )?;
    if seen.contains(&key) {
        return Ok(());
    }
    if seen.len() == MAX_MATCHES {
        return Err("REGEX distinct match capacity exhausted".into());
    }
    seen.try_reserve(1)?;
    print_match(out, result)?;
    let _inserted = seen.insert(key);
    Ok(())
}

fn print_announcement(out: &mut impl Write, expression: &[u8]) -> Result<()> {
    out.write_all(b"> ")?;
    out.write_all(expression)?;
    writeln!(out)?;
    out.flush()?;
    Ok(())
}

fn marker(
    clock: &Arc<dyn RuntimeClock>,
    refresh: RelativeTime,
) -> Result<Option<Pin<Box<Deadline>>>> {
    if refresh == RelativeTime::ZERO || refresh == RelativeTime::FOREVER {
        return Ok(None);
    }
    let target = clock
        .sample()?
        .now
        .as_micros()
        .checked_add(refresh.as_micros())
        .filter(|target| *target != u64::MAX)
        .ok_or("REGEX refresh deadline overflow")?;
    Ok(Some(Box::pin(Deadline::at(
        clock.clone(),
        gnunet_types::AbsoluteTime::from_micros(target),
    )?)))
}

enum Step<'id> {
    Stop,
    Refresh,
    Client(Progress<'id>),
}

async fn observe<'id>(
    owner: &mut Owner<'id>,
    signals: &mut StopSignals,
    refresh: &mut Option<Pin<Box<Deadline>>>,
) -> Result<Step<'id>> {
    let mut driving = std::pin::pin!(owner.drive(None));
    poll_fn(|cx| {
        if let Poll::Ready(result) = signals.poll_stop(cx) {
            return Poll::Ready(result.map(|()| Step::Stop).map_err(Into::into));
        }
        if let Poll::Ready(result) = driving.as_mut().poll(cx) {
            return Poll::Ready(result.map(Step::Client).map_err(Into::into));
        }
        if let Some(timer) = refresh
            && let Poll::Ready(result) = timer.as_mut().poll(cx)
        {
            return Poll::Ready(result.map(|()| Step::Refresh).map_err(Into::into));
        }
        Poll::Pending
    })
    .await
}

fn ended(cause: EndCause) -> Box<dyn std::error::Error> {
    match cause {
        EndCause::Io(error) => Box::new(error),
        EndCause::Ports(error) => Box::new(error),
        EndCause::Protocol(error) | EndCause::Resource(error) | EndCause::Clock(error) => {
            Box::new(error)
        }
        cause => format!("REGEX subscription ended: {cause:?}").into(),
    }
}

async fn execute(source: EndpointSource, settings: Settings) -> Result<()> {
    let clock = source.clock();
    let now = clock.sample()?.now.as_micros();
    let send = now
        .checked_add(SEND_MICROS)
        .ok_or("REGEX send deadline overflow")?;
    let instance = Instance::new();
    let limits = Limits::default();
    let refresh = match settings.action {
        Action::Search => None,
        Action::Announce { refresh, .. } => Some(refresh),
    };
    let deadlines = Deadlines {
        send_until: send,
        first_result_until: refresh.is_none().then_some(u64::MAX),
        until: if refresh == Some(RelativeTime::ZERO) {
            send
        } else {
            u64::MAX
        },
    };
    let mut owner = match settings.action {
        Action::Search => Owner::Search(Search::new(
            &instance,
            source,
            &settings.expression,
            deadlines,
            limits,
        )?),
        Action::Announce {
            refresh,
            compression,
        } => Owner::Announcement(Announcement::new(
            &instance,
            source,
            AnnouncementRequest {
                regex: &settings.expression,
                compression,
                refresh_delay: refresh,
            },
            deadlines,
            limits,
        )?),
    };
    let mut signals = StopSignals::for_client(None)?;
    let mut out = io::stdout().lock();
    let mut seen = HashSet::new();
    let mut timer = None;
    let mut announced = false;
    let result = async {
        loop {
            match observe(&mut owner, &mut signals, &mut timer).await? {
                Step::Stop => return Ok(()),
                Step::Refresh => {
                    print_announcement(&mut out, &settings.expression)?;
                    timer = marker(
                        &clock,
                        refresh.ok_or("REGEX search received an announcement timer")?,
                    )?;
                    tokio::task::yield_now().await;
                }
                Step::Client(Progress::Submitted { job, epoch, .. }) => {
                    exact(&owner, job, epoch)?;
                    if let Some(refresh) = refresh
                        && !announced
                    {
                        print_announcement(&mut out, &settings.expression)?;
                        if refresh == RelativeTime::ZERO {
                            return Ok(());
                        }
                        announced = true;
                        timer = marker(&clock, refresh)?;
                    }
                }
                Step::Client(Progress::ResultReady {
                    job,
                    epoch,
                    ordinal,
                }) => {
                    exact(&owner, job, epoch)?;
                    let view = owner.result()?.ok_or("REGEX result was not retained")?;
                    if (view.job, view.epoch, view.ordinal) != (job, epoch, ordinal) {
                        return Err(
                            "REGEX result no longer belongs to the original job and source".into(),
                        );
                    }
                    publish_match(&mut out, &mut seen, view.result)?;
                    owner.release()?;
                }
                Step::Client(Progress::Ended(end)) => return Err(ended(end.cause)),
                Step::Client(Progress::Unavailable(error)) => return Err(error.into()),
                Step::Client(Progress::Closed | Progress::WaitDeadline) => {
                    return Err("REGEX client stopped without a terminal observation".into());
                }
                Step::Client(_) => {}
            }
        }
    }
    .await;
    let _closed = owner.close();
    result
}

pub(crate) fn run() -> Result<()> {
    let args = Arguments::new();
    let Some((prepared, clock)) = crate::configured::prepare(
        b"gnunet-regex",
        b"Announce regular expressions and observe announcing peers.",
        args.options(),
    )?
    else {
        return Ok(());
    };
    let main = prepared.main();
    let settings = args.settings(main.arguments)?;
    crate::configured::run(main.config, clock, [b"regex"], move |[source]| {
        execute(source, settings)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_regex_output_joins_arguments_and_deduplicates_paths() -> Result<()> {
        if expression(&Action::Search, &[b"one".to_vec(), b"two three".to_vec()])?
            != b"one two three"
            || !expression(&Action::Search, &[])?.is_empty()
        {
            return Err("REGEX positional expression changed".into());
        }
        let mut output = Vec::new();
        let mut seen = HashSet::new();
        let get = [[0; 32]];
        let result = ipc::SearchResult {
            peer: [0; 32],
            get_path: &get,
            put_path: &[],
        };
        publish_match(&mut output, &mut seen, result)?;
        publish_match(&mut output, &mut seen, result)?;
        let zero = "0".repeat(52);
        let expected = format!("{zero} ( get: 1, put: 0 )\n - get: {zero}\n");
        if output != expected.as_bytes() {
            return Err("REGEX peer/path text or repeat filtering changed".into());
        }
        Ok(())
    }
}
