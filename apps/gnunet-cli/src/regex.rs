//! Actual original-MQ REGEX search/announcement, with no fabricated ACK or DONE.
use super::peer::hexadecimal;
use gnunet::clients::regex::{
    self as native, Announcement, AnnouncementRequest, Deadlines, End, EndCause, EndpointSource,
    Epoch, Instance, Job, Limits, Progress, RelativeTime, ResultView, Search, Submission, ipc,
};
use std::{
    error::Error,
    ffi::{OsStr, OsString},
    future::{Future, poll_fn},
    io::{self, Write},
    os::unix::ffi::OsStrExt,
    path::PathBuf,
    pin::Pin,
    task::Poll,
    time::Duration,
};
use tokio::time::Instant;
type Result<T> = std::result::Result<T, Box<dyn Error>>;
#[derive(Clone, Copy, Eq, PartialEq)]
enum Action {
    Search,
    Announce,
}
struct Command<'a> {
    action: Action,
    socket: PathBuf,
    expression: &'a [u8],
    timeout_ms: u64,
    send_ms: u64,
    first_ms: u64,
    maximum: u64,
    hold_ms: u64,
    compression: u16,
    refresh: RelativeTime,
    limits: Limits,
}
fn text(value: &OsStr) -> Result<&str> {
    value
        .to_str()
        .ok_or_else(|| "expected an ASCII REGEX option".into())
}
fn parse(args: &[OsString]) -> Result<Command<'_>> {
    let action = match args.first().map(OsString::as_os_str) {
        Some(a) if a == "search" => Action::Search,
        Some(a) if a == "announce" => Action::Announce,
        _ => return Err("expected regex search|announce; see regex --help".into()),
    };
    let socket = PathBuf::from(args.get(1).ok_or("missing explicit REGEX UNIXPATH")?);
    let expression = args
        .get(2)
        .ok_or("missing literal search string or announcement expression")?
        .as_os_str()
        .as_bytes();
    let (
        mut timeout_ms,
        mut send,
        mut first,
        mut maximum,
        mut hold_ms,
        mut compression,
        mut refresh,
    ) = match action {
        Action::Search => (30_000u64, None, None, 1u64, 0u64, 0u16, RelativeTime::ZERO),
        Action::Announce => (
            315_000u64,
            None,
            None,
            1u64,
            300_000u64,
            0u16,
            RelativeTime::from_micros(300_000_000),
        ),
    };
    let mut limits = Limits::default();
    let mut at = 3;
    while at < args.len() {
        let flag = text(&args[at])?;
        let value = text(args.get(at + 1).ok_or("missing REGEX option value")?)?;
        at += 2;
        match flag {
            "--timeout-ms" => timeout_ms = value.parse()?,
            "--send-timeout-ms" => send = Some(value.parse::<u64>()?),
            "--first-result-ms" if action == Action::Search => first = Some(value.parse::<u64>()?),
            "--max-results" if action == Action::Search => maximum = value.parse()?,
            "--hold-ms" if action == Action::Announce => hold_ms = value.parse()?,
            "--compression" | "-c" if action == Action::Announce => compression = value.parse()?,
            "--refresh-ms" | "-r" if action == Action::Announce => {
                refresh = if value == "forever" {
                    RelativeTime::FOREVER
                } else {
                    RelativeTime::from_micros(
                        value
                            .parse::<u64>()?
                            .checked_mul(1000)
                            .ok_or("refresh duration overflow")?,
                    )
                }
            }
            "--io-slice-bytes" => limits.io_slice_bytes = value.parse()?,
            "--path-entries" => limits.path_entries = value.parse()?,
            _ => return Err(format!("unknown or inapplicable REGEX option: {flag}").into()),
        }
    }
    let send_ms = send.unwrap_or(timeout_ms.min(10_000));
    let first_ms = first.unwrap_or(timeout_ms);
    if timeout_ms == 0
        || send_ms == 0
        || send_ms > timeout_ms
        || first_ms < send_ms
        || first_ms > timeout_ms
        || hold_ms > timeout_ms
        || limits.io_slice_bytes == 0
        || limits.path_entries > Limits::default().path_entries
    {
        return Err("invalid finite REGEX deadline/resource bounds".into());
    }
    // Request/size validation precedes constructing a runtime/native source.
    let string = ipc::StringBytes::new(expression)?;
    let size = match action {
        Action::Search => ipc::Request::Search { string }.encoded_len()?,
        Action::Announce => ipc::Request::Announce {
            compression,
            reserved: 0,
            refresh_delay: refresh,
            regex: string,
        }
        .encoded_len()?,
    };
    if size > limits.frame_bytes {
        return Err("REGEX expression exceeds official frame bound".into());
    }
    let duration = Duration::from_millis(timeout_ms);
    if std::time::Instant::now().checked_add(duration).is_none()
        || timeout_ms.checked_mul(1000).is_none()
    {
        return Err("REGEX timeout is not representable".into());
    }
    Ok(Command {
        action,
        socket,
        expression,
        timeout_ms,
        send_ms,
        first_ms,
        maximum,
        hold_ms,
        compression,
        refresh,
        limits,
    })
}
fn row(out: &mut impl Write, value: serde_json::Value) -> Result<()> {
    serde_json::to_writer(&mut *out, &value)?;
    writeln!(out)?;
    out.flush()?;
    Ok(())
}
fn submission(value: Submission) -> serde_json::Value {
    match value {
        Submission::Unsent => serde_json::json!({"kind":"unsent","bytes":0}),
        Submission::Partial { bytes, total } => {
            serde_json::json!({"kind":"partial","bytes":bytes,"total":total})
        }
        Submission::Written { bytes } => serde_json::json!({"kind":"written","bytes":bytes}),
    }
}
fn ending(out: &mut impl Write, end: &End<'_>, policy: &str, results: u64) -> Result<()> {
    row(
        out,
        serde_json::json!({"event":"regex_local_end","policy":policy,"job":end.job.diagnostic(),"source_epoch":end.epoch.map(Epoch::diagnostic),"retired_mq":end.retired_mq,"queued":end.queued,"write":end.write.map(native::WriteId::diagnostic),"submission":submission(end.submission),"cause":format!("{:?}",end.cause),"observed_results":results,"wire_done":false,"remote_cancel_ack":false,"exhaustive_search":false,"publication_ack":false}),
    )
}
enum Owner<'id> {
    Search(Search<'id>),
    Announcement(Announcement<'id>),
}
impl<'id> Owner<'id> {
    fn job(&self) -> Job<'id> {
        match self {
            Self::Search(s) => s.job(),
            Self::Announcement(a) => a.job(),
        }
    }
    fn epoch(&self) -> Option<Epoch<'id>> {
        match self {
            Self::Search(s) => s.epoch(),
            Self::Announcement(a) => a.epoch(),
        }
    }
    fn close(&mut self) -> Option<End<'id>> {
        match self {
            Self::Search(s) => s.close(),
            Self::Announcement(a) => a.close(),
        }
    }
    fn cancel(&mut self) -> Option<End<'id>> {
        match self {
            Self::Search(s) => s.cancel(),
            Self::Announcement(a) => a.cancel(),
        }
    }
    async fn drive(
        &mut self,
        until: Option<Instant>,
    ) -> std::result::Result<Progress<'id>, native::Error> {
        match self {
            Self::Search(s) => s.drive(until).await,
            Self::Announcement(a) => a.drive(until).await,
        }
    }
    fn result(&self) -> Result<Option<ResultView<'_, 'id>>> {
        match self {
            Self::Search(s) => Ok(s.result()?),
            Self::Announcement(_) => Err("announcement received an unexpected RESULT".into()),
        }
    }
    fn release(&mut self) -> Result<()> {
        match self {
            Self::Search(s) => Ok(s.release_result()?),
            Self::Announcement(_) => Err("announcement has no RESULT to release".into()),
        }
    }
}
async fn wait<'id>(
    owner: &mut Owner<'id>,
    until: Instant,
    mut interrupt: Pin<&mut impl Future<Output = io::Result<()>>>,
) -> Result<Option<Progress<'id>>> {
    let mut driving = std::pin::pin!(owner.drive(Some(until)));
    poll_fn(|cx| {
        if let Poll::Ready(value) = interrupt.as_mut().poll(cx) {
            return Poll::Ready(value.map(|()| None).map_err(Into::into));
        }
        driving
            .as_mut()
            .poll(cx)
            .map(|r| r.map(Some).map_err(Into::into))
    })
    .await
}
fn exact(owner: &Owner<'_>, job: Job<'_>, epoch: Epoch<'_>) -> Result<()> {
    if owner.job() != job || owner.epoch() != Some(epoch) {
        return Err("REGEX response targeted a different original job/source".into());
    }
    Ok(())
}
fn finish(owner: &mut Owner<'_>, out: &mut impl Write, policy: &str, results: u64) -> Result<()> {
    let end = owner
        .cancel()
        .ok_or("original REGEX source ended without a cancellation receipt")?;
    ending(out, &end, policy, results)
}
async fn observe(
    owner: &mut Owner<'_>,
    command: &Command<'_>,
    hard: Instant,
    logical_until: u64,
    out: &mut impl Write,
) -> Result<()> {
    let interrupt = tokio::signal::ctrl_c();
    let mut interrupt = std::pin::pin!(interrupt);
    let (mut results, mut written, mut hold) = (0u64, false, None);
    loop {
        let observed_now = Instant::now();
        if observed_now < hard && hold.is_some_and(|until| observed_now >= until) {
            if !written {
                finish(owner, out, "announcement_hold_source_lost", results)?;
                return Err("REGEX original hold ended before source restoration; no publication acknowledgement exists".into());
            }
            finish(owner, out, "announcement_hold_complete", results)?;
            return Ok(());
        }
        let until = hold.map_or(hard, |until: Instant| until.min(hard));
        let Some(progress) = wait(owner, until, interrupt.as_mut()).await? else {
            finish(owner, out, "ctrl_c", results)?;
            return Err(
                "REGEX cancelled locally; no remote revocation acknowledgement exists".into(),
            );
        };
        match progress {
            Progress::Connected { job, epoch } => {
                exact(owner, job, epoch)?;
                row(
                    out,
                    serde_json::json!({"event":"regex_connected","job":job.diagnostic(),"source_epoch":epoch.diagnostic()}),
                )?;
            }
            Progress::Queued { job, epoch, write } => {
                exact(owner, job, epoch)?;
                row(
                    out,
                    serde_json::json!({"event":"regex_queued","job":job.diagnostic(),"source_epoch":epoch.diagnostic(),"write":write.diagnostic(),"local_only":true,"publication_ack":false}),
                )?;
            }
            Progress::Submitted { job, epoch, write } => {
                exact(owner, job, epoch)?;
                written = true;
                row(
                    out,
                    serde_json::json!({"event":"regex_written","job":job.diagnostic(),"source_epoch":epoch.diagnostic(),"write":write.diagnostic(),"whole_local_write":true,"publication_ack":false,"dht_visibility":"unknown"}),
                )?;
                if command.action == Action::Announce {
                    if command.hold_ms == 0 {
                        finish(owner, out, "announcement_written", results)?;
                        return Ok(());
                    }
                    let began = Instant::now();
                    if hold.is_none() {
                        hold = Some(
                            began
                                .checked_add(Duration::from_millis(command.hold_ms))
                                .ok_or("announcement hold deadline overflow")?,
                        );
                    }
                    row(
                        out,
                        serde_json::json!({"event":"regex_announcement_holding","job":job.diagnostic(),"source_epoch":epoch.diagnostic(),"hold_ms":command.hold_ms,"refresh_micros":command.refresh.as_micros(),"command_absolute_deadline_micros":logical_until,"remaining_native_budget_ms":hard.saturating_duration_since(began).as_millis(),"actual_mq_retained":true,"may_end_early_on_loss_or_deadline":true,"publication_ack":false}),
                    )?;
                }
            }
            Progress::ResultReady {
                job,
                epoch,
                ordinal,
            } => {
                exact(owner, job, epoch)?;
                let view = owner
                    .result()?
                    .ok_or("REGEX actual RESULT was not retained")?;
                if view.job != job || view.epoch != epoch || view.ordinal != ordinal {
                    return Err("REGEX RESULT metadata differs from original observation".into());
                }
                row(
                    out,
                    serde_json::json!({"event":"regex_result","job":job.diagnostic(),"source_epoch":epoch.diagnostic(),"ordinal":ordinal,"observed_at_micros":view.observed_at,"peer_hex":hexadecimal(&view.result.peer),"get_path_hex":view.result.get_path.iter().map(|p|hexadecimal(p)).collect::<Vec<_>>(),"put_path_hex":view.result.put_path.iter().map(|p|hexadecimal(p)).collect::<Vec<_>>(),"authenticated_peer":false}),
                )?;
                owner.release()?;
                results = results
                    .checked_add(1)
                    .ok_or("REGEX result counter overflow")?;
                if command.maximum != 0 && results >= command.maximum {
                    finish(owner, out, "result_limit", results)?;
                    return Ok(());
                }
            }
            Progress::SourceLost { end, retry_after } => {
                if end.job != owner.job() || end.epoch != owner.epoch() {
                    return Err("REGEX source loss targeted a different original job/source".into());
                }
                written = false;
                row(
                    out,
                    serde_json::json!({
                        "event":"regex_source_lost", "job":end.job.diagnostic(),
                        "source_epoch":end.epoch.map(Epoch::diagnostic),
                        "retired_mq":end.retired_mq, "queued":end.queued, "write":end.write.map(native::WriteId::diagnostic),
                        "submission":submission(end.submission), "cause":format!("{:?}", end.cause),
                        "retry_after_micros":retry_after.as_micros(),
                        "logical_job_continues":true, "command_absolute_deadline_micros":logical_until,
                        "publication_ack":false, "prior_dht_publication":"unknown"
                    }),
                )?;
            }
            Progress::Ended(end) => {
                if end.job != owner.job() || end.epoch != owner.epoch() {
                    return Err("REGEX end targeted a different original source".into());
                }
                let reason = match &end.cause {
                    EndCause::FirstResultDeadline
                    | EndCause::LifetimeDeadline
                    | EndCause::SendDeadline
                    | EndCause::GraceDeadline => "deadline_inconclusive",
                    EndCause::Eof => "eof_inconclusive",
                    _ => "native_end_inconclusive",
                };
                let output = ending(out, &end, reason, results);
                let original:Box<dyn Error>=match end.cause {
                    EndCause::Io(error)=>Box::new(error),
                    EndCause::Ports(error)=>Box::new(error),
                    EndCause::Protocol(error)|EndCause::Resource(error)|EndCause::Clock(error)=>Box::new(error),
                    _=>format!("REGEX {reason}; observed {results} results, local whole write={written}; no exhaustive empty set or publication acknowledgement").into(),
                };
                if let Err(secondary) = output {
                    let _diagnostic = writeln!(
                        io::stderr().lock(),
                        "REGEX end output also failed: {secondary}"
                    );
                }
                return Err(original);
            }
            Progress::WaitDeadline => {
                if command.action == Action::Announce
                    && hold.is_some_and(|until| Instant::now() >= until)
                    && Instant::now() < hard
                {
                    if written {
                        finish(owner, out, "announcement_hold_complete", results)?;
                        return Ok(());
                    }
                    finish(owner, out, "announcement_hold_source_lost", results)?;
                    return Err("REGEX original hold ended before source restoration".into());
                }
                finish(owner, out, "observation_deadline_inconclusive", results)?;
                return Err(format!(
                    "REGEX observation deadline is inconclusive ({results} results observed)"
                )
                .into());
            }
            Progress::Unavailable(error) => return Err(error.into()),
            Progress::ConnectRetry { error, retry_after } => row(
                out,
                serde_json::json!({"event":"regex_connect_retry","error":error.to_string(),"retry_after_micros":retry_after.as_micros()}),
            )?,
            Progress::Activity { .. } => {}
            Progress::Closed => {
                return Err("REGEX owner closed without its original end observation".into());
            }
        }
    }
}
pub(super) fn run(args: &[OsString], out: &mut impl Write) -> Result<()> {
    if args.is_empty() || args.first().is_some_and(|a| a == "--help" || a == "-h") {
        writeln!(
            out,
            "regex search <UNIXPATH> <STRING> [--max-results N] [--first-result-ms N] [options]"
        )?;
        writeln!(
            out,
            "regex announce <UNIXPATH> <EXPRESSION> [--compression N|-c N] [--refresh-ms N|forever|-r N] [--hold-ms N] [options]"
        )?;
        writeln!(
            out,
            "Options: --timeout-ms N --send-timeout-ms N --io-slice-bytes N --path-entries N"
        )?;
        writeln!(
            out,
            "Defaults: search overall30000 ms and1 actual result (--max-results0 streams until deadline); announce overall315000 ms, hold300000 ms, refresh300000 ms, compression0. Send min(10000,overall) ms. Explicit --hold-ms0 exits only after whole local write. Quote one exact expression/string argument. Only original Queued/whole local write are reported for announce, without publication ACK. Source EOF/IO emits actual old-source exposure and reconnects the same registration under unchanged first-result/overall and announcement-hold deadlines. Deadlines are inconclusive, never wire DONE/no-match proof. Ctrl-C closes the current attempt/MQ without restoration or remote revocation ACK."
        )?;
        return Ok(());
    }
    let command = parse(args)?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let source = EndpointSource::unix(command.socket.clone());
            let now = source.clock().sample()?.now.as_micros();
            let target = |ms: u64| -> Result<u64> {
                now.checked_add(ms.checked_mul(1000).ok_or("REGEX deadline overflow")?)
                    .filter(|n| *n < u64::MAX)
                    .ok_or_else(|| "REGEX absolute deadline overflow".into())
            };
            let deadlines = Deadlines {
                send_until: target(command.send_ms)?,
                first_result_until: if command.action == Action::Search {
                    Some(target(command.first_ms)?)
                } else {
                    None
                },
                until: target(command.timeout_ms)?,
            };
            let hard = Instant::now()
                .checked_add(Duration::from_millis(command.timeout_ms))
                .ok_or("REGEX native deadline overflow")?;
            let instance = Instance::new();
            let mut owner = match command.action {
                Action::Search => Owner::Search(Search::new(
                    &instance,
                    source,
                    command.expression,
                    deadlines,
                    command.limits,
                )?),
                Action::Announce => Owner::Announcement(Announcement::new(
                    &instance,
                    source,
                    AnnouncementRequest {
                        regex: command.expression,
                        compression: command.compression,
                        refresh_delay: command.refresh,
                    },
                    deadlines,
                    command.limits,
                )?),
            };
            let result = observe(&mut owner, &command, hard, deadlines.until, out).await;
            // Independent actual close precedes any cleanup output and needs no
            // clock read, including writer/interrupt/source-port error paths.
            let cleanup = owner
                .close()
                .map(|end| ending(out, &end, "cleanup_after_error", 0));
            match (result, cleanup) {
                (Err(error), _) => Err(error),
                (Ok(()), Some(Err(error))) => Err(error),
                (Ok(()), _) => Ok(()),
            }
        })
}
