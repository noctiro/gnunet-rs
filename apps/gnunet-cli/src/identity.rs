//! Explicit public/private IDENTITY commands driven by the production original-MQ client.
use super::peer::hexadecimal;
mod crypt;
mod keys;
mod messages;
mod standalone;
use gnunet::{
    clients::identity::{
        Client, EndpointSource, Instance, KeyType, Limits, Lookup, LookupOutcome, LookupProgress,
        Operation, Outcome, Progress, SecretKey, ipc,
    },
    crypto::Entropy,
    types::Error as Fault,
};
use serde_json::{Value, json};
use std::{
    error::Error,
    ffi::{OsStr, OsString},
    future::{Future, poll_fn},
    io::{self, Write},
    path::PathBuf,
    pin::Pin,
    task::Poll,
    time::Duration,
};
use tokio::time::Instant;
use zeroize::Zeroizing;
type Result<T> = std::result::Result<T, Box<dyn Error>>;
pub(super) use standalone::run as run_standalone;

async fn interrupt() -> io::Result<()> {
    let mut signals = gnunet_service_runtime::signals::Termination::new()?;
    poll_fn(|cx| signals.poll_stop(cx)).await
}

async fn observed<T, E: Error + 'static>(
    progress: impl Future<Output = std::result::Result<T, E>>,
    mut signal: Pin<&mut impl Future<Output = io::Result<()>>>,
) -> Result<Option<T>> {
    let mut progress = std::pin::pin!(progress);
    poll_fn(|cx| {
        if let Poll::Ready(result) = signal.as_mut().poll(cx) {
            return Poll::Ready(
                result
                    .map(|()| None)
                    .map_err(|e| Box::new(e) as Box<dyn Error>),
            );
        }
        progress
            .as_mut()
            .poll(cx)
            .map(|r| r.map(Some).map_err(|e| Box::new(e) as Box<dyn Error>))
    })
    .await
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Action {
    List,
    Monitor,
    Lookup,
    Suffix,
    Export,
    Decrypt,
    Create,
    Rename,
    Delete,
}
#[derive(Clone, Copy)]
enum Display {
    Json,
    Text { quiet: bool, verbose: bool },
}
impl Display {
    fn event(self, out: &mut impl Write, event: impl FnOnce() -> Value) -> Result<()> {
        if matches!(self, Self::Json) {
            row(out, event())?;
        }
        Ok(())
    }
    fn ego(
        self,
        out: &mut impl Write,
        event: &str,
        name: &[u8],
        key: &SecretKey,
        private: bool,
    ) -> Result<()> {
        match self {
            Self::Json => identity_row(out, event, name, key, private),
            Self::Text { quiet, .. } => keys::text(out, (!quiet).then_some(name), key, private),
        }
    }
    fn raw(self) -> bool {
        matches!(self, Self::Text { .. })
    }
}
struct Command {
    action: Action,
    names: Vec<Vec<u8>>,
    filter: Option<Vec<u8>>,
    display: Display,
    key_type: KeyType,
    imported: Option<SecretKey>,
    private_keys: bool,
    encrypted: Option<Zeroizing<Vec<u8>>>,
    timeout: Duration,
    hold: Option<Duration>,
    limits: Limits,
}
fn parse(
    args: &[OsString],
    imported: Option<keys::Imported>,
    encrypted: Option<Zeroizing<Vec<u8>>>,
) -> Result<(Command, PathBuf)> {
    let (action, count) = match args.first().and_then(|s| s.to_str()) {
        Some("list") => (Action::List, 0),
        Some("monitor") => (Action::Monitor, 0),
        Some("lookup") => (Action::Lookup, 1),
        Some("lookup-suffix") => (Action::Suffix, 1),
        Some("export") => (Action::Export, 1),
        Some("decrypt") => (Action::Decrypt, 1),
        Some("create") => (Action::Create, 1),
        Some("rename") => (Action::Rename, 2),
        Some("delete") => (Action::Delete, 1),
        _ => {
            return Err(
                "expected identity list|monitor|lookup|lookup-suffix|export|create|rename|delete|encrypt|decrypt"
                    .into(),
            );
        }
    };
    let socket = PathBuf::from(args.get(1).ok_or("missing explicit IDENTITY UNIXPATH")?);
    if imported.as_ref().is_some_and(|key| key.at < 2 + count) {
        return Err("private key option must follow the identity name".into());
    }
    let names = args.get(2..2 + count).ok_or("missing identity name")?;
    let mut private_keys = action == Action::Export;
    let mut explicit_type = false;
    let mut key_type = KeyType::Eddsa;
    let mut timeout_ms = if action == Action::Monitor {
        330_000
    } else {
        30_000
    };
    let mut hold_ms = 300_000;
    let mut limits = Limits {
        reconnect: false,
        ..Limits::default()
    };
    let mut at = if action == Action::Decrypt {
        4
    } else {
        2 + count
    };
    while at < args.len() {
        if let Some(key) = &imported
            && key.at == at
        {
            at += key.width;
            continue;
        }
        if matches!(args[at].to_str(), Some("--private-keys" | "-p")) {
            if matches!(action, Action::Rename | Action::Delete | Action::Decrypt) {
                return Err(
                    "private output requires list, monitor, lookup, export or create".into(),
                );
            }
            private_keys = true;
            at += 1;
            continue;
        }
        let option = args[at].to_str().ok_or("expected ASCII identity option")?;
        let value = args
            .get(at + 1)
            .and_then(|s| s.to_str())
            .ok_or("missing identity option value")?;
        match option {
            "--type" if action == Action::Create => {
                explicit_type = true;
                key_type = match value {
                    "pkey" | "ecdsa" => KeyType::Ecdsa,
                    "edkey" | "eddsa" => KeyType::Eddsa,
                    _ => return Err("identity type must be pkey|edkey".into()),
                }
            }
            "--timeout-ms" => timeout_ms = value.parse::<u64>()?,
            "--hold-ms" if action == Action::Monitor => hold_ms = value.parse::<u64>()?,
            "--max-egos" if matches!(action, Action::List | Action::Monitor) => {
                limits.egos = value.parse()?
            }
            // Never echo an unrecognized argument: a malformed invocation can
            // place sensitive material where an option name was expected.
            _ => return Err("unknown or inapplicable identity option".into()),
        }
        at += 2;
    }
    if imported.is_some() && (action != Action::Create || explicit_type) {
        return Err("private key import requires create; its embedded type replaces --type".into());
    }
    if timeout_ms == 0
        || limits.egos == 0
        || limits.egos > 65_536
        || action == Action::Monitor && hold_ms > timeout_ms
        || timeout_ms.checked_mul(1000).is_none()
    {
        return Err("invalid finite identity deadline/resource bounds".into());
    }
    let timeout = Duration::from_millis(timeout_ms);
    if Instant::now().checked_add(timeout).is_none() {
        return Err("identity deadline is not representable".into());
    }
    limits.initialization_timeout = timeout;
    let names = names
        .iter()
        .map(|name| {
            let name = crate::argument::wire_bytes(name)?;
            validate_name(name, limits)?;
            Ok(name.to_vec())
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((
        Command {
            action,
            names,
            filter: None,
            display: Display::Json,
            key_type,
            imported: imported.map(|value| value.key),
            private_keys,
            encrypted,
            timeout,
            hold: Some(Duration::from_millis(hold_ms)),
            limits,
        },
        socket,
    ))
}
fn validate_name(name: &[u8], limits: Limits) -> Result<()> {
    if name.len() > limits.name_bytes {
        return Err("identity name exceeds configured bound".into());
    }
    ipc::Request::Lookup { name }.encoded_len()?;
    Ok(())
}
fn row(out: &mut impl Write, value: Value) -> Result<()> {
    serde_json::to_writer(&mut *out, &value)?;
    writeln!(out)?;
    out.flush()?;
    Ok(())
}
/// Explicit private-key export shared by management frontdoors. The secret is
/// streamed from the existing zeroizing fixed buffer, never a JSON Value.
#[cfg(feature = "namestore")]
pub(crate) fn private_key_row(out: &mut impl Write, public: &Value, key: &SecretKey) -> Result<()> {
    keys::row(out, public, key)
}
fn identity_row(
    out: &mut impl Write,
    event: &str,
    name: &[u8],
    key: &SecretKey,
    private: bool,
) -> Result<()> {
    // Only the public serialization is derived and exposed. Opaque secret keys
    // and complete native frames never enter diagnostics or JSON values.
    let public = key.public_key()?;
    let public_row = json!({"event":event,"name":String::from_utf8_lossy(name),"name_bytes":name,"public_key_hex":hexadecimal(&public)});
    if private {
        keys::row(out, &public_row, key)
    } else {
        row(out, public_row)
    }
}

struct Random;
impl Entropy for Random {
    fn fill(&mut self, output: &mut [u8]) -> std::result::Result<(), Fault> {
        gnunet_native::entropy::fill(output).map_err(|_| Fault::Entropy)
    }
}
#[derive(Debug)]
struct Closed {
    epoch: Option<u64>,
    operations: usize,
    exposed: usize,
    egos: usize,
}
impl From<gnunet::clients::identity::Loss<'_>> for Closed {
    fn from(report: gnunet::clients::identity::Loss<'_>) -> Self {
        Self {
            epoch: report.epoch.map(|epoch| epoch.diagnostic()),
            operations: report.operations,
            exposed: report.exposed,
            egos: report.egos,
        }
    }
}
enum Terminal {
    Found,
    Known {
        code: u32,
        material_present: bool,
    },
    Local {
        reason: gnunet::clients::identity::LocalReason,
        submission: gnunet::clients::identity::Submission,
        result_code: Option<u32>,
    },
}
struct SourceLoss {
    report: Closed,
    cause: gnunet::clients::identity::LossCause,
}
#[derive(Default)]
struct Observation {
    operation: Option<u64>,
    terminal: Option<Terminal>,
    loss: Option<SourceLoss>,
}
struct Failures {
    original: Option<Box<dyn Error>>,
    retirement: Option<Box<dyn Error>>,
    diagnostic: Option<Box<dyn Error>>,
    closed: Option<Closed>,
    mutation: Option<Observation>,
}
impl std::fmt::Debug for Terminal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Found => f.write_str("Found([private material redacted])"),
            Self::Known {
                code,
                material_present,
            } => f
                .debug_struct("Known")
                .field("code", code)
                .field("private_material_present", material_present)
                .finish(),
            Self::Local {
                reason,
                submission,
                result_code,
            } => f
                .debug_struct("Local")
                .field("reason", reason)
                .field("submission", submission)
                .field("result_code", result_code)
                .finish(),
        }
    }
}
impl std::fmt::Debug for SourceLoss {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceLoss")
            .field("report", &self.report)
            .field("cause", &self.cause)
            .finish()
    }
}
impl std::fmt::Debug for Observation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Observation")
            .field("operation", &self.operation)
            .field("terminal", &self.terminal)
            .field("loss", &self.loss)
            .finish()
    }
}
impl std::fmt::Debug for Failures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Failures")
            .field("original", &self.original)
            .field("retirement", &self.retirement)
            .field("diagnostic", &self.diagnostic)
            .field("closed", &self.closed)
            .field("mutation", &self.mutation)
            .finish()
    }
}
impl std::fmt::Display for Failures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "identity original/cleanup facts: {self:?}")
    }
}
impl Error for Failures {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        let source = self
            .mutation
            .as_ref()
            .and_then(|state| state.loss.as_ref())
            .and_then(|loss| match &loss.cause {
                gnunet::clients::identity::LossCause::Io(error) => {
                    Some(error as &(dyn Error + 'static))
                }
                gnunet::clients::identity::LossCause::Ports(error) => {
                    Some(error as &(dyn Error + 'static))
                }
                gnunet::clients::identity::LossCause::Protocol(error)
                | gnunet::clients::identity::LossCause::Resource(error) => {
                    Some(error as &(dyn Error + 'static))
                }
                _ => None,
            });
        source
            .or(self.original.as_deref())
            .or(self.retirement.as_deref())
            .or(self.diagnostic.as_deref())
    }
}
fn finish(
    out: &mut impl Write,
    original: Result<()>,
    report: Option<gnunet::clients::identity::Loss<'_>>,
    raw_output: bool,
) -> Result<()> {
    finish_state(out, original, Ok(()), report, raw_output, None)
}
fn finish_state(
    out: &mut impl Write,
    original: Result<()>,
    retirement: Result<()>,
    report: Option<gnunet::clients::identity::Loss<'_>>,
    raw_output: bool,
    mutation: Option<Observation>,
) -> Result<()> {
    let closed = report.map(Closed::from);
    // Keep machine-readable key, envelope and text output free of JSON events.
    let diagnostic = if raw_output {
        out.flush()
            .map_err(|error| Box::new(error) as Box<dyn Error>)
    } else if let Some(report) = &closed {
        row(
            out,
            json!({"event":"identity_source_closed","epoch":report.epoch,"operations":report.operations,"exposed_operations":report.exposed,"invalidated_egos":report.egos}),
        )
    } else {
        Ok(())
    };
    if original.is_err()
        || retirement.is_err()
        || diagnostic.is_err()
        || mutation.as_ref().is_some_and(|state| state.loss.is_some())
    {
        return Err(Box::new(Failures {
            original: original.err(),
            retirement: retirement.err(),
            diagnostic: diagnostic.err(),
            closed,
            mutation,
        }));
    }
    Ok(())
}
async fn lookup(
    command: &Command,
    source: EndpointSource,
    hard: Instant,
    until: u64,
    out: &mut impl Write,
) -> Result<()> {
    let instance = Instance::new();
    let clock = source.clock();
    let name = command.names[0].as_slice();
    let mut lookup = if command.action == Action::Suffix {
        Lookup::by_suffix(&instance, source, name, until, command.limits)?
    } else {
        Lookup::exact(&instance, source, name, until, command.limits)?
    };
    let mut state = Observation {
        operation: Some(lookup.operation().diagnostic()),
        ..Observation::default()
    };
    let result = async {
        let interrupt = interrupt();
        tokio::pin!(interrupt);
        loop {
            if Instant::now() >= hard { return Err("identity lookup deadline".into()); }
            let Some(progress) = observed(lookup.drive(Some(hard)), interrupt.as_mut()).await? else {
                return Err("identity lookup interrupted".into());
            };
            match progress {
                LookupProgress::Finished { outcome: LookupOutcome::Found(identity), .. } => {
                    state.terminal = Some(Terminal::Found);
                    return match command.action {
                        Action::Export => keys::line(out, identity.secret()),
                        Action::Decrypt => messages::decrypt(identity.secret(), command.encrypted.as_ref().ok_or("missing original encrypted message")?, hard, (clock.clone(), until), interrupt.as_mut(), out).await,
                        _ => command.display.ego(out, "identity_found", identity.name(), identity.secret(), command.private_keys),
                    };
                },
                LookupProgress::Finished { outcome: LookupOutcome::ResultCode(code), .. } => {
                    if !matches!(command.action, Action::Export | Action::Decrypt) { command.display.event(out, || json!({"event":"identity_lookup_result","code":code}))?; }
                    return Err(format!("identity lookup returned code {code}").into());
                }
                LookupProgress::Finished { outcome: LookupOutcome::Local { reason, submission, result_code }, .. } => {
                    if !matches!(command.action, Action::Export | Action::Decrypt) { command.display.event(out, || json!({"event":"identity_lookup_local_end","reason":format!("{reason:?}"),"submission":format!("{submission:?}"),"result_code":result_code}))?; }
                    return Err(format!("identity lookup local end: reason={reason:?}, submission={submission:?}, result_code={result_code:?}").into());
                }
                LookupProgress::Source(Progress::Lost { report, cause }) => {
                    if state.loss.is_some() { return Err("repeated original identity lookup source loss".into()); }
                    state.loss = Some(SourceLoss { report: report.into(), cause });
                }
                LookupProgress::Source(Progress::WaitDeadline) => return Err("identity lookup deadline".into()),
                LookupProgress::Source(Progress::Unavailable(error)) => return Err(error.into()),
                LookupProgress::Closed => return Err("identity lookup closed before result".into()),
                _ => {}
            }
        }
    }.await;
    let report = lookup.close();
    finish_state(
        out,
        result,
        Ok(()),
        report,
        command.display.raw() || matches!(command.action, Action::Export | Action::Decrypt),
        Some(state),
    )
}
async fn monitor(
    command: &Command,
    source: EndpointSource,
    hard: Instant,
    out: &mut impl Write,
) -> Result<()> {
    let instance = Instance::new();
    let mut client = Client::monitor(&instance, source, command.limits)?;
    let mut state = Observation::default();
    let result = async {
        let interrupt = interrupt();
        tokio::pin!(interrupt);
        let mut initialized = false;
        let mut end = None;
        loop {
            if end.is_some_and(|end| Instant::now() >= end) {
                return command.display.event(out, || json!({"event":"identity_monitor_stopped","reason":"hold_elapsed"}));
            }
            let observation = if initialized && command.hold.is_none() { None } else { Some(end.map_or(hard, |end: Instant| hard.min(end))) };
            if observation.is_some_and(|target| Instant::now() >= target) { return Err("identity initialization/overall deadline".into()); }
            let Some(progress) = observed(client.drive(observation), interrupt.as_mut()).await? else {
                return command.display.event(out, || json!({"event":"identity_monitor_stopped","reason":"interrupt"}));
            };
            match progress {
                Progress::Ego { ego, change, initial } => {
                    let ego = client.ego(ego)?;
                    if !command.filter.as_deref().is_none_or(|name| name == ego.name()) { continue; }
                    command.display.ego(out, if initial { "identity_initial" } else { match change {
                        gnunet::clients::identity::Change::Added => "identity_added",
                        gnunet::clients::identity::Change::Renamed => "identity_renamed",
                    } }, ego.name(), ego.secret(), command.private_keys)?;
                }
                Progress::Deleted { identity, .. } => {
                    if !command.display.raw() {
                        identity_row(out, "identity_deleted", identity.name(), identity.secret(), command.private_keys)?;
                    }
                }
                Progress::Initialized(_) => {
                    command.display.event(out, || json!({"event":"identity_initialized"}))?;
                    if command.action == Action::List || command.hold.is_some_and(|hold| hold.is_zero()) { return Ok(()); }
                    initialized = true;
                    end = command.hold.map(|hold| Instant::now().checked_add(hold).ok_or("identity hold overflow")).transpose()?;
                }
                Progress::Lost { report, cause } => {
                    state.loss = Some(SourceLoss { report: report.into(), cause });
                    command.display.event(out, || json!({"event":"identity_source_lost","invalidated_egos":report.egos,"cause":format!("{:?}",state.loss.as_ref().map(|loss| &loss.cause))}))?;
                    return Err("identity monitor lost its original source".into());
                }
                Progress::WaitDeadline if end.is_some_and(|end| Instant::now() >= end) => return command.display.event(out, || json!({"event":"identity_monitor_stopped","reason":"hold_elapsed"})),
                Progress::WaitDeadline => return Err("identity initialization/overall deadline".into()),
                Progress::Unavailable(error) => return Err(error.into()),
                Progress::Closed => return Err("identity monitor closed".into()),
                _ => {}
            }
        }
    }.await;
    let report = client.close();
    finish_state(
        out,
        result,
        Ok(()),
        report,
        command.display.raw(),
        Some(state),
    )
}
async fn mutation(
    command: &mut Command,
    source: EndpointSource,
    hard: Instant,
    until: u64,
    out: &mut impl Write,
) -> Result<()> {
    let instance = Instance::new();
    let mut client = Client::new(&instance, source, command.limits)?;
    let name = command.names[0].as_slice();
    let operation = match command.action {
        Action::Create => {
            let key = match command.imported.take() {
                Some(key) => key,
                None => SecretKey::generate(command.key_type, &mut Random)?,
            };
            if Instant::now() >= hard {
                return finish(
                    out,
                    Err("identity deadline before CREATE admission".into()),
                    client.close(),
                    command.display.raw(),
                );
            }
            client.create(name, key, until)?
        }
        Action::Rename => client.rename(name, &command.names[1], until)?,
        Action::Delete => client.delete(name, until)?,
        _ => return Err("invalid identity mutation".into()),
    };
    let mut state = Observation {
        operation: Some(operation.diagnostic()),
        ..Observation::default()
    };
    let result = observe_mutation(
        &mut client,
        operation,
        hard,
        (command.display, command.private_keys),
        out,
        &mut state,
    )
    .await;
    let report = client.close();
    let retirement = retire_mutation(&mut client, operation, &mut state).await;
    finish_state(
        out,
        result,
        retirement,
        report,
        command.display.raw(),
        Some(state),
    )
}
async fn observe_mutation<'id>(
    client: &mut Client<'id>,
    operation: Operation<'id>,
    hard: Instant,
    (display, private_keys): (Display, bool),
    out: &mut impl Write,
    state: &mut Observation,
) -> Result<()> {
    let interrupt = interrupt();
    tokio::pin!(interrupt);
    loop {
        if Instant::now() >= hard {
            return Err(
                "identity operation deadline; exposed mutation outcome may be unknown".into(),
            );
        }
        let Some(progress) = observed(client.drive(Some(hard)), interrupt.as_mut()).await? else {
            return Err(
                "identity operation interrupted; exposed mutation outcome may be unknown".into(),
            );
        };
        match progress {
            Progress::Completed(completion) if completion.operation == operation => {
                match completion.outcome {
                    Outcome::Result { code, created } => {
                        state.terminal = Some(Terminal::Known {
                            code,
                            material_present: created.is_some(),
                        });
                        display.event(out, || json!({"event":"identity_result","code":code}))?;
                        if code != 0 {
                            return Err(format!("identity service returned code {code}").into());
                        }
                        if let Some(key) = created {
                            match display {
                                Display::Json => {
                                    let public = json!({"event":"identity_created","public_key_hex":hexadecimal(&key.public_key()?)});
                                    if private_keys {
                                        keys::row(out, &public, &key)?;
                                    } else {
                                        row(out, public)?;
                                    }
                                }
                                Display::Text { verbose: true, .. } => {
                                    keys::text(out, None, &key, private_keys)?
                                }
                                Display::Text { .. } => {}
                            }
                        }
                        return Ok(());
                    }
                    Outcome::Local {
                        reason,
                        submission,
                        result_code,
                        ..
                    } => {
                        state.terminal = Some(Terminal::Local {
                            reason,
                            submission,
                            result_code,
                        });
                        display.event(
                            out,
                            || json!({"event":"identity_local_end","reason":format!("{reason:?}"),"submission":format!("{submission:?}"),"result_code":result_code}),
                        )?;
                        return Err(
                            "identity operation ended without a normal service result".into()
                        );
                    }
                    Outcome::Found(_) => return Err("unexpected identity mutation response".into()),
                }
            }
            Progress::Completed(_) => return Err("foreign identity completion".into()),
            Progress::Lost { report, cause } => {
                if state.loss.is_some() {
                    return Err("repeated identity source loss".into());
                }
                state.loss = Some(SourceLoss {
                    report: report.into(),
                    cause,
                });
            }
            Progress::WaitDeadline => {
                return Err(
                    "identity operation deadline; exposed mutation outcome may be unknown".into(),
                );
            }
            Progress::Unavailable(error) => return Err(error.into()),
            Progress::Closed => return Err("identity source closed before result".into()),
            _ => {}
        }
    }
}
// The original physical source is already closed. Its bounded local event
// queue is drained without a new clock sample, reconnect or mutation replay.
async fn retire_mutation<'id>(
    client: &mut Client<'id>,
    operation: Operation<'id>,
    state: &mut Observation,
) -> Result<()> {
    loop {
        match client.drive(None).await? {
            Progress::Closed => return Ok(()),
            Progress::Completed(completion) => {
                if completion.operation != operation || state.terminal.is_some() {
                    return Err("foreign or duplicate original identity terminal".into());
                }
                state.terminal = Some(match completion.outcome {
                    Outcome::Result { code, created } => Terminal::Known {
                        code,
                        material_present: created.is_some(),
                    },
                    Outcome::Local {
                        reason,
                        submission,
                        result_code,
                        ..
                    } => Terminal::Local {
                        reason,
                        submission,
                        result_code,
                    },
                    Outcome::Found(_) => {
                        return Err("unexpected original identity mutation terminal".into());
                    }
                });
            }
            Progress::Lost { report, cause } => {
                if state.loss.is_some() {
                    return Err("repeated original identity source loss".into());
                }
                state.loss = Some(SourceLoss {
                    report: report.into(),
                    cause,
                });
            }
            _ => {}
        }
    }
}
pub(super) fn run(args: &mut [OsString], out: &mut impl Write) -> Result<()> {
    if args
        .first()
        .is_some_and(|value| value == OsStr::new("encrypt"))
    {
        return messages::encrypt(args, out);
    }
    let encrypted = if args
        .first()
        .is_some_and(|value| value == OsStr::new("decrypt"))
    {
        Some(messages::take(args, 3)?)
    } else {
        None
    };
    let imported = keys::extract(args)?;
    if let Some(message) = &encrypted {
        messages::validate(message, true)?;
    }
    if args.is_empty() || args.first().is_some_and(|s| s == OsStr::new("--help")) {
        writeln!(
            out,
            "identity list|monitor <UNIXPATH> [--timeout-ms N] [--max-egos N]"
        )?;
        writeln!(
            out,
            "identity lookup|lookup-suffix|export|delete <UNIXPATH> <NAME> [--timeout-ms N]"
        )?;
        writeln!(
            out,
            "identity create <UNIXPATH> <NAME> [--type edkey|pkey | --private-key BASE32] [--private-keys] [--timeout-ms N]"
        )?;
        writeln!(
            out,
            "identity encrypt <TYPED_PUBLIC_KEY> <MESSAGE> [--timeout-ms N]"
        )?;
        writeln!(
            out,
            "identity decrypt <UNIXPATH> <NAME> <BASE32_ENVELOPE> [--timeout-ms N]"
        )?;
        writeln!(
            out,
            "identity rename <UNIXPATH> <OLD> <NEW> [--timeout-ms N]"
        )?;
        writeln!(
            out,
            "Monitor adds --hold-ms N (default300000). Other commands default30000 ms; monitor overall330000 ms. Create defaults to EdDSA using OS entropy. Normal JSON output contains names and public keys only. Explicit --private-keys/-p adds standard typed private text; export writes exactly one standard private-key line. --private-key/--privkey/-P imports the36-byte typed/58-character Base32GNS format; its embedded type is retained. Private argv values are inherently visible to process inspection; CLI-owned copies are erased and errors never echo input. List ends at actual initial inventory END. Ctrl-C closes the original source; exposed mutations may already have committed."
        )?;
        return Ok(());
    }
    let (mut command, socket) = parse(args, imported, encrypted)?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(execute(&mut command, EndpointSource::unix(socket), out))
}

async fn execute(
    command: &mut Command,
    source: EndpointSource,
    out: &mut impl Write,
) -> Result<()> {
    let hard = Instant::now()
        .checked_add(command.timeout)
        .ok_or("identity native deadline overflow")?;
    let now = source.clock().sample()?.now.as_micros();
    let micros = u64::try_from(command.timeout.as_micros())?;
    let until = now
        .checked_add(micros)
        .filter(|n| *n != u64::MAX)
        .ok_or("identity deadline overflow")?;
    if Instant::now() >= hard {
        return Err("identity deadline before original source admission".into());
    }
    match command.action {
        Action::Lookup | Action::Suffix | Action::Export | Action::Decrypt => {
            lookup(command, source, hard, until, out).await
        }
        Action::List | Action::Monitor => monitor(command, source, hard, out).await,
        _ => mutation(command, source, hard, until, out).await,
    }
}
