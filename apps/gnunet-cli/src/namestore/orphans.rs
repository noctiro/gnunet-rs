//! Explicit NAMESTORE maintenance over the original IDENTITY inventory and
//! credited NAMESTORE sources. No cross-service transaction or replay exists.
use super::{Result, records_json, row, string_json, text};
use gnunet::{
    clients::{identity, namestore as ns},
    types::Error as Fault,
};
use serde_json::{Value, json};
use std::{
    error::Error,
    ffi::OsString,
    fmt,
    future::{Future, poll_fn},
    io::{self, Write},
    os::unix::ffi::OsStrExt,
    path::PathBuf,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Instant;

type Work<T> = std::result::Result<T, Cause>;
const DEFAULT_LIMIT: usize = 1000;
const DEFAULT_PLAN_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Action {
    List,
    PurgeOrphans,
    PurgeZone,
}
impl Action {
    fn name(self) -> &'static str {
        match self {
            Self::List => "list-orphans",
            Self::PurgeOrphans => "purge-orphans",
            Self::PurgeZone => "purge-zone",
        }
    }
}
struct Settings {
    action: Action,
    socket: PathBuf,
    identity: PathBuf,
    ego: Option<Vec<u8>>,
    timeout: Duration,
    limit: usize,
    plan_bytes: usize,
}
impl Settings {
    fn read(args: &[OsString]) -> Result<Self> {
        let action = match args.first().and_then(|v| v.to_str()) {
            Some("list-orphans") => Action::List,
            Some("purge-orphans") => Action::PurgeOrphans,
            Some("purge-zone") => Action::PurgeZone,
            _ => return Err("expected list-orphans, purge-orphans or purge-zone".into()),
        };
        let socket = args.get(1).ok_or("missing explicit NAMESTORE UNIXPATH")?;
        let mut identity = None;
        let mut ego = None;
        let mut timeout = None;
        let mut limit = None;
        let mut plan_bytes = None;
        let mut at = 2;
        while at < args.len() {
            let option = text(&args[at])?;
            let value = args
                .get(at + 1)
                .ok_or("missing NAMESTORE maintenance option value")?;
            match option {
                "--identity-socket" if identity.is_none() => identity = Some(PathBuf::from(value)),
                "--ego" if action == Action::PurgeZone && ego.is_none() => {
                    let raw = value.as_os_str().as_bytes();
                    if raw.is_empty()
                        || raw.len() > identity::Limits::default().name_bytes
                        || raw.contains(&0)
                    {
                        return Err("invalid bounded ego name".into());
                    }
                    let mut name = Vec::new();
                    name.try_reserve_exact(raw.len())?;
                    name.extend_from_slice(raw);
                    ego = Some(name);
                }
                "--timeout-ms" if timeout.is_none() => timeout = Some(text(value)?.parse::<u64>()?),
                "--limit" if limit.is_none() => limit = Some(text(value)?.parse::<usize>()?),
                "--plan-bytes" if plan_bytes.is_none() => {
                    plan_bytes = Some(text(value)?.parse::<usize>()?)
                }
                _ => {
                    return Err(
                        "unknown, duplicate or inapplicable NAMESTORE maintenance option".into(),
                    );
                }
            }
            at += 2;
        }
        let identity = identity.ok_or("required --identity-socket UNIXPATH")?;
        for path in [socket.as_os_str(), identity.as_os_str()] {
            if path.is_empty() || path.as_bytes().len() > 4096 || path.as_bytes().contains(&0) {
                return Err("invalid bounded service socket path".into());
            }
        }
        let timeout = timeout.unwrap_or(30_000);
        let limit = limit.unwrap_or(DEFAULT_LIMIT);
        let plan_bytes = plan_bytes.unwrap_or(DEFAULT_PLAN_BYTES);
        if !(1..=86_400_000).contains(&timeout)
            || !(1..=1_000_000).contains(&limit)
            || !(1..=256 * 1024 * 1024).contains(&plan_bytes)
        {
            return Err(
                "invalid finite maintenance deadline, record limit or plan byte bound".into(),
            );
        }
        if action == Action::PurgeZone && ego.is_none() {
            return Err("purge-zone requires --ego NAME".into());
        }
        let timeout = Duration::from_millis(timeout);
        if Instant::now().checked_add(timeout).is_none() {
            return Err("native maintenance deadline overflow".into());
        }
        Ok(Self {
            action,
            socket: PathBuf::from(socket),
            identity,
            ego,
            timeout,
            limit,
            plan_bytes,
        })
    }
}

// The vector is allocated once before receiving keys, so adding labels never
// reallocates an allocation containing moved secret owners. Record payloads and
// returned private frames are dropped immediately after inspection/output.
struct Marked {
    key: ns::SecretKey,
    label: Vec<u8>,
}
struct Plan {
    labels: Vec<Marked>,
    bytes: usize,
    bound: usize,
}
impl Plan {
    fn new(limit: usize, bound: usize) -> Work<Self> {
        let requested = limit
            .checked_mul(std::mem::size_of::<Marked>())
            .ok_or(Fault::Overflow)?;
        if requested > bound {
            return Err(Cause::Policy(
                "cleanup label allocation exceeds --plan-bytes",
            ));
        }
        let mut labels = Vec::new();
        labels
            .try_reserve_exact(limit)
            .map_err(|_| Fault::Capacity)?;
        let bytes = labels
            .capacity()
            .checked_mul(std::mem::size_of::<Marked>())
            .ok_or(Fault::Overflow)?;
        if bytes > bound {
            return Err(Cause::Policy(
                "actual cleanup label allocation exceeds --plan-bytes",
            ));
        }
        Ok(Self {
            labels,
            bytes,
            bound,
        })
    }
    fn push(&mut self, key: ns::SecretKey, label: &[u8]) -> Work<()> {
        if self.labels.len() == self.labels.capacity() {
            return Err(Fault::Capacity.into());
        }
        if self
            .bytes
            .checked_add(label.len())
            .is_none_or(|n| n > self.bound)
        {
            return Err(Cause::Policy("cleanup labels exceed --plan-bytes"));
        }
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(label.len())
            .map_err(|_| Fault::Capacity)?;
        let bytes = self
            .bytes
            .checked_add(owned.capacity())
            .ok_or(Fault::Overflow)?;
        if bytes > self.bound {
            return Err(Cause::Policy("actual cleanup labels exceed --plan-bytes"));
        }
        owned.extend_from_slice(label);
        self.labels.push(Marked { key, label: owned });
        self.bytes = bytes;
        Ok(())
    }
}

#[derive(Debug)]
enum Cause {
    Protocol(Fault),
    Identity(identity::Error),
    Namestore(ns::Error),
    IdentityLost(identity::LossCause),
    NamestoreLost(ns::LossCause),
    Connect(io::Error),
    Output(Box<dyn Error>),
    Signal(io::Error),
    Policy(&'static str),
    DirectoryChanged,
    Deadline,
    Interrupted,
    StoreRejected(u32),
    StoreLocal {
        reason: ns::LocalReason,
        submission: ns::Submission,
    },
    IteratorLocal {
        reason: ns::LocalReason,
        submission: ns::Submission,
    },
    IdentityCode(u32),
    LookupLocal {
        reason: identity::LocalReason,
        submission: identity::Submission,
        result_code: Option<u32>,
    },
}
impl From<Fault> for Cause {
    fn from(value: Fault) -> Self {
        Self::Protocol(value)
    }
}
impl fmt::Display for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(e) => e.fmt(f),
            Self::Identity(e) => write!(f, "IDENTITY: {e}"),
            Self::Namestore(e) => write!(f, "NAMESTORE: {e}"),
            Self::IdentityLost(e) => write!(f, "original IDENTITY source lost: {e:?}"),
            Self::NamestoreLost(e) => write!(f, "original NAMESTORE source lost: {e:?}"),
            Self::Connect(e) => write!(f, "original service connection: {e}"),
            Self::Output(e) => write!(f, "maintenance output: {e}"),
            Self::Signal(e) => write!(f, "maintenance signal: {e}"),
            Self::Policy(message) => f.write_str(message),
            Self::DirectoryChanged => f.write_str("directory_changed: original IDENTITY membership no longer matches the scan"),
            Self::Deadline => f.write_str("original maintenance deadline; incomplete scan or exposed deletion is not completion"),
            Self::Interrupted => f.write_str("maintenance interrupted; exposed deletion is not rolled back"),
            Self::StoreRejected(code) => write!(f, "actual NAMESTORE deletion result {code}"),
            Self::StoreLocal { reason, submission } => write!(f, "deletion ended without a service result: {reason:?}, {submission:?}"),
            Self::IteratorLocal { reason, submission } => write!(f, "iterator ended before natural END: {reason:?}, {submission:?}; no cleanup started"),
            Self::IdentityCode(code) => write!(f, "actual IDENTITY lookup result {code}"),
            Self::LookupLocal { reason, submission, result_code } => write!(f, "ego lookup ended locally: {reason:?}, {submission:?}, actual code {result_code:?}"),
        }
    }
}
impl Error for Cause {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Protocol(e) => Some(e),
            Self::Identity(e) => Some(e),
            Self::Namestore(e) => Some(e),
            Self::Connect(e) | Self::Signal(e) => Some(e),
            Self::Output(e) => Some(e.as_ref()),
            Self::IdentityLost(identity::LossCause::Io(e)) => Some(e),
            Self::IdentityLost(
                identity::LossCause::Protocol(e) | identity::LossCause::Resource(e),
            ) => Some(e),
            Self::IdentityLost(identity::LossCause::Ports(e)) => Some(e),
            Self::NamestoreLost(ns::LossCause::Io(e)) => Some(e),
            Self::NamestoreLost(ns::LossCause::Protocol(e) | ns::LossCause::Resource(e)) => Some(e),
            Self::NamestoreLost(ns::LossCause::Ports(e)) => Some(e),
            _ => None,
        }
    }
}
#[derive(Debug, Default)]
struct Facts {
    scanned: usize,
    selected: usize,
    natural_end: bool,
    successful_deletions: usize,
    last_result: Option<Value>,
    scan_terminal: Option<Value>,
    identity_loss: Option<Value>,
    lookup_loss: Option<Value>,
    iterator_loss: Option<Value>,
    writer_loss: Option<Value>,
    identity: Option<Value>,
    lookup: Option<Value>,
    iterator: Option<Value>,
    writer: Option<Value>,
}
#[derive(Debug)]
struct Failure {
    original: Option<Cause>,
    settlement: Option<Cause>,
    diagnostic: Option<Box<dyn Error>>,
    facts: Facts,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NAMESTORE maintenance original: {:?}; settlement: {:?}; reporting: {:?}; facts: {:?}",
            self.original, self.settlement, self.diagnostic, self.facts
        )
    }
}
impl Error for Failure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original
            .as_ref()
            .map(|e| e as &dyn Error)
            .or_else(|| self.settlement.as_ref().map(|e| e as &dyn Error))
            .or(self.diagnostic.as_deref())
    }
}
fn identity_loss(report: identity::Loss<'_>) -> Value {
    json!({"epoch":report.epoch.map(|epoch|epoch.diagnostic()),"operations":report.operations,
        "exposed":report.exposed,"egos":report.egos})
}
fn namestore_loss(report: ns::Loss<'_>) -> Value {
    json!({"epoch":report.epoch.map(|epoch|epoch.diagnostic()),"operations":report.operations,"exposed":report.exposed,
        "control":report.control.map(|control|json!({"allocation":control.control.diagnostic(),
            "kind":format!("{:?}",control.kind),"submission":format!("{:?}",control.submission)}))})
}
struct Inventory<'id> {
    client: identity::Client<'id>,
    ready: bool,
    epoch: Option<identity::Epoch<'id>>,
}
impl<'id> Inventory<'id> {
    fn event(&mut self, event: identity::Progress<'id>, facts: &mut Facts) -> Work<()> {
        match event {
            identity::Progress::Connected(epoch) => {
                if self.epoch.is_some() {
                    return Err(Cause::DirectoryChanged);
                }
                self.epoch = Some(epoch);
            }
            identity::Progress::Initialized(epoch) => {
                if self.ready
                    || self.epoch != Some(epoch)
                    || self.client.epoch() != Some(epoch)
                    || !self.client.initialized()
                {
                    return Err(Fault::StaleGeneration.into());
                }
                self.ready = true;
            }
            identity::Progress::Ego {
                change, initial, ..
            } => {
                if self.ready && (initial || change == identity::Change::Added) {
                    return Err(Cause::DirectoryChanged);
                }
                // The SDK preserves the same exact key/token on rename. This
                // does not change orphan membership or a selected zone key.
            }
            identity::Progress::Deleted { .. } if self.ready => {
                return Err(Cause::DirectoryChanged);
            }
            identity::Progress::Lost { report, cause } => {
                facts.identity_loss = Some(identity_loss(report));
                return Err(Cause::IdentityLost(cause));
            }
            identity::Progress::Unavailable(error) => return Err(Cause::Identity(error)),
            identity::Progress::ConnectRetry { error, .. } => return Err(Cause::Connect(error)),
            identity::Progress::WaitDeadline => return Err(Cause::Deadline),
            identity::Progress::Closed => return Err(Cause::Policy("IDENTITY inventory closed")),
            identity::Progress::Completed(_) | identity::Progress::EgoRetired(_) => {
                return Err(Fault::Malformed.into());
            }
            _ => {}
        }
        Ok(())
    }
    fn idle(&mut self, cx: &mut Context<'_>, hard: Instant, facts: &mut Facts) -> Poll<Work<()>> {
        match self.client.poll_inventory(cx, Some(hard)) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(identity::InventoryProgress::Source(event))) => {
                self.event(event, facts)?;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Ok(identity::InventoryProgress::Idle(epoch))) => {
                if !self.ready
                    || self.epoch != Some(epoch)
                    || self.client.epoch() != Some(epoch)
                    || !self.client.initialized()
                {
                    Poll::Ready(Err(Fault::StaleGeneration.into()))
                } else {
                    Poll::Ready(Ok(()))
                }
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(Cause::Identity(error))),
        }
    }
    fn contains(&self, key: &ns::SecretKey) -> bool {
        self.client
            .egos()
            .any(|ego| ego.secret().constant_time_eq(key))
    }
}
#[derive(Clone, Copy)]
struct Time {
    until: u64,
    hard: Instant,
}
#[derive(Clone, Copy)]
enum Drive {
    NativeGuard,
    Io,
}
// Every wait polls the original inventory before advancing the other source.
// The timer always points at the one original native deadline, never a new TTL.
async fn guarded<T>(
    mut progress: impl FnMut(&mut Context<'_>, Drive) -> Poll<std::result::Result<T, ns::Error>>,
    mut inventory: Option<&mut Inventory<'_>>,
    time: Time,
    mut signal: Pin<&mut impl Future<Output = io::Result<()>>>,
    facts: &mut Facts,
) -> Work<T> {
    let mut timer = std::pin::pin!(tokio::time::sleep_until(time.hard));
    poll_fn(|cx| {
        // Original stream/partial/operation timers must retire their own scope
        // even when directory input prevents physical I/O on the other source.
        if let Poll::Ready(result) = progress(cx, Drive::NativeGuard) {
            return Poll::Ready(result.map_err(Cause::Namestore));
        }
        if let Poll::Ready(result) = signal.as_mut().poll(cx) {
            return Poll::Ready(Err(match result {
                Ok(()) => Cause::Interrupted,
                Err(e) => Cause::Signal(e),
            }));
        }
        if timer.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(Cause::Deadline));
        }
        if let Some(inventory) = inventory.as_mut() {
            match inventory.idle(cx, time.hard, facts) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        progress(cx, Drive::Io).map_err(Cause::Namestore)
    })
    .await
}

async fn execute(settings: Settings, out: &mut impl Write) -> Result<()> {
    let source = ns::EndpointSource::unix(settings.socket.clone());
    let clock = source.clock();
    let identity_source =
        ns::EndpointSource::unix_with_clock(settings.identity.clone(), clock.clone());
    let time = Time {
        until: clock
            .sample()?
            .now
            .as_micros()
            .checked_add(u64::try_from(settings.timeout.as_micros())?)
            .filter(|value| *value != u64::MAX)
            .ok_or("canonical maintenance deadline overflow")?,
        hard: Instant::now()
            .checked_add(settings.timeout)
            .ok_or("native maintenance deadline overflow")?,
    };
    let mut plan = if settings.action == Action::List {
        None
    } else {
        Some(
            Plan::new(settings.limit, settings.plan_bytes)
                .map_err(|e| Box::new(e) as Box<dyn Error>)?,
        )
    };
    let identity_instance = identity::Instance::new();
    let lookup_instance = identity::Instance::new();
    let ns_instance = ns::Instance::new();
    let limits = ns::Limits {
        operations: 1,
        reconnect: false,
        ..ns::Limits::default()
    };
    let identity_limits = identity::Limits {
        operations: 1,
        reconnect: false,
        initialization_timeout: settings.timeout,
        ..identity::Limits::default()
    };
    let mut inventory = Inventory {
        client: identity::Client::monitor(&identity_instance, identity_source, identity_limits)?,
        ready: false,
        epoch: None,
    };
    let mut lookup = None;
    let mut iterator = None;
    let mut writer = None;
    let mut pending = None;
    let mut facts = Facts::default();
    let interrupt = tokio::signal::ctrl_c();
    tokio::pin!(interrupt);
    let result: Work<()> = async {
        while !inventory.ready {
            let event = guarded(|cx, drive| match drive {
                Drive::NativeGuard => inventory.client.poll_native_guard(cx).map_or(Poll::Pending, |event|Poll::Ready(Ok(event))),
                Drive::Io => inventory.client.poll(cx, Some(time.hard)),
            }, None, time, interrupt.as_mut(), &mut facts).await
                .map_err(|cause| match cause { Cause::Namestore(error) => Cause::Identity(error), other => other })?;
            inventory.event(event, &mut facts)?;
        }
        row(out, json!({"event":"namestore_management_identity_ready","egos":inventory.client.egos().count(),
            "epoch":inventory.epoch.map(|epoch|epoch.diagnostic())})).map_err(Cause::Output)?;
        let selected_zone = if let Some(name) = &settings.ego {
            lookup = Some(identity::Lookup::exact(&lookup_instance,
                ns::EndpointSource::unix_with_clock(settings.identity.clone(), clock.clone()), name, time.until, identity_limits).map_err(Cause::Identity)?);
            let owner = lookup.as_mut().ok_or(Fault::NotReady)?;
            let operation = owner.operation();
            loop {
                let event = guarded(|cx, drive| match drive {
                    Drive::NativeGuard => match owner.poll_native_guard(cx) {
                        Ok(Some(event)) => Poll::Ready(Ok(event)), Ok(None) => Poll::Pending, Err(error) => Poll::Ready(Err(error)),
                    },
                    Drive::Io => owner.poll(cx, Some(time.hard)),
                }, Some(&mut inventory), time, interrupt.as_mut(), &mut facts).await
                    .map_err(|cause| match cause { Cause::Namestore(error) => Cause::Identity(error), other => other })?;
                match event {
                    identity::LookupProgress::Finished { operation: original, epoch, outcome } => {
                        if original != operation { return Err(Fault::StaleGeneration.into()); }
                        // Lookup's actual Finished contract has already stopped
                        // this dedicated MQ. It returns no invented Loss count.
                        let outcome_fact = match &outcome {
                            identity::LookupOutcome::Found(_) => json!({"found":true}),
                            identity::LookupOutcome::ResultCode(code) => json!({"code":code}),
                            identity::LookupOutcome::Local { reason, submission, result_code } => json!({
                                "reason":format!("{reason:?}"),"submission":format!("{submission:?}"),"result_code":result_code}),
                        };
                        facts.lookup = Some(json!({"operation":original.diagnostic(),"epoch":epoch.map(|epoch|epoch.diagnostic()),
                            "finished_physically_closed":true,"outcome":outcome_fact}));
                        match outcome {
                            identity::LookupOutcome::Found(identity) => {
                                let key = identity.into_secret();
                                if !inventory.contains(&key) { return Err(Cause::DirectoryChanged); }
                                break Some(key);
                            }
                            identity::LookupOutcome::ResultCode(code) => return Err(Cause::IdentityCode(code)),
                            identity::LookupOutcome::Local { reason, submission, result_code } => return Err(Cause::LookupLocal { reason, submission, result_code }),
                        }
                    }
                    identity::LookupProgress::Source(identity::Progress::Lost { report, cause }) => {
                        facts.lookup_loss = Some(identity_loss(report)); return Err(Cause::IdentityLost(cause));
                    }
                    identity::LookupProgress::Source(identity::Progress::Unavailable(error)) => return Err(Cause::Identity(error)),
                    identity::LookupProgress::Source(identity::Progress::ConnectRetry { error, .. }) => return Err(Cause::Connect(error)),
                    identity::LookupProgress::Source(identity::Progress::WaitDeadline) => return Err(Cause::Deadline),
                    identity::LookupProgress::Closed => return Err(Cause::Policy("ego lookup closed without its result")),
                    _ => {},
                }
            }
        } else { None };
        iterator = Some(ns::ZoneIterator::new(&ns_instance, source, selected_zone.as_ref(), 0, time.until, limits).map_err(Cause::Namestore)?);
        let stream = iterator.as_mut().ok_or(Fault::NotReady)?;
        let operation = stream.operation();
        loop {
            let event = guarded(|cx, drive| match drive {
                Drive::NativeGuard => match stream.poll_native_guard(cx) {
                    Ok(Some(event)) => Poll::Ready(Ok(event)), Ok(None) => Poll::Pending, Err(error) => Poll::Ready(Err(error)),
                },
                Drive::Io => stream.poll(cx, Some(time.hard)),
            }, Some(&mut inventory), time, interrupt.as_mut(), &mut facts).await?;
            match event {
                ns::Progress::Record { operation: original, reply, .. } => {
                    if original != operation { return Err(Fault::StaleGeneration.into()); }
                    facts.scanned = facts.scanned.checked_add(1).ok_or(Fault::Overflow)?;
                    if facts.scanned > settings.limit { return Err(Cause::Policy("record limit reached before natural END; no cleanup started")); }
                    let ns::ipc::Response::Records { zone, label, expires, records, .. } = reply.view()? else { return Err(Fault::Malformed.into()); };
                    let key = ns::SecretKey::from_serialized(zone.expose_serialized())?;
                    let selected = match &selected_zone {
                        Some(original) if original.constant_time_eq(&key) => true,
                        Some(_) => return Err(Fault::StaleGeneration.into()),
                        None => !inventory.contains(&key),
                    };
                    if selected {
                        facts.selected += 1;
                        if let Some(plan) = plan.as_mut() { plan.push(key, label.bytes())?; }
                        else {
                            let public = json!({"event":"namestore_orphan_records","ordinal":facts.selected,
                                "label":string_json(label.bytes()),"expires_us":expires.as_micros(),"records":records_json(records).map_err(Cause::Output)?});
                            crate::identity::private_key_row(out, &public, &key).map_err(Cause::Output)?;
                        }
                    }
                    // Even the last allowed record gets one further read credit:
                    // END uses none, whereas a real N+1 record is refused above.
                    let _next = stream.next(1, time.until).map_err(Cause::Namestore)?;
                }
                ns::Progress::Completed(completion) => {
                    if completion.operation != operation || completion.kind != ns::Kind::Iterator { return Err(Fault::StaleGeneration.into()); }
                    let source = json!({"operation":completion.operation.diagnostic(),"epoch":completion.epoch.map(|epoch|epoch.diagnostic()),"rid":completion.request_id});
                    match completion.outcome {
                        ns::Outcome::Reply(reply) if matches!(reply.view()?, ns::ipc::Response::End { .. }) => {
                            facts.scan_terminal = Some(json!({"source":source,"natural_end":true}));
                            facts.natural_end = true; break;
                        },
                        ns::Outcome::Local { reason, submission } => {
                            facts.scan_terminal = Some(json!({"source":source,"natural_end":false,
                                "reason":format!("{reason:?}"),"submission":format!("{submission:?}")}));
                            return Err(Cause::IteratorLocal { reason, submission });
                        },
                        _ => return Err(Fault::Malformed.into()),
                    }
                }
                ns::Progress::Lost { report, cause } => { facts.iterator_loss = Some(namestore_loss(report)); return Err(Cause::NamestoreLost(cause)); },
                ns::Progress::Unavailable(error) => return Err(Cause::Namestore(error)),
                ns::Progress::ConnectRetry { error, .. } => return Err(Cause::Connect(error)),
                ns::Progress::WaitDeadline => return Err(Cause::Deadline),
                ns::Progress::Closed => return Err(Cause::Policy("iterator closed before natural END")),
                _ => {},
            }
        }
        row(out, json!({"event":"namestore_management_scan_complete","scanned":facts.scanned,"selected":facts.selected,
            "plan_bytes":plan.as_ref().map_or(0, |plan|plan.bytes),"natural_end":true})).map_err(Cause::Output)?;
        if let Some(plan) = plan.as_ref() {
            writer = Some(ns::Client::new(&ns_instance,
                ns::EndpointSource::unix_with_clock(settings.socket.clone(), clock.clone()), limits).map_err(Cause::Namestore)?);
            let client = writer.as_mut().ok_or(Fault::NotReady)?;
            for (index, marked) in plan.labels.iter().enumerate() {
                if (settings.action == Action::PurgeOrphans && inventory.contains(&marked.key))
                    || (settings.action == Action::PurgeZone && !inventory.contains(&marked.key))
                { return Err(Cause::DirectoryChanged); }
                let set = ns::ipc::StoreSet { label: ns::ipc::CString::new(&marked.label)?, records: ns::ipc::Records::empty()?, reserved: 0 };
                let mut bytes = [0; ns::ipc::SET_PREFIX + 256];
                let count = ns::ipc::encode_sets(&[set], &mut bytes)?;
                let operation = client.store(&marked.key, ns::ipc::RecordSets::new(&bytes[..count], 1)?, true, time.until).map_err(Cause::Namestore)?;
                pending = Some((operation, index + 1));
                loop {
                    let event = guarded(|cx, drive| match drive {
                        Drive::NativeGuard => client.poll_native_guard(cx).map_or(Poll::Pending, |event|Poll::Ready(Ok(event))),
                        Drive::Io => client.poll(cx, Some(time.hard)),
                    }, Some(&mut inventory), time, interrupt.as_mut(), &mut facts).await?;
                    match event {
                        ns::Progress::Completed(completion) => {
                            if completion.operation != operation || completion.kind != ns::Kind::Store { return Err(Fault::StaleGeneration.into()); }
                            pending = None;
                            deletion(completion.outcome, index + 1, &mut facts)?;
                            row(out, facts.last_result.as_ref().ok_or(Fault::NotReady)?.clone()).map_err(Cause::Output)?;
                            break;
                        }
                        ns::Progress::Lost { report, cause } => { facts.writer_loss = Some(namestore_loss(report)); return Err(Cause::NamestoreLost(cause)); },
                        ns::Progress::Unavailable(error) => return Err(Cause::Namestore(error)),
                        ns::Progress::ConnectRetry { error, .. } => return Err(Cause::Connect(error)),
                        ns::Progress::WaitDeadline => return Err(Cause::Deadline),
                        ns::Progress::Closed => return Err(Cause::Policy("deletion source closed without its actual result")),
                        _ => {},
                    }
                }
            }
        }
        row(out, json!({"event":"namestore_management_complete","action":settings.action.name(),"scanned":facts.scanned,
            "selected":facts.selected,"successful_deletions":facts.successful_deletions,"natural_end":facts.natural_end,
            "scope":"observed local records and actual service responses; no atomic cross-service snapshot, physical erase, publication or fsync proof"})).map_err(Cause::Output)?;
        Ok(())
    }.await;
    // Stop every independent physical owner before any reporting or local
    // completion drain. None of these closes needs a working clock or signal.
    facts.iterator = iterator
        .as_mut()
        .and_then(|owner| owner.close().or_else(|| owner.take_close_report()))
        .map(namestore_loss);
    facts.writer = writer
        .as_mut()
        .and_then(ns::Client::close)
        .map(namestore_loss);
    facts.identity = inventory.client.close().map(identity_loss);
    if let Some(owner) = lookup.as_mut() {
        let stopped = owner.close().map(identity_loss);
        if stopped.is_some() {
            facts.lookup = stopped;
        }
    }
    let mut settlement = None;
    if let (Some(client), Some((operation, ordinal))) = (writer.as_mut(), pending) {
        loop {
            match client.drive(None).await {
                Ok(ns::Progress::Completed(completion))
                    if completion.operation == operation && completion.kind == ns::Kind::Store =>
                {
                    let terminal = deletion(completion.outcome, ordinal, &mut facts).err();
                    if settlement.is_none() {
                        settlement = terminal;
                    }
                    break;
                }
                Ok(ns::Progress::Completed(_)) => {
                    settlement = Some(Fault::StaleGeneration.into());
                    break;
                }
                Ok(ns::Progress::Closed) => {
                    facts.last_result = Some(
                        json!({"event":"namestore_management_delete_unsettled","ordinal":ordinal,
                        "terminal_observed":false,"actual_service_result":false}),
                    );
                    if settlement.is_none() {
                        settlement = Some(Cause::Policy(
                            "closed deletion source supplied no matching terminal outcome",
                        ));
                    }
                    break;
                }
                Ok(ns::Progress::Lost { report, cause }) => {
                    facts.writer_loss = Some(namestore_loss(report));
                    settlement = Some(Cause::NamestoreLost(cause));
                }
                Ok(_) => {}
                Err(error) => {
                    settlement = Some(Cause::Namestore(error));
                    break;
                }
            }
        }
    }
    let original = result.err();
    let diagnostic = row(out, json!({"event":"namestore_management_closed","action":settings.action.name(),
        "scanned":facts.scanned,"selected":facts.selected,"natural_end":facts.natural_end,"successful_deletions":facts.successful_deletions,
        "last_result":facts.last_result,"scan_terminal":facts.scan_terminal,"identity":facts.identity,"lookup":facts.lookup,"iterator":facts.iterator,"writer":facts.writer,
        "identity_loss":facts.identity_loss,"lookup_loss":facts.lookup_loss,"iterator_loss":facts.iterator_loss,"writer_loss":facts.writer_loss,
        "failure":original.as_ref().map(ToString::to_string),"settlement_failure":settlement.as_ref().map(ToString::to_string)})).err();
    if original.is_some() || settlement.is_some() || diagnostic.is_some() {
        Err(Box::new(Failure {
            original,
            settlement,
            diagnostic,
            facts,
        }))
    } else {
        Ok(())
    }
}
fn deletion(outcome: ns::Outcome, ordinal: usize, facts: &mut Facts) -> Work<()> {
    match outcome {
        ns::Outcome::Reply(reply) => {
            let ns::ipc::Response::Generic { code, .. } = reply.view()? else {
                return Err(Fault::Malformed.into());
            };
            if code == 0 {
                facts.successful_deletions = facts
                    .successful_deletions
                    .checked_add(1)
                    .ok_or(Fault::Overflow)?;
            }
            facts.last_result = Some(
                json!({"event":"namestore_management_delete_result","ordinal":ordinal,"code":code,
                "successful_deletions":facts.successful_deletions,"actual_service_result":true}),
            );
            if code == 0 {
                Ok(())
            } else {
                Err(Cause::StoreRejected(code))
            }
        }
        ns::Outcome::Local { reason, submission } => {
            facts.last_result = Some(
                json!({"event":"namestore_management_delete_local","ordinal":ordinal,
                "reason":format!("{reason:?}"),"submission":format!("{submission:?}"),"actual_service_result":false}),
            );
            Err(Cause::StoreLocal { reason, submission })
        }
    }
}

pub(super) fn run(args: &[OsString], out: &mut impl Write) -> Result<()> {
    let settings = Settings::read(args)?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(execute(settings, out))
}
pub(super) fn help(out: &mut impl Write) -> Result<()> {
    writeln!(
        out,
        "namestore list-orphans|purge-orphans <UNIXPATH> --identity-socket UNIXPATH [--timeout-ms N] [--limit N] [--plan-bytes N]"
    )?;
    writeln!(
        out,
        "namestore purge-zone <UNIXPATH> --identity-socket UNIXPATH --ego NAME [--timeout-ms N] [--limit N] [--plan-bytes N]"
    )?;
    writeln!(
        out,
        "List-orphans explicitly exports each original typed private key for recovery with identity create --private-key; protect its output. Purge scans through actual END before deleting complete selected labels, one original STORE at a time. Limits default to1000 returned labels and16MiB cleanup-plan bytes. A changing/lost identity inventory, incomplete scan or unknown deletion stops the operation without replay; earlier service responses remain reported. Empty STORE does not promise physical database erasure, cross-label atomicity or publication completion."
    )?;
    Ok(())
}

#[cfg(test)]
mod tests;
