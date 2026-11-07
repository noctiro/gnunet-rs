//! Bounded standard record-line IO over the actual original native clients.
use super::{KEY_BYTES, Result, bytes, row, text};
use gnunet::{
    clients::{identity, namestore as ns},
    gnsrecord::{self, RecordData, RecordFlags, RecordType},
    gnsrecord_text::{
        self, Codec, Profile, Workspace,
        recordline::{self, Line},
    },
    idna,
};
use serde_json::json;
use std::{
    error::Error,
    ffi::{OsStr, OsString},
    fmt,
    fs::File,
    future::{Future, poll_fn},
    io::{self, Read, Write},
    path::PathBuf,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    signal::unix::{Signal, SignalKind, signal},
    time::{Instant, Sleep},
};
use zeroize::{Zeroize, Zeroizing};
const FRAME: usize = u16::MAX as usize;
const TEXT: usize = 262140;
const LINE: usize = TEXT + 512;
const RECORDS: usize = FRAME / gnsrecord::RECORD_HEADER_LEN;
struct Settings {
    socket: PathBuf,
    identity: PathBuf,
    input: Option<PathBuf>,
    ego: Option<Vec<u8>>,
    timeout: Duration,
    bytes: usize,
    records: u64,
    records_per_set: usize,
    filter: u16,
    sets: u64,
    egos: usize,
    profile: Profile,
}
impl Settings {
    fn read(args: &[OsString], import: bool) -> Result<Self> {
        let socket = PathBuf::from(args.first().ok_or("missing NAMESTORE UNIXPATH")?);
        let (mut identity, mut input, mut ego) = (None, None, None);
        let (mut timeout, mut maximum, mut records, mut sets, mut egos) = (
            30000u64,
            16 * 1024 * 1024usize,
            65536u64,
            65536u64,
            128usize,
        );
        let mut records_per_set = RECORDS;
        let mut filter = 0;
        let mut profile = Profile::NATIVE_255;
        let mut at = 1;
        while at < args.len() {
            let option = text(&args[at])?;
            let value = args.get(at + 1).ok_or("missing record-line option value")?;
            match option {
                "--identity-socket" => identity = Some(PathBuf::from(value)),
                "--input" if import => {
                    input = (value != OsStr::new("-")).then(|| PathBuf::from(value))
                }
                "--ego" if !import => ego = Some(bytes(value, 255, "ego name")?),
                "--timeout-ms" => timeout = text(value)?.parse()?,
                "--max-bytes" => maximum = text(value)?.parse()?,
                "--max-records" => records = text(value)?.parse()?,
                "--max-records-per-set" => records_per_set = text(value)?.parse()?,
                "--max-sets" => sets = text(value)?.parse()?,
                "--filter" if !import => filter = text(value)?.parse()?,
                "--max-egos" => egos = text(value)?.parse()?,
                "--record-profile" => {
                    profile = match text(value)? {
                        "native" => Profile::NATIVE_255,
                        "little" => Profile::LITTLE_255,
                        "big" => Profile::BIG_255,
                        _ => return Err("record-profile must be native|little|big".into()),
                    }
                }
                _ => return Err("unknown or inapplicable record-line option".into()),
            }
            at += 2;
        }
        if !(1..=86400000).contains(&timeout)
            || !(1..=64 * 1024 * 1024).contains(&maximum)
            || !(1..=1000000).contains(&records)
            || !(1..=1000000).contains(&sets)
            || !(1..=RECORDS).contains(&records_per_set)
            || !(1..=4096).contains(&egos)
            || ego.as_ref().is_some_and(Vec::is_empty)
        {
            return Err("invalid finite record-line limits".into());
        }
        if !import && ego.is_none() {
            return Err("export-recordline requires --ego NAME".into());
        }
        Ok(Self {
            socket,
            identity: identity.ok_or("required --identity-socket UNIXPATH")?,
            input,
            ego,
            timeout: Duration::from_millis(timeout),
            bytes: maximum,
            records,
            records_per_set,
            filter,
            sets,
            egos,
            profile,
        })
    }
}
fn storage(size: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    bytes.try_reserve_exact(size)?;
    bytes.resize(size, 0);
    Ok(bytes)
}
// No detached reader. The original budget is checked after synchronous OS IO;
// an individual blocked Read/Write is not advertised as preemptible.
struct Control {
    interrupt: Signal,
    terminate: Signal,
    hard: Instant,
    timer: Pin<Box<Sleep>>,
}
impl Control {
    fn new(timeout: Duration) -> io::Result<Self> {
        let hard = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| io::Error::other("record-line deadline overflow"))?;
        Ok(Self {
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
            hard,
            timer: Box::pin(tokio::time::sleep_until(hard)),
        })
    }
    fn check(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if Instant::now() >= self.hard || self.timer.as_mut().poll(cx).is_ready() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original record-line deadline",
            ));
        }
        for stream in [&mut self.interrupt, &mut self.terminate] {
            match stream.poll_recv(cx) {
                Poll::Ready(Some(())) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "record-line stopped",
                    ));
                }
                Poll::Ready(None) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "record-line signal source ended",
                    ));
                }
                Poll::Pending => {}
            }
        }
        Ok(())
    }
    async fn gate(&mut self) -> Result<()> {
        poll_fn(|cx| Poll::Ready(self.check(cx))).await?;
        Ok(())
    }
    async fn drive<T, E: Error + 'static>(
        &mut self,
        future: impl Future<Output = std::result::Result<T, E>>,
    ) -> Result<T> {
        let mut future = std::pin::pin!(future);
        poll_fn(|cx| {
            if let Err(error) = self.check(cx) {
                return Poll::Ready(Err(Box::new(error) as Box<dyn Error>));
            }
            future
                .as_mut()
                .poll(cx)
                .map(|result| result.map_err(|error| Box::new(error) as Box<dyn Error>))
        })
        .await
    }
}
#[derive(Debug, Default)]
struct Report {
    line: u64,
    input_bytes: usize,
    converted_records: u64,
    admitted_sets: u64,
    stored_sets: u64,
    stored_records: u64,
    failed_sets: u64,
    unapplied_sets: u64,
    unknown_sets: u64,
    staged_records: usize,
    converted_unstaged: bool,
    pending_store: bool,
    legal_eof: bool,
    exported_sets: u64,
    exported_records: u64,
    output_bytes: usize,
    natural_end: bool,
    partial_group: bool,
    local: Option<String>,
    identity_local: Option<String>,
    close_exposed: usize,
}
#[derive(Debug, Default)]
struct Failure {
    report: Report,
    original: Option<Box<dyn Error>>,
    identity_loss: Option<identity::LossCause>,
    store_loss: Option<ns::LossCause>,
    diagnostic: Option<Box<dyn Error>>,
    cleanup: Option<Box<dyn Error>>,
    flush: Option<io::Error>,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NAMESTORE record-line report={:?}", self.report)?;
        if let Some(e) = &self.original {
            write!(f, "; original: {e}")?;
        }
        if let Some(e) = &self.identity_loss {
            write!(f, "; original IDENTITY loss: {e:?}")?;
        }
        if let Some(e) = &self.store_loss {
            write!(f, "; original NAMESTORE loss: {e:?}")?;
        }
        if let Some(e) = &self.diagnostic {
            write!(f, "; diagnostic: {e}")?;
        }
        if let Some(e) = &self.cleanup {
            write!(f, "; cleanup: {e}")?;
        }
        if let Some(e) = &self.flush {
            write!(f, "; output flush: {e}")?;
        }
        Ok(())
    }
}
impl Error for Failure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        let identity: Option<&(dyn Error + 'static)> = match &self.identity_loss {
            Some(identity::LossCause::Io(e)) => Some(e),
            Some(identity::LossCause::Protocol(e) | identity::LossCause::Resource(e)) => Some(e),
            Some(identity::LossCause::Ports(e)) => Some(e),
            _ => None,
        };
        let store: Option<&(dyn Error + 'static)> = match &self.store_loss {
            Some(ns::LossCause::Io(e)) => Some(e),
            Some(ns::LossCause::Protocol(e) | ns::LossCause::Resource(e)) => Some(e),
            Some(ns::LossCause::Ports(e)) => Some(e),
            _ => None,
        };
        identity
            .or(store)
            .or(self.original.as_deref())
            .or(self.diagnostic.as_deref())
            .or(self.cleanup.as_deref())
            .or_else(|| self.flush.as_ref().map(|e| e as _))
    }
}

fn summary(out: &mut impl Write, failure: &mut Failure, import: bool) {
    let r = &failure.report;
    let complete = failure.original.is_none()
        && failure.identity_loss.is_none()
        && failure.store_loss.is_none()
        && failure.flush.is_none()
        && failure.diagnostic.is_none()
        && failure.cleanup.is_none()
        && if import {
            r.legal_eof && !r.pending_store && r.unknown_sets == 0 && r.failed_sets == 0
        } else {
            r.natural_end
        };
    if let Err(error) = row(
        out,
        json!({"event":"namestore_recordline_summary","direction":if import{"import"}else{"export"},
        "complete":complete,"line":r.line,"input_bytes":r.input_bytes,"converted_records":r.converted_records,
        "admitted_sets":r.admitted_sets,"stored_sets":r.stored_sets,"stored_records":r.stored_records,
        "failed_sets":r.failed_sets,"unapplied_sets":r.unapplied_sets,"unknown_sets":r.unknown_sets,"staged_records":r.staged_records,
        "converted_unstaged_record":r.converted_unstaged,"pending_store":r.pending_store,"legal_eof":r.legal_eof,
        "exported_sets":r.exported_sets,"exported_records":r.exported_records,"output_bytes":r.output_bytes,
        "natural_end":r.natural_end,"partial_group":r.partial_group,"local":r.local,"identity_local":r.identity_local,"close_exposed":r.close_exposed,
        "identity_loss":failure.identity_loss.as_ref().map(|c|format!("{c:?}")),
        "namestore_loss":failure.store_loss.as_ref().map(|c|format!("{c:?}")),
        "error":failure.original.as_ref().map(ToString::to_string)}),
    ) {
        failure.diagnostic.get_or_insert(error);
    }
}
struct Buffers {
    stage: Zeroizing<Vec<u8>>,
    names: Zeroizing<Vec<u8>>,
    work: Zeroizing<Vec<u8>>,
    value: Zeroizing<Vec<u8>>,
    wire: Zeroizing<Vec<u8>>,
    sets: Zeroizing<Vec<u8>>,
    text: Zeroizing<Vec<u8>>,
    group_text: Zeroizing<Vec<u8>>,
    idna: idna::Workspace,
}
impl Buffers {
    fn new() -> Result<Self> {
        Ok(Self {
            stage: storage(TEXT)?,
            names: storage(1024)?,
            work: storage(4096)?,
            value: storage(FRAME)?,
            wire: storage(FRAME)?,
            sets: storage(FRAME)?,
            text: storage(TEXT)?,
            group_text: Zeroizing::new(Vec::new()),
            idna: idna::Workspace::new(),
        })
    }
    fn convert(&mut self, kind: RecordType, value: &str, profile: Profile) -> Result<usize> {
        let backend = idna::Backend::new(
            &mut self.idna,
            idna::Limits::GNUNET,
            idna::NativeProfile::Libunistring1_5Unicode18_0,
        );
        let mut codec = Codec::new(
            &backend,
            Workspace::new(&mut self.stage, &mut self.names, &mut self.work),
            profile,
            gnsrecord_text::Limits {
                input_bytes: TEXT,
                output_bytes: TEXT,
                ..Default::default()
            },
        )?;
        Ok(codec.string_to_value(kind, value, &mut self.value)?)
    }
    fn render(&mut self, record: RecordData<'_>, profile: Profile) -> Result<usize> {
        let backend = idna::Backend::new(
            &mut self.idna,
            idna::Limits::GNUNET,
            idna::NativeProfile::Libunistring1_5Unicode18_0,
        );
        let mut codec = Codec::new(
            &backend,
            Workspace::new(&mut self.stage, &mut self.names, &mut self.work),
            profile,
            gnsrecord_text::Limits {
                input_bytes: TEXT,
                output_bytes: TEXT,
                ..Default::default()
            },
        )?;
        let n = codec.value_to_string(record.record_type, record.data, &mut self.text)?;
        // Some official string schemas stop at NUL. Such a producer value can
        // be displayed, but must not silently lose its tail during a backup.
        let text = std::str::from_utf8(&self.text[..n])?;
        let m = codec.string_to_value(record.record_type, text, &mut self.value)?;
        if self.value[..m] != *record.data {
            return Err("record-line text cannot preserve the original binary value".into());
        }
        Ok(n)
    }
}
struct Meta {
    start: usize,
    end: usize,
    kind: RecordType,
    expiration: u64,
    flags: RecordFlags,
}
struct Group {
    label: String,
    owner: String,
    start_line: u64,
    end_line: u64,
    data: Zeroizing<Vec<u8>>,
    records: Vec<Meta>,
    maximum: usize,
}
impl Group {
    fn new(label: &str, owner: &str, line: u64, maximum: usize) -> Result<Self> {
        let mut records = Vec::new();
        records.try_reserve(1)?;
        Ok(Self {
            label: label.to_owned(),
            owner: owner.to_owned(),
            start_line: line,
            end_line: line,
            data: Zeroizing::new(Vec::new()),
            records,
            maximum,
        })
    }
    fn push(
        &mut self,
        kind: RecordType,
        expiration: u64,
        flags: RecordFlags,
        value: &[u8],
    ) -> Result<()> {
        if self.records.len() == self.maximum {
            return Err("record-line per-set record bound exceeded".into());
        }
        let start = self.data.len();
        let end = start
            .checked_add(value.len())
            .ok_or("record-line data overflow")?;
        if end
            .checked_add((self.records.len() + 1) * gnsrecord::RECORD_HEADER_LEN)
            .is_none_or(|n| n > FRAME)
        {
            return Err("record-line group exceeds one STORE frame".into());
        }
        RecordData {
            expiration_time: expiration,
            record_type: kind,
            flags,
            data: value,
        }
        .validate_fixed_size()?;
        self.data.try_reserve(value.len())?;
        self.data.extend_from_slice(value);
        self.records.try_reserve(1)?;
        self.records.push(Meta {
            start,
            end,
            kind,
            expiration,
            flags,
        });
        Ok(())
    }
    fn encode(&self, buffers: &mut Buffers) -> Result<usize> {
        let mut records = Vec::new();
        records.try_reserve_exact(self.records.len())?;
        for m in &self.records {
            records.push(RecordData {
                expiration_time: m.expiration,
                record_type: m.kind,
                flags: m.flags,
                data: &self.data[m.start..m.end],
            });
        }
        let n = gnsrecord::serialize(&records[..self.records.len()], &mut buffers.wire)?;
        let set = ns::ipc::StoreSet {
            label: ns::ipc::CString::new(self.label.as_bytes())?,
            records: ns::ipc::Records::new(&buffers.wire[..n], self.records.len().try_into()?)?,
            reserved: 0,
        };
        let n = set.encoded_len()?;
        if n.checked_add(ns::ipc::STORE_PREFIX + KEY_BYTES)
            .is_none_or(|n| n > FRAME)
        {
            return Err("complete record-line set cannot fit one original STORE frame".into());
        }
        Ok(set.encode(&mut buffers.sets)?)
    }
}
// The only read-ahead storage is owned and zeroized, like the current line.
struct Input<R> {
    reader: R,
    chunk: Zeroizing<[u8; 8192]>,
    at: usize,
    end: usize,
}
impl<R: Read> Input<R> {
    fn new(reader: R) -> Self {
        Self {
            reader,
            chunk: Zeroizing::new([0; 8192]),
            at: 0,
            end: 0,
        }
    }
    fn line(
        &mut self,
        line: &mut Zeroizing<Vec<u8>>,
        total: &mut usize,
        maximum: usize,
    ) -> Result<bool> {
        line.as_mut_slice().zeroize();
        line.clear();
        loop {
            if self.at == self.end {
                // Read at most the first offending byte at either cap. Reaching
                // a cap never masquerades as a real EOF.
                let allowance = (maximum.saturating_sub(*total) + 1)
                    .min(LINE.saturating_sub(line.len()) + 1)
                    .min(self.chunk.len());
                self.chunk.as_mut_slice().zeroize();
                self.end = match self.reader.read(&mut self.chunk[..allowance]) {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    result => result?,
                };
                self.at = 0;
                if self.end == 0 {
                    return Ok(!line.is_empty());
                }
            }
            let available = &self.chunk[self.at..self.end];
            let n = available
                .iter()
                .position(|b| *b == b'\n')
                .map_or(available.len(), |n| n + 1);
            if n > maximum.saturating_sub(*total) {
                return Err("record-line complete input byte bound exceeded".into());
            }
            if n > LINE.saturating_sub(line.len()) {
                return Err("record-line physical line bound exceeded".into());
            }
            line.try_reserve(n)?;
            line.extend_from_slice(&available[..n]);
            *total += n;
            self.at += n;
            if line.last() == Some(&b'\n') {
                line.pop();
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return Ok(true);
            }
        }
    }
}

async fn lookup(
    name: &[u8],
    source: ns::EndpointSource,
    until: u64,
    control: &mut Control,
    failure: &mut Failure,
) -> Result<identity::Identity> {
    control.gate().await?;
    let instance = identity::Instance::new();
    let mut lookup = identity::Lookup::exact(
        &instance,
        source,
        name,
        until,
        identity::Limits {
            reconnect: false,
            operations: 1,
            ..Default::default()
        },
    )?;
    let result = async {
        loop {
            match control.drive(lookup.drive(Some(control.hard))).await? {
                identity::LookupProgress::Finished {
                    outcome: identity::LookupOutcome::Found(ego),
                    ..
                } => return Ok(ego),
                identity::LookupProgress::Finished { outcome, .. } => {
                    failure.report.identity_local = Some(format!("{outcome:?}"));
                    return Err("record-line owner lookup did not return an existing ego".into());
                }
                identity::LookupProgress::Source(identity::Progress::Lost { cause, .. }) => {
                    failure.identity_loss.get_or_insert(cause);
                    return Err("original record-line IDENTITY source lost".into());
                }
                identity::LookupProgress::Source(identity::Progress::Unavailable(error)) => {
                    return Err(error.into());
                }
                identity::LookupProgress::Source(identity::Progress::WaitDeadline) => {
                    return Err("record-line owner lookup deadline".into());
                }
                identity::LookupProgress::Closed => {
                    return Err("record-line owner lookup closed without a result".into());
                }
                _ => {}
            }
        }
    }
    .await;
    let _close = lookup.close();
    if result.is_err() {
        // Close queues the actual original local result without further IO.
        for _ in 0..4 {
            match lookup.drive(Some(Instant::now())).await {
                Ok(identity::LookupProgress::Finished { outcome, .. }) => {
                    failure.report.identity_local = Some(format!("{outcome:?}"));
                    break;
                }
                Ok(identity::LookupProgress::Source(identity::Progress::Lost {
                    cause, ..
                })) => {
                    failure.identity_loss.get_or_insert(cause);
                }
                Ok(
                    identity::LookupProgress::Closed
                    | identity::LookupProgress::Source(identity::Progress::WaitDeadline),
                ) => break,
                Err(error) => {
                    failure.cleanup.get_or_insert(Box::new(error));
                    break;
                }
                _ => {}
            }
        }
    }
    result
}
struct Zone {
    owner: String,
    key: ns::SecretKey,
}
async fn owner(
    owner: &str,
    source: &ns::EndpointSource,
    settings: &Settings,
    zones: &mut Vec<Zone>,
    until: u64,
    control: &mut Control,
    failure: &mut Failure,
) -> Result<usize> {
    if let Some(index) = zones.iter().position(|zone| zone.owner == owner) {
        return Ok(index);
    }
    if zones.len() == settings.egos {
        return Err("record-line retained owner bound exceeded".into());
    }
    let public = gnsrecord::ZoneKey::from_ztld(owner)
        .ok()
        .map(|key| key.to_wire());
    let key = if let Some(public) = public {
        // Fixed C resolves public headers against the actual IDENTITY inventory.
        // Public text is never interpreted as imported private authority.
        control.gate().await?;
        let instance = identity::Instance::new();
        let mut monitor = identity::Client::monitor(
            &instance,
            source.duplicate()?,
            identity::Limits {
                reconnect: false,
                egos: settings.egos,
                operations: 1,
                initialization_timeout: settings.timeout,
                ..Default::default()
            },
        )?;
        let found: Result<ns::SecretKey> = async {
            loop {
                match control.drive(monitor.drive(Some(control.hard))).await? {
                    identity::Progress::Initialized(_) => {
                        for ego in monitor.egos() {
                            if ego.public_key()? == public {
                                return Ok(ego.secret().try_clone_secret());
                            }
                        }
                        return Err("record-line public owner has no existing IDENTITY ego".into());
                    }
                    identity::Progress::Lost { cause, .. } => {
                        failure.identity_loss.get_or_insert(cause);
                        return Err("record-line public owner inventory lost".into());
                    }
                    identity::Progress::Unavailable(error) => return Err(error.into()),
                    identity::Progress::WaitDeadline => {
                        return Err("record-line public owner inventory deadline".into());
                    }
                    identity::Progress::Closed => {
                        return Err("record-line public owner inventory closed before END".into());
                    }
                    _ => {}
                }
            }
        }
        .await;
        let _close = monitor.close();
        found?
    } else {
        lookup(
            owner.as_bytes(),
            source.duplicate()?,
            until,
            control,
            failure,
        )
        .await?
        .into_secret()
    };
    zones.try_reserve(1)?;
    zones.push(Zone {
        owner: owner.to_owned(),
        key,
    });
    Ok(zones.len() - 1)
}
fn store_completion(
    completion: ns::Completion<'_>,
    group: &Group,
    failure: &mut Failure,
) -> Result<()> {
    if !failure.report.pending_store {
        return Err("duplicate original record-line STORE result".into());
    }
    match completion.outcome {
        ns::Outcome::Reply(reply) => {
            let ns::ipc::Response::Generic { code, .. } = reply.view()? else {
                return Err("unexpected original record-line STORE reply".into());
            };
            failure.report.pending_store = false;
            failure.report.local = Some(format!("service_code={code}"));
            if code == 0 {
                failure.report.stored_sets += 1;
                failure.report.stored_records += group.records.len() as u64;
                failure.report.staged_records = 0;
                Ok(())
            } else {
                failure.report.failed_sets += 1;
                Err(format!("record-line STORE returned actual code {code}").into())
            }
        }
        ns::Outcome::Local { reason, submission } => {
            failure.report.pending_store = false;
            failure.report.local = Some(format!("{reason:?}, {submission:?}"));
            if matches!(submission, ns::Submission::Unsent) {
                failure.report.unapplied_sets += 1;
            } else {
                failure.report.unknown_sets += 1;
            }
            Err("record-line STORE retired locally; exposed outcome is not replayed".into())
        }
    }
}
// One complete mutation, bound to its selected existing authority and original
// canonical target. Submission never renews the target between header groups.
struct StoreRequest<'a> {
    group: &'a Group,
    key: &'a ns::SecretKey,
    until: u64,
}
async fn store(
    request: StoreRequest<'_>,
    buffers: &mut Buffers,
    client: &mut ns::Client<'_>,
    control: &mut Control,
    failure: &mut Failure,
    out: &mut impl Write,
) -> Result<()> {
    let StoreRequest { group, key, until } = request;
    let n = group.encode(buffers)?;
    control.gate().await?;
    let operation = client.store(
        key,
        ns::ipc::RecordSets::new(&buffers.sets[..n], 1)?,
        true,
        until,
    )?;
    failure.report.admitted_sets += 1;
    failure.report.pending_store = true;
    failure.report.local = None;
    let result=async {
        loop {
            match control.drive(client.drive(Some(control.hard))).await? {
                ns::Progress::Completed(completion) if completion.operation==operation=>{
                    let result=store_completion(completion,group,failure);
                    // Actual receipt facts precede fallible output.
                    if let Err(error) = row(out,json!({"event":"namestore_recordline_store_result","first_line":group.start_line,
                        "last_line":group.end_line,"label":group.label,"owner":group.owner,"result":failure.report.local,
                        "stored_sets":failure.report.stored_sets,"stored_records":failure.report.stored_records,
                        "failed_sets":failure.report.failed_sets,"unknown_sets":failure.report.unknown_sets})) {
                        failure.diagnostic.get_or_insert(error);
                        if result.is_ok() { return Err("record-line receipt output failed after actual STORE result".into()); }
                    }
                    return result;
                }
                ns::Progress::Completed(_)=>return Err("foreign record-line STORE completion".into()),
                ns::Progress::Lost{report,cause}=>{failure.report.close_exposed=failure.report.close_exposed.max(report.exposed);failure.store_loss.get_or_insert(cause);return Err("original record-line NAMESTORE source lost; no mutation replay".into());}
                ns::Progress::Unavailable(error)=>return Err(error.into()),
                ns::Progress::WaitDeadline=>return Err("original record-line STORE observation deadline".into()),
                ns::Progress::Closed=>return Err("record-line STORE closed before original outcome".into()),
                _=>{}
            }
        }
    }.await;
    if result.is_err() && failure.report.pending_store {
        if let Some(report) = client.close() {
            failure.report.close_exposed = failure.report.close_exposed.max(report.exposed);
        }
        // Exactly one live operation. Closing retains its original queued result
        // (including known success) before local Closed; no more IO or admission.
        for _ in 0..4 {
            match client.drive(Some(Instant::now())).await {
                Ok(ns::Progress::Completed(completion)) if completion.operation == operation => {
                    let _terminal = store_completion(completion, group, failure);
                    break;
                }
                Ok(ns::Progress::Lost { cause, .. }) => {
                    failure.store_loss.get_or_insert(cause);
                }
                Ok(ns::Progress::Closed | ns::Progress::WaitDeadline) => break,
                Err(error) => {
                    failure.cleanup.get_or_insert(Box::new(error));
                    break;
                }
                _ => {}
            }
        }
        if failure.report.pending_store {
            failure.report.unknown_sets += 1;
        }
    }
    result
}
async fn import(
    settings: &Settings,
    reader: &mut Input<impl Read>,
    out: &mut impl Write,
    failure: &mut Failure,
    control: &mut Control,
) -> Result<()> {
    control.gate().await?;
    let source = ns::EndpointSource::unix(settings.socket.clone());
    let identity_source =
        ns::EndpointSource::unix_with_clock(settings.identity.clone(), source.clock());
    let until = source
        .clock()
        .sample()?
        .now
        .as_micros()
        .checked_add(settings.timeout.as_micros().try_into()?)
        .filter(|n| *n != u64::MAX)
        .ok_or("record-line canonical deadline overflow")?;
    let instance = ns::Instance::new();
    let mut client = ns::Client::new(
        &instance,
        source,
        ns::Limits {
            reconnect: false,
            operations: 1,
            ..Default::default()
        },
    )?;
    let result = async {
        let mut buffers = Buffers::new()?;
        let mut line = Zeroizing::new(Vec::new());
        let mut zones = Vec::new();
        let mut group: Option<Group> = None;
        loop {
            control.gate().await?;
            let present =
                reader.line(&mut line, &mut failure.report.input_bytes, settings.bytes)?;
            control.gate().await?;
            if !present {
                failure.report.legal_eof = true;
                if let Some(group) = &group
                    && !group.records.is_empty()
                {
                    if failure.report.admitted_sets == settings.sets {
                        return Err("record-line set bound exceeded".into());
                    }
                    let index = owner(
                        &group.owner,
                        &identity_source,
                        settings,
                        &mut zones,
                        until,
                        control,
                        failure,
                    )
                    .await?;
                    store(
                        StoreRequest {
                            group,
                            key: &zones[index].key,
                            until,
                        },
                        &mut buffers,
                        &mut client,
                        control,
                        failure,
                        out,
                    )
                    .await?;
                }
                return Ok(());
            }
            failure.report.line += 1;
            match recordline::parse(std::str::from_utf8(&line)?)? {
                Line::Empty => {}
                Line::Header {
                    label,
                    owner: next_owner,
                } => {
                    if let Some(previous) = &group
                        && !previous.records.is_empty()
                    {
                        if failure.report.admitted_sets == settings.sets {
                            return Err("record-line set bound exceeded".into());
                        }
                        let index = owner(
                            &previous.owner,
                            &identity_source,
                            settings,
                            &mut zones,
                            until,
                            control,
                            failure,
                        )
                        .await?;
                        store(
                            StoreRequest {
                                group: previous,
                                key: &zones[index].key,
                                until,
                            },
                            &mut buffers,
                            &mut client,
                            control,
                            failure,
                            out,
                        )
                        .await?;
                    }
                    group = Some(Group::new(
                        label,
                        next_owner,
                        failure.report.line,
                        settings.records_per_set,
                    )?);
                    failure.report.staged_records = 0;
                }
                Line::Record {
                    record_type,
                    expiration_time,
                    flags,
                    value,
                } => {
                    let group = group
                        .as_mut()
                        .ok_or("record-line record precedes its owner header")?;
                    if failure.report.converted_records == settings.records {
                        return Err("record-line record bound exceeded".into());
                    }
                    let n = buffers.convert(record_type, value, settings.profile)?;
                    failure.report.converted_records += 1;
                    failure.report.converted_unstaged = true;
                    group.push(record_type, expiration_time, flags, &buffers.value[..n])?;
                    failure.report.converted_unstaged = false;
                    group.end_line = failure.report.line;
                    failure.report.staged_records = group.records.len();
                }
            }
        }
    }
    .await;
    if let Some(report) = client.close() {
        failure.report.close_exposed = failure.report.close_exposed.max(report.exposed);
    }
    result
}

fn export_group(
    buffers: &mut Buffers,
    label: &[u8],
    owner: &[u8],
    records: ns::ipc::Records<'_>,
    settings: &Settings,
    failure: &mut Failure,
    out: &mut impl Write,
) -> Result<()> {
    if failure.report.exported_sets == settings.sets {
        return Err("record-line export set bound before actual END; incomplete".into());
    }
    let label = std::str::from_utf8(label)?;
    let owner = std::str::from_utf8(owner)?;
    buffers.group_text.as_mut_slice().zeroize();
    buffers.group_text.clear();
    let mut line = storage(LINE)?;
    let n = recordline::format_header(label, owner, &mut line)?;
    buffers.group_text.try_reserve(n)?;
    buffers.group_text.extend_from_slice(&line[..n]);
    let mut count = 0;
    for record in records.records().iter() {
        let record = record?;
        // Iteration appends the apex nickname elsewhere. The public C exporter
        // excludes this synthetic NICK from replacement record sets.
        if record.record_type == RecordType::NICK && label != "@" {
            continue;
        }
        if count == settings.records_per_set as u64 {
            return Err("record-line export per-set record bound; incomplete".into());
        }
        if failure.report.exported_records + count == settings.records {
            return Err("record-line export record bound; incomplete".into());
        }
        let n = buffers.render(record, settings.profile)?;
        let value = std::str::from_utf8(&buffers.text[..n])?;
        let n = recordline::format_record(
            record.record_type,
            record.expiration_time,
            record.flags,
            value,
            &mut line,
        )?;
        let next = buffers
            .group_text
            .len()
            .checked_add(n)
            .ok_or("record-line output group overflow")?;
        if failure
            .report
            .output_bytes
            .checked_add(next)
            .is_none_or(|n| n > settings.bytes)
        {
            return Err("record-line complete output byte bound; incomplete".into());
        }
        buffers.group_text.try_reserve(n)?;
        buffers.group_text.extend_from_slice(&line[..n]);
        count += 1;
    }
    // Empty/synthetic-only groups are ignored by the public importer. Do not
    // emit a header that might be mistaken for an explicit delete instruction.
    if count == 0 {
        return Ok(());
    }
    if failure
        .report
        .output_bytes
        .checked_add(buffers.group_text.len())
        .is_none_or(|n| n > settings.bytes)
    {
        return Err("record-line complete output byte bound; incomplete".into());
    }
    // Convert the complete logical group before emitting any of it. OS output
    // may fail after a prefix; the resulting stream is then explicitly incomplete.
    failure.report.partial_group = true;
    let mut written = 0;
    while written < buffers.group_text.len() {
        let n = match out.write(&buffers.group_text[written..]) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "record-line output made no progress",
            )
            .into());
        }
        written += n;
        failure.report.output_bytes += n;
    }
    failure.report.partial_group = false;
    failure.report.exported_sets += 1;
    failure.report.exported_records += count;
    Ok(())
}
fn export_completion(completion: ns::Completion<'_>, failure: &mut Failure) -> Result<()> {
    match completion.outcome {
        ns::Outcome::Reply(reply) if matches!(reply.view()?, ns::ipc::Response::End { .. }) => {
            failure.report.natural_end = true;
            Ok(())
        }
        ns::Outcome::Local { reason, submission } => {
            failure.report.local = Some(format!("{reason:?}, {submission:?}"));
            Err("record-line iterator retired before actual END".into())
        }
        _ => Err("unexpected record-line iterator completion".into()),
    }
}
async fn export(
    settings: &Settings,
    out: &mut impl Write,
    failure: &mut Failure,
    control: &mut Control,
) -> Result<()> {
    control.gate().await?;
    let source = ns::EndpointSource::unix(settings.socket.clone());
    let identity_source =
        ns::EndpointSource::unix_with_clock(settings.identity.clone(), source.clock());
    let until = source
        .clock()
        .sample()?
        .now
        .as_micros()
        .checked_add(settings.timeout.as_micros().try_into()?)
        .filter(|n| *n != u64::MAX)
        .ok_or("record-line canonical deadline overflow")?;
    let ego = lookup(
        settings.ego.as_deref().ok_or("missing export ego")?,
        identity_source,
        until,
        control,
        failure,
    )
    .await?;
    let mut owner = ego.name().to_vec();
    if let Ok(name) = std::str::from_utf8(&owner)
        && let Ok(named_public) = gnsrecord::ZoneKey::from_ztld(name)
        && named_public.to_wire() != ego.public_key()?
    {
        owner.resize(58, 0);
        let n = gnsrecord::encode_base32(&ego.public_key()?, &mut owner)?;
        owner.truncate(n);
    }
    recordline::format_header("@", std::str::from_utf8(&owner)?, &mut [0; 514])?;
    let key = ego.into_secret();
    let instance = ns::Instance::new();
    let mut iterator = ns::ZoneIterator::new(
        &instance,
        source,
        Some(&key),
        settings.filter,
        until,
        ns::Limits {
            reconnect: false,
            operations: 1,
            credit: 1,
            ..Default::default()
        },
    )?;
    let original = iterator.operation();
    let result = async {
        let mut buffers = Buffers::new()?;
        loop {
            match control.drive(iterator.drive(Some(control.hard))).await? {
                ns::Progress::Record {
                    operation, reply, ..
                } => {
                    if operation != original {
                        return Err("foreign record-line iterator row".into());
                    }
                    let ns::ipc::Response::Records {
                        zone,
                        label,
                        records,
                        ..
                    } = reply.view()?
                    else {
                        return Err("unexpected record-line iterator row".into());
                    };
                    if !ns::SecretKey::from_serialized(zone.expose_serialized())?
                        .constant_time_eq(&key)
                    {
                        return Err(
                            "record-line iterator returned a different private authority".into(),
                        );
                    }
                    export_group(
                        &mut buffers,
                        label.bytes(),
                        &owner,
                        records,
                        settings,
                        failure,
                        out,
                    )?;
                    control.gate().await?;
                    let _next = iterator.next(1, until)?;
                }
                ns::Progress::Completed(completion) if completion.operation == original => {
                    return export_completion(completion, failure);
                }
                ns::Progress::Completed(_) => {
                    return Err("foreign record-line iterator completion".into());
                }
                ns::Progress::Lost { cause, .. } => {
                    failure.store_loss.get_or_insert(cause);
                    return Err("original record-line iterator lost; cursor not replayed".into());
                }
                ns::Progress::Unavailable(error) => return Err(error.into()),
                ns::Progress::WaitDeadline => {
                    return Err("record-line iterator deadline before actual END".into());
                }
                ns::Progress::Closed => {
                    return Err("record-line iterator closed before actual END".into());
                }
                _ => {}
            }
        }
    }
    .await;
    if let Some(report) = iterator.close().or_else(|| iterator.take_close_report()) {
        failure.report.close_exposed = failure.report.close_exposed.max(report.exposed);
    }
    if result.is_err() {
        for _ in 0..4 {
            match iterator.drive(Some(Instant::now())).await {
                Ok(ns::Progress::Completed(completion)) if completion.operation == original => {
                    let _terminal = export_completion(completion, failure);
                    break;
                }
                Ok(ns::Progress::Lost { cause, .. }) => {
                    failure.store_loss.get_or_insert(cause);
                }
                Ok(ns::Progress::Closed | ns::Progress::WaitDeadline) => break,
                Err(error) => {
                    failure.cleanup.get_or_insert(Box::new(error));
                    break;
                }
                _ => {}
            }
        }
    }
    result
}
pub(super) fn help(out: &mut impl Write) -> Result<()> {
    writeln!(
        out,
        "namestore import-recordline <UNIXPATH> --identity-socket <UNIXPATH> [--input FILE|-] [OPTIONS]"
    )?;
    writeln!(
        out,
        "namestore export-recordline <UNIXPATH> --identity-socket <UNIXPATH> --ego NAME [OPTIONS]"
    )?;
    writeln!(
        out,
        "Record-line: <label>.<existing-ego-or-typed-public-key>: then indented TYPE EXPIRATION [pSrsC] VALUE. p=public, absent p=private; S=supplemental, r=relative microseconds, s=shadow, C=critical. Header-only groups are ignored. Import replaces each nonempty adjacent header group via one original atomic STORE; no whole-file transaction/replay. Export text goes to stdout, completion diagnostics to stderr; actual iterator END and exit0 are required. Export --filter U16 defaults0 (standard visibility; include-maintenance1/omit-private2). This is not a raw database backup. Returned maintenance/unknown flags and unrepresentable text fail rather than lose data. --timeout-ms default30000, --max-bytes default16777216 (input/import or output/export), --max-records/--max-sets default65536, --max-records-per-set default4095 (actual STORE frame may impose less), --max-egos default128, --record-profile native|little|big. Input lines<=262652 bytes; complete groups must fit one actual STORE frame; synchronous OS IO cannot be preempted."
    )?;
    Ok(())
}
pub(super) fn run(args: &[OsString], import_mode: bool, out: &mut impl Write) -> Result<()> {
    let settings = Settings::read(args, import_mode)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let mut failure = Failure::default();
    let mut original_hard = None;
    let result = runtime.block_on(async {
        let mut control = Control::new(settings.timeout)?;
        original_hard = Some(control.hard);
        control.gate().await?;
        let result = if import_mode {
            let reader: Box<dyn Read> = match &settings.input {
                Some(path) => Box::new(File::open(path)?),
                None => Box::new(io::stdin()),
            };
            let mut reader = Input::new(reader);
            import(&settings, &mut reader, out, &mut failure, &mut control).await
        } else {
            export(&settings, out, &mut failure, &mut control).await
        };
        let final_gate = control.gate().await;
        result.and(final_gate)
    });
    failure.original = result.err();
    // Flush before describing success. A later diagnostic error independently
    // fails the command and cannot erase real committed group counts.
    if let Err(error) = out.flush() {
        failure.flush.get_or_insert(error);
    }
    if original_hard.is_some_and(|hard| Instant::now() >= hard) && failure.original.is_none() {
        failure.original = Some(
            io::Error::new(
                io::ErrorKind::TimedOut,
                "original record-line deadline during output",
            )
            .into(),
        );
    }
    if import_mode {
        summary(out, &mut failure, true);
        if let Err(error) = out.flush() {
            failure.flush.get_or_insert(error);
        }
    } else {
        let mut diagnostics = io::stderr().lock();
        summary(&mut diagnostics, &mut failure, false);
        if let Err(error) = diagnostics.flush() {
            failure.diagnostic.get_or_insert_with(|| Box::new(error));
        }
    }
    if original_hard.is_some_and(|hard| Instant::now() >= hard) && failure.original.is_none() {
        failure.original = Some(
            io::Error::new(
                io::ErrorKind::TimedOut,
                "original record-line deadline during terminal output",
            )
            .into(),
        );
    }
    if failure.original.is_some()
        || failure.cleanup.is_some()
        || failure.identity_loss.is_some()
        || failure.store_loss.is_some()
        || failure.diagnostic.is_some()
        || failure.flush.is_some()
    {
        Err(Box::new(failure))
    } else {
        Ok(())
    }
}
