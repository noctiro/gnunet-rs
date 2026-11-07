//! Public zonefile import over the original IDENTITY/NAMESTORE clients.
use super::{KEY_BYTES, Result, bytes, row, text};
use gnunet::{
    clients::{identity, namestore as ns},
    crypto::Entropy,
    gnsrecord::{self, RecordData, RecordFlags, RecordType},
    gnsrecord_text::{self, Codec, Profile, Workspace, zonefile},
    idna,
    types::Error as Fault,
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

// Pinned gnunet_error_codes.h:71 and the admitted IDENTITY lookup wire contract.
const IDENTITY_NOT_FOUND: u32 = 200;
const FRAME_BYTES: usize = u16::MAX as usize;
const RECORDS_PER_NAME: usize = 50;

struct Settings {
    socket: PathBuf,
    identity: PathBuf,
    input: Option<PathBuf>,
    zone: Option<String>,
    timeout: Duration,
    input_bytes: usize,
    records: usize,
    zones: usize,
    profile: Profile,
}
impl Settings {
    fn read(args: &[OsString]) -> Result<Self> {
        let socket = PathBuf::from(args.first().ok_or("missing NAMESTORE UNIXPATH")?);
        let mut identity = None;
        let mut input = None;
        let mut zone = None;
        let mut timeout = 30_000u64;
        let mut input_bytes = 16 * 1024 * 1024;
        let mut records = 65536;
        let mut zones = 128;
        let mut profile = Profile::NATIVE_255;
        let mut at = 1;
        while at < args.len() {
            let option = text(&args[at])?;
            let value = args.get(at + 1).ok_or("missing zonefile option value")?;
            match option {
                "--identity-socket" => identity = Some(PathBuf::from(value)),
                "--input" => {
                    input = (value != OsStr::new("-")).then(|| PathBuf::from(value));
                }
                "--zone" => {
                    let name = text(value)?;
                    if name.is_empty() || name.len() > 255 || name.as_bytes().contains(&0) {
                        return Err("initial ego name must contain 1..=255 UTF-8 bytes".into());
                    }
                    zone = Some(name.to_owned());
                }
                "--timeout-ms" => timeout = text(value)?.parse()?,
                "--max-input-bytes" => input_bytes = text(value)?.parse()?,
                "--max-records" => records = text(value)?.parse()?,
                "--max-zones" => zones = text(value)?.parse()?,
                "--record-profile" => {
                    profile = match text(value)? {
                        "native" => Profile::NATIVE_255,
                        "little" => Profile::LITTLE_255,
                        "big" => Profile::BIG_255,
                        _ => return Err("record-profile must be native, little, or big".into()),
                    };
                }
                _ => return Err(format!("unknown zonefile option {option}").into()),
            }
            at += 2;
        }
        if !(1..=86_400_000).contains(&timeout)
            || !(1..=64 * 1024 * 1024).contains(&input_bytes)
            || !(1..=1_000_000).contains(&records)
            || !(1..=128).contains(&zones)
        {
            return Err("invalid finite zonefile time/input/record/origin bounds".into());
        }
        Ok(Self {
            socket,
            identity: identity.ok_or("required --identity-socket UNIXPATH")?,
            input,
            zone,
            timeout: Duration::from_millis(timeout),
            input_bytes,
            records,
            zones,
            profile,
        })
    }
    fn parser_limits(&self) -> zonefile::Limits {
        zonefile::Limits {
            input_bytes: self.input_bytes,
            records: self.records,
            records_per_name: RECORDS_PER_NAME,
            ..Default::default()
        }
    }
}

fn storage(n: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut value = Zeroizing::new(Vec::new());
    value.try_reserve_exact(n)?;
    value.resize(n, 0);
    Ok(value)
}
fn read_input(reader: &mut impl Read, maximum: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut input = Zeroizing::new(Vec::new());
    let mut chunk = Zeroizing::new([0u8; 8192]);
    loop {
        // One extra byte distinguishes real EOF from a truncated budget-sized file.
        let allowance = (maximum - input.len() + 1).min(chunk.len());
        let count = match reader.read(&mut chunk[..allowance]) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if count == 0 {
            return Ok(input);
        }
        if count > maximum - input.len() {
            return Err("zonefile input exceeds its complete byte budget".into());
        }
        input.try_reserve(count)?;
        input.extend_from_slice(&chunk[..count]);
    }
}

#[derive(Debug)]
struct CloseFacts {
    epoch: Option<String>,
    operations: usize,
    exposed: usize,
    control: bool,
}
impl CloseFacts {
    fn identity(report: identity::Loss<'_>) -> Self {
        Self {
            epoch: report.epoch.map(|epoch| format!("{epoch:?}")),
            operations: report.operations,
            exposed: report.exposed,
            control: false,
        }
    }
    fn store(report: ns::Loss<'_>) -> Self {
        Self {
            epoch: report.epoch.map(|epoch| format!("{epoch:?}")),
            operations: report.operations,
            exposed: report.exposed,
            control: report.control.is_some(),
        }
    }
    fn value(&self) -> serde_json::Value {
        json!({"epoch":self.epoch,"operations":self.operations,
            "exposed_operations":self.exposed,"control_pending":self.control})
    }
}
#[derive(Debug, Default)]
struct Report {
    input_bytes: usize,
    converted_records: u64,
    admitted_sets: u64,
    stored_sets: u64,
    stored_records: u64,
    created_egos: u64,
    staged_records: usize,
    pending_record: bool,
    legal_eof: bool,
    pending_create: bool,
    pending_store: bool,
    unknown: bool,
    identity_close: Option<CloseFacts>,
    store_close: Option<CloseFacts>,
}
#[derive(Debug, Default)]
struct Failure {
    original: Option<Box<dyn Error>>,
    entropy: Option<io::Error>,
    close_output: Option<io::Error>,
    summary_output: Option<io::Error>,
    flush: Option<io::Error>,
    report: Report,
}
impl Failure {
    fn failed(&self) -> bool {
        self.original.is_some()
            || self.entropy.is_some()
            || self.close_output.is_some()
            || self.summary_output.is_some()
            || self.flush.is_some()
    }
    fn close_row(&mut self, out: &mut impl Write, source: &str, facts: CloseFacts) {
        let value = facts.value();
        if facts.exposed != 0 {
            self.report.unknown |= (source == "namestore" && self.report.pending_store)
                || (source == "identity" && self.report.pending_create);
        }
        if source == "identity" {
            self.report.identity_close = Some(facts);
        } else {
            self.report.store_close = Some(facts);
        }
        if let Err(error) = writeln!(
            out,
            "{}",
            json!({
                "event":"zonefile_source_closed","source":source,"facts":value
            })
        ) {
            self.close_output.get_or_insert(error);
        }
    }
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NAMESTORE zonefile import report={:?}", self.report)?;
        if let Some(error) = &self.original {
            write!(f, "; original: {error}")?;
        }
        for (name, error) in [
            ("entropy", &self.entropy),
            ("close output", &self.close_output),
            ("summary output", &self.summary_output),
            ("flush", &self.flush),
        ] {
            if let Some(error) = error {
                write!(f, "; {name}: {error}")?;
            }
        }
        Ok(())
    }
}
impl Error for Failure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original.as_deref().or_else(|| {
            self.entropy
                .as_ref()
                .or(self.close_output.as_ref())
                .or(self.summary_output.as_ref())
                .or(self.flush.as_ref())
                .map(|error| error as _)
        })
    }
}
#[derive(Debug)]
struct OwnerIdnaFailure(idna::Error);
impl fmt::Display for OwnerIdnaFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "zonefile owner IDNA conversion: {:?}", self.0)
    }
}
impl Error for OwnerIdnaFailure {}

#[derive(Debug)]
enum SourceFailure {
    Identity(identity::LossCause),
    Store(ns::LossCause),
}
impl fmt::Display for SourceFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "original zonefile source lost: {self:?}")
    }
}
impl Error for SourceFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Identity(identity::LossCause::Io(error))
            | Self::Store(ns::LossCause::Io(error)) => Some(error),
            Self::Identity(identity::LossCause::Protocol(error))
            | Self::Identity(identity::LossCause::Resource(error))
            | Self::Store(ns::LossCause::Protocol(error))
            | Self::Store(ns::LossCause::Resource(error)) => Some(error),
            Self::Identity(identity::LossCause::Ports(error)) => Some(error),
            Self::Store(ns::LossCause::Ports(error)) => Some(error),
            _ => None,
        }
    }
}

struct Control {
    interrupt: Signal,
    terminate: Signal,
    hard: Instant,
    timer: Pin<Box<Sleep>>,
}
impl Control {
    fn new(hard: Instant) -> io::Result<Self> {
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
                "original zonefile import deadline",
            ));
        }
        for stream in [&mut self.interrupt, &mut self.terminate] {
            match stream.poll_recv(cx) {
                Poll::Ready(Some(())) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "zonefile import stopped",
                    ));
                }
                Poll::Ready(None) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "original zonefile signal source ended",
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
        operation: impl Future<Output = std::result::Result<T, E>>,
    ) -> Result<T> {
        let mut operation = std::pin::pin!(operation);
        poll_fn(|cx| {
            if let Err(error) = self.check(cx) {
                return Poll::Ready(Err(Box::new(error) as Box<dyn Error>));
            }
            operation
                .as_mut()
                .poll(cx)
                .map(|result| result.map_err(|error| Box::new(error) as Box<dyn Error>))
        })
        .await
    }
}

struct Execution<'a, W: Write> {
    until: u64,
    control: &'a mut Control,
    failure: &'a mut Failure,
    out: &'a mut W,
}

struct Random {
    file: File,
    error: Option<io::Error>,
}
impl Entropy for Random {
    fn fill(&mut self, output: &mut [u8]) -> std::result::Result<(), Fault> {
        match self.file.read_exact(output) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.error.get_or_insert(error);
                Err(Fault::Entropy)
            }
        }
    }
}
struct Zone {
    name: Vec<u8>,
    key: identity::SecretKey,
}

async fn lookup(
    name: &[u8],
    source: ns::EndpointSource,
    execution: &mut Execution<'_, impl Write>,
) -> Result<Option<identity::SecretKey>> {
    let Execution {
        until,
        control,
        failure,
        out,
    } = execution;
    let until = *until;
    control.gate().await?;
    let instance = identity::Instance::new();
    let limits = identity::Limits {
        reconnect: false,
        operations: 1,
        ..Default::default()
    };
    let mut lookup = identity::Lookup::exact(&instance, source, name, until, limits)?;
    let result = async {
        loop {
            match control.drive(lookup.drive(Some(control.hard))).await? {
                identity::LookupProgress::Finished {
                    outcome: identity::LookupOutcome::Found(ego),
                    ..
                } => {
                    return Ok(Some(ego.into_secret()));
                }
                identity::LookupProgress::Finished {
                    outcome: identity::LookupOutcome::ResultCode(IDENTITY_NOT_FOUND),
                    ..
                } => return Ok(None),
                identity::LookupProgress::Finished { outcome, .. } => {
                    return Err(
                        format!("IDENTITY lookup ended without a found ego: {outcome:?}").into(),
                    );
                }
                identity::LookupProgress::Source(identity::Progress::Lost { report, cause }) => {
                    failure.close_row(out, "identity", CloseFacts::identity(report));
                    return Err(Box::new(SourceFailure::Identity(cause)) as Box<dyn Error>);
                }
                identity::LookupProgress::Source(identity::Progress::Unavailable(error)) => {
                    return Err(error.into());
                }
                identity::LookupProgress::Source(identity::Progress::WaitDeadline) => {
                    return Err("IDENTITY lookup observation deadline".into());
                }
                identity::LookupProgress::Closed => {
                    return Err("IDENTITY lookup closed before a result".into());
                }
                _ => {}
            }
        }
    }
    .await;
    if let Some(report) = lookup.close() {
        failure.close_row(out, "identity", CloseFacts::identity(report));
    }
    result
}

async fn create(
    name: &[u8],
    source: ns::EndpointSource,
    execution: &mut Execution<'_, impl Write>,
) -> Result<identity::SecretKey> {
    let Execution {
        until,
        control,
        failure,
        out,
    } = execution;
    let until = *until;
    control.gate().await?;
    let instance = identity::Instance::new();
    let limits = identity::Limits {
        reconnect: false,
        operations: 1,
        ..Default::default()
    };
    let mut client = identity::Client::new(&instance, source, limits)?;
    let result = async {
        control.gate().await?;
        let mut random = Random { file: File::open("/dev/urandom")?, error: None };
        control.gate().await?;
        let submitted = client.create_generated(name, identity::KeyType::Eddsa, &mut random, until);
        failure.entropy = random.error.take();
        let operation = submitted?;
        failure.report.pending_create = true;
        loop {
            match control.drive(client.drive(Some(control.hard))).await? {
                identity::Progress::Completed(completion) if completion.operation == operation => {
                    return match completion.outcome {
                        identity::Outcome::Result { code: 0, created: Some(key) } => {
                            failure.report.pending_create = false;
                            failure.report.created_egos += 1;
                            row(out, json!({"event":"zonefile_ego_created","ego":String::from_utf8_lossy(name),"actual_result_code":0}))?;
                            Ok(key)
                        }
                        identity::Outcome::Result { code, .. } => {
                            failure.report.pending_create = false;
                            Err(format!("original IDENTITY CREATE returned code {code} or no creation material; not replayed").into())
                        }
                        identity::Outcome::Local { reason, submission, result_code, .. } => {
                            failure.report.unknown |= !matches!(submission, identity::Submission::Unsent);
                            if matches!(submission, identity::Submission::Unsent) {
                                failure.report.pending_create = false;
                            }
                            Err(format!("original IDENTITY CREATE ended locally: {reason:?}, {submission:?}, result {result_code:?}; not replayed").into())
                        }
                        identity::Outcome::Found(_) => Err("unexpected lookup result on original CREATE operation".into()),
                    };
                }
                identity::Progress::Completed(_) => return Err("foreign IDENTITY CREATE completion".into()),
                identity::Progress::Lost { report, cause } => {
                    failure.close_row(out, "identity", CloseFacts::identity(report));
                    return Err(Box::new(SourceFailure::Identity(cause)) as Box<dyn Error>);
                }
                identity::Progress::Unavailable(error) => return Err(error.into()),
                identity::Progress::WaitDeadline => return Err("IDENTITY CREATE observation deadline; outcome may be unknown".into()),
                identity::Progress::Closed => return Err("IDENTITY CREATE closed without its original result".into()),
                _ => {}
            }
        }
    }.await;
    if let Some(report) = client.close() {
        failure.close_row(out, "identity", CloseFacts::identity(report));
    }
    result
}

async fn zone(
    name: &[u8],
    initial: bool,
    settings: &Settings,
    zones: &mut Vec<Zone>,
    source: &ns::EndpointSource,
    execution: &mut Execution<'_, impl Write>,
) -> Result<usize> {
    if let Some(index) = zones.iter().position(|zone| zone.name == name) {
        return Ok(index);
    }
    if zones.len() == settings.zones {
        return Err("zonefile origin cache capacity exhausted".into());
    }
    execution.control.gate().await?;
    let found = lookup(name, source.duplicate()?, execution).await?;
    if execution.failure.close_output.is_some() {
        return Err("zonefile identity close diagnostic failed".into());
    }
    let key = match found {
        Some(key) => key,
        None if initial => {
            return Err("initial --zone ego does not exist; no key was created".into());
        }
        None => {
            execution.control.gate().await?;
            create(name, source.duplicate()?, execution).await?
        }
    };
    if execution.failure.close_output.is_some() {
        return Err("zonefile identity close diagnostic failed".into());
    }
    zones.push(Zone {
        name: name.to_vec(),
        key,
    });
    Ok(zones.len() - 1)
}

struct Buffers {
    stage: Zeroizing<Vec<u8>>,
    names: Zeroizing<Vec<u8>>,
    work: Zeroizing<Vec<u8>>,
    value: Zeroizing<Vec<u8>>,
    unicode: Zeroizing<Vec<u8>>,
    records: Zeroizing<Vec<u8>>,
    sets: Zeroizing<Vec<u8>>,
    idna: idna::Workspace,
}
struct Pending {
    origin: Vec<u8>,
    raw_owner: Vec<u8>,
    owner: Vec<u8>,
    ttl: u64,
    kind: RecordType,
    bytes: usize,
}
impl Buffers {
    fn new() -> Result<Self> {
        Ok(Self {
            stage: storage(FRAME_BYTES)?,
            names: storage(1024)?,
            work: storage(4096)?,
            value: storage(FRAME_BYTES)?,
            unicode: storage(1024)?,
            records: storage(FRAME_BYTES)?,
            sets: storage(FRAME_BYTES)?,
            idna: idna::Workspace::new(),
        })
    }
    fn convert(&mut self, record: zonefile::Record<'_>, profile: Profile) -> Result<Pending> {
        let bytes = {
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
                    input_bytes: FRAME_BYTES,
                    output_bytes: FRAME_BYTES,
                    ..Default::default()
                },
            )?;
            codec.string_to_value(record.record_type, record.value, &mut self.value)?
        };
        let count = idna::to_unicode(
            record.owner.as_bytes(),
            &mut self.unicode,
            &mut self.idna,
            idna::Limits::GNUNET,
        )
        .map_err(OwnerIdnaFailure)?;
        let owner = &self.unicode[..count];
        if owner.is_empty() || owner.len() > 255 {
            return Err("zonefile decoded owner exceeds NAMESTORE label bound".into());
        }
        ns::ipc::CString::new(owner)?;
        Ok(Pending {
            origin: record.origin.as_bytes().to_vec(),
            raw_owner: record.owner.as_bytes().to_vec(),
            owner: owner.to_vec(),
            ttl: record.ttl_micros,
            kind: record.record_type,
            bytes,
        })
    }
}
struct Meta {
    start: usize,
    end: usize,
    ttl: u64,
    kind: RecordType,
}
struct Group {
    origin: Vec<u8>,
    raw_owner: Vec<u8>,
    owner: Vec<u8>,
    data: Zeroizing<Vec<u8>>,
    records: Vec<Meta>,
}
impl Group {
    fn new() -> Result<Self> {
        let mut data = Zeroizing::new(Vec::new());
        data.try_reserve_exact(FRAME_BYTES)?;
        let mut records = Vec::new();
        records.try_reserve_exact(RECORDS_PER_NAME)?;
        Ok(Self {
            origin: Vec::new(),
            raw_owner: Vec::new(),
            owner: Vec::new(),
            data,
            records,
        })
    }
    fn same(&self, pending: &Pending) -> bool {
        self.origin == pending.origin && self.raw_owner == pending.raw_owner
    }
    fn push(&mut self, pending: Pending, value: &[u8]) -> Result<()> {
        if self.records.is_empty() {
            self.origin = pending.origin;
            self.raw_owner = pending.raw_owner;
            self.owner = pending.owner;
        }
        if self.records.len() >= RECORDS_PER_NAME {
            return Err("zonefile adjacent group exceeds50 records".into());
        }
        let end = self
            .data
            .len()
            .checked_add(pending.bytes)
            .ok_or("zonefile group byte overflow")?;
        let headers = (self.records.len() + 1)
            .checked_mul(gnsrecord::RECORD_HEADER_LEN)
            .ok_or("zonefile record header overflow")?;
        if end
            .checked_add(headers)
            .is_none_or(|length| length > FRAME_BYTES)
        {
            return Err("zonefile group cannot fit one NAMESTORE STORE".into());
        }
        let start = self.data.len();
        self.data.extend_from_slice(&value[..pending.bytes]);
        self.records.push(Meta {
            start,
            end,
            ttl: pending.ttl,
            kind: pending.kind,
        });
        Ok(())
    }
    fn clear(&mut self) {
        self.data.as_mut_slice().zeroize();
        self.data.clear();
        self.records.clear();
        self.origin.clear();
        self.raw_owner.clear();
        self.owner.clear();
    }
    fn encode(&self, buffers: &mut Buffers, limits: ns::Limits) -> Result<usize> {
        let mut records = [RecordData {
            expiration_time: 0,
            record_type: RecordType::ANY,
            flags: RecordFlags::NONE,
            data: &[],
        }; RECORDS_PER_NAME];
        for (destination, meta) in records.iter_mut().zip(&self.records) {
            *destination = RecordData {
                expiration_time: meta.ttl,
                record_type: meta.kind,
                flags: RecordFlags::RELATIVE_EXPIRATION,
                data: &self.data[meta.start..meta.end],
            };
            destination.validate_fixed_size()?;
        }
        let length = gnsrecord::serialize(&records[..self.records.len()], &mut buffers.records)?;
        let set = ns::ipc::StoreSet {
            label: ns::ipc::CString::new(&self.owner)?,
            records: ns::ipc::Records::new(
                &buffers.records[..length],
                u16::try_from(self.records.len())?,
            )?,
            reserved: 0,
        };
        let sets = [set];
        let length = ns::ipc::encoded_sets_len(&sets)?;
        let total = ns::ipc::STORE_PREFIX
            .checked_add(KEY_BYTES)
            .and_then(|bytes| bytes.checked_add(length))
            .ok_or("zonefile STORE length overflow")?;
        if total > limits.frame_bytes || total > limits.source_bytes {
            return Err("entire zonefile group does not fit one original STORE frame".into());
        }
        ns::ipc::encode_sets(&sets, &mut buffers.sets)?;
        Ok(length)
    }
}

async fn store(
    group: &mut Group,
    buffers: &mut Buffers,
    client: &mut ns::Client<'_>,
    zones: &[Zone],
    execution: &mut Execution<'_, impl Write>,
) -> Result<()> {
    let Execution {
        until,
        control,
        failure,
        out,
    } = execution;
    let until = *until;
    if group.records.is_empty() {
        return Ok(());
    }
    control.gate().await?;
    let zone = zones
        .iter()
        .find(|zone| zone.name == group.origin)
        .ok_or("zonefile group has no actual resolved ego")?;
    let limits = ns::Limits {
        reconnect: false,
        operations: 1,
        ..Default::default()
    };
    let length = group.encode(buffers, limits)?;
    control.gate().await?;
    let operation = client.store(
        &zone.key,
        ns::ipc::RecordSets::new(&buffers.sets[..length], 1)?,
        true,
        until,
    )?;
    failure.report.admitted_sets += 1;
    failure.report.pending_store = true;
    loop {
        match control.drive(client.drive(Some(control.hard))).await? {
            ns::Progress::Completed(completion) if completion.operation == operation => {
                match completion.outcome {
                    ns::Outcome::Reply(reply) => {
                        let response = reply.view()?;
                        let ns::ipc::Response::Generic { code, .. } = response else {
                            return Err("unexpected original zonefile STORE response".into());
                        };
                        failure.report.pending_store = false;
                        if code == 0 {
                            failure.report.stored_sets += 1;
                            failure.report.stored_records += u64::try_from(group.records.len())?;
                            failure.report.staged_records = 0;
                        }
                        // Receipt facts precede output. Output failure cannot erase a real commit result.
                        row(
                            out,
                            json!({"event":"zonefile_store_result","origin":String::from_utf8_lossy(&group.origin),"label":String::from_utf8_lossy(&group.owner),"code":code,"stored_sets":failure.report.stored_sets,"stored_records":failure.report.stored_records}),
                        )?;
                        if code != 0 {
                            return Err(
                                format!("NAMESTORE STORE returned actual code {code}").into()
                            );
                        }
                        group.clear();
                        return Ok(());
                    }
                    ns::Outcome::Local { reason, submission } => {
                        failure.report.unknown |= !matches!(submission, ns::Submission::Unsent);
                        if matches!(submission, ns::Submission::Unsent) {
                            failure.report.pending_store = false;
                        }
                        return Err(format!(
                            "zonefile STORE ended locally: {reason:?}, {submission:?}; not replayed"
                        )
                        .into());
                    }
                }
            }
            ns::Progress::Completed(_) => return Err("foreign zonefile STORE completion".into()),
            ns::Progress::Lost { report, cause } => {
                failure.report.unknown |= report.exposed != 0;
                failure.close_row(out, "namestore", CloseFacts::store(report));
                return Err(Box::new(SourceFailure::Store(cause)));
            }
            ns::Progress::Unavailable(error) => return Err(error.into()),
            ns::Progress::WaitDeadline => {
                return Err("zonefile STORE observation deadline; outcome may be unknown".into());
            }
            ns::Progress::Closed => {
                return Err("zonefile STORE closed without its original result".into());
            }
            _ => {}
        }
    }
}

async fn execute(settings: &Settings, input: &str, out: &mut impl Write) -> Result<()> {
    let mut failure = Failure {
        report: Report {
            input_bytes: input.len(),
            ..Default::default()
        },
        ..Default::default()
    };
    // Freeze the original native budget before source/canonical preparation.
    let hard = Instant::now()
        .checked_add(settings.timeout)
        .ok_or("zonefile native deadline overflow")?;
    let mut control = Control::new(hard)?;
    control.gate().await?;
    let source = ns::EndpointSource::unix(settings.socket.clone());
    let identity_source =
        ns::EndpointSource::unix_with_clock(settings.identity.clone(), source.clock());
    let now = source.clock().sample()?.now.as_micros();
    let until = now
        .checked_add(u64::try_from(settings.timeout.as_micros())?)
        .filter(|until| *until != u64::MAX)
        .ok_or("zonefile canonical deadline overflow")?;
    let mut scratch = storage(FRAME_BYTES)?;
    let mut parser = zonefile::Parser::new(
        input,
        settings.zone.as_deref(),
        &mut scratch,
        settings.parser_limits(),
    )?;
    let mut buffers = Buffers::new()?;
    let mut group = Group::new()?;
    let mut zones = Vec::new();
    zones.try_reserve_exact(settings.zones)?;
    let instance = ns::Instance::new();
    let limits = ns::Limits {
        reconnect: false,
        operations: 1,
        ..Default::default()
    };
    control.gate().await?;
    let mut client = ns::Client::new(&instance, source, limits)?;
    let result = {
        let mut execution = Execution {
            until,
            control: &mut control,
            failure: &mut failure,
            out,
        };
        async {
            loop {
                execution.control.gate().await?;
                if execution.failure.close_output.is_some() {
                    return Err("zonefile close output failed".into());
                }
                match parser.next_event()? {
                    Some(zonefile::Event::Origin(origin)) => {
                        let initial = origin.initial;
                        let name = bytes(OsStr::new(origin.name), 255, "origin ego")?;
                        store(
                            &mut group,
                            &mut buffers,
                            &mut client,
                            &zones,
                            &mut execution,
                        )
                        .await?;
                        zone(
                            &name,
                            initial,
                            settings,
                            &mut zones,
                            &identity_source,
                            &mut execution,
                        )
                        .await?;
                    }
                    Some(zonefile::Event::Record(record)) => {
                        let pending = buffers.convert(record, settings.profile)?;
                        execution.failure.report.converted_records += 1;
                        execution.failure.report.pending_record = true;
                        if !group.records.is_empty() && !group.same(&pending) {
                            store(
                                &mut group,
                                &mut buffers,
                                &mut client,
                                &zones,
                                &mut execution,
                            )
                            .await?;
                        }
                        group.push(pending, &buffers.value)?;
                        execution.failure.report.pending_record = false;
                        execution.failure.report.staged_records = group.records.len();
                        if execution
                            .failure
                            .report
                            .converted_records
                            .is_multiple_of(64)
                        {
                            tokio::task::yield_now().await;
                        }
                    }
                    Some(zonefile::Event::End) => {
                        execution.failure.report.legal_eof = true;
                        store(
                            &mut group,
                            &mut buffers,
                            &mut client,
                            &zones,
                            &mut execution,
                        )
                        .await?;
                        return Ok(());
                    }
                    None => return Err("zonefile parser ended without its legal EOF event".into()),
                }
            }
        }
        .await
    };
    failure.original = result.err();
    // Never consult the clock while physically retiring the sole original MQ.
    if let Some(report) = client.close() {
        failure.close_row(out, "namestore", CloseFacts::store(report));
    }
    let successful = !failure.failed() && failure.report.legal_eof && !failure.report.pending_store;
    if let Err(error) = writeln!(
        out,
        "{}",
        json!({"event":"zonefile_import_finished","successful":successful,
        "input_bytes":failure.report.input_bytes,"converted_records":failure.report.converted_records,
        "admitted_sets":failure.report.admitted_sets,
        "stored_sets":failure.report.stored_sets,"stored_records":failure.report.stored_records,
        "created_egos":failure.report.created_egos,"staged_records":failure.report.staged_records,
        "converted_unstaged_record":failure.report.pending_record,
        "legal_eof":failure.report.legal_eof,"create_without_result":failure.report.pending_create,
        "store_without_result":failure.report.pending_store,"unknown":failure.report.unknown,
        "identity_close":failure.report.identity_close.as_ref().map(CloseFacts::value),
        "namestore_close":failure.report.store_close.as_ref().map(CloseFacts::value)})
    ) {
        failure.summary_output = Some(error);
    }
    failure.flush = out.flush().err();
    if failure.failed() {
        Err(Box::new(failure))
    } else {
        Ok(())
    }
}

pub(super) fn run(args: &[OsString], out: &mut impl Write) -> Result<()> {
    if args.is_empty() || args.first().is_some_and(|arg| arg == OsStr::new("--help")) {
        return help(out);
    }
    let settings = Settings::read(args)?;
    // No native protocol/ego/key capability exists during these synchronous OS
    // reads. Size is bounded; a blocked read is not advertised as cancelable by
    // an asynchronous deadline. The single protocol deadline starts afterwards.
    let input = match &settings.input {
        Some(path) => read_input(&mut File::open(path)?, settings.input_bytes)?,
        None => read_input(&mut io::stdin().lock(), settings.input_bytes)?,
    };
    let text = std::str::from_utf8(&input)?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(execute(&settings, text, out))
}

pub(super) fn help(out: &mut impl Write) -> Result<()> {
    writeln!(
        out,
        "namestore import-zonefile <UNIXPATH> --identity-socket UNIXPATH [--zone EGO] [--input FILE|-] [--timeout-ms N] [--max-input-bytes N] [--max-records N] [--max-zones N] [--record-profile native|little|big]"
    )?;
    writeln!(
        out,
        "Reads bounded complete UTF-8 input before any ego/create/STORE work; default stdin,16MiB,65536 records,128 origins. Synchronous OS reads can block and are not canceled by the later protocol deadline. The single protocol deadline (default30000ms) covers parsing, actual ego lookup/create and every STORE; it never renews per group."
    )?;
    writeln!(
        out,
        "$ORIGIN selects an ego (missing names are created as EdDSA only after actual IDENTITY_NOT_FOUND); optional --zone requires an existing literal ego. $TTL is decimal seconds, starts0 and sets relative-expiration microseconds. IN inherits the previous owner; relative/FQDN owners and apex @ are supported. Quotes, parentheses and backslashes in record text are passed to the existing type codec; RDATA domains are not expanded by $ORIGIN."
    )?;
    writeln!(
        out,
        "Each adjacent origin/owner group replaces one complete label set; nonadjacent repetitions replace again, never append or form a whole-file transaction. A group is limited to50 records and one actual STORE frame. Legal EOF flushes the final group. Late syntax/conversion/service errors preserve previously stored groups and report the staged/unknown remainder. Only original successful service results increment stored counts; local writes/admission are separate. Unknown writes/creates are never replayed. Native/little/big selects the existing Messenger record producer layout, default native."
    )?;
    Ok(())
}
