//! NAMESTORE commands with opaque IDENTITY lookup and original bounded MQs.
mod orphans;
mod recordline;
mod zonefile;
use super::peer::hexadecimal;
use gnunet::{
    clients::{
        identity::{self, Lookup, LookupOutcome, LookupProgress},
        namestore::{
            Client, ControlKind, EndpointSource, Instance, Limits, Loss, Monitor, Operation,
            Outcome, Progress, SecretKey, ZoneIterator, ipc,
        },
    },
    gnsrecord::{self, RecordData, RecordFlags, RecordType, ZoneKey},
};
use serde_json::{Value, json};
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
use zeroize::Zeroizing;
type Result<T> = std::result::Result<T, Box<dyn Error>>;
const MAX_JSON_BYTES: usize = 1024 * 1024;
const MAX_TIMEOUT_MS: u64 = 86_400_000;
const KEY_BYTES: usize = gnunet::wire::identity::KEY_LEN;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    Lookup,
    Replace,
    ImportUri,
    Delete,
    Batch,
    Reverse,
    Iterate,
    Monitor,
    EditBegin,
    EditCancel,
}
struct EncodedSets {
    bytes: Zeroizing<Vec<u8>>,
    count: u16,
}
struct Command {
    action: Action,
    socket: PathBuf,
    identity_socket: PathBuf,
    ego: Vec<u8>,
    label: Vec<u8>,
    hint: Vec<u8>,
    replacement: Vec<u8>,
    sets: Option<EncodedSets>,
    target: Option<ZoneKey>,
    single_tx: bool,
    filter: u16,
    iterate_first: bool,
    max_results: u64,
    timeout: Duration,
    limits: Limits,
}
fn bytes(value: &OsStr, maximum: usize, what: &str) -> Result<Vec<u8>> {
    let value = value.as_bytes();
    if value.len() > maximum || value.contains(&0) {
        return Err(format!("invalid {what}: embedded NUL or size above {maximum} bytes").into());
    }
    Ok(value.to_vec())
}
fn text(value: &OsStr) -> Result<&str> {
    value
        .to_str()
        .ok_or_else(|| "expected UTF-8 option/input".into())
}
fn unhex(text: &str) -> Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) || text.len() / 2 > usize::from(u16::MAX) {
        return Err("data_hex must contain an even, bounded number of hex digits".into());
    }
    let digit = |v| match v {
        b'0'..=b'9' => Some(v - b'0'),
        b'a'..=b'f' => Some(v - b'a' + 10),
        b'A'..=b'F' => Some(v - b'A' + 10),
        _ => None,
    };
    let mut output = Vec::new();
    output.try_reserve_exact(text.len() / 2)?;
    for pair in text.as_bytes().as_chunks::<2>().0 {
        output.push(
            digit(pair[0]).ok_or("invalid hexadecimal value")? << 4
                | digit(pair[1]).ok_or("invalid hexadecimal value")?,
        );
    }
    Ok(output)
}
fn json_value(value: &OsStr) -> Result<Value> {
    let value = text(value)?;
    if value.len() > MAX_JSON_BYTES {
        return Err("JSON input exceeds the 1 MiB local input bound".into());
    }
    Ok(serde_json::from_str(value)?)
}
fn unsigned(value: &Value, field: &str) -> Result<u64> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing or invalid unsigned field {field}").into())
}
fn keys(value: &Value, allowed: &[&str]) -> Result<()> {
    let object = value.as_object().ok_or("expected a JSON object")?;
    if object.keys().any(|k| !allowed.contains(&k.as_str())) {
        return Err("unknown JSON object field".into());
    }
    Ok(())
}
struct SerializedRecords {
    bytes: Zeroizing<Vec<u8>>,
    count: u16,
}
fn records(value: &Value, limits: Limits) -> Result<SerializedRecords> {
    let records = value.as_array().ok_or("records must be a JSON array")?;
    if records.len() > limits.records {
        return Err("too many records in one label".into());
    }
    let count = u16::try_from(records.len())?;
    let mut payloads = Vec::new();
    payloads.try_reserve_exact(records.len())?;
    for record in records {
        keys(record, &["type", "flags", "expiration_us", "data_hex"])?;
        payloads.push(Zeroizing::new(unhex(
            record
                .get("data_hex")
                .and_then(Value::as_str)
                .ok_or("record requires data_hex string")?,
        )?));
    }
    let mut borrowed = Vec::new();
    borrowed.try_reserve_exact(records.len())?;
    for (record, payload) in records.iter().zip(&payloads) {
        let data = RecordData {
            expiration_time: unsigned(record, "expiration_us")?,
            record_type: RecordType::new(u32::try_from(unsigned(record, "type")?)?),
            flags: RecordFlags::from_bits_preserve(u16::try_from(
                record
                    .get("flags")
                    .map_or(Ok(0), |v| v.as_u64().ok_or("invalid record flags"))?,
            )?),
            data: payload,
        };
        data.validate_fixed_size()?;
        borrowed.push(data);
    }
    let len = gnsrecord::serialized_len(&borrowed)?;
    if len > usize::from(u16::MAX) {
        return Err("one record set exceeds the official 16-bit length".into());
    }
    let mut serialized = Zeroizing::new(Vec::new());
    serialized.try_reserve_exact(len)?;
    serialized.resize(len, 0);
    gnsrecord::serialize(&borrowed, &mut serialized)?;
    ipc::Records::new(&serialized, count)?;
    Ok(SerializedRecords {
        bytes: serialized,
        count,
    })
}
fn encode_sets(value: Value, limits: Limits) -> Result<EncodedSets> {
    let sets = value
        .as_array()
        .ok_or("batch must be an array of label/records objects")?;
    if sets.is_empty() || sets.len() > limits.record_sets {
        return Err("batch requires 1..=512 complete label sets".into());
    }
    let mut serialized = Vec::new();
    serialized.try_reserve_exact(sets.len())?;
    let mut labels = Vec::new();
    labels.try_reserve_exact(sets.len())?;
    for set in sets {
        keys(set, &["label", "records"])?;
        let label = set
            .get("label")
            .and_then(Value::as_str)
            .ok_or("set requires label string")?;
        if label.len() > limits.label_bytes {
            return Err("label exceeds the official 255-byte bound".into());
        }
        ipc::CString::new(label.as_bytes())?;
        labels.push(label);
        serialized.push(records(
            set.get("records").ok_or("set requires records")?,
            limits,
        )?);
    }
    let borrowed = labels
        .iter()
        .zip(&serialized)
        .map(|(label, records)| {
            Ok(ipc::StoreSet {
                label: ipc::CString::new(label.as_bytes())?,
                records: ipc::Records::new(&records.bytes, records.count)?,
                reserved: 0,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let len = ipc::encoded_sets_len(&borrowed)?;
    let frame_len = ipc::STORE_PREFIX
        .checked_add(KEY_BYTES)
        .and_then(|n| n.checked_add(len))
        .ok_or("batch length overflow")?;
    if frame_len > limits.frame_bytes || frame_len > limits.source_bytes {
        return Err("entire batch does not fit ONE official STORE frame; nothing has been sent (split it explicitly, or reduce the batch)".into());
    }
    let mut encoded = Zeroizing::new(Vec::new());
    encoded.try_reserve_exact(len)?;
    encoded.resize(len, 0);
    ipc::encode_sets(&borrowed, &mut encoded)?;
    Ok(EncodedSets {
        bytes: encoded,
        count: u16::try_from(sets.len())?,
    })
}
fn import_uri(
    value: &OsStr,
    expiration: u64,
    flags: RecordFlags,
    limits: Limits,
) -> Result<(Vec<u8>, EncodedSets)> {
    let value = text(value)?;
    let rest = value
        .strip_prefix("gnunet://gns/")
        .ok_or("expected gnunet://gns/<typed-public-key>/<label>")?;
    let maximum = 58usize
        .checked_add(1)
        .and_then(|length| length.checked_add(limits.label_bytes))
        .ok_or("GNS URI length limit overflow")?;
    if rest.len() > maximum {
        return Err("GNS URI exceeds the public key and label length bounds".into());
    }
    let (key, label) = rest
        .split_once('/')
        .ok_or("GNS URI requires one public key and label")?;
    // Public text decoding is not key or delegation authentication. Use the
    // existing typed public-key decoder and preserve the label for server NFC.
    let key = ZoneKey::from_ztld(key)?;
    if label.is_empty()
        || label.len() > limits.label_bytes
        || label.contains(['/', '?', '#'])
        || label.chars().any(char::is_whitespace)
        || label.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(
            "GNS URI requires one nonempty bounded label, with no query or fragment".into(),
        );
    }
    ipc::CString::new(label.as_bytes())?;
    // The normal public GNSRECORD data_from_identity contract excludes type32
    // from the record value. The record's own type identifies these 32 bytes.
    let sets = encode_sets(
        json!([{"label":label,"records":[{
            "type":key.kind().record_type().value(),
            "flags":flags.bits(),
            "expiration_us":expiration,
            "data_hex":hexadecimal(key.key())
        }]}]),
        limits,
    )?;
    Ok((label.as_bytes().to_vec(), sets))
}
fn parse(args: &[OsString]) -> Result<Command> {
    let (action, positional) = match args.first().and_then(|s| s.to_str()) {
        Some("lookup") => (Action::Lookup, 1),
        Some("replace") => (Action::Replace, 2),
        Some("import-uri") => (Action::ImportUri, 1),
        Some("delete") => (Action::Delete, 1),
        Some("batch") => (Action::Batch, 1),
        Some("reverse") => (Action::Reverse, 1),
        Some("iterate") => (Action::Iterate, 0),
        Some("monitor") => (Action::Monitor, 0),
        Some("edit-begin") => (Action::EditBegin, 2),
        Some("edit-cancel") => (Action::EditCancel, 3),
        _ => return Err("expected namestore lookup|replace|import-uri|delete|batch|reverse|iterate|monitor|edit-begin|edit-cancel".into()),
    };
    let socket = PathBuf::from(args.get(1).ok_or("missing explicit NAMESTORE UNIXPATH")?);
    let inputs = args
        .get(2..2 + positional)
        .ok_or("missing command arguments")?;
    let mut identity_socket = None;
    let mut ego = None;
    let mut timeout_ms = if action == Action::Monitor {
        300_000
    } else {
        30_000
    };
    let mut max_results = 1000;
    let mut filter = 0;
    let mut single_tx = true;
    let mut iterate_first = true;
    let mut uri_expiration = None;
    let mut uri_relative = false;
    let mut uri_shadow = false;
    let mut uri_maintenance = false;
    let limits = Limits {
        reconnect: false,
        operations: 1,
        ..Limits::default()
    };
    let mut at = 2 + positional;
    while at < args.len() {
        let option = text(&args[at])?;
        let value = args.get(at + 1).ok_or("missing NAMESTORE option value")?;
        match option {
            "--identity-socket" => identity_socket = Some(PathBuf::from(value)),
            "--ego" => {
                ego = Some(bytes(
                    value,
                    identity::Limits::default().name_bytes,
                    "ego name",
                )?)
            }
            "--timeout-ms" => timeout_ms = text(value)?.parse()?,
            "--filter" if matches!(action, Action::Lookup | Action::Iterate | Action::Monitor) => {
                filter = text(value)?.parse()?
            }
            "--limit" if matches!(action, Action::Iterate | Action::Monitor) => {
                max_results = text(value)?.parse()?
            }
            "--single-tx" if action == Action::Batch => single_tx = boolean(value)?,
            "--initial" if action == Action::Monitor => iterate_first = boolean(value)?,
            "--expiration-us" if action == Action::ImportUri => {
                uri_expiration = Some(text(value)?.parse::<u64>()?);
            }
            "--relative" if action == Action::ImportUri => uri_relative = boolean(value)?,
            "--shadow" if action == Action::ImportUri => uri_shadow = boolean(value)?,
            "--maintenance" if action == Action::ImportUri => uri_maintenance = boolean(value)?,
            _ => return Err(format!("unknown or inapplicable NAMESTORE option {option}").into()),
        }
        at += 2;
    }
    let identity_socket = identity_socket.ok_or("required --identity-socket UNIXPATH")?;
    let ego = ego.ok_or("required --ego NAME (resolved by real IDENTITY lookup)")?;
    if timeout_ms == 0 || timeout_ms > MAX_TIMEOUT_MS || max_results == 0 || max_results > 1_000_000
    {
        return Err("invalid finite timeout (1..=86400000ms) or result bound (1..=1000000)".into());
    }
    let timeout = Duration::from_millis(timeout_ms);
    if Instant::now().checked_add(timeout).is_none() {
        return Err("native timeout overflow".into());
    }
    let mut command = Command {
        action,
        socket,
        identity_socket,
        ego,
        label: Vec::new(),
        hint: Vec::new(),
        replacement: Vec::new(),
        sets: None,
        target: None,
        single_tx,
        filter,
        iterate_first,
        max_results,
        timeout,
        limits,
    };
    if matches!(
        action,
        Action::Lookup | Action::Replace | Action::Delete | Action::EditBegin | Action::EditCancel
    ) {
        command.label = bytes(&inputs[0], limits.label_bytes, "label")?;
        // Case and Unicode are preserved; actual service applies official NFC policy.
        std::str::from_utf8(&command.label)?;
        ipc::CString::new(&command.label)?;
    }
    match action {
        Action::ImportUri => {
            let mut flags = RecordFlags::NONE;
            if uri_relative {
                flags = flags.union(RecordFlags::RELATIVE_EXPIRATION);
            }
            if uri_shadow {
                flags = flags.union(RecordFlags::SHADOW);
            }
            if uri_maintenance {
                flags = flags.union(RecordFlags::MAINTENANCE);
            }
            let (label, sets) = import_uri(
                &inputs[0],
                uri_expiration.ok_or("import-uri requires --expiration-us U64")?,
                flags,
                limits,
            )?;
            command.label = label;
            command.sets = Some(sets);
        }
        Action::Replace | Action::Delete => {
            let input = if action == Action::Delete {
                json!([])
            } else {
                json_value(&inputs[1])?
            };
            let label = std::str::from_utf8(&command.label)?;
            command.sets = Some(encode_sets(
                json!([{"label":label,"records":input}]),
                limits,
            )?);
        }
        Action::Batch => command.sets = Some(encode_sets(json_value(&inputs[0])?, limits)?),
        Action::Reverse => {
            let value = text(&inputs[0])?;
            command.target = Some(if value.len() == 72 {
                ZoneKey::from_wire(&unhex(value)?)?
            } else {
                ZoneKey::from_ztld(value)?
            });
        }
        Action::EditBegin | Action::EditCancel => {
            command.hint = bytes(&inputs[1], limits.hint_bytes, "hint")?;
            ipc::CString::new(&command.hint)?;
            if action == Action::EditCancel {
                command.replacement = bytes(&inputs[2], limits.hint_bytes, "replacement hint")?;
                ipc::CString::new(&command.replacement)?;
            }
            let frame = ipc::EDIT_PREFIX
                + KEY_BYTES
                + command.label.len()
                + 1
                + command.hint.len()
                + 1
                + if action == Action::EditCancel {
                    command.replacement.len() + 1
                } else {
                    0
                };
            if frame > limits.frame_bytes {
                return Err("editor-hint frame exceeds wire bound".into());
            }
        }
        _ => {}
    }
    Ok(command)
}
fn boolean(value: &OsStr) -> Result<bool> {
    match text(value)? {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err("expected 0 or 1".into()),
    }
}
fn row(out: &mut impl Write, value: Value) -> Result<()> {
    serde_json::to_writer(&mut *out, &value)?;
    writeln!(out)?;
    out.flush()?;
    Ok(())
}
fn records_json(records: ipc::Records<'_>) -> Result<Value> {
    let mut output = Vec::new();
    output.try_reserve_exact(usize::from(records.count()))?;
    for record in records.records().iter() {
        let record = record?;
        output.push(
            json!({"type":record.record_type.value(),"flags":record.flags.bits(),
            "expiration_us":record.expiration_time,"data_hex":hexadecimal(record.data)}),
        );
    }
    Ok(Value::Array(output))
}
fn string_json(value: &[u8]) -> Value {
    json!({"text":String::from_utf8_lossy(value),"bytes_hex":hexadecimal(value)})
}
fn reply(out: &mut impl Write, response: ipc::Response<'_>) -> Result<()> {
    // Deliberately enumerate fields: no response Debug or serialized zone key.
    let value = match response {
        ipc::Response::Generic { rid, code } => {
            json!({"event":"namestore_result","rid":rid,"code":code})
        }
        ipc::Response::Lookup {
            rid,
            label,
            found,
            records,
            ..
        } => json!({
            "event":"namestore_lookup","rid":rid,"label":string_json(label.bytes()),"found":found,"records":records_json(records)?}),
        ipc::Response::ZoneToName {
            rid,
            code,
            label,
            records,
            ..
        } => json!({
            "event":"namestore_reverse","rid":rid,"code":code,"label":label.map(|s|string_json(s.bytes())),"records":records_json(records)?}),
        ipc::Response::Records {
            rid,
            label,
            expires,
            records,
            ..
        } => json!({
            "event":"namestore_records","rid":rid,"label":string_json(label.bytes()),"expires_us":expires.as_micros(),"records":records_json(records)?}),
        ipc::Response::End { rid } => json!({"event":"namestore_end","rid":rid}),
        ipc::Response::MonitorSync => json!({"event":"namestore_monitor_sync"}),
        ipc::Response::Edit {
            rid,
            code,
            hint,
            records,
        } => json!({
            "event":"namestore_edit","rid":rid,"code":code,"previous_hint":hint.map(|s|string_json(s.bytes())),"records":records_json(records)?}),
    };
    row(out, value)
}
fn loss(out: &mut impl Write, report: Option<Loss<'_>>) -> Result<()> {
    if let Some(report) = report {
        row(
            out,
            json!({"event":"namestore_source_closed","epoch":report.epoch.map(|e|e.diagnostic()),
            "operations":report.operations,"exposed":report.exposed,
            "control":report.control.map(|c|json!({"allocation":c.control.diagnostic(),"kind":format!("{:?}",c.kind),"submission":format!("{:?}",c.submission)}))}),
        )?;
    }
    Ok(())
}
/// Both errors are real: an operation failure does not erase a subsequent
/// failure to report its original source retirement.
#[derive(Debug)]
struct CleanupFailure {
    operation: Box<dyn Error>,
    cleanup: Box<dyn Error>,
}
impl std::fmt::Display for CleanupFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}; source-retirement reporting: {}",
            self.operation, self.cleanup
        )
    }
}
impl Error for CleanupFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.operation.as_ref())
    }
}
fn retain_cleanup(result: Result<()>, cleanup: Result<()>) -> Result<()> {
    match (result, cleanup) {
        (Err(operation), Err(cleanup)) => Err(Box::new(CleanupFailure { operation, cleanup })),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
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
async fn ego(
    command: &Command,
    source: EndpointSource,
    hard: Instant,
    until: u64,
    mut signal: Pin<&mut impl Future<Output = io::Result<()>>>,
    out: &mut impl Write,
) -> Result<SecretKey> {
    let instance = identity::Instance::new();
    let limits = identity::Limits {
        reconnect: false,
        initialization_timeout: command.timeout,
        ..identity::Limits::default()
    };
    let mut lookup = Lookup::exact(&instance, source, &command.ego, until, limits)?;
    let result = async {
        loop {
            if Instant::now() >= hard { return Err("IDENTITY lookup deadline; NAMESTORE request was not sent".into()); }
            let Some(progress) = observed(lookup.drive(Some(hard)), signal.as_mut()).await? else {
                return Err("interrupted during IDENTITY lookup; NAMESTORE request was not sent".into());
            };
            match progress {
                LookupProgress::Finished { operation, epoch, outcome: LookupOutcome::Found(identity) } => {
                    row(out,json!({"event":"namestore_ego_resolved","operation":format!("{operation:?}"),"epoch":epoch.map(|e|format!("{e:?}"))}))?;
                    return Ok(identity.into_secret());
                }
                LookupProgress::Finished { outcome: LookupOutcome::ResultCode(code), .. } => return Err(format!("IDENTITY ego lookup returned actual code {code}").into()),
                LookupProgress::Finished { outcome: LookupOutcome::Local { reason, submission, result_code }, .. } => return Err(format!("IDENTITY ego lookup ended locally: {reason:?}, {submission:?}, observed code {result_code:?}").into()),
                LookupProgress::Source(identity::Progress::Unavailable(e)) => return Err(e.into()),
                LookupProgress::Source(identity::Progress::WaitDeadline) => return Err("IDENTITY observation deadline".into()),
                LookupProgress::Source(identity::Progress::Lost { cause, .. }) => return Err(format!("IDENTITY source lost before ego lookup: {cause:?}").into()),
                LookupProgress::Closed => return Err("IDENTITY lookup closed without a result".into()),
                _ => {}
            }
        }
    }.await;
    // No clock is consulted, including on error, signal and output failure.
    let _closed = lookup.close();
    result
}
fn observe(out: &mut impl Write, progress: &Progress<'_>) -> Result<()> {
    let value = match progress {
        Progress::Connected(epoch) => {
            json!({"event":"namestore_connected","epoch":epoch.diagnostic()})
        }
        Progress::Queued {
            epoch,
            operation,
            request_id,
        } => {
            json!({"event":"namestore_queued","epoch":epoch.diagnostic(),"operation":operation.diagnostic(),"rid":request_id})
        }
        Progress::Written {
            epoch,
            operation,
            request_id,
        } => {
            json!({"event":"namestore_whole_write","epoch":epoch.diagnostic(),"operation":operation.diagnostic(),"rid":request_id,"database_result":false})
        }
        Progress::ControlQueued {
            epoch,
            control,
            kind,
        } => {
            json!({"event":"namestore_control_queued","epoch":epoch.diagnostic(),"control":control.diagnostic(),"kind":format!("{kind:?}")})
        }
        Progress::ControlWritten {
            epoch,
            control,
            kind,
        } => {
            json!({"event":"namestore_control_whole_write","epoch":epoch.diagnostic(),"control":control.diagnostic(),"kind":format!("{kind:?}"),"server_ack":false})
        }
        Progress::Ignored { epoch, request_id } => {
            json!({"event":"namestore_ignored","epoch":epoch.diagnostic(),"rid":request_id})
        }
        Progress::Lost { report, cause } => {
            json!({"event":"namestore_source_lost","epoch":report.epoch.map(|e|e.diagnostic()),"operations":report.operations,"exposed":report.exposed,"cause":format!("{cause:?}")})
        }
        Progress::ConnectRetry { error, retry_after } => {
            json!({"event":"namestore_connect_retry","error":error.to_string(),"retry_after_ms":retry_after.as_millis()})
        }
        Progress::Activity { .. }
        | Progress::Completed(_)
        | Progress::Record { .. }
        | Progress::Synchronized { .. }
        | Progress::Unavailable(_)
        | Progress::WaitDeadline
        | Progress::Closed => return Ok(()),
    };
    row(out, value)
}
async fn single(
    command: &Command,
    source: EndpointSource,
    key: &SecretKey,
    hard: Instant,
    until: u64,
    mut signal: Pin<&mut impl Future<Output = io::Result<()>>>,
    out: &mut impl Write,
) -> Result<()> {
    let instance = Instance::new();
    let mut client = Client::new(&instance, source, command.limits)?;
    let result = async {
        let operation = match command.action {
            Action::Lookup => client.lookup(key, &command.label, command.filter, until)?,
            Action::Reverse => client.zone_to_name(key, command.target.ok_or("missing public reverse target")?, until)?,
            Action::Replace | Action::ImportUri | Action::Delete | Action::Batch => {
                let sets = command.sets.as_ref().ok_or("missing preflighted record sets")?;
                let operation = client.store(key, ipc::RecordSets::new(&sets.bytes, sets.count)?, command.single_tx, until)?;
                row(out,json!({"event":"namestore_store_admitted","operation":operation.diagnostic(),"sets":sets.count,"single_tx":command.single_tx,"whole_batch_in_original_frame":true,"database_result":false}))?;
                operation
            }
            Action::EditBegin => client.edit_begin(key, &command.label, &command.hint, until)?,
            Action::EditCancel => client.edit_cancel(key, &command.label, &command.hint, &command.replacement, until)?,
            _ => return Err("invalid one-shot NAMESTORE command".into()),
        };
        loop {
            if Instant::now() >= hard { return Err("NAMESTORE deadline; exposed mutation/lock outcome may be unknown".into()); }
            let Some(progress) = observed(client.drive(Some(hard)), signal.as_mut()).await? else {
                return Err("NAMESTORE interrupted; original MQ closed; exposed mutations/locks may already have committed".into());
            };
            observe(out, &progress)?;
            match progress {
                Progress::Completed(c) => {
                    if c.operation != operation { return Err("foreign NAMESTORE completion".into()); }
                    row(out,json!({"event":"namestore_completion","operation":c.operation.diagnostic(),"epoch":c.epoch.map(|e|e.diagnostic()),"rid":c.request_id,"kind":format!("{:?}",c.kind)}))?;
                    return match c.outcome {
                        Outcome::Reply(r) => {
                            let response = r.view()?;
                            let successful = match response {
                                ipc::Response::Generic {code,..} => code == 0,
                                ipc::Response::Lookup {found,..} => found >= 0,
                                ipc::Response::ZoneToName {code,..} => code == 0,
                                ipc::Response::Edit {code,..} => code == 0,
                                _ => false,
                            };
                            reply(out,response)?;
                            if successful { Ok(()) } else {
                                Err("NAMESTORE actual service result was unsuccessful; see raw status above".into())
                            }
                        },
                        Outcome::Local {reason,submission} => {
                            row(out,json!({"event":"namestore_local_end","reason":format!("{reason:?}"),"submission":format!("{submission:?}"),"database_result":false}))?;
                            Err("NAMESTORE ended without an actual service result".into())
                        }
                    };
                }
                Progress::Unavailable(error) => return Err(error.into()),
                Progress::Lost {..} => return Err("original NAMESTORE source lost; operation not replayed".into()),
                Progress::WaitDeadline => return Err("NAMESTORE observation deadline; not a database result".into()),
                Progress::Closed => return Err("NAMESTORE closed without original result".into()),
                _ => {}
            }
        }
    }.await;
    let cleanup = loss(out, client.close());
    retain_cleanup(result, cleanup)
}
// Both subscriptions own separate official MQs. Only this enum's active branch
// exists, so the CLI does not allocate both owners or add a hidden poller.
enum Stream<'id> {
    Iterator(ZoneIterator<'id>),
    Monitor(Monitor<'id>),
}
impl<'id> Stream<'id> {
    fn operation(&self) -> Operation<'id> {
        match self {
            Self::Iterator(s) => s.operation(),
            Self::Monitor(s) => s.operation(),
        }
    }
    async fn drive(
        &mut self,
        hard: Instant,
    ) -> std::result::Result<Progress<'id>, gnunet::clients::namestore::Error> {
        match self {
            Self::Iterator(s) => s.drive(Some(hard)).await,
            Self::Monitor(s) => s.drive(Some(hard)).await,
        }
    }
    fn next(&mut self, until: u64) -> Result<()> {
        let _control = match self {
            Self::Iterator(s) => s.next(1, until)?,
            Self::Monitor(s) => s.next(1, until)?,
        };
        Ok(())
    }
    fn close(&mut self) -> Option<Loss<'id>> {
        match self {
            Self::Iterator(s) => s.close().or_else(|| s.take_close_report()),
            Self::Monitor(s) => s.close().or_else(|| s.take_close_report()),
        }
    }
}
async fn stream(
    command: &Command,
    source: EndpointSource,
    key: &SecretKey,
    hard: Instant,
    until: u64,
    mut signal: Pin<&mut impl Future<Output = io::Result<()>>>,
    out: &mut impl Write,
) -> Result<()> {
    let instance = Instance::new();
    let mut stream = if command.action == Action::Monitor {
        Stream::Monitor(Monitor::new(
            &instance,
            source,
            Some(key),
            command.iterate_first,
            command.filter,
            until,
            command.limits,
        )?)
    } else {
        Stream::Iterator(ZoneIterator::new(
            &instance,
            source,
            Some(key),
            command.filter,
            until,
            command.limits,
        )?)
    };
    let operation = stream.operation();
    let result = async {
        let mut count = 0u64;
        let mut stopping = None;
        loop {
            if Instant::now() >= hard {
                row(out,json!({"event":"namestore_local_window_end","records":count,"natural_end":false,"complete_snapshot":false}))?;
                return if command.action == Action::Monitor { Ok(()) } else { Err("iterator deadline before actual END; snapshot incomplete".into()) };
            }
            let Some(progress) = observed(stream.drive(hard), signal.as_mut()).await? else {
                return Err("NAMESTORE stream interrupted; original source closed".into());
            };
            observe(out, &progress)?;
            match progress {
                Progress::Record {epoch,operation:original,reply:r} => {
                    if original != operation { return Err("foreign stream record".into()); }
                    row(out,json!({"event":"namestore_record_source","epoch":epoch.diagnostic(),"operation":original.diagnostic(),"ordinal":count+1}))?;
                    reply(out, r.view()?)?;
                    count += 1;
                    if count >= command.max_results {
                        match &mut stream {
                            Stream::Monitor(_) => {
                                row(out,json!({"event":"namestore_monitor_limit","records":count,"natural_end":false,"complete_snapshot":false}))?;
                                return Ok(());
                            }
                            Stream::Iterator(iterator) => {
                                stopping = iterator.stop(until)?;
                                if stopping.is_none() {
                                    row(out,json!({"event":"namestore_iterator_local_stop","records":count,"natural_end":false,"server_ack":false}))?;
                                    return Ok(());
                                }
                            }
                        }
                    } else if stopping.is_none() {
                        stream.next(until)?;
                    }
                }
                Progress::Synchronized {epoch,operation:original} => {
                    if original != operation { return Err("foreign monitor sync".into()); }
                    row(out,json!({"event":"namestore_monitor_sync","epoch":epoch.diagnostic(),"operation":original.diagnostic(),"records":count}))?;
                }
                Progress::ControlWritten {control,kind:ControlKind::Stop,..} => {
                    if stopping != Some(control) { return Err("foreign iterator STOP write".into()); }
                    row(out,json!({"event":"namestore_iterator_stopped","records":count,"natural_end":false,"server_ack":false,"whole_stop_written":true}))?;
                    return Ok(());
                }
                Progress::Completed(c) => {
                    if c.operation != operation { return Err("foreign stream completion".into()); }
                    match c.outcome {
                        Outcome::Reply(r) => {
                            let response = r.view()?;
                            if !matches!(response, ipc::Response::End {..}) {
                                return Err("unexpected stream terminal response".into());
                            }
                            reply(out,response)?;
                            row(out,json!({"event":"namestore_iterator_complete","records":count,"natural_end":true,"epoch":c.epoch.map(|e|e.diagnostic()),"rid":c.request_id}))?;
                            return Ok(());
                        }
                        Outcome::Local {reason,submission} => {
                            row(out,json!({"event":"namestore_stream_local_end","records":count,"reason":format!("{reason:?}"),"submission":format!("{submission:?}"),"natural_end":false,"complete_snapshot":false}))?;
                            return if command.action == Action::Monitor && reason == gnunet::clients::namestore::LocalReason::Deadline {
                                Ok(())
                            } else { Err("NAMESTORE stream ended locally before natural END".into()) };
                        }
                    }
                }
                Progress::WaitDeadline => {
                    row(out,json!({"event":"namestore_local_window_end","records":count,"natural_end":false,"complete_snapshot":false}))?;
                    return if command.action == Action::Monitor { Ok(()) } else { Err("iterator observation deadline; snapshot incomplete".into()) };
                }
                Progress::Unavailable(error) => return Err(error.into()),
                Progress::Lost {..} => return Err("original stream source lost; cursor not replayed".into()),
                Progress::Closed => return Err("stream closed without an actual terminal event".into()),
                _ => {}
            }
        }
    }.await;
    let cleanup = loss(out, stream.close());
    retain_cleanup(result, cleanup)
}
fn help(out: &mut impl Write) -> Result<()> {
    orphans::help(out)?;
    zonefile::help(out)?;
    recordline::help(out)?;
    writeln!(
        out,
        "namestore lookup <UNIXPATH> <LABEL> --identity-socket <UNIXPATH> --ego <NAME> [OPTIONS]"
    )?;
    writeln!(
        out,
        "namestore replace <UNIXPATH> <LABEL> '<RECORDS_JSON>' [IDENTITY/OPTIONS]"
    )?;
    writeln!(
        out,
        "namestore import-uri <UNIXPATH> 'gnunet://gns/<TYPED_PUBLIC_KEY>/<LABEL>' [IDENTITY/OPTIONS] --expiration-us U64 [--relative 0|1] [--shadow 0|1] [--maintenance 0|1]"
    )?;
    writeln!(
        out,
        "namestore delete <UNIXPATH> <LABEL> [IDENTITY/OPTIONS]"
    )?;
    writeln!(
        out,
        "namestore batch <UNIXPATH> '<SETS_JSON>' [IDENTITY/OPTIONS] [--single-tx 0|1]"
    )?;
    writeln!(
        out,
        "namestore reverse <UNIXPATH> <PUBLIC_ZONE_72HEX_OR_ZTLD> [IDENTITY/OPTIONS]"
    )?;
    writeln!(
        out,
        "namestore iterate|monitor <UNIXPATH> [IDENTITY/OPTIONS] [--limit N] [--filter U16]"
    )?;
    writeln!(
        out,
        "namestore edit-begin <UNIXPATH> <LABEL> <HINT> [IDENTITY/OPTIONS]"
    )?;
    writeln!(
        out,
        "namestore edit-cancel <UNIXPATH> <LABEL> <EXPECTED_HINT> <REPLACEMENT_HINT> [IDENTITY/OPTIONS]"
    )?;
    writeln!(
        out,
        "Single-zone JSON commands require --identity-socket UNIXPATH --ego NAME. No private-key argument/file is accepted. Records JSON: [{{\"type\":1,\"flags\":0,\"expiration_us\":1800000000000000,\"data_hex\":\"7f000001\"}}]. Sets JSON: [{{\"label\":\"www\",\"records\":[...]}}]. Numeric record types/flags and expiration microseconds are preserved."
    )?;
    writeln!(
        out,
        "--timeout-ms 1..86400000 includes IDENTITY lookup; default30000, monitor300000. --limit default1000 bounds record sets, not records. --filter defaults0 (maintenance1/omit-private2 bits preserved). Monitor --initial 0|1 defaults1. Labels preserve case/Unicode for official server NFC policy; @ is the apex, not empty string."
    )?;
    writeln!(
        out,
        "Replace/delete/import-uri each send one entire label set. Import-uri replaces the label with one PKEY/EDKEY record containing the raw 32-byte public key; it does not append. Expiration is absolute microseconds unless --relative 1; relative/shadow/maintenance default0 preserve the standard record flags. URI text decoding is not authentication. Batch defaults single_tx1 and always fits exactly one preflighted STORE frame; an oversized batch is refused before connecting. single_tx0 permits official partial commit; raw result code is printed. There is no cross-frame transaction, wire CANCEL or monitor STOP. Edit-cancel conditionally changes the advisory hint; closing or Ctrl-C never rolls it back. Iterator --limit sends actual STOP and distinguishes it from service END; monitor ends locally at limit/deadline and reports snapshot completeness as unclaimed. Whole local write is not database/publication success."
    )?;
    Ok(())
}
pub(super) fn run(args: &[OsString], out: &mut impl Write) -> Result<()> {
    if args
        .first()
        .and_then(|arg| arg.to_str())
        .is_some_and(|action| matches!(action, "list-orphans" | "purge-orphans" | "purge-zone"))
    {
        return orphans::run(args, out);
    }
    if let Some(action) = args.first().and_then(|arg| arg.to_str())
        && matches!(action, "import-recordline" | "export-recordline")
    {
        return recordline::run(&args[1..], action == "import-recordline", out);
    }
    if args
        .first()
        .is_some_and(|arg| arg == OsStr::new("import-zonefile"))
    {
        return zonefile::run(&args[1..], out);
    }
    if args.is_empty() || args.first().is_some_and(|s| s == OsStr::new("--help")) {
        return help(out);
    }
    // All JSON/record/length/resource preflight happens before either service MQ.
    let command = parse(args)?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let source = EndpointSource::unix(command.socket.clone());
            let identity_source =
                EndpointSource::unix_with_clock(command.identity_socket.clone(), source.clock());
            let now = source.clock().sample()?.now.as_micros();
            let until = now
                .checked_add(u64::try_from(command.timeout.as_micros())?)
                .filter(|n| *n != u64::MAX)
                .ok_or("canonical deadline overflow")?;
            let hard = Instant::now()
                .checked_add(command.timeout)
                .ok_or("native deadline overflow")?;
            let interrupt = tokio::signal::ctrl_c();
            tokio::pin!(interrupt);
            let key = ego(
                &command,
                identity_source,
                hard,
                until,
                interrupt.as_mut(),
                out,
            )
            .await?;
            if matches!(command.action, Action::Iterate | Action::Monitor) {
                stream(&command, source, &key, hard, until, interrupt.as_mut(), out).await
            } else {
                single(&command, source, &key, hard, until, interrupt.as_mut(), out).await
            }
        })
}
