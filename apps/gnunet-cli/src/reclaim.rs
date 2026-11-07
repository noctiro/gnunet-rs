//! Real RECLAIM commands over original IPC and an opaque IDENTITY ego lookup.
use super::peer::hexadecimal;
use gnunet::{
    clients::{
        identity::{self, Lookup, LookupOutcome, LookupProgress, SecretKey},
        reclaim::{
            self as native, Attribute, AttributeList, AttributeType, Client, ControlKind,
            Credential, CredentialType, EndpointSource, Identifier, Instance,
            Iterator as ReclaimIterator, Limits, ListLimits, Name, Operation, Outcome,
            Presentation, Progress, RelativeTime, Sensitive, Ticket, Uri, ipc,
        },
    },
    reclaim_credentials as credentials,
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
mod data;
mod driver;
type Result<T> = std::result::Result<T, Box<dyn Error>>;
const MAX_TIMEOUT_MS: u64 = 86_400_000;
const MAX_ROWS: u64 = 1_000_000;
#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    AttributeStore,
    AttributeDelete,
    AttributeGet,
    AttributeList,
    CredentialStore,
    CredentialDelete,
    CredentialGet,
    CredentialList,
    TicketIssue,
    TicketList,
    TicketRevoke,
    TicketConsume,
}
impl Action {
    fn iteration(self) -> Option<ipc::Iteration> {
        match self {
            Self::AttributeStore
            | Self::AttributeDelete
            | Self::AttributeGet
            | Self::AttributeList
            | Self::TicketIssue => Some(ipc::Iteration::Attributes),
            Self::CredentialStore
            | Self::CredentialDelete
            | Self::CredentialGet
            | Self::CredentialList => Some(ipc::Iteration::Credentials),
            Self::TicketList => Some(ipc::Iteration::Tickets),
            _ => None,
        }
    }
    fn visible(self) -> bool {
        matches!(
            self,
            Self::AttributeGet
                | Self::AttributeList
                | Self::CredentialGet
                | Self::CredentialList
                | Self::TicketList
        )
    }
}
struct Command {
    action: Action,
    socket: PathBuf,
    identity_socket: Option<PathBuf>,
    ego: Zeroizing<Vec<u8>>,
    name: Zeroizing<Vec<u8>>,
    value: Zeroizing<Vec<u8>>,
    kind: u32,
    id: Option<Identifier>,
    credential: Option<Identifier>,
    flags: Option<u32>,
    ticket: Zeroizing<Vec<u8>>,
    uri: Zeroizing<Vec<u8>>,
    ids: Vec<Identifier>,
    names: Vec<Zeroizing<Vec<u8>>>,
    expiration: RelativeTime,
    timeout: Duration,
    limits: Limits,
    limit: u64,
    scan_limit: u64,
    output_bytes: usize,
}
#[derive(Clone, Copy)]
struct Window {
    hard: Instant,
    until: u64,
}
struct Output<'w, W> {
    writer: &'w mut W,
    remaining: usize,
}
impl<W: Write> Output<'_, W> {
    fn emit(&mut self, value: Value) -> Result<()> {
        let bytes = Zeroizing::new(serde_json::to_vec(&value)?);
        let needed = bytes
            .len()
            .checked_add(1)
            .ok_or("JSON line size overflow")?;
        if needed > self.remaining {
            return Err("RECLAIM output byte bound reached; original source will close".into());
        }
        self.remaining -= needed;
        self.writer.write_all(&bytes)?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;
        Ok(())
    }
}
fn text(value: &OsStr) -> Result<&str> {
    value
        .to_str()
        .ok_or_else(|| "expected UTF-8 RECLAIM option/input".into())
}
fn bytes(value: &OsStr, max: usize) -> Result<Zeroizing<Vec<u8>>> {
    let b = value.as_bytes();
    if b.len() > max || b.contains(&0) {
        return Err("input is too large or contains NUL".into());
    }
    let mut v = Zeroizing::new(Vec::new());
    v.try_reserve_exact(b.len())?;
    v.extend_from_slice(b);
    Ok(v)
}
fn unhex(input: &str, max: usize) -> Result<Zeroizing<Vec<u8>>> {
    if !input.len().is_multiple_of(2) || input.len() / 2 > max {
        return Err("hex input must have an even bounded length".into());
    }
    let digit = |b| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    };
    let mut result = Zeroizing::new(Vec::new());
    result.try_reserve_exact(input.len() / 2)?;
    for p in input.as_bytes().as_chunks::<2>().0 {
        result.push((digit(p[0]).ok_or("invalid hex")? << 4) | digit(p[1]).ok_or("invalid hex")?);
    }
    Ok(result)
}
fn identifier(value: &str) -> Result<Identifier> {
    Ok(Identifier::decode(&unhex(value, 32)?)?)
}
fn parse(args: &[OsString]) -> Result<Command> {
    let (action,n)=match args.first().and_then(|a|a.to_str()) {
        Some("attribute-store")=>(Action::AttributeStore,2),Some("attribute-delete")=>(Action::AttributeDelete,1),
        Some("attribute-get")=>(Action::AttributeGet,1),Some("attribute-list")=>(Action::AttributeList,0),
        Some("credential-store")=>(Action::CredentialStore,2),Some("credential-delete")=>(Action::CredentialDelete,1),
        Some("credential-get")=>(Action::CredentialGet,1),Some("credential-list")=>(Action::CredentialList,0),
        Some("ticket-issue")=>(Action::TicketIssue,2),Some("ticket-list")=>(Action::TicketList,0),
        Some("ticket-revoke")=>(Action::TicketRevoke,1),Some("ticket-consume")=>(Action::TicketConsume,2),
        _=>return Err("expected reclaim attribute-store|attribute-delete|attribute-get|attribute-list|credential-store|credential-delete|credential-get|credential-list|ticket-issue|ticket-list|ticket-revoke|ticket-consume".into()),
    };
    let socket = PathBuf::from(args.get(1).ok_or("missing explicit RECLAIM UNIXPATH")?);
    let inputs = args
        .get(2..2 + n)
        .ok_or("missing RECLAIM positional input")?;
    let store = matches!(action, Action::AttributeStore | Action::CredentialStore);
    let mut command = Command {
        action,
        socket,
        identity_socket: None,
        ego: Zeroizing::new(Vec::new()),
        name: Zeroizing::new(Vec::new()),
        value: Zeroizing::new(Vec::new()),
        kind: 1,
        id: None,
        credential: None,
        flags: None,
        ticket: Zeroizing::new(Vec::new()),
        uri: Zeroizing::new(Vec::new()),
        ids: Vec::new(),
        names: Vec::new(),
        expiration: RelativeTime::from_micros(3_600_000_000),
        timeout: Duration::from_secs(30),
        limits: Limits {
            operations: 1,
            source_bytes: 65535,
            reconnect: false,
            ..Limits::default()
        },
        limit: 10_000,
        scan_limit: 10_000,
        output_bytes: 16 * 1024 * 1024,
    };
    let mut timeout_ms = 30_000u64;
    let mut ego_present = false;
    let mut encoding = "text";
    let mut selection = "names";
    let mut at = 2 + n;
    while at < args.len() {
        let option = text(&args[at])?;
        let value = args.get(at + 1).ok_or("missing RECLAIM option value")?;
        match option {
            "--identity-socket" => command.identity_socket = Some(PathBuf::from(value)),
            "--ego" => {
                command.ego = bytes(value, identity::Limits::default().name_bytes)?;
                ego_present = true;
            }
            "--timeout-ms" => timeout_ms = text(value)?.parse()?,
            "--limit" if action.visible() => command.limit = text(value)?.parse()?,
            "--scan-limit" => command.scan_limit = text(value)?.parse()?,
            "--output-bytes" => command.output_bytes = text(value)?.parse()?,
            "--io-slice-bytes" => command.limits.io_slice_bytes = text(value)?.parse()?,
            "--expiration-us" if store => {
                command.expiration = RelativeTime::from_micros(text(value)?.parse()?)
            }
            "--id" if store => command.id = Some(identifier(text(value)?)?),
            "--credential-id" if action == Action::AttributeStore => {
                command.credential = Some(identifier(text(value)?)?)
            }
            "--flags" if store => command.flags = Some(text(value)?.parse()?),
            "--encoding" if store => encoding = text(value)?,
            "--select" if action == Action::TicketIssue => selection = text(value)?,
            "--type" if store => {
                command.kind = if let Ok(v) = text(value)?.parse::<u32>() {
                    v
                } else if action == Action::AttributeStore {
                    credentials::attribute_type(value.as_bytes())
                        .ok_or("unknown attribute type name; use numeric type with --encoding hex")?
                        .value()
                } else {
                    credentials::credential_type(value.as_bytes())
                        .ok_or(
                            "unknown credential type name; use numeric type with --encoding hex",
                        )?
                        .value()
                }
            }
            _ => return Err("unknown or inapplicable RECLAIM option".into()),
        }
        at += 2;
    }
    if timeout_ms == 0
        || timeout_ms > MAX_TIMEOUT_MS
        || command.limit == 0
        || command.limit > MAX_ROWS
        || command.scan_limit == 0
        || command.scan_limit > MAX_ROWS
        || command.output_bytes == 0
        || command.output_bytes > 256 * 1024 * 1024
        || command.limits.io_slice_bytes == 0
        || command.limits.io_slice_bytes > command.limits.frame_bytes
    {
        return Err("invalid finite RECLAIM deadline, row, byte or syscall bounds".into());
    }
    command.timeout = Duration::from_millis(timeout_ms);
    if Instant::now()
        .checked_add(command.timeout)
        .and_then(|t| t.checked_add(command.limits.retirement_grace))
        .is_none()
    {
        return Err("RECLAIM deadline overflow".into());
    }
    if action != Action::TicketConsume {
        if command.identity_socket.is_none() {
            return Err("required --identity-socket UNIXPATH".into());
        }
        if !ego_present {
            return Err("required --ego NAME (opaque original IDENTITY lookup)".into());
        }
    } else if command.identity_socket.is_some() || ego_present {
        return Err("ticket-consume takes no private identity/ego".into());
    }
    if store {
        command.name = bytes(&inputs[0], u16::MAX.into())?;
        Name::new(&command.name)?;
        let raw = inputs[1].as_os_str().as_bytes();
        command.value = match encoding {
            "hex" => unhex(text(&inputs[1])?, 65535)?,
            "text" => {
                let length = raw
                    .len()
                    .checked_add(1)
                    .filter(|n| *n <= 65535)
                    .ok_or("text value too large")?;
                let mut value = Zeroizing::new(Vec::new());
                value.try_reserve_exact(length)?;
                value.resize(length, 0);
                let written = if action == Action::AttributeStore {
                    credentials::attribute_from_string(
                        AttributeType::new(command.kind),
                        raw,
                        &mut value,
                    )?
                } else {
                    credentials::credential_from_string(
                        CredentialType::new(command.kind),
                        raw,
                        &mut value,
                    )?
                };
                value.truncate(written);
                value
            }
            _ => return Err("--encoding must be text|hex".into()),
        };
        let length = if action == Action::AttributeStore {
            command.attribute(None)?.encoded_len()?
        } else {
            command.credential(None)?.encoded_len()?
        };
        if ipc::STORE_PREFIX + gnunet::wire::identity::KEY_LEN + length > command.limits.frame_bytes
        {
            return Err("complete STORE exceeds the official original frame bound".into());
        }
    }
    if matches!(
        action,
        Action::AttributeDelete
            | Action::AttributeGet
            | Action::CredentialDelete
            | Action::CredentialGet
    ) {
        command.id = Some(identifier(text(&inputs[0])?)?);
    }
    match action {
        Action::TicketIssue => {
            command.uri = bytes(&inputs[0], 255)?;
            Uri::new(&command.uri)?;
            let selectors = text(&inputs[1])?;
            if selectors.len() > command.limits.frame_bytes {
                return Err("attribute selection text exceeds one bounded input frame".into());
            }
            if selectors.is_empty() {
                return Err("ticket-issue requires at least one selected attribute".into());
            }
            for token in selectors.split(',') {
                if command.ids.len() + command.names.len() == command.limits.list_items {
                    return Err("too many selected attributes".into());
                }
                match selection {
                    "ids" => {
                        let id = identifier(token)?;
                        if command.ids.contains(&id) {
                            return Err("duplicate selected identifier".into());
                        }
                        command.ids.push(id);
                    }
                    "names" => {
                        let name = bytes(OsStr::new(token), 65535)?;
                        if name.is_empty()
                            || command.names.iter().any(|s| s.eq_ignore_ascii_case(&name))
                        {
                            return Err("empty/duplicate selected attribute name".into());
                        }
                        command.names.push(name);
                    }
                    _ => return Err("--select must be names|ids".into()),
                }
            }
        }
        Action::TicketConsume => {
            command.ticket = bytes(&inputs[0], 127)?;
            Ticket::new(&command.ticket)?;
            command.uri = bytes(&inputs[1], 255)?;
            Uri::new(&command.uri)?;
        }
        Action::TicketRevoke => {
            command.ticket = bytes(&inputs[0], 127)?;
            Ticket::new(&command.ticket)?;
        }
        _ => {}
    }
    Ok(command)
}
impl Command {
    fn attribute<'a>(&'a self, old: Option<Attribute<'a>>) -> Result<Attribute<'a>> {
        Ok(Attribute {
            kind: AttributeType::new(self.kind),
            flags: self.flags.or(old.map(|a| a.flags)).unwrap_or(0),
            id: self.id.or(old.map(|a| a.id)).unwrap_or(Identifier::ZERO),
            credential: self
                .credential
                .or(old.map(|a| a.credential))
                .unwrap_or(Identifier::ZERO),
            name: old.map(|a| a.name).unwrap_or(Name::new(&self.name)?),
            reserved: [0; 2],
            value: Sensitive::new(&self.value),
        })
    }
    fn credential<'a>(&'a self, old: Option<Credential<'a>>) -> Result<Credential<'a>> {
        Ok(Credential {
            kind: CredentialType::new(self.kind),
            flags: self.flags.or(old.map(|c| c.flags)).unwrap_or(0),
            id: self.id.or(old.map(|c| c.id)).unwrap_or(Identifier::ZERO),
            name: Name::new(&self.name)?,
            reserved: [0; 2],
            value: Sensitive::new(&self.value),
        })
    }
}
async fn observed<T, E: Error + 'static>(
    progress: impl Future<Output = std::result::Result<T, E>>,
    mut signal: Pin<&mut impl Future<Output = io::Result<()>>>,
) -> Result<Option<T>> {
    let mut progress = std::pin::pin!(progress);
    poll_fn(|cx| {
        if let Poll::Ready(r) = signal.as_mut().poll(cx) {
            return Poll::Ready(r.map(|()| None).map_err(|e| Box::new(e) as Box<dyn Error>));
        }
        progress
            .as_mut()
            .poll(cx)
            .map(|r| r.map(Some).map_err(|e| Box::new(e) as Box<dyn Error>))
    })
    .await
}
fn help(out: &mut impl Write) -> Result<()> {
    writeln!(
        out,
        "reclaim attribute-store|credential-store <UNIXPATH> <NAME> <VALUE> [--type NAME|U32] [--encoding text|hex] [--id 64HEX] [--expiration-us U64] [IDENTITY/OPTIONS]"
    )?;
    writeln!(
        out,
        "reclaim attribute-get|attribute-delete|credential-get|credential-delete <UNIXPATH> <64HEX_ID> [IDENTITY/OPTIONS]"
    )?;
    writeln!(
        out,
        "reclaim attribute-list|credential-list|ticket-list <UNIXPATH> [IDENTITY/OPTIONS] [--limit N]"
    )?;
    writeln!(
        out,
        "reclaim ticket-issue <UNIXPATH> <RP_URI> <A1,A2,...> [--select names|ids] [IDENTITY/OPTIONS]"
    )?;
    writeln!(
        out,
        "reclaim ticket-revoke <UNIXPATH> <TICKET_GNS_NAME> [IDENTITY/OPTIONS]"
    )?;
    writeln!(
        out,
        "reclaim ticket-consume <UNIXPATH> <TICKET_GNS_NAME> <RP_URI> [OPTIONS]"
    )?;
    writeln!(
        out,
        "IDENTITY: --identity-socket UNIXPATH --ego NAME required except consume; no key file, import, generation or raw private argument. OPTIONS: --timeout-ms 30000 --scan-limit 10000 --output-bytes 16777216 --io-slice-bytes 65535. IDs are exact32-byte hex. Text conversion uses the production STRING/JWT/PABC format helper; hex preserves arbitrary plugin bytes. Store defaults expiration1hour and zero ID for service assignment; attribute-store without --id first reuses one existing same ASCII-case-insensitive name. Explicit --id performs a checked original-object update. Attribute --credential-id 64HEX and raw --flags U32 are supported. Ticket selection requires actual complete iteration and all requested attributes; an incomplete scan never authorizes issuance. Actual service statuses remain raw, including the C consume-word defect. NEXT/STOP whole local write is no ACK. Finite listing at --limit is a local STOP, never natural END."
    )?;
    Ok(())
}
pub(super) fn run(args: &[OsString], out: &mut impl Write) -> Result<()> {
    if args.is_empty() || args.first().is_some_and(|s| s == OsStr::new("--help")) {
        return help(out);
    }
    let command = parse(args)?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let source = EndpointSource::unix(command.socket.clone());
            let clock = source.clock();
            let now = clock.sample()?.now.as_micros();
            let window = Window {
                until: now
                    .checked_add(u64::try_from(command.timeout.as_micros())?)
                    .filter(|n| *n != u64::MAX)
                    .ok_or("canonical deadline overflow")?,
                hard: Instant::now()
                    .checked_add(command.timeout)
                    .ok_or("native deadline overflow")?,
            };
            let interrupt = tokio::signal::ctrl_c();
            tokio::pin!(interrupt);
            let mut output = Output {
                writer: out,
                remaining: command.output_bytes,
            };
            let key = if let Some(path) = &command.identity_socket {
                Some(
                    driver::ego(
                        &command,
                        EndpointSource::unix_with_clock(path.clone(), clock),
                        window,
                        interrupt.as_mut(),
                        &mut output,
                    )
                    .await?,
                )
            } else {
                None
            };
            driver::execute(
                &command,
                source,
                key.as_ref(),
                window,
                interrupt.as_mut(),
                &mut output,
            )
            .await
        })
}
