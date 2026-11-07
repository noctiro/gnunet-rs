//! Actual pinned did:gns operations over the admitted DID helper/client stack.
use super::peer::hexadecimal;
use gnunet::{clients::did as host, crypto::Entropy, types::Error as Fault};
use serde_json::{Value, json};
use std::{
    cell::Cell,
    error::Error,
    ffi::{OsStr, OsString},
    fs::File,
    future::{Future, poll_fn},
    io::{self, Read, Write},
    os::unix::ffi::OsStrExt,
    path::PathBuf,
    rc::Rc,
    task::Poll,
    time::Duration,
};
use zeroize::Zeroizing;
type Result<T> = std::result::Result<T, Box<dyn Error>>;
#[derive(Clone, Copy, Eq, PartialEq)]
enum Action {
    Create,
    Replace,
    Remove,
    Show,
    ShowAll,
    Resolve,
}
struct Command {
    action: Action,
    socket: PathBuf,
    identity_socket: Option<PathBuf>,
    ego: Zeroizing<Vec<u8>>,
    document: Option<Zeroizing<Vec<u8>>>,
    did: Option<host::did::Did>,
    expiration: u64,
    create_ego: bool,
    timeout: Duration,
    limits: host::Limits,
    output_bytes: usize,
}
fn text(s: &OsStr) -> Result<&str> {
    s.to_str()
        .ok_or_else(|| "DID options/JSON/identifier must be UTF-8".into())
}
fn copy(value: &OsStr, maximum: usize) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = value.as_bytes();
    if bytes.len() > maximum || bytes.contains(&0) {
        return Err("DID input exceeds its byte bound or contains NUL".into());
    }
    let mut result = Zeroizing::new(Vec::new());
    result.try_reserve_exact(bytes.len())?;
    result.extend_from_slice(bytes);
    Ok(result)
}
fn boolean(value: &OsStr) -> Result<bool> {
    match text(value)? {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err("expected 0 or 1".into()),
    }
}
fn parse(args: &[OsString]) -> Result<Command> {
    let (action, count) = match args.first().and_then(|v| v.to_str()) {
        Some("create") => (Action::Create, 0),
        Some("replace") => (Action::Replace, 1),
        Some("remove") => (Action::Remove, 0),
        Some("show") => (Action::Show, 1),
        Some("show-all") => (Action::ShowAll, 0),
        Some("resolve") => (Action::Resolve, 1),
        _ => return Err("expected did create|replace|remove|show|show-all|resolve".into()),
    };
    let socket = PathBuf::from(args.get(1).ok_or("missing original explicit UNIXPATH")?);
    let positional = args
        .get(2..2 + count)
        .ok_or("missing DID operation argument")?;
    let mut command = Command {
        action,
        socket,
        identity_socket: None,
        ego: Zeroizing::new(Vec::new()),
        document: None,
        did: None,
        expiration: host::did::DEFAULT_EXPIRATION_MICROS,
        create_ego: action == Action::Create,
        timeout: Duration::from_secs(30),
        limits: host::Limits::default(),
        output_bytes: 16 * 1024 * 1024,
    };
    let mut ego_present = false;
    let mut create_explicit = false;
    let mut timeout_ms = 30_000u64;
    let mut at = 2 + count;
    while at < args.len() {
        let option = text(&args[at])?;
        let value = args.get(at + 1).ok_or("missing DID option value")?;
        match option {
            "--identity-socket"
                if matches!(action, Action::Create | Action::Replace | Action::Remove) =>
            {
                command.identity_socket = Some(PathBuf::from(value))
            }
            "--ego" if matches!(action, Action::Create | Action::Replace | Action::Remove) => {
                command.ego = copy(value, host::identity::Limits::default().name_bytes)?;
                ego_present = true;
            }
            "--document" if action == Action::Create => {
                command.document = Some(copy(value, 48 * 1024)?)
            }
            "--expiration-us" if matches!(action, Action::Create | Action::Replace) => {
                command.expiration = text(value)?.parse()?
            }
            "--create-ego" if action == Action::Create => {
                command.create_ego = boolean(value)?;
                create_explicit = true;
            }
            "--timeout-ms" => timeout_ms = text(value)?.parse()?,
            "--max-egos" if action == Action::ShowAll => {
                command.limits.egos = text(value)?.parse()?
            }
            "--max-records" => command.limits.records = text(value)?.parse()?,
            "--io-slice-bytes" => command.limits.io_slice_bytes = text(value)?.parse()?,
            "--output-bytes" => command.output_bytes = text(value)?.parse()?,
            "--gns-recursion" if action == Action::Resolve => {
                command.limits.gns_recursion = text(value)?.parse()?
            }
            "--gns-options" if action == Action::Resolve => {
                command.limits.gns_options = text(value)?.parse()?
            }
            _ => return Err("unknown or inapplicable DID option".into()),
        }
        at += 2;
    }
    match action {
        Action::Show => {
            command.ego = copy(&positional[0], host::identity::Limits::default().name_bytes)?
        }
        Action::Resolve => command.did = Some(host::did::Did::parse(text(&positional[0])?)?),
        Action::Replace => command.document = Some(copy(&positional[0], 48 * 1024)?),
        _ => {}
    }
    if matches!(action, Action::Create | Action::Replace | Action::Remove)
        && (!ego_present || command.identity_socket.is_none())
    {
        return Err("publication/removal requires --identity-socket UNIXPATH --ego NAME".into());
    }
    if command.document.is_some() && !create_explicit {
        command.create_ego = false;
    }
    if timeout_ms == 0
        || timeout_ms > 86_400_000
        || command.output_bytes == 0
        || command.output_bytes > 256 * 1024 * 1024
        || command.limits.egos == 0
        || command.limits.egos > 4096
        || command.limits.records == 0
        || command.limits.records > 4096
        || command.limits.io_slice_bytes == 0
        || command.limits.io_slice_bytes > 65535
    {
        return Err("invalid finite DID time, output, record, ego or syscall bound".into());
    }
    command.timeout = Duration::from_millis(timeout_ms);
    if tokio::time::Instant::now()
        .checked_add(command.timeout)
        .and_then(|d| d.checked_add(command.limits.retirement_grace))
        .is_none()
    {
        return Err("DID deadline overflow".into());
    }
    Ok(command)
}
struct Output<'a, W> {
    writer: &'a mut W,
    remaining: usize,
}
impl<W: Write> Output<'_, W> {
    fn emit(&mut self, value: Value) -> Result<()> {
        let bytes = Zeroizing::new(serde_json::to_vec(&value)?);
        let size = bytes.len().checked_add(1).ok_or("DID output overflow")?;
        if size > self.remaining {
            return Err("DID output byte bound exceeded".into());
        }
        self.remaining -= size;
        self.writer.write_all(&bytes)?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;
        Ok(())
    }
}
// Explicit lazy OS entropy: opened only if real IDENTITY lookup missed and the
// caller requested automatic creation. No existing/new identity file is opened.
struct OsEntropy {
    device: Option<File>,
    failure: Option<io::Error>,
}
impl Entropy for OsEntropy {
    fn fill(&mut self, out: &mut [u8]) -> std::result::Result<(), Fault> {
        if self.device.is_none() {
            match File::open("/dev/urandom") {
                Ok(file) => self.device = Some(file),
                Err(error) => {
                    out.fill(0);
                    self.failure = Some(error);
                    return Err(Fault::EntropyUnavailable);
                }
            }
        }
        let result = self
            .device
            .as_mut()
            .ok_or(Fault::EntropyUnavailable)?
            .read_exact(out);
        if let Err(error) = result {
            out.fill(0);
            self.failure = Some(error);
            return Err(Fault::EntropyUnavailable);
        }
        Ok(())
    }
}
fn did_text(did: host::did::Did) -> Result<String> {
    let mut out = [0; host::did::DID_BYTES];
    Ok(did.write(&mut out)?.to_owned())
}
fn event<W: Write>(output: &mut Output<'_, W>, event: host::Event) -> Result<()> {
    // Event contains only public provider/original-token/code/byte metadata.
    // Neither opaque keys, documents, creation material nor full frames occur.
    output.emit(json!({"event":"did_provider","observation":format!("{event:?}")}))
}
fn help(out: &mut impl Write) -> Result<()> {
    writeln!(
        out,
        "did show <IDENTITY_UNIXPATH> <EGO> [OPTIONS]\ndid show-all <IDENTITY_UNIXPATH> [--max-egos 256] [OPTIONS]\ndid resolve <GNS_UNIXPATH> <did:gns:PUBLIC_ZONE> [--gns-recursion 128] [--gns-options U16] [OPTIONS]"
    )?;
    writeln!(
        out,
        "did create <NAMESTORE_UNIXPATH> --identity-socket UNIXPATH --ego NAME [--document JSON] [--create-ego 0|1] [--expiration-us U64] [OPTIONS]\ndid replace <NAMESTORE_UNIXPATH> <JSON> --identity-socket UNIXPATH --ego NAME [--expiration-us U64] [OPTIONS]\ndid remove <NAMESTORE_UNIXPATH> --identity-socket UNIXPATH --ego NAME [OPTIONS]"
    )?;
    writeln!(
        out,
        "OPTIONS: --timeout-ms 30000 --max-records 1024 --io-slice-bytes 65535 --output-bytes 16777216. Default expiry is the actual pinned library365days. Create without custom JSON may create a missing EdDSA ego using explicit OS entropy; --create-ego0 forbids it. Custom JSON requires an existing ego and its matching public did:gns id; no raw key/file input is accepted. New records are official DID_DOCUMENT65561 at didd. Resolve performs one original ANY lookup, prefers matching validated DID_DOCUMENT and permits only bound valid current-C TXT fallback; no arbitrary TXT reinterpretation/signature claim. Replace/remove preserve unrelated records and never clear @ or delete the ego. Whole local writes are not success/publication/cache-flush acknowledgements. All phases share one original finite deadline; source loss never replays an unknown mutation."
    )?;
    Ok(())
}
pub(super) fn run(args: &[OsString], out: &mut impl Write) -> Result<()> {
    if args.is_empty() || args.first().is_some_and(|v| v == OsStr::new("--help")) {
        return help(out);
    }
    let command = parse(args)?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run_command(command, out))
}

async fn run_command(command: Command, out: &mut impl Write) -> Result<()> {
    let primary = host::EndpointSource::unix(command.socket.clone());
    let clock = primary.clock();
    let sources = match command.action {
        Action::Show | Action::ShowAll => host::Sources {
            clock: clock.clone(),
            identity: Some(primary),
            namestore: None,
            gns: None,
        },
        Action::Resolve => host::Sources {
            clock: clock.clone(),
            identity: None,
            namestore: None,
            gns: Some(primary),
        },
        _ => host::Sources {
            clock: clock.clone(),
            identity: Some(host::EndpointSource::unix_with_clock(
                command
                    .identity_socket
                    .clone()
                    .ok_or("missing identity endpoint")?,
                clock.clone(),
            )),
            namestore: Some(primary),
            gns: None,
        },
    };
    let id = host::identity::Instance::new();
    let ns = host::ns::Instance::new();
    let mut gns = host::gns::Instance::new();
    let mut client = host::Client::new(
        host::Instances {
            identity: &id,
            namestore: &ns,
            gns: &mut gns,
        },
        sources,
        command.limits,
    )?;
    let deadline = client.deadline(command.timeout)?;
    let mut entropy = OsEntropy {
        device: None,
        failure: None,
    };
    let mut output = Output {
        writer: out,
        remaining: command.output_bytes,
    };
    let failed = Rc::new(Cell::new(false));
    let cancel_flag = failed.clone();
    let interrupt = tokio::signal::ctrl_c();
    tokio::pin!(interrupt);
    let control = poll_fn(|cx| {
        if cancel_flag.get() {
            Poll::Ready(Ok(()))
        } else {
            interrupt.as_mut().poll(cx)
        }
    });
    tokio::pin!(control);
    let mut first_output_error = None;
    let result = {
        let mut observe = |observation| {
            if first_output_error.is_none()
                && let Err(error) = event(&mut output, observation)
            {
                failed.set(true);
                first_output_error = Some(error);
            }
        };
        match command.action {
            Action::Show => client
                .show(&command.ego, &deadline, control.as_mut(), &mut observe)
                .await
                .map(Return::Did),
            Action::ShowAll => client
                .show_all(&deadline, control.as_mut(), &mut observe)
                .await
                .map(Return::Directory),
            Action::Resolve => client
                .resolve(
                    command.did.ok_or("missing requested public DID")?,
                    &deadline,
                    control.as_mut(),
                    &mut observe,
                )
                .await
                .map(Return::Document),
            Action::Create | Action::Replace => client
                .publish(
                    host::Publish {
                        ego: &command.ego,
                        document: command.document.as_deref().map(Vec::as_slice),
                        expiration_micros: command.expiration,
                        mode: if command.action == Action::Create {
                            host::PublishMode::Create
                        } else {
                            host::PublishMode::Replace
                        },
                        create_ego: command.create_ego,
                    },
                    &mut entropy,
                    &deadline,
                    control.as_mut(),
                    &mut observe,
                )
                .await
                .map(Return::Did),
            Action::Remove => client
                .remove(&command.ego, &deadline, control.as_mut(), &mut observe)
                .await
                .map(Return::Did),
        }
    };
    if let Some(error) = first_output_error {
        return Err(error);
    }
    if let Some(error) = entropy.failure {
        output.emit(json!({"event":"did_entropy_failed","error":error.to_string()}))?;
    }
    match result?{
            Return::Did(did)=>output.emit(json!({"event":"did_result","operation":match command.action{Action::Show=>"show",Action::Create=>"create",Action::Replace=>"replace",Action::Remove=>"remove",_=>"unknown"},
                "did":did_text(did)?,"gns_publication_confirmed":false,"gns_cache_flush_ack":false,"ego_deleted":false,"published_document_checked":command.action!=Action::Show})),
            Return::Directory(rows)=>{for row in rows{output.emit(json!({"event":"did_ego","ego":String::from_utf8_lossy(&row.name),"ego_hex":hexadecimal(&row.name),"did":did_text(row.did)?,"published_document_checked":false}))?;}output.emit(json!({"event":"did_directory_complete","actual_initial_end":true}))},
            Return::Document(document)=>output.emit(json!({"event":"did_resolved","did":did_text(document.did())?,"record_form":format!("{:?}",document.form()),"document":serde_json::from_slice::<Value>(document.json())?,"verification_performed_here":false,"resolution_source":"configured GNS IPC"})),
        }
}
enum Return {
    Did(host::did::Did),
    Directory(Vec<host::NamedDid>),
    Document(host::Resolved),
}
