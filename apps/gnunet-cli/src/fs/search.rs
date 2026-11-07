//! Incremental native KSK/SKS search; caller stop never means a search is complete.
use super::{
    publication::hex,
    search_export,
    service::{duration, target},
};
use gnunet::{
    fs::{Keywords, Limits as UriLimits, Uri, client::Instance, ublock},
    fs_host::{
        ipc,
        search::{self, QueryId, ResultId, Session, Step},
    },
    types::Error as ProtocolError,
};
use serde_json::{Value, json};
use std::{
    error::Error,
    ffi::OsStr,
    fmt,
    future::{Future, poll_fn},
    io::{self, Write},
    os::unix::ffi::OsStrExt,
    path::Path,
    task::Poll,
    time::Duration,
};
use tokio::{
    signal::unix::{SignalKind, signal},
    time::Instant,
};

const QUERIES: usize = 64;
const KNOWN: usize = 1024;

#[derive(Debug)]
enum Cause {
    Search(search::Error),
    Output(io::Error),
    Signal(io::Error),
    State(&'static str),
}
impl fmt::Display for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Search(e) => e.fmt(f),
            Self::Output(e) | Self::Signal(e) => e.fmt(f),
            Self::State(e) => f.write_str(e),
        }
    }
}
impl Error for Cause {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Search(e) => Some(e),
            Self::Output(e) | Self::Signal(e) => Some(e),
            Self::State(_) => None,
        }
    }
}
#[derive(Debug)]
struct Failure {
    cause: Option<Cause>,
    queries: Vec<(QueryId, ipc::Error)>,
    cleanup: Option<search::Error>,
    diagnostic: Option<io::Error>,
    export: Option<search_export::Failure>,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FS search stopped")?;
        if let Some(e) = &self.cause {
            write!(f, ": {e}")?;
        }
        for (query, e) in &self.queries {
            write!(f, "; query {}: {e}", query.index())?;
        }
        if let Some(e) = &self.cleanup {
            write!(f, "; cleanup: {e}")?;
        }
        if let Some(e) = &self.export {
            write!(f, "; result directory: {e}")?;
        }
        if let Some(e) = &self.diagnostic {
            write!(f, "; diagnostic output: {e}")?;
        }
        Ok(())
    }
}
impl Error for Failure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        if let Some(cause) = &self.cause {
            Some(cause)
        } else if let Some((_, cause)) = self.queries.first() {
            Some(cause)
        } else if let Some(cause) = &self.cleanup {
            Some(cause)
        } else if let Some(cause) = &self.export {
            Some(cause)
        } else {
            self.diagnostic
                .as_ref()
                .map(|e| e as &(dyn Error + 'static))
        }
    }
}
fn row(out: &mut impl Write, value: &Value) -> io::Result<()> {
    serde_json::to_writer(&mut *out, value).map_err(io::Error::other)?;
    writeln!(out)?;
    out.flush()
}
fn error_value(error: &search::Error) -> Value {
    let kind = match error {
        search::Error::Transport(_) => "native",
        search::Error::Protocol(_) => "protocol",
        search::Error::Block(_) => "authenticated_artifact",
        search::Error::Limit => "resource_limit",
    };
    json!({"kind":kind,"error":error.to_string()})
}
fn query_value<F, const N: usize>(session: &Session<'_, F, N>, id: QueryId) -> Value
where
    F: FnMut() -> Result<ipc::EndpointSource, ipc::Error>,
{
    match session.query(id) {
        Some(query) => json!({
            "query_id":id.index(),"label":std::str::from_utf8(query.label).ok(),"label_hex":hex(query.label),
            "lookup_key_hex":hex(query.query),"kind":format!("{:?}",query.kind),
            "namespace_hex":hex(query.namespace),
            "parent_results":query.parents.iter().map(|id|id.index()).collect::<Vec<_>>(),
        }),
        None => json!({"query_id":id.index(),"retained":false}),
    }
}
fn result_value<F, const N: usize>(
    session: &Session<'_, F, N>,
    id: ResultId,
    event: &str,
    mandatory: usize,
    optional: usize,
) -> Result<Value, Cause>
where
    F: FnMut() -> Result<ipc::EndpointSource, ipc::Error>,
{
    let record = session
        .result(id)
        .ok_or(Cause::State("native search result disappeared"))?;
    let metadata = record
        .metadata()
        .iter()
        .map(|owned| {
            let item = owned.item();
            json!({"kind":item.kind,"format":item.format as u32,"data_hex":hex(item.data),
            "plugin_hex":item.plugin.map(hex),"mime_hex":item.mime.map(hex)})
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "event":event,"result_id":id.index(),"uri":std::str::from_utf8(record.raw_uri()).ok(),
        "uri_bytes":record.raw_uri(),"visible":record.visible(),
        "mandatory_total":mandatory,"mandatory_missing":record.mandatory_missing(),
        "optional_total":optional,"optional_support":record.applicability(),
        "matched_queries":record.matched_queries().iter().map(|id|query_value(session,*id)).collect::<Vec<_>>(),
        "source_namespace_query":record.source_namespace_query().map(|id|query_value(session,id)),
        "followed_update_query":record.continuation().map(|id|query_value(session,id)),
        "availability":session.availability_summary(id).map(|summary|json!({
            "attempts":summary.attempts(),"successes":summary.successes(),"trials":summary.trials(),
            "rank":summary.rank(),"certainty":summary.certainty(),"cancelled":summary.cancelled(),
            "setup_deadlines":summary.setup_deadlines(),"queries_written":summary.queries_written(),
            "source_elapsed_us":summary.source_elapsed().0,"active":summary.active(),
            "errors":format!("{:?}",summary.errors())
        })),
        "metadata":metadata,
    }))
}
fn native_value(step: &ipc::Step) -> Value {
    match step {
        ipc::Step::Connected => json!({"kind":"connected"}),
        ipc::Step::Written { bytes, complete } => {
            json!({"kind":"written","bytes":bytes,"complete":complete})
        }
        ipc::Step::Read { bytes } => json!({"kind":"read","bytes":bytes}),
        // Session consumes ordinary Block events before native projection.
        ipc::Step::Event(_) => json!({"kind":"native_event"}),
        ipc::Step::Ignored => json!({"kind":"ignored"}),
        ipc::Step::Retry { cause, retry_after } => {
            json!({"kind":"retry","cause":cause.to_string(),"retry_after":{"seconds":retry_after.as_secs(),"nanoseconds":retry_after.subsec_nanos()}})
        }
        ipc::Step::Unavailable(cause) => json!({"kind":"unavailable","cause":cause.to_string()}),
        ipc::Step::WaitDeadline => json!({"kind":"observation_timeout"}),
        ipc::Step::Finished => json!({"kind":"query_finished"}),
    }
}
fn max_visible(
    raw: Option<&impl AsRef<OsStr>>,
    bound: usize,
) -> Result<Option<usize>, Box<dyn Error>> {
    raw.map(|raw| -> Result<usize, Box<dyn Error>> {
        let value = raw
            .as_ref()
            .to_str()
            .ok_or("max-visible-results must be UTF-8 digits")?;
        if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err("max-visible-results must be positive decimal digits".into());
        }
        let value = value.parse::<usize>()?;
        if value == 0 || value > bound {
            return Err(format!("max-visible-results must be between 1 and {bound}").into());
        }
        Ok(value)
    })
    .transpose()
}

enum QueryInput<'a> {
    Uri(&'a [u8]),
    Text(&'a [u8]),
    Args(Vec<&'a [u8]>),
}
struct Arguments<'a> {
    socket: &'a OsStr,
    query: QueryInput<'a>,
    timeout: Option<&'a OsStr>,
    maximum: Option<&'a OsStr>,
    output: Option<&'a OsStr>,
    local_only: bool,
    anonymity: u32,
}
/// One shared level grammar for immediate and persisted original searches.
/// Callers handle `--` before offering an argument to this parser.
pub(super) fn anonymity_option<T: AsRef<OsStr>>(
    args: &[T],
    at: &mut usize,
    selected: &mut Option<u32>,
) -> Result<bool, Box<dyn Error>> {
    let raw = args
        .get(*at)
        .ok_or("missing search option")?
        .as_ref()
        .as_bytes();
    let (value, consumed) = if matches!(raw, b"-a" | b"--anonymity") {
        (
            args.get(*at + 1)
                .ok_or("-a/--anonymity requires a level")?
                .as_ref()
                .as_bytes(),
            2,
        )
    } else if let Some(value) = raw.strip_prefix(b"--anonymity=") {
        (value, 1)
    } else if raw.starts_with(b"-a") && raw.len() > 2 {
        (&raw[2..], 1)
    } else {
        return Ok(false);
    };
    if selected.is_some() {
        return Err("search anonymity may be specified only once".into());
    }
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return Err("search anonymity must be unsigned decimal digits".into());
    }
    let level = std::str::from_utf8(value)?.parse::<u32>()?;
    *selected = Some(level);
    *at += consumed;
    Ok(true)
}
fn selected<'a>(
    slot: &mut Option<&'a OsStr>,
    value: &'a OsStr,
    message: &'static str,
) -> Result<(), Box<dyn Error>> {
    if value.is_empty() || slot.replace(value).is_some() {
        return Err(message.into());
    }
    Ok(())
}
fn arguments<T: AsRef<OsStr>>(args: &[T]) -> Result<Arguments<'_>, Box<dyn Error>> {
    let max_keywords = UriLimits::default().max_keywords;
    let mut positional = Vec::new();
    positional.try_reserve_exact(4)?;
    let mut output = None;
    let mut text = None;
    let mut timeout = None;
    let mut maximum = None;
    let mut local_only = false;
    let mut anonymity = None;
    let mut literal = false;
    let mut index = 0;
    while index < args.len() {
        let value = args[index].as_ref();
        let raw = value.as_bytes();
        if !literal && raw == b"--" {
            literal = true;
            index += 1;
            continue;
        }
        if !literal && anonymity_option(args, &mut index, &mut anonymity)? {
            continue;
        }
        if !literal && matches!(raw, b"-n" | b"--no-network") {
            local_only = true;
            index += 1;
            continue;
        }
        let option = if literal {
            None
        } else if matches!(
            raw,
            b"-o" | b"--output" | b"--keywords" | b"--timeout" | b"--max-visible-results"
        ) {
            index += 1;
            let argument = args
                .get(index)
                .ok_or("FS search option requires a value")?
                .as_ref();
            Some((raw, argument))
        } else if let Some(argument) = raw.strip_prefix(b"--output=") {
            Some((b"--output".as_slice(), OsStr::from_bytes(argument)))
        } else if let Some(argument) = raw.strip_prefix(b"--keywords=") {
            Some((b"--keywords".as_slice(), OsStr::from_bytes(argument)))
        } else if let Some(argument) = raw.strip_prefix(b"--timeout=") {
            Some((b"--timeout".as_slice(), OsStr::from_bytes(argument)))
        } else if let Some(argument) = raw.strip_prefix(b"--max-visible-results=") {
            Some((
                b"--max-visible-results".as_slice(),
                OsStr::from_bytes(argument),
            ))
        } else if raw.starts_with(b"-o") && raw.len() > 2 {
            Some((b"--output".as_slice(), OsStr::from_bytes(&raw[2..])))
        } else {
            None
        };
        if let Some((name, argument)) = option {
            match name {
                b"-o" | b"--output" => selected(
                    &mut output,
                    argument,
                    "search requires at most one nonempty output filename",
                )?,
                b"--keywords" => selected(
                    &mut text,
                    argument,
                    "search requires at most one nonempty keyword text",
                )?,
                b"--timeout" => selected(
                    &mut timeout,
                    argument,
                    "search requires at most one nonempty timeout",
                )?,
                b"--max-visible-results" => selected(
                    &mut maximum,
                    argument,
                    "search requires at most one nonempty result limit",
                )?,
                _ => return Err("unknown FS search option".into()),
            }
        } else {
            if !literal && raw.starts_with(b"-") {
                return Err(
                    "unknown FS search option; use -- before literal keyword arguments".into(),
                );
            }
            if positional.len() == max_keywords + 1 {
                return Err("too many FS search arguments".into());
            }
            positional.try_reserve(1)?;
            positional.push(value);
        }
        index += 1;
    }
    let socket = *positional
        .first()
        .ok_or("FS search requires a socket and query")?;
    let query = if let Some(text) = text {
        if positional.len() != 1 {
            return Err("--keywords requires only the socket as a positional argument".into());
        }
        QueryInput::Text(text.as_bytes())
    } else {
        let first = *positional
            .get(1)
            .ok_or("FS search requires a URI or keyword arguments")?;
        if first.as_bytes().starts_with(b"gnunet://fs/") {
            if positional.len() > 4 {
                return Err("too many positional FS URI search arguments".into());
            }
            if let Some(value) = positional.get(2) {
                selected(
                    &mut timeout,
                    value,
                    "search timeout specified more than once",
                )?;
            }
            if let Some(value) = positional.get(3) {
                selected(
                    &mut maximum,
                    value,
                    "search result limit specified more than once",
                )?;
            }
            QueryInput::Uri(first.as_bytes())
        } else {
            let mut terms = Vec::new();
            terms.try_reserve_exact(positional.len() - 1)?;
            terms.extend(positional[1..].iter().map(|value| value.as_bytes()));
            QueryInput::Args(terms)
        }
    };
    Ok(Arguments {
        socket,
        query,
        timeout,
        maximum,
        output,
        local_only,
        anonymity: anonymity.unwrap_or(1),
    })
}
fn export_value(value: &search_export::Report) -> Value {
    json!({"visible_results":value.visible_results,"prepared_entries":value.entries,"wire_bytes":value.wire_bytes,
        "written_bytes":value.write.bytes,"commit_stage":format!("{:?}",value.write.stage),
        "durable":value.write.stage==gnunet::fs_host::CommitStage::Durable,
        "partial_search":true,"complete_visible_records_only":true,"metadata_omissions":0})
}
#[expect(
    clippy::large_enum_variant,
    reason = "One bounded poll observation retains the actual step or error on the stack without allocating for each search callback."
)]
enum Observation {
    Step(Result<Step, search::Error>),
    Stop,
    NativeDeadline,
    Signal(io::Error),
}

pub(super) fn run(args: &[impl AsRef<OsStr>], out: &mut impl Write) -> Result<(), Box<dyn Error>> {
    let arguments = arguments(args)?;
    let interval = duration(arguments.timeout.as_ref())?;
    let uri_limits = UriLimits::default();
    let query = match &arguments.query {
        QueryInput::Uri(raw) => Uri::parse(raw, uri_limits)?,
        QueryInput::Text(raw) => Uri::Keywords(Keywords::from_user_text(raw, uri_limits)?),
        QueryInput::Args(raw) => Uri::Keywords(Keywords::from_user_args(raw, uri_limits)?),
    };
    let (mandatory, optional) = match query {
        Uri::Keywords(keywords) => {
            let mandatory = keywords.iter().filter(|term| term.mandatory()).count();
            (mandatory, keywords.len() - mandatory)
        }
        Uri::Namespace(_) => (0, 0),
        _ => return Err("fs search requires a KSK or SKS URI".into()),
    };
    let limits = search::Limits::default();
    let limit = max_visible(arguments.maximum.as_ref(), limits.results)?;
    let mut export = arguments
        .output
        .map(|path| search_export::Target::open(Path::new(path)))
        .transpose()?;
    let source = ipc::EndpointSource::unix(Path::new(arguments.socket).to_path_buf());
    // Capture the immutable native bound before any canonical sample; callbacks,
    // local output and wait cancellation never renew this original operation.
    let hard = Instant::now()
        .checked_add(Duration::from_micros(interval))
        .ok_or("search native deadline is too large")?;
    let deadline = target(&source, interval)?;
    let options = search::Options {
        anonymity: arguments.anonymity,
        local_only: arguments.local_only,
        deadline,
        limits,
        block: ublock::Limits::default(),
        protocol: ipc::ProtocolLimits::default(),
        native: ipc::Limits::default(),
    };
    // Some official user terms (optional empty/leading plus) cannot be encoded
    // as a KSK URI without changing meaning. Keep their actual query and report
    // the absence of a faithful URI, rather than refusing or rewriting the term.
    let canonical = match query.encoded_len() {
        Ok(length) => {
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(length)?;
            bytes.resize(length, 0);
            query.encode(&mut bytes)?;
            Some(bytes)
        }
        Err(ProtocolError::InvalidInput) if !matches!(&arguments.query, QueryInput::Uri(_)) => None,
        Err(error) => return Err(error.into()),
    };
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        let mut interrupt=signal(SignalKind::interrupt())?;
        let mut terminate=signal(SignalKind::terminate())?;
        let mut native=Box::pin(tokio::time::sleep_until(hard));
        if Instant::now()>=hard {return Err("search deadline elapsed during setup".into());}
        let mut identities:[Instance;QUERIES]=std::array::from_fn(|_|Instance::new());
        let mut visible=vec![false;limits.results];
        let mut terminal=Vec::new();
        terminal.try_reserve_exact(QUERIES).map_err(io::Error::other)?;
        let mut session=Session::<_,KNOWN>::new(query,&mut identities,||source.duplicate(),options)?;
        let mut visible_count=0usize;
        let mut native_steps=0usize;
        let mut rejected=0usize;
        let mut ignored=0usize;
        let mut native_deadline=None;
        let stopped:Result<&str,Cause>=async {
            row(out,&json!({"event":"fs_search_started","query_uri":canonical.as_deref().and_then(|bytes|std::str::from_utf8(bytes).ok()),"query_uri_bytes":canonical,
                "mandatory_total":mandatory,"optional_total":optional,"query_count":session.query_count(),
                "deadline_micros":deadline.as_micros(),"max_visible_results":limit,"anonymity":options.anonymity,
                "local_only":options.local_only,"result_capacity":limits.results,"query_capacity":QUERIES,"directory_requested":export.is_some()}))
                .map_err(Cause::Output)?;
            loop {
                // drive() explicitly retains the same partial MQs/advertisement
                // when this wait is canceled by a signal or original hard bound.
                let observation={
                    let wait=Instant::now().checked_add(Duration::from_millis(50)).unwrap_or(hard).min(hard);
                    let mut driving=std::pin::pin!(session.drive(Some(wait)));
                    poll_fn(|cx| {
                        if Instant::now()>=hard || native.as_mut().poll(cx).is_ready() {return Poll::Ready(Observation::NativeDeadline);}
                        for signal in [&mut interrupt,&mut terminate] {
                            if let Poll::Ready(value)=signal.poll_recv(cx) {
                                return Poll::Ready(match value {Some(())=>Observation::Stop,None=>Observation::Signal(io::Error::new(io::ErrorKind::UnexpectedEof,"search signal stream closed"))});
                            }
                        }
                        driving.as_mut().poll(cx).map(Observation::Step)
                    }).await
                };
                let step=match observation {
                    Observation::Stop=>return Ok("caller_stop"),
                    Observation::NativeDeadline=>return Ok("caller_deadline"),
                    Observation::Signal(error)=>return Err(Cause::Signal(error)),
                    Observation::Step(Ok(step))=>step,
                    Observation::Step(Err(search::Error::Protocol(ProtocolError::Deadline)))=>return Ok("caller_deadline"),
                    Observation::Step(Err(cause @ search::Error::Transport(ipc::Error::Protocol(ProtocolError::Deadline))))=>{
                        native_deadline=Some((None,cause));return Ok("caller_deadline");
                    },
                    Observation::Step(Err(cause))=>return Err(Cause::Search(cause)),
                };
                match step {
                    Step::Result{result}|Step::Update{result}|Step::Pending{result}=> {
                        let event=match step {Step::Result{..}=>"fs_search_result",Step::Update{..}=>"fs_search_update",_=>"fs_search_pending"};
                        let value=result_value(&session,result,event,mandatory,optional)?;
                        row(out,&value).map_err(Cause::Output)?;
                        let record=session.result(result).ok_or(Cause::State("native search result disappeared"))?;
                        let counted=visible.get_mut(result.index()).ok_or(Cause::State("native search result exceeds retained table"))?;
                        if record.visible() && !*counted { *counted=true;visible_count+=1; }
                        if limit.is_some_and(|limit|visible_count>=limit) { return Ok("visible_result_limit"); }
                    }
                    Step::Ignored=>ignored=ignored.checked_add(1).ok_or(Cause::State("ignored-advertisement counter overflow"))?,
                    Step::Rejected{query,cause}=> {
                        rejected=rejected.checked_add(1).ok_or(Cause::State("rejected-advertisement counter overflow"))?;
                        row(out,&json!({"event":"fs_search_rejected","query":query_value(&session,query),"cause":error_value(&cause)})).map_err(Cause::Output)?;
                    }
                    Step::Native{query,step}=> {
                        native_steps=native_steps.checked_add(1).ok_or(Cause::State("native-step counter overflow"))?;
                        if matches!(step,ipc::Step::Retry{..}|ipc::Step::Unavailable(_)) {
                            row(out,&json!({"event":"fs_search_unavailable","query":query_value(&session,query),"step":native_value(&step)})).map_err(Cause::Output)?;
                        }
                    }
                    Step::Failed{query,cause}=> {
                        if matches!(&cause,ipc::Error::Protocol(ProtocolError::Deadline)) {
                            native_deadline=Some((Some(query),search::Error::Transport(cause)));
                            return Ok("caller_deadline");
                        }
                        terminal.push((query,cause));
                        let (_,cause)=terminal.last().ok_or(Cause::State("original query failure disappeared"))?;
                        row(out,&json!({"event":"fs_search_query_failed","query":query_value(&session,query),"cause":cause.to_string()})).map_err(Cause::Output)?;
                    }
                }
            }
        }.await;
        let cleanup=match session.cancel() {
            Ok(())|Err(search::Error::Protocol(ProtocolError::Closed))=>None,
            Err(error)=>Some(error),
        };
        // C also archives on timeout/interrupt/shutdown, not only a successful
        // search. Preserve this actual session's current visible union after
        // cancel, including an empty observation; never restart to fill an archive.
        let archived=export.as_mut().map(|target|target.write(session.results()));
        let (archive,export_failure)=match archived {
            None=>(None,None),Some(Ok(report))=>(Some(report),None),
            Some(Err(failure))=>(Some(failure.report),Some(failure)),
        };
        let retained_results=session.results().len();
        let query_count=session.query_count();
        drop(session);
        let (reason,cause)=match stopped {Ok(reason)=>(reason,None),Err(cause)=>("error",Some(cause))};
        let final_row=json!({"event":"fs_search_stopped","reason":reason,
            "visible_results":visible_count,"retained_results":retained_results,"query_count":query_count,
            "native_steps":native_steps,"rejected_advertisements":rejected,"ignored_advertisements":ignored,
            "terminal_query_failures":terminal.iter().map(|(id,cause)|json!({"query_id":id.index(),"cause":cause.to_string()})).collect::<Vec<_>>(),
            "cause":cause.as_ref().map(ToString::to_string),"cleanup_error":cleanup.as_ref().map(error_value),
            "native_deadline":native_deadline.as_ref().map(|(id,cause)|json!({"query_id":id.map(|id|id.index()),"cause":error_value(cause)})),
            "directory":archive.as_ref().map(export_value),"directory_error":export_failure.as_ref().map(ToString::to_string),
            "scope":"caller observation stopped; no whole-network completion or absence conclusion"});
        let diagnostic=row(out,&final_row).err();
        if cause.is_some() || cleanup.is_some() || diagnostic.is_some() || !terminal.is_empty() || export_failure.is_some() {
            return Err(Box::new(Failure{cause,queries:terminal,cleanup,diagnostic,export:export_failure}) as Box<dyn Error>);
        }
        Ok(())
    })
}

#[cfg(test)]
mod anonymity_tests {
    use super::*;
    #[test]
    fn selected_search_level_preserves_query_values_and_literal_option_keywords()
    -> Result<(), Box<dyn Error>> {
        let zero = arguments(&["fs", "gnunet://fs/ksk/query", "--anonymity=0"])?;
        if zero.anonymity != 0 || !matches!(zero.query, QueryInput::Uri(b"gnunet://fs/ksk/query")) {
            return Err("nonanonymous URI search selection changed".into());
        }
        let maximum = arguments(&["fs", "-a", "4294967295", "--keywords", "-a0"])?;
        if maximum.anonymity != u32::MAX || !matches!(maximum.query, QueryInput::Text(b"-a0")) {
            return Err("keyword option value was interpreted as anonymity".into());
        }
        let literal = arguments(&["fs", "-a3", "--", "--anonymity", "0"])?;
        let QueryInput::Args(terms) = literal.query else {
            return Err("literal keyword query changed".into());
        };
        if literal.anonymity != 3 || terms != [b"--anonymity".as_slice(), b"0".as_slice()] {
            return Err("literal keyword options were consumed".into());
        }
        Ok(())
    }
    #[test]
    fn ambiguous_or_unrepresentable_search_levels_are_refused() -> Result<(), Box<dyn Error>> {
        for args in [
            vec!["fs", "query", "-a"],
            vec!["fs", "query", "--anonymity="],
            vec!["fs", "query", "-a", "-1"],
            vec!["fs", "query", "--anonymity=4294967296"],
            vec!["fs", "query", "-a0", "--anonymity", "1"],
        ] {
            if arguments(&args).is_ok() {
                return Err("invalid search anonymity was admitted".into());
            }
        }
        Ok(())
    }
}
