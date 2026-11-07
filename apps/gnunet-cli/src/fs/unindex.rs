//! User-level stable-file unindex through original DATASTORE and FS owners.
use super::{
    metadata_options,
    publication::hex,
    service::{datastore_client, duration, target},
};
use gnunet::{
    fs::{Limits as UriLimits, Uri},
    fs_host::{
        Buffers, Control,
        ipc::EndpointSource,
        network::unindex::{self, Report},
    },
};
use serde_json::{Value, json};
use std::{
    cell::Cell,
    error::Error,
    ffi::OsStr,
    fmt,
    future::{Future, poll_fn},
    io::{self, Write},
    os::unix::ffi::OsStrExt,
    path::Path,
    rc::Rc,
    task::Poll,
    time::Duration,
};
use tokio::{
    signal::unix::{SignalKind, signal},
    time::Instant,
};

struct Arguments<'a> {
    positional: Vec<&'a OsStr>,
    keywords: Vec<Vec<u8>>,
    metadata: metadata_options::Arguments,
}
pub(super) fn add_keywords(raw: &[u8], keywords: &mut Vec<Vec<u8>>) -> Result<(), Box<dyn Error>> {
    let Uri::Keywords(terms) = Uri::parse(raw, UriLimits::default())? else {
        return Err("unindex --keywords requires a KSK URI".into());
    };
    for term in terms.iter() {
        if term.is_empty() || term.len() > 4096 {
            return Err("unindex keywords must contain 1..4096 decoded bytes".into());
        }
        let mut owned = Vec::new();
        owned.try_reserve_exact(term.len())?;
        owned.resize(term.len(), 0);
        term.write(&mut owned)?;
        if !keywords.contains(&owned) {
            if keywords.len() == 256 {
                return Err("at most 256 explicit unindex keywords are allowed".into());
            }
            keywords.try_reserve(1)?;
            keywords.push(owned);
        }
    }
    Ok(())
}
fn arguments<T: AsRef<OsStr>>(args: &[T]) -> Result<Arguments<'_>, Box<dyn Error>> {
    let mut positional = Vec::new();
    positional.try_reserve_exact(4)?;
    let mut keywords = Vec::new();
    let mut metadata = metadata_options::Arguments::default();
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
        if !literal && metadata.consume(args, &mut index, false)? {
            continue;
        }
        let selected = if !literal && raw == b"--keywords" {
            index += 1;
            Some(
                args.get(index)
                    .ok_or("--keywords requires a KSK URI")?
                    .as_ref()
                    .as_bytes(),
            )
        } else if !literal && raw.starts_with(b"--keywords=") {
            Some(&raw[11..])
        } else {
            None
        };
        if let Some(raw) = selected {
            add_keywords(raw, &mut keywords)?;
        } else {
            if !literal && raw.starts_with(b"-") {
                return Err("unknown FS unindex option".into());
            }
            if positional.len() == 4 {
                return Err("too many FS unindex arguments".into());
            }
            positional.push(value);
        }
        index += 1;
    }
    if positional.len() < 3 {
        return Err("fs unindex requires FS socket, DATASTORE socket and filename".into());
    }
    Ok(Arguments {
        positional,
        keywords,
        metadata,
    })
}
fn value(report: &Report) -> Value {
    let p = report.observation;
    json!({"file_id_hex":report.file_id.as_ref().map(|id|hex(id)),
        "content":report.content.map(|content|json!({"key_hex":hex(&content.key),"query_hex":hex(&content.query),"size":content.size})),
        "hashed_bytes":p.hashed_bytes,"encoded_plaintext_bytes":p.encoded.plaintext_bytes,
        "encoded_blocks":p.encoded.blocks,"encoded_bytes":p.encoded.encoded_bytes,
        "content_positive_remove_statuses":p.content_positive,"content_zero_remove_statuses":p.content_zero,
        "keyword_queries":p.keyword_queries,"keyword_rows":p.keyword_rows,"keyword_matches":p.keyword_matches,
        "keyword_end_responses":p.keyword_ends,"keyword_positive_remove_statuses":p.keyword_positive,"keyword_zero_remove_statuses":p.keyword_zero,
        "skipped_keyword_rows":p.skipped_rows,"last_remove_status":p.last_status,"last_store_submitted":p.last_store_submitted,
        "requested_cancel":p.requested_cancel,"fs_request_written_bytes":p.fs_written_bytes,
        "reconstructed_keywords":report.reconstructed_keywords,"selected_keywords":report.selected_keywords,
        "fs_admitted":report.fs_admitted,"unindexed":report.unindexed,"original_fs_reply_retained":report.response().is_some(),
        "scope":"current stable file; exact local removal responses and original FS acknowledgement, not every historical/custom advertisement or remote deletion",
        "partial_datastore_cleanup":p.content_zero!=0 || p.keyword_zero!=0,
        "zero_remove_status":"raw service result; cannot distinguish absence from every backend failure"})
}
#[derive(Debug)]
struct Failure {
    outcome: Result<Report, Box<unindex::Failure>>,
    signal: Option<io::Error>,
    output: Option<io::Error>,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.outcome {
            Ok(report) => write!(f, "file unindex terminal facts: {report:?}")?,
            Err(e) => write!(f, "{e}; original typed failures: {e:?}")?,
        }
        if let Some(e) = &self.signal {
            write!(f, "; signal: {e}")?;
        }
        if let Some(e) = &self.output {
            write!(f, "; output: {e}")?;
        }
        Ok(())
    }
}
impl Error for Failure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.outcome
            .as_ref()
            .err()
            .map(|e| e.as_ref() as &dyn Error)
            .or_else(|| self.signal.as_ref().map(|e| e as _))
            .or_else(|| self.output.as_ref().map(|e| e as _))
    }
}
pub(super) fn run(args: &[impl AsRef<OsStr>], out: &mut impl Write) -> Result<(), Box<dyn Error>> {
    let selection = arguments(args)?;
    let args = &selection.positional;
    let interval = duration(args.get(3))?;
    let hard = Instant::now()
        .checked_add(Duration::from_micros(interval))
        .ok_or("unindex native deadline is too large")?;
    let fs_source = EndpointSource::unix(Path::new(args[0]).to_path_buf());
    let store_source =
        EndpointSource::unix_with_clock(Path::new(args[1]).to_path_buf(), fs_source.clock());
    let deadline = target(&fs_source, interval)?;
    let metadata = selection.metadata.select()?;
    let filename = Path::new(args[2]);
    let mut input = gnunet::fs_host::open_input(filename)?;
    let mut refs = Vec::new();
    refs.try_reserve_exact(selection.keywords.len())?;
    refs.extend(selection.keywords.iter().map(Vec::as_slice));
    let mut options = unindex::Options::new(deadline, hard);
    options.extra_keywords = &refs;
    options.metadata = metadata;
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async{
        let mut interrupt=signal(SignalKind::interrupt())?;let mut terminate=signal(SignalKind::terminate())?;
        let stop=Rc::new(Cell::new(false));let mut signal_error=None;
        let mut identity=gnunet::datastore_host::Instance::new();
        let mut wire=Vec::new();wire.try_reserve_exact(65535)?;wire.resize(65535,0);
        let mut slots=[gnunet::datastore_host::Slot::new(&mut wire)];
        let mut reservations=[gnunet::datastore_host::ReservationSlot::default();1];
        let store=datastore_client(&mut identity,&mut slots,&mut reservations,store_source)?;
        let mut buffers=Buffers::new();
        let outcome={
            let running=stop.clone();
            let mut original=std::pin::pin!(buffers.unindex_file(&mut input,filename,fs_source,store,options,move|_|{
                if running.get(){Control::Cancel}else{Control::Continue}
            }));
            poll_fn(|cx|{
                if !stop.get(){
                    for signals in [&mut interrupt,&mut terminate]{
                        if let Poll::Ready(value)=signals.poll_recv(cx){
                            stop.set(true);
                            if value.is_none() && signal_error.is_none(){signal_error=Some(io::Error::new(io::ErrorKind::UnexpectedEof,"unindex signal stream closed"));}
                            break;
                        }
                    }
                }
                // Retain and drive the original future through its real cancel,
                // operation settlement and physical closes. Never recreate it.
                original.as_mut().poll(cx)
            }).await
        };
        let report=match &outcome{Ok(report)=>report,Err(failure)=>&failure.report};
        let partial=report.observation.content_zero!=0 || report.observation.keyword_zero!=0;
        let row=json!({"event":if outcome.is_err(){"fs_unindex_failed"}else if partial{"fs_unindex_partial"}else{"fs_unindex_complete"},
            "report":value(report),"cause":outcome.as_ref().err().map(ToString::to_string),
            "failure_facts":outcome.as_ref().err().map(|e|format!("{e:?}")),"stop_requested":stop.get(),
            "signal_error":signal_error.as_ref().map(ToString::to_string)});
        let output=(||->io::Result<()>{serde_json::to_writer(&mut *out,&row).map_err(io::Error::other)?;writeln!(out)?;out.flush()})().err();
        if outcome.is_err() || signal_error.is_some() || output.is_some(){return Err(Box::new(Failure{outcome,signal:signal_error,output}) as Box<dyn Error>);}
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn check(value: bool) -> Result<(), Box<dyn Error>> {
        if value {
            Ok(())
        } else {
            Err("unindex metadata selection changed".into())
        }
    }
    #[test]
    fn explicit_metadata_selection_and_literal_paths_share_publication_semantics()
    -> Result<(), Box<dyn Error>> {
        let disabled = arguments(&["fs", "ds", "file", "-D"])?;
        check(!disabled.metadata.select()?.automatic_keywords_enabled())?;
        let filename = arguments(&["fs", "ds", "file", "--extractors", "-"])?;
        let metadata = filename.metadata.select()?;
        check(metadata.automatic_keywords_enabled() && !metadata.format_extraction_enabled())?;
        let literal = arguments(&["fs", "ds", "--", "-D"])?;
        check(
            literal.positional[2] == OsStr::new("-D")
                && literal.metadata.select()?.format_extraction_enabled(),
        )?;
        check(arguments(&["fs", "ds", "file", "-m", "title:value"]).is_err())?;
        check(arguments(&["fs", "ds", "file", "--extractor-library"]).is_err())
    }
}
