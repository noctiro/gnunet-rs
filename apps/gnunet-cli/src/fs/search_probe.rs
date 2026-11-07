//! Real automatic probes of authenticated search hits, with independent history.
use super::{
    publication::hex,
    service::{duration, target},
};
use gnunet::{
    crypto::Entropy,
    fs::{Limits as UriLimits, Uri, client::Instance, ublock},
    fs_host::{
        ipc, network, probe_task,
        search::{
            self, Session, Step,
            automatic::{self, Automatic, Event, Persistence},
        },
    },
    types::Error as ProtocolError,
};
use serde_json::{Value, json};
use std::{
    error::Error,
    ffi::OsStr,
    fmt,
    fs::File,
    future::{Future, poll_fn},
    io::{self, Read, Write},
    os::unix::ffi::OsStrExt,
    path::Path,
};

struct OsEntropy(File);
impl Entropy for OsEntropy {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), ProtocolError> {
        self.0.read_exact(out).map_err(|_| ProtocolError::Entropy)
    }
}
fn row(out: &mut impl Write, value: &Value) -> io::Result<()> {
    serde_json::to_writer(&mut *out, value).map_err(io::Error::other)?;
    writeln!(out)?;
    out.flush()
}
fn summary(s: search::availability::Summary) -> Value {
    json!({"attempts":s.attempts(),"successes":s.successes(),"trials":s.trials(),"cancelled":s.cancelled(),"rank":s.rank(),"certainty":s.certainty(),"setup_deadlines":s.setup_deadlines(),"queries_written":s.queries_written(),"source_elapsed_us":s.source_elapsed().0,"active":s.active(),"errors":format!("{:?}",s.errors())})
}
fn observed(result: &Result<network::probe::Observed, network::probe::Failure>) -> Value {
    match result {
        Ok(o) => {
            let p = o.progress();
            let r = o.range();
            json!({"kind":"success","leaf":o.leaf(),"range_start":r.start,"range_end":r.end,"queries_written":o.queries_written(),"bytes":p.plaintext_bytes,"blocks":p.blocks,"encoded_bytes":p.encoded_bytes,"elapsed_us":o.elapsed().0,"retired":o.retired()})
        }
        Err(f) => {
            let p = f.progress();
            let r = f.range();
            let kind = match f.cause() {
                network::Error::Deadline { .. } if f.queries_written() > 0 => "inconclusive",
                network::Error::Deadline { .. } => "setup_deadline",
                network::Error::Cancelled(_) => "cancelled",
                _ => "error",
            };
            json!({"kind":kind,"cause":f.cause().to_string(),"leaf":f.leaf(),"range_start":r.as_ref().map(|r|r.start),"range_end":r.as_ref().map(|r|r.end),"queries_written":f.queries_written(),"bytes":p.plaintext_bytes,"blocks":p.blocks,"encoded_bytes":p.encoded_bytes,"last_checked_us":f.last_checked().map(|t|t.as_micros()),"retired":f.retired()})
        }
    }
}
fn native_trial(result: &Result<network::probe::Observed, network::probe::Failure>) -> bool {
    result.is_ok()
        || result.as_ref().err().is_some_and(|f| {
            matches!(f.cause(), network::Error::Deadline { .. }) && f.queries_written() > 0
        })
}
fn terminal(kind: probe_task::Kind) -> &'static str {
    match kind {
        probe_task::Kind::Success => "success",
        probe_task::Kind::Inconclusive => "inconclusive",
        probe_task::Kind::SetupDeadline => "setup_deadline",
        probe_task::Kind::Cancelled => "cancelled",
        probe_task::Kind::Authentication => "authentication",
        probe_task::Kind::Protocol => "protocol",
        probe_task::Kind::Clock => "clock",
        probe_task::Kind::Resource => "resource",
        probe_task::Kind::Transport => "transport",
        probe_task::Kind::Setup => "setup",
        probe_task::Kind::Local => "local",
        probe_task::Kind::Other => "other",
    }
}
fn persistence(p: &automatic::persistence::Outcome) -> Value {
    json!({"task_id":hex(&p.task_id),"origin":hex(&p.origin),"kind":p.receipt.as_ref().map(|r|terminal(r.kind())),"historical":p.status.map(|s|summary(s.historical)),"phase":p.status.map(|s|format!("{:?}",s.phase)),"recorded":p.cause.is_none()&&p.receipt.is_some(),"cause":p.cause.as_ref().map(ToString::to_string),"receipt_body_hash":p.receipt.as_ref().map(|r|hex(&r.body_hash())),"fresh_observation":false})
}
fn is_deadline(error: &search::Error) -> bool {
    matches!(
        error,
        search::Error::Protocol(ProtocolError::Deadline)
            | search::Error::Transport(ipc::Error::Protocol(ProtocolError::Deadline))
    )
}
#[derive(Debug, Default)]
struct Failure {
    coordinator: Option<automatic::Failure>,
    persistence: Option<automatic::persistence::Error>,
    recording: Option<probe_task::Cause>,
    output: Option<io::Error>,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("automatic search/probe run failed")?;
        if let Some(e) = &self.coordinator {
            write!(f, "; coordinator: {e}")?;
        }
        if let Some(e) = &self.persistence {
            write!(f, "; persistence: {e}")?;
        }
        if let Some(e) = &self.recording {
            write!(f, "; recording: {e}")?;
        }
        if let Some(e) = &self.output {
            write!(f, "; output: {e}")?;
        }
        Ok(())
    }
}
impl Error for Failure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        if let Some(e) = &self.coordinator {
            Some(e)
        } else if let Some(e) = &self.persistence {
            Some(e)
        } else if let Some(e) = &self.recording {
            Some(e)
        } else {
            self.output.as_ref().map(|e| e as _)
        }
    }
}

pub(super) fn run(args: &[impl AsRef<OsStr>], out: &mut impl Write) -> Result<(), Box<dyn Error>> {
    let interval = match args.get(3) {
        Some(v) => duration(Some(v))?,
        None => 5_000_000,
    };
    let quota = match args.get(4) {
        Some(v) => {
            let n = v
                .as_ref()
                .to_str()
                .ok_or("trial quota must be UTF-8 digits")?
                .parse::<u64>()?;
            if n == 0 {
                return Err("trial quota must be positive".into());
            }
            Some(n)
        }
        None => None,
    };
    let max_running = match args.get(5) {
        Some(v) => v
            .as_ref()
            .to_str()
            .ok_or("max-running must be UTF-8 digits")?
            .parse()?,
        None => 2,
    };
    let query = Uri::parse(args[1].as_ref().as_bytes(), UriLimits::default())?;
    if !matches!(query, Uri::Keywords(_) | Uri::Namespace(_)) {
        return Err("automatic search probing requires a KSK or SKS query".into());
    }
    let source = ipc::EndpointSource::unix(Path::new(args[0].as_ref()).to_path_buf());
    let deadline = target(&source, interval)?;
    let store = Persistence::open(args[2].as_ref(), probe_task::Limits::default())?;
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        let mut identities:[Instance;64]=std::array::from_fn(|_|Instance::new());
        let options=search::Options{anonymity:1,local_only:false,deadline,limits:search::Limits::default(),block:ublock::Limits::default(),protocol:ipc::ProtocolLimits::default(),native:ipc::Limits::default()};
        let session=Session::<_,1024>::new(query,&mut identities,||source.duplicate(),options)?;
        let mut driver=Automatic::new(session,automatic::Policy{max_running,..Default::default()})?.with_persistence(store);
        let stop=driver.stop_handle();let mut entropy=OsEntropy(File::open("/dev/urandom")?);
        let mut interrupt=tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
        let mut terminate=tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let(mut probes,mut successes,mut trials,mut historical_max_trials)=(0u64,0u64,0u64,0u32);
        let mut failure=Failure::default();let mut stopped="caller_stop";
        loop {
            let actual={let mut next=std::pin::pin!(driver.next(&mut entropy));poll_fn(|cx|{if interrupt.poll_recv(cx).is_ready()||terminate.poll_recv(cx).is_ready(){stop.request();}next.as_mut().poll(cx)}).await};
            let value=match actual {
                Ok(Some(Event::Search(step)))=>{
                    match *step {
                        Step::Result{result}|Step::Update{result}|Step::Pending{result}=>{
                            let record=driver.session().result(result).ok_or("original automatic result disappeared")?;
                            Some(json!({"event":"fs_search_probe_hit","result_id":result.index(),"uri":std::str::from_utf8(record.raw_uri()).ok(),"visible":record.visible(),"mandatory_missing":record.mandatory_missing()}))
                        },
                        Step::Rejected{query,cause}=>Some(json!({"event":"fs_search_probe_rejected","query_id":query.index(),"cause":cause.to_string()})),
                        Step::Failed{query,cause}=>Some(json!({"event":"fs_search_probe_query_failed","query_id":query.index(),"cause":cause.to_string()})),
                        _=>None,
                    }
                },
                Ok(Some(Event::Probe(report)))=>{
                    probes+=1;successes+=u64::from(report.native.observation.is_ok());trials+=u64::from(native_trial(&report.native.observation));
                    if let Some(status)=report.persistence.as_ref().and_then(|p|p.status){historical_max_trials=historical_max_trials.max(status.historical.trials());}
                    let original=driver.session().result(report.native.result);
                    let value=json!({"event":"fs_search_probe_result","result_id":report.native.result.index(),"uri":original.and_then(|r|std::str::from_utf8(r.raw_uri()).ok()),"current":summary(report.native.summary),"native":observed(&report.native.observation),"persistent":report.persistence.as_deref().map(persistence)});
                    if let Some(cause)=report.persistence.and_then(|p|p.cause) && failure.recording.is_none(){failure.recording=Some(cause);}
                    if quota.is_some_and(|quota|trials>=quota){stop.request();stopped="trial_quota";}
                    Some(value)
                },
                Ok(Some(Event::AdmissionFailed{result,cause}))=>Some(json!({"event":"fs_search_probe_admission_failed","result_id":result.index(),"cause":cause.to_string()})),
                Ok(Some(Event::PersistenceFailed{result,cause,accounting}))=>{
                    let value=json!({"event":"fs_search_probe_persistence_failed","result_id":result.index(),"cause":cause.to_string(),"accounting":accounting.as_ref().map(ToString::to_string)});
                    match cause {automatic::persistence::Error::Exhausted(status)|automatic::persistence::Error::Cancelled(status)=>{historical_max_trials=historical_max_trials.max(status.historical.trials());},cause=>if failure.persistence.is_none(){failure.persistence=Some(cause);}}
                    Some(value)
                },
                Ok(Some(Event::AccountingRefused{native,persistence}))=>{
                    stop.request();Some(json!({"event":"fs_search_probe_accounting_refused","result_id":native.original.result().index(),"cause":native.cause.to_string(),"native":observed(native.original.observation()),"persistent":persistence.as_deref().map(self::persistence)}))
                },
                Ok(None)=>break,
                Err(cause)=>{
                    if cause.cause.as_ref().is_some_and(is_deadline) && cause.cleanup.is_none(){stopped="deadline";}else{failure.coordinator=Some(cause);}
                    break;
                },
            };
            if failure.output.is_none() && let Some(value)=value && let Err(error)=row(out,&value){failure.output=Some(error);stop.request();}
        }
        if failure.output.is_none(){row(out,&json!({"event":"fs_search_probe_stopped","reason":stopped,"probes":probes,"successes":successes,"trials":trials,"historical_max_trials":historical_max_trials,"cleanup":failure.coordinator.as_ref().and_then(|e|e.cleanup.as_ref()).map(ToString::to_string),"whole_search_complete":false}))?;}
        if failure.coordinator.is_some()||failure.persistence.is_some()||failure.recording.is_some()||failure.output.is_some(){Err(Box::new(failure)as Box<dyn Error>)}else{Ok(())}
    })
}
