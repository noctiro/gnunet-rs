//! One original FS IndexList and streamed opaque filename/hash observations.
use super::service::{duration, target};
use gnunet::{
    fs::client::{Event, Failure as NativeFailure},
    fs_host::ipc,
    types::Error as Fault,
};
use serde_json::json;
use std::{
    error::Error,
    ffi::OsStr,
    fmt,
    future::{Future, poll_fn},
    io::{self, Write},
    path::Path,
    task::Poll,
    time::Duration,
};
use tokio::{
    signal::unix::{SignalKind, signal},
    time::Instant,
};

const DEFAULT_MAX_RECORDS: u64 = 65536;
const MAX_RECORDS: u64 = 1000000;
fn maximum(raw: Option<&impl AsRef<OsStr>>) -> Result<u64, Box<dyn Error>> {
    let Some(raw) = raw else {
        return Ok(DEFAULT_MAX_RECORDS);
    };
    let value = raw
        .as_ref()
        .to_str()
        .ok_or("max-records requires decimal digits")?;
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err("max-records requires decimal digits".into());
    }
    let number = value.parse()?;
    if number > MAX_RECORDS {
        return Err("max-records exceeds 1000000".into());
    }
    Ok(number)
}
#[derive(Debug)]
struct Report {
    observed: u64,
    emitted: u64,
    index_end: bool,
    attached: bool,
    initial_retries: u64,
    initial_retry: Option<ipc::Error>,
    request_written_bytes: usize,
    request_wholewritten: bool,
    row_in_progress: bool,
    maximum: u64,
    retired: bool,
    owner_dropped: bool,
    native_failure: Option<NativeFailure>,
    reason: &'static str,
}
#[derive(Debug)]
enum Cause {
    Native(ipc::Error),
    NativeDeadline,
    Stop,
    Capacity,
    Finished,
    UnexpectedEvent,
    SecondAttachment,
    FilenameBound,
    Signal(io::Error),
}
impl fmt::Display for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Native(e) => write!(f, "{e}"),
            Self::NativeDeadline => f.write_str("original native list deadline elapsed"),
            Self::Stop => f.write_str("caller stopped the original list"),
            Self::Capacity => f.write_str("list record bound reached before IndexEnd"),
            Self::Finished => f.write_str("FS list finished without an observed IndexEnd"),
            Self::UnexpectedEvent => {
                f.write_str("foreign FS operation event on original IndexList")
            }
            Self::SecondAttachment => {
                f.write_str("IndexList source changed before an observed IndexEnd")
            }
            Self::FilenameBound => f.write_str("index filename exceeds native frame bound"),
            Self::Signal(e) => write!(f, "signal source: {e}"),
        }
    }
}
impl Error for Cause {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Native(e) => Some(e),
            Self::Signal(e) => Some(e),
            _ => None,
        }
    }
}
#[derive(Debug)]
struct Failure {
    report: Report,
    operation: Option<Cause>,
    close: Option<ipc::Error>,
    output: Option<io::Error>,
    terminal_output: Option<io::Error>,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FS index listing terminal facts: {:?}", self.report)?;
        if let Some(e) = &self.operation {
            write!(f, "; operation: {e}")?;
        }
        if let Some(e) = &self.close {
            write!(f, "; original close: {e}")?;
        }
        if let Some(e) = &self.output {
            write!(f, "; row output: {e}")?;
        }
        if let Some(e) = &self.terminal_output {
            write!(f, "; terminal output: {e}")?;
        }
        Ok(())
    }
}
impl Error for Failure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.operation
            .as_ref()
            .map(|e| e as &dyn Error)
            .or_else(|| self.close.as_ref().map(|e| e as _))
            .or_else(|| self.output.as_ref().map(|e| e as _))
            .or_else(|| self.terminal_output.as_ref().map(|e| e as _))
    }
}
// The serializer borrows only this one original Received frame. Byte slices are
// serialized directly, without per-byte Value objects or a retained whole list.
// Conventional Write/flush are synchronous OS boundaries, not preemptible waits.
fn row(out: &mut impl Write, ordinal: u64, file_id: &[u8; 64], filename: &[u8]) -> io::Result<()> {
    write!(
        out,
        "{{\"event\":\"fs_indexed_file\",\"observation\":{ordinal},\"file_id_bytes\":"
    )?;
    serde_json::to_writer(&mut *out, file_id.as_slice()).map_err(io::Error::other)?;
    out.write_all(b",\"filename\":")?;
    serde_json::to_writer(&mut *out, &std::str::from_utf8(filename).ok())
        .map_err(io::Error::other)?;
    out.write_all(b",\"filename_bytes\":")?;
    serde_json::to_writer(&mut *out, filename).map_err(io::Error::other)?;
    out.write_all(b"}\n")?;
    out.flush()
}
#[expect(
    clippy::large_enum_variant,
    reason = "One bounded poll wake owns the actual service step or error without allocating for each indexed-file observation."
)]
enum Wake {
    Step(Result<ipc::Step, ipc::Error>),
    NativeDeadline,
    Stop,
    Signal(io::Error),
}
pub(super) fn run(args: &[impl AsRef<OsStr>], out: &mut impl Write) -> Result<(), Box<dyn Error>> {
    let interval = duration(args.get(1))?;
    let maximum = maximum(args.get(2))?;
    // Immutable native bound predates the first canonical sample and is never
    // renewed by a row, retry, blocked output or partial frame.
    let hard = Instant::now()
        .checked_add(Duration::from_micros(interval))
        .ok_or("list deadline is too large")?;
    let source = ipc::EndpointSource::unix(Path::new(args[0].as_ref()).to_path_buf());
    let deadline = target(&source, interval)?;
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async{
        let mut interrupt=signal(SignalKind::interrupt())?;
        let mut terminate=signal(SignalKind::terminate())?;
        let mut alarm=Box::pin(tokio::time::sleep_until(hard));
        if Instant::now()>=hard{return Err("list deadline elapsed during setup".into());}
        let mut identity=ipc::Instance::new();
        let mut client=ipc::Client::<0>::new(&mut identity,ipc::Request::IndexList,source,Default::default(),Default::default(),deadline)?;
        let mut report=Report{observed:0,emitted:0,index_end:false,attached:false,initial_retries:0,initial_retry:None,
            request_written_bytes:0,request_wholewritten:false,row_in_progress:false,maximum,retired:false,owner_dropped:false,native_failure:None,reason:"unsettled"};
        let mut operation=None;let mut output=None;
        loop{
            let wake={
                // This exact wait is retained across native wakeups. Canceling
                // the wait for Stop/hard leaves state in the same actual client.
                let mut pending=std::pin::pin!(client.drive(Some(hard)));
                poll_fn(|cx|{
                    if Instant::now()>=hard || alarm.as_mut().poll(cx).is_ready(){return Poll::Ready(Wake::NativeDeadline);}
                    for signals in [&mut interrupt,&mut terminate]{
                        if let Poll::Ready(value)=signals.poll_recv(cx){return Poll::Ready(match value{
                            Some(())=>Wake::Stop,None=>Wake::Signal(io::Error::new(io::ErrorKind::UnexpectedEof,"list signal stream closed")),
                        });}
                    }
                    pending.as_mut().poll(cx).map(Wake::Step)
                }).await
            };
            let step=match wake{
                Wake::NativeDeadline=>{report.reason="native_deadline";operation=Some(Cause::NativeDeadline);break;},
                Wake::Stop=>{report.reason="caller_stop";operation=Some(Cause::Stop);break;},
                Wake::Signal(e)=>{report.reason="signal_failure";operation=Some(Cause::Signal(e));break;},
                Wake::Step(Err(e))=>{report.reason="source_or_protocol_failure";operation=Some(Cause::Native(e));break;},
                Wake::Step(Ok(step))=>step,
            };
            match step{
                ipc::Step::Connected=>{
                    if report.attached{report.reason="source_changed";operation=Some(Cause::SecondAttachment);break;}
                    report.attached=true;
                }
                ipc::Step::Written{bytes,complete}=>{report.request_written_bytes+=bytes;report.request_wholewritten|=complete;}
                ipc::Step::Event(response)=>match response.event(){
                    Event::IndexEntry{file_id,filename}=>{
                        // Observe first, then classify/output. Reading IndexEnd
                        // remains allowed after exactly N entries: only entry
                        // N+1 triggers this bound and is never silently discarded.
                        report.observed+=1;
                        if report.observed>maximum{report.reason="record_limit";operation=Some(Cause::Capacity);break;}
                        if filename.len()>65535{report.reason="filename_bound";operation=Some(Cause::FilenameBound);break;}
                        report.row_in_progress=true;
                        match row(out,report.observed,&file_id,filename){
                            Ok(())=>{report.row_in_progress=false;report.emitted+=1;}
                            Err(e)=>{report.reason="output_failure";output=Some(e);break;}
                        }
                    }
                    Event::IndexEnd=>{report.index_end=true;report.reason="index_end";break;}
                    _=>{report.reason="unexpected_event";operation=Some(Cause::UnexpectedEvent);break;}
                },
                ipc::Step::Retry{cause,..}=>{
                    if report.attached || client.failure().is_some(){report.reason="source_lost";operation=Some(Cause::Native(cause));break;}
                    report.initial_retries=report.initial_retries.saturating_add(1);
                    if report.initial_retry.is_none(){report.initial_retry=Some(cause);}
                }
                ipc::Step::Unavailable(e)=>{report.reason="source_unavailable";operation=Some(Cause::Native(e));break;}
                ipc::Step::Finished=>{report.reason="missing_index_end";operation=Some(Cause::Finished);break;}
                _=>{},
            }
            tokio::task::yield_now().await;
        }
        // A source error/partial list never starts another Client or splices
        // rows from a replacement epoch. Retire the same actual owner without
        // sampling a failed/expired clock; retain its independent original error.
        let cause=match &operation {
            Some(Cause::Native(ipc::Error::Protocol(cause)))=>*cause,
            Some(Cause::NativeDeadline)=>Fault::Deadline,
            Some(Cause::Stop)=>Fault::Cancelled,
            Some(Cause::Capacity)=>Fault::Capacity,
            Some(Cause::UnexpectedEvent | Cause::FilenameBound)=>Fault::Malformed,
            Some(Cause::SecondAttachment)=>Fault::Stale,
            Some(Cause::Finished)=>Fault::Closed,
            Some(Cause::Native(_) | Cause::Signal(_))=>Fault::Io,
            None if output.is_some()=>Fault::Io,
            None=>Fault::Cancelled,
        };
        let close=client.abort_with_cause(cause).err();
        report.retired=close.is_none();
        report.native_failure=client.failure();
        drop(client);report.owner_dropped=true;
        let summary=json!({"event":"fs_index_list_stopped","reason":report.reason,
            "index_end_observed":report.index_end,"complete":report.index_end,"partial":!report.index_end,
            "observed_records":report.observed,"emitted_records":report.emitted,"max_records":report.maximum,
            "row_output_in_progress":report.row_in_progress,"output_rows_complete":report.emitted==report.observed && !report.row_in_progress,
            "source_attached":report.attached,"initial_retries":report.initial_retries,"initial_retry":report.initial_retry.as_ref().map(ToString::to_string),
            "request_written_bytes":report.request_written_bytes,"request_wholewritten":report.request_wholewritten,
            "original_retirement_succeeded":report.retired,"original_owner_dropped":report.owner_dropped,
            "native_failure":report.native_failure.map(|failure|format!("{failure:?}")),
            "operation_error":operation.as_ref().map(ToString::to_string),"close_error":close.as_ref().map(ToString::to_string),
            "row_output_error":output.as_ref().map(ToString::to_string),
            "scope":"one original query/source; filename/hash observations are not authority to open a path"});
        let terminal_output=(||->io::Result<()>{serde_json::to_writer(&mut *out,&summary).map_err(io::Error::other)?;writeln!(out)?;out.flush()})().err();
        if !report.index_end || operation.is_some() || close.is_some() || output.is_some() || terminal_output.is_some(){
            return Err(Box::new(Failure{report,operation,close,output,terminal_output}) as Box<dyn Error>);
        }
        Ok(())
    })
}
