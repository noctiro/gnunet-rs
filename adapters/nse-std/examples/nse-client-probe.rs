//! Typed Rust NSE subscriber to an actual service, using common original framing.
use gnunet_client::nse::{Client, Instance};
use gnunet_client_host::Endpoint;
use gnunet_service_runtime::framing::{
    Accounting, Budget, Class, Framed, Limits, OwnedFrame, ReadStep,
};
use std::{
    error::Error,
    future::poll_fn,
    io::{self, Write},
    path::PathBuf,
    time::Duration,
};
fn main() -> Result<(), Box<dyn Error>> {
    let path = PathBuf::from(std::env::args_os().nth(1).ok_or("socket path")?);
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async{
        let socket=tokio::time::timeout(Duration::from_secs(5),Endpoint::unix(path)?.attempt(0)).await??;
        let mut framed=Framed::new(socket,Limits{frame_bytes:65535,ordinary:Budget{frames:1,bytes:65535},reserved:Budget::default(),accounting:Accounting::Retained,io_slice_bytes:3})?;
        let mut instance=Instance::new();let mut client=Client::new(&mut instance);let epoch=client.begin_connection()?;let start=client.prepare_start(epoch)?;
        framed.enqueue_owned(OwnedFrame::copy_from(start.bytes())?,epoch,Class::Ordinary).map_err(|r|r.reason)?;
        loop{let progress=tokio::time::timeout(Duration::from_secs(5),poll_fn(|cx|framed.poll_write(cx))).await??;if progress.origin!=epoch{return Err("wrong original START epoch".into());}
        if progress.complete{client.written(&start)?;break;}}
        loop{match tokio::time::timeout(Duration::from_secs(5),poll_fn(|cx|framed.poll_read(cx))).await??{
            ReadStep::Eof=>return Err("EOF before actual NSE estimate".into()),ReadStep::Progress{complete:false,..}=>{},ReadStep::Progress{complete:true,..}=>{
                let bytes=framed.frame().ok_or("missing estimate frame")?;let observation=client.receive(epoch,bytes)?.ok_or("not an estimate")?;
                let raw:String=bytes.iter().map(|b|format!("{b:02x}")).collect();
                writeln!(io::stdout().lock(),"{{\"kind\":\"Rust-native-NSE-subscriber\",\"epoch\":{},\"timestamp\":{},\"log2_bits\":\"{:016x}\",\"deviation_bits\":\"{:016x}\",\"hex\":\"{raw}\"}}",epoch.value(),observation.estimate.timestamp.as_micros(),observation.estimate.log2_size.bits(),observation.estimate.deviation.bits())?;
                if !framed.release_frame(){return Err("frame was not retained".into());}framed.retire();client.close();return Ok::<_,Box<dyn Error>>(());
            }
        }}
    })
}
