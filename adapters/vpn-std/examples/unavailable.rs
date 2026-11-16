//! Real IPC SERVICE without a configured TUN, for C public-API interoperability.
//! It returns actual allocation failure; no lease or forwarding success is faked.
use gnunet_service_runtime::{
    BoundListeners, LocalListenerAccess,
    clock::{RuntimeClock, SystemClock},
    credentials::UnixAccess,
    service::ServiceOptions,
    signals::Termination,
};
use gnunet_vpn::{
    ClientSlot, Engine, FlowSlot, Instance, LeaseSlot, PacketSlot, RequestSlot, Storage,
};
use gnunet_vpn_host::server::Server;
use std::{
    error::Error,
    future::poll_fn,
    io::{self, Write},
    path::PathBuf,
    sync::Arc,
    task::Poll,
};
type Failure = Box<dyn Error>;
fn main() -> Result<(), Failure> {
    let mut args = std::env::args_os().skip(1);
    let path = PathBuf::from(
        args.next()
            .ok_or("expected one owned new native local socket path")?,
    );
    if args.next().is_some() {
        return Err("expected one owned new native local socket path".into());
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let bound = BoundListeners::bind_local(path, LocalListenerAccess::Owner).await?;
            for warning in bound.failures() {
                writeln!(io::stderr().lock(), "local endpoint preparation: {warning}")?;
            }
            let listeners = bound.listeners();
            let mut termination = Termination::new()?;
            let mut instance = Instance::new();
            let mut clients = [ClientSlot::new(); 8];
            let mut requests = [RequestSlot::new(); 32];
            let mut leases = [LeaseSlot::new(); 1];
            let mut flows = [FlowSlot::new(); 1];
            let mut bytes = [0; 1284];
            let mut packets = [PacketSlot::new(&mut bytes)];
            let core = Engine::new(
                &mut instance,
                Storage {
                    clients: &mut clients,
                    requests: &mut requests,
                    leases: &mut leases,
                    flows: &mut flows,
                    packets: &mut packets,
                },
                gnunet_vpn::Limits {
                    packet_bytes: 1280,
                    ..Default::default()
                },
            )?;
            let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
            let mut service = Server::new(
                core,
                clock,
                gnunet_vpn_host::server::Limits {
                    clients: 8,
                    ..Default::default()
                },
                ServiceOptions::default(),
                UnixAccess {
                    match_uid: cfg!(unix),
                    match_gid: false,
                },
            )?;
            writeln!(
                io::stdout().lock(),
                "READY vpn-ipc wire=0.29.1 tun=absent allocation=unavailable"
            )?;
            io::stdout().lock().flush()?;
            let result = poll_fn(|cx| {
                match termination.poll_stop(cx) {
                    Poll::Ready(result) => return Poll::Ready(result.map_err(Failure::from)),
                    Poll::Pending => {}
                }
                match service.poll(cx, &listeners, None, &mut |_| {}) {
                    Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
                    Poll::Ready(Ok(_)) => {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Poll::Pending => Poll::Pending,
                }
            })
            .await;
            let closed = service.shutdown(|_| {});
            writeln!(
                io::stdout().lock(),
                "STOPPED vpn-ipc report={:?} quiescent={} cleanup={:?}",
                closed.report,
                service.ipc_quiescent(),
                closed.failure
            )?;
            io::stdout().lock().flush()?;
            result?;
            if let Some(error) = closed.failure {
                return Err(error.into());
            }
            if !service.ipc_quiescent() {
                return Err("original IPC debt remains".into());
            }
            Ok(())
        })
}
