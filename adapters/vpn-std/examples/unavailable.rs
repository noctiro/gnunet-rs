//! Real IPC SERVICE without a configured TUN, for C public-API interoperability.
//! It returns actual allocation failure; no lease or forwarding success is faked.
#![cfg(unix)]
use gnunet_service_runtime::{
    clock::{RuntimeClock, SystemClock},
    credentials::UnixAccess,
    service::{Listener, ServiceOptions},
};
use gnunet_vpn::{
    ClientSlot, Engine, FlowSlot, Instance, LeaseSlot, PacketSlot, RequestSlot, Storage,
};
use gnunet_vpn_host::server::Server;
use std::{
    error::Error,
    future::poll_fn,
    io::{self, Write},
    os::unix::fs::MetadataExt,
    path::PathBuf,
    sync::Arc,
    task::Poll,
};
use tokio::{
    net::UnixListener,
    signal::unix::{SignalKind, signal},
};
type Failure = Box<dyn Error>;
struct SocketPath {
    path: PathBuf,
    dev: u64,
    ino: u64,
}
impl Drop for SocketPath {
    fn drop(&mut self) {
        if let Ok(metadata) = std::fs::symlink_metadata(&self.path)
            && metadata.dev() == self.dev
            && metadata.ino() == self.ino
        {
            let _cleanup = std::fs::remove_file(&self.path);
        }
    }
}
fn main() -> Result<(), Failure> {
    let mut args = std::env::args_os().skip(1);
    let path = PathBuf::from(
        args.next()
            .ok_or("expected one owned new Unix socket path")?,
    );
    if args.next().is_some() {
        return Err("expected one owned new Unix socket path".into());
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let listener = UnixListener::bind(&path)?;
            let metadata = std::fs::symlink_metadata(&path)?;
            let _owned_path = SocketPath {
                path,
                dev: metadata.dev(),
                ino: metadata.ino(),
            };
            let listeners = [Listener::Unix(&listener)];
            let mut interrupt = signal(SignalKind::interrupt())?;
            let mut terminate = signal(SignalKind::terminate())?;
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
                    match_uid: true,
                    match_gid: false,
                },
            )?;
            writeln!(
                io::stdout().lock(),
                "READY vpn-ipc wire=0.29.1 tun=absent allocation=unavailable"
            )?;
            io::stdout().lock().flush()?;
            let result = poll_fn(|cx| {
                if interrupt.poll_recv(cx).is_ready() || terminate.poll_recv(cx).is_ready() {
                    return Poll::Ready(Ok::<(), Failure>(()));
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
