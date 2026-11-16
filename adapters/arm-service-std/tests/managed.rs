//! Shared native listener leases and actual private backlog bytes, without a child process.
#![cfg(any(unix, windows))]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assert native queue and pure lease facts while propagating real setup and I/O failures"
)]
use gnunet_arm_core::wire::ArmAbi;
use gnunet_arm_service_core::{ListenerSlot, Owner, OwnerScope, ServiceSlot, ServiceSpec};
use gnunet_arm_service_host::{
    addresses::Address,
    listeners::{BindOutcome, ManagedListeners},
};
use gnunet_service_runtime::{LocalListenerAccess, connection::Connection, local};
use socket2::{SockRef, Socket};
use std::{io, net::Ipv4Addr, path::PathBuf, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
type Result = std::result::Result<(), Box<dyn std::error::Error>>;

struct Directory(PathBuf);
impl Directory {
    fn create() -> io::Result<Self> {
        let mut nonce = [0; 16];
        gnunet_native::entropy::fill(&mut nonce)?;
        let parent = std::env::temp_dir();
        let name = format!("gn-arm-managed-{:032x}", u128::from_be_bytes(nonce));
        gnunet_native::filesystem::Directory::open(&parent)?
            .create_private_directory(std::ffi::OsStr::new(&name))?;
        Ok(Self(parent.join(name)))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_dir_all(&self.0);
    }
}
fn core<T>(result: std::result::Result<T, gnunet_arm_service_core::Error>) -> io::Result<T> {
    result.map_err(|error| io::Error::other(format!("core lease: {error:?}")))
}
fn accepted(socket: Socket, address: &Address) -> io::Result<Connection> {
    socket.set_nonblocking(true)?;
    match address {
        Address::Unix(_) => {
            #[cfg(unix)]
            let stream = local::Stream::from_std(socket.into())?;
            #[cfg(windows)]
            let stream = local::Stream::from_connected_socket(socket)?;
            Ok(Connection::from_unix(stream))
        }
        Address::Tcp(_) => Ok(Connection::from_tcp(tokio::net::TcpStream::from_std(
            socket.into(),
        )?)),
        Address::Abstract(_) => Err(io::ErrorKind::Unsupported.into()),
    }
}

#[test]
fn local_and_tcp_readiness_retain_the_same_lease_and_unconsumed_backlog() -> Result {
    let directory = Directory::create()?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            for address in [
                Address::Unix(directory.0.join("ipc")),
                Address::Tcp((Ipv4Addr::LOCALHOST, 0).into()),
            ] {
                let specs = [ServiceSpec {
                    name: b"one",
                    binary: b"fixture",
                    command: b"fixture",
                    immediate: false,
                    pipe_control: false,
                }];
                let mut scope = OwnerScope::new();
                let mut services = [ServiceSlot::new()];
                let mut listeners = [ListenerSlot::new()];
                let mut clients = [];
                let mut frames = [];
                let mut owner = core(Owner::new(
                    &mut scope,
                    &specs,
                    &mut services,
                    &mut clients,
                    &mut listeners,
                    &mut frames,
                    ArmAbi::U64Align8,
                ))?;
                let mut managed = ManagedListeners::new(1);
                assert!(matches!(
                    managed
                        .bind_address(0, address, LocalListenerAccess::Owner)
                        .await?,
                    BindOutcome::Bound { index: 0 }
                ));
                assert!(managed.failures().is_empty());
                managed.attach(&mut owner)?;
                while managed.apply_next(&mut owner)? {}
                assert!(!core(owner.startup_next())?);
                assert!(
                    tokio::time::timeout(Duration::from_millis(5), managed.next_event())
                        .await
                        .is_err()
                );
                let address = managed.address(0).ok_or("missing actual address")?.clone();
                let mut peer = match &address {
                    Address::Unix(path) => {
                        Connection::from_unix(local::Stream::connect(path).await?)
                    }
                    Address::Tcp(address) => {
                        Connection::from_tcp(tokio::net::TcpStream::connect(address).await?)
                    }
                    Address::Abstract(_) => return Err("unexpected abstract endpoint".into()),
                };
                peer.write_all(b"queue").await?;
                let first =
                    tokio::time::timeout(Duration::from_secs(2), managed.next_event()).await??;
                let second =
                    tokio::time::timeout(Duration::from_secs(2), managed.next_event()).await??;
                assert_eq!(first, second);
                assert!(first.readiness.readable);
                assert!(!first.readiness.error);
                assert!(managed.ordinary_ready()?);
                let id = managed.id(0).ok_or("missing attached listener")?;
                let original = managed.descriptor(id).ok_or("missing original socket")?;
                // Only this explicit operation consumes a connection. No child or
                // native-spawn receipt is fabricated by this listener-only witness.
                let (socket, _) = SockRef::from(&original).accept()?;
                let mut stream = accepted(socket, &address)?;
                let mut bytes = [0; 5];
                tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut bytes))
                    .await??;
                assert_eq!(&bytes, b"queue");
                drop(stream);
                drop(peer);
                drop(managed);
                if let Address::Unix(path) = address {
                    assert!(!path.exists());
                }
            }
            Ok(())
        })
}
