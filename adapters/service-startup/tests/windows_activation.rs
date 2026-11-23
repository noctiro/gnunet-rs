//! Original Windows listeners, queued connections and creator-owned local nodes.
#[cfg(windows)]
mod windows {
    use gnunet_native::local_path::{EndpointAccess, LocalPath};
    use gnunet_service_runtime::{
        Activation, BoundListeners,
        local::Stream,
        process::{ChildRegistry, Console, LaunchLimits, OriginalChild, RegistryError, Stdio},
        service::Listener,
    };
    use gnunet_service_startup::{
        CapturedStartup, ParentFailure, ParentRole, ReadyReceipt, ReadyStatus,
        capture_from_environment,
        daemon::{self, LaunchCause, Reexec},
        launch,
    };
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use std::{
        error::Error,
        ffi::OsStr,
        fs,
        future::{Future, poll_fn},
        io,
        net::{Ipv4Addr, Ipv6Addr, SocketAddr},
        os::windows::io::AsSocket,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
        task::{Context, Waker},
        time::{Duration, SystemTime, UNIX_EPOCH},
    };
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    type Failure = Box<dyn Error>;
    const ROLE: &str = "GNUNET_ACTIVATION_FIXTURE";
    const NODE: &str = "GNUNET_ACTIVATION_NODE";
    const PAYLOAD: &[u8] = b"original queued stream";

    fn check(value: bool, message: &'static str) -> io::Result<()> {
        if value {
            Ok(())
        } else {
            Err(io::Error::other(message))
        }
    }
    fn pending_once(future: impl Future) -> io::Result<()> {
        let mut future = std::pin::pin!(future);
        check(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending(),
            "startup completed before the queued stream was released",
        )
    }
    struct Directory(PathBuf);
    impl Directory {
        fn new() -> io::Result<Self> {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(io::Error::other)?
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "gn-act-{}-{nonce:x}-{:x}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path)?;
            Ok(Self(path))
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _cleanup = fs::remove_dir_all(&self.0);
        }
    }
    struct Children {
        registry: ChildRegistry,
        child: Option<OriginalChild>,
    }
    impl Drop for Children {
        fn drop(&mut self) {
            if let Some(child) = &self.child
                && self.registry.owns(child)
            {
                let _cleanup = self.registry.terminate(child, 0xdead_0003);
            }
        }
    }
    async fn send(stream: &mut (impl AsyncWrite + Unpin)) -> io::Result<()> {
        stream.write_all(PAYLOAD).await
    }
    async fn receive(stream: &mut (impl AsyncRead + Unpin)) -> io::Result<()> {
        let mut bytes = [0u8; PAYLOAD.len()];
        stream.read_exact(&mut bytes).await?;
        check(bytes == PAYLOAD, "queued payload changed")
    }
    async fn echo(stream: &mut (impl AsyncRead + AsyncWrite + Unpin)) -> io::Result<()> {
        receive(stream).await?;
        send(stream).await
    }
    async fn round(bound: &BoundListeners) -> io::Result<()> {
        for listener in bound.listeners() {
            match listener {
                Listener::Unix(listener) => echo(&mut listener.accept().await?.0).await?,
                Listener::Tcp(listener) => echo(&mut listener.accept().await?.0).await?,
            }
        }
        Ok(())
    }
    async fn child(captured: CapturedStartup, activation: Activation) -> Result<(), Failure> {
        check(activation.len() == 3, "native listener count/order changed")?;
        let path = PathBuf::from(std::env::var_os(NODE).ok_or("missing original node")?);
        let mut bound = BoundListeners::from_activation(activation)?;
        check(
            bound.unix_paths().next().is_none(),
            "recipient adopted creator cleanup",
        )?;
        let mut parent = captured
            .parent_control
            .ok_or("missing original parent")?
            .register()?;
        // These streams were queued before native process creation. Import and
        // reactor registration must preserve the existing accept queues.
        round(&bound).await?;
        parent.ready.signal(ReadyStatus::AcceptRegistered).await?;
        // The creator's listener copies are closed before this second round.
        round(&bound).await?;
        bound
            .close()
            .map_err(|errors| io::Error::other(format!("{errors:?}")))?;
        check(
            gnunet_native::local_path::is_socket(&path)?,
            "recipient removed creator node",
        )?;
        Ok(())
    }
    fn tcp(address: SocketAddr) -> io::Result<(Socket, SocketAddr)> {
        let socket = Socket::new(
            Domain::for_address(address),
            Type::STREAM,
            Some(Protocol::TCP),
        )?;
        gnunet_native::network::set_exclusive_address_use(socket.as_socket())?;
        if address.is_ipv6() {
            socket.set_only_v6(true)?;
        }
        socket.bind(&address.into())?;
        socket.listen(5)?;
        let address = socket
            .local_addr()?
            .as_socket()
            .ok_or(io::ErrorKind::InvalidData)?;
        Ok((socket, address))
    }
    fn launch_refusal_retains_sources(executable: &Path) -> Result<(), Failure> {
        let directory = Directory::new()?;
        let (socket, address) = tcp((Ipv4Addr::LOCALHOST, 0).into())?;
        let activation = Activation::from_sockets(vec![socket])?;
        let mut children = Children {
            registry: ChildRegistry::new(1)?,
            child: None,
        };
        let outcome = daemon::launch(
            &mut children.registry,
            Reexec {
                executable,
                argv0: OsStr::new("gnunet-activation-refusal"),
                arguments: &[],
                environment: std::env::vars_os().collect(),
                directory: &directory.0,
                stderr: Stdio::Null,
                activation,
            },
            LaunchLimits {
                handles: 3,
                ..LaunchLimits::default()
            },
        );
        let failure = match outcome {
            Ok(parent) => {
                children.child = Some(parent.child().clone());
                return Err("native handle budget admitted an unexpected child".into());
            }
            Err(failure) => {
                children.child = failure.child.clone();
                failure
            }
        };
        check(
            failure.child.is_none() && children.registry.pending_children() == 0,
            "refused native admission installed a child record",
        )?;
        check(
            matches!(&failure.cause,
            LaunchCause::Registry(RegistryError::Native(error))
                if error.kind() == io::ErrorKind::InvalidInput),
            "native handle-budget failure lost its original cause",
        )?;
        // Retained native cleanup owners remain usable in ordinary Send/Sync
        // error channels without weakening source lifetime.
        let failure: Box<dyn Error + Send + Sync> = Box::new(failure);
        check(
            std::net::TcpListener::bind(address).is_err(),
            "failure discarded the original source listener",
        )?;
        drop(failure);
        drop(std::net::TcpListener::bind(address)?);
        Ok(())
    }
    enum Startup {
        Detached(daemon::Parent),
        Supervised(launch::Parent),
    }
    impl Startup {
        fn child(&self) -> &OriginalChild {
            match self {
                Self::Detached(parent) => parent.child(),
                Self::Supervised(parent) => parent.child(),
            }
        }
        async fn wait(&mut self) -> Result<ReadyReceipt, ParentFailure> {
            match self {
                Self::Detached(parent) => parent.wait().await,
                Self::Supervised(parent) => poll_fn(|cx| parent.poll_ready(cx)).await,
            }
        }
    }
    async fn parent(executable: &Path, role: ParentRole) -> Result<(), Failure> {
        let directory = Directory::new()?;
        let path = directory.0.join("ipc");
        let local = Socket::new(Domain::UNIX, Type::STREAM, None)?;
        local.bind(&SockAddr::unix(&path)?)?;
        let mut node = LocalPath::capture(path.clone())?;
        node.set_access(EndpointAccess::Owner)?;
        local.listen(5)?;
        let (ipv4, address4) = tcp((Ipv4Addr::LOCALHOST, 0).into())?;
        let (ipv6, address6) = tcp((Ipv6Addr::LOCALHOST, 0).into())?;
        // Only clients enter the reactor here; all original listeners remain
        // unregistered and quiescent until native provider publication.
        let mut queued_local = Stream::connect(&path).await?;
        let mut queued4 = tokio::net::TcpStream::connect(address4).await?;
        let mut queued6 = tokio::net::TcpStream::connect(address6).await?;
        send(&mut queued4).await?;
        send(&mut queued6).await?;
        let mut activation = Activation::from_sockets(vec![local, ipv4, ipv6])?;
        let mut environment: Vec<_> = std::env::vars_os()
            .filter(|(key, _)| {
                !key.to_str().is_some_and(|key| {
                    key.eq_ignore_ascii_case("LISTEN_FDS")
                        || key.eq_ignore_ascii_case("LISTEN_FDNAMES")
                })
            })
            .collect();
        environment.push((ROLE.into(), "child".into()));
        environment.push((NODE.into(), path.as_os_str().into()));
        let mut children = Children {
            registry: ChildRegistry::new(1)?,
            child: None,
        };
        let mut bootstrap = match role {
            ParentRole::Supervisor => {
                let sockets: Vec<_> = activation
                    .sockets()
                    .iter()
                    .map(gnunet_service_runtime::ActivatedSocket::launch_source)
                    .collect();
                match launch::launch(
                    &mut children.registry,
                    launch::Command {
                        executable,
                        argv0: OsStr::new("gnunet-activation-fixture"),
                        arguments: &[],
                        environment,
                        directory: &directory.0,
                        stdio: [Stdio::Null, Stdio::Null, Stdio::Inherit],
                        console: Console::Inherit,
                        role,
                        listeners: &sockets,
                    },
                    LaunchLimits::default(),
                ) {
                    Ok(parent) => {
                        children.child = Some(parent.child().clone());
                        Startup::Supervised(parent)
                    }
                    Err(error) => {
                        children.child = error.child.clone();
                        return Err(error.into());
                    }
                }
            }
            ParentRole::DetachLauncher => {
                match daemon::launch(
                    &mut children.registry,
                    Reexec {
                        executable,
                        argv0: OsStr::new("gnunet-activation-fixture"),
                        arguments: &[],
                        environment,
                        directory: &directory.0,
                        stderr: Stdio::Inherit,
                        activation: std::mem::take(&mut activation),
                    },
                    LaunchLimits::default(),
                ) {
                    Ok(parent) => {
                        children.child = Some(parent.child().clone());
                        Startup::Detached(parent)
                    }
                    Err(error) => {
                        children.child = error.child.clone();
                        return Err(error.into());
                    }
                }
            }
        };
        // Child cannot report ready until its first queued stream receives data.
        // Cancel the real wait once; its original bootstrap and source owners
        // must survive until this same startup is driven again.
        pending_once(bootstrap.wait())?;
        send(&mut queued_local).await?;
        // Actual ready receipt releases source copies only after child import.
        // Node ownership stays here until the original child is physically reaped.
        bootstrap.wait().await?;
        // Borrowed supervisor sources release only after actual qualified import.
        // The creator pathname lease remains here through the original reap.
        drop(activation);
        receive(&mut queued_local).await?;
        receive(&mut queued4).await?;
        receive(&mut queued6).await?;
        let mut fresh_local = Stream::connect(&path).await?;
        let mut fresh4 = tokio::net::TcpStream::connect(address4).await?;
        let mut fresh6 = tokio::net::TcpStream::connect(address6).await?;
        send(&mut fresh_local).await?;
        send(&mut fresh4).await?;
        send(&mut fresh6).await?;
        receive(&mut fresh_local).await?;
        receive(&mut fresh4).await?;
        receive(&mut fresh6).await?;
        loop {
            children.registry.reap_completed()?;
            if let Some(receipt) = children.registry.take_reaped() {
                check(
                    receipt.child == *bootstrap.child() && receipt.exit_code == 0,
                    "original activation child failed or was replaced",
                )?;
                break;
            }
            poll_fn(|cx| children.registry.poll_child_signal(cx)).await?;
        }
        check(
            gnunet_native::local_path::is_socket(&path)?,
            "original node was unlinked",
        )?;
        node.remove()?;
        Ok(())
    }
    pub fn run() -> Result<(), Failure> {
        let role = std::env::var_os(ROLE);
        #[expect(
            unsafe_code,
            reason = "Fresh child before files/runtime/foreign owners; parent publishes an exclusively inherited read-only section before resuming it"
        )]
        let captured = role
            .as_ref()
            .map(|_| {
                // SAFETY: exclusive fresh-process startup and immutable publication.
                unsafe { capture_from_environment() }
            })
            .transpose()?;
        let (captured, activation) = match captured {
            Some(mut captured) => {
                let incoming = captured
                    .activation
                    .take()
                    .ok_or("missing native activation")?;
                let activation = Activation::from_imported(incoming.materialize()?)?;
                (Some(captured), activation)
            }
            None => (None, Activation::default()),
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let work = async {
                match captured {
                    Some(captured) => child(captured, activation).await,
                    None => {
                        let executable = std::env::current_exe()?;
                        launch_refusal_retains_sources(&executable)?;
                        parent(&executable, ParentRole::Supervisor).await?;
                        parent(&executable, ParentRole::DetachLauncher).await
                    }
                }
            };
            tokio::time::timeout(Duration::from_secs(30), work)
                .await
                .map_err(io::Error::other)?
        })
    }
}
#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    windows::run()
}
#[cfg(not(windows))]
fn main() {}
