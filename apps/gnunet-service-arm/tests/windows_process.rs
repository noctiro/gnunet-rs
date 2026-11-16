//! Normal native ARM SERVICE, official IPC, managed children and final resource records.
#[cfg(windows)]
mod windows {
    use gnunet_arm_core::wire::{
        ArmAbi, List, Request, ResultCode, ResultReply, ServiceStatus, WireId,
    };
    use gnunet_native::process::{Console, LaunchLimits, Stdio};
    use gnunet_service_runtime::process::{ChildRegistry, OriginalChild};
    use gnunet_service_startup::{
        CapturedStartup, ParentRole, ReadyStatus, StopSignals, capture_from_environment, launch,
    };
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use std::{
        error::Error,
        ffi::{OsStr, OsString},
        fs,
        future::poll_fn,
        io,
        net::{Ipv4Addr, SocketAddrV4},
        os::windows::io::{AsHandle, AsSocket},
        path::{Path, PathBuf},
        time::Duration,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    type Failure = Box<dyn Error>;
    const ROLE: &str = "GNUNET_ARM_SERVICE_FIXTURE";
    fn check(condition: bool, message: &'static str) -> io::Result<()> {
        if condition {
            Ok(())
        } else {
            Err(io::Error::other(message))
        }
    }
    struct Directory(PathBuf);
    impl Directory {
        fn new() -> io::Result<Self> {
            let mut nonce = [0; 16];
            gnunet_native::entropy::fill(&mut nonce)?;
            let parent = std::env::temp_dir();
            let name = format!("gn-arm-service-{:032x}", u128::from_be_bytes(nonce));
            gnunet_native::filesystem::Directory::open(&parent)?
                .create_private_directory(OsStr::new(&name))?;
            let directory = parent.join(name);
            fs::create_dir(directory.join("config.d"))?;
            Ok(Self(directory))
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _cleanup = fs::remove_dir_all(&self.0);
        }
    }
    struct Children {
        registry: ChildRegistry,
        original: Option<OriginalChild>,
    }
    impl Drop for Children {
        fn drop(&mut self) {
            if let Some(original) = &self.original
                && self.registry.owns(original)
            {
                let _cleanup = self.registry.terminate(original, 0xffff_ff03);
            }
        }
    }
    #[derive(Clone, Copy)]
    enum ConsoleMode {
        Foreground,
        DetachManaged,
    }
    async fn fixture(captured: CapturedStartup) -> Result<(), Failure> {
        check(
            captured.activation.is_none(),
            "managed helper received unrelated listener exports",
        )?;
        let mut parent = captured
            .parent_control
            .ok_or("managed helper lost supervisor")?
            .register()?;
        fs::write("managed-resource-payload", [7; 512])?;
        parent.ready.signal(ReadyStatus::AcceptRegistered).await?;
        let mut stop = StopSignals::new(Some(parent.control))?;
        poll_fn(|cx| stop.poll_stop(cx)).await?;
        fs::write("managed-cooperative-stop", b"actual control")?;
        Ok(())
    }
    fn encoded(request: Request<'_>) -> Result<Vec<u8>, Failure> {
        let mut bytes = vec![0; request.encoded_len()?];
        request.encode(&mut bytes)?;
        Ok(bytes)
    }
    async fn frame(stream: &mut tokio::net::TcpStream) -> io::Result<Vec<u8>> {
        let mut header = [0; 4];
        stream.read_exact(&mut header).await?;
        let bytes = usize::from(u16::from_be_bytes([header[0], header[1]]));
        if bytes < 4 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut frame = vec![0; bytes];
        frame[..4].copy_from_slice(&header);
        stream.read_exact(&mut frame[4..]).await?;
        Ok(frame)
    }
    async fn parent(mode: ConsoleMode) -> Result<(), Failure> {
        let directory = Directory::new()?;
        let listener = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
        listener.bind(&SockAddr::from(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))?;
        listener.listen(5)?;
        let address = listener
            .local_addr()?
            .as_socket()
            .ok_or("missing native TCP address")?;
        let config = directory.0.join("arm.conf");
        let usage = directory.0.join("resources");
        fs::write(
            &config,
            format!(
                "[arm]\nSTART_USER_SERVICES = YES\nSTART_SYSTEM_SERVICES = NO\nHOSTNAME = 127.0.0.1\nPORT = {}\nRESOURCE_DIAGNOSTICS = {}\n[native]\nTYPE = SIMPLE\nPREFIX = {}\nBINARY = gnunet-arm-resource-child\nRUN_PER_USER = YES\nIMMEDIATE_START = YES\nPIPECONTROL = YES\n[arm-rust]\nABI = align8\nMAX_SERVICES = 8\nMAX_CHILDREN = 2\n",
                address.port(),
                usage.display(),
                std::env::current_exe()?.display()
            ),
        )?;
        let stdout = fs::File::create(directory.0.join("stdout"))?;
        let stderr = fs::File::create(directory.0.join("stderr"))?;
        let mut environment: Vec<_> = std::env::vars_os().collect();
        environment.extend([
            (
                "GNUNET_BASE_CONFIG".into(),
                directory.0.join("config.d").into_os_string(),
            ),
            (ROLE.into(), "child".into()),
        ]);
        let mut arguments = vec![OsString::from("-c"), config.into_os_string()];
        if matches!(mode, ConsoleMode::DetachManaged) {
            arguments.push("-d".into());
        }
        let mut children = Children {
            registry: ChildRegistry::new(1)?,
            original: None,
        };
        let mut bootstrap = match launch::launch(
            &mut children.registry,
            launch::Command {
                executable: Path::new(env!("CARGO_BIN_EXE_gnunet-service-arm")),
                argv0: OsStr::new("gnunet-service-arm"),
                arguments: &arguments,
                environment,
                directory: &directory.0,
                stdio: [
                    Stdio::Null,
                    Stdio::Handle(stdout.as_handle()),
                    Stdio::Handle(stderr.as_handle()),
                ],
                console: Console::Inherit,
                role: ParentRole::Supervisor,
                listeners: &[listener.as_socket()],
            },
            LaunchLimits::default(),
        ) {
            Ok(parent) => {
                children.original = Some(parent.child().clone());
                parent
            }
            Err(error) => {
                children.original = error.child.clone();
                return Err(error.into());
            }
        };
        let ready = bootstrap.wait().await?;
        check(
            ready.child() == bootstrap.child(),
            "normal service readiness changed process identity",
        )?;
        let mut peer = tokio::net::TcpStream::connect(address).await?;
        peer.write_all(&encoded(Request::Test)?).await?;
        check(
            frame(&mut peer).await? == encoded(Request::Test)?,
            "normal service changed official ARM TEST bytes",
        )?;
        peer.write_all(&encoded(Request::List {
            reserved: 0,
            id: WireId(91),
        })?)
        .await?;
        let listing = frame(&mut peer).await?;
        let listing = List::decode(ArmAbi::U64Align8, &listing)?;
        let row = listing
            .get(0)?
            .ok_or("normal ARM lost its managed service")?;
        check(
            listing.id()? == WireId(91)
                && listing.len() == 1
                && row.name == b"native"
                && row.status == ServiceStatus::STARTED,
            "normal ARM LIST changed configured native admission",
        )?;
        while !directory.0.join("managed-resource-payload").exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        peer.write_all(&encoded(Request::Stop {
            reserved: 0,
            id: WireId(92),
            service: b"arm",
        })?)
        .await?;
        let stopped = ResultReply::decode(ArmAbi::U64Align8, &frame(&mut peer).await?)?;
        check(
            stopped.id == WireId(92) && stopped.result == ResultCode::STOPPING,
            "ARM self-stop did not acknowledge STOPPING",
        )?;
        let mut byte = [0];
        check(
            peer.read(&mut byte).await? == 0,
            "ARM self-stop requester did not reach final EOF",
        )?;
        loop {
            children.registry.reap_completed()?;
            if let Some(exit) = children.registry.take_reaped() {
                check(
                    exit.child == *bootstrap.child() && exit.exit_code == 0,
                    "normal ARM original process failed or was replaced",
                )?;
                break;
            }
            poll_fn(|cx| children.registry.poll_child_signal(cx)).await?;
        }
        check(
            directory.0.join("managed-cooperative-stop").is_file(),
            "normal ARM replaced cooperative child stop with forced termination",
        )?;
        let record = fs::read_to_string(usage)?;
        check(
            record.lines().count() == 1
                && record.starts_with("gnunet-arm-resource-child(")
                && record.contains("platform=windows")
                && record.contains("user-cpu-us=")
                && record.contains("kernel-cpu-us="),
            "normal ARM lost its actual native resource receipt",
        )?;
        let written = record
            .split_whitespace()
            .find_map(|field| field.strip_prefix("write-bytes="))
            .ok_or("missing original I/O transfer observation")?
            .parse::<u64>()?;
        check(
            written >= 512,
            "native resource accounting substituted an empty write counter",
        )?;
        check(
            fs::read(directory.0.join("stdout"))?.is_empty(),
            "normal ARM emitted internal debug status to stdout",
        )?;
        Ok(())
    }
    pub fn run() -> Result<(), Failure> {
        let fixture_role = std::env::var_os(ROLE).is_some();
        #[expect(
            unsafe_code,
            reason = "Fresh fixture process captures exclusive inherited startup declarations before runtime, native handles or competing owners"
        )]
        let captured = if fixture_role {
            // SAFETY: this is the first child ownership action after native exec.
            Some(unsafe { capture_from_environment() }?)
        } else {
            None
        };
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                tokio::time::timeout(Duration::from_secs(30), async {
                    if let Some(captured) = captured {
                        fixture(captured).await
                    } else {
                        parent(ConsoleMode::Foreground).await?;
                        parent(ConsoleMode::DetachManaged).await
                    }
                })
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
