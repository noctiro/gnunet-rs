//! Normal Windows detached children over the shared original-process bootstrap.
#[cfg(windows)]
mod windows {
    use gnunet_native::pipe::Endpoint;
    use gnunet_service_runtime::{
        pipe::{PipeConnection, PipeListener},
        process::{ChildRegistry, Console, LaunchLimits, OriginalChild, Stdio},
    };
    use gnunet_service_startup::{
        CapturedStartup, ParentFailure, ParentRole, ReadyReceipt, ReadyStatus,
        capture_from_environment,
        daemon::{self, Reexec},
        launch,
    };
    use std::{
        error::Error,
        ffi::{OsStr, OsString},
        fs,
        future::poll_fn,
        io::{self, Read, Write},
        os::windows::io::AsHandle,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
        time::{Duration, SystemTime, UNIX_EPOCH},
    };
    type Failure = Box<dyn Error>;
    const ROLE: &str = "GNUNET_DETACH_FIXTURE";
    const GATE: &str = "GNUNET_DETACH_GATE";
    fn check(value: bool, message: &'static str) -> io::Result<()> {
        if value {
            Ok(())
        } else {
            Err(io::Error::other(message))
        }
    }
    fn arguments() -> Vec<OsString> {
        vec!["--daemonize".into(), "literal $X %PATH%".into(), "".into()]
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
                "gn-detach-{}-{nonce:x}-{:x}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path)?;
            let directory = Self(path);
            fs::write(
                directory.0.join("cwd-marker"),
                b"detached working directory",
            )?;
            Ok(directory)
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
    async fn child(role: &OsStr, captured: CapturedStartup) -> Result<(), Failure> {
        check(
            std::env::var_os("GNUNET_OS_CONTROL_PIPE").is_none()
                && std::env::var_os("GNUNET_RS_DETACH_PIPE").is_none(),
            "detach bootstrap hints remained",
        )?;
        let control = captured.parent_control.ok_or("missing detach launcher")?;
        check(
            control.role()
                == if role == "managed" {
                    ParentRole::Supervisor
                } else {
                    ParentRole::DetachLauncher
                },
            "detach origin was lost",
        )?;
        check(
            std::env::args_os().next().as_deref() == Some(OsStr::new("gnunet-detach-fixture")),
            "explicit argv0 changed",
        )?;
        check(
            std::env::args_os().skip(1).collect::<Vec<_>>() == arguments(),
            "original arguments changed",
        )?;
        check(
            fs::read("cwd-marker")? == b"detached working directory",
            "working directory changed",
        )?;
        let mut byte = [0];
        check(
            io::stdin().read(&mut byte)? == 0,
            "detached stdin was not EOF",
        )?;
        io::stdout().write_all(b"detached stdout\n")?;
        io::stderr().write_all(b"detached stderr\n")?;
        if role == "exit" {
            return Ok(());
        }
        let mut parent = control.register()?;
        let status = if role == "failure" {
            ReadyStatus::InitializationFailed
        } else {
            ReadyStatus::AcceptRegistered
        };
        parent.ready.signal(status).await?;
        drop(parent.ready);
        let signal = poll_fn(|cx| parent.control.poll_signal(cx)).await?;
        check(
            signal == if role == "managed" { Some(15) } else { None },
            "original supervisor control or one-shot EOF changed",
        )?;
        if role == "failure" {
            return Ok(());
        }
        // The launcher owner is gone. The child must still reach and use a new
        // original qualified connection instead of treating that EOF as shutdown.
        let endpoint = Endpoint::parse(std::env::var_os(GATE).ok_or("missing private gate")?)?;
        let (mut reader, mut writer) = PipeConnection::connect(&endpoint)?.split();
        writer.begin(42)?;
        poll_fn(|cx| writer.poll_send(cx)).await?;
        check(
            poll_fn(|cx| reader.poll_byte(cx)).await? == Some(15),
            "detached child did not receive its explicit stop",
        )?;
        Ok(())
    }
    async fn reap(children: &mut Children, child: &OriginalChild) -> Result<(), Failure> {
        loop {
            children.registry.reap_completed()?;
            if let Some(receipt) = children.registry.take_reaped() {
                check(
                    receipt.child == *child && receipt.exit_code == 0,
                    "detached child exit changed",
                )?;
                return Ok(());
            }
            poll_fn(|cx| children.registry.poll_child_signal(cx)).await?;
        }
    }
    enum Startup {
        Reexec(daemon::Parent),
        Managed(launch::Parent),
    }
    impl Startup {
        fn child(&self) -> &OriginalChild {
            match self {
                Self::Reexec(parent) => parent.child(),
                Self::Managed(parent) => parent.child(),
            }
        }
        async fn wait(&mut self) -> Result<ReadyReceipt, ParentFailure> {
            match self {
                Self::Reexec(parent) => parent.wait().await,
                Self::Managed(parent) => parent.wait().await,
            }
        }
    }
    async fn parent(executable: &Path, role: &str) -> Result<(), Failure> {
        let directory = Directory::new()?;
        let stderr_path = directory.0.join("stderr.log");
        let stderr = fs::File::create(&stderr_path)?;
        let mut gate = PipeListener::bind()?;
        let mut environment: Vec<_> = std::env::vars_os()
            .filter(|(key, _)| {
                !key.to_str().is_some_and(|key| {
                    key.eq_ignore_ascii_case("LISTEN_FDS")
                        || key.eq_ignore_ascii_case("LISTEN_FDNAMES")
                })
            })
            .collect();
        environment.push((ROLE.into(), role.into()));
        environment.push((GATE.into(), gate.endpoint().as_os_str().into()));
        // Generated detach hints must override old explicit values using native
        // case-insensitive environment-name ordering, without global mutation.
        environment.push(("gnunet_os_control_pipe".into(), "stale endpoint".into()));
        environment.push(("gnunet_rs_detach_pipe".into(), "stale marker".into()));
        environment.push(("gnunet_rs_activation_handle".into(), "invalid".into()));
        environment.push(("listen_fds".into(), "3".into()));
        environment.push(("listen_fdnames".into(), "foreign descriptors".into()));
        let mut children = Children {
            registry: ChildRegistry::new(1)?,
            child: None,
        };
        let mut parent = if role == "managed" {
            let parent = match launch::launch(
                &mut children.registry,
                launch::Command {
                    executable,
                    argv0: OsStr::new("gnunet-detach-fixture"),
                    arguments: &arguments(),
                    environment,
                    directory: &directory.0,
                    stdio: [Stdio::Null, Stdio::Null, Stdio::Handle(stderr.as_handle())],
                    console: Console::Inherit,
                    role: ParentRole::Supervisor,
                    listeners: &[],
                },
                LaunchLimits::default(),
            ) {
                Ok(parent) => parent,
                Err(error) => {
                    children.child = error.child.clone();
                    return Err(error.into());
                }
            };
            children.child = Some(parent.child().clone());
            Startup::Managed(parent)
        } else {
            let launched = daemon::launch(
                &mut children.registry,
                Reexec {
                    executable,
                    argv0: OsStr::new("gnunet-detach-fixture"),
                    arguments: &arguments(),
                    environment,
                    directory: &directory.0,
                    stderr: Stdio::Handle(stderr.as_handle()),
                    activation: Default::default(),
                },
                LaunchLimits::default(),
            );
            let parent = match launched {
                Ok(parent) => {
                    children.child = Some(parent.child().clone());
                    parent
                }
                Err(error) => {
                    children.child = error.child.clone();
                    return Err(error.into());
                }
            };
            Startup::Reexec(parent)
        };
        let child = parent.child().clone();
        let outcome = parent.wait().await;
        match role {
            "ready" | "managed" => check(
                outcome?.child() == &child,
                "ready came from a replacement child",
            )?,
            "failure" => check(
                matches!(
                    outcome,
                    Err(ParentFailure::Reported(ReadyStatus::InitializationFailed))
                ),
                "I became successful detachment",
            )?,
            "exit" => check(
                matches!(outcome, Err(ParentFailure::Exited(0))),
                "pre-connect exit became successful detachment",
            )?,
            _ => return Err("unknown detach fixture role".into()),
        }
        let mut control = if let Startup::Managed(parent) = &mut parent {
            let mut control = parent.take_control().ok_or("missing qualified control")?;
            control.begin(&children.registry, 15)?;
            poll_fn(|cx| control.poll_send(cx)).await?;
            Some(control)
        } else {
            None
        };
        drop(parent);
        if role == "ready" || role == "managed" {
            let identity = children.registry.identity(&child)?;
            let (mut reader, mut writer) = gate.accept(&identity).await?.split();
            check(
                poll_fn(|cx| reader.poll_byte(cx)).await? == Some(42),
                "child did not survive launcher EOF",
            )?;
            writer.begin(15)?;
            poll_fn(|cx| writer.poll_send(cx)).await?;
            // Keep the physical gate alive until the original child actually
            // exits; acceptance alone must not cancel an outstanding stop write.
            reap(&mut children, &child).await?;
        } else {
            reap(&mut children, &child).await?;
        }
        // Retain the physical supervisor writer until child receipt and reap;
        // software write admission alone cannot prove native completion.
        drop(control.take());
        drop(stderr);
        check(
            fs::read(stderr_path)? == b"detached stderr\n",
            "explicit stderr destination changed",
        )?;
        Ok(())
    }
    pub fn run() -> Result<(), Failure> {
        let role = std::env::var_os(ROLE);
        #[expect(
            unsafe_code,
            reason = "Fresh fixture startup before native owners/runtime; parent exclusively supplies inherited metadata"
        )]
        let captured = role
            .as_ref()
            .map(|_| {
                // SAFETY: first child action before any competing native ownership.
                unsafe { capture_from_environment() }
            })
            .transpose()?;
        check(
            captured
                .as_ref()
                .is_none_or(|captured| captured.activation.is_none()),
            "daemon fixture received unexpected activation",
        )?;
        if role.as_deref() == Some(OsStr::new("managed")) {
            #[expect(
                unsafe_code,
                reason = "Fresh fixture child before runtime/stream use, with unique native standard routes supplied by the parent and no cached handles or competing mutation"
            )]
            // SAFETY: original process startup owns all stream/console effects.
            let stderr = unsafe { daemon::detach_managed() }?;
            check(
                stderr == daemon::DetachedStderr::Preserved,
                "managed detachment replaced file stderr",
            )?;
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let work = async {
                if let Some(role) = role {
                    return child(&role, captured.ok_or("missing early capture")?).await;
                }
                let executable = std::env::current_exe()?;
                for role in ["ready", "managed", "failure", "exit"] {
                    parent(&executable, role).await?;
                }
                Ok(())
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
