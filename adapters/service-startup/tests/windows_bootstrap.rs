//! Standalone original Windows children using real private process pipes.
#[cfg(windows)]
mod windows {
    use gnunet_native::process::{Console, LaunchLimits, Spawn, Stdio};
    use gnunet_service_runtime::{
        pipe::PipeListener,
        process::{ChildRegistry, OriginalChild},
    };
    use gnunet_service_startup::{
        ParentBootstrap, ParentFailure, ReadyFailure, ReadyStatus, capture_from_environment,
    };
    use std::{
        error::Error,
        ffi::{OsStr, OsString},
        future::{Future, poll_fn},
        io,
        path::Path,
        task::{Context, Waker},
        time::Duration,
    };
    type Failure = Box<dyn Error>;
    const ROLE: &str = "GNUNET_WINDOWS_BOOTSTRAP_FIXTURE";
    const CONTROL: &str = "GNUNET_OS_CONTROL_PIPE";
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
            "operation completed before fixture released its byte",
        )
    }
    struct Child {
        registry: ChildRegistry,
        token: OriginalChild,
    }
    impl Drop for Child {
        fn drop(&mut self) {
            if self.registry.owns(&self.token) {
                let _cleanup = self.registry.terminate(&self.token, 0xdead_0002);
            }
        }
    }
    fn spawn(executable: &Path, endpoint: &OsStr, role: &str) -> Result<Child, Failure> {
        let mut environment: Vec<(OsString, OsString)> = std::env::vars_os()
            .filter(|(key, _)| {
                !key.to_str().is_some_and(|key| {
                    key.eq_ignore_ascii_case("LISTEN_FDS")
                        || key.eq_ignore_ascii_case("LISTEN_FDNAMES")
                })
            })
            .collect();
        environment.push((ROLE.into(), role.into()));
        environment.push((CONTROL.into(), endpoint.into()));
        let mut registry = ChildRegistry::new(1)?;
        let token = registry.spawn(
            Spawn {
                executable,
                argv0: OsStr::new("gnunet-bootstrap-fixture"),
                arguments: &[],
                environment: &environment,
                directory: &std::env::current_dir()?,
                stdio: [Stdio::Null; 3],
                exported_handles: &[],
                console: Console::Detached,
            },
            LaunchLimits::default(),
        )?;
        Ok(Child { registry, token })
    }
    async fn child(
        role: &OsStr,
        captured: gnunet_service_startup::CapturedStartup,
    ) -> Result<(), Failure> {
        check(
            std::env::var_os(CONTROL).is_none(),
            "consumed bootstrap hint remained",
        )?;
        #[expect(
            unsafe_code,
            reason = "The once-only guard refuses repeats before reading declarations or adopting any owner"
        )]
        // SAFETY: first capture already completed; repetition has no native effect.
        let repeated = unsafe { capture_from_environment() };
        check(
            repeated
                .err()
                .is_some_and(|error| error.kind() == io::ErrorKind::AlreadyExists),
            "bootstrap capture was repeated",
        )?;
        if role == "exit-before-connect" {
            return Ok(());
        }
        let mut parent = captured
            .parent_control
            .ok_or_else(|| io::Error::other("missing parent pipe"))?
            .register()?;
        check(
            poll_fn(|cx| parent.control.poll_signal(cx)).await? == Some(-1),
            "handshake byte changed",
        )?;
        if role == "eof" {
            return Ok(());
        }
        let status = if role == "initialization" {
            ReadyStatus::InitializationFailed
        } else if role == "stopped" {
            ReadyStatus::ServerNotStarted
        } else {
            ReadyStatus::AcceptRegistered
        };
        let first = parent.ready.signal(status).await?;
        check(
            first.byte() == status.byte(),
            "submitted readiness byte changed",
        )?;
        check(
            parent.ready.signal(status).await? == first,
            "ready resumption changed intent",
        )?;
        let different = if status == ReadyStatus::AcceptRegistered {
            ReadyStatus::ServerNotStarted
        } else {
            ReadyStatus::AcceptRegistered
        };
        check(
            matches!(
                parent.ready.begin(different),
                Err(ReadyFailure::IntentMismatch { .. })
            ),
            "ready outbox accepted a replacement intent",
        )?;
        if role == "ready" {
            for expected in [15, 2] {
                check(
                    poll_fn(|cx| parent.control.poll_signal(cx)).await? == Some(expected),
                    "control byte changed",
                )?;
            }
        }
        check(
            poll_fn(|cx| parent.control.poll_signal(cx))
                .await?
                .is_none(),
            "parent EOF became a signal",
        )?;
        check(
            poll_fn(|cx| parent.control.poll_signal(cx))
                .await?
                .is_none(),
            "EOF was not sticky",
        )?;
        Ok(())
    }
    async fn reap(child: &mut Child) -> Result<(), Failure> {
        loop {
            child.registry.reap_completed()?;
            if let Some(receipt) = child.registry.take_reaped() {
                check(
                    receipt.child == child.token && receipt.exit_code == 0,
                    "bootstrap child failed",
                )?;
                return Ok(());
            }
            poll_fn(|cx| child.registry.poll_child_signal(cx)).await?;
        }
    }
    async fn parent(executable: &Path, role: &str) -> Result<(), Failure> {
        let listener = PipeListener::bind()?;
        let mut child = spawn(executable, listener.endpoint().as_os_str(), role)?;
        let mut bootstrap = ParentBootstrap::new(listener, &child.registry, &child.token)?;
        if role == "exit-before-connect" {
            for _ in 0..2 {
                check(
                    matches!(bootstrap.wait_ready().await, Err(ParentFailure::Exited(0))),
                    "pre-connect exit became readiness or lost its sticky exit code",
                )?;
            }
            check(
                bootstrap.take_control().is_none(),
                "exit supplied a qualified control direction",
            )?;
            return reap(&mut child).await;
        }
        bootstrap.connect().await?;
        let mut control = bootstrap
            .take_control()
            .ok_or_else(|| io::Error::other("missing qualified sender"))?;
        check(
            bootstrap.take_control().is_none(),
            "control direction transferred twice",
        )?;
        pending_once(poll_fn(|cx| bootstrap.poll_status(cx)))?;
        control.begin(&child.registry, -1)?;
        check(
            poll_fn(|cx| control.poll_send(cx)).await?.byte() == 255,
            "signed handshake changed",
        )?;
        check(
            control.take_submission().is_some() && control.take_submission().is_none(),
            "outbox credit was duplicated",
        )?;
        let result = bootstrap.wait_ready().await;
        match role {
            "ready" => {
                check(
                    result?.child() == &child.token,
                    "ready receipt lost original identity",
                )?;
                check(
                    bootstrap.wait_ready().await?.child() == &child.token,
                    "ready receipt was not sticky",
                )?;
                for byte in [15, 2] {
                    control.begin(&child.registry, byte)?;
                    check(
                        poll_fn(|cx| control.poll_send(cx)).await?.byte() == byte as u8,
                        "control submission changed",
                    )?;
                    check(
                        control.take_submission().is_some(),
                        "missing submission credit",
                    )?;
                }
            }
            "initialization" => check(
                matches!(
                    result,
                    Err(ParentFailure::Reported(ReadyStatus::InitializationFailed))
                ),
                "I became ready",
            )?,
            "stopped" => check(
                matches!(
                    result,
                    Err(ParentFailure::Reported(ReadyStatus::ServerNotStarted))
                ),
                "S became ready",
            )?,
            "eof" => check(
                matches!(result, Err(ParentFailure::Eof)),
                "EOF became ready",
            )?,
            _ => return Err(io::Error::other("unknown parent fixture role").into()),
        }
        drop(control);
        drop(bootstrap);
        reap(&mut child).await
    }
    async fn foreign_client(executable: &Path) -> Result<(), Failure> {
        use gnunet_service_runtime::pipe::PipeConnection;
        let listener = PipeListener::bind()?;
        // The original child has its own separate reserved endpoint, so this
        // parent-process connection is deterministically foreign to its token.
        let other = PipeListener::bind()?;
        let mut child = spawn(executable, other.endpoint().as_os_str(), "ready")?;
        let foreign = PipeConnection::connect(listener.endpoint())?;
        let mut bootstrap = ParentBootstrap::new(listener, &child.registry, &child.token)?;
        check(
            matches!(bootstrap.connect().await, Err(ParentFailure::Pipe(error)) if error.kind() == io::ErrorKind::PermissionDenied),
            "foreign process supplied startup evidence",
        )?;
        check(
            matches!(bootstrap.connect().await, Err(ParentFailure::Pipe(error)) if error.kind() == io::ErrorKind::PermissionDenied),
            "rejected physical pipe was recycled",
        )?;
        drop(foreign);
        child.registry.terminate(&child.token, 0xdead_0002)?;
        loop {
            child.registry.reap_completed()?;
            if let Some(receipt) = child.registry.take_reaped() {
                check(
                    receipt.child == child.token && receipt.exit_code == 0xdead_0002,
                    "foreign-client fixture did not drain its original child",
                )?;
                break;
            }
            poll_fn(|cx| child.registry.poll_child_signal(cx)).await?;
        }
        Ok(())
    }
    pub fn run() -> Result<(), Failure> {
        let role = std::env::var_os(ROLE);
        #[expect(
            unsafe_code,
            reason = "Fresh child startup before native owners/runtime; inherited metadata is exclusively supplied"
        )]
        let captured = role
            .as_ref()
            .map(|_| {
                // SAFETY: no competing child-native ownership exists before capture.
                unsafe { capture_from_environment() }
            })
            .transpose()?;
        check(
            captured
                .as_ref()
                .is_none_or(|captured| captured.activation.is_none()),
            "bootstrap fixture received unexpected activation",
        )?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let work = async {
                if let Some(role) = role {
                    return child(&role, captured.ok_or("missing early capture")?).await;
                }
                let executable = std::env::current_exe()?;
                for role in [
                    "ready",
                    "initialization",
                    "stopped",
                    "eof",
                    "exit-before-connect",
                ] {
                    parent(&executable, role).await?;
                }
                foreign_client(&executable).await
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
