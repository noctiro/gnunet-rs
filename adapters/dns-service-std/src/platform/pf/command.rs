//! Bounded control subprocess I/O with retained original wait authority.
use std::{
    fmt,
    fs::File,
    future::{Future, poll_fn},
    io,
    path::Path,
    pin::Pin,
    process::{ExitStatus, Stdio},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    process::{Child, ChildStdin, ChildStdout, Command},
    time::{Instant, timeout_at},
};
const OUTPUT_BYTES: usize = 32768;
enum Capture {
    Bytes(Vec<u8>),
    #[cfg(any(test, target_os = "freebsd"))]
    States(super::states::Parser),
}
impl Capture {
    fn feed(&mut self, bytes: &[u8]) -> io::Result<()> {
        match self {
            Self::Bytes(output) => {
                if bytes.len() > OUTPUT_BYTES.saturating_sub(output.len()) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "PF command output limit",
                    ));
                }
                output.extend_from_slice(bytes);
                Ok(())
            }
            #[cfg(any(test, target_os = "freebsd"))]
            Self::States(parser) => parser.feed(bytes),
        }
    }
    fn close(&mut self) -> io::Result<()> {
        match self {
            Self::Bytes(_) => Ok(()),
            #[cfg(any(test, target_os = "freebsd"))]
            Self::States(parser) => parser.close(),
        }
    }
}
struct Collected {
    status: ExitStatus,
    capture: Capture,
}
pub(super) struct Output {
    pub status: ExitStatus,
    pub bytes: Vec<u8>,
}
struct Running {
    child: Child,
    input: Option<ChildStdin>,
    output: Option<ChildStdout>,
    data: Vec<u8>,
    offset: usize,
    capture: Capture,
    output_prefix: usize,
    status: Option<ExitStatus>,
    wait_failed: bool,
}
#[derive(Debug)]
struct Failure {
    original: io::Error,
    retirement: Option<io::Error>,
    input_prefix: usize,
    output_prefix: usize,
    retained: bool,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PF command: {}; retirement={:?}; original-child-retained={}; stdin-prefix={}; stdout-prefix={}",
            self.original, self.retirement, self.retained, self.input_prefix, self.output_prefix
        )
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}
#[derive(Debug)]
struct RetirementFailure {
    stop: Option<io::Error>,
    wait: Option<io::Error>,
    status: Option<ExitStatus>,
}
impl fmt::Display for RetirementFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PF command stop={:?}; wait={:?}; observed-exit={:?}",
            self.stop, self.wait, self.status
        )
    }
}
impl std::error::Error for RetirementFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.stop
            .as_ref()
            .or(self.wait.as_ref())
            .map(|error| error as _)
    }
}
/// A canceled wait leaves the command and its I/O cursors here.
#[derive(Default)]
pub(super) struct Runner {
    active: Option<Running>,
    lease: Option<File>,
    user: Option<gnunet_native::process::EffectiveUser>,
}
#[derive(Clone, Copy)]
enum OnFailure {
    Retire,
    Retain,
}
impl Running {
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.wait_failed {
            return Poll::Ready(Err(io::Error::other(
                "PF command original wait authority is lost",
            )));
        }
        if self.status.is_none() {
            match std::pin::pin!(self.child.wait()).as_mut().poll(cx) {
                Poll::Ready(Ok(status)) => self.status = Some(status),
                Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Interrupted => {
                    cx.waker().wake_by_ref();
                }
                Poll::Ready(Err(error)) => {
                    self.wait_failed = true;
                    return Poll::Ready(Err(error));
                }
                Poll::Pending => {}
            }
        }
        let mut progress = false;
        if let Some(input) = &mut self.input {
            if self.offset == self.data.len() {
                self.input = None;
                progress = true;
            } else {
                let end = self.data.len().min(self.offset.saturating_add(4096));
                match Pin::new(input).poll_write(cx, &self.data[self.offset..end]) {
                    Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                    Poll::Ready(Ok(count)) => {
                        self.offset += count;
                        progress = true;
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => {}
                }
            }
        }
        if let Some(output) = &mut self.output {
            let mut slab = [0; 4096];
            let mut buffer = ReadBuf::new(&mut slab);
            match Pin::new(output).poll_read(cx, &mut buffer) {
                Poll::Ready(Ok(())) if buffer.filled().is_empty() => {
                    self.capture.close()?;
                    self.output = None;
                    progress = true;
                }
                Poll::Ready(Ok(())) => {
                    self.output_prefix = self
                        .output_prefix
                        .checked_add(buffer.filled().len())
                        .ok_or_else(|| io::Error::other("PF observed output length overflow"))?;
                    self.capture.feed(buffer.filled())?;
                    progress = true;
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => {}
            }
        }
        if self.status.is_some() && self.input.is_none() && self.output.is_none() {
            return Poll::Ready(Ok(()));
        }
        if progress {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
    fn stop(&mut self) -> io::Result<()> {
        self.input = None;
        self.output = None;
        if self.status.is_some() {
            return Ok(());
        }
        if self.wait_failed {
            return Err(io::Error::other("PF command lost exclusive wait authority"));
        }
        self.child.start_kill()
    }
}
impl Runner {
    pub fn leased(file: &File) -> io::Result<Self> {
        Ok(Self {
            active: None,
            lease: Some(file.try_clone()?),
            user: Some(gnunet_native::process::EffectiveUser::current()),
        })
    }
    pub fn idle(&self) -> bool {
        self.active.is_none()
    }
    pub async fn retire(&mut self) -> io::Result<()> {
        let Some(active) = self.active.as_mut() else {
            return Ok(());
        };
        let stop = active.stop().err();
        if active.wait_failed {
            return Err(io::Error::other(RetirementFailure {
                stop,
                wait: Some(io::Error::other(
                    "PF original wait authority is lost; no PID retry is permitted",
                )),
                status: active.status,
            }));
        }
        let wait = if active.status.is_none() {
            let until = Instant::now()
                .checked_add(Duration::from_secs(1))
                .ok_or_else(|| io::Error::other("PF retirement deadline overflow"))?;
            match timeout_at(until, active.child.wait()).await {
                Ok(Ok(status)) => {
                    active.status = Some(status);
                    None
                }
                Ok(Err(error)) => {
                    active.wait_failed = true;
                    Some(error)
                }
                Err(error) => Some(io::Error::new(io::ErrorKind::TimedOut, error)),
            }
        } else {
            None
        };
        let status = active.status;
        if status.is_some() {
            self.active = None;
        }
        if stop.is_none() && wait.is_none() {
            Ok(())
        } else {
            Err(io::Error::other(RetirementFailure { stop, wait, status }))
        }
    }
    pub async fn run(&mut self, program: &Path, args: &[&str], input: &[u8]) -> io::Result<Output> {
        let until = self.deadline(None)?;
        self.bytes(program, args, input, until, OnFailure::Retire)
            .await
    }
    /// Read-only probes fail before waiting for child retirement so their
    /// caller can fence packet admission first. Cleanup retains this runner.
    pub async fn observe_until(
        &mut self,
        program: &Path,
        args: &[&str],
        hard: Instant,
    ) -> io::Result<Output> {
        let until = self.deadline(Some(hard))?;
        self.bytes(program, args, &[], until, OnFailure::Retain)
            .await
    }
    async fn bytes(
        &mut self,
        program: &Path,
        args: &[&str],
        input: &[u8],
        until: Instant,
        failure: OnFailure,
    ) -> io::Result<Output> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(OUTPUT_BYTES)
            .map_err(io::Error::other)?;
        let output = self
            .collect(program, args, input, Capture::Bytes(bytes), until, failure)
            .await?;
        match output.capture {
            Capture::Bytes(bytes) => Ok(Output {
                status: output.status,
                bytes,
            }),
            #[cfg(any(test, target_os = "freebsd"))]
            Capture::States(_) => Err(io::Error::other("PF command output kind mismatch")),
        }
    }
    #[cfg(any(test, target_os = "freebsd"))]
    pub async fn states(
        &mut self,
        program: &Path,
        args: &[&str],
        selection: super::states::Selection,
        hard: Instant,
    ) -> io::Result<(ExitStatus, Vec<super::states::Id>)> {
        let until = self.deadline(Some(hard))?;
        let capture = Capture::States(super::states::Parser::new(selection)?);
        let output = self
            .collect(program, args, &[], capture, until, OnFailure::Retire)
            .await?;
        match output.capture {
            Capture::States(parser) => Ok((output.status, parser.into_targets()?)),
            Capture::Bytes(_) => Err(io::Error::other("PF command output kind mismatch")),
        }
    }
    fn deadline(&self, hard: Option<Instant>) -> io::Result<Instant> {
        if !self.idle() {
            return Err(io::Error::other(
                "PF command still owns an unresolved original child",
            ));
        }
        let until = Instant::now()
            .checked_add(Duration::from_secs(3))
            .ok_or_else(|| io::Error::other("PF command deadline overflow"))?;
        Ok(hard.map_or(until, |hard| until.min(hard)))
    }
    async fn collect(
        &mut self,
        program: &Path,
        args: &[&str],
        input: &[u8],
        capture: Capture,
        until: Instant,
        failure: OnFailure,
    ) -> io::Result<Collected> {
        let mut data = Vec::new();
        data.try_reserve_exact(input.len())
            .map_err(io::Error::other)?;
        data.extend_from_slice(input);
        let mut command = Command::new(program);
        command
            .args(args)
            .env_clear()
            .env("LC_ALL", "C")
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(false);
        if let Some(lease) = &self.lease {
            gnunet_native::process::inherit_file(command.as_std_mut(), lease)?;
        }
        if let Some(user) = self.user {
            user.apply(command.as_std_mut());
        }
        if Instant::now() >= until {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "PF command preparation expired",
            ));
        }
        let mut child = command.spawn()?;
        // Drop only the parent's exec-configuration duplicate. The exec'd
        // original command retains its own shared-open-description lease.
        drop(command);
        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        self.active = Some(Running {
            child,
            input: stdin,
            output: stdout,
            data,
            offset: 0,
            capture,
            output_prefix: 0,
            status: None,
            wait_failed: false,
        });
        let result = timeout_at(
            until,
            poll_fn(|cx| match self.active.as_mut() {
                Some(active) => active.poll(cx),
                None => Poll::Ready(Err(io::Error::other("PF command original owner missing"))),
            }),
        )
        .await;
        let original = match result {
            // Tokio polls the inner future before its timer. A native child
            // already ready after an unpolled interval can therefore complete
            // beyond `until`; keep its observed effects, but refuse admission.
            Ok(Ok(())) if Instant::now() < until => None,
            Ok(Ok(())) => Some(io::Error::new(
                io::ErrorKind::TimedOut,
                "PF command completion observed after its original deadline",
            )),
            Ok(Err(error)) => Some(error),
            Err(error) => Some(io::Error::new(io::ErrorKind::TimedOut, error)),
        };
        if let Some(original) = original {
            let (input_prefix, output_prefix) = self
                .active
                .as_ref()
                .map_or((0, 0), |active| (active.offset, active.output_prefix));
            let retirement = match failure {
                OnFailure::Retire => self.retire().await.err(),
                OnFailure::Retain => None,
            };
            return Err(io::Error::other(Failure {
                original,
                retirement,
                input_prefix,
                output_prefix,
                retained: !self.idle(),
            }));
        }
        let active = self
            .active
            .take()
            .ok_or_else(|| io::Error::other("PF command original owner missing"))?;
        Ok(Collected {
            status: active
                .status
                .ok_or_else(|| io::Error::other("PF command exit was not observed"))?,
            capture: active.capture,
        })
    }
}
impl Drop for Runner {
    fn drop(&mut self) {
        if let Some(active) = &mut self.active {
            let _stop = active.stop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct LeaseDirectory(std::path::PathBuf);
    impl Drop for LeaseDirectory {
        fn drop(&mut self) {
            let _cleanup = std::fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn ready_native_completion_after_an_unpolled_deadline_is_not_admitted() -> io::Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let mut runner = Runner::default();
            let hard = Instant::now() + Duration::from_millis(100);
            let mut request = std::pin::pin!(runner.states(
                Path::new("/bin/cat"),
                &[],
                super::super::states::Selection::Dns(Vec::new()),
                hard,
            ));
            // The original cat is waiting for stdin at the first native wait.
            // This poll closes stdin; keep its waiter unpolled while the actual
            // child exits and the runtime publishes pipe/process readiness.
            poll_fn(|cx| match request.as_mut().poll(cx) {
                Poll::Pending => Poll::Ready(Ok(())),
                Poll::Ready(_) => Poll::Ready(Err(io::Error::other(
                    "PF fixture did not retain its original pending child",
                ))),
            })
            .await?;
            tokio::time::sleep_until(hard + Duration::from_millis(20)).await;
            let error = request.await.err().ok_or_else(|| {
                io::Error::other("late native PF completion became successful admission")
            })?;
            let failure = error
                .get_ref()
                .and_then(|cause| cause.downcast_ref::<Failure>())
                .ok_or_else(|| io::Error::other("original command failure was not retained"))?;
            if failure.original.kind() != io::ErrorKind::TimedOut {
                return Err(io::Error::other(
                    "late PF completion lost its timeout cause",
                ));
            }
            Ok(())
        })
    }
    #[test]
    fn state_output_is_streamed_past_the_control_output_cap_without_a_pf_command() -> io::Result<()>
    {
        use std::{
            fs::{DirBuilder, OpenOptions},
            os::unix::fs::{DirBuilderExt, OpenOptionsExt},
            time::{SystemTime, UNIX_EPOCH},
        };
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("gnunet-pf-stream-{}-{stamp}", std::process::id()));
        DirBuilder::new().mode(0o700).create(&path)?;
        let directory = LeaseDirectory(path);
        let path = directory.0.join("fixture");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        let ignored = b"all tcp 10.0.0.1:53000 -> 192.0.2.53:443 ESTABLISHED:ESTABLISHED\n   id: 0000000000000001 creatorid: 12345678\n";
        for _ in 0..1024 {
            std::io::Write::write_all(&mut file, ignored)?;
        }
        std::io::Write::write_all(&mut file, b"all udp 10.0.0.1:53000 -> 192.0.2.53:53 SINGLE:SINGLE\n   id: 0000000000000002 creatorid: 12345678\n")?;
        drop(file);
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let mut runner = Runner::default();
                let (status, targets) = runner
                    .states(
                        Path::new("/bin/cat"),
                        &[path.to_str().ok_or(io::ErrorKind::InvalidInput)?],
                        super::super::states::Selection::Dns(vec![
                            "10.0.0.1".parse().map_err(io::Error::other)?,
                        ]),
                        Instant::now() + Duration::from_secs(3),
                    )
                    .await?;
                if !status.success()
                    || targets.len() != 1
                    || targets[0].to_string() != "0000000000000002/12345678"
                    || !runner.idle()
                {
                    return Err(io::Error::other(
                        "streaming state query lost its target or original child",
                    ));
                }
                Ok(())
            })
    }
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "The private cat child must retain the real flock after all parent duplicates close; no PF command runs"
    )]
    fn command_keeps_the_original_lease_after_parent_descriptors_close() -> io::Result<()> {
        use std::{
            fs::{DirBuilder, OpenOptions, TryLockError},
            os::unix::fs::{DirBuilderExt, OpenOptionsExt},
            time::{SystemTime, UNIX_EPOCH},
        };
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "gnunet-pf-child-lease-{}-{stamp}",
            std::process::id()
        ));
        DirBuilder::new().mode(0o700).create(&path)?;
        let directory = LeaseDirectory(path);
        let path = directory.0.join("lease");
        let original = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        original.try_lock().map_err(io::Error::other)?;
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let mut runner = Runner::leased(&original)?;
                {
                    let mut running =
                        std::pin::pin!(runner.run(Path::new("/bin/cat"), &[], b"leased"));
                    assert!(
                        running
                            .as_mut()
                            .poll(&mut Context::from_waker(std::task::Waker::noop()))
                            .is_pending(),
                        "original child must remain live with its input pipe open"
                    );
                }
                drop(runner.lease.take());
                drop(original);
                let contender = OpenOptions::new().read(true).write(true).open(&path)?;
                assert!(
                    matches!(contender.try_lock(), Err(TryLockError::WouldBlock)),
                    "exec'd child must fence a replacement after parent descriptors close"
                );
                runner.retire().await?;
                assert!(
                    runner.idle(),
                    "original child must be reaped before replacement"
                );
                contender.try_lock().map_err(io::Error::other)?;
                Ok(())
            })
    }
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Private-pipe fixture checks original-child retention and actual binary I/O; it never invokes pfctl"
    )]
    fn canceled_command_keeps_its_child_until_explicit_retirement() -> io::Result<()> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let mut runner = Runner::default();
                {
                    let mut waiting =
                        std::pin::pin!(runner.run(Path::new("/bin/cat"), &[], b"original"));
                    assert!(
                        waiting
                            .as_mut()
                            .poll(&mut Context::from_waker(std::task::Waker::noop()))
                            .is_pending()
                    );
                }
                let original = runner.active.as_ref().and_then(|active| active.child.id());
                assert!(original.is_some());
                assert!(
                    runner
                        .run(Path::new("/bin/cat"), &[], b"replacement")
                        .await
                        .is_err()
                );
                assert_eq!(
                    runner.active.as_ref().and_then(|active| active.child.id()),
                    original
                );
                runner.retire().await?;
                assert!(runner.idle());
                let input: Vec<u8> = (0u8..=255).cycle().take(8192).collect();
                let output = runner.run(Path::new("/bin/cat"), &[], &input).await?;
                assert!(output.status.success());
                assert_eq!(output.bytes, input);
                assert!(runner.idle());
                Ok(())
            })
    }
}
