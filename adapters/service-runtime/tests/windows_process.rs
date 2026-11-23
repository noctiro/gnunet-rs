//! Standalone Windows children qualify original-handle launch and cancellation.
#[cfg(windows)]
mod windows {
    use gnunet_native::{
        process::{Console, ExportedHandle, LaunchLimits, Process, ProcessWait, Spawn, Stdio},
        socket_activation::{ExportSection, Source},
    };
    use gnunet_service_runtime::process::{ChildRegistry, RegistryError};
    use std::{
        ffi::{OsStr, OsString},
        fs::{self, File},
        io::{self, Read, Seek, SeekFrom, Write},
        os::windows::{
            ffi::OsStringExt,
            io::{AsHandle, AsSocket, FromRawHandle},
        },
        path::{Path, PathBuf},
        sync::{
            Arc, Mutex,
            atomic::{AtomicU64, Ordering},
            mpsc,
        },
        task::{Context, Poll, Wake, Waker},
        thread,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };
    const ROLE: &str = "GNUNET_NATIVE_PROCESS_FIXTURE";
    fn check(value: bool, message: &'static str) -> io::Result<()> {
        if value {
            Ok(())
        } else {
            Err(io::Error::other(message))
        }
    }
    fn arguments() -> Vec<OsString> {
        vec![
            "".into(),
            "two words".into(),
            "a\"b".into(),
            "a\\".into(),
            OsString::from_wide(&[0xd800, 0x5c]),
        ]
    }
    fn environment(role: &str) -> Vec<(OsString, OsString)> {
        let mut values: Vec<_> = std::env::vars_os().collect();
        values.push((ROLE.into(), role.into()));
        values.push(("GNUNET_NATIVE_CASE".into(), "old".into()));
        values.push(("gnunet_native_case".into(), "new".into()));
        values.push(("GNUNET_NATIVE_HANDLE".into(), "not-a-handle".into()));
        values
    }
    fn command<'a>(
        executable: &'a Path,
        arguments: &'a [OsString],
        environment: &'a [(OsString, OsString)],
        directory: &'a Path,
        handles: &'a [ExportedHandle<'a>],
    ) -> Spawn<'a> {
        Spawn {
            executable,
            argv0: OsStr::new("gnunet-process-fixture"),
            arguments,
            environment,
            directory,
            stdio: [Stdio::Null; 3],
            exported_handles: handles,
            console: Console::Detached,
        }
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
                "gn-process-{}-{nonce:x}-{:x}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path)?;
            let directory = Self(path);
            fs::write(directory.0.join("cwd-marker"), b"correct directory")?;
            Ok(directory)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _cleanup = fs::remove_dir_all(&self.0);
        }
    }
    struct Child(Process);
    impl Drop for Child {
        fn drop(&mut self) {
            if !matches!(self.0.try_wait(), Ok(Some(_))) {
                let _cleanup = self.0.terminate(0xdead_0001);
            }
        }
    }
    struct Unpark(thread::Thread);
    impl Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    fn drive<T>(mut poll: impl FnMut(&mut Context<'_>) -> Poll<io::Result<T>>) -> io::Result<T> {
        let waker = Waker::from(Arc::new(Unpark(thread::current())));
        let mut context = Context::from_waker(&waker);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Poll::Ready(result) = poll(&mut context) {
                return result;
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "native process notification stalled",
                    )
                })?;
            thread::park_timeout(remaining);
        }
    }
    #[expect(
        unsafe_code,
        reason = "This fresh fixture child uniquely adopts the exact file handle exported by its parent; no other owner is constructed from the advertised value"
    )]
    #[expect(
        clippy::exit,
        reason = "This standalone fixture child must return the actual full-width Windows exit code 259, which ExitCode cannot represent"
    )]
    fn child(role: &OsStr) -> io::Result<()> {
        check(
            fs::read("cwd-marker")? == b"correct directory",
            "child working directory changed",
        )?;
        if role == "arguments" {
            check(
                std::env::args_os().next().as_deref() == Some(OsStr::new("gnunet-process-fixture")),
                "native filename was substituted for explicit argv0",
            )?;
            let actual: Vec<_> = std::env::args_os().skip(1).collect();
            check(
                actual == arguments(),
                "native command quoting altered an argument",
            )?;
            check(
                std::env::var_os("GnUnEt_NaTiVe_CaSe").as_deref() == Some(OsStr::new("new")),
                "case-insensitive environment overlay changed",
            )?;
            let value = std::env::var("GNUNET_NATIVE_HANDLE").map_err(io::Error::other)?;
            let raw = usize::from_str_radix(&value, 16).map_err(io::Error::other)?;
            // SAFETY: this test's parent transferred one independently duplicated
            // disk-file handle in the explicit native allowlist under this key.
            let mut file = unsafe { File::from_raw_handle(raw as *mut _) };
            check(
                file.metadata()?.is_file(),
                "export is not the original disk file",
            )?;
            file.write_all(b"child-ok")?;
            file.flush()?;
            std::process::exit(259);
        }
        if role == "quick" {
            std::process::exit(259);
        }
        if role == "wait" {
            fs::write("ready", b"ready")?;
            let deadline = Instant::now() + Duration::from_secs(10);
            while !Path::new("stop").is_file() {
                if Instant::now() >= deadline {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                thread::sleep(Duration::from_millis(1));
            }
            std::process::exit(37);
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unknown fixture child role",
        ))
    }
    fn arguments_and_unsigned_exit(executable: &Path) -> io::Result<()> {
        let directory = Directory::new()?;
        let mut file = gnunet_native::paths::create_private_file(&directory.0.join("export"))?;
        let handles = [ExportedHandle {
            handle: file.as_handle(),
            environment_key: OsStr::new("GNUNET_NATIVE_HANDLE"),
        }];
        let args = arguments();
        let env = environment("arguments");
        let child = Child(
            command(executable, &args, &env, &directory.0, &handles)
                .launch(LaunchLimits::default())?,
        );
        let mut wait = ProcessWait::new(&child.0)?;
        check(
            drive(|cx| wait.poll_exit(cx))? == 259,
            "completed code 259 was mistaken for a running process",
        )?;
        check(
            child.0.try_wait()? == Some(259),
            "exit observation changed the original process",
        )?;
        drop(wait);
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        check(
            bytes == b"child-ok",
            "child did not receive the original exported resource",
        )
    }
    struct RegistryChild {
        registry: ChildRegistry,
        token: gnunet_service_runtime::process::OriginalChild,
    }
    impl Drop for RegistryChild {
        fn drop(&mut self) {
            if self.registry.owns(&self.token) {
                let _cleanup = self.registry.terminate(&self.token, 0xdead_0004);
            }
        }
    }
    fn suspended_start_permissions(executable: &Path) -> io::Result<()> {
        let directory = Directory::new()?;
        let environment = environment("quick");
        for cancel in [false, true] {
            let mut registry = ChildRegistry::new(1).map_err(io::Error::other)?;
            let token = registry
                .spawn_suspended(
                    command(executable, &[], &environment, &directory.0, &[]),
                    LaunchLimits::default(),
                )
                .map_err(io::Error::other)?;
            let mut child = RegistryChild { registry, token };
            let original = child
                .registry
                .original(&child.token)
                .map_err(io::Error::other)?;
            check(
                original.try_wait()?.is_none(),
                "suspended child ran before permission",
            )?;
            let code = if cancel {
                child
                    .registry
                    .cancel_preparation(&child.token)
                    .map_err(io::Error::other)?;
                check(
                    child.registry.resume(&child.token).is_err(),
                    "failed setup could resume its original child",
                )?;
                check(
                    child
                        .registry
                        .original(&child.token)
                        .map_err(io::Error::other)?
                        .try_wait()?
                        .is_none(),
                    "revocation manufactured an exit",
                )?;
                child
                    .registry
                    .terminate(&child.token, 0xdead_0004)
                    .map_err(io::Error::other)?;
                0xdead_0004
            } else {
                child
                    .registry
                    .resume(&child.token)
                    .map_err(io::Error::other)?;
                check(
                    child.registry.resume(&child.token).is_err(),
                    "original child resumed twice",
                )?;
                check(
                    child.registry.cancel_preparation(&child.token).is_err(),
                    "running original child was marked unstarted",
                )?;
                259
            };
            drive(|cx| {
                child
                    .registry
                    .poll_child_signal(cx)
                    .map_err(io::Error::other)
            })?;
            child.registry.reap_completed().map_err(io::Error::other)?;
            let receipt = child
                .registry
                .take_reaped()
                .ok_or("missing suspended-child receipt")
                .map_err(io::Error::other)?;
            check(
                receipt.child == child.token && receipt.exit_code == code,
                "suspended original child was lost, replaced or falsely completed",
            )?;
        }
        Ok(())
    }
    fn activation_requires_the_admitted_child(executable: &Path) -> io::Result<()> {
        let directory = Directory::new()?;
        let environment = environment("quick");
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let sources = [Source::new(listener.as_socket())];
        let mut section = ExportSection::for_listeners(&sources)?;
        let mut registry = ChildRegistry::new(1).map_err(io::Error::other)?;
        let token = registry
            .spawn_for_activation(
                command(executable, &[], &environment, &directory.0, &[]),
                &mut section,
                OsStr::new("GNUNET_RS_ACTIVATION_HANDLE"),
                LaunchLimits::default(),
            )
            .map_err(io::Error::other)?;
        let mut original = RegistryChild { registry, token };
        let mut registry = ChildRegistry::new(1).map_err(io::Error::other)?;
        let mut unrelated_section = ExportSection::for_listeners(&sources)?;
        let token = registry
            .spawn_for_activation(
                command(executable, &[], &environment, &directory.0, &[]),
                &mut unrelated_section,
                OsStr::new("GNUNET_RS_ACTIVATION_HANDLE"),
                LaunchLimits::default(),
            )
            .map_err(io::Error::other)?;
        let mut unrelated = RegistryChild { registry, token };

        let refused = section.publish(
            unrelated
                .registry
                .activation_target(&unrelated.token)
                .map_err(io::Error::other)?,
        );
        check(
            matches!(refused, Err(failure) if failure.exported == 0
                && failure.error.kind() == io::ErrorKind::PermissionDenied),
            "activation exported a listener to an unrelated child",
        )?;
        check(
            original.registry.resume(&original.token).is_err(),
            "original activation child resumed without publication",
        )?;

        for mut child in [original, unrelated] {
            let code = 0xdead_0004;
            child
                .registry
                .terminate(&child.token, code)
                .map_err(io::Error::other)?;
            drive(|cx| {
                child
                    .registry
                    .poll_child_signal(cx)
                    .map_err(io::Error::other)
            })?;
            child.registry.reap_completed().map_err(io::Error::other)?;
            check(
                child
                    .registry
                    .take_reaped()
                    .is_some_and(|r| r.child == child.token && r.exit_code == code),
                "activation refusal lost the actual suspended process",
            )?;
        }
        Ok(())
    }
    fn registry_cancellation_and_credit(executable: &Path) -> io::Result<()> {
        let directory = Directory::new()?;
        let env = environment("wait");
        let mut registry = ChildRegistry::new(1).map_err(io::Error::other)?;
        let other = ChildRegistry::new(1).map_err(io::Error::other)?;
        let token = registry
            .spawn(
                command(executable, &[], &env, &directory.0, &[]),
                LaunchLimits::default(),
            )
            .map_err(io::Error::other)?;
        check(
            matches!(other.terminate(&token, 1), Err(RegistryError::Stale)),
            "another registry acquired child authority",
        )?;
        let waker = Waker::from(Arc::new(Unpark(thread::current())));
        let mut context = Context::from_waker(&waker);
        {
            let mut waiting =
                std::pin::pin!(std::future::poll_fn(|cx| registry.poll_child_signal(cx)));
            use std::future::Future;
            check(
                waiting.as_mut().poll(&mut context).is_pending(),
                "waiting child exited before release",
            )?;
        }
        fs::write(directory.0.join("stop"), b"stop")?;
        drive(|cx| registry.poll_child_signal(cx).map_err(io::Error::other))?;
        check(
            registry.reap_completed().map_err(io::Error::other)? == 1,
            "original child was not consumed once",
        )?;
        check(
            !registry.credit_available(1),
            "untaken completion released child credit",
        )?;
        check(
            matches!(
                registry.spawn(
                    command(executable, &[], &env, &directory.0, &[]),
                    LaunchLimits::default()
                ),
                Err(RegistryError::Capacity)
            ),
            "a full registry created another child",
        )?;
        let exit = registry
            .take_reaped()
            .ok_or_else(|| io::Error::other("missing original receipt"))?;
        check(
            exit.child == token && exit.exit_code == 37,
            "receipt changed its original identity or exit code",
        )?;
        check(
            registry.take_reaped().is_none() && registry.credit_available(1),
            "receipt credit was not consumed once",
        )?;
        let quick = environment("quick");
        let replacement = registry
            .spawn(
                command(executable, &[], &quick, &directory.0, &[]),
                LaunchLimits::default(),
            )
            .map_err(io::Error::other)?;
        check(
            replacement != token
                && matches!(registry.terminate(&token, 1), Err(RegistryError::Stale)),
            "retired token targeted a replacement",
        )?;
        drive(|cx| registry.poll_child_signal(cx).map_err(io::Error::other))?;
        registry.reap_completed().map_err(io::Error::other)?;
        check(
            registry
                .take_reaped()
                .is_some_and(|receipt| receipt.child == replacement && receipt.exit_code == 259),
            "replacement's unsigned code or identity changed",
        )?;
        fs::remove_file(directory.0.join("stop"))?;
        let forced = registry
            .spawn(
                command(executable, &[], &env, &directory.0, &[]),
                LaunchLimits::default(),
            )
            .map_err(io::Error::other)?;
        registry
            .terminate(&forced, 0xf123_4567)
            .map_err(io::Error::other)?;
        drive(|cx| registry.poll_child_signal(cx).map_err(io::Error::other))?;
        registry.reap_completed().map_err(io::Error::other)?;
        check(
            registry
                .take_reaped()
                .is_some_and(|receipt| receipt.child == forced && receipt.exit_code == 0xf123_4567),
            "forced termination lost its original handle or unsigned code",
        )
    }
    fn exact_reaping_preserves_other_receipts(executable: &Path) -> io::Result<()> {
        let directory = Directory::new()?;
        let env = environment("quick");
        let mut registry = ChildRegistry::new(2).map_err(io::Error::other)?;
        let first = registry
            .spawn(
                command(executable, &[], &env, &directory.0, &[]),
                LaunchLimits::default(),
            )
            .map_err(io::Error::other)?;
        let second = registry
            .spawn(
                command(executable, &[], &env, &directory.0, &[]),
                LaunchLimits::default(),
            )
            .map_err(io::Error::other)?;
        let mut completed = 0;
        while completed < 2 {
            drive(|cx| registry.poll_child_signal(cx).map_err(io::Error::other))?;
            completed += registry.reap_completed().map_err(io::Error::other)?;
        }
        let receipt = registry.reap_child(&second).map_err(io::Error::other)?;
        check(
            receipt.is_some_and(|value| value.child == second && value.exit_code == 259),
            "exact reaping consumed another child's completion",
        )?;
        check(
            registry.credit_available(1) && !registry.credit_available(2),
            "exact reaping released another child's credit",
        )?;
        check(
            matches!(registry.reap_child(&second), Err(RegistryError::Stale)),
            "exact reaping consumed one receipt twice",
        )?;
        check(
            registry
                .take_reaped()
                .is_some_and(|value| value.child == first && value.exit_code == 259)
                && registry.credit_available(2),
            "exact reaping lost the unrelated queued receipt",
        )
    }
    struct BlockingWake {
        entered: mpsc::Sender<()>,
        release: Mutex<mpsc::Receiver<()>>,
    }
    impl Wake for BlockingWake {
        fn wake(self: Arc<Self>) {
            let _entered = self.entered.send(());
            let _released = self
                .release
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .recv_timeout(Duration::from_secs(5));
        }
    }
    fn cancellation_does_not_wait_for_caller_wake(executable: &Path) -> io::Result<()> {
        let directory = Directory::new()?;
        let env = environment("wait");
        let child = Child(
            command(executable, &[], &env, &directory.0, &[]).launch(LaunchLimits::default())?,
        );
        let mut wait = ProcessWait::new(&child.0)?;
        let (entered, entered_rx) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        let waker = Waker::from(Arc::new(BlockingWake {
            entered,
            release: Mutex::new(release_rx),
        }));
        check(
            wait.poll_exit(&mut Context::from_waker(&waker))
                .is_pending(),
            "child exited before release",
        )?;
        fs::write(directory.0.join("stop"), b"stop")?;
        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .map_err(io::Error::other)?;
        let (closed, closed_rx) = mpsc::channel();
        let cleanup = thread::spawn(move || {
            drop(wait);
            let _closed = closed.send(());
        });
        let independent = closed_rx.recv_timeout(Duration::from_secs(1));
        let _release = release.send(());
        cleanup
            .join()
            .map_err(|_| io::Error::other("wait cleanup thread panicked"))?;
        independent.map_err(|_| io::Error::other("wait teardown blocked on caller Wake code"))?;
        check(
            child.0.try_wait()? == Some(37),
            "callback wake fabricated process exit",
        )
    }
    pub fn run() -> io::Result<()> {
        if let Some(role) = std::env::var_os(ROLE) {
            return child(&role);
        }
        let executable = std::env::current_exe()?;
        arguments_and_unsigned_exit(&executable)?;
        suspended_start_permissions(&executable)?;
        activation_requires_the_admitted_child(&executable)?;
        registry_cancellation_and_credit(&executable)?;
        exact_reaping_preserves_other_receipts(&executable)?;
        cancellation_does_not_wait_for_caller_wake(&executable)
    }
}
#[cfg(windows)]
fn main() -> std::io::Result<()> {
    windows::run()
}
#[cfg(not(windows))]
fn main() {}
