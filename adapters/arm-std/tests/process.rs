//! Shared native process port with actual owned children, descriptors and waits.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Finite integration invariants assert actual native outcomes while IO/setup errors propagate"
)]
use gnunet_arm_host::process::{
    self, ChildExit, ChildRegistry, DescriptorMap, EnvironmentChange, EnvironmentSnapshot,
    LaunchError, NativeCommand, OriginalChild, PipeWriteOutcome, ProcessLimits, SignalAttempt,
    SpawnResult, Spawned,
};
use gnunet_config::Configuration;
use std::{
    error::Error,
    ffi::OsString,
    io::{self, Read, Write},
    net::{Ipv4Addr, TcpListener, TcpStream},
    os::{
        fd::{AsFd, AsRawFd},
        unix::{
            ffi::{OsStrExt, OsStringExt},
            fs::PermissionsExt,
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
type Test = Result<(), Box<dyn Error>>;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        let p = std::env::temp_dir().join(format!(
            "arm-proc-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&p)?;
        Ok(Self(p))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.0));
    }
}
struct Registry(ChildRegistry);
impl Registry {
    fn new(maximum: usize) -> Result<Self, LaunchError> {
        Ok(Self(ChildRegistry::new(maximum)?))
    }
}
impl Drop for Registry {
    fn drop(&mut self) {
        for pid in self.0.child_pids().collect::<Vec<_>>() {
            if let Ok(pid) = i32::try_from(pid) {
                match nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(pid),
                    nix::sys::signal::Signal::SIGKILL,
                ) {
                    Ok(()) | Err(_) => {}
                }
            }
        }
        let until = Instant::now() + Duration::from_secs(2);
        while self.0.pending_children() > 0 && Instant::now() < until {
            drop(self.0.reap_completed());
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}
fn runtime() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}
fn fixture() -> Result<PathBuf, Box<dyn Error>> {
    static BUILT: OnceLock<Result<PathBuf, String>> = OnceLock::new();
    BUILT
        .get_or_init(|| {
            let directory =
                std::env::temp_dir().join(format!("gnunet-process-target-{}", std::process::id()));
            std::fs::create_dir(&directory).map_err(|e| e.to_string())?;
            let binary = directory.join("target");
            let source =
                Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/process_fixture.c");
            let output = std::process::Command::new("cc")
                .arg(&source)
                .args(["-Wall", "-Wextra", "-Werror"])
                .arg("-o")
                .arg(&binary)
                .output()
                .map_err(|e| e.to_string())?;
            if !output.status.success() {
                return Err(String::from_utf8_lossy(&output.stderr).into_owned());
            }
            Ok(binary)
        })
        .clone()
        .map_err(Into::into)
}
fn command<'fd>(directory: &Directory, mode: &str) -> Result<NativeCommand<'fd>, Box<dyn Error>> {
    let environment = EnvironmentSnapshot::from_values(
        [
            (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
            (
                OsString::from("GNUNET_PROCESS_TEST_OUTPUT"),
                directory.0.join("trace").into_os_string(),
            ),
            (
                OsString::from("GNUNET_PROCESS_TEST_MODE"),
                OsString::from(mode),
            ),
        ],
        directory.0.clone(),
    )?;
    Ok(NativeCommand {
        filename: fixture()?.into_os_string(),
        argv: vec![
            OsString::from("different nonexistent argv0"),
            OsString::from("alpha beta"),
        ],
        environment,
        environment_changes: Vec::new(),
        cwd: Some(directory.0.clone()),
        stdio: 0,
        stdio_snapshot: None,
        listeners: Vec::new(),
        mappings: Vec::new(),
    })
}
fn spawn(
    command: NativeCommand<'_>,
    registry: &mut ChildRegistry,
) -> Result<Spawned, Box<dyn Error>> {
    match process::spawn(
        &Configuration::default(),
        Path::new(env!("CARGO_BIN_EXE_gnunet-arm-spawn-helper")),
        command,
        ProcessLimits::default(),
        registry,
    )? {
        SpawnResult::Admitted(value) => Ok(value),
        SpawnResult::Refused { error } => {
            Err(format!("unexpected native refusal: {error:?}").into())
        }
    }
}
async fn drain(registry: &mut ChildRegistry, child: &OriginalChild, expected: ChildExit) -> Test {
    tokio::time::timeout(Duration::from_secs(3), registry.drain_children()).await??;
    let event = registry.take_reaped().ok_or("missing actual wait")?;
    assert_eq!(&event.child, child);
    assert_eq!(event.exit, expected);
    assert_eq!(registry.pending_children(), 0);
    Ok(())
}
async fn ready(directory: &Directory) -> Test {
    let until = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        if std::fs::read_to_string(directory.0.join("trace")).is_ok_and(|s| s.contains("ready=1")) {
            return Ok(());
        }
        if tokio::time::Instant::now() >= until {
            return Err("child never published ready".into());
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}
#[test]
fn actual_filename_is_independent_of_raw_argv0_and_environment_cwd_are_preserved() -> Test {
    runtime()?.block_on(async {
        let directory = Directory::new()?;
        let mut registry = Registry::new(2)?;
        let mut cmd = command(&directory, "exit")?;
        cmd.argv[0] = OsString::from_vec(b"arbitrary\xff argv0".to_vec());
        cmd.environment_changes.push(EnvironmentChange {
            key: "GNUNET_PROCESS_TEST_VALUE".into(),
            value: Some(OsString::from_vec(vec![0xfe, 0xfd])),
        });
        let child = spawn(cmd, &mut registry.0)?.child;
        drain(&mut registry.0, &child, ChildExit::Exited(0)).await?;
        let trace = std::fs::read_to_string(directory.0.join("trace"))?;
        assert!(trace.contains("arg0=617262697472617279ff206172677630"));
        assert!(trace.contains("arg1=616c7068612062657461"));
        assert!(trace.contains("value=fefd"));
        let canonical = std::fs::canonicalize(&directory.0)?;
        let cwd = canonical
            .as_os_str()
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert!(trace.contains(&format!("cwd={cwd}")));
        Ok(())
    })
}
#[test]
fn original_multiple_listener_queues_survive_actual_helper_exec_and_parent_flags() -> Test {
    runtime()?.block_on(async {
        let directory = Directory::new()?;
        let unix = UnixListener::bind(directory.0.join("listener"))?;
        unix.set_nonblocking(true)?;
        let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        tcp.set_nonblocking(true)?;
        let mut unix_peer = UnixStream::connect(directory.0.join("listener"))?;
        unix_peer.set_read_timeout(Some(Duration::from_secs(3)))?;
        unix_peer.write_all(b"queue")?;
        let mut tcp_peer = TcpStream::connect(tcp.local_addr()?)?;
        tcp_peer.set_read_timeout(Some(Duration::from_secs(3)))?;
        tcp_peer.write_all(b"queue")?;
        let flags = |fd| nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GETFD);
        let before = [flags(unix.as_fd())?, flags(tcp.as_fd())?];
        let mut registry = Registry::new(1)?;
        let mut cmd = command(&directory, "accept")?;
        cmd.listeners = vec![unix.as_fd(), tcp.as_fd()];
        let spawned = spawn(cmd, &mut registry.0)?;
        let mut response = [0; 11];
        unix_peer.read_exact(&mut response)?;
        assert_eq!(&response, b"child:queue");
        tcp_peer.read_exact(&mut response)?;
        assert_eq!(&response, b"child:queue");
        drain(&mut registry.0, &spawned.child, ChildExit::Exited(0)).await?;
        assert_eq!(before, [flags(unix.as_fd())?, flags(tcp.as_fd())?]);
        assert!(std::fs::read_to_string(directory.0.join("trace"))?.contains("accepted=2"));
        let _new = UnixStream::connect(directory.0.join("listener"))?;
        Ok(())
    })
}
#[test]
fn overlapping_explicit_descriptor_targets_cannot_clobber_the_other_source() -> Test {
    runtime()?.block_on(async {
        let directory = Directory::new()?;
        let (read_a, mut write_a) = std::io::pipe()?;
        let (read_b, mut write_b) = std::io::pipe()?;
        write_a.write_all(b"A")?;
        write_b.write_all(b"B")?;
        let mut cmd = command(&directory, "map")?;
        cmd.environment_changes = vec![
            EnvironmentChange {
                key: "GNUNET_PROCESS_TEST_FD_A".into(),
                value: Some(read_a.as_raw_fd().to_string().into()),
            },
            EnvironmentChange {
                key: "GNUNET_PROCESS_TEST_FD_B".into(),
                value: Some(read_b.as_raw_fd().to_string().into()),
            },
        ];
        cmd.mappings = vec![
            DescriptorMap {
                source: read_a.as_fd(),
                target: read_b.as_raw_fd(),
            },
            DescriptorMap {
                source: read_b.as_fd(),
                target: read_a.as_raw_fd(),
            },
        ];
        let mut registry = Registry::new(1)?;
        let child = spawn(cmd, &mut registry.0)?.child;
        drain(&mut registry.0, &child, ChildExit::Exited(0)).await?;
        assert!(std::fs::read_to_string(directory.0.join("trace"))?.contains("map=4241"));
        Ok(())
    })
}
#[test]
fn explicit_stdin_mapping_wins_without_mutating_the_parent_stdio() -> Test {
    runtime()?.block_on(async {
        let directory = Directory::new()?;
        let (read, mut write) = std::io::pipe()?;
        write.write_all(b"raw")?;
        let mut cmd = command(&directory, "stdin")?;
        cmd.stdio = 7;
        cmd.mappings.push(DescriptorMap {
            source: read.as_fd(),
            target: 0,
        });
        let mut registry = Registry::new(1)?;
        let child = spawn(cmd, &mut registry.0)?.child;
        drain(&mut registry.0, &child, ChildExit::Exited(0)).await?;
        assert!(std::fs::read_to_string(directory.0.join("trace"))?.contains("stdin=726177"));
        Ok(())
    })
}
#[test]
fn exact_one_control_byte_and_broken_pipe_fallback_have_real_distinct_effects() -> Test {
    runtime()?.block_on(async {
        for (mode, attempt) in [
            ("control", SignalAttempt::ControlPipe),
            ("close-control", SignalAttempt::NativeKill),
        ] {
            let directory = Directory::new()?;
            let mut cmd = command(&directory, mode)?;
            cmd.stdio = 8;
            let mut registry = Registry::new(1)?;
            let spawned = spawn(cmd, &mut registry.0)?;
            let token = spawned.control.ok_or("missing actual control writer")?;
            ready(&directory).await?;
            assert_eq!(registry.0.signal_control(&token, 15)?, attempt);
            drain(
                &mut registry.0,
                &spawned.child,
                ChildExit::Signaled {
                    signal: 15,
                    core_dumped: false,
                },
            )
            .await?;
            assert!(matches!(
                registry.0.signal_control(&token, 15),
                Err(LaunchError::Stale)
            ));
        }
        Ok(())
    })
}
#[test]
fn full_nonblocking_control_pipe_really_falls_back_to_original_pid_kill() -> Test {
    runtime()?.block_on(async {
        let directory = Directory::new()?;
        let mut cmd = command(&directory, "hold-control")?;
        cmd.stdio = 8;
        let mut registry = Registry::new(1)?;
        let spawned = spawn(cmd, &mut registry.0)?;
        ready(&directory).await?;
        let until = Instant::now() + Duration::from_secs(2);
        let mut written = 0;
        loop {
            let report = registry.0.signal_report(&spawned.child, 0)?;
            match (report.attempt, report.pipe) {
                (SignalAttempt::ControlPipe, PipeWriteOutcome::Complete) => written += 1,
                (
                    SignalAttempt::NativeKill,
                    PipeWriteOutcome::Error {
                        kind: io::ErrorKind::WouldBlock,
                        ..
                    },
                ) => break,
                (
                    SignalAttempt::NativeKill,
                    PipeWriteOutcome::Error {
                        kind: io::ErrorKind::Interrupted,
                        ..
                    },
                ) => {}
                other => return Err(format!("unexpected actual pipe result: {other:?}").into()),
            }
            if Instant::now() > until {
                return Err("pipe never reached real finite EAGAIN".into());
            }
        }
        assert!(written > 0);
        assert_eq!(
            registry.0.signal(&spawned.child, 15)?,
            SignalAttempt::NativeKill
        );
        drain(
            &mut registry.0,
            &spawned.child,
            ChildExit::Signaled {
                signal: 15,
                core_dumped: false,
            },
        )
        .await?;
        Ok(())
    })
}
#[test]
fn capacity_completed_credit_and_foreign_or_retired_child_tokens_never_signal() -> Test {
    runtime()?.block_on(async {
        let directory = Directory::new()?;
        let mut registry = Registry::new(1)?;
        let child = spawn(command(&directory, "exit")?, &mut registry.0)?.child;
        tokio::time::timeout(Duration::from_secs(3), registry.0.drain_children()).await??;
        assert!(matches!(
            process::spawn(
                &Configuration::default(),
                Path::new(env!("CARGO_BIN_EXE_gnunet-arm-spawn-helper")),
                command(&directory, "exit")?,
                ProcessLimits::default(),
                &mut registry.0
            ),
            Err(LaunchError::Capacity)
        ));
        assert!(registry.0.take_reaped().is_some());
        assert!(matches!(
            registry.0.signal(&child, 0),
            Err(LaunchError::Stale)
        ));
        let other = Directory::new()?;
        let mut cmd = command(&other, "hold-control")?;
        cmd.stdio = 8;
        let spawned = spawn(cmd, &mut registry.0)?;
        let mut foreign = Registry::new(1)?;
        assert!(matches!(
            foreign.0.signal(&spawned.child, 0),
            Err(LaunchError::Stale)
        ));
        assert_ne!(spawned.child, child);
        ready(&other).await?;
        registry
            .0
            .close_control(&spawned.control.ok_or("actual control")?)?;
        assert_eq!(
            registry.0.signal(&spawned.child, 15)?,
            SignalAttempt::NativeKill
        );
        drain(
            &mut registry.0,
            &spawned.child,
            ChildExit::Signaled {
                signal: 15,
                core_dumped: false,
            },
        )
        .await?;
        Ok(())
    })
}
#[test]
fn nonexecutable_is_refused_but_late_missing_interpreter_is_real_admitted_exit_one() -> Test {
    runtime()?.block_on(async {
        let directory = Directory::new()?;
        let target = directory.0.join("target");
        std::fs::write(&target, b"#!/owned/does-not-exist\n")?;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))?;
        let mut registry = Registry::new(1)?;
        let mut cmd = command(&directory, "exit")?;
        cmd.filename = target.clone().into_os_string();
        assert!(matches!(
            process::spawn(
                &Configuration::default(),
                Path::new(env!("CARGO_BIN_EXE_gnunet-arm-spawn-helper")),
                cmd,
                ProcessLimits::default(),
                &mut registry.0
            )?,
            SpawnResult::Refused { .. }
        ));
        assert_eq!(registry.0.pending_children(), 0);
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700))?;
        let mut cmd = command(&directory, "exit")?;
        cmd.filename = target.into_os_string();
        let child = spawn(cmd, &mut registry.0)?.child;
        drain(&mut registry.0, &child, ChildExit::Exited(1)).await?;
        Ok(())
    })
}

#[test]
fn full_pipe_kill_zero_retains_the_actual_writer_for_a_later_successful_signal() -> Test {
    runtime()?.block_on(async {
        let directory = Directory::new()?;
        let release = directory.0.join("release");
        let mut command = command(&directory, "drain-control")?;
        command.stdio = 8;
        command.environment_changes.push(EnvironmentChange {
            key: "GNUNET_PROCESS_TEST_RELEASE".into(),
            value: Some(release.clone().into_os_string()),
        });
        let mut registry = Registry::new(1)?;
        let spawned = spawn(command, &mut registry.0)?;
        let token = spawned.control.ok_or("actual writer")?;
        ready(&directory).await?;
        let until = Instant::now() + Duration::from_secs(2);
        let mut bytes = 0;
        loop {
            let report = registry.0.signal_control_report(&token, 0)?;
            match (report.attempt, report.pipe) {
                (SignalAttempt::ControlPipe, PipeWriteOutcome::Complete) => bytes += 1,
                (
                    SignalAttempt::NativeKill,
                    PipeWriteOutcome::Error {
                        kind: io::ErrorKind::WouldBlock,
                        ..
                    },
                ) => break,
                (
                    SignalAttempt::NativeKill,
                    PipeWriteOutcome::Error {
                        kind: io::ErrorKind::Interrupted,
                        ..
                    },
                ) => {}
                other => return Err(format!("unexpected actual writer outcome: {other:?}").into()),
            }
            if Instant::now() > until {
                return Err("control pipe never filled".into());
            }
        }
        assert!(bytes > 0);
        assert!(registry.0.owns(&spawned.child));
        // The actual native kill(0) probe did not terminate the child. It must
        // execute new code after this file and genuinely drain the same pipe.
        std::fs::write(&release, b"drain original pipe")?;
        let until = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            if std::fs::read_to_string(directory.0.join("trace"))
                .is_ok_and(|trace| trace.contains("drained=1"))
            {
                break;
            }
            if tokio::time::Instant::now() > until {
                return Err("child did not remain alive to drain pipe after kill(0)".into());
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(
            registry.0.signal_control(&token, 0)?,
            SignalAttempt::ControlPipe
        );
        assert_eq!(
            registry.0.signal_control(&token, 15)?,
            SignalAttempt::ControlPipe
        );
        drain(
            &mut registry.0,
            &spawned.child,
            ChildExit::Signaled {
                signal: 15,
                core_dumped: false,
            },
        )
        .await?;
        let trace = std::fs::read_to_string(directory.0.join("trace"))?;
        assert!(trace.contains("control=0") && trace.contains("control=15"));
        Ok(())
    })
}

#[test]
fn directory_filename_is_admitted_before_the_actual_exec_refuses_it() -> Test {
    runtime()?.block_on(async {
        let directory = Directory::new()?;
        let mut registry = Registry::new(1)?;
        let mut command = command(&directory, "exit")?;
        command.filename = directory.0.clone().into_os_string();
        let child = spawn(command, &mut registry.0)?.child;
        drain(&mut registry.0, &child, ChildExit::Exited(1)).await
    })
}
