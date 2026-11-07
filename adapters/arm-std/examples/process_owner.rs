//! Finite generic process observer; signal changes occur only in this fresh exec.
#![deny(unsafe_code)]
use gnunet_arm_host::process::{
    self, ChildExit, ChildRegistry, EnvironmentChange, EnvironmentSnapshot, NativeCommand,
    ProcessLimits, SpawnResult,
};
use gnunet_config::Configuration;
use std::{
    ffi::OsString,
    io::{self, Write},
    os::{fd::OwnedFd, unix::ffi::OsStrExt},
    path::PathBuf,
    time::Duration,
};
#[expect(
    unsafe_code,
    reason = "This finite new-exec fixture changes only its own SIGPIPE profile before runtime/threads; production process port never mutates the caller's signal handler"
)]
fn profile(value: &str) -> io::Result<()> {
    // SAFETY: signal has only scalar arguments. This newly exec'd fixture owns
    // its startup disposition and runs before threads or runtime creation.
    if unsafe {
        libc::signal(
            libc::SIGPIPE,
            if value == "default" {
                libc::SIG_DFL
            } else {
                libc::SIG_IGN
            },
        )
    } == libc::SIG_ERR
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
#[expect(
    unsafe_code,
    reason = "At the start of this dedicated fixture every advertised descriptor is exclusively inherited foreign ownership, validated/deduplicated before one owning transfer"
)]
fn inherited() -> io::Result<Vec<OwnedFd>> {
    use std::os::fd::FromRawFd;
    let Some(raw) = std::env::var_os("GNUNET_PROCESS_OWNER_FDS") else {
        return Ok(Vec::new());
    };
    let mut unique = std::collections::BTreeSet::new();
    let mut descriptors = Vec::new();
    for field in raw.as_bytes().split(|byte| *byte == b':') {
        let fd = std::str::from_utf8(field)
            .ok()
            .and_then(|field| field.parse::<i32>().ok())
            .filter(|fd| *fd >= 3)
            .ok_or(io::ErrorKind::InvalidInput)?;
        if !unique.insert(fd) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        // SAFETY: this first fresh fixture phase has opened nothing; the tool
        // offers only valid original fds. The scalar query creates no FD owner.
        if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
            return Err(io::Error::last_os_error());
        }
        descriptors.push(fd);
    }
    let owned = descriptors
        .into_iter()
        .map(|fd| {
            // SAFETY: all descriptors were validated before transfer and uniquely
            // offered by the exec parent; this constructs the only Rust owner once.
            unsafe { OwnedFd::from_raw_fd(fd) }
        })
        .collect::<Vec<_>>();
    Ok(owned)
}
async fn run(
    args: Vec<OsString>,
    descriptors: Vec<OwnedFd>,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::fd::AsFd;
    if args.len() < 5 {
        return Err("filename/mode/output/stdio/profile required".into());
    }
    let mode = args[1].to_str().ok_or("mode")?;
    let flags = args[3].to_str().ok_or("flags")?.parse()?;
    let mut changes = vec![
        EnvironmentChange {
            key: "GNUNET_PROCESS_TEST_OUTPUT".into(),
            value: Some(args[2].clone()),
        },
        EnvironmentChange {
            key: "GNUNET_PROCESS_TEST_MODE".into(),
            value: Some(args[1].clone()),
        },
    ];
    if let Some(value) = std::env::var_os("GNUNET_PROCESS_OWNER_VALUE") {
        changes.push(EnvironmentChange {
            key: "GNUNET_PROCESS_TEST_VALUE".into(),
            value: Some(value),
        });
    }
    let mut registry = ChildRegistry::new(1)?;
    let helper = std::env::current_exe()?
        .parent()
        .and_then(std::path::Path::parent)
        .ok_or("debug path")?
        .join("gnunet-arm-spawn-helper");
    let command = NativeCommand {
        filename: args[0].clone(),
        argv: args[5..].to_vec(),
        environment: EnvironmentSnapshot::system()?,
        environment_changes: changes,
        cwd: None,
        stdio: flags,
        stdio_snapshot: None,
        listeners: descriptors.iter().map(|fd| fd.as_fd()).collect(),
        mappings: Vec::new(),
    };
    let child = match process::spawn(
        &Configuration::default(),
        &helper,
        command,
        ProcessLimits::default(),
        &mut registry,
    )? {
        SpawnResult::Refused { .. } => {
            writeln!(
                io::stdout(),
                "{{\"event\":\"admission\",\"admitted\":false,\"pid_positive\":false}}"
            )?;
            return Ok(());
        }
        SpawnResult::Admitted(value) => value,
    };
    writeln!(
        io::stdout(),
        "{{\"event\":\"admission\",\"admitted\":true,\"pid_positive\":true}}"
    )?;
    io::stdout().flush()?;
    if mode == "control" || mode == "close-control" {
        let until = tokio::time::Instant::now() + Duration::from_secs(3);
        while !std::fs::read_to_string(PathBuf::from(&args[2])).is_ok_and(|s| s.contains("ready=1"))
        {
            if tokio::time::Instant::now() >= until {
                return Err("target never became ready".into());
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        registry.signal(&child.child, 15)?;
        writeln!(io::stdout(), "{{\"event\":\"signal\",\"ok\":true}}")?;
        io::stdout().flush()?;
    }
    registry.drain_children().await?;
    let event = registry.take_reaped().ok_or("real wait")?;
    match event.exit {
        ChildExit::Exited(code) => writeln!(
            io::stdout(),
            "{{\"event\":\"wait\",\"exit\":{code},\"signal\":0}}"
        )?,
        ChildExit::Signaled { signal, .. } => writeln!(
            io::stdout(),
            "{{\"event\":\"wait\",\"exit\":null,\"signal\":{signal}}}"
        )?,
    };
    Ok(())
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    let descriptors = inherited()?;
    profile(args.get(4).and_then(|s| s.to_str()).ok_or("profile")?)?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run(args, descriptors))
}
