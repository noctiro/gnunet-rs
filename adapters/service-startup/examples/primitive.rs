//! Exec-only native probe; never invoke credential operations in the parent task.
#![deny(unsafe_code)]
use gnunet_service_startup::{
    self as startup, GroupsProfile, Identity, InheritedMode, InheritedResources, PrivilegeRoute,
    ReadyStatus, ReadyWriter,
};
use std::{
    error::Error,
    fs::{self, File},
    io::{self, Read, Write},
    os::fd::AsRawFd,
    path::Path,
    process::ExitCode,
};
fn opt(n: Option<i32>) -> String {
    n.map_or_else(|| "null".into(), |n| n.to_string())
}
fn ids(i: Identity) -> String {
    format!("[{}, {}, {}, {}]", i.uid, i.euid, i.gid, i.egid)
}
fn persist(path: &Path, json: &str) -> io::Result<()> {
    fs::write(path, format!("{json}\n"))
}
#[expect(
    unsafe_code,
    reason = "Read-only integer F_GETFD probes only this exec child's declared descriptor state"
)]
fn open(fd: i32) -> bool {
    // SAFETY: F_GETFD consumes an integer only and reports invalid descriptors.
    unsafe { libc::fcntl(fd, libc::F_GETFD) >= 0 }
}
#[expect(
    unsafe_code,
    reason = "This isolated-child observation borrows only validated live standard descriptors for read-only fstat; it never adopts or closes them"
)]
fn is_null(fd: i32) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: all three stdio descriptors were open in the fixture and capture
    // restores every moved slot before returning; there is no concurrent close.
    let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
    let actual = nix::sys::stat::fstat(borrowed)?;
    let null = fs::metadata("/dev/null")?;
    Ok(actual.st_rdev as u64 == null.rdev() && actual.st_mode & libc::S_IFMT == libc::S_IFCHR)
}
fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let action = args.first().and_then(|s| s.to_str()).ok_or("action")?;
    let output = Path::new(args.get(1).ok_or("output")?);
    if action == "ready" || action == "ready-error" {
        let (read, write) = nix::unistd::pipe()?;
        let raw = write.as_raw_fd();
        let status = match args.get(2).and_then(|s| s.to_str()) {
            Some(".") => ReadyStatus::AcceptRegistered,
            Some("I") => ReadyStatus::InitializationFailed,
            Some("S") => ReadyStatus::ServerNotStarted,
            _ => return Err("status".into()),
        };
        if action == "ready-error" {
            drop(read);
            let result = ReadyWriter::from_owned(write).signal(status);
            persist(
                output,
                &format!(
                    "{{\"ok\":{},\"errno\":{},\"released_fd_closed\":{}}}",
                    result.is_ok(),
                    opt(result.err().and_then(|e| e.raw_os_error())),
                    !open(raw)
                ),
            )?;
        } else {
            ReadyWriter::from_owned(write).signal(status)?;
            let mut received = Vec::new();
            File::from(read).read_to_end(&mut received)?;
            persist(
                output,
                &format!(
                    "{{\"ok\":true,\"bytes\":{:?},\"released_fd_closed\":{}}}",
                    received,
                    !open(raw)
                ),
            )?;
        }
        return Ok(());
    }
    if action == "privilege" {
        let before = Identity::current();
        let name = args.get(2).ok_or("username or -")?;
        let plan = if name == "-" {
            None
        } else {
            match startup::resolve_user(name) {
                Ok(p) => Some(p),
                Err(_) => {
                    persist(
                        output,
                        &format!(
                            "{{\"ok\":false,\"lookup_failed\":true,\"before\":{},\"after\":{}}}",
                            ids(before),
                            ids(Identity::current())
                        ),
                    )?;
                    return Ok(());
                }
            }
        };
        let profile = if args.get(3).is_some_and(|p| p == "no-initgroups") {
            GroupsProfile::WithoutInitgroups
        } else {
            GroupsProfile::WithInitgroups
        };
        match startup::apply_privileges(plan.as_ref(), profile) {
            Ok(r) => {
                let (route, failed) = match r.route {
                    PrivilegeRoute::Unchanged => ("unchanged", "null".into()),
                    PrivilegeRoute::Primary => ("primary", "null".into()),
                    PrivilegeRoute::Fallback { failed_stage, .. } => {
                        ("fallback", format!("\"{failed_stage:?}\""))
                    }
                };
                persist(
                    output,
                    &format!(
                        "{{\"ok\":true,\"route\":\"{route}\",\"primary_failed\":{failed},\"groups_initialized\":{},\"before\":{},\"after\":{}}}",
                        r.groups_initialized,
                        ids(r.before),
                        ids(r.after)
                    ),
                )?;
            }
            Err(e) => {
                persist(
                    output,
                    &format!(
                        "{{\"ok\":false,\"apply_failed\":true,\"before\":{},\"after\":{}}}",
                        ids(before),
                        ids(Identity::current())
                    ),
                )?;
                return Err(e.into());
            }
        }
        return Ok(());
    }
    if action == "original-cloexec" {
        #[expect(
            unsafe_code,
            reason = "The isolated fixture borrows its exclusively inherited test fd only to set the original flag before capture validation; no owning handle is constructed"
        )]
        // SAFETY: the exec-child parent exclusively offers open fd128 and no
        // other owner/close/reuse exists before the one-shot capture below.
        let fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(128) };
        nix::fcntl::fcntl(
            fd,
            nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
        )?;
    }
    let mode = if action == "adopt" {
        InheritedMode::AdoptListeners
    } else {
        InheritedMode::CloseAfterConfiguredBind
    };
    #[expect(
        unsafe_code,
        reason = "This probe is a newly exec'd child and capture precedes every file/runtime/diagnostic open; pass_fds transfers its unique foreign descriptor set"
    )]
    // SAFETY: the isolated parent offers exclusive child descriptors; no runtime,
    // files, logging or other fd owners exist and this is the only capture call.
    let captured = unsafe { startup::capture_from_environment(mode) };
    let mut captured = match captured {
        Ok(c) => c,
        Err(e) => {
            persist(
                output,
                &format!(
                    "{{\"ok\":false,\"capture_error\":\"{:?}\",\"errno\":{},\"original_128_still_open\":{}}}",
                    e.kind(),
                    opt(e.raw_os_error()),
                    open(128)
                ),
            )?;
            return Ok(());
        }
    };
    if action == "control" {
        let signal = captured
            .parent_control
            .as_mut()
            .ok_or("no control")?
            .try_read_signal()?;
        persist(
            output,
            &format!("{{\"ok\":true,\"signal\":{}}}", opt(signal.map(i32::from))),
        )?;
        return Ok(());
    }
    if action == "twice" {
        #[expect(
            unsafe_code,
            reason = "A repeated call is intentionally tested: the one-shot guard rejects it before environment or descriptors can be touched"
        )]
        // SAFETY: identical isolated early-child context; rejection precedes
        // any second descriptor ownership transfer by the function's contract.
        let second = unsafe { startup::capture_from_environment(mode) };
        persist(
            output,
            &format!("{{\"ok\":true,\"second_rejected\":{}}}", second.is_err()),
        )?;
        return Ok(());
    }
    let inherited = captured.inherited;
    match inherited {
        InheritedResources::Listeners(a) => {
            let n = a.sockets.len();
            drop(a);
            persist(
                output,
                &format!("{{\"ok\":true,\"adopted_listeners\":{n}}}"),
            )?;
        }
        InheritedResources::CloseAfterBind(hold) => {
            let count = hold.len();
            if action == "bind" || action == "bind-user" {
                let config_path = Path::new(args.get(2).ok_or("config")?);
                let mut config = gnunet_config::Configuration::new(Default::default());
                config.deserialize(&fs::read(config_path)?, Some(config_path))?;
                let bound = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?
                    .block_on(gnunet_service_runtime::BoundListeners::bind(
                        &config,
                        b"probe",
                        Default::default(),
                    ));
                match bound {
                    Ok(bound) => {
                        let report = hold.complete_after_bind(&bound);
                        if action == "bind-user" {
                            let user = startup::configured_user(&config, b"probe")?;
                            let applied = user
                                .as_ref()
                                .map(|name| startup::resolve_user(name))
                                .transpose()
                                .and_then(|plan| {
                                    startup::apply_privileges(
                                        plan.as_ref(),
                                        GroupsProfile::WithInitgroups,
                                    )
                                });
                            if applied.is_err() {
                                drop(bound);
                                persist(
                                    output,
                                    &format!(
                                        "{{\"ok\":false,\"released\":{},\"phase\":\"{:?}\",\"user_failed\":true,\"ids\":{}}}",
                                        report.owned_descriptors_released,
                                        report.phase,
                                        ids(Identity::current())
                                    ),
                                )?;
                                return Ok(());
                            }
                        }
                        drop(bound);
                        persist(
                            output,
                            &format!(
                                "{{\"ok\":true,\"released\":{},\"phase\":\"{:?}\"}}",
                                report.owned_descriptors_released, report.phase
                            ),
                        )?;
                    }
                    Err(_) => {
                        let report = hold.abort();
                        persist(
                            output,
                            &format!(
                                "{{\"ok\":false,\"released\":{},\"phase\":\"{:?}\"}}",
                                report.owned_descriptors_released, report.phase
                            ),
                        )?;
                    }
                }
            } else if action == "reuse" {
                let target = args
                    .get(2)
                    .and_then(|s| s.to_str())
                    .ok_or("target fd")?
                    .parse::<i32>()?;
                let report = hold.abort();
                let mut newfiles = Vec::new();
                let reused = loop {
                    let file = File::open("/dev/null")?;
                    let raw = file.as_raw_fd();
                    newfiles.push(file);
                    if raw == target {
                        break true;
                    }
                    if raw > target || newfiles.len() > 2048 {
                        break false;
                    }
                };
                persist(
                    output,
                    &format!(
                        "{{\"ok\":true,\"released\":{},\"reused\":{},\"replacement_open\":{}}}",
                        report.owned_descriptors_released,
                        reused,
                        open(target)
                    ),
                )?;
            } else {
                let report = hold.abort();
                persist(
                    output,
                    &format!(
                        "{{\"ok\":true,\"released\":{},\"phase\":\"{:?}\",\"stdio_open\":[{},{},{}],\"stdio_null\":[{},{},{}]}}",
                        count,
                        report.phase,
                        open(0),
                        open(1),
                        open(2),
                        is_null(0)?,
                        is_null(1)?,
                        is_null(2)?
                    ),
                )?;
            }
        }
    }
    Ok(())
}
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let _diagnostic = writeln!(io::stderr().lock(), "startup native probe: {e}");
            ExitCode::FAILURE
        }
    }
}
