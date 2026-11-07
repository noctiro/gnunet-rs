//! Actual ARM host local-start probe. Every parent signal/stdio change occurs
//! only in this newly exec'd isolated process, never the orchestrating task.
#![deny(unsafe_code)]
#[path = "../../resolver-broker-std/tests/support/domain.rs"]
mod resolution_domain;
use gnunet_arm_core::{
    FrameSlot,
    client::{Client, ConnectionStatus, Event, Inbound, OperationSlot, StdioInheritance},
    wire::ArmAbi,
};
use gnunet_arm_host::{
    ChildRegistry, ClientHost, Clock, LaunchLimits, Limits, LocalLauncher, Progress,
    launch::ChildExit,
};
use gnunet_config::{Configuration, ProjectData};
use std::{
    ffi::OsString,
    io::{self, Write},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::time::Instant;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
#[expect(
    unsafe_code,
    reason = "Only this isolated fresh-exec test caller sets its own SIGPIPE profile before runtime/threads; production launch only queries inherited state"
)]
fn profile(value: &str) -> io::Result<()> {
    if value == "inherit" {
        return Ok(());
    }
    let handler = match value {
        "ignore" => libc::SIG_IGN,
        "default" => libc::SIG_DFL,
        _ => return Err(io::ErrorKind::InvalidInput.into()),
    };
    // SAFETY: native integer/signal-set storage admits zero; sigemptyset below
    // initializes its mask. This is this test process, not the task parent.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: writable valid native sigset output.
    if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0 {
        return Err(io::Error::last_os_error());
    }
    action.sa_sigaction = handler;
    // SAFETY: initialized action applies only to this new private parent.
    if unsafe { libc::sigaction(libc::SIGPIPE, &action, std::ptr::null_mut()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut mask = nix::sys::signal::SigSet::empty();
    mask.add(nix::sys::signal::Signal::SIGUSR1);
    nix::sys::signal::pthread_sigmask(nix::sys::signal::SigmaskHow::SIG_BLOCK, Some(&mask), None)?;
    Ok(())
}
#[expect(
    unsafe_code,
    reason = "This new-exec fixture exclusively controls original stdio; record/config/runtime/SIGCHLD resources are already open above2 and no Rust OwnedFd refers to a stdio slot"
)]
fn closed_stdio(close: u8, cloexec: u8) -> io::Result<()> {
    if close > 7 || cloexec > 7 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    for fd in 0..3 {
        if close & (1 << fd) != 0 {
            // SAFETY: only an original foreign stdio slot is closed, once, in
            // this fixture process; all runtime/record owners have different fds.
            if unsafe { libc::close(fd) } != 0 {
                return Err(io::Error::last_os_error());
            }
        } else if cloexec & (1 << fd) != 0 {
            // SAFETY: integer-only query/change of this fixture's open stdio,
            // without moving/creating a Rust descriptor owner.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            if flags < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: the preceding read confirmed this fixture's original
            // stdio descriptor is open; only its own CLOEXEC flag changes.
            if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}
fn emit(record: &mut dyn Write, failure: &mut Option<io::Error>, line: std::fmt::Arguments<'_>) {
    if let Err(error) = record
        .write_fmt(line)
        .and_then(|()| record.write_all(b"\n"))
    {
        *failure = Some(error);
    }
}
async fn run(args: Vec<OsString>) -> Result<()> {
    let mut domain = resolution_domain::Domain::new(Configuration::default())?;
    domain.start()?;
    let file = PathBuf::from(args.first().ok_or("config")?);
    let mode = args.get(1).and_then(|s| s.to_str()).ok_or("mode")?;
    let flags: u32 = args
        .get(2)
        .and_then(|s| s.to_str())
        .ok_or("stdio flags")?
        .parse()?;
    let helper = PathBuf::from(args.get(4).ok_or("helper")?);
    let close: u8 = args
        .get(6)
        .and_then(|s| s.to_str())
        .unwrap_or("0")
        .parse()?;
    let cloexec: u8 = args
        .get(7)
        .and_then(|s| s.to_str())
        .unwrap_or("0")
        .parse()?;
    if (close != 0 || cloexec != 0) && args.get(5).is_none() {
        return Err("stdio fixture requires an independent record file".into());
    }
    let mut record: Box<dyn Write> = if let Some(path) = args.get(5) {
        Box::new(std::fs::File::create(path)?)
    } else {
        Box::new(io::stdout())
    };
    let mut cfg = Configuration::create(Arc::new(ProjectData::default()), Default::default())?;
    cfg.parse(file)?;
    domain.context.connect(cfg.duplicate()?)?;
    let mut registry = ChildRegistry::new(16)?;
    let mut ops = [OperationSlot::EMPTY; 16];
    let mut slots = [FrameSlot::EMPTY; 32];
    let mut pool = [0; 65536];
    let core = Client::new(&mut ops, &mut slots, &mut pool, 1, ArmAbi::U64Align8)?;
    let launcher = LocalLauncher::new(
        cfg.duplicate()?,
        helper,
        LaunchLimits::default(),
        &mut registry,
    )?;
    let mut host = ClientHost::connect(
        core,
        cfg,
        domain.resolution(),
        launcher,
        Limits::default(),
        Clock::system()?,
        |_| {},
    )?;
    closed_stdio(close, cloexec)?;
    let start = Instant::now();
    let operation = host.request_service_start(b"arm", StdioInheritance(flags))?;
    let until = start
        + if mode == "start" {
            Duration::from_secs(72)
        } else {
            Duration::from_millis(20)
        };
    let mut callbacks = 0;
    let mut canceled = false;
    let mut failure = None;
    loop {
        let progress=host.drive(Some(until),|event,_|match event{
            Inbound::Event(Event::Result{status,result,..})=>{callbacks+=1;if let Some(path)=std::env::var_os("ARM_COMMAND_RELEASE"){emit(&mut record,&mut failure,format_args!("{{\"event\":\"callback-release\",\"release_observed\":{}}}",PathBuf::from(path).exists()));}
 if let Some(path)=std::env::var_os("ARM_COMMAND_ACK") && let Err(error)=std::fs::File::create(path){failure=Some(error);}
 emit(&mut record,&mut failure,format_args!("{{\"event\":\"result\",\"status\":{},\"result\":{},\"elapsed_us\":{}}}",status as u32,result.map_or_else(||"null".to_string(),|r|r.0.to_string()),start.elapsed().as_micros()));},
            Inbound::Event(Event::Connection(status))=>emit(&mut record,&mut failure,format_args!("{{\"event\":\"connection\",\"status\":{}}}",match status{ConnectionStatus::Connected=>1,ConnectionStatus::Disconnected=>0,ConnectionStatus::Error=>-1})),_=>{}}).await?;
        if callbacks > 0 {
            break;
        }
        if progress == Progress::WaitDeadline {
            if mode == "start" {
                return Err("watchdog".into());
            }
            canceled = true;
            if mode == "cancel" {
                host.operation_cancel(operation)?;
                writeln!(record, "{{\"event\":\"cancel\"}}")?;
            }
            break;
        }
    }
    host.disconnect(|event, _| {
        if let Inbound::Event(Event::Result { status, result, .. }) = event {
            callbacks += 1;
            emit(
                &mut record,
                &mut failure,
                format_args!(
                    "{{\"event\":\"result\",\"status\":{},\"result\":{},\"elapsed_us\":{}}}",
                    status as u32,
                    result.map_or_else(|| "null".to_string(), |r| r.0.to_string()),
                    start.elapsed().as_micros()
                ),
            );
        }
    })?;
    drop(host);
    registry.drain_children().await?;
    let mut children = 0;
    while let Some(reaped) = registry.take_reaped() {
        children += 1;
        match reaped.exit {
            ChildExit::Exited(code) => writeln!(
                record,
                "{{\"event\":\"reaped\",\"pid\":{},\"exit\":{code},\"signal\":0}}",
                reaped.pid
            )?,
            ChildExit::Signaled { signal, .. } => writeln!(
                record,
                "{{\"event\":\"reaped\",\"pid\":{},\"exit\":null,\"signal\":{signal}}}",
                reaped.pid
            )?,
        }
    }
    if let Some(error) = failure {
        return Err(error.into());
    }
    writeln!(
        record,
        "{{\"event\":\"done\",\"callbacks\":{callbacks},\"canceled\":{canceled},\"children\":{children},\"failed\":0}}"
    )?;
    record.flush()?;
    Ok(())
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let value = args
        .get(3)
        .and_then(|s| s.to_str())
        .ok_or("signal profile")?;
    profile(value)?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run(args))
}
