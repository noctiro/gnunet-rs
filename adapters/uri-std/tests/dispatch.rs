//! Native argv and original-child retirement through the same executable fixture.
use gnunet_config::{Configuration, ProjectData};
use gnunet_native::{filesystem::Directory, os_bytes};
use gnunet_program_host::{logging::Logger, reporting::Reporter, shared_clock::SharedClock};
use gnunet_uri_host::{Bounds, CloseReport, DispatchFailure, Dispatcher, Report, Settings};
use std::{
    error::Error,
    ffi::OsStr,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;
type Outcome = std::result::Result<Report, DispatchFailure>;
struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        // Uniquely created private fixture; no external namespace administration.
        let _removed = std::fs::remove_dir_all(&self.0);
    }
}
fn scratch() -> Result<Scratch> {
    let base = std::env::temp_dir().canonicalize()?;
    let name = format!("uri-dispatch-{}", std::process::id());
    drop(Directory::open(&base)?.create_private_directory(OsStr::new(&name))?);
    Ok(Scratch(base.join(name)))
}
fn command(program: &Path, arguments: &[&OsStr]) -> Vec<u8> {
    let mut value = Vec::new();
    for word in std::iter::once(program.as_os_str()).chain(arguments.iter().copied()) {
        if !value.is_empty() {
            value.push(b' ');
        }
        value.push(b'"');
        for byte in os_bytes::encode(word).iter().copied() {
            if matches!(byte, b'\\' | b'"') {
                value.push(b'\\');
            }
            value.push(byte);
        }
        value.push(b'"');
    }
    value
}
async fn dispatch(program: &[u8], uri: &[u8]) -> Result<(Outcome, CloseReport)> {
    let mut config = Configuration::create(Arc::new(ProjectData::default()), Default::default())?;
    config.set_value(b"uri", b"gns", Some(program))?;
    let clock = SharedClock::native(64)?;
    let reporter = Reporter::new(
        Logger::new(b"uri-dispatch-test", std::process::id(), false)?,
        clock.clone(),
    );
    let bounds = Bounds::new(&clock, Duration::from_secs(10))?;
    let mut owner = Dispatcher::new(None, reporter.clone(), Arc::new(clock), Some(bounds))?;
    owner.start(Settings::from_uri(&config, uri)?)?;
    let result = owner.drive().await;
    let close = owner.close();
    if let Some(error) = reporter.take_error() {
        return Err(error.into());
    }
    Ok((result, close))
}
fn fixture() -> Result<bool> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.get(1).is_some_and(|word| word == "--capture-uri") {
        if args.len() != 4 {
            return Err("configured URI was split into extra arguments".into());
        }
        std::fs::write(&args[2], os_bytes::encode(&args[3]))?;
        return Ok(true);
    }
    #[cfg(windows)]
    if args.get(1).is_some_and(|word| word == "--exit-259") {
        exit_259();
    }
    Ok(false)
}
#[cfg(windows)]
#[expect(
    clippy::exit,
    reason = "The dedicated fixture owns no runtime or native resources and must emit the full Windows exit word259 rather than a portable u8 status"
)]
fn exit_259() -> ! {
    std::process::exit(259)
}
fn run() -> Result {
    if fixture()? {
        return Ok(());
    }
    let scratch = scratch()?;
    let output = scratch.0.join("native URI.bin");
    let executable = std::env::current_exe()?;
    let program = command(
        &executable,
        &[OsStr::new("--capture-uri"), output.as_os_str()],
    );
    let uri = "GnUnEt://gns/日本語 payload%20&|<>\"end".as_bytes();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (result, close) = runtime.block_on(dispatch(&program, uri))?;
    let report = result?;
    if !report.spawned
        || !report.status.is_some_and(|status| status.success())
        || close.report.undrained
        || close.kill.is_some()
        || close.wait.is_some()
        || std::fs::read(&output)? != uri
    {
        return Err(
            io::Error::other("original child argv/exit/retirement observations disagree").into(),
        );
    }
    #[cfg(windows)]
    {
        let program = command(&executable, &[OsStr::new("--exit-259")]);
        let (result, close) = runtime.block_on(dispatch(&program, uri))?;
        let failure = result.err().ok_or("nonzero native exit became success")?;
        if !failure
            .report
            .status
            .is_some_and(|status| status.code() == Some(259))
            || close.report.undrained
        {
            return Err("completed Windows code259 was mistaken for a running process".into());
        }
        let script = scratch.0.join("must-not-use-cmd.cmd");
        let marker = scratch.0.join("shell-was-invoked");
        std::fs::write(
            &script,
            format!("@echo unexpected>\"{}\"\r\n", marker.display()),
        )?;
        let (result, close) = runtime.block_on(dispatch(&command(&script, &[]), uri))?;
        if result.is_ok() || close.report.spawned || marker.try_exists()? {
            return Err("batch selection implicitly invoked a command interpreter".into());
        }
    }
    Ok(())
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            let _reported = writeln!(io::stderr().lock(), "URI native dispatch: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
