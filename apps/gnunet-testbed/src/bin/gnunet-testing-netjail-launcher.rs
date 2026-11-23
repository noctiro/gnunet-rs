//! Installed launcher for the Linux GNUnet TESTING fixture.
use std::{
    io::{self, Write},
    process::ExitCode,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _report = writeln!(
                io::stderr().lock(),
                "gnunet-testing-netjail-launcher: {error}"
            );
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    Err("netjail requires Linux network namespaces".into())
}

#[cfg(target_os = "linux")]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    use gnunet_testbed_host::testing::{
        Helper,
        netjail::{Netjail, enter_fixture_user_namespace},
        topology::Topology,
    };
    use std::{
        ffi::OsStr,
        fs::OpenOptions,
        io::Read,
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
        path::PathBuf,
        process::Command,
        time::Duration,
    };
    use tokio::time::Instant;

    // Four header bytes, four barrier-count bytes, and the final C string NUL.
    const MAX_TOPOLOGY: usize = u16::MAX as usize - 9;
    const USAGE: &str = "Usage: gnunet-testing-netjail-launcher [--current-user-namespace] [--helper ABSOLUTE_PATH] FILE\n       gnunet-testing-netjail-launcher [--current-user-namespace] [--helper ABSOLUTE_PATH] -s TOPOLOGY";
    let mut args = std::env::args_os().skip(1);
    let mut source = args.next().ok_or(USAGE)?;
    if source == "-h" || source == "--help" {
        writeln!(io::stdout().lock(), "{USAGE}")?;
        return Ok(());
    }
    let current_user_namespace = source == "--current-user-namespace";
    if current_user_namespace {
        source = args.next().ok_or(USAGE)?;
    }
    let helper = if source == "--helper" {
        let path = args.next().ok_or(USAGE)?;
        source = args.next().ok_or(USAGE)?;
        PathBuf::from(path)
    } else {
        gnunet_config::ProjectData::default().libexec_binary_path(b"gnunet-cmds-helper")?
    };
    if !helper.is_absolute() {
        return Err("the test helper path must be absolute".into());
    }
    let source = if source == "-s" { None } else { Some(source) };
    let topology = if let Some(path) = source {
        if args.next().is_some() {
            return Err(USAGE.into());
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)?;
        if !file.metadata()?.is_file() {
            return Err("the netjail topology must be a regular file".into());
        }
        let mut bytes = Vec::new();
        file.take((MAX_TOPOLOGY + 1) as u64)
            .read_to_end(&mut bytes)?;
        bytes
    } else {
        let text = args.next().ok_or(USAGE)?;
        if args.next().is_some() {
            return Err(USAGE.into());
        }
        OsStr::as_encoded_bytes(&text).to_vec()
    };
    if topology.len() > MAX_TOPOLOGY {
        return Err("topology exceeds the official helper frame limit".into());
    }
    let topology = Topology::parse(&topology)?;
    let metadata = std::fs::metadata(&helper)?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err("the test helper must be an executable file".into());
    }
    if !current_user_namespace {
        enter_fixture_user_namespace()?;
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let deadline = Instant::now() + Duration::from_secs(600);
    let fixture = Netjail::provision(&topology, deadline)?;
    runtime.block_on(fixture.run(|peer| {
        let mut command = Command::new(&helper);
        command.arg(peer.helper_id());
        Helper::new(command, &[])
    }))?;
    Ok(())
}
