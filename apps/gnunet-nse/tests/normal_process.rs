//! Built NSE command over literal official IPC and native redirected stdout.
use gnunet_wire::official::{
    AbsoluteTime,
    nse::{Double, ESTIMATE_LEN, Estimate},
};
use std::{
    error::Error,
    ffi::OsStr,
    fs,
    io::{self, Read, Write},
    net::{Ipv4Addr, TcpListener},
    path::PathBuf,
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};
type Failure = Box<dyn Error>;
fn check(value: bool, message: &'static str) -> io::Result<()> {
    if value {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}
struct Directory(PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        let mut nonce = [0; 16];
        gnunet_native::entropy::fill(&mut nonce[..12])?;
        let base = fs::canonicalize(std::env::temp_dir())?;
        let name = format!("nse cli {:024x}", u128::from_le_bytes(nonce));
        gnunet_native::filesystem::Directory::open(&base)?
            .create_private_directory(OsStr::new(&name))?;
        Ok(Self(base.join(name)))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}
struct Process(Option<Child>);
impl Process {
    fn output(&mut self) -> Result<Output, Failure> {
        let until = Instant::now() + Duration::from_secs(8);
        loop {
            if self
                .0
                .as_mut()
                .ok_or("original child lost")?
                .try_wait()?
                .is_some()
            {
                return Ok(self
                    .0
                    .take()
                    .ok_or("original child lost")?
                    .wait_with_output()?);
            }
            if Instant::now() >= until {
                return Err("NSE command did not exit".into());
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _stop = child.kill();
            let _reap = child.wait();
        }
    }
}
fn run(monitor: bool) -> Result<(), Failure> {
    let directory = Directory::new()?;
    let defaults = directory.0.join("defaults");
    fs::create_dir(&defaults)?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let config = directory.0.join("nse config.conf");
    fs::write(
        &config,
        format!(
            "[nse]\nHOSTNAME = 127.0.0.1\nPORT = {}\n[nse-client-rust]\nFIRST_ESTIMATE_TIMEOUT = 5 s\nMONITOR_TIMEOUT = 2 s\n",
            listener.local_addr()?.port()
        ),
    )?;
    let mut command = Command::new(env!("CARGO_BIN_EXE_gnunet-nse"));
    command.env_clear();
    for key in [
        "SystemRoot",
        "WINDIR",
        "PATH",
        "PATHEXT",
        "TEMP",
        "TMP",
        "TMPDIR",
    ] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    command
        .env("GNUNET_BASE_CONFIG", defaults)
        .env("HOME", &directory.0)
        .env("USERPROFILE", &directory.0)
        .arg("-c")
        .arg(config)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if monitor {
        command.arg("-m");
    }
    let mut child = Process(Some(command.spawn()?));
    let until = Instant::now() + Duration::from_secs(5);
    let (mut stream, _) = loop {
        match listener.accept() {
            Ok(accepted) => break accepted,
            Err(cause) if cause.kind() == io::ErrorKind::WouldBlock && Instant::now() < until => {
                thread::sleep(Duration::from_millis(5))
            }
            Err(cause) => return Err(cause.into()),
        }
    };
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut start = [0; 4];
    stream.read_exact(&mut start)?;
    check(
        start == [0, 4, 1, 65],
        "not the literal official NSE START321",
    )?;
    let estimate = Estimate {
        timestamp: AbsoluteTime::from_micros(0),
        log2_size: Double::from_value(4.0),
        deviation: Double::from_value(1.0),
    };
    let mut encoded = [0; ESTIMATE_LEN];
    let length = estimate.encode(&mut encoded)?;
    for piece in encoded[..length].chunks(3) {
        stream.write_all(piece)?;
    }
    let output = child.output()?;
    if !output.status.success() {
        return Err(format!(
            "NSE command failed: {:?}; {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    check(output.stdout == b"1970-01-01 00:00:00 UTC: #peers=16.000000 (ld(#peers)=4.000000, stddev=1.000000)\n", "incorrect native estimate output")?;
    check(
        stream.read(&mut [0])? == 0,
        "original NSE stream did not close",
    )?;
    Ok(())
}
#[test]
fn first_estimate_uses_official_start_and_exact_native_output() -> Result<(), Failure> {
    run(false)
}
#[test]
fn completed_finite_monitor_target_succeeds_and_retires_the_original_source() -> Result<(), Failure>
{
    run(true)
}
