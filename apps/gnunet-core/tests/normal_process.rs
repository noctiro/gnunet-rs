//! Normal CORE executable over literal official IPC frames and private TCP peers.
//! This is a Rust process/transport regression, not a C interoperability receipt.
use std::{
    error::Error,
    ffi::OsStr,
    fs,
    io::{self, Read, Write},
    net::{Ipv4Addr, Shutdown, TcpListener},
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
        gnunet_native::entropy::fill(&mut nonce)?;
        let name = format!("core cli {:032x}", u128::from_be_bytes(nonce));
        let parent = fs::canonicalize(std::env::temp_dir())?;
        gnunet_native::filesystem::Directory::open(&parent)?
            .create_private_directory(OsStr::new(&name))?;
        Ok(Self(parent.join(name)))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}
struct Process(Option<Child>);
impl Process {
    fn output(&mut self) -> io::Result<Output> {
        let until = Instant::now() + Duration::from_secs(6);
        loop {
            let child = self
                .0
                .as_mut()
                .ok_or_else(|| io::Error::other("original process already consumed"))?;
            if child.try_wait()?.is_some() {
                return self
                    .0
                    .take()
                    .ok_or_else(|| io::Error::other("original process lost"))?
                    .wait_with_output();
            }
            if Instant::now() >= until {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "CORE executable did not exit",
                ));
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _stop = child.kill();
            let _reap = child.try_wait();
        }
    }
}
// Official core.h MonitorNotifyMessage: header, NBO state, peer[32], absolute NBO
// timeout. Message assignments 78/79 and this 48-byte layout are independently
// checked against the retained official C reference; no Rust encoder is used.
fn monitor(state: u32, peer: u8) -> [u8; 48] {
    let mut bytes = [peer; 48];
    bytes[..4].copy_from_slice(&[0, 48, 0, 79]);
    bytes[4..8].copy_from_slice(&state.to_be_bytes());
    bytes[40..48].copy_from_slice(&u64::MAX.to_be_bytes());
    bytes
}
enum Snapshot {
    Complete,
    Interrupted,
}
fn snapshot(mode: Snapshot) -> Result<(), Failure> {
    let directory = Directory::new()?;
    let defaults = directory.0.join("defaults");
    fs::create_dir(&defaults)?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let config = directory.0.join("core config.conf");
    let mut configuration = b"[PATHS]\nGNUNET_HOME = ".to_vec();
    configuration.extend_from_slice(&gnunet_native::os_bytes::encode(directory.0.as_os_str()));
    configuration.extend_from_slice(format!("\n[core]\nHOSTNAME = 127.0.0.1\nPORT = {port}\n[core-cli-rust]\nLIFETIME = 1 s\nSNAPSHOT_TIMEOUT = 1 s\nFRAME_TIMEOUT = 1 s\nIO_SLICE_BYTES = 1\n").as_bytes());
    fs::write(&config, configuration)?;
    let mut command = Command::new(env!("CARGO_BIN_EXE_gnunet-core"));
    command.env_clear();
    // Retain only ordinary OS startup context. No parent/bootstrap/logging hint
    // or unrelated GNUnet default configuration enters this private invocation.
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
        .env("HOME", &directory.0)
        .env("USERPROFILE", &directory.0)
        .env("GNUNET_BASE_CONFIG", defaults)
        .arg("-c")
        .arg(&config)
        .arg("-s")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut process = Process(Some(command.spawn()?));
    let until = Instant::now() + Duration::from_secs(4);
    let mut stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < until => {
                thread::sleep(Duration::from_millis(5))
            }
            Err(error) => return Err(error.into()),
        }
    };
    drop(listener);
    // Select the blocking I/O profile required by the fixture timeouts.
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    let mut request = [0; 4];
    stream.read_exact(&mut request)?;
    check(
        request == [0, 4, 0, 78],
        "normal CLI sent a different CORE monitor request",
    )?;
    for chunk in monitor(4, 0x42).chunks(3) {
        stream.write_all(chunk)?;
    }
    if matches!(mode, Snapshot::Complete) {
        for bytes in [monitor(999, 0x43), monitor(11, 0)] {
            for chunk in bytes.chunks(3) {
                stream.write_all(chunk)?;
            }
        }
    } else {
        stream.shutdown(Shutdown::Write)?;
    }
    check(
        stream.read(&mut [0])? == 0,
        "normal CLI left its original transport open",
    )?;
    let output = process.output()?;
    let stdout = std::str::from_utf8(&output.stdout)?;
    check(
        stdout.matches("state=4,").count() == 1,
        "original peer observation was lost or replayed",
    )?;
    match mode {
        Snapshot::Complete => {
            if !output.status.success() {
                return Err(io::Error::other(format!(
                    "CORE snapshot failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                ))
                .into());
            }
            check(
                stdout.contains("unknown state") && stdout.matches("state=999,").count() == 1,
                "future peer-state value was lost",
            )?;
        }
        Snapshot::Interrupted => check(
            !output.status.success(),
            "EOF fabricated successful snapshot completion",
        )?,
    }
    Ok(())
}
#[test]
fn normal_snapshot_keeps_fragmented_rows_and_requires_the_official_end() -> Result<(), Failure> {
    snapshot(Snapshot::Complete)
}
#[test]
fn normal_snapshot_eof_without_end_fails_and_does_not_replay_a_row() -> Result<(), Failure> {
    snapshot(Snapshot::Interrupted)
}
