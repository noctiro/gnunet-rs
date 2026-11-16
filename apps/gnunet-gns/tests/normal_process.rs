//! Built GNS command: literal official IPC and exact native text output.
use std::{
    error::Error,
    ffi::OsStr,
    fs,
    io::{self, Read, Write},
    net::{Ipv4Addr, TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};
type Failure = Box<dyn Error>;
const ZONE: &[u8] =
    include_bytes!("../../../crates/gnunet-gnscrypto/tests/fixtures/pkey_ascii-zone.bin");
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
        let name = format!("gns cli {:024x}", u128::from_le_bytes(nonce));
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
                return Err("GNS command did not exit".into());
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
fn frame(stream: &mut TcpStream) -> Result<Vec<u8>, Failure> {
    let mut head = [0; 4];
    stream.read_exact(&mut head)?;
    let size = usize::from(u16::from_be_bytes([head[0], head[1]]));
    check(size >= 4, "invalid request size")?;
    let mut data = vec![0; size];
    data[..4].copy_from_slice(&head);
    stream.read_exact(&mut data[4..])?;
    Ok(data)
}

fn run(present: bool) -> Result<(), Failure> {
    let directory = Directory::new()?;
    let defaults = directory.0.join("defaults");
    fs::create_dir(&defaults)?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let config = directory.0.join("gns config.conf");
    fs::write(
        &config,
        format!(
            "[gns]\nHOSTNAME = 127.0.0.1\nPORT = {}\n",
            listener.local_addr()?.port()
        ),
    )?;
    let zone = gnunet_gns_client_host::ZoneKey::from_wire(ZONE)?;
    let mut encoded = [0; 64];
    let name = format!("testdelegation.{}", zone.write_ztld(&mut encoded)?);
    let mut command = Command::new(env!("CARGO_BIN_EXE_gnunet-gns"));
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
        .arg("-u")
        .arg(name)
        .arg("-t")
        .arg("TXT")
        .arg("-r")
        .arg("-T")
        .arg("5 s")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = Process(Some(command.spawn()?));
    let until = Instant::now() + Duration::from_secs(5);
    let (mut stream, _) = loop {
        match listener.accept() {
            Ok(accepted) => break accepted,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < until => {
                thread::sleep(Duration::from_millis(5))
            }
            Err(error) => return Err(error.into()),
        }
    };
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let request = frame(&mut stream)?;
    check(request.len() == 71, "unexpected GNS lookup size")?;
    check(
        request[2..4] == 500_u16.to_be_bytes(),
        "wrong GNS lookup type",
    )?;
    check(
        request[8..20] == [0, 0, 0, 128, 0, 0, 0, 16, 0, 0, 0, 36],
        "GNS lookup policy changed",
    )?;
    check(
        request[20..56] == *ZONE && request[56..] == *b"testdelegation\0",
        "zone or relative name changed",
    )?;
    let text = "café 🌍".as_bytes();
    let size = if present { 12 + 16 + text.len() } else { 12 };
    let mut response = u16::try_from(size)?.to_be_bytes().to_vec();
    response.extend_from_slice(&501_u16.to_be_bytes());
    response.extend_from_slice(&request[4..8]);
    response.extend_from_slice(&u32::from(present).to_be_bytes());
    if present {
        response.extend_from_slice(&u64::MAX.to_be_bytes());
        response.extend_from_slice(&u16::try_from(text.len())?.to_be_bytes());
        response.extend_from_slice(&0_u16.to_be_bytes());
        response.extend_from_slice(&16_u32.to_be_bytes());
        response.extend_from_slice(text);
    }
    for part in response.chunks(5) {
        stream.write_all(part)?;
    }
    let output = child.output()?;
    if !output.status.success() {
        return Err(format!(
            "GNS command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    check(
        output.stdout
            == if present {
                "café 🌍\n".as_bytes()
            } else {
                &[]
            },
        "raw UTF-8 output or empty answer changed",
    )?;
    Ok(())
}
#[test]
fn normal_raw_unicode_record_output() -> Result<(), Failure> {
    run(true)
}
#[test]
fn normal_empty_gns_answer_succeeds() -> Result<(), Failure> {
    run(false)
}
