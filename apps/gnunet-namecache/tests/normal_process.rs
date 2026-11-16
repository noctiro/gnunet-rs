//! Built command over literal official IPC; published public-zone vectors only.
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
const BLOCK: &[u8] =
    include_bytes!("../../../crates/gnunet-gnscrypto/tests/fixtures/pkey_ascii-block.bin");
const QUERY: &[u8] =
    include_bytes!("../../../crates/gnunet-gnscrypto/tests/fixtures/pkey_ascii-query.bin");
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
        let name = format!("nc cli {:024x}", u128::from_le_bytes(nonce));
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
                return Err("NAMECACHE command did not exit".into());
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
#[derive(Clone, Copy)]
enum Reply {
    Block,
    Missing,
    RejectedDelete,
    Corrupt,
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
fn run(reply: Reply) -> Result<(), Failure> {
    let directory = Directory::new()?;
    let defaults = directory.0.join("defaults");
    fs::create_dir(&defaults)?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let config = directory.0.join("namecache config.conf");
    fs::write(
        &config,
        format!(
            "[namecache]\nHOSTNAME = 127.0.0.1\nPORT = {}\n",
            listener.local_addr()?.port()
        ),
    )?;
    let zone = gnunet_gnsrecord::ZoneKey::from_wire(ZONE)?;
    let mut zone_text = [0; 64];
    let mut command = Command::new(env!("CARGO_BIN_EXE_gnunet-namecache"));
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
        .arg("-z")
        .arg(zone.write_ztld(&mut zone_text)?)
        .arg("-n")
        .arg("testdelegation")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if matches!(reply, Reply::RejectedDelete) {
        command.arg("-d");
    }
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
    check(
        request.len() == 72 && request[8..] == *QUERY,
        "command derived a different public query",
    )?;
    let mut response = if matches!(reply, Reply::RejectedDelete) {
        check(
            request[2..4] == 1850_u16.to_be_bytes(),
            "delete sent wrong operation",
        )?;
        let mut data = vec![0, 12, 7, 59];
        data.extend_from_slice(&request[4..8]);
        data.extend_from_slice(&(-7_i32).to_be_bytes());
        data
    } else {
        check(
            request[2..4] == 431_u16.to_be_bytes(),
            "lookup sent wrong operation",
        )?;
        let block = if matches!(reply, Reply::Missing) {
            &[][..]
        } else {
            BLOCK
        };
        let size = u16::try_from(16 + block.len())?;
        let mut data = size.to_be_bytes().to_vec();
        data.extend_from_slice(&432_u16.to_be_bytes());
        data.extend_from_slice(&request[4..8]);
        data.extend_from_slice(if block.is_empty() {
            &[0; 8]
        } else {
            &BLOCK[104..112]
        });
        data.extend_from_slice(block);
        data
    };
    if matches!(reply, Reply::Corrupt) {
        *response.last_mut().ok_or("empty block")? ^= 1;
    }
    for part in response.chunks(5) {
        stream.write_all(part)?;
    }
    let output = child.output()?;
    match reply {
        Reply::Block => {
            check(output.status.success(), "verified block display failed")?;
            let text = std::str::from_utf8(&output.stdout)?;
            check(
                text.contains("192.0.2.1") && text.contains("interop"),
                "verified records were not displayed",
            )?;
        }
        Reply::Missing => check(
            output.status.success() && output.stdout.starts_with(b"No matching block found"),
            "missing block outcome changed",
        )?,
        Reply::RejectedDelete => check(
            !output.status.success()
                && String::from_utf8_lossy(&output.stdout).contains("result=-7"),
            "signed delete failure was lost",
        )?,
        Reply::Corrupt => check(
            !output.status.success() && output.stdout.is_empty(),
            "corrupt block exposed plaintext or succeeded",
        )?,
    }
    Ok(())
}
#[test]
fn normal_public_lookup_verifies_and_decrypts() -> Result<(), Failure> {
    run(Reply::Block)
}
#[test]
fn normal_lookup_preserves_absence() -> Result<(), Failure> {
    run(Reply::Missing)
}
#[test]
fn normal_delete_preserves_signed_failure() -> Result<(), Failure> {
    run(Reply::RejectedDelete)
}
#[test]
fn normal_corrupt_lookup_exposes_no_plaintext() -> Result<(), Failure> {
    run(Reply::Corrupt)
}
