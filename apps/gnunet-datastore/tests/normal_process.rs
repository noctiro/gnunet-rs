//! Built DATASTORE command over literal official IPC and backup bytes.
//! These are Rust native process regressions, not C interoperability receipts.
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
const BODY: [u8; 5] = [0, 0xff, 10, 13, 0x1a];
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
        let parent = fs::canonicalize(std::env::temp_dir())?;
        let name = format!("datastore cli {:032x}", u128::from_be_bytes(nonce));
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
        let until = Instant::now() + Duration::from_secs(8);
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
                    "DATASTORE command did not exit",
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
fn backup() -> Vec<u8> {
    let mut data = b"GNUNETDATASTORE1".to_vec();
    for word in [5_u32, 42, 7, 2, 5] {
        data.extend_from_slice(&word.to_be_bytes());
    }
    data.extend_from_slice(&u64::MAX.to_be_bytes());
    data.extend_from_slice(&[0x4d; 64]);
    data.extend_from_slice(&BODY);
    data
}
fn value(kind: u16, uid: u64) -> Vec<u8> {
    let mut frame = vec![0; 112 + BODY.len()];
    let length = u16::try_from(frame.len()).unwrap_or(0);
    frame[..2].copy_from_slice(&length.to_be_bytes());
    frame[2..4].copy_from_slice(&kind.to_be_bytes());
    for (offset, word) in [(8, 5_u32), (12, 42), (16, 7), (20, 2), (24, 5)] {
        frame[offset..offset + 4].copy_from_slice(&word.to_be_bytes());
    }
    frame[32..40].copy_from_slice(&uid.to_be_bytes());
    frame[40..48].copy_from_slice(&u64::MAX.to_be_bytes());
    frame[48..112].copy_from_slice(&[0x4d; 64]);
    frame[112..].copy_from_slice(&BODY);
    frame
}
fn frame(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut head = [0; 4];
    stream.read_exact(&mut head)?;
    let length = usize::from(u16::from_be_bytes([head[0], head[1]]));
    if !(4..=65535).contains(&length) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut bytes = vec![0; length];
    bytes[..4].copy_from_slice(&head);
    stream.read_exact(&mut bytes[4..])?;
    Ok(bytes)
}
#[derive(Clone, Copy)]
enum Mode {
    Dump,
    Insert,
    Roundtrip,
    Truncated,
}
fn run(mode: Mode) -> Result<(), Failure> {
    let directory = Directory::new()?;
    let defaults = directory.0.join("defaults");
    fs::create_dir(&defaults)?;
    let config = directory.0.join("datastore config.conf");
    let file = directory.0.join("backup file.bin");
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let mut config_bytes = b"[PATHS]\nGNUNET_HOME = ".to_vec();
    config_bytes.extend_from_slice(&gnunet_native::os_bytes::encode(directory.0.as_os_str()));
    config_bytes.extend_from_slice(
        format!(
            "\n[datastore]\nHOSTNAME = 127.0.0.1\nPORT = {}\n",
            listener.local_addr()?.port()
        )
        .as_bytes(),
    );
    fs::write(&config, config_bytes)?;
    let mut command = Command::new(env!("CARGO_BIN_EXE_gnunet-datastore"));
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
        .env("HOME", &directory.0)
        .env("USERPROFILE", &directory.0)
        .env("GNUNET_BASE_CONFIG", defaults)
        .arg("-c")
        .arg(config);
    match mode {
        Mode::Dump => {
            command.arg("-d");
        }
        Mode::Insert | Mode::Truncated => {
            command.arg("-i");
        }
        Mode::Roundtrip => {
            command.args(["-d", "-i", "-f"]).arg(&file);
        }
    }
    command
        .stdin(if matches!(mode, Mode::Insert | Mode::Truncated) {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut process = Process(Some(command.spawn()?));
    if matches!(mode, Mode::Insert | Mode::Truncated) {
        let mut bytes = backup();
        if matches!(mode, Mode::Truncated) {
            bytes.pop();
        }
        process
            .0
            .as_mut()
            .and_then(|child| child.stdin.take())
            .ok_or("original input pipe absent")?
            .write_all(&bytes)?;
    }
    if matches!(mode, Mode::Truncated) {
        let output = process.output()?;
        check(!output.status.success(), "truncated input reported success")?;
        if let Ok((mut stream, _)) = listener.accept() {
            stream.set_nonblocking(false)?;
            stream.set_read_timeout(Some(Duration::from_secs(2)))?;
            let mut data = Vec::new();
            match stream.read_to_end(&mut data) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
                Err(error) => return Err(error.into()),
            }
            let mut offset = 0;
            while offset < data.len() {
                check(
                    data.len() - offset >= 4,
                    "unexpected partial request after truncated input",
                )?;
                let length = usize::from(u16::from_be_bytes([data[offset], data[offset + 1]]));
                let kind = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
                check(
                    !matches!(kind, 92 | 93 | 95 | 102 | 103),
                    "truncated record admitted a storage mutation",
                )?;
                check(
                    length >= 4 && length <= data.len() - offset,
                    "invalid request after truncated input",
                )?;
                offset += length;
            }
        }
        return Ok(());
    }
    let until = Instant::now() + Duration::from_secs(5);
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
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(4)))?;
    stream.set_write_timeout(Some(Duration::from_secs(4)))?;
    if matches!(mode, Mode::Dump | Mode::Roundtrip) {
        for uid in [0_u64, 43] {
            let mut expected = vec![0; 20];
            expected[..4].copy_from_slice(&[0, 20, 0, 97]);
            expected[8..16].copy_from_slice(&uid.to_be_bytes());
            check(
                frame(&mut stream)? == expected,
                "dump UID cursor or request changed",
            )?;
            if uid == 0 {
                for chunk in value(100, 42).chunks(7) {
                    stream.write_all(chunk)?;
                }
            } else {
                stream.write_all(&[0, 4, 0, 101])?;
            }
        }
    }
    if matches!(mode, Mode::Insert | Mode::Roundtrip) {
        check(
            frame(&mut stream)? == value(95, 0),
            "binary backup record or PUT bytes changed",
        )?;
        let mut status = [0; 16];
        status[..4].copy_from_slice(&[0, 16, 0, 94]);
        status[4..8].copy_from_slice(&1_i32.to_be_bytes());
        stream.write_all(&status)?;
    }
    check(
        stream.read(&mut [0])? == 0,
        "original storage transport was not retired",
    )?;
    let output = process.output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "DATASTORE command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ))
        .into());
    }
    match mode {
        Mode::Dump => check(output.stdout == backup(), "stdout bytes were converted")?,
        Mode::Roundtrip => check(
            fs::read(file)? == backup(),
            "file bytes or dump-before-insert order changed",
        )?,
        _ => check(
            output.stdout.is_empty(),
            "insert wrote backup data to stdout",
        )?,
    }
    Ok(())
}
#[test]
fn normal_dump_keeps_binary_stdout() -> Result<(), Failure> {
    run(Mode::Dump)
}
#[test]
fn normal_insert_keeps_binary_stdin() -> Result<(), Failure> {
    run(Mode::Insert)
}
#[test]
fn normal_file_roundtrip_dumps_before_importing() -> Result<(), Failure> {
    run(Mode::Roundtrip)
}
#[test]
fn normal_truncated_input_admits_no_mutation() -> Result<(), Failure> {
    run(Mode::Truncated)
}
