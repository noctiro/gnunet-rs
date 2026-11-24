//! Normal selected CLI against a controlled private TCP protocol peer.
#![cfg(all(feature = "statistics", any(unix, windows)))]
use std::{
    error::Error,
    fs::{self, File},
    io::{self, Read, Write},
    net::{Ipv4Addr, TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
mod support;
use support::Directory;
type Result<T> = std::result::Result<T, Box<dyn Error>>;
struct OriginalChild(Child);
impl Drop for OriginalChild {
    fn drop(&mut self) {
        let _termination = self.0.kill();
        let _reaped = self.0.wait();
    }
}
fn frame(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut head = [0; 4];
    stream.read_exact(&mut head)?;
    let size = usize::from(u16::from_be_bytes([head[0], head[1]]));
    if !(4..=65535).contains(&size) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut bytes = vec![0; size];
    bytes[..4].copy_from_slice(&head);
    stream.read_exact(&mut bytes[4..])?;
    Ok(bytes)
}
fn peer(listener: TcpListener, set: bool, blocked: bool) -> io::Result<()> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(5))
            }
            Err(error) => return Err(error),
        }
    };
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(if blocked { 15 } else { 5 })))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let request = frame(&mut stream)?;
    if set {
        if request != b"\0\x14\0\xa8\0\0\0\x02\0\0\0\0\0\0\0\x09s\0p\0" {
            return Err(io::Error::other("CLI SET wire mismatch"));
        }
        if frame(&mut stream)? != b"\0\x04\0\xae" {
            return Err(io::Error::other("missing CLI SET processing barrier"));
        }
        // Processing latency is independent of the client's connection retry
        // backoff. The CLI must await this real ACK rather than a local write.
        thread::sleep(Duration::from_millis(50));
        stream.write_all(b"\0\x04\0\xaf")?;
    } else {
        if request != b"\0\x08\0\xa9s\0p\0" {
            return Err(io::Error::other("CLI GET wire mismatch"));
        }
        for _ in 0..if blocked { 2048 } else { 1 } {
            stream.write_all(b"\0\x14\0\xaa\x80\0\0\0\0\0\0\0\0\0\0\x09s\0p\0")?;
        }
        stream.write_all(b"\0\x04\0\xab")?;
    }
    let mut byte = [0];
    match stream.read(&mut byte) {
        Ok(0) => Ok(()),
        Ok(_) => Err(io::Error::other("unexpected extra CLI request")),
        Err(error) if error.kind() == io::ErrorKind::ConnectionReset => Ok(()),
        Err(error) => Err(error),
    }
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Program {
    Grouped,
    Standalone,
}

fn run(program: Program, set: bool, blocked: bool) -> Result<()> {
    let directory = Directory::create()?;
    fs::create_dir(directory.path().join("config.d"))?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    fs::write(
        directory.path().join("config"),
        format!(
            "[statistics]\nHOSTNAME = 127.0.0.1\nPORT = {}\n",
            listener.local_addr()?.port()
        ),
    )?;
    let server = thread::spawn(move || peer(listener, set, blocked));
    let mut command = Command::new(match program {
        Program::Grouped => env!("CARGO_BIN_EXE_gnunet-cli"),
        Program::Standalone => env!("CARGO_BIN_EXE_gnunet-statistics"),
    });
    for (key, _) in std::env::vars_os() {
        if key.to_str().is_some_and(|key| {
            let key = key.to_ascii_uppercase();
            key.starts_with("GNUNET_") || key.starts_with("LISTEN_")
        }) {
            command.env_remove(key);
        }
    }
    match program {
        Program::Grouped => {
            command
                .args(["statistics", if set { "set" } else { "get" }, "-c"])
                .arg(directory.path().join("config"))
                .args(["-", "s", "p"]);
            if set {
                command.args(["9", "--persistent"]);
            }
        }
        Program::Standalone => {
            command
                .arg("-c")
                .arg(directory.path().join("config"))
                .args(["-s", "s", "-n", "p", "-r", "127.0.0.1", "-q", "-S", ","]);
            if set {
                command.args(["-p", "9"]);
            }
        }
    }
    let started = Instant::now();
    let mut child = OriginalChild(
        command
            .env("GNUNET_BASE_CONFIG", directory.path().join("config.d"))
            .stdin(Stdio::null())
            .stdout(if blocked {
                Stdio::piped()
            } else {
                File::create(directory.path().join("out"))?.into()
            })
            .stderr(File::create(directory.path().join("err"))?)
            .spawn()?,
    );
    let deadline = Instant::now() + Duration::from_secs(12);
    let status = loop {
        if let Some(status) = child.0.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            return Err("normal STATISTICS CLI deadline".into());
        }
        thread::sleep(Duration::from_millis(5));
    };
    let peer_result = server
        .join()
        .map_err(|_| io::Error::other("controlled peer panicked"))?;
    if let Err(peer_error) = peer_result {
        let errors = fs::read_to_string(directory.path().join("err"))?;
        return Err(format!("controlled peer: {peer_error}; CLI: {status}: {errors}").into());
    }
    if blocked {
        if status.success() {
            return Err("blocked stdout was reported as completed GET".into());
        }
        let mut output = String::new();
        child
            .0
            .stdout
            .take()
            .ok_or("original stdout pipe missing")?
            .read_to_string(&mut output)?;
        let errors = fs::read_to_string(directory.path().join("err"))?;
        if output.is_empty()
            || started.elapsed() < Duration::from_secs(9)
            || !errors.contains("deadline: true")
        {
            return Err(format!("stdout pressure was not qualified: {errors}").into());
        }
        if output.contains("statistics_end") {
            return Err("blocked GET fabricated terminal output".into());
        }
        return Ok(());
    }
    if !status.success() {
        return Err(format!(
            "CLI failed: {}",
            fs::read_to_string(directory.path().join("err"))?
        )
        .into());
    }
    let output = fs::read_to_string(directory.path().join("out"))?;
    if program == Program::Standalone {
        let expected = if set {
            String::new()
        } else {
            format!("{:16},\n", 9)
        };
        if output != expected {
            return Err(format!("unexpected standalone output: {output:?}").into());
        }
    } else if set {
        if output != "{\"event\":\"statistics_set_confirmed\"}\n" {
            return Err(format!("unexpected SET output: {output}").into());
        }
    } else if !output.contains("\"value\":9")
        || !output.ends_with("{\"event\":\"statistics_end\",\"count\":1}\n")
    {
        return Err(format!("incomplete GET output: {output}").into());
    }
    Ok(())
}
#[test]
fn configured_get_streams_value_and_real_end() -> Result<()> {
    run(Program::Grouped, false, false)
}
#[test]
fn configured_set_requires_real_processing_confirmation() -> Result<()> {
    run(Program::Grouped, true, false)
}
#[test]
fn standalone_get_uses_official_filter_and_text_output() -> Result<()> {
    run(Program::Standalone, false, false)
}
#[test]
fn standalone_set_waits_for_processing_without_a_text_receipt() -> Result<()> {
    run(Program::Standalone, true, false)
}
#[cfg(windows)]
#[test]
fn unread_output_pipe_exits_at_the_original_get_deadline() -> Result<()> {
    run(Program::Grouped, false, true)
}
