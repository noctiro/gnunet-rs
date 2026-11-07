//! Actual service processes, independent official IPC and durable restarts.
#![cfg(unix)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible process tests assert actual IPC, persisted bytes and failure cleanup"
)]

use std::{
    error::Error,
    fs::{self, File},
    io::{self, Read, Write},
    os::unix::{fs::DirBuilderExt, net::UnixStream},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
type Result<T> = std::result::Result<T, Box<dyn Error>>;

struct Directory(PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "gnunet-stats-process-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        fs::write(
            path.join("service.conf"),
            format!(
                "[statistics]\nUNIXPATH = {}\nDATABASE = {}\n",
                path.join("statistics.sock").display(),
                path.join("statistics.dat").display()
            ),
        )?;
        Ok(Self(path))
    }
    fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
    fn spawn(&self, attempt: u32) -> io::Result<OwnedChild> {
        let output = self.file(&format!("stdout-{attempt}"));
        let errors = self.file(&format!("stderr-{attempt}"));
        let child = Command::new(env!("CARGO_BIN_EXE_gnunet-service-statistics"))
            .arg("-c")
            .arg(self.file("service.conf"))
            .stdin(Stdio::null())
            .stdout(File::create(&output)?)
            .stderr(File::create(&errors)?)
            .spawn()?;
        Ok(OwnedChild(child, output, errors))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        match fs::remove_dir_all(&self.0) {
            Ok(()) | Err(_) => {}
        }
    }
}
struct OwnedChild(Child, PathBuf, PathBuf);
impl OwnedChild {
    fn ready(&mut self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if fs::read_to_string(&self.1).is_ok_and(|text| {
                text.lines()
                    .any(|line| line.starts_with("READY statistics "))
            }) {
                return Ok(());
            }
            if let Some(status) = self.0.try_wait()? {
                return Err(format!(
                    "service exited before readiness: {status}: {}",
                    fs::read_to_string(&self.2).unwrap_or_default()
                )
                .into());
            }
            if Instant::now() >= deadline {
                return Err("service readiness deadline".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn wait(&mut self) -> Result<ExitStatus> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.0.try_wait()? {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err("service shutdown deadline".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        match self.0.kill() {
            Ok(()) | Err(_) => {}
        }
        match self.0.wait() {
            Ok(_) | Err(_) => {}
        }
    }
}
fn connect(path: &Path) -> io::Result<UnixStream> {
    let stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    Ok(stream)
}

#[test]
fn signal_shutdown_persists_only_official_persistent_records_and_restarts() -> Result<()> {
    let directory = Directory::new()?;
    let mut child = directory.spawn(1)?;
    child.ready()?;
    let mut stream = connect(&directory.file("statistics.sock"))?;
    stream.write_all(b"\0\x14\0\xa8\0\0\0\x02\0\0\0\0\0\0\0\x09s\0p\0\0\x14\0\xa8\0\0\0\0\0\0\0\0\0\0\0\x07s\0q\0\0\x04\0\xae")?;
    let mut ack = [0; 4];
    stream.read_exact(&mut ack)?;
    assert_eq!(&ack, b"\0\x04\0\xaf");
    drop(stream);
    // Only this live, owned child is signalled.
    assert!(
        Command::new("kill")
            .arg("-TERM")
            .arg(child.0.id().to_string())
            .status()?
            .success()
    );
    assert!(child.wait()?.success());
    assert!(fs::read_to_string(&child.1)?.contains("STOPPED statistics "));
    assert!(!directory.file("statistics.sock").exists());
    assert_eq!(
        fs::read(directory.file("statistics.dat"))?,
        b"\0\x14\0\xa8\0\0\0\x02\0\0\0\0\0\0\0\x09s\0p\0"
    );

    let mut restarted = directory.spawn(2)?;
    restarted.ready()?;
    let mut stream = connect(&directory.file("statistics.sock"))?;
    stream.write_all(b"\0\x06\0\xa9\0\0")?;
    let mut reply = [0; 24];
    stream.read_exact(&mut reply)?;
    assert_eq!(
        &reply,
        b"\0\x14\0\xaa\x80\0\0\0\0\0\0\0\0\0\0\x09s\0p\0\0\x04\0\xab"
    );
    drop(stream);
    assert!(
        Command::new("kill")
            .arg("-TERM")
            .arg(restarted.0.id().to_string())
            .status()?
            .success()
    );
    assert!(restarted.wait()?.success());
    assert!(fs::read_to_string(&restarted.1)?.contains("STOPPED statistics "));
    assert!(!directory.file("statistics.sock").exists());
    Ok(())
}

#[test]
fn malformed_database_and_existing_socket_file_fail_before_ready() -> Result<()> {
    let directory = Directory::new()?;
    fs::write(directory.file("statistics.dat"), b"\0\x14\0\xa8partial")?;
    let mut malformed = directory.spawn(1)?;
    assert!(!malformed.wait()?.success());
    assert!(!fs::read_to_string(&malformed.1)?.contains("READY statistics "));
    assert!(!directory.file("statistics.sock").exists());
    assert_eq!(
        fs::read(directory.file("statistics.dat"))?,
        b"\0\x14\0\xa8partial"
    );
    fs::remove_file(directory.file("statistics.dat"))?;
    fs::write(directory.file("statistics.sock"), b"unrelated file")?;
    let mut occupied = directory.spawn(2)?;
    assert!(!occupied.wait()?.success());
    assert!(!fs::read_to_string(&occupied.1)?.contains("READY statistics "));
    assert_eq!(
        fs::read(directory.file("statistics.sock"))?,
        b"unrelated file"
    );
    Ok(())
}
