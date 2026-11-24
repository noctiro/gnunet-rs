//! Normal CLI binary output and real undrained private pipe retirement.
#![cfg(all(feature = "fs", any(unix, windows)))]
use std::{
    error::Error,
    fs,
    io::Read,
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};
mod support;
use support::Directory;
type Result<T> = std::result::Result<T, Box<dyn Error>>;
struct Original(Child);
impl Drop for Original {
    fn drop(&mut self) {
        let _stop = self.0.kill();
        let _joined = self.0.wait();
    }
}
fn settled(child: &mut Child, budget: Duration) -> Result<ExitStatus> {
    let until = Instant::now() + budget;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= until {
            return Err("original FS CLI did not retire within its bound".into());
        }
        thread::sleep(Duration::from_millis(10));
    }
}
fn check(value: bool) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err("normal FS CLI output contract mismatch".into())
    }
}
fn run(blocked: bool) -> Result<()> {
    let directory = Directory::create()?;
    let source = directory.path().join("source");
    let repository = directory.path().join("repository");
    fs::create_dir(&repository)?;
    // More than a native pipe buffer; includes every possible byte value.
    let expected: Vec<u8> = (0..2 * 1024 * 1024)
        .map(|index| (index % 256) as u8)
        .collect();
    fs::write(&source, &expected)?;
    let mut import = Original(
        Command::new(env!("CARGO_BIN_EXE_gnunet-cli"))
            .args(["fs", "import"])
            .arg(&repository)
            .arg(&source)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?,
    );
    check(settled(&mut import.0, Duration::from_secs(20))?.success())?;
    let mut uri = String::new();
    import
        .0
        .stdout
        .take()
        .ok_or("missing import stdout")?
        .read_to_string(&mut uri)?;
    let mut cat = Original(
        Command::new(env!("CARGO_BIN_EXE_gnunet-cli"))
            .args(["fs", "cat"])
            .arg(&repository)
            .arg(uri.trim())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?,
    );
    if blocked {
        // Keep the original pipe reader open and deliberately undrained.
        check(!settled(&mut cat.0, Duration::from_secs(12))?.success())?;
        let mut diagnostic = String::new();
        cat.0
            .stderr
            .take()
            .ok_or("missing cat stderr")?
            .read_to_string(&mut diagnostic)?;
        check(diagnostic.contains("deadline") && diagnostic.contains("pending: true"))?;
        check(!diagnostic.contains("flushed: 2097152"))?;
    } else {
        let mut output = cat.0.stdout.take().ok_or("missing cat stdout")?;
        let reader = thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = (|| -> std::io::Result<()> {
                let mut chunk = [0; 16 * 1024];
                loop {
                    let count = output.read(&mut chunk)?;
                    if count == 0 {
                        return Ok(());
                    }
                    bytes.extend_from_slice(&chunk[..count]);
                    thread::sleep(Duration::from_millis(1));
                }
            })();
            (result, bytes)
        });
        let status = settled(&mut cat.0, Duration::from_secs(20));
        if status.is_err() {
            let _stop = cat.0.kill();
            let _joined = cat.0.wait();
        }
        let (read, actual) = reader.join().map_err(|_| "output reader panicked")?;
        read?;
        check(status?.success() && actual == expected)?;
    }
    Ok(())
}
#[test]
fn binary_cat_keeps_original_pipe_bytes() -> Result<()> {
    run(false)
}
#[test]
fn undrained_cat_pipe_exits_with_pending_receipt() -> Result<()> {
    run(true)
}

#[test]
fn extraction_deadline_settles_original_worker_under_backpressure() -> Result<()> {
    let directory = Directory::create()?;
    for ordinal in 0..1024 {
        fs::write(
            directory
                .path()
                .join(format!("{ordinal:04}-{}", "n".repeat(96))),
            [],
        )?;
    }
    let mut child = Original(
        Command::new(env!("CARGO_BIN_EXE_gnunet-cli"))
            .args(["fs", "extract"])
            .arg(directory.path())
            .args(["-D", "--timeout", "2"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?,
    );
    check(!settled(&mut child.0, Duration::from_secs(12))?.success())?;
    let mut diagnostic = String::new();
    child
        .0
        .stderr
        .take()
        .ok_or("missing extraction stderr")?
        .read_to_string(&mut diagnostic)?;
    check(diagnostic.contains("joined true") && diagnostic.contains("deadline true"))?;
    check(!diagnostic.contains("fs_extract_complete"))?;
    Ok(())
}
