use super::*;
use std::sync::Mutex;
fn check(value: bool) -> Result<(), Box<dyn std::error::Error>> {
    if value {
        Ok(())
    } else {
        Err("output receipt/retirement contract mismatch".into())
    }
}

#[derive(Clone)]
struct Capture(Arc<Mutex<Vec<u8>>>);
impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let count = bytes.len().min(7);
        self.0
            .lock()
            .map_err(|_| io::Error::other("capture poisoned"))?
            .extend_from_slice(&bytes[..count]);
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn utf8_streaming_boundaries_and_slow_partial_receipts() -> Result<(), Box<dyn std::error::Error>> {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let mut out = BoundedOutput::start(
        Capture(Arc::clone(&captured)),
        Encoding::Utf8,
        Duration::from_secs(2),
    )?;
    let mut expected = vec![b'a'; CAPACITY - 1];
    expected.extend_from_slice("🦀中文".as_bytes());
    for fragment in expected.chunks(3) {
        out.write_all(fragment)?;
    }
    check(out.snapshot().flushed == (CAPACITY - 1) as u64)?;
    let done = out.finish()?;
    check(done.written == expected.len() as u64)?;
    check(done.written == done.flushed)?;
    check(!done.pending)?;
    check(*captured.lock().map_err(|_| "capture poisoned")? == expected)?;
    Ok(())
}
struct Gate {
    entered: mpsc::SyncSender<()>,
    release: mpsc::Receiver<()>,
    flush: bool,
}
impl Gate {
    fn wait(&self) -> io::Result<()> {
        self.entered.send(()).map_err(io::Error::other)?;
        self.release
            .recv_timeout(Duration::from_secs(3))
            .map_err(io::Error::other)
    }
}
impl Write for Gate {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if !self.flush {
            self.wait()?;
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.flush {
            self.wait()?;
        }
        Ok(())
    }
}
fn blocked(flush: bool) -> Result<(), Box<dyn std::error::Error>> {
    let (entered, started) = mpsc::sync_channel(1);
    let (release, gate) = mpsc::sync_channel(1);
    let mut out = BoundedOutput::start(
        Gate {
            entered,
            release: gate,
            flush,
        },
        Encoding::Utf8,
        Duration::from_secs(2),
    )?;
    out.control()
        .deadline(Instant::now() + Duration::from_millis(100));
    out.write_all(b"original")?;
    let error = out.finish().err().ok_or("blocked output claimed success")?;
    started.recv_timeout(Duration::from_secs(1))?;
    let snapshot = error.snapshot();
    check(snapshot.pending)?;
    check(snapshot.submitted == 8)?;
    check(snapshot.written == if flush { 8 } else { 0 })?;
    check(snapshot.flushed == 0)?;
    release.send(())?;
    // The retained original I/O can finish later; no new write/retry is issued.
    let until = Instant::now() + Duration::from_secs(2);
    while error.snapshot().written != 8 && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(1));
    }
    check(error.snapshot().written == 8)?;
    if flush {
        while error.snapshot().flushed != 8 && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(1));
        }
        check(error.snapshot().flushed == 8)?;
    } else {
        check(error.snapshot().flushed == 0)?;
    }
    Ok(())
}
#[test]
fn blocked_write_retains_original_job() -> Result<(), Box<dyn std::error::Error>> {
    blocked(false)
}
#[test]
fn blocked_flush_does_not_claim_flushed_bytes() -> Result<(), Box<dyn std::error::Error>> {
    blocked(true)
}
#[test]
fn binary_output_preserves_non_utf8_and_nul() -> Result<(), Box<dyn std::error::Error>> {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let mut out = BoundedOutput::start(
        Capture(Arc::clone(&captured)),
        Encoding::Bytes,
        Duration::from_secs(2),
    )?;
    out.write_all(&[0, 255, 128, 0])?;
    check(out.finish()?.flushed == 4)?;
    check(*captured.lock().map_err(|_| "capture poisoned")? == [0, 255, 128, 0])?;
    Ok(())
}
#[test]
fn invalid_text_is_sticky_and_never_submitted() -> Result<(), Box<dyn std::error::Error>> {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let mut out = BoundedOutput::start(
        Capture(Arc::clone(&captured)),
        Encoding::Utf8,
        Duration::from_secs(2),
    )?;
    out.write_all(&[0xff])?;
    check(out.flush().err().ok_or("invalid UTF-8 accepted")?.kind() == io::ErrorKind::InvalidData)?;
    check(out.write(b"later").is_err())?;
    let error = out.finish().err().ok_or("failed output claimed success")?;
    check(error.snapshot().submitted == 0)?;
    check(captured.lock().map_err(|_| "capture poisoned")?.is_empty())?;
    Ok(())
}
#[test]
fn cleanup_grace_cannot_be_renewed() -> Result<(), Box<dyn std::error::Error>> {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let mut out = BoundedOutput::start(Capture(captured), Encoding::Utf8, Duration::from_secs(2))?;
    out.control().cleanup(Duration::from_millis(10))?;
    std::thread::sleep(Duration::from_millis(20));
    out.control().cleanup(Duration::from_secs(2))?;
    out.write_all(b"late")?;
    check(out.flush().err().ok_or("cleanup deadline renewed")?.kind() == io::ErrorKind::TimedOut)?;
    check(out.snapshot().submitted == 0)?;
    Ok(())
}
