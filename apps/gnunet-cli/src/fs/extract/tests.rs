#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions identify actual CLI output and joined-worker fixture failures; I/O and extraction errors remain returned to the harness."
)]
use super::*;
use std::{ffi::OsString, fs, os::unix::fs::DirBuilderExt, sync::atomic::AtomicU64};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Result<Self, Box<dyn Error>> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "gnunet-cli-extract-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}
fn command(source: &std::path::Path) -> Vec<OsString> {
    vec![
        "extract".into(),
        source.as_os_str().into(),
        "--timeout".into(),
        "10".into(),
    ]
}

#[test]
fn normal_extract_frontdoor_emits_real_metadata_terms_and_joined_completion()
-> Result<(), Box<dyn Error>> {
    let directory = Directory::new()?;
    let path = directory.0.join("Preview.html");
    fs::write(&path, b"<html><title>Visible preview</title></html>")?;
    let mut output = Vec::new();
    super::super::run(&command(&path), &mut output)?;
    let mut lines = output
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty());
    let object: serde_json::Value = serde_json::from_slice(lines.next().ok_or("missing object")?)?;
    assert_eq!(object["event"], "fs_extracted_object");
    assert!(
        object["metadata"]
            .as_array()
            .ok_or("missing metadata")?
            .iter()
            .any(|item| item["kind"] == 4 && item["text"] == "Visible preview")
    );
    assert!(
        object["keyword_bytes"]
            .as_array()
            .ok_or("missing terms")?
            .iter()
            .any(|term| term == &serde_json::json!(b"Visible preview".as_slice()))
    );
    let complete: serde_json::Value =
        serde_json::from_slice(lines.next().ok_or("missing completion")?)?;
    assert_eq!(complete["event"], "fs_extract_complete");
    assert_eq!(complete["worker_joined"], true);
    assert_eq!(complete["emitted"], 1);
    assert!(lines.next().is_none());
    assert_eq!(fs::read_dir(&directory.0)?.count(), 1);
    Ok(())
}

struct FailedOutput {
    failed: bool,
}
impl Write for FailedOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if !self.failed {
            self.failed = true;
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "selected output refusal",
            ));
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn output_failure_cancels_and_joins_original_worker_without_publication_artifacts()
-> Result<(), Box<dyn Error>> {
    let directory = Directory::new()?;
    for name in ["a.html", "b.html", "c.html"] {
        fs::write(directory.0.join(name), b"<title>actual</title>")?;
    }
    let mut output = FailedOutput { failed: false };
    let outcome = super::super::run(&command(&directory.0), &mut output);
    let error = match outcome {
        Ok(()) => return Err("failed output was reported complete".into()),
        Err(error) => error,
    };
    let failure = error
        .downcast_ref::<Failure>()
        .ok_or("original extraction facts were lost")?;
    assert!(failure.joined);
    assert_eq!(failure.emitted, 0);
    assert!(
        failure
            .output
            .as_ref()
            .is_some_and(|e| e.kind() == io::ErrorKind::BrokenPipe)
    );
    assert!(!failure.complete());
    assert_eq!(fs::read_dir(&directory.0)?.count(), 3);
    Ok(())
}
