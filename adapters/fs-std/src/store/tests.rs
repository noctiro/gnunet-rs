//! Physical selected-directory and exact-descriptor cleanup boundaries.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible filesystem cases assert original identity and preserved foreign bytes"
)]
use super::*;
#[cfg(feature = "network")]
use std::ffi::OsStr;
use std::{
    fs::{self, OpenOptions},
    io::Seek,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
struct Temporary(PathBuf);
impl Temporary {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let p = std::env::temp_dir().join(format!(
            "gnunet-publication-spool-{}-{stamp}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p)?;
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700))?;
        Ok(Self(p))
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn cleanup_and_existing_refresh_refuse_a_foreign_name_even_with_matching_bytes() -> TestResult {
    let temp = Temporary::new()?;
    let parent = File::open(&temp.0)?;
    let name = temp.0.join("temporary");
    let held = temp.0.join("held-original");
    let mut original = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&name)?;
    original.write_all(b"same bytes")?;
    original.sync_all()?;
    original.rewind()?;
    fs::rename(&name, &held)?;
    fs::write(&name, b"same bytes")?;
    assert!(Repository::remove_owned_temp(&parent, b"temporary", &original).is_err());
    assert_eq!(fs::read(&name)?, b"same bytes");
    assert_eq!(fs::read(&held)?, b"same bytes");
    assert!(
        Repository::existing_open(&parent, b"temporary", &mut original, b"same bytes").is_err()
    );
    assert_eq!(fs::read(&name)?, b"same bytes");
    assert_eq!(fs::read(&held)?, b"same bytes");
    assert!(Repository::existing(&parent, b"temporary", b"different").is_err());
    assert_eq!(fs::read(&name)?, b"same bytes");
    Ok(())
}
#[cfg(feature = "network")]
#[test]
fn raw_payloads_use_the_original_directory_and_do_not_widen_content_block_limits() -> TestResult {
    let temp = Temporary::new()?;
    let parent = File::open(&temp.0)?;
    let mut repo = Repository::open_child(&parent, OsStr::new("objects"))?;
    let bytes: Vec<_> = (0..50_000).map(|n| (n % 251) as u8).collect();
    let (hash, insert) = repo.insert_payload(&bytes)?;
    assert_eq!(insert, Insert::Created);
    assert_eq!(repo.insert_payload(&bytes)?.1, Insert::Existing);
    let mut output = vec![0; u16::MAX as usize];
    let n = repo.read_payload(&hash, &mut output)?;
    assert_eq!(&output[..n], bytes);
    assert!(repo.cache(hash, &bytes).is_err());
    assert!(Repository::open_child(&parent, OsStr::new("../outside")).is_err());
    let outside = temp.0.join("outside");
    fs::create_dir(&outside)?;
    fs::write(outside.join("sentinel"), b"unchanged")?;
    std::os::unix::fs::symlink(&outside, temp.0.join("alias"))?;
    assert!(Repository::open_child(&parent, OsStr::new("alias")).is_err());
    assert_eq!(fs::read(outside.join("sentinel"))?, b"unchanged");
    Ok(())
}
