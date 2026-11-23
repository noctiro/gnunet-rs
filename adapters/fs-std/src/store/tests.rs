//! Physical selected-directory and exact-descriptor cleanup boundaries.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible filesystem cases assert original identity and preserved foreign bytes"
)]
use super::{Insert, Repository, native::Directory};
#[cfg(all(unix, feature = "network"))]
use std::ffi::OsStr;
#[cfg(all(unix, feature = "network"))]
use std::fs::File;
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::{
    fs::{self, OpenOptions},
    io::Seek,
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
        #[cfg(unix)]
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
fn cache_preserves_raw_bytes_and_reports_real_retention() -> TestResult {
    use gnunet_native::filesystem::Directory as NativeDirectory;

    let temporary = Temporary::new()?;
    let root = temporary.0.join("objects");
    let mut repository = Repository::open(&root)?;
    let bytes = vec![7; 1024];
    let query = gnunet_crypto::hash512(&bytes);
    let created = repository.cache(query, &bytes)?;
    let names = fs::read_dir(&root)?.collect::<std::io::Result<Vec<_>>>()?;
    assert_eq!(names.len(), 1);
    let barrier = NativeDirectory::open(&temporary.0)?
        .sync()?
        .combine(NativeDirectory::open(&root)?.sync()?)
        .combine(NativeDirectory::open(&names[0].path())?.sync()?);
    let retention = crate::Retention::FileSynchronized(barrier);
    assert_eq!(created, Insert::Created(retention));
    assert_eq!(
        repository.cache(query, &bytes)?,
        Insert::Existing(retention)
    );
    let objects = fs::read_dir(names[0].path())?.collect::<std::io::Result<Vec<_>>>()?;
    assert_eq!(objects.len(), 1, "owned temporary must be gone");
    assert_eq!(fs::read(objects[0].path())?, bytes);
    #[cfg(unix)]
    assert_eq!(
        fs::metadata(objects[0].path())?.permissions().mode() & 0o777,
        0o600
    );
    #[cfg(windows)]
    assert_eq!(
        gnunet_native::identity::file_owner(&fs::File::open(objects[0].path())?)?,
        gnunet_native::identity::process_user()?
    );
    fs::write(objects[0].path(), vec![8; bytes.len()])?;
    assert!(matches!(
        repository.cache(query, &bytes),
        Err(crate::Error::Corrupt)
    ));
    assert_eq!(fs::read(objects[0].path())?, vec![8; bytes.len()]);
    assert!(repository.cache([0; 64], &bytes).is_err());
    assert!(!repository.cleanup_pending());
    Ok(())
}

#[test]
fn authenticated_streaming_uses_the_original_root_after_rename() -> TestResult {
    let temporary = Temporary::new()?;
    let selected = temporary.0.join("selected");
    let held = temporary.0.join("held-original");
    let mut repository = Repository::open(&selected)?;
    fs::rename(&selected, &held)?;
    fs::create_dir(&selected)?;
    let bytes: Vec<_> = (0..100_000).map(|n| (n % 251) as u8).collect();
    let mut buffers = crate::Buffers::new();
    let imported = buffers.publish(
        &mut bytes.as_slice(),
        bytes.len() as u64,
        &mut repository,
        crate::Limits::default(),
        |_| crate::Control::Continue,
    )?;
    assert!(imported.created_blocks > 1);
    let mut recovered = Vec::new();
    buffers.copy_to(
        &mut repository,
        imported.content,
        &mut recovered,
        crate::Limits::default(),
        |_| crate::Control::Continue,
    )?;
    assert_eq!(recovered, bytes);
    assert_eq!(
        fs::read_dir(&selected)?.count(),
        0,
        "replacement root must stay empty"
    );
    assert!(fs::read_dir(&held)?.next().is_some());
    Ok(())
}
#[test]
fn cleanup_and_existing_refresh_refuse_a_foreign_name_even_with_matching_bytes() -> TestResult {
    let temp = Temporary::new()?;
    let parent = Directory::open(&temp.0)?;
    let name = temp.0.join("temporary");
    let held = temp.0.join("held-original");
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut original = options.open(&name)?;
    original.write_all(b"same bytes")?;
    original.sync_all()?;
    original.rewind()?;
    fs::rename(&name, &held)?;
    fs::write(&name, b"same bytes")?;
    assert!(parent.remove("temporary", &original).is_err());
    assert_eq!(fs::read(&name)?, b"same bytes");
    assert_eq!(fs::read(&held)?, b"same bytes");
    assert!(
        super::repository::Repository::existing_open(
            &parent,
            "temporary",
            &mut original,
            b"same bytes"
        )
        .is_err()
    );
    assert_eq!(fs::read(&name)?, b"same bytes");
    assert_eq!(fs::read(&held)?, b"same bytes");
    assert!(super::repository::Repository::existing(&parent, "temporary", b"different").is_err());
    assert_eq!(fs::read(&name)?, b"same bytes");
    Ok(())
}
#[cfg(all(unix, feature = "network"))]
#[test]
fn raw_payloads_use_the_original_directory_and_do_not_widen_content_block_limits() -> TestResult {
    let temp = Temporary::new()?;
    let parent = File::open(&temp.0)?;
    let mut repo = Repository::open_child(&parent, OsStr::new("objects"))?;
    let bytes: Vec<_> = (0..50_000).map(|n| (n % 251) as u8).collect();
    let (hash, insert) = repo.insert_payload(&bytes)?;
    assert_eq!(
        insert,
        Insert::Created(crate::Retention::FileSynchronized(
            gnunet_native::DirectorySync::Synchronized
        ))
    );
    assert_eq!(
        repo.insert_payload(&bytes)?.1,
        Insert::Existing(crate::Retention::FileSynchronized(
            gnunet_native::DirectorySync::Synchronized
        ))
    );
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
