//! Actual generated raw32 namespace signing and native refusal boundaries.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible key-file tests assert actual file preservation and official signature/decryption"
)]
use super::{Cause, KeyFile, Stage};
use gnunet_fs::{
    Content, Uri, metadata,
    ublock::{Context, Limits, Publisher},
};
use nix::{sys::stat::Mode, unistd::mkfifo};
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
struct Temporary(PathBuf);
impl Temporary {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "gnunet-fs-namespace-key-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}
fn fixture(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}
#[test]
fn generated_raw_seed_reopens_and_signs_the_official_namespace_ublock() -> TestResult {
    let temporary = Temporary::new()?;
    let path = temporary.0.join("namespace.seed");
    let key = KeyFile::create(&path)?;
    assert_eq!(fs::metadata(&path)?.len(), 32);
    assert_eq!(fs::metadata(&path)?.mode() & 0o7777, 0o600);
    key.revalidate()?;
    let public = key.public_key();
    let reopened = KeyFile::open(&path)?;
    assert_eq!(reopened.public_key(), public);
    reopened.revalidate()?;
    let publisher = Publisher::namespace(reopened.secret(), b"raw-\xff-label", Limits::default())?;
    let content = Content {
        key: [31; 64],
        query: [32; 64],
        size: 7,
    };
    let mut wire = vec![0; 65535];
    let sealed = publisher.seal(b"next", Uri::Content(content), None, &mut wire)?;
    let context = Context::namespace(&public, b"raw-\xff-label", Limits::default())?;
    let mut plain = vec![0; 65535];
    let authenticated = context.open(sealed.bytes(), &mut plain)?;
    let record = authenticated.decode(&mut [], &mut metadata::NoCodec, metadata::Mode::Strict)?;
    assert!(matches!(record.uri()?,Uri::Content(found) if found==content));
    assert_eq!(record.update_identifier(), b"next");
    let existing = KeyFile::create(&path);
    assert!(matches!(existing,Err(error) if !error.created && error.stage==Stage::Unopened));
    assert_eq!(KeyFile::open(&path)?.public_key(), public);
    Ok(())
}
#[test]
fn unsafe_or_changed_seed_authority_is_refused_without_overwrite_or_unlink() -> TestResult {
    let temporary = Temporary::new()?;
    let path = temporary.0.join("key");
    fixture(&path, &[7; 32])?;
    let linked = temporary.0.join("symlink");
    symlink(&path, &linked)?;
    assert!(KeyFile::open(&linked).is_err());
    assert!(KeyFile::create(&linked).is_err());
    let fifo = temporary.0.join("fifo");
    mkfifo(&fifo, Mode::S_IRUSR | Mode::S_IWUSR)?;
    assert!(matches!(KeyFile::open(&fifo),Err(error) if matches!(error.cause,Cause::Private)));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
    assert!(matches!(KeyFile::open(&path),Err(error) if matches!(error.cause,Cause::Private)));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    let mut writer = OpenOptions::new().write(true).truncate(true).open(&path)?;
    writer.write_all(&[7; 31])?;
    writer.sync_all()?;
    assert!(matches!(KeyFile::open(&path),Err(error) if matches!(error.cause,Cause::Length)));
    writer.write_all_at(&[7; 32], 0)?;
    writer.sync_all()?;
    let changed = KeyFile::open(&path)?;
    writer.write_all_at(&[8], 0)?;
    writer.sync_all()?;
    assert!(matches!(changed.revalidate(),Err(error) if matches!(error.cause,Cause::Changed)));
    assert_eq!(fs::read(&path)?[0], 8);
    let original = KeyFile::open(&path)?;
    let held = temporary.0.join("held-original");
    fs::rename(&path, &held)?;
    fixture(&path, &[9; 32])?;
    assert!(matches!(original.revalidate(),Err(error) if matches!(error.cause,Cause::Changed)));
    assert_eq!(fs::read(&path)?, vec![9; 32]);
    assert_eq!(fs::metadata(&held)?.len(), 32);
    let selected_parent = temporary.0.join("parent");
    fs::create_dir(&selected_parent)?;
    fixture(&selected_parent.join("key"), &[10; 32])?;
    let selected = KeyFile::open(selected_parent.join("key"))?;
    let old_parent = temporary.0.join("held-parent");
    fs::rename(&selected_parent, &old_parent)?;
    fs::create_dir(&selected_parent)?;
    fixture(&selected_parent.join("key"), &[11; 32])?;
    assert!(matches!(selected.revalidate(),Err(error) if matches!(error.cause,Cause::Changed)));
    assert_eq!(fs::read(selected_parent.join("key"))?, vec![11; 32]);
    assert_eq!(fs::read(old_parent.join("key"))?, vec![10; 32]);
    Ok(())
}
