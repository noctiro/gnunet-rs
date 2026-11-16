//! Actual TLS pairs and native namespace ownership on each supported platform.
use super::*;
use std::{
    ffi::OsStr,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
struct Scratch {
    parent: Directory,
    root: Directory,
    name: OsString,
    path: PathBuf,
}
impl Scratch {
    fn new() -> Result<Self, Failure> {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let serial = NEXT.fetch_add(1, Ordering::Relaxed);
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let name = OsString::from(format!("gqt-{:x}-{stamp:x}-{serial:x}", std::process::id()));
        let base = std::env::temp_dir();
        let parent = Directory::open(&base)?;
        let root = parent.create_private_directory(&name)?;
        Ok(Self {
            parent,
            root,
            path: base.join(&name),
            name,
        })
    }
    fn pair(&self) -> Pair {
        Pair {
            key: self.path.join("key.der"),
            certificate: self.path.join("cert.der"),
        }
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        for name in ["key.der", "cert.der", "moved"] {
            if let Ok(file) = self.root.open_file(OsStr::new(name)) {
                let _cleanup = self.root.remove_file(OsStr::new(name), &file);
            }
        }
        let _cleanup = self.parent.remove_directory(&self.name, &self.root);
    }
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Fallible actual TLS and private-file assertions"
)]
fn created_pair_reloads_without_replacing_private_material() -> Result<(), Failure> {
    let scratch = Scratch::new()?;
    let pair = scratch.pair();
    let created = prepare(Profile::Raw, Some(&pair))?;
    assert!(created.directory_sync[0].is_some());
    let original = scratch.root.open_file(OsStr::new("key.der"))?;
    validate_private_file(&original)?;
    let before = read(&pair.key, KEY_BYTES, true)?;
    let loaded = prepare(Profile::Http3, Some(&pair))?;
    assert!(loaded.directory_sync == [None, None]);
    assert!(scratch.root.same_file(OsStr::new("key.der"), &original)?);
    assert!(before.as_slice() == read(&pair.key, KEY_BYTES, true)?.as_slice());
    Ok(())
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Fallible original-file preservation assertions"
)]
fn partial_pair_preserves_the_original_file() -> Result<(), Failure> {
    let scratch = Scratch::new()?;
    let pair = scratch.pair();
    let mut original = scratch.root.create_private_file(OsStr::new("key.der"))?;
    original.write_all(b"public sentinel for a partial pair")?;
    assert!(prepare(Profile::Raw, Some(&pair)).is_err());
    assert!(scratch.root.same_file(OsStr::new("key.der"), &original)?);
    assert!(!present(&pair.certificate)?);
    Ok(())
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Fallible original-object cleanup assertions"
)]
fn cleanup_refuses_a_replaced_credential_link() -> Result<(), Failure> {
    let scratch = Scratch::new()?;
    let pair = scratch.pair();
    let mut created = NewFile::create(&pair.key)?;
    fs::rename(&pair.key, scratch.path.join("moved"))?;
    let mut replacement = scratch.root.create_private_file(OsStr::new("key.der"))?;
    replacement.write_all(b"public replacement sentinel")?;
    assert!(created.remove().is_err());
    drop(created);
    assert!(
        scratch
            .root
            .same_file(OsStr::new("key.der"), &replacement)?
    );
    assert!(read(&pair.key, KEY_BYTES, true)?.as_slice() == b"public replacement sentinel");
    Ok(())
}
