#![expect(
    clippy::panic_in_result_fn,
    reason = "Native identity tests assert sealed original-file and no-clobber publication facts"
)]
use super::*;
use gnunet_native::filesystem::{Directory, publication, validate_readonly};
use std::{ffi::OsStr, fs, io::Write, path::PathBuf};

type Result = std::result::Result<(), Box<dyn std::error::Error>>;
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> io::Result<Self> {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).map_err(io::Error::other)?;
        let base = std::env::temp_dir().canonicalize()?;
        let name = format!("pils-sealed-{:032x}", u128::from_be_bytes(nonce));
        drop(Directory::open(&base)?.create_private_directory(OsStr::new(&name))?);
        Ok(Self(base.join(name)))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _removed = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn created_master_retains_only_the_original_readonly_key_lease() -> Result {
    let scratch = Scratch::new()?;
    let path = scratch.0.join("private.key");
    let (_master, lease) = load_or_create(&path)?;
    validate_readonly(&lease.key)?;
    let info = exact(&lease.key)?;
    assert_eq!(info.bytes, 32);
    assert_eq!(info.identity, lease.snapshot.initial().identity);
    lease.verify_fence()?;
    assert_eq!(fs::read_dir(&scratch.0)?.count(), 2);
    Ok(())
}

#[test]
fn reopened_master_retains_only_the_original_readonly_key_lease() -> Result {
    let scratch = Scratch::new()?;
    let path = scratch.0.join("private.key");
    let (master, lease) = load_or_create(&path)?;
    let identity = lease.snapshot.initial().identity;
    let public = master.initial_public_key();
    drop(lease);
    let (reloaded, lease) = load_or_create(&path)?;
    validate_readonly(&lease.key)?;
    assert!((&lease.key).write(&[0x55; 32]).is_err());
    assert_eq!(lease.snapshot.initial().identity, identity);
    assert_eq!(reloaded.initial_public_key(), public);
    lease.verify_fence()?;
    assert_eq!(fs::read_dir(&scratch.0)?.count(), 2);
    Ok(())
}

#[test]
fn same_inode_key_rewrite_refuses_the_original_startup_lease() -> Result {
    let scratch = Scratch::new()?;
    let path = scratch.0.join("private.key");
    let (master, lease) = load_or_create(&path)?;
    let before = lease.snapshot.initial();
    let mut writer =
        Directory::open(&scratch.0)?.open_file_for_update(OsStr::new("private.key"))?;
    let mut seed = Zeroizing::new([0; 32]);
    writer.read_exact(seed.as_mut())?;
    seed[0] ^= 1;
    writer.seek(SeekFrom::Start(0))?;
    writer.write_all(seed.as_ref())?;
    let changed = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1);
    writer.set_times(fs::FileTimes::new().set_modified(changed))?;
    writer.sync_all()?;
    drop(writer);

    let observed = exact(&lease.key)?;
    assert_eq!(observed.identity, before.identity);
    assert_eq!(observed.bytes, before.bytes);
    assert_ne!(observed.times.modified, before.times.modified);
    assert!(lease.verify_fence().is_err());

    drop(lease);
    let (reloaded, lease) = load_or_create(&path)?;
    assert_ne!(reloaded.initial_public_key(), master.initial_public_key());
    assert_eq!(lease.snapshot.initial().identity, before.identity);
    lease.verify_fence()?;
    Ok(())
}

#[test]
fn key_publication_collision_preserves_the_original_and_native_failure() -> Result {
    let scratch = Scratch::new()?;
    let path = scratch.0.join("private.key");
    let namespace = Namespace::writer(&path)?;
    let seed = [0x39; 32];
    let (file, _) = namespace.publish(&seed)?;
    validate_readonly(&file)?;
    let before = exact(&file)?;
    let error = match namespace.publish(&[0x74; 32]) {
        Err(error) => error,
        Ok(_) => return Err("existing PILS key was replaced".into()),
    };
    assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
    let failure = error
        .get_ref()
        .and_then(|cause| cause.downcast_ref::<publication::Failure>())
        .ok_or("original native publication failure was discarded")?;
    assert_eq!(failure.stage, "publish-create");
    assert_eq!(failure.cause.kind(), io::ErrorKind::AlreadyExists);
    assert!(failure.may_have_published);
    assert!(failure.writer_close.is_none());
    assert!(matches!(failure.cleanup, publication::Cleanup::Retired));
    let snapshot = PrivateFileSnapshot::new(before, &seed);
    namespace.verify_key_snapshot(&file, &snapshot)?;
    let mut actual = [0; 32];
    (&file).read_exact(&mut actual)?;
    assert_eq!(actual, seed);
    assert_eq!(fs::read_dir(&scratch.0)?.count(), 2);
    Ok(())
}
