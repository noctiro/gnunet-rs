//! Native file-object recovery; catalog authorization is covered by startup fixtures.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Physical filesystem assertions accompany finite fallible native setup"
)]
use super::super::{Binding, State};
use super::*;
use std::{fs, path::PathBuf};
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> io::Result<Self> {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).map_err(io::Error::other)?;
        let temporary = std::env::temp_dir();
        let name = format!("tcp-epoch-{:032x}", u128::from_be_bytes(nonce));
        gnunet_native::filesystem::Directory::open(&temporary)?
            .create_private_directory(std::ffi::OsStr::new(&name))?;
        Ok(Self(temporary.join(name)))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}
fn image(reserved: u64) -> Persisted {
    Persisted {
        state: State {
            dirty: true,
            reserved,
        },
        binding: Binding {
            id: [3; 32],
            local: gnunet_crypto::EddsaPrivateKey::from_seed([7; 32]).public_key(),
            minimum: 2,
        },
    }
}
type Test = Result<(), Box<dyn std::error::Error>>;
#[test]
fn equal_bytes_cannot_settle_an_unknown_original_publication() -> Test {
    let scratch = Scratch::new()?;
    let parent = scratch.0.join("frontier");
    let moved = scratch.0.join("moved");
    gnunet_service_runtime::private_parents(&parent.join("state"))?;
    let path = parent.join("state");
    let mut store = Store::open(path.clone())?;
    store.update_bound(image(10), || {})?;
    let failed = store.update_bound(image(11), || {
        assert!(fs::rename(&parent, &moved).is_ok());
    });
    assert!(matches!(
        failed,
        Err(Failure {
            outcome: Outcome::Unknown,
            ..
        })
    ));
    let mut candidate = store
        .unknown
        .as_ref()
        .ok_or("missing original uncertain publication")?
        .candidate
        .original()?;
    validate_readonly(candidate)?;
    assert!(candidate.write(b"changed").is_err());
    fs::rename(&moved, &parent)?;
    let original = parent.join("original-publication");
    fs::rename(&path, &original)?;
    fs::copy(&original, &path)?;
    assert!(store.reconcile().is_err());
    assert!(store.loaded().is_err());
    fs::remove_file(&path)?;
    fs::rename(&original, &path)?;
    store.reconcile()?;
    assert_eq!(store.loaded()?, Some(image(11).state));
    let settled = store.current.as_ref().ok_or("missing settled original")?;
    validate_readonly(&settled.file)?;
    assert!((&settled.file).write(b"changed").is_err());
    let expected = gnunet_native::filesystem::Directory::open(&parent)?.sync()?;
    assert_eq!(store.directory_sync(), expected);
    Ok(())
}

#[test]
fn normal_publication_and_startup_keep_read_only_original_files() -> Test {
    let scratch = Scratch::new()?;
    let path = scratch.0.join("state");
    let mut store = Store::open(path.clone())?;
    store.update_bound(image(10), || {})?;
    let original = store.current.as_ref().ok_or("missing published original")?;
    validate_readonly(&original.file)?;
    assert!((&original.file).write(b"changed").is_err());
    assert_eq!(fs::read(&path)?, image(10).bytes());
    drop(store);

    let reopened = Store::open(path.clone())?;
    assert_eq!(reopened.loaded()?, Some(image(10).state));
    let original = reopened
        .current
        .as_ref()
        .ok_or("missing reopened original")?;
    validate_readonly(&original.file)?;
    assert!((&original.file).write(b"changed").is_err());
    assert_eq!(fs::read(&path)?, image(10).bytes());
    Ok(())
}
#[test]
fn settled_object_replacement_blocks_its_ready_state_until_original_returns() -> Test {
    let scratch = Scratch::new()?;
    let path = scratch.0.join("state");
    let mut store = Store::open(path.clone())?;
    store.update_bound(image(10), || {})?;
    let original = scratch.0.join("original");
    fs::rename(&path, &original)?;
    fs::copy(&original, &path)?;
    assert!(store.loaded().is_err());
    assert!(store.update_bound(image(11), || {}).is_err());
    assert!(store.reconcile().is_err());
    fs::remove_file(&path)?;
    fs::rename(&original, &path)?;
    // Ensure a changed fence even where rename does not advance change time.
    let restored = File::options().write(true).open(&path)?;
    restored.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(5_000))?;
    drop(restored);
    assert!(store.loaded().is_err());
    store.reconcile()?;
    assert_eq!(store.loaded()?, Some(image(10).state));
    Ok(())
}
#[test]
fn same_inode_frontier_edit_revokes_loaded_state_and_cannot_be_overwritten() -> Test {
    let scratch = Scratch::new()?;
    let path = scratch.0.join("state");
    let mut store = Store::open(path.clone())?;
    store.update_bound(image(10), || {})?;
    let before = store
        .current
        .as_ref()
        .ok_or("missing settled frontier")?
        .info;
    let bytes = image(100).bytes();
    let mut edited = File::options().write(true).open(&path)?;
    edited.write_all(&bytes)?;
    edited.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(5_000))?;
    edited.sync_all()?;
    let after = private_data_file_info(&edited)?;
    assert_eq!(
        (before.identity, before.bytes),
        (after.identity, after.bytes)
    );
    assert_ne!(before.times.modified, after.times.modified);
    drop(edited);

    assert!(matches!(
        store.loaded(),
        Err(Failure {
            stage: Stage::Read,
            outcome: Outcome::Unknown,
            ..
        })
    ));
    assert!(store.update_bound(image(11), || {}).is_err());
    assert!(store.reconcile().is_err());
    assert_eq!(fs::read(&path)?, bytes);
    assert_eq!(store.committed(), Some(image(10)));
    Ok(())
}
#[test]
fn canonical_file_appearing_after_empty_open_blocks_initialization() -> Test {
    let scratch = Scratch::new()?;
    let path = scratch.0.join("state");
    let mut store = Store::open(path.clone())?;
    assert_eq!(store.loaded()?, None);
    let mut foreign = store.owner.parent.create_private_file(&store.owner.name)?;
    let bytes = image(100).bytes();
    foreign.write_all(&bytes)?;
    foreign.sync_all()?;
    drop(foreign);

    assert!(store.loaded().is_err());
    assert!(store.reconcile().is_err());
    assert!(store.update_bound(image(11), || {}).is_err());
    assert_eq!(fs::read(path)?, bytes);
    Ok(())
}
#[test]
fn cleanup_retains_its_original_file_and_never_deletes_a_replacement() -> Test {
    let scratch = Scratch::new()?;
    let mut store = Store::open(scratch.0.join("state"))?;
    store.update_bound(image(10), || {})?;
    let candidate = Candidate::new(store.owner.clone())?;
    let name = scratch.0.join(&candidate.name);
    let original = scratch.0.join("original-stage");
    fs::rename(&name, &original)?;
    fs::write(&name, b"foreign stage")?;
    store.cleanup = Some(candidate);
    assert!(store.reconcile().is_err());
    assert!(store.loaded().is_err());
    assert_eq!(fs::read(&name)?, b"foreign stage");
    fs::remove_file(&name)?;
    fs::rename(&original, &name)?;
    store.reconcile()?;
    assert!(!name.try_exists()?);
    assert_eq!(store.loaded()?, Some(image(10).state));
    Ok(())
}
#[test]
fn bound_predecessor_and_original_stage_can_resolve_a_nonpublication() -> Test {
    let scratch = Scratch::new()?;
    let mut store = Store::open(scratch.0.join("state"))?;
    store.update_bound(image(10), || {})?;
    let mut candidate = Candidate::new(store.owner.clone())?;
    let path = scratch.0.join(&candidate.name);
    let file = candidate.file.as_mut().ok_or("stage absent")?;
    file.write_all(&image(11).bytes())?;
    publication::seal_retained(&candidate.owner.parent, &candidate.name, file, 89)?;
    store.unknown = Some(Pending {
        image: image(11),
        candidate,
    });
    assert!(store.loaded().is_err());
    store.reconcile()?;
    assert!(!path.try_exists()?);
    assert_eq!(store.loaded()?, Some(image(10).state));
    Ok(())
}
