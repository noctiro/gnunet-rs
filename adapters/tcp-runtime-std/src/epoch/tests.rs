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
    let expected = if cfg!(windows) {
        DirectorySync::Unavailable
    } else {
        DirectorySync::Synchronized
    };
    assert_eq!(store.directory_sync(), expected);
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
    fs::remove_file(&path)?;
    fs::rename(&original, &path)?;
    assert_eq!(store.loaded()?, Some(image(10).state));
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
    file.sync_all()?;
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
