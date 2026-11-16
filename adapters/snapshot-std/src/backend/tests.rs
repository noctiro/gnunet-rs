//! Native private filesystem transactions; bodies contain only public test bytes.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Regressions assert original-object observations and independently reopened bytes"
)]
use super::*;
use std::{ffi::OsStr, fs, io, path::PathBuf};
type Result = std::result::Result<(), Box<dyn std::error::Error>>;

#[test]
#[cfg(unix)]
fn replay_namespace_refuses_a_nonprivate_parent_before_creating_any_entry() -> Result {
    use std::os::unix::fs::PermissionsExt;
    let scratch = Private::create()?;
    fs::set_permissions(&scratch.0, fs::Permissions::from_mode(0o755))?;
    assert!(
        Store::open(
            Namespace::TransportTcp,
            scratch.0.join("replay"),
            Limits::default()
        )
        .is_err()
    );
    assert_eq!(Directory::open(&scratch.0)?.entries()?.count(), 0);
    Ok(())
}

struct Private(PathBuf);
impl Private {
    fn create() -> io::Result<Self> {
        let mut nonce = [0; 16];
        gnunet_native::entropy::fill(&mut nonce)?;
        let parent = std::env::temp_dir();
        let name = format!("gnunet-snapshot-test-{:032x}", u128::from_be_bytes(nonce));
        Directory::open(&parent)?.create_private_directory(OsStr::new(&name))?;
        Ok(Self(parent.join(name)))
    }
}
impl Drop for Private {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn every_namespace_roundtrips_its_existing_envelope_and_actual_barrier_profile() -> Result {
    let scratch = Private::create()?;
    for (index, namespace) in [
        Namespace::Identity,
        Namespace::Namestore,
        Namespace::Revocation,
        Namespace::Oidc,
        Namespace::Messenger,
        Namespace::Hostlist,
        Namespace::Transport,
        Namespace::TransportDv,
        Namespace::TransportTcp,
        Namespace::GnsPublication,
    ]
    .into_iter()
    .enumerate()
    {
        let path = scratch.0.join(index.to_string());
        let (mut store, loaded) = Store::open(namespace, &path, Limits::default())?;
        assert!(loaded.created_directory());
        assert_eq!(loaded.generation(), 0);
        assert_eq!(loaded.namespace(), namespace);
        let expected_barrier = if cfg!(windows) {
            DirectorySync::Unavailable
        } else {
            DirectorySync::Synchronized
        };
        assert_eq!(loaded.directory_sync(), expected_barrier);
        assert!(loaded.into_body().is_empty());
        let first = store.commit(0, Zeroizing::new(b"public first body".to_vec()))?;
        assert_eq!(first.namespace(), namespace);
        assert_eq!(first.generation(), 1);
        assert_eq!(first.directory_sync(), expected_barrier);
        store.commit(1, Zeroizing::new(b"public replacement".to_vec()))?;
        let bytes = fs::read(path.join(namespace.image()))?;
        assert_eq!(&bytes[..8], namespace.magic());
        assert_eq!(&bytes[8..16], &2u64.to_be_bytes());
        assert_eq!(&bytes[HEADER..], b"public replacement");
        drop(store);
        let (reopened, loaded) = Store::open(namespace, &path, Limits::default())?;
        assert!(!loaded.created_directory());
        assert_eq!(loaded.generation(), 2);
        assert_eq!(loaded.into_body().as_slice(), b"public replacement");
        assert_eq!(reopened.generation(), 2);
    }
    Ok(())
}

#[test]
fn complete_marker_never_grants_a_second_writer_the_creators_authority() -> Result {
    let scratch = Private::create()?;
    let path = scratch.0.join("identity");
    let (store, loaded) = Store::open(Namespace::Identity, &path, Limits::default())?;
    assert!(loaded.created_directory());
    match Store::open(Namespace::Identity, &path, Limits::default()) {
        Err(error) => assert_eq!(error.reason, Error::Conflict),
        Ok(_) => return Err("second writer admitted while original lease is held".into()),
    }
    drop(store);
    let (_reopened, loaded) = Store::open(Namespace::Identity, &path, Limits::default())?;
    assert!(!loaded.created_directory());
    Ok(())
}

#[test]
fn concurrent_complete_directory_initialization_admits_one_original_writer() -> Result {
    let scratch = Private::create()?;
    let path = scratch.0.join("concurrent");
    let start = Arc::new(std::sync::Barrier::new(8));
    let attempts = std::thread::scope(|scope| {
        let mut threads = Vec::new();
        for _ in 0..8 {
            let start = start.clone();
            let path = &path;
            threads.push(scope.spawn(move || {
                start.wait();
                Store::open(Namespace::TransportTcp, path, Limits::default())
            }));
        }
        threads
            .into_iter()
            .map(|thread| thread.join())
            .collect::<Vec<_>>()
    });
    let mut winner = None;
    for result in attempts {
        match result.map_err(|_| "initialization thread failed")? {
            Ok((store, loaded)) => {
                assert!(winner.is_none());
                assert!(loaded.created_directory());
                winner = Some(store);
            }
            Err(error) => assert_eq!(error.reason, Error::Conflict, "{error}"),
        }
    }
    let mut winner = winner.ok_or("no original writer admitted")?;
    winner.commit(0, Zeroizing::new(b"one original writer".to_vec()))?;
    assert_eq!(Directory::open(&scratch.0)?.entries()?.count(), 1);
    Ok(())
}

#[test]
fn existing_unmarked_and_foreign_directories_are_not_initialized() -> Result {
    let scratch = Private::create()?;
    let parent = Directory::open(&scratch.0)?;
    let unmarked = parent.create_private_directory(OsStr::new("unmarked"))?;
    let original = unmarked.create_private_file(OsStr::new("foreign"))?;
    assert!(
        Store::open(
            Namespace::Identity,
            scratch.0.join("unmarked"),
            Limits::default()
        )
        .is_err()
    );
    assert!(unmarked.same_file(OsStr::new("foreign"), &original)?);
    assert_eq!(unmarked.entries()?.count(), 1);
    let (other, _) = Store::open(
        Namespace::Namestore,
        scratch.0.join("other"),
        Limits::default(),
    )?;
    drop(other);
    assert!(
        Store::open(
            Namespace::Identity,
            scratch.0.join("other"),
            Limits::default()
        )
        .is_err()
    );
    assert!(
        !scratch
            .0
            .join("other")
            .join(Namespace::Identity.lock())
            .exists()
    );
    Ok(())
}

#[test]
fn replacing_the_canonical_name_fences_the_original_writer_and_keeps_first_cause() -> Result {
    let scratch = Private::create()?;
    let path = scratch.0.join("store");
    let (mut store, _) = Store::open(Namespace::Identity, &path, Limits::default())?;
    store.commit(0, Zeroizing::new(b"original".to_vec()))?;
    let parent = Directory::open(&path)?;
    let foreign = parent.create_private_file(OsStr::new("foreign"))?;
    parent.replace_file(
        OsStr::new("foreign"),
        &foreign,
        OsStr::new(Namespace::Identity.image()),
    )?;
    let first = store
        .commit(1, Zeroizing::new(b"must not publish".to_vec()))
        .err()
        .ok_or("foreign replacement must fence")?;
    assert_eq!(first.exposure, Exposure::Unknown);
    let again = store
        .commit(1, Zeroizing::new(b"never retried".to_vec()))
        .err()
        .ok_or("first cause is sticky")?;
    assert!(Arc::ptr_eq(&first, &again));
    assert!(parent.same_file(OsStr::new(Namespace::Identity.image()), &foreign)?);
    assert_eq!(store.generation(), 1);
    Ok(())
}

#[test]
fn recovery_retires_only_one_exact_recognized_pending_name() -> Result {
    let scratch = Private::create()?;
    let path = scratch.0.join("store");
    let (mut store, _) = Store::open(Namespace::TransportTcp, &path, Limits::default())?;
    store.commit(0, Zeroizing::new(b"canonical".to_vec()))?;
    drop(store);
    let directory = Directory::open(&path)?;
    let pending_name = format!("{}0000000000000002", Namespace::TransportTcp.temporary());
    let pending = directory.create_private_file(OsStr::new(&pending_name))?;
    drop(pending);
    let (store, loaded) = Store::open(Namespace::TransportTcp, &path, Limits::default())?;
    assert_eq!(loaded.recovered_temporaries(), 1);
    assert_eq!(loaded.into_body().as_slice(), b"canonical");
    assert!(!path.join(pending_name).exists());
    drop(store);
    let unknown = directory.create_private_file(OsStr::new("unexpected"))?;
    assert!(Store::open(Namespace::TransportTcp, &path, Limits::default()).is_err());
    assert!(directory.same_file(OsStr::new("unexpected"), &unknown)?);
    Ok(())
}
