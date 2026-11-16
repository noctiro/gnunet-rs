#![expect(
    clippy::panic_in_result_fn,
    reason = "Real filesystem witnesses assert original OS fence, inode and commit boundaries."
)]
use super::*;
use crate::test_support::Directory as Scratch;
use std::fs;
#[test]
fn actual_raw8_is_atomic_and_kernel_fence_releases_without_pid_guessing()
-> Result<(), Box<dyn std::error::Error>> {
    let scratch = Scratch::new()?;
    let path = scratch.0.join("proof");
    let mut first = Store::open(path.clone())?;
    assert_eq!(first.loaded()?, None);
    #[cfg(unix)]
    assert_eq!(first.directory_sync(), DirectorySync::Synchronized);
    #[cfg(windows)]
    assert_eq!(first.directory_sync(), DirectorySync::Unavailable);
    assert!(matches!(
        Store::open(path.clone()),
        Err(Error {
            stage: Stage::Fence,
            ..
        })
    ));
    first.commit([0; 8])?;
    assert_eq!(first.loaded()?, Some([0; 8]));
    assert_eq!(fs::read(&path)?, [0; 8]);
    first.commit([3; 8])?;
    assert_eq!(fs::read(&path)?, [3; 8]);
    assert_eq!(fs::metadata(&path)?.len(), 8);
    assert!(first.quiescent()?);
    drop(first);
    assert!(scratch.0.join("proof.nse-lock").is_file());
    let second = Store::open(path)?;
    assert_eq!(second.loaded()?, Some([3; 8]));
    assert!(second.quiescent()?);
    Ok(())
}
#[test]
fn real_postrename_directory_failure_retains_original_unknown_until_readback()
-> Result<(), Box<dyn std::error::Error>> {
    let scratch = Scratch::new()?;
    let live = scratch.0.join("live");
    let moved = scratch.0.join("moved");
    fs::create_dir(&live)?;
    let path = live.join("proof");
    fs::write(&path, [1; 8])?;
    let mut store = Store::open(path)?;
    let result = store.commit_observed([2; 8], || {
        assert!(fs::rename(&live, &moved).is_ok());
    });
    assert!(matches!(
        result,
        Err(Error {
            stage: Stage::DirectorySync,
            outcome: Outcome::Unknown,
            ..
        })
    ));
    assert_eq!(fs::read(moved.join("proof"))?, [2; 8]);
    assert!(store.quiescent().is_err());
    assert!(store.loaded().is_err());
    assert!(matches!(
        store.commit([9; 8]),
        Err(Error {
            stage: Stage::Recovery,
            outcome: Outcome::Unknown,
            ..
        })
    ));
    assert!(store.recover().is_err());
    fs::rename(&moved, &live)?;
    assert!(!store.quiescent()?);
    assert_eq!(store.recover()?, Some([2; 8]));
    assert!(store.quiescent()?);
    assert_eq!(store.loaded()?, Some([2; 8]));
    store.commit([4; 8])?;
    assert_eq!(fs::read(live.join("proof"))?, [4; 8]);
    Ok(())
}
#[test]
fn malformed_file_and_replaced_fence_never_authorize_another_epoch()
-> Result<(), Box<dyn std::error::Error>> {
    let scratch = Scratch::new()?;
    let path = scratch.0.join("proof");
    fs::write(&path, [7; 9])?;
    assert!(matches!(
        Store::open(path.clone()),
        Err(Error {
            stage: Stage::Read,
            ..
        })
    ));
    fs::remove_file(&path)?;
    let mut store = Store::open(path.clone())?;
    fs::rename(scratch.0.join("proof.nse-lock"), scratch.0.join("old-lock"))?;
    fs::write(scratch.0.join("proof.nse-lock"), [])?;
    assert!(store.quiescent().is_err());
    assert!(store.loaded().is_err());
    assert!(matches!(
        store.commit([5; 8]),
        Err(Error {
            stage: Stage::Fence,
            outcome: Outcome::Unknown,
            ..
        })
    ));
    assert!(!path.exists());
    Ok(())
}
#[test]
fn staging_cleanup_never_deletes_a_replacement() -> Result<(), Box<dyn std::error::Error>> {
    let scratch = Scratch::new()?;
    let namespace = Namespace::open(&scratch.0.join("proof"))?;
    let (name, file) = namespace.staging()?;
    let path = scratch.0.join(&name);
    fs::rename(&path, scratch.0.join("saved-stage"))?;
    fs::write(&path, [9])?;
    assert!(namespace.discard(&name, &file).is_err());
    assert_eq!(fs::read(&path)?, [9]);
    Ok(())
}
fn postrename_readback_refusal_case(recovery: bool) -> Result<(), Box<dyn std::error::Error>> {
    let scratch = Scratch::new()?;
    let path = scratch.0.join("proof");
    let saved = scratch.0.join("original-renamed-proof");
    let mut store = Store::open(path.clone())?;
    store.commit([1; 8])?;
    // The real replacement has already happened and its original bytes were
    // fsynced. Make only the subsequent exact readback fail on an actual
    // non-regular filesystem object, retaining the original replacement.
    let result = store.commit_observed([2; 8], || {
        assert!(fs::rename(&path, &saved).is_ok());
        assert!(fs::create_dir(&path).is_ok());
    });
    let original = result.err().ok_or("readback unexpectedly succeeded")?;
    assert_eq!(
        store.unknown.as_ref().map(|pending| pending.bytes),
        Some([2; 8])
    );
    let failure = if recovery {
        store
            .recover()
            .err()
            .ok_or("recovery adopted wrong object")?
    } else {
        original
    };
    assert_eq!(failure.stage, Stage::Read);
    assert_eq!(failure.outcome, Outcome::Unknown);
    assert!(matches!(
        store.loaded(),
        Err(Error {
            outcome: Outcome::Unknown,
            ..
        })
    ));
    assert!(matches!(
        store.commit([3; 8]),
        Err(Error {
            outcome: Outcome::Unknown,
            ..
        })
    ));
    fs::remove_dir(&path)?;
    fs::rename(&saved, &path)?;
    assert_eq!(store.recover()?, Some([2; 8]));
    assert_eq!(store.loaded()?, Some([2; 8]));
    store.commit([3; 8])?;
    assert_eq!(store.loaded()?, Some([3; 8]));
    Ok(())
}
#[test]
fn postrename_readback_refusal_never_reports_not_committed()
-> Result<(), Box<dyn std::error::Error>> {
    postrename_readback_refusal_case(false)
}
#[test]
fn postrename_readback_recovery_refusal_never_reports_not_committed()
-> Result<(), Box<dyn std::error::Error>> {
    postrename_readback_refusal_case(true)
}

#[test]
fn equal_bytes_in_a_replacement_cannot_settle_the_original_publication()
-> Result<(), Box<dyn std::error::Error>> {
    let scratch = Scratch::new()?;
    let path = scratch.0.join("proof");
    let original = scratch.0.join("original");
    let mut store = Store::open(path.clone())?;
    store.commit([1; 8])?;
    let failed = store.commit_observed([2; 8], || {
        assert!(fs::rename(&path, &original).is_ok());
        assert!(fs::write(&path, [2; 8]).is_ok());
    });
    assert!(matches!(
        failed,
        Err(Error {
            stage: Stage::Read,
            outcome: Outcome::Unknown,
            ..
        })
    ));
    assert!(store.recover().is_err());
    assert!(!store.quiescent()?);
    fs::remove_file(&path)?;
    fs::rename(&original, &path)?;
    assert_eq!(store.recover()?, Some([2; 8]));
    assert!(store.quiescent()?);
    Ok(())
}
