#![expect(
    clippy::panic_in_result_fn,
    reason = "Real filesystem ownership and durable replay witnesses assert their original outcomes"
)]
use super::*;
use crate::replay::{DATA, LOCK};
use gnunet_types::Error;
use std::{
    os::unix::fs::{DirBuilderExt, symlink},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
type Test = Result<(), Box<dyn std::error::Error>>;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> io::Result<Self> {
        let p = std::env::temp_dir().join(format!(
            "udp-namespace-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&p)?;
        Ok(Self(p))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _removed = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn returning_full_identity_keeps_replay_floors_and_outgoing_highwater_under_root_fence() -> Test {
    let scratch = Scratch::new()?;
    let root = Namespace::open(&scratch.0)?;
    let a = [1; 32];
    let mut b = a;
    b[31] = 2;
    let remote = [3; 32];
    let mut first = root.journal(a, 4)?;
    first.commit_time(a, remote, 50)?;
    assert_eq!(first.reserve_monotime(100, 3)?, (100, 102));
    assert!(Namespace::open(&scratch.0).is_err());
    assert!(Journal::open(&scratch.0, a, 4).is_err());
    assert!(root.journal(a, 4).is_err());
    drop(root);
    assert!(Namespace::open(&scratch.0).is_err()); // child retains the actual root lock
    drop(first);
    let root = Namespace::open(&scratch.0)?;
    let mut second = root.journal(b, 4)?;
    assert_eq!(second.latest(remote)?, None);
    assert_eq!(second.reserve_monotime(1, 1)?, (1, 1));
    second.commit_time(b, remote, 7)?;
    drop(second);
    let mut returned = root.journal(a, 4)?;
    assert_eq!(returned.latest(remote)?, Some(50));
    assert!(matches!(
        returned.commit_time(a, remote, 50),
        Err(JournalError::Core(Error::Replay))
    ));
    assert_eq!(returned.reserve_monotime(1, 1)?, (103, 103));
    assert!(returned.quiescent()?);
    Ok(())
}
#[test]
fn unsuffixed_snapshot_and_temporary_history_are_refused_without_replacement() -> Test {
    let snapshot = Scratch::new()?;
    let mut old = Journal::open(&snapshot.0, [1; 32], 2)?;
    old.commit_time([1; 32], [2; 32], 42)?;
    drop(old);
    let bytes = fs::read(snapshot.0.join(DATA))?;
    assert!(Namespace::open(&snapshot.0).is_err());
    assert_eq!(fs::read(snapshot.0.join(DATA))?, bytes);
    let temporary = Scratch::new()?;
    fs::write(temporary.0.join(format!("{TEMP}retained")), [7])?;
    assert!(Namespace::open(&temporary.0).is_err());
    assert_eq!(fs::read(temporary.0.join(format!("{TEMP}retained")))?, [7]);
    Ok(())
}
#[test]
fn root_fence_replacement_revokes_live_child_and_symlink_child_is_refused() -> Test {
    let scratch = Scratch::new()?;
    let root = Namespace::open(&scratch.0)?;
    let child = root.journal([1; 32], 2)?;
    fs::rename(scratch.0.join(LOCK), scratch.0.join("original-lock"))?;
    fs::write(scratch.0.join(LOCK), [])?;
    assert!(
        matches!(child.latest([2;32]),Err(JournalError::Native(ref e)) if e.stage==Stage::Fence && e.outcome==Outcome::Unknown)
    );
    assert!(root.journal([3; 32], 2).is_err());
    fs::remove_file(scratch.0.join(LOCK))?;
    fs::rename(scratch.0.join("original-lock"), scratch.0.join(LOCK))?;
    assert_eq!(child.latest([2; 32])?, None);
    let other = Scratch::new()?;
    let name = format!("udp-{}", "04".repeat(32));
    symlink(&other.0, scratch.0.join(name))?;
    assert!(root.journal([4; 32], 2).is_err());
    Ok(())
}
