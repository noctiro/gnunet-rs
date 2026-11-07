use super::*;
use std::error::Error as StdError;
type Failure = Box<dyn StdError>;

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Result<Self, Failure> {
        let path = std::env::temp_dir().join(format!("gn-tcp-ns-{label}-{}", std::process::id()));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _removed = fs::remove_dir_all(&self.0);
    }
}
fn check(value: bool) -> Result<(), Failure> {
    if value {
        Ok(())
    } else {
        Err(Error::Conflict.into())
    }
}

#[test]
fn full_peer_paths_preserve_original_intent_and_shared_writer_fence() -> Result<(), Failure> {
    let dir = Directory::new("qualified")?;
    let owner = Namespace::open(&dir.0)?;
    check(Namespace::open(&dir.0).is_err())?;
    check(Store::open(dir.0.join("tcp.frontier")).is_err())?;
    let a = EddsaPublicKey::from_bytes([1; 32]);
    let mut b_bytes = [1; 32];
    b_bytes[31] = 2;
    let b = EddsaPublicKey::from_bytes(b_bytes);
    let (a_frontier, a_ledger) = owner.paths(a)?;
    let (b_frontier, b_ledger) = owner.paths(b)?;
    check(a_frontier != b_frontier && a_ledger != b_ledger)?;
    let mut first = Store::open(a_frontier.clone())?;
    first.prepare_replay(a, &a_ledger)?;
    check(Store::open(a_frontier.clone()).is_err())?;
    let original = fs::read(&a_frontier)?;
    let mut second = Store::open(b_frontier)?;
    second.prepare_replay(b, &b_ledger)?;
    check(fs::read(&a_frontier)? == original)?;
    drop(first);
    let (returned, returned_ledger) = owner.paths(a)?;
    check(returned == a_frontier && returned_ledger == a_ledger)?;
    let mut restored = Store::open(returned)?;
    restored.prepare_replay(a, &returned_ledger)?;
    check(fs::read(&a_frontier)? == original)?;
    check(restored.prepare_replay(b, &returned_ledger).is_err())?;
    check(fs::read(&a_frontier)? == original)
}

#[test]
fn unsuffixed_frontier_or_ledger_cannot_be_silently_reset() -> Result<(), Failure> {
    let dir = Directory::new("legacy")?;
    let path = dir.0.join("tcp.frontier");
    let mut original = Store::open(path.clone())?;
    original.prepare_replay(
        EddsaPublicKey::from_bytes([1; 32]),
        &dir.0.join("tcp.replay"),
    )?;
    let bytes = fs::read(&path)?;
    drop(original);
    check(Namespace::open(&dir.0).is_err())?;
    check(fs::read(&path)? == bytes)?;
    let second = Directory::new("footprint")?;
    fs::create_dir(second.0.join("tcp.replay"))?;
    check(Namespace::open(&second.0).is_err())
}
