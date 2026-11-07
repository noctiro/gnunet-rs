//! Actual offline file/directory/type6 preparation and authenticated re-reading.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible real tree fixtures assert retained source bindings and genuine reader/parent proofs"
)]
use super::*;
use crate::input_tree::InputDir;
use crate::publication::plan::{Artifact, Limits, Plan};
use crate::{Buffers, Control, Repository};
use gnunet_fs::{Uri, content::BLOCK_BYTES, directory as dir};
use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
struct Temporary(PathBuf);
impl Temporary {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "gnunet-prepared-tree-{}-{n}-{}",
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
fn fixture(path: &Path) -> io::Result<()> {
    fs::create_dir(path)?;
    fs::create_dir(path.join("empty"))?;
    fs::create_dir(path.join("nested"))?;
    fs::write(path.join("a"), b"same repeated plaintext")?;
    fs::write(path.join("b"), b"same repeated plaintext")?;
    fs::write(
        path.join("nested").join("large"),
        vec![0x5a; 2 * BLOCK_BYTES + 3],
    )?;
    Ok(())
}
#[test]
fn full_tree_reauthenticates_after_the_original_source_is_removed_and_rejects_a_renamed_manifest_child()
-> TestResult {
    let temp = Temporary::new()?;
    let source = temp.0.join("source");
    fixture(&source)?;
    let input = InputDir::open(&source)?;
    let mut repo = Repository::open(temp.0.join("objects"))?;
    let (tree, puts) = prepare_tree(
        &mut repo,
        &input,
        None,
        &mut Buffers::new(),
        Limits::default(),
        |_| Control::Continue,
    )?;
    assert_eq!(tree.objects.len(), 6);
    assert!(tree.sources.is_empty());
    assert!(tree.objects.last().is_some_and(|object| object.directory
        && object.path.is_empty()
        && object.content == tree.root));
    let a = tree
        .objects
        .iter()
        .find(|object| object.path == b"a")
        .ok_or("missing a object")?;
    let b = tree
        .objects
        .iter()
        .find(|object| object.path == b"b")
        .ok_or("missing b object")?;
    assert_eq!(a.content, b.content);
    assert_eq!(a.put_count, 1);
    assert_eq!(b.put_count, 1);
    assert_ne!(a.first_put, b.first_put);
    assert_eq!(puts[a.first_put], puts[b.first_put]);
    let root = tree.root;
    let mut seen = Vec::new();
    let verified = Buffers::new().visit_directory(
        &mut repo,
        root,
        Limits::default().file,
        dir::Limits::default(),
        |entry| {
            let raw = entry.entry();
            let name = dir::filename(raw.metadata.items()).ok_or(crate::Error::Corrupt)?;
            let Uri::Content(content) = raw.uri()? else {
                return Err(crate::Error::Corrupt);
            };
            seen.push((name.to_vec(), content));
            Ok(())
        },
    )?;
    assert_eq!(verified.content(), root);
    assert_eq!(seen.len(), 4);
    drop(input);
    fs::remove_dir_all(&source)?;
    let mut plan = Plan {
        artifact: Artifact::Tree(tree),
        puts,
    };
    let checked = plan.verify(&mut repo, &mut Buffers::new(), Limits::default(), |_| {
        Control::Continue
    })?;
    assert_eq!(checked.puts(), plan.puts.len());
    assert_eq!(checked.bytes(), plan.stored_bytes()?);
    let Artifact::Tree(tree) = &mut plan.artifact else {
        return Err("missing actual tree".into());
    };
    tree.objects
        .iter_mut()
        .find(|object| object.path == b"a")
        .ok_or("missing a object")?
        .path = b"renamed".to_vec();
    assert!(
        plan.verify(&mut repo, &mut Buffers::new(), Limits::default(), |_| {
            Control::Continue
        })
        .is_err()
    );
    Ok(())
}
#[test]
fn indexed_tree_keeps_three_original_source_bindings_and_full_directories_then_refuses_a_changed_source()
-> TestResult {
    let temp = Temporary::new()?;
    let source = temp.0.join("source");
    fixture(&source)?;
    let input = InputDir::open(&source)?;
    let mut repo = Repository::open(temp.0.join("objects"))?;
    let (tree, puts) = prepare_tree(
        &mut repo,
        &input,
        Some(&source),
        &mut Buffers::new(),
        Limits::default(),
        |_| Control::Continue,
    )?;
    assert_eq!(tree.sources.len(), 3);
    assert_eq!(tree.objects.len(), 6);
    for object in &tree.objects {
        let rows = &puts[object.first_put..object.first_put + object.put_count];
        if object.directory {
            assert!(object.indexed.is_none());
            assert!(rows.iter().all(|put| matches!(put.kind, 1 | 2)));
        } else {
            assert!(object.indexed.is_some());
            assert!(rows.iter().any(|put| put.kind == 6));
            for leaf in rows.iter().filter(|put| put.kind == 6) {
                assert_eq!(leaf.payload.bytes, 72);
            }
        }
    }
    let a = tree
        .objects
        .iter()
        .find(|object| object.path == b"a")
        .ok_or("missing a object")?;
    let b = tree
        .objects
        .iter()
        .find(|object| object.path == b"b")
        .ok_or("missing b object")?;
    let a_source = &tree.sources[a.indexed.ok_or("missing indexed source")?];
    let b_source = &tree.sources[b.indexed.ok_or("missing indexed source")?];
    assert_eq!(a_source.file_id, b_source.file_id);
    assert_ne!(a_source.path, b_source.path);
    let plan = Plan {
        artifact: Artifact::Tree(tree),
        puts,
    };
    let checked = plan.verify(&mut repo, &mut Buffers::new(), Limits::default(), |_| {
        Control::Continue
    })?;
    assert_eq!(checked.puts(), plan.puts.len());
    fs::write(source.join("a"), b"changed native source!!")?;
    assert!(
        plan.verify(&mut repo, &mut Buffers::new(), Limits::default(), |_| {
            Control::Continue
        })
        .is_err()
    );
    Ok(())
}
