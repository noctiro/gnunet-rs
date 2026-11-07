//! Real prepared content and signed immutable artifact verification.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible artifact cases assert real reader receipts and no metadata-only acceptance"
)]
use super::*;
use crate::namespace::key::KeyFile;
use gnunet_fs::{Keyword, Keywords, metadata as md};
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
type TestResult = Result<(), Box<dyn std::error::Error>>;
struct Temporary(PathBuf);
impl Temporary {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let p = std::env::temp_dir().join(format!(
            "gnunet-publication-plan-{}-{stamp}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&p)?;
        Ok(Self(p))
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}
fn object(root: &Path, hash: [u8; 64]) -> PathBuf {
    let name: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    root.join(&name[..2]).join(&name[2..])
}
#[test]
fn full_file_verification_reaches_every_real_merkle_node_and_refuses_spool_changes() -> TestResult {
    let temp = Temporary::new()?;
    let path = temp.0.join("source");
    let bytes: Vec<_> = (0..100_001).map(|n| (n % 251) as u8).collect();
    fs::write(&path, &bytes)?;
    let root = temp.0.join("objects");
    let mut repo = Repository::open(&root)?;
    let mut input = crate::open_input(&path)?;
    let plan = prepare_file(
        &mut repo,
        &mut input,
        &mut Buffers::new(),
        Limits::default(),
        |_| Control::Continue,
    )?;
    let Artifact::File(content) = plan.artifact else {
        return Err("expected real file plan".into());
    };
    assert_eq!(plan.puts.len(), 5);
    assert_eq!(plan.puts.last().map(|p| p.key), Some(content.query));
    drop(input);
    fs::remove_file(&path)?;
    let checked = plan.verify(&mut repo, &mut Buffers::new(), Limits::default(), |_| {
        Control::Continue
    })?;
    assert_eq!(
        checked
            .file()
            .ok_or("missing actual reader receipt")?
            .verified
            .content(),
        content
    );
    assert_eq!(checked.puts(), 5);
    assert_eq!(checked.bytes(), plan.stored_bytes()?);
    let mut reordered = plan.clone();
    let last = reordered.puts.len() - 1;
    reordered.puts.swap(0, last);
    assert!(reordered.validate(Limits::default()).is_err());
    let mut extra = plan.clone();
    extra.puts.push(plan.puts[0]);
    assert!(extra.validate(Limits::default()).is_err());
    let original = object(&root, plan.puts[0].payload.hash);
    let mut file = fs::OpenOptions::new().write(true).open(original)?;
    file.write_all(b"changed")?;
    file.sync_all()?;
    assert!(
        plan.verify(&mut repo, &mut Buffers::new(), Limits::default(), |_| {
            Control::Continue
        })
        .is_err()
    );
    Ok(())
}
#[test]
fn repeated_keywords_and_pre_signed_namespace_keep_exact_selected_wire_artifacts() -> TestResult {
    let temp = Temporary::new()?;
    let mut repo = Repository::open(temp.0.join("objects"))?;
    let items = [md::Item {
        kind: 4,
        format: md::Format::CString,
        data: b"selected title\0",
        plugin: None,
        mime: Some(b"text/plain\0"),
    }];
    let mut order = [0];
    let mut scratch = [0; 1024];
    let metadata = md::plan_uncompressed(
        &items,
        &mut order,
        &mut scratch,
        md::Limits::default(),
        md::Options::default(),
    )?;
    // A published target URI is a link, not an assertion that its content exists.
    let target = Content {
        key: [7; 64],
        query: [9; 64],
        size: 13,
    }
    .uri();
    let terms = [
        Keyword::new(b"repeat", false)?,
        Keyword::new(b"repeat", true)?,
        Keyword::new(b"other", false)?,
    ];
    let plan = prepare_keywords(
        &mut repo,
        Keywords::new(&terms)?,
        target,
        Some(&metadata),
        Limits::default(),
    )?;
    assert_eq!(plan.puts.len(), 3);
    assert_eq!(plan.puts[0], plan.puts[1]);
    let checked = plan.verify(&mut repo, &mut Buffers::new(), Limits::default(), |_| {
        Control::Continue
    })?;
    assert_eq!(checked.puts(), 3);
    assert!(checked.file().is_none());
    let key_path = temp.0.join("namespace.key");
    let key = KeyFile::create(&key_path)?;
    let public = key.public_key();
    let namespace = prepare_namespace(
        &mut repo,
        &key,
        b"this",
        b"next",
        target,
        Some(&metadata),
        Limits::default(),
    )?;
    drop(key);
    fs::remove_file(key_path)?;
    let checked = namespace.verify(&mut repo, &mut Buffers::new(), Limits::default(), |_| {
        Control::Continue
    })?;
    assert_eq!(checked.puts(), 1);
    assert!(checked.file().is_none());
    let Artifact::Namespace {
        public: original, ..
    } = &namespace.artifact
    else {
        return Err("expected namespace plan".into());
    };
    assert_eq!(*original, public);
    let mut changed = namespace;
    let Artifact::Namespace { update, .. } = &mut changed.artifact else {
        return Err("expected namespace plan".into());
    };
    *update = b"wrong".to_vec();
    assert!(
        changed
            .verify(&mut repo, &mut Buffers::new(), Limits::default(), |_| {
                Control::Continue
            })
            .is_err()
    );
    Ok(())
}
