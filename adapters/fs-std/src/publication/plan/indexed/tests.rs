//! Actual indexed source, type6 payload and complete FileReader boundaries.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible indexed-source cases assert genuine authenticated receipts and source refusal"
)]
use super::*;
use std::{
    fs,
    io::Write,
    path::PathBuf,
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
        let root = std::env::temp_dir().join(format!(
            "gnunet-index-plan-{}-{stamp}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root)?;
        Ok(Self(root))
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn indexed_descriptors_are_exact_weighted_positions_and_the_live_source_reaches_a_real_reader_receipt()
-> TestResult {
    let temp = Temporary::new()?;
    let path = temp.0.join("source");
    let bytes = vec![0x6d; 2 * content::BLOCK_BYTES + 129];
    fs::write(&path, &bytes)?;
    let mut input = crate::open_input(&path)?;
    let mut repo = Repository::open(temp.0.join("objects"))?;
    let prepared = prepare(
        &mut repo,
        &mut input,
        &path,
        &mut Buffers::new(),
        Limits::default(),
        |_| Control::Continue,
    )?;
    assert_eq!(prepared.source.file_id, gnunet_crypto::hash512(&bytes));
    assert_eq!(prepared.puts.len(), 4);
    assert_eq!(prepared.puts[0].key, prepared.puts[1].key);
    assert_ne!(prepared.puts[0].payload.hash, prepared.puts[1].payload.hash);
    for put in &prepared.puts {
        let position = put.position.ok_or("missing node position")?;
        if position.level == 0 {
            assert_eq!(put.kind, 6);
            assert_eq!(put.payload.bytes, 72);
            let mut descriptor = [0; 72];
            assert_eq!(repo.read_payload(&put.payload.hash, &mut descriptor)?, 72);
            assert_eq!(&descriptor[..64], &prepared.source.file_id);
            assert_eq!(
                u64::from_be_bytes(descriptor[64..].try_into()?),
                position.index * content::BLOCK_BYTES as u64
            );
        } else {
            assert_eq!(put.kind, 2);
            assert_eq!(put.payload.hash, put.key);
        }
    }
    drop(input);
    let checked = verify(
        &prepared.source,
        prepared.content,
        &prepared.puts,
        &mut repo,
        &mut Buffers::new(),
        Limits::default(),
        |_| Control::Continue,
    )?;
    assert_eq!(checked.verified.content(), prepared.content);
    assert_eq!(checked.progress.plaintext_bytes, bytes.len() as u64);
    let guard = SourceGuard::open(&prepared.source)?;
    let mut changed = fs::OpenOptions::new().write(true).open(&path)?;
    changed.write_all(b"changed")?;
    changed.sync_all()?;
    assert!(guard.stable().is_err());
    assert!(
        verify(
            &prepared.source,
            prepared.content,
            &prepared.puts,
            &mut repo,
            &mut Buffers::new(),
            Limits::default(),
            |_| Control::Continue
        )
        .is_err()
    );
    Ok(())
}
#[test]
fn missing_indexed_source_cannot_be_replaced_by_an_intact_descriptor_spool() -> TestResult {
    let temp = Temporary::new()?;
    let path = temp.0.join("empty");
    fs::write(&path, [])?;
    let mut input = crate::open_input(&path)?;
    let mut repo = Repository::open(temp.0.join("objects"))?;
    let prepared = prepare(
        &mut repo,
        &mut input,
        &path,
        &mut Buffers::new(),
        Limits::default(),
        |_| Control::Continue,
    )?;
    let checked = verify(
        &prepared.source,
        prepared.content,
        &prepared.puts,
        &mut repo,
        &mut Buffers::new(),
        Limits::default(),
        |_| Control::Continue,
    )?;
    assert_eq!(checked.verified.content(), prepared.content);
    assert_eq!(prepared.puts.len(), 1);
    assert_eq!(prepared.puts[0].kind, 6);
    drop(input);
    fs::remove_file(&path)?;
    let mut descriptor = [0; 72];
    assert_eq!(
        repo.read_payload(&prepared.puts[0].payload.hash, &mut descriptor)?,
        72
    );
    assert!(SourceGuard::open(&prepared.source).is_err());
    assert!(
        verify(
            &prepared.source,
            prepared.content,
            &prepared.puts,
            &mut repo,
            &mut Buffers::new(),
            Limits::default(),
            |_| Control::Continue
        )
        .is_err()
    );
    Ok(())
}
