//! Actual local graph/WAL task-origin semantics; no native publication claim.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible graph fixtures assert original binding, stable origin and private WAL recovery"
)]
use super::*;
use gnunet_fs::Content;
use std::{
    fs, io,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
type TestResult = Result<(), Box<dyn std::error::Error>>;
struct Temporary(PathBuf);
impl Temporary {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "gnunet-graph-origin-{}-{}",
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
fn namespace() -> [u8; 32] {
    gnunet_crypto::gns::EdkeySecret::from_seed([29; 32]).public_key()
}
fn record(size: u64) -> Record<'static> {
    Record {
        identifier: b"origin-\xff",
        update: b"",
        uri: Content {
            key: [7; 64],
            query: [8; 64],
            size,
        }
        .uri(),
        metadata: None,
    }
}
#[test]
fn task_origins_survive_interleaved_preparation_and_reopen_without_merging_equal_publications()
-> TestResult {
    let temp = Temporary::new()?;
    let path = temp.0.join("graph");
    let mut graph = Graph::create(
        &path,
        namespace(),
        Limits::default(),
        store::Limits::default(),
    )?;
    let binding = graph.binding();
    let first = graph.prepare_task(binding, [1; 32], record(1))?;
    let second = graph.prepare_task(binding, [2; 32], record(1))?;
    assert!(graph.confirm_task(&first)?.is_none());
    let immediate = graph.prepare(record(1))?;
    assert_eq!(graph.append_accepted(&immediate)?.index(), 0);
    let second_receipt = graph.append_task_accepted(&second)?;
    let first_receipt = graph.append_task_accepted(&first)?;
    assert_eq!(second_receipt.id().index(), 1);
    assert_eq!(first_receipt.id().index(), 2);
    assert!(first_receipt.newly_recorded() && second_receipt.newly_recorded());
    assert_eq!(first_receipt.binding(), binding);
    assert_eq!(first_receipt.origin(), [1; 32]);
    assert_eq!(first_receipt.body_hash(), first.body_hash());
    assert_ne!(first_receipt.body_hash(), second_receipt.body_hash());
    assert_eq!(graph.children(b"origin-\xff").count(), 3);
    assert_eq!(
        graph
            .record_ids()
            .map(|id| Ok(graph.record(id)?.ok_or(Error::Order)?.task_origin()))
            .collect::<Result<Vec<_>, Error>>()?,
        vec![None, Some([2; 32]), Some([1; 32])]
    );
    drop(graph);
    let mut graph = Graph::open(
        &path,
        namespace(),
        Limits::default(),
        store::Limits::default(),
    )?;
    assert_eq!(graph.binding(), binding);
    let confirmed = graph
        .confirm_task(&first)?
        .ok_or("original task record absent")?;
    assert_eq!(confirmed.id(), first_receipt.id());
    assert_eq!(confirmed.body_hash(), first_receipt.body_hash());
    assert!(!confirmed.newly_recorded());
    let repeated = graph.append_task_accepted(&first)?;
    assert_eq!(repeated, confirmed);
    assert_eq!(graph.record_count(), 3);
    assert_eq!(
        graph.append_task_accepted(&second)?.id(),
        second_receipt.id()
    );
    assert_eq!(graph.append_accepted(&immediate)?.index(), 0);
    assert_eq!(graph.record_count(), 3);
    Ok(())
}
#[test]
fn exact_existing_origin_confirms_at_capacity_but_conflicts_foreign_stores_and_duplicate_wal_origins_refuse()
-> TestResult {
    let temp = Temporary::new()?;
    let path = temp.0.join("graph");
    let limits = Limits {
        max_records: 1,
        ..Default::default()
    };
    let mut graph = Graph::create(&path, namespace(), limits, store::Limits::default())?;
    let binding = graph.binding();
    let original = graph.prepare_task(binding, [3; 32], record(1))?;
    let actual = graph.append_task_accepted(&original)?;
    assert!(actual.newly_recorded());
    drop(graph);
    let mut graph = Graph::open(&path, namespace(), limits, store::Limits::default())?;
    let again = graph.prepare_task(binding, [3; 32], record(1))?;
    let confirmed = graph.append_task_accepted(&again)?;
    assert_eq!(confirmed.id(), actual.id());
    assert!(!confirmed.newly_recorded());
    assert_eq!(graph.record_count(), 1);
    assert!(matches!(
        graph.prepare_task(binding, [3; 32], record(2)),
        Err(Error::Binding)
    ));
    assert!(matches!(
        graph.prepare_task(binding, [4; 32], record(1)),
        Err(Error::Limit)
    ));
    let mut foreign = Graph::create(
        temp.0.join("foreign"),
        namespace(),
        Limits::default(),
        store::Limits::default(),
    )?;
    assert_ne!(foreign.binding(), binding);
    assert!(matches!(
        foreign.prepare_task(binding, [3; 32], record(1)),
        Err(Error::Binding)
    ));
    assert!(matches!(
        foreign.confirm_task(&original),
        Err(Error::Binding)
    ));
    assert!(matches!(
        foreign.append_task_accepted(&original),
        Err(Error::Binding)
    ));
    assert_eq!(foreign.record_count(), 0);
    drop(graph);
    // A structurally complete second row with the same task origin is corruption,
    // not an invitation for reopen to silently collapse two physical records.
    let mut wal = Store::open(&path, store::Limits::default())?;
    wal.append(ACCEPTED, &original.body)?;
    drop(wal);
    assert!(matches!(
        Graph::open(
            &path,
            namespace(),
            Limits::default(),
            store::Limits::default()
        ),
        Err(Error::Binding)
    ));
    Ok(())
}
