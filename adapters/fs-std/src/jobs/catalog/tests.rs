//! Actual private WAL tests, not typed-task execution or network acceptance.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible catalog tests assert real journal recovery and unchanged physical authority"
)]
use super::*;
use std::{
    io::{Read, Seek, SeekFrom, Write},
    sync::atomic::{AtomicU64, Ordering},
};
type TestResult = Result<(), Box<dyn std::error::Error>>;
struct Temporary(PathBuf);
impl Temporary {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        loop {
            let path = std::env::temp_dir().join(format!(
                "gnunet-catalog-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_dir_all(&self.0);
    }
}
fn registration(path: &Path) -> Result<Registration, Error> {
    // A real original Store supplies its random identity. Catalog cannot infer
    // typed-task meaning from this fixture: the production runner must still
    // open a genuine Search Task, which this journal intentionally is not.
    let task = Store::create(path, store::Limits::default())?;
    let task_id = *task.task_id();
    drop(task);
    Ok(Registration {
        task_id,
        kind: Kind::Search,
        task: Directory::capture(path)?,
        output_parent: None,
        cache: None,
        graph: None,
        policy: Policy::default(),
    })
}

#[test]
fn original_registration_policy_reopen_and_foreign_catalog_indexes_are_distinct() -> TestResult {
    let temp = Temporary::new()?;
    let binding = registration(&temp.0.join("task"))?;
    let path = temp.0.join("catalog");
    let mut catalog = Catalog::create(&path, Limits::default())?;
    let id = catalog.register(binding.clone())?;
    let original_id = *catalog.task_id();
    assert_eq!(id.index(), 0);
    assert!(matches!(
        catalog.register(binding.clone()),
        Err(Error::Conflict)
    ));
    let mut same_path = binding.clone();
    same_path.task_id = [17; 32];
    assert!(matches!(catalog.register(same_path), Err(Error::Conflict)));
    let mut other = Catalog::create(temp.0.join("other"), Limits::default())?;
    let foreign = other.register(binding)?;
    assert_eq!(id.index(), foreign.index());
    assert_ne!(id, foreign);
    assert!(catalog.entry(foreign).is_none());
    assert!(matches!(
        catalog.set_enabled(foreign, false),
        Err(Error::Protocol(ProtocolError::Stale))
    ));
    let policy = Policy {
        slice_us: 1_000_000,
        quota: Some(3),
        repeat_delay_us: Some(50_000),
    };
    catalog.set_policy(id, policy)?;
    catalog.set_enabled(id, false)?;
    let original = catalog.entry(id).ok_or("missing original record")?;
    assert_eq!(original.registration.policy, policy);
    assert!(!original.enabled);
    drop(catalog);
    let catalog = Catalog::open(&path, Limits::default())?;
    assert_eq!(catalog.task_id(), &original_id);
    let original = catalog
        .entry(id)
        .ok_or("original persistent coordinate was lost")?;
    assert_eq!(original.registration.policy, policy);
    assert!(!original.enabled);
    assert_eq!(catalog.entries().len(), 1);
    assert!(catalog.entry_at(1).is_none());
    original.registration.revalidate()?;
    Ok(())
}

#[test]
fn original_directory_descriptor_and_bounds_refuse_replacement_without_adopting_it() -> TestResult {
    let temp = Temporary::new()?;
    let task_path = temp.0.join("task");
    let binding = registration(&task_path)?;
    let original = Directory::capture(&task_path)?;
    let mut catalog = Catalog::create(
        temp.0.join("catalog"),
        Limits {
            max_entries: 1,
            ..Limits::default()
        },
    )?;
    let id = catalog.register(binding)?;
    let count = catalog.store.record_count();
    let next = registration(&temp.0.join("next"))?;
    assert!(matches!(
        catalog.register(next),
        Err(Error::Protocol(ProtocolError::Capacity))
    ));
    assert_eq!(catalog.store.record_count(), count);
    assert!(matches!(
        catalog.set_policy(
            id,
            Policy {
                quota: Some(0),
                ..Policy::default()
            }
        ),
        Err(Error::Protocol(ProtocolError::InvalidInput))
    ));
    assert_eq!(catalog.store.record_count(), count);
    std::fs::rename(&task_path, temp.0.join("old-task"))?;
    std::fs::create_dir(&task_path)?;
    assert!(matches!(original.open(), Err(Error::Authority)));
    let record = catalog.entry(id).ok_or("missing historical binding")?;
    assert_eq!(record.registration.task.identity(), original.identity());
    assert!(matches!(
        record.registration.revalidate(),
        Err(Error::Authority)
    ));
    let catalog_path = temp.0.join("catalog");
    drop(catalog);
    let catalog = Catalog::open(&catalog_path, Limits::default())?;
    assert!(catalog.entry(id).is_some());
    assert!(matches!(
        catalog
            .entry(id)
            .ok_or("missing retained entry")?
            .registration
            .task
            .open(),
        Err(Error::Authority)
    ));
    Ok(())
}

#[test]
fn exclusive_writer_and_complete_wal_corruption_are_never_repaired_as_success() -> TestResult {
    let temp = Temporary::new()?;
    let path = temp.0.join("catalog");
    let mut catalog = Catalog::create(&path, Limits::default())?;
    catalog.register(registration(&temp.0.join("task"))?)?;
    match Catalog::open(&path, Limits::default()) {
        Err(Error::Storage(error)) => assert_eq!(error.failure().kind, store::FailureKind::Locked),
        Err(error) => return Err(error.into()),
        Ok(_) => return Err("second catalog acquired live exclusive writer".into()),
    }
    drop(catalog);
    let wal = path.join("records.wal");
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&wal)?;
    let before = file.metadata()?.len();
    file.seek(SeekFrom::End(-1))?;
    let mut byte = [0];
    file.read_exact(&mut byte)?;
    byte[0] ^= 1;
    file.seek(SeekFrom::End(-1))?;
    file.write_all(&byte)?;
    file.sync_all()?;
    drop(file);
    match Catalog::open(&path, Limits::default()) {
        Err(Error::Storage(error)) => {
            assert_eq!(error.failure().kind, store::FailureKind::Checksum)
        }
        Err(error) => return Err(error.into()),
        Ok(_) => return Err("complete corrupt catalog opened successfully".into()),
    }
    assert_eq!(std::fs::metadata(wal)?.len(), before);
    Ok(())
}

#[test]
fn probe_kind_roundtrips_without_download_or_graph_bindings() -> TestResult {
    let temp = Temporary::new()?;
    // This fixture tests only catalog codec/shape, not typed native provenance.
    let mut probe = registration(&temp.0.join("probe-task"))?;
    probe.kind = Kind::Probe;
    let path = temp.0.join("catalog");
    let mut catalog = Catalog::create(&path, Limits::default())?;
    let id = catalog.register(probe.clone())?;
    assert_eq!(
        catalog
            .entry(id)
            .ok_or("missing registered probe")?
            .registration
            .kind,
        Kind::Probe
    );
    let mut invalid = registration(&temp.0.join("invalid-probe"))?;
    invalid.kind = Kind::Probe;
    invalid.output_parent = Some(Directory::capture(&temp.0)?);
    assert!(matches!(
        catalog.register(invalid),
        Err(Error::Protocol(ProtocolError::InvalidInput))
    ));
    drop(catalog);
    let catalog = Catalog::open(&path, Limits::default())?;
    let record = catalog.entry(id).ok_or("missing reloaded probe")?;
    assert_eq!(record.registration.kind, Kind::Probe);
    assert_eq!(record.registration.task_id, probe.task_id);
    assert!(record.registration.output_parent.is_none());
    assert!(record.registration.cache.is_none());
    assert!(record.registration.graph.is_none());
    Ok(())
}
