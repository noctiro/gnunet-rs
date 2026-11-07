//! Real local WAL/official-artifact functional cases; no native peer claim.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible graph tests assert exact retained namespace records and source SCCs"
)]
use super::*;
use gnunet_fs::{
    Content,
    metadata::{self as md, Compression, Format, Item},
};
use gnunet_fs_codec::Compressor;
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
            "gnunet-namespace-graph-{}-{}",
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
    gnunet_crypto::gns::EdkeySecret::from_seed([17; 32]).public_key()
}
fn target(size: u64) -> Uri<'static> {
    Content {
        key: [11; 64],
        query: [22; 64],
        size,
    }
    .uri()
}
fn encoded_metadata() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    selected_metadata(2048, Compression::Adaptive)
}
fn selected_metadata(
    size: usize,
    compression: Compression,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let data = vec![b'a'; size];
    let items = [Item {
        kind: 4,
        format: Format::Binary,
        data: &data,
        plugin: Some(b"graph-test\0"),
        mime: None,
    }];
    let mut order = [0];
    let mut plain = vec![0; size + 2048];
    let mut coded = vec![0; size + 2048];
    let plan = md::plan(
        &items,
        &mut order,
        &mut plain,
        &mut coded,
        &mut Compressor::new(),
        md::Limits::default(),
        md::Options {
            compression,
            ..Default::default()
        },
    )?;
    let mut bytes = vec![0; plan.report().wire_bytes];
    plan.write(&mut bytes)?;
    Ok(bytes)
}
fn labels(graph: &Graph, roots: Vec<RecordId>) -> Result<Vec<Vec<u8>>, Error> {
    roots
        .into_iter()
        .map(|id| {
            graph
                .record_identifier(id)
                .map(<[u8]>::to_vec)
                .ok_or(Error::Order)
        })
        .collect()
}
type SnapshotRow = (Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>);
fn snapshot(graph: &mut Graph) -> Result<Vec<SnapshotRow>, Error> {
    graph
        .record_ids()
        .map(|id| {
            let record = graph.record(id)?.ok_or(Error::Order)?;
            Ok((
                record.identifier().to_vec(),
                record.update().to_vec(),
                record.raw_uri().to_vec(),
                record.metadata().map(<[u8]>::to_vec),
            ))
        })
        .collect()
}
#[test]
fn real_records_restart_preserves_multiedges_empty_labels_metadata_and_source_scc_cover()
-> TestResult {
    let temp = Temporary::new()?;
    let path = temp.0.join("graph");
    let metadata = encoded_metadata()?;
    let mut graph = Graph::create(
        &path,
        namespace(),
        Limits::default(),
        store::Limits::default(),
    )?;
    for (identifier, update, size) in [
        (b"this".as_slice(), b"next".as_slice(), 1),
        (b"next", b"future", 2),
        (b"this", b"next", 3),
        (b"a", b"b", 4),
        (b"b", b"a", 5),
        (b"", b"", 6),
        (b"opaque-\xff", b"opaque-\xff", 7),
    ] {
        let prepared = graph.prepare(Record {
            identifier,
            update,
            uri: target(size),
            metadata: Some(&metadata),
        })?;
        graph.append_accepted(&prepared)?;
    }
    assert_eq!(graph.children(b"this").count(), 2);
    let records = snapshot(&mut graph)?;
    assert_eq!(
        labels(&graph, graph.roots()?)?,
        vec![
            b"".to_vec(),
            b"a".to_vec(),
            b"opaque-\xff".to_vec(),
            b"this".to_vec()
        ]
    );
    assert_eq!(labels(&graph, graph.component_roots()?)?.len(), 5);
    assert_eq!(graph.children(b"").count(), 1);
    drop(graph);
    assert!(matches!(
        Graph::open(&path, [9; 32], Limits::default(), store::Limits::default()),
        Err(Error::Binding)
    ));
    let mut graph = Graph::open(
        &path,
        namespace(),
        Limits::default(),
        store::Limits::default(),
    )?;
    let actual = snapshot(&mut graph)?;
    assert_eq!(actual, records);
    assert_eq!(
        labels(&graph, graph.roots()?)?,
        vec![
            b"".to_vec(),
            b"a".to_vec(),
            b"opaque-\xff".to_vec(),
            b"this".to_vec()
        ]
    );
    Ok(())
}
#[test]
fn preflight_refuses_before_append_and_original_graph_only_retry_is_idempotent() -> TestResult {
    let temp = Temporary::new()?;
    let path = temp.0.join("graph");
    let mut graph = Graph::create(
        &path,
        namespace(),
        Limits {
            max_records: 2,
            max_labels: 4,
            ..Default::default()
        },
        store::Limits::default(),
    )?;
    assert!(matches!(
        graph.prepare(Record {
            identifier: b"bad\0name",
            update: b"",
            uri: target(1),
            metadata: None
        }),
        Err(Error::Format)
    ));
    assert!(matches!(
        graph.prepare(Record {
            identifier: b"this",
            update: b"next",
            uri: target(1),
            metadata: Some(b"broken")
        }),
        Err(Error::Metadata(_))
    ));
    assert_eq!(graph.record_count(), 0);
    let original = graph.prepare(Record {
        identifier: b"this",
        update: b"next",
        uri: target(1),
        metadata: None,
    })?;
    let stale = graph.prepare(Record {
        identifier: b"other",
        update: b"",
        uri: target(2),
        metadata: None,
    })?;
    let id = graph.append_accepted(&original)?;
    assert!(matches!(graph.append_accepted(&stale), Err(Error::Binding)));
    assert_eq!(graph.record_count(), 1);
    drop(graph);
    let mut graph = Graph::open(
        &path,
        namespace(),
        Limits {
            max_records: 2,
            max_labels: 4,
            ..Default::default()
        },
        store::Limits::default(),
    )?;
    assert_eq!(graph.append_accepted(&original)?, id);
    assert_eq!(graph.record_count(), 1);
    let next = graph.prepare(Record {
        identifier: b"next",
        update: b"",
        uri: target(2),
        metadata: None,
    })?;
    graph.append_accepted(&next)?;
    assert!(matches!(
        graph.prepare(Record {
            identifier: b"later",
            update: b"",
            uri: target(3),
            metadata: None
        }),
        Err(Error::Limit)
    ));
    assert_eq!(graph.record_count(), 2);
    let mut foreign = Graph::create(
        temp.0.join("foreign"),
        namespace(),
        Limits::default(),
        store::Limits::default(),
    )?;
    assert!(matches!(
        foreign.append_accepted(&original),
        Err(Error::Binding)
    ));
    Ok(())
}

#[test]
fn graph_keeps_only_label_metadata_and_propagates_actual_record_corruption() -> TestResult {
    use std::io::{Read, Seek, SeekFrom, Write};
    let temp = Temporary::new()?;
    let path = temp.0.join("streamed-graph");
    let metadata = selected_metadata(8192, Compression::Never)?;
    let limits = Limits {
        max_records: 8,
        max_retained_bytes: 4096,
        ..Limits::default()
    };
    assert!(metadata.len() > limits.max_retained_bytes);
    let mut graph = Graph::create(&path, namespace(), limits, store::Limits::default())?;
    for size in 1..=8 {
        let plan = graph.prepare(Record {
            identifier: b"source",
            update: b"next",
            uri: target(size),
            metadata: Some(&metadata),
        })?;
        graph.append_accepted(&plan)?;
    }
    assert_eq!(graph.labels.len(), 2);
    assert_eq!(graph.record_count(), 8);
    assert!(graph.retained_bytes() <= limits.max_retained_bytes);
    drop(graph);
    let mut graph = Graph::open(&path, namespace(), limits, store::Limits::default())?;
    assert_eq!(graph.children(b"source").count(), 8);
    for id in graph.record_ids() {
        let original = graph.record(id)?.ok_or("accepted graph record absent")?;
        assert_eq!(original.metadata(), Some(metadata.as_slice()));
    }
    let last = graph.record_ids().last().ok_or("last accepted id absent")?;
    let mut disk = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path.join("records.wal"))?;
    let mut byte = [0];
    disk.seek(SeekFrom::End(-1))?;
    disk.read_exact(&mut byte)?;
    byte[0] ^= 255;
    disk.seek(SeekFrom::End(-1))?;
    disk.write_all(&byte)?;
    disk.sync_all()?;
    let error = graph
        .record(last)
        .err()
        .ok_or("corrupt record was exposed as valid")?;
    let Error::Storage(original) = error else {
        return Err("storage cause was erased".into());
    };
    assert_eq!(original.failure().kind, store::FailureKind::Checksum);
    assert!(std::ptr::eq(
        original.failure(),
        graph
            .storage_failure()
            .ok_or("graph store not fenced")?
            .failure()
    ));
    assert!(
        matches!(graph.prepare(Record { identifier: b"later", update: b"", uri: target(9), metadata: None }), Err(Error::Storage(error)) if std::ptr::eq(error.failure(), original.failure()))
    );
    Ok(())
}
