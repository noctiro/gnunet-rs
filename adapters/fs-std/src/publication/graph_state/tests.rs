//! Real local graph/Task WAL fixtures for structural binding and ordering only.
//! STATUS bytes below are wire fixtures, not a native receipt or C acceptance.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible original-history cases assert graph/task binding and lifecycle gates"
)]
use super::*;
use crate::{
    durable::store::{self, Store},
    namespace::graph::{self, Graph, Record, TaskPrepared, TaskReceipt},
    network::BlockOptions,
    publication::{
        codec,
        model::{Counts, Event, Manifest, Phase, State as TaskState},
        plan::{Artifact, Limits, Payload, Plan, Put},
    },
};
use gnunet_crypto::{gns::EdkeySecret, hash512};
use gnunet_fs::{Content, Uri, ublock};
use gnunet_wire::official::{
    AbsoluteTime,
    datastore::{Response, Status},
};
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
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "gnunet-graph-task-model-{}-{now}-{}",
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
fn plan() -> TestResult<Plan> {
    let secret = EdkeySecret::from_seed([17; 32]);
    let target = Uri::Content(Content {
        key: [3; 64],
        query: [4; 64],
        size: 123,
    });
    let mut target_uri = vec![0; target.encoded_len()?];
    target.encode(&mut target_uri)?;
    let publisher = ublock::Publisher::namespace(&secret, b"label", ublock::Limits::default())?;
    let mut wire = vec![0; 65535];
    let sealed = publisher.seal(b"", target, None, &mut wire)?;
    Ok(Plan {
        artifact: Artifact::Namespace {
            public: secret.public_key(),
            identifier: b"label".to_vec(),
            update: Vec::new(),
            target_uri,
            metadata: None,
        },
        puts: vec![Put {
            kind: 9,
            key: *sealed.query(),
            payload: Payload {
                hash: hash512(sealed.bytes()),
                bytes: sealed.bytes().len(),
            },
            position: None,
        }],
    })
}
fn append(store: &mut Store, state: &mut TaskState, event: Event<'_>) -> TestResult {
    state.prepare(&event)?;
    let (kind, bytes) = codec::encode_event(&event)?;
    let seq = store.append(kind, &bytes)?;
    state.apply(seq, store.record_count() - 1, kind, &bytes)?;
    Ok(())
}
fn phase(store: &mut Store, state: &mut TaskState, next: Phase) -> TestResult {
    let counts = state.counts;
    append(
        store,
        state,
        Event::Phase {
            phase: next,
            counts,
        },
    )
}
fn start(path: &Path, plan: Plan, target: Option<GraphTarget>) -> TestResult<(Store, TaskState)> {
    let manifest = Manifest {
        plan,
        blocks: BlockOptions {
            expiration: AbsoluteTime::NEVER,
            priority: 7,
            anonymity: 2,
            replication: 3,
        },
        limits: Limits::default(),
        graph: target,
    };
    let mut store = Store::create(path, store::Limits::default())?;
    let (kind, bytes) = codec::encode_event(&Event::Manifest(Box::new(manifest)))?;
    store.append(kind, &bytes)?;
    let mut state = TaskState::load(&mut store)?;
    phase(&mut store, &mut state, Phase::Running)?;
    append(
        &mut store,
        &mut state,
        Event::Intent {
            index: 0,
            request_hash: hash512(b"structural original PUT fixture"),
        },
    )?;
    Ok((store, state))
}
fn accepted(store: &mut Store, state: &mut TaskState) -> TestResult<Attempt> {
    let attempt = state.pending.ok_or("original intent missing")?.attempt;
    let mut response = vec![0; 64];
    let used = Response::Status(Status {
        code: 0,
        min_expiration: AbsoluteTime::NEVER,
        message: None,
    })
    .encode(&mut response)?;
    response.truncate(used);
    append(
        store,
        state,
        Event::Accepted {
            attempt,
            response: &response,
            interruption: None,
        },
    )?;
    Ok(attempt)
}
fn prepared(graph: &mut Graph, store: &Store, state: &TaskState) -> TestResult<TaskPrepared> {
    let Artifact::Namespace {
        identifier,
        update,
        target_uri,
        metadata,
        ..
    } = &state.manifest.plan.artifact
    else {
        return Err("namespace artifact missing".into());
    };
    Ok(graph.prepare_task(
        graph.binding(),
        *store.task_id(),
        Record {
            identifier,
            update,
            uri: Uri::parse(target_uri, gnunet_fs::Limits::default())?,
            metadata: metadata.as_deref(),
        },
    )?)
}
fn fact(receipt: &TaskReceipt, attempt: Attempt) -> Recorded {
    Recorded {
        binding: receipt.binding(),
        origin: receipt.origin(),
        attempt,
        record_index: receipt.id().index(),
        body_hash: receipt.body_hash(),
    }
}
#[test]
fn tracked_graph_fact_requires_original_native_prefix_before_complete_and_replays_exactly()
-> TestResult {
    let temp = Temporary::new()?;
    let plan = plan()?;
    let Artifact::Namespace { public, .. } = plan.artifact else {
        return Err("namespace missing".into());
    };
    let mut graph = Graph::create(
        temp.0.join("graph"),
        public,
        graph::Limits::default(),
        store::Limits::default(),
    )?;
    let target = GraphTarget {
        binding: graph.binding(),
    };
    let (mut store, mut state) = start(&temp.0.join("task"), plan.clone(), Some(target))?;
    let candidate = prepared(&mut graph, &store, &state)?;
    let attempt = state.pending.ok_or("intent missing")?.attempt;
    let projected = Recorded {
        binding: target.binding,
        origin: *store.task_id(),
        attempt,
        record_index: 0,
        body_hash: candidate.body_hash(),
    };
    assert!(state.check(&Event::GraphRecorded(projected)).is_err());
    let attempt = accepted(&mut store, &mut state)?;
    assert!(
        state
            .check(&Event::Phase {
                phase: Phase::Complete,
                counts: state.counts
            })
            .is_err()
    );
    let receipt = graph.append_task_accepted(&candidate)?;
    let original = fact(&receipt, attempt);
    let mut stale = original;
    stale.attempt.intent_record = stale
        .attempt
        .intent_record
        .checked_add(1)
        .ok_or("test generation overflow")?;
    assert!(state.check(&Event::GraphRecorded(stale)).is_err());
    let (kind, bytes) = codec::encode_event(&Event::GraphRecorded(original))?;
    let Event::GraphRecorded(decoded) = codec::decode_event(kind, &bytes)? else {
        return Err("graph fact missing".into());
    };
    assert_eq!(decoded, original);
    let mut trailing = bytes;
    trailing.push(0);
    assert!(codec::decode_event(kind, &trailing).is_err());
    append(&mut store, &mut state, Event::GraphRecorded(original))?;
    assert_eq!(state.graph.recorded, Some(original));
    assert!(state.check(&Event::GraphRecorded(original)).is_err());
    phase(&mut store, &mut state, Phase::Complete)?;
    let replayed = TaskState::load(&mut store)?;
    assert_eq!(replayed.phase, Phase::Complete);
    assert_eq!(replayed.graph.recorded, Some(original));
    assert_eq!(graph.record_count(), 1);
    let mut wrong = target;
    wrong.binding.namespace[0] ^= 1;
    let bad = Manifest {
        plan,
        blocks: state.manifest.blocks,
        limits: Limits::default(),
        graph: Some(wrong),
    };
    assert!(bad.validate().is_err());
    Ok(())
}
#[test]
fn foreign_task_facts_cannot_cross_origins_and_cancelled_history_can_reconcile_without_resume()
-> TestResult {
    let temp = Temporary::new()?;
    let plan = plan()?;
    let Artifact::Namespace { public, .. } = plan.artifact else {
        return Err("namespace missing".into());
    };
    let mut graph = Graph::create(
        temp.0.join("graph"),
        public,
        graph::Limits::default(),
        store::Limits::default(),
    )?;
    let target = GraphTarget {
        binding: graph.binding(),
    };
    let (mut first_store, mut first) = start(&temp.0.join("first"), plan.clone(), Some(target))?;
    let (mut next_store, mut next) = start(&temp.0.join("next"), plan.clone(), Some(target))?;
    assert_ne!(first_store.task_id(), next_store.task_id());
    let first_attempt = accepted(&mut first_store, &mut first)?;
    let next_attempt = accepted(&mut next_store, &mut next)?;
    assert_eq!(first_attempt, next_attempt);
    phase(&mut first_store, &mut first, Phase::CancelRequested)?;
    phase(&mut first_store, &mut first, Phase::Cancelled)?;
    let candidate = prepared(&mut graph, &first_store, &first)?;
    let receipt = graph.append_task_accepted(&candidate)?;
    let first_fact = fact(&receipt, first_attempt);
    assert!(next.check(&Event::GraphRecorded(first_fact)).is_err());
    append(
        &mut first_store,
        &mut first,
        Event::GraphRecorded(first_fact),
    )?;
    assert_eq!(first.phase, Phase::Cancelled);
    assert!(
        first
            .check(&Event::Phase {
                phase: Phase::Running,
                counts: first.counts
            })
            .is_err()
    );
    let confirmed = graph
        .confirm_task(&candidate)?
        .ok_or("original graph fact missing")?;
    assert_eq!(confirmed.id(), receipt.id());
    assert!(!confirmed.newly_recorded());
    let next_candidate = prepared(&mut graph, &next_store, &next)?;
    let next_receipt = graph.append_task_accepted(&next_candidate)?;
    assert_ne!(next_receipt.id(), receipt.id());
    let next_fact = fact(&next_receipt, next_attempt);
    append(&mut next_store, &mut next, Event::GraphRecorded(next_fact))?;
    phase(&mut next_store, &mut next, Phase::Complete)?;
    assert_eq!(graph.record_count(), 2);
    let (mut untracked_store, mut untracked) = start(&temp.0.join("untracked"), plan, None)?;
    accepted(&mut untracked_store, &mut untracked)?;
    assert!(untracked.check(&Event::GraphRecorded(next_fact)).is_err());
    phase(&mut untracked_store, &mut untracked, Phase::Complete)?;
    assert_eq!(untracked.counts.accepted, 1);
    assert_eq!(untracked.graph.recorded, None);
    assert_eq!(
        untracked.counts,
        Counts {
            accepted: 1,
            bytes: untracked.manifest.plan.puts[0].payload.bytes as u128
        }
    );
    Ok(())
}
