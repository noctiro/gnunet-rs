//! Structural-history fixtures. Real publication receipt provenance is covered
//! by native task integration; these tests do not claim a daemon or C execution.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible model fixtures assert immutable request and original receipt bindings"
)]
use super::super::plan::{Artifact, Payload, Plan, Position, Put};
use super::*;
use crate::durable::store::{self, Store};
use gnunet_crypto::{gns::EdkeySecret, hash512};
use gnunet_fs::{Content, Keyword, Keywords, Uri, content, metadata as md, ublock};
use gnunet_wire::official::{
    AbsoluteTime,
    datastore::{Response, Status},
};
use std::{
    fs, io,
    path::PathBuf,
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
            "gnunet-publication-model-{}-{now}-{}",
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
fn uri(uri: Uri<'_>) -> TestResult<Vec<u8>> {
    let mut bytes = vec![0; uri.encoded_len()?];
    uri.encode(&mut bytes)?;
    Ok(bytes)
}
fn file_plan() -> TestResult<Plan> {
    let mut wire = [0; content::TAG_BYTES];
    let encoded = content::encode_data(b"", &mut wire)?;
    let key = encoded.key();
    Ok(Plan {
        artifact: Artifact::File(key.content(0)),
        puts: vec![Put {
            kind: 1,
            key: key.query,
            payload: Payload {
                hash: key.query,
                bytes: wire.len(),
            },
            position: Some(Position { level: 0, index: 0 }),
        }],
    })
}
fn keyword_plan() -> TestResult<Plan> {
    let terms = [Keyword::new(b"same", true)?, Keyword::new(b"same", false)?];
    let query_uri = uri(Uri::Keywords(Keywords::new(&terms)?))?;
    let target = Uri::Content(Content {
        key: [3; 64],
        query: [4; 64],
        size: 123,
    });
    let target_uri = uri(target)?;
    let publisher = ublock::Publisher::keyword(b"same", ublock::Limits::default())?;
    let mut wire = vec![0; 65535];
    let sealed = publisher.seal(b"", target, None, &mut wire)?;
    let put = Put {
        kind: 9,
        key: *sealed.query(),
        payload: Payload {
            hash: hash512(sealed.bytes()),
            bytes: sealed.bytes().len(),
        },
        position: None,
    };
    Ok(Plan {
        artifact: Artifact::Keywords {
            query_uri,
            target_uri,
            metadata: None,
        },
        puts: vec![put, put],
    })
}
fn namespace_plan() -> TestResult<Plan> {
    let secret = EdkeySecret::from_seed([11; 32]);
    let identifier = b"\xfflabel";
    let update = vec![b'u'; 4097];
    let target = Uri::Content(Content {
        key: [5; 64],
        query: [6; 64],
        size: 987,
    });
    let target_uri = uri(target)?;
    let mut order = [];
    let mut scratch = [];
    let selected = md::plan_uncompressed(
        &[],
        &mut order,
        &mut scratch,
        md::Limits::default(),
        md::Options::default(),
    )?;
    let mut metadata = vec![0; selected.report().wire_bytes];
    selected.write(&mut metadata)?;
    let publisher = ublock::Publisher::namespace(&secret, identifier, ublock::Limits::default())?;
    let mut wire = vec![0; 65535];
    let sealed = publisher.seal(&update, target, Some(&selected), &mut wire)?;
    Ok(Plan {
        artifact: Artifact::Namespace {
            public: secret.public_key(),
            identifier: identifier.to_vec(),
            update,
            target_uri,
            metadata: Some(metadata),
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
fn manifest(plan: Plan) -> Manifest {
    Manifest {
        graph: None,
        plan,
        blocks: BlockOptions {
            expiration: AbsoluteTime::from_micros(123456789),
            priority: 17,
            anonymity: 3,
            replication: 9,
        },
        limits: super::super::plan::Limits::default(),
    }
}
fn start(path: &std::path::Path, manifest: Manifest) -> TestResult<(Store, State)> {
    let mut store = Store::create(path, store::Limits::default())?;
    let (kind, body) = codec::encode_event(&Event::Manifest(Box::new(manifest)))?;
    store.append(kind, &body)?;
    let state = State::load(&mut store)?;
    Ok((store, state))
}

#[test]
fn replay_preserves_original_storage_authority_failure_and_fences_later_appends() -> TestResult {
    let temporary = Temporary::new()?;
    let path = temporary.0.join("task");
    let (mut store, historical) = start(&path, manifest(file_plan()?))?;
    let count = store.record_count();
    let wal = path.join("records.wal");
    let original = path.join("original.wal");
    fs::rename(&wal, &original)?;
    // The replacement contains valid original framing. The real anchored inode
    // changed, so fresh replay must refuse rather than use the old decoded State.
    fs::copy(&original, &wal)?;
    let failure = State::load(&mut store)
        .err()
        .ok_or("replacement WAL was accepted")?;
    let super::super::Cause::Storage(error) = failure else {
        return Err("original storage failure was reclassified as a model error".into());
    };
    assert_eq!(error.failure().kind, store::FailureKind::Authority);
    assert!(store.fenced());
    assert_eq!(store.record_count(), count);
    assert_eq!(historical.applied(), count as u64);
    let append = store
        .append(0, &[])
        .err()
        .ok_or("fenced store appended a new record")?;
    assert!(std::ptr::eq(error.failure(), append.failure()));
    Ok(())
}
fn append(store: &mut Store, state: &mut State, event: Event<'_>) -> TestResult {
    state.prepare(&event)?;
    let (kind, bytes) = codec::encode_event(&event)?;
    let sequence = store.append(kind, &bytes)?;
    state.apply(sequence, store.record_count() - 1, kind, &bytes)?;
    Ok(())
}
fn phase(store: &mut Store, state: &mut State, value: Phase) -> TestResult {
    let counts = state.counts;
    append(
        store,
        state,
        Event::Phase {
            phase: value,
            counts,
        },
    )
}
fn status(code: i32, message: Option<&[u8]>) -> TestResult<Vec<u8>> {
    let response = Response::Status(Status {
        code,
        min_expiration: AbsoluteTime::from_micros(44),
        message,
    });
    let mut wire = vec![0; 65535];
    let n = response.encode(&mut wire)?;
    wire.truncate(n);
    Ok(wire)
}
#[test]
fn all_artifacts_roundtrip_and_actual_nonnegative_receipts_alone_advance_the_prefix() -> TestResult
{
    for plan in [file_plan()?, keyword_plan()?, namespace_plan()?] {
        let original = manifest(plan);
        let (kind, bytes) = codec::encode_event(&Event::Manifest(Box::new(original.clone())))?;
        let Event::Manifest(decoded) = codec::decode_event(kind, &bytes)? else {
            return Err("manifest lost".into());
        };
        assert_eq!(decoded.plan.puts, original.plan.puts);
        assert_eq!(decoded.blocks.priority, 17);
        assert_eq!(decoded.blocks.anonymity, 3);
        assert_eq!(decoded.blocks.replication, 9);
        assert_eq!(decoded.blocks.expiration.as_micros(), 123456789);
        match (&decoded.plan.artifact, &original.plan.artifact) {
            (Artifact::File(a), Artifact::File(b)) => assert_eq!(a, b),
            (
                Artifact::Keywords {
                    query_uri: a,
                    target_uri: b,
                    metadata: c,
                },
                Artifact::Keywords {
                    query_uri: x,
                    target_uri: y,
                    metadata: z,
                },
            ) => assert_eq!((a, b, c), (x, y, z)),
            (
                Artifact::Namespace {
                    public: a,
                    identifier: b,
                    update: c,
                    target_uri: d,
                    metadata: e,
                },
                Artifact::Namespace {
                    public: v,
                    identifier: w,
                    update: x,
                    target_uri: y,
                    metadata: z,
                },
            ) => assert_eq!((a, b, c, d, e), (v, w, x, y, z)),
            _ => return Err("artifact changed".into()),
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(codec::decode_event(kind, &trailing).is_err());
    }
    let temporary = Temporary::new()?;
    let path = temporary.0.join("task");
    let plan = file_plan()?;
    let payload = plan.puts[0].payload.bytes;
    let (mut store, mut state) = start(&path, manifest(plan))?;
    phase(&mut store, &mut state, Phase::Running)?;
    append(
        &mut store,
        &mut state,
        Event::Intent {
            index: 0,
            request_hash: [7; 64],
        },
    )?;
    let attempt = state.pending.ok_or("intent missing")?.attempt;
    assert!(
        state
            .check(&Event::NotApplied {
                attempt,
                reason: NoEffect::UnexposedRegistration,
                interruption: None
            })
            .is_err()
    );
    assert!(
        state
            .check(&Event::Phase {
                phase: Phase::Complete,
                counts: Counts {
                    accepted: 1,
                    bytes: payload as u128
                }
            })
            .is_err()
    );
    let duplicate = status(0, Some(b"already\xffthere\0"))?;
    append(
        &mut store,
        &mut state,
        Event::Accepted {
            attempt,
            response: &duplicate,
            interruption: Some(Interruption::TimedOut),
        },
    )?;
    assert_eq!(
        state.counts,
        Counts {
            accepted: 1,
            bytes: payload as u128
        }
    );
    assert!(state.current_run_interrupted());
    assert!(state.pending.is_none());
    let accepted = state.accepted[0];
    let native = store
        .read_record(accepted.record_index)?
        .ok_or("receipt missing")?;
    let (found, raw, interruption) = codec::accepted_view(native.kind, native.bytes)?;
    assert_eq!(found, attempt);
    assert_eq!(raw, duplicate);
    assert_eq!(interruption, Some(Interruption::TimedOut));
    assert!(
        state
            .check(&Event::Phase {
                phase: Phase::Complete,
                counts: state.counts
            })
            .is_err()
    );
    phase(&mut store, &mut state, Phase::PauseRequested)?;
    phase(&mut store, &mut state, Phase::Paused)?;
    drop(state);
    drop(store);
    let mut store = Store::open(&path, store::Limits::default())?;
    let mut state = State::load(&mut store)?;
    assert_eq!(state.phase, Phase::Paused);
    assert_eq!(state.accepted.len(), 1);
    assert!(state.current_run_interrupted());
    phase(&mut store, &mut state, Phase::Running)?;
    assert!(!state.current_run_interrupted());
    phase(&mut store, &mut state, Phase::Complete)?;
    Ok(())
}
#[test]
fn explicit_refused_retry_is_attempt_bound_and_unknown_never_becomes_no_effect() -> TestResult {
    let temporary = Temporary::new()?;
    let path = temporary.0.join("task");
    let (mut store, mut state) = start(&path, manifest(keyword_plan()?))?;
    phase(&mut store, &mut state, Phase::Running)?;
    append(
        &mut store,
        &mut state,
        Event::Intent {
            index: 0,
            request_hash: [9; 64],
        },
    )?;
    let first = state.pending.ok_or("first intent missing")?.attempt;
    let refused = status(-1, Some(b"refused\xff\0"))?;
    append(
        &mut store,
        &mut state,
        Event::Refused {
            attempt: first,
            response: &refused,
            interruption: None,
        },
    )?;
    phase(&mut store, &mut state, Phase::Failed)?;
    assert!(state.requires_explicit_retry());
    assert!(!state.uncertain());
    assert_eq!(state.counts.accepted, 0);
    assert!(
        state
            .check(&Event::Phase {
                phase: Phase::Running,
                counts: state.counts
            })
            .is_err()
    );
    append(
        &mut store,
        &mut state,
        Event::RetryRefused { attempt: first },
    )?;
    phase(&mut store, &mut state, Phase::Running)?;
    append(
        &mut store,
        &mut state,
        Event::Intent {
            index: 0,
            request_hash: [9; 64],
        },
    )?;
    let second = state.pending.ok_or("second intent missing")?.attempt;
    assert_ne!(first.intent_record, second.intent_record);
    let positive = status(7, None)?;
    assert!(
        state
            .check(&Event::Accepted {
                attempt: first,
                response: &positive,
                interruption: None
            })
            .is_err()
    );
    append(
        &mut store,
        &mut state,
        Event::NotApplied {
            attempt: second,
            reason: NoEffect::NotSent,
            interruption: Some(Interruption::TimedOut),
        },
    )?;
    assert!(state.pending.is_none());
    assert_eq!(state.counts.accepted, 0);
    append(
        &mut store,
        &mut state,
        Event::Intent {
            index: 0,
            request_hash: [9; 64],
        },
    )?;
    let third = state.pending.ok_or("third intent missing")?.attempt;
    append(
        &mut store,
        &mut state,
        Event::Unknown {
            attempt: third,
            outcome: Outcome::Status {
                code: 0,
                min_expiration: AbsoluteTime::from_micros(44),
            },
            response: None,
            interruption: None,
        },
    )?;
    phase(&mut store, &mut state, Phase::Uncertain)?;
    assert!(state.uncertain());
    assert!(!state.requires_explicit_retry());
    assert_eq!(state.counts.accepted, 0);
    assert!(
        state
            .check(&Event::NotApplied {
                attempt: third,
                reason: NoEffect::NotSubmitted,
                interruption: None
            })
            .is_err()
    );
    assert!(
        state
            .check(&Event::RetryRefused { attempt: third })
            .is_err()
    );
    assert!(
        state
            .check(&Event::Phase {
                phase: Phase::Running,
                counts: state.counts
            })
            .is_err()
    );
    phase(&mut store, &mut state, Phase::CancelRequested)?;
    phase(&mut store, &mut state, Phase::Cancelled)?;
    let original = state.pending;
    drop(state);
    drop(store);
    let mut store = Store::open(&path, store::Limits::default())?;
    let state = State::load(&mut store)?;
    assert_eq!(state.phase, Phase::Cancelled);
    assert_eq!(state.pending, original);
    assert_eq!(state.counts, Counts::default());
    assert!(state.uncertain());
    assert!(
        state
            .check(&Event::Phase {
                phase: Phase::Running,
                counts: state.counts
            })
            .is_err()
    );
    Ok(())
}
