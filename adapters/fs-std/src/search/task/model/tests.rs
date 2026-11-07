//! Focused structural history and complete numeric-policy preservation.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible history tests assert exact original fields and real signed source bytes"
)]
use super::*;
use crate::durable::store::{self, Store};
use crate::ipc;
use gnunet_fs::{Content, Keyword, Keywords, metadata, ublock};
use gnunet_wire::official::AbsoluteTime;
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
            "gnunet-search-model-{}-{now}-{}",
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
fn manifest() -> TestResult<Manifest> {
    let terms = [
        Keyword::new(b"needle", true)?,
        Keyword::new(b"needle", false)?,
        Keyword::new(b"\xff", true)?,
    ];
    let uri = Uri::Keywords(Keywords::new(&terms)?);
    let mut query_uri = vec![0; uri.encoded_len()?];
    uri.encode(&mut query_uri)?;
    Ok(Manifest {
        query_uri,
        max_observations: 73,
        options: search::Options {
            anonymity: 7,
            local_only: true,
            deadline: AbsoluteTime::from_micros(123456),
            limits: search::Limits {
                queries: 5,
                results: 17,
                retained_bytes: 800_001,
                metadata_entries: 73,
                metadata_bytes: 60_003,
            },
            block: ublock::Limits {
                max_wire_bytes: 61_000,
                max_label_bytes: 513,
                uri: gnunet_fs::Limits {
                    max_input_bytes: 4095,
                    max_keywords: 7,
                    max_keyword_bytes: 257,
                    max_identifier_bytes: 511,
                },
                metadata: metadata::Limits {
                    max_coded_bytes: 64_003,
                    max_plain_bytes: 400_003,
                    max_entries: 99,
                },
            },
            protocol: ipc::ProtocolLimits {
                max_block_bytes: 62_000,
                expected_loc_peer: Some([9; 32]),
                seen_replay: ipc::SeenReplay::Continued,
            },
            native: ipc::Limits {
                frame_bytes: 65_534,
                io_slice_bytes: 17,
            },
        },
    })
}
fn policies(options: search::Options) -> Vec<u64> {
    let mut values = vec![u64::from(options.anonymity), u64::from(options.local_only)];
    values.extend(
        [
            options.limits.queries,
            options.limits.results,
            options.limits.retained_bytes,
            options.limits.metadata_entries,
            options.limits.metadata_bytes,
            options.block.max_wire_bytes,
            options.block.max_label_bytes,
            options.block.uri.max_input_bytes,
            options.block.uri.max_keywords,
            options.block.uri.max_keyword_bytes,
            options.block.uri.max_identifier_bytes,
            options.block.metadata.max_coded_bytes,
            options.block.metadata.max_plain_bytes,
            options.block.metadata.max_entries,
            options.protocol.max_block_bytes,
            options.native.frame_bytes,
            options.native.io_slice_bytes,
        ]
        .map(|n| n as u64),
    );
    values.push(u64::from(options.protocol.expected_loc_peer.is_some()));
    if let Some(peer) = options.protocol.expected_loc_peer {
        values.extend(peer.map(u64::from));
    }
    values.push(match options.protocol.seen_replay {
        ipc::SeenReplay::RecentWindow => 0,
        ipc::SeenReplay::Continued => 1,
    });
    values
}
fn append(store: &mut Store, state: &mut State, event: Event<'_>) -> TestResult {
    state.prepare(&event)?;
    let (kind, body) = codec::encode_event(&event)?;
    let sequence = store.append(kind, &body)?;
    let index = store.record_count() - 1;
    state.apply(sequence, index, kind, &body)?;
    Ok(())
}
#[test]
fn manifest_roundtrip_retains_all_policies_and_omits_only_run_deadline() -> TestResult {
    let original = manifest()?;
    let expected = policies(original.options);
    let (kind, bytes) = codec::encode_event(&Event::Manifest(original.clone()))?;
    let Event::Manifest(decoded) = codec::decode_event(kind, &bytes)? else {
        return Err("manifest type changed".into());
    };
    assert_eq!(decoded.query_uri, original.query_uri);
    assert_eq!(decoded.max_observations, 73);
    assert_eq!(decoded.options.deadline, AbsoluteTime::from_micros(0));
    assert_eq!(policies(decoded.options), expected);
    assert!(matches!(decoded.query()?,Uri::Keywords(keywords) if keywords.len()==3));
    let mut trailing = bytes;
    trailing.push(0);
    assert!(matches!(
        codec::decode_event(kind, &trailing),
        Err(ModelError::Format)
    ));
    let mut invalid = original;
    invalid.options.limits.queries = 65;
    assert_eq!(invalid.validate(), Err(ModelError::Limit));
    Ok(())
}
#[test]
fn raw_prefix_restart_preserves_pending_summary_and_refuses_invalid_lifecycle() -> TestResult {
    let temporary = Temporary::new()?;
    let path = temporary.0.join("task");
    let original = manifest()?;
    let (kind, body) = codec::encode_event(&Event::Manifest(original))?;
    let mut store = Store::create(&path, store::Limits::default())?;
    store.append(kind, &body)?;
    let mut state = State::load(&mut store)?;
    append(
        &mut store,
        &mut state,
        Event::Phase {
            phase: Phase::Running,
            counts: Counts::default(),
        },
    )?;
    let limits = ublock::Limits::default();
    let context = ublock::Context::keyword(b"needle", limits)?;
    let publisher = ublock::Publisher::keyword(b"needle", limits)?;
    let content = Content {
        key: [11; 64],
        query: [22; 64],
        size: 123,
    };
    let mut encoded = vec![0; 1024];
    let sealed = publisher.seal(b"", content.uri(), None, &mut encoded)?;
    let wire = sealed.bytes();
    let observation = Observation {
        query_id: 0,
        kind: Kind::Keyword,
        namespace: context.namespace_key(),
        label: b"needle",
        lookup_key: context.query(),
        wire,
        expiration: AbsoluteTime::from_micros(100),
        observed_at: AbsoluteTime::from_micros(100),
    };
    append(&mut store, &mut state, Event::Observation(observation))?;
    assert_eq!(state.observations.len(), 1);
    assert_eq!(state.counts, Counts::default());
    assert_eq!(
        state.check(&Event::Observation(Observation {
            observed_at: AbsoluteTime::from_micros(99),
            ..observation
        })),
        Err(ModelError::Format)
    );
    assert_eq!(
        state.check(&Event::Observation(Observation {
            observed_at: AbsoluteTime::from_micros(101),
            ..observation
        })),
        Err(ModelError::Format)
    );
    let foreign = [0; 32];
    assert_eq!(
        state.check(&Event::Observation(Observation {
            namespace: &foreign,
            ..observation
        })),
        Err(ModelError::Binding)
    );
    let counts = Counts {
        observations: 1,
        results: 1,
        visible: 0,
        queries: 1,
    };
    append(
        &mut store,
        &mut state,
        Event::Phase {
            phase: Phase::PauseRequested,
            counts,
        },
    )?;
    assert_eq!(
        state.check(&Event::Observation(observation)),
        Err(ModelError::Transition)
    );
    append(
        &mut store,
        &mut state,
        Event::Phase {
            phase: Phase::Paused,
            counts,
        },
    )?;
    drop(state);
    drop(store);
    let mut store = Store::open(&path, store::Limits::default())?;
    let mut state = State::load(&mut store)?;
    assert_eq!(state.phase, Phase::Paused);
    assert_eq!(state.counts, counts);
    assert_eq!(state.observations.len(), 1);
    let native = store
        .read_record(state.observations[0])?
        .ok_or("raw original record missing")?;
    let restored = codec::observation_view(native.kind, native.bytes)?;
    assert_eq!(restored.wire, wire);
    assert_eq!(restored.expiration.as_micros(), 100);
    assert_eq!(restored.observed_at, AbsoluteTime::from_micros(100));
    let mut plaintext = vec![0; wire.len()];
    let opened = context.open(restored.wire, &mut plaintext)?;
    let decoded = opened.decode(&mut [], &mut metadata::NoCodec, metadata::Mode::Strict)?;
    assert!(matches!(decoded.uri()?,Uri::Content(value) if value==content));
    append(
        &mut store,
        &mut state,
        Event::Phase {
            phase: Phase::CancelRequested,
            counts,
        },
    )?;
    assert_eq!(
        state.check(&Event::Phase {
            phase: Phase::Running,
            counts
        }),
        Err(ModelError::Transition)
    );
    append(
        &mut store,
        &mut state,
        Event::Phase {
            phase: Phase::Cancelled,
            counts,
        },
    )?;
    assert_eq!(
        state.check(&Event::Phase {
            phase: Phase::Running,
            counts
        }),
        Err(ModelError::Transition)
    );
    drop(state);
    drop(store);
    let mut store = Store::open(&path, store::Limits::default())?;
    assert_eq!(State::load(&mut store)?.phase, Phase::Cancelled);
    Ok(())
}
