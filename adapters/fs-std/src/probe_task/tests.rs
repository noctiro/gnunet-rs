//! Private WAL and genuine zero-I/O native refusal tests; no native success or C acceptance claim.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Focused fallible tests assert original source binding, real setup outcomes and historical replay refusal"
)]
use super::*;
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
type TestResult = Result<(), Box<dyn std::error::Error>>;
struct Temporary(PathBuf);
impl Temporary {
    fn new() -> std::io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        loop {
            let p = std::env::temp_dir().join(format!(
                "gnunet-probe-task-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::create_dir(&p) {
                Ok(()) => return Ok(Self(p)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_dir_all(&self.0);
    }
}
fn content() -> Content {
    Content {
        key: [1; 64],
        query: [2; 64],
        size: BLOCK_BYTES as u64 + 1,
    }
}
fn options() -> probe::Options {
    let mut options = probe::Options::new(AbsoluteTime::from_micros(0));
    options.max_path_blocks = 1;
    options
}
fn deadline(source: &EndpointSource) -> Result<AbsoluteTime, ProtocolError> {
    Ok(AbsoluteTime::from_micros(
        source
            .clock()
            .sample()?
            .now
            .as_micros()
            .checked_add(5_000_000)
            .ok_or(ProtocolError::Overflow)?,
    ))
}
#[test]
fn actual_setup_refusal_records_once_and_original_receipt_cannot_cross_tasks() -> TestResult {
    let temp = Temporary::new()?;
    let path = temp.0.join("task");
    let mut task = Task::create(&path, content().uri(), options(), Limits::default())?;
    let source = EndpointSource::unix(temp.0.join("never-opened.sock"));
    let target = deadline(&source)?;
    let outcome = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(task.run(source, &mut Buffers::new(), 1, target, |_| {
            Control::Continue
        }))?;
    assert_eq!(outcome.receipt.kind(), Kind::Resource);
    let actual = outcome
        .recorded
        .result()
        .as_ref()
        .err()
        .ok_or("expected original native path-budget refusal")?;
    assert_eq!(actual.queries_written(), 0);
    assert_eq!(actual.started(), None);
    assert!(outcome.recorded.frames().is_empty());
    assert_eq!(task.status().historical.trials(), 0);
    assert_eq!(task.status().historical.errors().resource, 1);
    let before = task.status().state_records;
    outcome.receipt.record(&mut task)?;
    assert_eq!(task.status().state_records, before);
    let mut foreign = Task::create(
        temp.0.join("foreign"),
        content().uri(),
        options(),
        Limits::default(),
    )?;
    assert!(matches!(
        outcome.receipt.record(&mut foreign),
        Err(Cause::Protocol(ProtocolError::StaleGeneration))
    ));
    drop(task);
    let mut task = Task::open(&path, Limits::default())?;
    assert_eq!(task.status().historical.attempts(), 1);
    assert_eq!(task.status().historical.errors().resource, 1);
    assert_eq!(task.observations().count(), 1);
    let source = EndpointSource::unix(temp.0.join("never-opened.sock"));
    let pending = task.begin_recorded(&source, 0, deadline(&source)?)?;
    outcome.receipt.record(&mut task)?;
    assert_eq!(task.status().pending, Some(pending));
    assert_eq!(task.status().historical.errors().resource, 1);
    task.abandon_interrupted()?;
    assert_eq!(task.status().interrupted, 1);
    assert_eq!(task.status().historical.trials(), 0);
    Ok(())
}
#[test]
fn interrupted_intent_requires_explicit_abandon_and_cancel_never_creates_a_trial() -> TestResult {
    let temp = Temporary::new()?;
    let path = temp.0.join("task");
    let limits = Limits {
        max_attempts: 2,
        max_trials: 2,
        ..Limits::default()
    };
    let mut task = Task::create(&path, content().uri(), options(), limits)?;
    let source = EndpointSource::unix(temp.0.join("unused.sock"));
    let original = task.begin_recorded(&source, 1, deadline(&source)?)?;
    drop(task);
    let mut task = Task::open(&path, limits)?;
    assert_eq!(task.status().pending, Some(original));
    assert!(!task.status().active);
    let error = task
        .begin_recorded(&source, 1, deadline(&source)?)
        .err()
        .ok_or("bare original intent must refuse a fresh attempt")?;
    assert!(matches!(
        error,
        Cause::Protocol(ProtocolError::OutcomeUnknown)
    ));
    assert_eq!(task.status().historical.trials(), 0);
    task.abandon_interrupted()?;
    assert_eq!(task.status().interrupted, 1);
    let second = task.begin_recorded(&source, 0, deadline(&source)?)?;
    assert_eq!(second.ordinal, 2);
    task.cancel()?;
    assert_eq!(task.status().phase, Phase::Cancelled);
    assert_eq!(task.status().interrupted, 2);
    assert_eq!(task.status().historical.trials(), 0);
    drop(task);
    let task = Task::open(&path, limits)?;
    assert_eq!(task.status().phase, Phase::Cancelled);
    assert_eq!(task.status().historical.attempts(), 2);
    assert_eq!(task.status().historical.successes(), 0);
    Ok(())
}
#[test]
fn checksum_valid_historical_success_without_a_real_root_path_is_refused() -> TestResult {
    let temp = Temporary::new()?;
    let path = temp.0.join("task");
    let mut task = Task::create(&path, content().uri(), options(), Limits::default())?;
    let source = EndpointSource::unix(temp.0.join("unused.sock"));
    let original = task.begin_recorded(&source, 1, deadline(&source)?)?;
    let scope = (*task.task_id(), task.manifest_hash);
    drop(task);
    // Deliberately written through the real Store so the CRC/sequence are valid.
    // This is malformed historical input, never a fabricated native Observed.
    let terminal = codec::Terminal {
        task: scope.0,
        manifest: scope.1,
        observation: Observation {
            attempt: original,
            kind: Kind::Success,
            progress: Progress {
                plaintext_bytes: 1,
                blocks: 1,
                encoded_bytes: 17,
            },
            queries_written: 1,
            started: Some(original.admitted),
            last_checked: Some(AbsoluteTime::from_micros(original.admitted.as_micros() + 1)),
            retired: true,
            wanted: Control::Continue,
        },
        transport_loss: false,
        diagnostic: Vec::new(),
        last_response: Vec::new(),
        frames: Vec::new(),
    };
    let body = codec::encode_terminal(&terminal)?;
    let mut store = Store::open(&path, store::Limits::default())?;
    store.append(OBSERVATION, &body)?;
    drop(store);
    let error = Task::open(&path, Limits::default())
        .err()
        .ok_or("historical success without root authentication was accepted")?;
    assert!(matches!(error.cause, Cause::Format | Cause::Transcript(_)));
    assert!(error.recorded.is_none());
    Ok(())
}

#[test]
fn actual_same_content_observation_cannot_be_transplanted_into_another_task_wal() -> TestResult {
    let temp = Temporary::new()?;
    let source = EndpointSource::unix(temp.0.join("never-opened.sock"));
    let mut original = Task::create(
        temp.0.join("original"),
        content().uri(),
        options(),
        Limits::default(),
    )?;
    let target = deadline(&source)?;
    let outcome = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(original.run(source, &mut Buffers::new(), 1, target, |_| {
            Control::Continue
        }))?;
    assert_eq!(outcome.receipt.kind(), Kind::Resource);
    let intent = codec::encode_attempt(outcome.receipt.attempt())?;
    let foreign_path = temp.0.join("foreign");
    let foreign = Task::create(&foreign_path, content().uri(), options(), Limits::default())?;
    assert_ne!(original.task_id(), foreign.task_id());
    drop(foreign);
    // Both original frames are genuine and remain sequence/CRC-valid here, but
    // their original task scope is different. This cannot become foreign history.
    let mut store = Store::open(&foreign_path, store::Limits::default())?;
    store.append(INTENT, &intent)?;
    store.append(OBSERVATION, &outcome.receipt.body)?;
    drop(store);
    let refused = Task::open(&foreign_path, Limits::default())
        .err()
        .ok_or("cross-task actual observation was adopted")?;
    assert!(matches!(
        refused.cause,
        Cause::Protocol(ProtocolError::Conflict)
    ));
    assert!(refused.recorded.is_none());
    Ok(())
}
