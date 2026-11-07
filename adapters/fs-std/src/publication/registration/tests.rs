//! Structural original-history tests; native receipt provenance is tested by
//! the actual registration runner and is not established by these wire fixtures.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible history fixtures assert original request generation and raw response class"
)]
use super::*;
use gnunet_wire::official::{AbsoluteTime, datastore};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn frame(response: Response<'_>) -> TestResult<Vec<u8>> {
    let mut bytes = vec![0; response.encoded_len()?];
    response.encode(&mut bytes)?;
    Ok(bytes)
}
fn append(state: &mut State, index: usize, event: Event<'_>, phase: Phase) -> TestResult {
    state.check(&event, 1, phase)?;
    state.prepare(&event)?;
    state.apply(index, event)?;
    Ok(())
}
fn intent(state: &mut State, index: usize) -> TestResult<Attempt> {
    append(
        state,
        index,
        Event::Intent {
            index: 0,
            request_hash: [9; 64],
        },
        Phase::Running,
    )?;
    Ok(state.pending.ok_or("original intent missing")?.attempt)
}
#[test]
fn only_actual_fs_reply_shape_advances_index_prefix_and_retry_keeps_generation() -> TestResult {
    let mut state = State::default();
    let first = intent(&mut state, 1)?;
    assert!(
        state
            .check(
                &Event::NotApplied {
                    attempt: first,
                    reason: NoEffect::NotSent,
                    interruption: None
                },
                1,
                Phase::Running
            )
            .is_err()
    );
    let mut status = vec![0; 32];
    let used = datastore::Response::Status(datastore::Status {
        code: 1,
        min_expiration: AbsoluteTime::NEVER,
        message: None,
    })
    .encode(&mut status)?;
    status.truncate(used);
    assert!(
        state
            .check(
                &Event::Accepted {
                    attempt: first,
                    response: &status,
                    interruption: None
                },
                1,
                Phase::Running
            )
            .is_err()
    );
    assert!(state.accepted.is_empty());
    let failed = frame(Response::IndexFailed {
        message: b"refused \xff",
    })?;
    let refused = Event::Refused {
        attempt: first,
        response: &failed,
        interruption: None,
    };
    let (kind, bytes) = encode_event(&refused)?;
    append(&mut state, 2, decode_event(kind, &bytes)?, Phase::Running)?;
    assert!(state.requires_explicit_retry());
    assert!(!state.uncertain());
    assert!(
        state
            .check(
                &Event::Intent {
                    index: 0,
                    request_hash: [9; 64]
                },
                1,
                Phase::Running
            )
            .is_err()
    );
    append(
        &mut state,
        3,
        Event::RetryRefused { attempt: first },
        Phase::Failed,
    )?;
    let second = intent(&mut state, 4)?;
    assert_ne!(first.intent_record, second.intent_record);
    let accepted = frame(Response::IndexStarted)?;
    assert!(
        state
            .check(
                &Event::Accepted {
                    attempt: first,
                    response: &accepted,
                    interruption: None
                },
                1,
                Phase::Running
            )
            .is_err()
    );
    let actual = Event::Accepted {
        attempt: second,
        response: &accepted,
        interruption: Some(Interruption::TimedOut),
    };
    let (kind, bytes) = encode_event(&actual)?;
    let (attempt, original, interruption) = accepted_view(kind, &bytes)?;
    assert_eq!(attempt, second);
    assert_eq!(original, accepted);
    assert_eq!(interruption, Some(Interruption::TimedOut));
    append(
        &mut state,
        5,
        decode_event(kind, &bytes)?,
        Phase::PauseRequested,
    )?;
    assert!(state.complete(1));
    assert_eq!(state.accepted.len(), 1);
    assert!(state.pending.is_none());
    Ok(())
}
#[test]
fn bare_intent_and_unknown_do_not_become_no_send_or_explicit_retry_permissions() -> TestResult {
    let mut state = State::default();
    let original = intent(&mut state, 1)?;
    assert!(state.uncertain());
    assert!(!state.complete(1));
    let event = Event::Unknown {
        attempt: original,
        response: None,
        interruption: Some(Interruption::Cancelled),
    };
    let (kind, bytes) = encode_event(&event)?;
    append(
        &mut state,
        2,
        decode_event(kind, &bytes)?,
        Phase::CancelRequested,
    )?;
    assert!(state.uncertain());
    assert!(!state.requires_explicit_retry());
    for phase in [
        Phase::Running,
        Phase::Failed,
        Phase::Uncertain,
        Phase::Cancelled,
    ] {
        assert!(
            state
                .check(&Event::RetryRefused { attempt: original }, 1, phase)
                .is_err()
        );
        assert!(
            state
                .check(
                    &Event::NotApplied {
                        attempt: original,
                        reason: NoEffect::NotSent,
                        interruption: None
                    },
                    1,
                    phase
                )
                .is_err()
        );
        assert!(
            state
                .check(
                    &Event::Intent {
                        index: 0,
                        request_hash: [9; 64]
                    },
                    1,
                    phase
                )
                .is_err()
        );
    }
    assert!(state.accepted.is_empty());
    assert!(!state.complete(1));
    let mut truncated = bytes.clone();
    let _last = truncated.pop();
    assert!(decode_event(kind, &truncated).is_err());
    let mut trailing = bytes;
    trailing.push(0);
    assert!(decode_event(kind, &trailing).is_err());
    Ok(())
}
