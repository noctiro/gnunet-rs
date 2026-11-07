//! Public source paths with actual matching failure inputs. Write/retirement
//! receipts are scripted local observations, not native IO or consensus votes.
use super::*;

fn drain(session: &mut Session<'_>, expected: FailureContext) -> Result<(), Error> {
    // A later caller/cleanup cause cannot replace the original business phase.
    session.cancel(Error::Io)?;
    let mut cleanup_loss = false;
    for _ in 0..1024 {
        check(session.failure_context() == Some(expected))?;
        session.retire_step()?;
        if let Some(effect) = session.effect() {
            let id = effect.id;
            if !cleanup_loss && effect.action.cleanup() {
                session.admit_effect(id)?;
                let _original = session.complete_effect(id, Completion::Lost(Error::Io))?;
                cleanup_loss = true;
            } else {
                receipt(session)?;
            }
        }
        if session.is_quiescent() {
            check(cleanup_loss && session.outcome().cleanup_failure == Some(Error::Io))?;
            check(!session.outcome().client_done_written)?;
            return check(session.failure_context() == Some(expected));
        }
    }
    Err(Error::Deadline)
}

#[test]
fn unqualified_round_preserves_original_task_failure_after_old_rows_and_cleanup()
-> Result<(), Error> {
    let domain = Instance::new();
    let peers = [[1; 32], [2; 32], [3; 32], [4; 32]];
    let mut session = Session::new(
        &domain,
        peers[0],
        join(&peers),
        Limits::default(),
        Abi::native(),
        10_000,
    )?;
    grading_offers(&mut session, GradingCase::TiedRound, 0, &peers)?;
    session.conclude(10_000)?;
    let mut first = None;
    for _ in 0..32_768 {
        match session.step(20_000, 64) {
            Err(Error::Unavailable) => {
                let context = session.failure_context().ok_or(Error::NotFound)?;
                check(context.cause == Error::Unavailable && context.stage == FailureStage::Apply)?;
                check(context.kind.is_none() && context.repetition == Some(0))?;
                check(
                    context.participants == 4
                        && context.strong == 3
                        && context.positive_leaders == 0,
                )?;
                check(
                    context.grades
                        == LeaderGrades {
                            pending: 0,
                            zero: 4,
                            one: 0,
                            two: 0,
                        },
                )?;
                // All original phase sources/tasks were really closed before
                // Apply. The earliest failure labels survive their removal.
                check(context.tasks == TasksByKind::default())?;
                check(context.first_task == first && first.is_some())?;
                check(context.observed_canonical == 20_000)?;
                check(
                    session
                        .outcome()
                        .failure
                        .is_some_and(|failure| failure.cause == Error::Unavailable),
                )?;
                return drain(&mut session, context);
            }
            Err(error) => return Err(error),
            Ok(_) => {}
        }
        check(session.failure_context().is_none())?;
        let reconcile = session.effect().and_then(|effect| match effect.action {
            Action::Reconcile {
                task,
                set,
                peer,
                context,
                ..
            } => Some((task, set, peer, context)),
            _ => None,
        });
        if let Some((task, set, peer, round)) = reconcile {
            receipt(&mut session)?;
            if first.is_none() {
                first = Some(TaskFailureContext {
                    cause: Error::Deadline,
                    stage: FailureStage::Run,
                    task_serial: task.serial,
                    set_serial: set.serial,
                    round,
                    peer_index: peers
                        .iter()
                        .position(|original| *original == peer)
                        .ok_or(Error::NotFound)?,
                    state: FailureTaskState::Active,
                    observed_canonical: 20_000,
                });
            }
            // The native task reports its original Deadline. No local write or
            // failure produces a successful remote SET DONE or membership vote.
            session.set_result(
                task,
                peer,
                SetEvent::Failure(Error::Deadline),
                20_000,
                &mut OpaqueApplication,
            )?;
        } else {
            if let Some(effect) = session.effect() {
                check(!matches!(
                    effect.action,
                    Action::ClientElement { .. } | Action::ClientDone | Action::CloseClient { .. }
                ))?;
            }
            receipt(&mut session)?;
        }
    }
    Err(Error::Deadline)
}

#[test]
fn original_public_deadline_snapshots_waitstart_before_retirement_changes_phase()
-> Result<(), Error> {
    let domain = Instance::new();
    let peers = [[1; 32], [2; 32]];
    let request = join(&peers);
    let deadline = request.deadline;
    let mut session = Session::new(
        &domain,
        peers[0],
        request,
        Limits::default(),
        Abi::native(),
        10_000,
    )?;
    session.conclude(10_000)?;
    session.step(deadline, 1)?;
    let context = session.failure_context().ok_or(Error::NotFound)?;
    check(context.cause == Error::Deadline && context.stage == FailureStage::WaitStart)?;
    check(context.kind.is_none() && context.repetition.is_none() && context.first_task.is_none())?;
    check(context.participants == 2 && context.strong == 2 && context.positive_leaders == 0)?;
    check(context.grades == LeaderGrades::default() && context.tasks == TasksByKind::default())?;
    check(context.observed_canonical == deadline && session.task_failures() == (None, 0))?;
    drain(&mut session, context)
}
