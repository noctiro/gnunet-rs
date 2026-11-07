//! Real production source/task/effect boundaries with explicit local receipts.
//! No remote DONE, confirmation vote, native daemon or agreement is fabricated.
use super::*;

fn check(value: bool) -> Result<(), Error> {
    if value { Ok(()) } else { Err(Error::Conflict) }
}
fn local_write(session: &mut Session<'_>) -> Result<(), Error> {
    let effect = session.effect().ok_or(Error::NotReady)?.id;
    session.admit_effect(effect)?;
    let _terminal = session.complete_effect(effect, Completion::Written)?;
    Ok(())
}
fn fixture(domain: &Instance) -> Result<Session<'_>, Error> {
    let mut session = Session::new(
        domain,
        [1; 32],
        Join {
            session: [7; 64],
            start: 20_000,
            deadline: 1_000_000,
            peers: &[[1; 32], [2; 32], [3; 32], [4; 32]],
        },
        Limits::default(),
        Abi::native(),
        10_000,
    )?;
    local_write(&mut session)?;
    // Start at the production gradecast boundary without supplying successful
    // peer transcripts for preceding phases or changing the actual electorate.
    session.now = 20_000;
    session.stage = Stage::InitRep;
    for _ in 0..8 {
        session.init_rep_step()?;
        if session.stage == Stage::Gradecast {
            return Ok(session);
        }
    }
    Err(Error::NotReady)
}
fn prepared_source<'id>(session: &mut Session<'id>, leader: usize) -> Result<SetId<'id>, Error> {
    session.leader_setup(leader, 2)?;
    let source = session.leaders[leader].source.ok_or(Error::NotReady)?;
    session.leader_setup(leader, 2)?;
    local_write(session)?;
    for _ in 0..8 {
        session.leader_setup(leader, 2)?;
        if session.leaders[leader].stage == LeaderStage::Run(2) {
            return Ok(source);
        }
    }
    Err(Error::NotReady)
}

#[test]
fn one_retired_source_fails_active_and_planned_tasks_without_touching_another_effect()
-> Result<(), Error> {
    let domain = Instance::new();
    let mut session = fixture(&domain)?;
    let lost = prepared_source(&mut session, 0)?;
    let live = prepared_source(&mut session, 1)?;
    let old = session
        .tasks
        .iter()
        .position(|task| task.set == lost && task.peer == 1)
        .ok_or(Error::NotReady)?;
    session.gradecast_task(old)?;
    local_write(&mut session)?;
    let next = session
        .tasks
        .iter()
        .position(|task| task.set == live && task.peer == 1)
        .ok_or(Error::NotReady)?;
    session.gradecast_task(next)?;
    let other_effect = session.effect().ok_or(Error::NotReady)?.id;
    let failed_id = session.tasks[old].id;
    check(session.source_retired(lost, Error::Io, None)?.is_none())?;
    check(
        session
            .effect()
            .is_some_and(|effect| effect.id == other_effect),
    )?;
    check(session.tasks.iter().all(|task| {
        task.set != lost || task.peer == session.local || task.state == TaskState::Failed
    }))?;
    check(session.tasks[next].state == TaskState::Starting)?;
    check(!session.set_live(lost) && session.set_live(live))?;
    check(session.set_len(lost) == Err(Error::Closed))?;
    check(session.tasks[old].id == failed_id)?;
    check(session.outcome().failure.is_none() && !session.outcome().client_done_written)?;
    check(session.leaders[0].echo_ballot.count() == 1)?;
    local_write(&mut session)?;
    check(session.tasks[next].state == TaskState::Active)?;
    session.leader_run(0, 2)?;
    let close = session.effect().ok_or(Error::NotReady)?;
    check(matches!(close.action, Action::CloseSet { set } if set == lost))?;
    let close_id = close.id;
    check(!session.sets[session.set_at(lost)?].closed)?;
    session.admit_effect(close_id)?;
    let _terminal = session.complete_effect(close_id, Completion::Retired)?;
    session.leader_run(0, 2)?;
    check(session.set_at(lost).is_err() && session.set_live(live))
}

#[test]
fn original_pending_dispositions_never_reactivate_the_retired_source() -> Result<(), Error> {
    for completion in [
        Completion::Unsent(Error::Io),
        Completion::Lost(Error::Io),
        Completion::Written,
    ] {
        let domain = Instance::new();
        let mut session = fixture(&domain)?;
        let lost = prepared_source(&mut session, 0)?;
        let task = session
            .tasks
            .iter()
            .position(|task| task.set == lost && task.peer == 1)
            .ok_or(Error::NotReady)?;
        session.gradecast_task(task)?;
        let effect = session.effect().ok_or(Error::NotReady)?.id;
        session.admit_effect(effect)?;
        let terminal = session
            .source_retired(
                lost,
                Error::Io,
                Some(RetiredEffect::Disposition { effect, completion }),
            )?
            .ok_or(Error::NotReady)?;
        check(terminal.effect.id == effect && terminal.completion == completion)?;
        check(session.tasks[task].state == TaskState::Failed)?;
        check(!session.sets[session.set_at(lost)?].ready)?;
        check(!session.sets[session.set_at(lost)?].closed)?;
        check(session.publish(Action::PrepareSet { set: lost }) == Err(Error::Closed))?;
        check(session.outcome().failure.is_none())?;
        check(session.leaders[0].confirm_ballot.count() == 1)?;
    }
    Ok(())
}

#[test]
fn population_loss_keeps_uncommitted_offer_rejection_owned() -> Result<(), Error> {
    let domain = Instance::new();
    let mut session = fixture(&domain)?;
    session.leader_setup(0, 2)?;
    let source = session.leaders[0].source.ok_or(Error::NotReady)?;
    session.leader_setup(0, 2)?;
    let effect = session.effect().ok_or(Error::NotReady)?.id;
    let context = RoundContext {
        kind: 2,
        peer1: 3,
        peer2: 0,
        repetition: 0,
        leader: 0,
        contested: 0,
    };
    let offer = session.offer([4; 32], context, 20_000)?;
    let _terminal = session.source_retired(
        source,
        Error::Io,
        Some(RetiredEffect::Disposition {
            effect,
            completion: Completion::Unsent(Error::Io),
        }),
    )?;
    check(session.offer([4; 32], context, 20_000) == Err(Error::Closed))?;
    check(!session.offer_live(offer))?;
    session.step(20_000, 1)?;
    check(session.effect().is_some_and(|effect| {
        matches!(effect.action, Action::RejectOffer { offer: original } if original == offer)
    }))?;
    // Queueing/publishing the reject is not a write or physical listener close.
    check(session.offer_at(offer).is_ok())?;
    check(!session.offer_live(offer))?;
    check(session.outcome().failure.is_none() && !session.outcome().client_done_written)
}

#[test]
fn population_loss_fails_future_plans_without_recreating_the_native_source() -> Result<(), Error> {
    let domain = Instance::new();
    let mut session = fixture(&domain)?;
    session.leader_setup(0, 2)?;
    let source = session.leaders[0].source.ok_or(Error::NotReady)?;
    session.leader_setup(0, 2)?;
    let effect = session.effect().ok_or(Error::NotReady)?.id;
    let _terminal = session.source_retired(
        source,
        Error::Io,
        Some(RetiredEffect::Disposition {
            effect,
            completion: Completion::Unsent(Error::Io),
        }),
    )?;
    for _ in 0..8 {
        session.leader_setup(0, 2)?;
        check(session.effect().is_none())?;
        if session.leaders[0].stage == LeaderStage::Run(2) {
            break;
        }
    }
    check(session.leaders[0].source == Some(source))?;
    check(
        session
            .tasks
            .iter()
            .all(|task| task.peer == session.local || task.state == TaskState::Failed),
    )?;
    check(session.apply_step() == Err(Error::Unavailable))?;
    check(!session.outcome().client_done_written && session.outcome().failure.is_none())
}
