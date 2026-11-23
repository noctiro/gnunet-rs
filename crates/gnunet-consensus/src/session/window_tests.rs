//! Phase expiry and never-issued population ownership. Local receipts below
//! establish only the stated host disposition, never a remote agreement vote.
use super::*;

fn gradecast(domain: &Instance) -> Result<Session<'_>, Error> {
    let peers = [[1; 32], [2; 32], [3; 32], [4; 32]];
    let mut session = Session::new(
        domain,
        peers[0],
        join(&peers),
        Limits::default(),
        Abi::native(),
        10_000,
    )?;
    receipt(&mut session)?;
    // Stage directly at the production repetition boundary for these local
    // transition tests; no preface or end-to-end success is implied.
    session.stage = Stage::InitRep;
    session.now = 20_000;
    for _ in 0..8 {
        session.init_rep_step()?;
        if session.stage == Stage::Gradecast {
            return Ok(session);
        }
    }
    Err(Error::NotReady)
}

#[test]
fn missed_leader_windows_grade_without_native_creation_or_invented_votes() -> Result<(), Error> {
    let domain = Instance::new();
    let mut session = gradecast(&domain)?;
    let local = session.local;
    // The first leader has only a local snapshot; the second has no snapshot.
    session.leader_setup(local, Round::Lead)?;
    let never_issued = session.leaders[local].source.ok_or(Error::NotReady)?;
    session.now = session.window_deadline(Round::Lead, 0);
    for leader in [local, 1] {
        session.leader_setup(leader, Round::Lead)?;
        check(session.leaders[leader].stage == LeaderStage::Setup(Round::Echo))?;
    }
    check(session.effect().is_none() && session.set_at(never_issued).is_err())?;
    check(session.tasks.is_empty() && session.unfinished == 0)?;
    check(session.leaders[2].stage == LeaderStage::Setup(Round::Lead))?;
    session.now = session.window_deadline(Round::Echo, 0);
    session.leader_setup(local, Round::Echo)?;
    check(session.leaders[local].stage == LeaderStage::EchoGrade)?;
    session.echo_grade_step(local)?;
    check(session.leaders[local].contested)?;
    session.now = session.window_deadline(Round::Confirm, 0);
    session.leader_setup(local, Round::Confirm)?;
    session.confirm_grade_step(local)?;
    check(session.leaders[local].stage == LeaderStage::Done)?;
    check(session.leaders[local].confidence == 0)?;
    check(
        session
            .round_ballot
            .as_ref()
            .ok_or(Error::NotReady)?
            .count()
            == 0,
    )?;
    check(session.effect().is_none() && session.outcome().failure.is_none())
}

#[test]
fn issued_population_keeps_active_cancellation_and_original_close_debt() -> Result<(), Error> {
    let domain = Instance::new();
    let mut session = gradecast(&domain)?;
    session.leader_setup(0, Round::Lead)?;
    let source = session.leaders[0].source.ok_or(Error::NotReady)?;
    session.leader_setup(0, Round::Lead)?;
    receipt(&mut session)?;
    // Only some tasks have been planned when the actual window expires.
    session.leader_setup(0, Round::Lead)?; // Local contribution.
    session.leader_setup(0, Round::Lead)?; // Original outgoing peer1.
    let active = session
        .tasks
        .iter()
        .position(|task| task.set == source && task.peer == 1)
        .ok_or(Error::NotReady)?;
    session.gradecast_task(active)?;
    let task_id = session.tasks[active].id;
    receipt(&mut session)?;
    let (peer1, peer2) = Session::arrange(0, 3, session.peers.len());
    let context = RoundContext {
        kind: 2,
        peer1,
        peer2,
        repetition: 0,
        leader: 0,
        contested: 0,
    };
    let old_offer = session.offer(session.peers[3], context, session.now)?;
    let next_offer = session.offer(
        session.peers[3],
        RoundContext { kind: 3, ..context },
        session.now,
    )?;
    session.now = session.window_deadline(Round::Lead, 0);
    for _ in 0..4 {
        session.leader_setup(0, Round::Lead)?;
        if session.leaders[0].stage == LeaderStage::Run(Round::Lead) {
            break;
        }
    }
    check(!session.leader_run(0, Round::Lead)?)?;
    for index in 0..session.tasks.len() {
        if session.tasks[index].peer != session.local {
            session.gradecast_task(index)?;
            if session.tasks[index].state == TaskState::Cancel {
                session.gradecast_task(index)?;
                let action = &session.effect().ok_or(Error::NotReady)?.action;
                check(matches!(action, Action::CancelTask { task } if *task == task_id))?;
                receipt(&mut session)?;
            }
        }
    }
    check(session.unfinished == 0 && session.task_failures().1 == 3)?;
    check(session.leaders[0].echo_ballot.count() == 1)?;
    session.leader_run(0, Round::Lead)?;
    check(
        matches!(session.effect().ok_or(Error::NotReady)?.action, Action::CloseSet { set } if set == source),
    )?;
    check(session.leaders[0].stage == LeaderStage::Run(Round::Lead))?;
    check(!session.sets[session.set_at(source)?].closed)?;
    receipt(&mut session)?;
    session.leader_run(0, Round::Lead)?;
    check(session.leaders[0].stage == LeaderStage::Setup(Round::Echo))?;
    check(session.offers[session.offer_at(old_offer)?].retire)?;
    check(!session.offers[session.offer_at(next_offer)?].retire)?;
    check(session.set_at(source).is_err() && session.outcome().failure.is_none())
}

#[test]
fn cancellation_discards_only_never_issued_population() -> Result<(), Error> {
    let domain = Instance::new();
    let mut session = gradecast(&domain)?;
    session.leader_setup(0, Round::Lead)?;
    let never_issued = session.leaders[0].source.ok_or(Error::NotReady)?;
    session.leader_setup(1, Round::Lead)?;
    let issued = session.leaders[1].source.ok_or(Error::NotReady)?;
    session.leader_setup(1, Round::Lead)?;
    receipt(&mut session)?;
    session.cancel(Error::Cancelled)?;
    let mut closed = 0;
    for _ in 0..32 {
        session.retire_step()?;
        check(session.set_at(never_issued).is_err())?;
        if let Some(effect) = session.effect()
            && let Action::CloseSet { set } = effect.action
        {
            check(set == issued)?;
            closed += 1;
        }
        receipt(&mut session)?;
        if session.is_quiescent() {
            return check(closed == 1 && !session.outcome().client_done_written);
        }
    }
    Err(Error::NotReady)
}

#[test]
fn expired_preface_and_offers_keep_original_phase_bound() -> Result<(), Error> {
    for snapshot in [false, true] {
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
        receipt(&mut session)?;
        session.conclude(10_000)?;
        session.step(20_000, 1)?;
        if snapshot {
            session.setup_step()?;
        }
        let context = RoundContext {
            kind: 0,
            peer1: 2,
            peer2: 0,
            repetition: -1,
            leader: -1,
            contested: 0,
        };
        // Pick an authenticated incoming cyclic role rather than reversing it.
        let peer = 3;
        let (peer1, peer2) = Session::arrange(0, peer, peers.len());
        let context = RoundContext {
            peer1,
            peer2,
            ..context
        };
        session.offer(peers[peer], context, 20_000)?;
        let end = session.window_deadline(Round::Union, 0);
        check(session.offer(peers[peer], context, end) == Err(Error::Deadline))?;
        session.setup_step()?;
        check(session.kind == Round::Inventory && session.stage == Stage::Setup)?;
        check(session.sets.is_empty() && session.tasks.is_empty() && session.effect().is_none())?;
        check(session.offers.iter().all(|offer| offer.retire))?;
        check(session.outcome().failure.is_none())?;
        session.setup_step()?;
        let next = *session.inputs.first().ok_or(Error::NotReady)?;
        check(session.set_context(next)?.deadline == session.window_deadline(Round::Inventory, 0))?;
    }
    Ok(())
}

#[test]
fn waiting_for_conclude_retires_expired_offers_without_using_their_slots_early() -> Result<(), Error>
{
    let domain = Instance::new();
    let peers = [[1; 32], [2; 32]];
    let mut session = Session::new(
        &domain,
        peers[1],
        join(&peers),
        Limits {
            offers: 1,
            ..Limits::default()
        },
        Abi::native(),
        10_000,
    )?;
    receipt(&mut session)?;
    let union = RoundContext {
        kind: 0,
        peer1: 0,
        peer2: 1,
        repetition: -1,
        leader: -1,
        contested: 0,
    };
    let inventory = RoundContext { kind: 1, ..union };
    let offer = session.offer(peers[0], union, 10_000)?;
    let deadline = session.window_deadline(Round::Union, 0);
    check(session.stage == Stage::Collect && session.next_deadline() == Some(deadline))?;
    check(!session.step(deadline - 1, 1)? && session.offer_live(offer))?;
    check(session.step(deadline, 1)? && !session.offer_live(offer))?;
    check(session.effect().is_some_and(
        |effect| matches!(effect.action, Action::RejectOffer { offer: original } if original == offer),
    ))?;
    check(session.next_deadline() == Some(session.schedule.deadline()))?;
    check(session.offer(peers[0], inventory, deadline) == Err(Error::Capacity))?;
    receipt(&mut session)?;
    check(session.offer(peers[0], union, deadline - 1) == Err(Error::Deadline))?;
    let next = session.offer(peers[0], inventory, deadline)?;
    check(next != offer && session.offer_live(next) && session.stage == Stage::Collect)
}
