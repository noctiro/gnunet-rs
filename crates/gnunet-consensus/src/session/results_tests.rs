//! Public task transcripts: partial SET results are not completed proposals.
//! Local write/retirement receipts are scripted and supply no native IO credit.
use super::*;

const BASE: [u8; 4] = [0, 24, 0, 1];
const GOOD: [u8; 4] = [0, 24, 0, 2];
const PARTIAL: [u8; 4] = [0, 24, 0, 99];

#[derive(Clone, Copy)]
enum Refusal {
    Failure,
    Malformed,
}

fn failed_participant(refusal: Refusal) -> Result<(), Error> {
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
    session.insert(24, &[1], 10_000, &mut OpaqueApplication)?;
    grading_offers(&mut session, GradingCase::TiedRound, 0, &peers)?;
    session.conclude(10_000)?;
    let (mut inventory, mut leader, mut output, mut done) = (false, false, 0, false);
    for _ in 0..65_536 {
        session.step(20_000, 1)?;
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
        if let Some((task, set, peer, context)) = reconcile {
            let population = original_population(&session, set)?;
            if context.kind == 1 {
                check(
                    population.contains(&BASE.to_vec())
                        && population.contains(&GOOD.to_vec())
                        && !population.contains(&PARTIAL.to_vec()),
                )?;
                inventory = true;
            }
            if context.kind == 3 && context.leader == 3 {
                check(
                    population.contains(&BASE.to_vec()) && !population.contains(&PARTIAL.to_vec()),
                )?;
                leader = true;
            }
            receipt(&mut session)?;
            if peer == peers[3] {
                if context.kind == 0 || context.kind == 2 && context.leader == 3 {
                    session.set_result(
                        task,
                        peer,
                        SetEvent::AddLocal {
                            element_type: 25,
                            data: &PARTIAL,
                        },
                        20_000,
                        &mut OpaqueApplication,
                    )?;
                    if context.kind == 2 {
                        session.set_result(
                            task,
                            peer,
                            SetEvent::AddRemote {
                                element_type: 25,
                                data: &BASE,
                            },
                            20_000,
                            &mut OpaqueApplication,
                        )?;
                    }
                }
                if context.kind == 1 {
                    let mut marker = [0; 12];
                    marker[2] = 2;
                    marker[3..11].copy_from_slice(&u64::MAX.to_be_bytes());
                    marker[11] = 3;
                    session.set_result(
                        task,
                        peer,
                        SetEvent::AddLocal {
                            element_type: 25,
                            data: &marker,
                        },
                        20_000,
                        &mut OpaqueApplication,
                    )?;
                }
                match refusal {
                    Refusal::Failure => session.set_result(
                        task,
                        peer,
                        SetEvent::Failure(Error::Unavailable),
                        20_000,
                        &mut OpaqueApplication,
                    )?,
                    Refusal::Malformed => check(
                        session.set_result(
                            task,
                            peer,
                            SetEvent::AddLocal {
                                element_type: 0,
                                data: &[],
                            },
                            20_000,
                            &mut OpaqueApplication,
                        ) == Err(Error::Malformed),
                    )?,
                }
            } else {
                let remote = if context.kind == 1 {
                    let mut marker = alloc::vec![0; 12];
                    marker[2] = 2;
                    marker[3..11].copy_from_slice(&2u64.to_be_bytes());
                    marker[11] = peers
                        .iter()
                        .position(|p| *p == peer)
                        .ok_or(Error::NotFound)? as u8;
                    alloc::vec![BASE.to_vec(), GOOD.to_vec(), marker]
                } else {
                    alloc::vec![BASE.to_vec(), GOOD.to_vec()]
                };
                source_union_done(&mut session, task, peer, &population, &remote)?;
            }
            check(session.outcome().failure.is_none())?;
            continue;
        }
        if let Some(effect) = session.effect() {
            if let Action::ClientElement { element_type, data } = &effect.action {
                check(*element_type == 24 && data == &[2])?;
                output += 1;
            }
            check(!matches!(effect.action, Action::CloseClient { .. }))?;
        }
        done |= receipt(&mut session)? == Some(true);
        if session.is_quiescent() {
            return check(
                inventory
                    && leader
                    && output == 1
                    && done
                    && session.outcome().failure.is_none()
                    && session.task_failures().1 != 0
                    && session.staged_bytes == 0
                    && session.sizes[3] == 0,
            );
        }
    }
    Err(Error::Deadline)
}
#[test]
fn failed_participant_cannot_publish_partial_union_lead_or_inventory() -> Result<(), Error> {
    failed_participant(Refusal::Failure)
}
#[test]
fn malformed_participant_cancels_its_original_tasks_without_killing_honest_quorum()
-> Result<(), Error> {
    failed_participant(Refusal::Malformed)
}

#[test]
fn completed_union_survives_source_loss_while_partial_task_is_discarded() -> Result<(), Error> {
    let domain = Instance::new();
    let peers = [[1; 32], [2; 32], [3; 32]];
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
    let mut completed = false;
    let mut lost = false;
    let mut observed = false;
    for _ in 0..4096 {
        session.step(20_000, 1)?;
        if let Some(effect) = session.effect() {
            match effect.action {
                Action::Reconcile {
                    task, set, peer, ..
                } => {
                    let population = original_population(&session, set)?;
                    receipt(&mut session)?;
                    if !completed {
                        source_union_done(&mut session, task, peer, &population, &[GOOD.to_vec()])?;
                        completed = true;
                    } else {
                        session.set_result(
                            task,
                            peer,
                            SetEvent::AddLocal {
                                element_type: 25,
                                data: &PARTIAL,
                            },
                            20_000,
                            &mut OpaqueApplication,
                        )?;
                        check(session.current.ids.is_empty())?;
                        check(
                            session
                                .source_retired(set, Error::Unavailable, None)?
                                .is_none(),
                        )?;
                        lost = true;
                    }
                    continue;
                }
                Action::PrepareSet { set } if session.set_context(set)?.kind == 1 => {
                    let population = original_population(&session, set)?;
                    check(
                        population.contains(&GOOD.to_vec())
                            && !population.contains(&PARTIAL.to_vec()),
                    )?;
                    observed = true;
                    break;
                }
                _ => {}
            }
        }
        receipt(&mut session)?;
    }
    check(completed && lost && observed && session.outcome().failure.is_none())?;
    session.cancel(Error::Cancelled)?;
    for _ in 0..1024 {
        session.retire_step()?;
        receipt(&mut session)?;
        if session.is_quiescent() {
            return Ok(());
        }
    }
    Err(Error::Deadline)
}

#[test]
fn inventory_sender_never_wraps_the_official_one_byte_index() -> Result<(), Error> {
    let peers: Vec<_> = (0u16..257)
        .map(|index| {
            let mut peer = [0; 32];
            peer[..2].copy_from_slice(&index.to_be_bytes());
            peer
        })
        .collect();
    for local in [255, 256] {
        let domain = Instance::new();
        let mut session = Session::new(
            &domain,
            peers[local],
            join(&peers),
            Limits {
                peers: 257,
                ..Limits::default()
            },
            Abi::native(),
            10_000,
        )?;
        for (index, peer) in peers.iter().enumerate() {
            let (peer1, peer2) = Session::arrange(local, index, peers.len());
            if index != local && peer2 as usize == local {
                session.offer(
                    *peer,
                    RoundContext {
                        kind: 0,
                        peer1,
                        peer2,
                        repetition: -1,
                        leader: -1,
                        contested: 0,
                    },
                    10_000,
                )?;
            }
        }
        session.conclude(10_000)?;
        let mut observed = false;
        for _ in 0..8192 {
            session.step(20_000, 32)?;
            if let Some(effect) = session.effect() {
                match effect.action {
                    Action::PrepareSet { set } if session.set_context(set)?.kind == 1 => {
                        let population = original_population(&session, set)?;
                        if local == 255 {
                            check(
                                population.len() == 1
                                    && Block::decode(&population[0])?.size_marker()?.1 == 255,
                            )?;
                        } else {
                            check(population.is_empty())?;
                        }
                        observed = true;
                        break;
                    }
                    Action::Reconcile { task, peer, .. } => {
                        receipt(&mut session)?;
                        session.set_result(
                            task,
                            peer,
                            SetEvent::Failure(Error::Unavailable),
                            20_000,
                            &mut OpaqueApplication,
                        )?;
                        continue;
                    }
                    _ => {}
                }
            }
            receipt(&mut session)?;
        }
        check(observed)?;
        session.cancel(Error::Cancelled)?;
        for _ in 0..1024 {
            session.retire_step()?;
            receipt(&mut session)?;
            if session.is_quiescent() {
                break;
            }
        }
        check(session.is_quiescent() && !session.outcome().client_done_written)?;
    }
    Ok(())
}
