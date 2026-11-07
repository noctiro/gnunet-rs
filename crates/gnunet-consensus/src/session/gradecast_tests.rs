//! Public Session transcripts for a single Byzantine leader D. Membership
//! differences and matching terminal SET results are explicit source inputs;
//! local Written/Retired receipts are not native IO or agreement evidence.
use super::*;

const NOW: u64 = 20_000;
const VALUE: [u8; 4] = [0, 24, 0, 9];
const BOTTOM: [u8; 3] = [0, 0, 1];
const LEADER: usize = 3;

fn offers(session: &mut Session<'_>, local: usize, peers: &[[u8; 32]]) -> Result<(), Error> {
    for (peer, identity) in peers.iter().enumerate() {
        if peer == local {
            continue;
        }
        let (peer1, peer2) = Session::arrange(local, peer, peers.len());
        if peer2 as usize != local {
            continue;
        }
        for repetition in -1..(peers.len() / 3 + 1) as i16 {
            for kind in [0, 1, 2, 3, 5] {
                if (repetition == -1) != (kind <= 1) {
                    continue;
                }
                for leader in -1..peers.len() as i16 {
                    if (kind <= 1) != (leader == -1)
                        || (kind == 2 && leader != local as i16 && leader != peer as i16)
                    {
                        continue;
                    }
                    session.offer(
                        *identity,
                        RoundContext {
                            kind,
                            peer1,
                            peer2,
                            repetition,
                            leader,
                            // A's real ECHO split below makes its confirmation
                            // bottom. Its incoming context agrees with its marker.
                            contested: u16::from(
                                kind == 5
                                    && repetition == 0
                                    && leader == LEADER as i16
                                    && peer == 0,
                            ),
                        },
                        10_000,
                    )?;
                }
            }
        }
    }
    Ok(())
}

fn population(context: RoundContext, receiver: usize, peer: usize) -> Vec<Vec<u8>> {
    if context.kind == 1 {
        let mut size = alloc::vec![0; 12];
        size[2] = 2;
        size[11] = peer as u8;
        return alloc::vec![size];
    }
    if context.repetition != 0 || context.leader != LEADER as i16 {
        return Vec::new();
    }
    let present = match context.kind {
        2 => receiver != 0,
        3 | 5 => match peer {
            0 => false,
            1 | 2 => true,
            // D equivocates only in its own authenticated SET operations.
            // To A it supplies empty; to B/C it supplies {x}.
            _ => receiver != 0,
        },
        _ => false,
    };
    if context.kind == 5 && peer == 0 {
        alloc::vec![BOTTOM.to_vec()]
    } else if present {
        alloc::vec![VALUE.to_vec()]
    } else {
        Vec::new()
    }
}

struct Observation {
    grade: u8,
    lead_failures: usize,
    confirm_done: usize,
}

fn receiver(local: usize) -> Result<Observation, Error> {
    let domain = Instance::new();
    let peers = [[1; 32], [2; 32], [3; 32], [4; 32]];
    let mut session = Session::new(
        &domain,
        peers[local],
        join(&peers),
        Limits::default(),
        Abi::native(),
        10_000,
    )?;
    offers(&mut session, local, &peers)?;
    session.conclude(10_000)?;
    let mut lead_failures = 0;
    let mut confirm_done = 0;
    let mut saw_echo_population = false;
    let mut saw_confirm_population = false;
    for _ in 0..32_768 {
        // Observe the produced grade before another genuine local transition
        // can apply and retire the repetition. No private state is injected.
        session.step(NOW, 1)?;
        if let Some(leader) = session.leaders.get(LEADER)
            && leader.stage == LeaderStage::Done
        {
            check(saw_echo_population && saw_confirm_population)?;
            check(session.task_failures().1 == lead_failures as u64)?;
            check(session.outcome().failure.is_none() && !session.outcome().client_done_written)?;
            check(confirm_done == 3)?;
            // Both receivers exclude A's actual bottom. A still counts D's
            // noncontested empty set, while B gets D's {x}: their genuine
            // confirmation support is exactly 2 and 3, respectively.
            check(leader.confirm_ballot.count() == 4)?;
            check(leader.confirm_ballot.noncontested() == 3)?;
            check(leader.confirm_worst == if local == 0 { 2 } else { 3 })?;
            return Ok(Observation {
                grade: leader.confidence,
                lead_failures,
                confirm_done,
            });
        }
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
            let original = original_population(&session, set)?;
            if context.repetition == 0 && context.leader == LEADER as i16 {
                if context.kind == 3 {
                    check(
                        original
                            == if local == 0 {
                                Vec::new()
                            } else {
                                alloc::vec![VALUE.to_vec()]
                            },
                    )?;
                    saw_echo_population = true;
                }
                if context.kind == 5 {
                    check(
                        original
                            == if local == 0 {
                                alloc::vec![BOTTOM.to_vec()]
                            } else {
                                alloc::vec![VALUE.to_vec()]
                            },
                    )?;
                    check(context.contested == u16::from(local == 0))?;
                    saw_confirm_population = true;
                }
            }
            let remote = peers
                .iter()
                .position(|identity| *identity == peer)
                .ok_or(Error::NotFound)?;
            receipt(&mut session)?;
            if local == 0
                && context.kind == 2
                && context.repetition == 0
                && context.leader == LEADER as i16
            {
                check(remote == LEADER && original.is_empty())?;
                session.set_result(
                    task,
                    peer,
                    SetEvent::Failure(Error::Unavailable),
                    NOW,
                    &mut OpaqueApplication,
                )?;
                lead_failures += 1;
            } else {
                let remote_population = population(context, local, remote);
                source_union_done(&mut session, task, peer, &original, &remote_population)?;
                if context.kind == 5 && context.repetition == 0 && context.leader == LEADER as i16 {
                    confirm_done += 1;
                }
            }
            continue;
        }
        if let Some(effect) = session.effect() {
            check(!matches!(
                effect.action,
                Action::ClientElement { .. } | Action::ClientDone | Action::CloseClient { .. }
            ))?;
        }
        receipt(&mut session)?;
    }
    Err(Error::Deadline)
}

#[test]
fn matching_confirmations_grade_missing_lead_one_and_other_receiver_two() -> Result<(), Error> {
    // D fails LEAD to A but tells B/C {x}. Honest A echoes empty, B/C {x}.
    // D's ECHO produces A's 2:2 split (bottom), but a 3:1 {x} majority at B/C.
    // In CONFIRM, A sees B/C {x} and D empty: two real matching votes (>t).
    // B sees B/C/D {x}, excluding A's bottom: three matching votes (n-t).
    let a = receiver(0)?;
    let b = receiver(1)?;
    check(a.lead_failures == 1 && b.lead_failures == 0)?;
    check(a.confirm_done == 3 && b.confirm_done == 3)?;
    check(a.grade == 1 && b.grade == 2 && a.grade.abs_diff(b.grade) <= 1)
}
