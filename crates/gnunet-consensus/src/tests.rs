//! Small source-only owner/algorithm cases. Native writes/retirements below are
//! explicitly scripted receipts, not actual daemon, SET peer or BFT evidence.
use super::*;
struct OpaqueApplication;
impl Validator for OpaqueApplication {
    fn check(&mut self, _: u16, _: &[u8], _: u64) -> Result<PayloadValidation, Error> {
        Ok(PayloadValidation::Opaque)
    }
}
fn check(value: bool) -> Result<(), Error> {
    if value { Ok(()) } else { Err(Error::Conflict) }
}
fn join<'a>(peers: &'a [[u8; 32]]) -> Join<'a> {
    Join {
        session: [7; 64],
        start: 20_000,
        deadline: 1_000_000,
        peers,
    }
}
fn receipt(session: &mut Session<'_>) -> Result<Option<bool>, Error> {
    let Some(effect) = session.effect() else {
        return Ok(None);
    };
    let id = effect.id;
    let done = matches!(effect.action, Action::ClientDone);
    let completion = if effect.action.cleanup() {
        Completion::Retired
    } else {
        Completion::Written
    };
    if let Action::PrepareSet { set } = effect.action {
        for i in 0..session.set_len(set)? {
            let e = session.set_element(set, i)?.ok_or(Error::NotReady)?;
            check(e.element_type == 25)?;
            Block::decode(e.data)?;
        }
    }
    session.admit_effect(id)?;
    let _original = session.complete_effect(id, completion)?;
    Ok(Some(done))
}
#[test]
fn global_namespace_uses_canonical_peer_set_and_optional_local_identity() -> Result<(), Error> {
    let domain = Instance::new();
    let reversed = [[2; 32], [1; 32]];
    let canonical = [[1; 32], [2; 32]];
    let a = Session::new(
        &domain,
        [1; 32],
        join(&reversed),
        Limits::default(),
        Abi::native(),
        10_000,
    )?;
    let b = Session::new(
        &domain,
        [2; 32],
        join(&canonical),
        Limits::default(),
        Abi::native(),
        10_000,
    )?;
    let without_local = [[2; 32]];
    let c = Session::new(
        &domain,
        [1; 32],
        join(&without_local),
        Limits::default(),
        Abi::native(),
        10_000,
    )?;
    check(a.global_id() == b.global_id() && b.global_id() == c.global_id())?;
    check(a.peers() == canonical)?;
    let duplicates = [[1; 32], [1; 32]];
    check(matches!(
        Session::new(
            &domain,
            [1; 32],
            join(&duplicates),
            Limits::default(),
            Abi::native(),
            10_000
        ),
        Err(Error::Conflict)
    ))
}
#[test]
fn one_participant_runs_real_phase_plan_and_filters_own_opaque_values() -> Result<(), Error> {
    let domain = Instance::new();
    let peers = [[1; 32]];
    let mut s = Session::new(
        &domain,
        [1; 32],
        join(&peers),
        Limits::default(),
        Abi::native(),
        10_000,
    )?;
    s.insert(24, &[9], 10_000, &mut OpaqueApplication)?;
    s.conclude(10_000)?;
    let mut done = false;
    for _ in 0..4096 {
        s.step(20_000, 64)?;
        if let Some(effect) = s.effect() {
            check(!matches!(
                effect.action,
                Action::Reconcile { .. }
                    | Action::ClientElement { .. }
                    | Action::CloseClient { .. }
            ))?;
            if matches!(effect.action, Action::ClientDone) {
                check(!s.outcome().client_done_written)?;
            }
        }
        if receipt(&mut s)? == Some(true) {
            done = true;
            s.cancel(Error::Closed)?;
            check(s.outcome().failure.is_none())?;
        }
        if s.is_quiescent() {
            return check(
                done && s.outcome().client_done_written
                    && s.outcome().failure.is_none()
                    && s.failure_context().is_none(),
            );
        }
    }
    Err(Error::Deadline)
}
#[test]
fn local_commit_writes_and_deadlines_never_substitute_for_remote_set_done() -> Result<(), Error> {
    let domain = Instance::new();
    let peers = [[1; 32], [2; 32]];
    let mut s = Session::new(
        &domain,
        [1; 32],
        join(&peers),
        Limits::default(),
        Abi::native(),
        10_000,
    )?;
    s.insert(0, &[3], 10_000, &mut OpaqueApplication)?;
    s.conclude(10_000)?;
    let mut now = 20_000;
    for _ in 0..16384 {
        let changed = match s.step(now, 64) {
            Ok(changed) => changed,
            Err(Error::Unavailable | Error::Deadline) => false,
            Err(e) => return Err(e),
        };
        if s.effect()
            .is_some_and(|e| matches!(e.action, Action::ClientDone))
        {
            return Err(Error::Conflict);
        }
        if receipt(&mut s)?.is_some() {
            continue;
        }
        if s.is_quiescent() {
            return check(
                !s.outcome().client_done_written
                    && s.outcome().failure.is_some()
                    && s.task_failures().1 != 0,
            );
        }
        if !changed {
            if let Some(end) = s.next_deadline() {
                now = now.saturating_add(1).max(end);
            } else {
                s.retire_step()?;
            }
        }
    }
    Err(Error::Deadline)
}
#[test]
fn cancellation_preserves_admitted_original_and_independent_retirement_failure() -> Result<(), Error>
{
    let domain = Instance::new();
    let peers = [[1; 32]];
    let mut s = Session::new(
        &domain,
        [1; 32],
        join(&peers),
        Limits::default(),
        Abi::native(),
        10_000,
    )?;
    let original = s.effect().ok_or(Error::NotReady)?.id;
    s.admit_effect(original)?;
    s.cancel(Error::Cancelled)?;
    check(
        s.effect()
            .is_some_and(|e| e.id == original && e.is_admitted()),
    )?;
    check(!s.is_quiescent())?;
    let terminal = s.complete_effect(original, Completion::Lost(Error::Io))?;
    check(terminal.effect.id == original && terminal.completion == Completion::Lost(Error::Io))?;
    for _ in 0..32 {
        s.retire_step()?;
        receipt(&mut s)?;
        if s.is_quiescent() {
            return check(
                s.outcome()
                    .failure
                    .is_some_and(|f| f.cause == Error::Cancelled)
                    && s.outcome().cleanup_failure == Some(Error::Io)
                    && !s.outcome().client_done_written,
            );
        }
    }
    Err(Error::Deadline)
}

#[test]
fn accepted_offer_releases_its_slot_and_bad_result_dispatches_original_cancel() -> Result<(), Error>
{
    let domain = Instance::new();
    let peers = [[1; 32], [2; 32]];
    let limits = Limits {
        offers: 1,
        ..Limits::default()
    };
    let mut s = Session::new(
        &domain,
        [2; 32],
        join(&peers),
        limits,
        Abi::native(),
        10_000,
    )?;
    let context = RoundContext {
        kind: 0,
        peer1: 0,
        peer2: 1,
        repetition: -1,
        leader: -1,
        contested: 0,
    };
    let original_offer = s.offer([1; 32], context, 10_000)?;
    s.conclude(10_000)?;
    for _ in 0..128 {
        s.step(20_000, 64)?;
        let task = s.effect().and_then(|e| match e.action {
            Action::Reconcile {
                task,
                incoming: Some(offer),
                ..
            } if offer == original_offer => Some(task),
            _ => None,
        });
        if let Some(task) = task {
            receipt(&mut s)?;
            check(!s.offer_live(original_offer) && s.offers.is_empty())?;
            let next = s.offer([1; 32], RoundContext { kind: 1, ..context }, 20_000)?;
            check(next != original_offer)?;
            check(
                s.set_result(
                    task,
                    [1; 32],
                    SetEvent::AddLocal {
                        element_type: 0,
                        data: &[],
                    },
                    20_000,
                    &mut OpaqueApplication,
                ) == Err(Error::Malformed),
            )?;
            s.step(20_000, 64)?;
            return check(s.effect().is_some_and(
                |e| matches!(e.action, Action::CancelTask { task: actual } if actual == task),
            ));
        }
        receipt(&mut s)?;
    }
    Err(Error::Deadline)
}

#[derive(Clone, Copy)]
enum GradingCase {
    TiedRound,
    ContestedConfirm,
    PrematureEarly,
}
fn contested_confirmation(
    case: GradingCase,
    key: RoundContext,
    receiver: usize,
    peer: usize,
) -> bool {
    if matches!(case, GradingCase::PrematureEarly) {
        return match (key.kind, key.repetition, key.leader) {
            (5, 0, 6) => match peer {
                0 | 1 => false,
                6 => receiver >= 3,
                _ => true,
            },
            (5, 1, 6) => true,
            (5, 1, 7) => match peer {
                0 | 1 => false,
                7 => receiver < 3,
                _ => true,
            },
            (5, 2, 6 | 7) => true,
            _ => false,
        };
    }
    matches!(case, GradingCase::ContestedConfirm)
        && key.kind == 5
        && key.repetition == 0
        && key.leader == 3
        && matches!(peer, 1 | 2)
}
fn grading_population(
    case: GradingCase,
    key: RoundContext,
    receiver: usize,
    peer: usize,
) -> Vec<Vec<u8>> {
    let present = match (key.kind, key.repetition, case) {
        (0, _, GradingCase::PrematureEarly) => false,
        (1, _, GradingCase::PrematureEarly) => peer == 6 && receiver < 3,
        (2, 0, GradingCase::PrematureEarly) if key.leader == 6 && peer == 6 => receiver < 4,
        (2, 1, GradingCase::PrematureEarly) if key.leader == 7 && peer == 7 => receiver == 5,
        (2, _, GradingCase::PrematureEarly) => peer < 3,
        (3, 0, GradingCase::PrematureEarly) if key.leader == 6 => {
            peer < 4 || (peer >= 6 && receiver < 2)
        }
        (5, 0, GradingCase::PrematureEarly) if key.leader == 6 => !(4..6).contains(&peer),
        (3 | 5, 0, GradingCase::PrematureEarly) if key.leader == 7 => false,
        (3, 1, GradingCase::PrematureEarly) if key.leader == 7 => {
            peer == 5 || (peer == 7 && receiver >= 2)
        }
        (5, 1, GradingCase::PrematureEarly) if key.leader >= 6 => false,
        (3, _, GradingCase::PrematureEarly) if key.leader >= 6 => peer < 3,
        (5, 2, GradingCase::PrematureEarly) if key.leader >= 6 => peer < 3,
        (3 | 5, _, GradingCase::PrematureEarly) => key.leader < 3,
        (0, _, _) => false,
        (1, _, GradingCase::TiedRound) => peer == 3 && receiver < 2,
        (1, _, GradingCase::ContestedConfirm) => peer == 3 && receiver == 0,
        (2, 0, GradingCase::TiedRound) => peer < 2,
        (3 | 5, 0, GradingCase::TiedRound) => key.leader < 2,
        (2, _, GradingCase::TiedRound) => peer < 3,
        (3 | 5, _, GradingCase::TiedRound) => key.leader < 3,
        (2, 0, GradingCase::ContestedConfirm) if peer == 3 && key.leader == 3 => receiver < 2,
        (2, 0, GradingCase::ContestedConfirm) => peer == 0,
        (3, 0, GradingCase::ContestedConfirm) if key.leader == 3 => {
            peer < 2 || (peer == 3 && receiver == 0)
        }
        (5, 0, GradingCase::ContestedConfirm) if key.leader == 3 => peer < 2,
        (3 | 5, 0, GradingCase::ContestedConfirm) => key.leader == 0,
        (_, _, GradingCase::ContestedConfirm) => false,
        _ => false,
    };
    let mut population = Vec::new();
    if present {
        population.push(alloc::vec![0, 24, 0, 9]);
    }
    if key.kind == 1 {
        let mut size = alloc::vec![0; 12];
        size[2] = 2;
        size[11] = peer as u8;
        population.push(size);
    }
    if contested_confirmation(case, key, receiver, peer) {
        population.push(alloc::vec![0, 0, 1]);
    }
    population
}
fn grading_offers(
    session: &mut Session<'_>,
    case: GradingCase,
    local: usize,
    peers: &[[u8; 32]],
) -> Result<(), Error> {
    for (peer, identity) in peers.iter().enumerate() {
        if peer == local {
            continue;
        }
        let (lo, hi) = (local.min(peer), local.max(peer));
        let (peer1, peer2) = if hi - lo <= peers.len() / 2 {
            (lo, hi)
        } else {
            (hi, lo)
        };
        if peer2 != local {
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
                    let mut key = RoundContext {
                        kind,
                        peer1: peer1 as i16,
                        peer2: peer2 as i16,
                        repetition,
                        leader,
                        contested: 0,
                    };
                    key.contested = u16::from(contested_confirmation(case, key, local, peer));
                    session.offer(*identity, key, 10_000)?;
                }
            }
        }
    }
    Ok(())
}
// These are explicit source-case SET transcripts. They exercise the public
// Session effects, complete original frozen-population differences and matching
// DONEs. They are not a native producer or a Byzantine/runtime qualification.
fn grading_source_case(case: GradingCase, local: usize) -> Result<(), Error> {
    let domain = Instance::new();
    let count = if matches!(case, GradingCase::PrematureEarly) {
        8
    } else {
        4
    };
    let peers: Vec<_> = (1..=count).map(|n| [n as u8; 32]).collect();
    let mut session = Session::new(
        &domain,
        peers[local],
        join(&peers),
        Limits::default(),
        Abi::native(),
        10_000,
    )?;
    grading_offers(&mut session, case, local, &peers)?;
    session.conclude(10_000)?;
    let expected_present = !matches!(case, GradingCase::ContestedConfirm);
    let wrapper = [0, 24, 0, 9];
    let mut next_round_observed = false;
    let mut third_round_observed = false;
    let mut elements = 0;
    let mut done = false;
    for _ in 0..16_384 {
        session.step(20_000, 64)?;
        let reconcile = session.effect().and_then(|effect| match &effect.action {
            Action::Reconcile {
                task,
                set,
                peer,
                context,
                ..
            } => Some((*task, *set, *peer, *context)),
            _ => None,
        });
        if let Some((task, set, peer, key)) = reconcile {
            let mut original = Vec::new();
            for i in 0..session.set_len(set)? {
                let element = session.set_element(set, i)?.ok_or(Error::NotReady)?;
                check(element.element_type == 25)?;
                original.push(element.data.to_vec());
            }
            if key.kind == 2 && key.repetition == 1 {
                let next_present = if matches!(case, GradingCase::PrematureEarly) {
                    local < 3
                } else {
                    expected_present
                };
                check(original.iter().any(|raw| raw.as_slice() == wrapper) == next_present)?;
                next_round_observed = true;
            }
            if key.kind == 2 && key.repetition == 2 {
                check(matches!(case, GradingCase::PrematureEarly))?;
                check(original.iter().any(|raw| raw.as_slice() == wrapper) == (local < 3))?;
                third_round_observed = true;
            }
            let remote_peer = peers
                .iter()
                .position(|p| *p == peer)
                .ok_or(Error::NotFound)?;
            let remote = grading_population(case, key, local, remote_peer);
            receipt(&mut session)?;
            for raw in remote.iter().filter(|raw| !original.contains(raw)) {
                session.set_result(
                    task,
                    peer,
                    SetEvent::AddLocal {
                        element_type: 25,
                        data: raw,
                    },
                    20_000,
                    &mut OpaqueApplication,
                )?;
            }
            for raw in original.iter().filter(|raw| !remote.contains(raw)) {
                session.set_result(
                    task,
                    peer,
                    SetEvent::AddRemote {
                        element_type: 25,
                        data: raw,
                    },
                    20_000,
                    &mut OpaqueApplication,
                )?;
            }
            let size = original.len() + remote.iter().filter(|raw| !original.contains(raw)).count();
            session.set_result(
                task,
                peer,
                SetEvent::Done {
                    current_size: size as u64,
                },
                20_000,
                &mut OpaqueApplication,
            )?;
            continue;
        }
        if let Some(effect) = session.effect() {
            match &effect.action {
                Action::ClientElement { element_type, data } => {
                    check(*element_type == 24 && data.as_slice() == [9])?;
                    elements += 1;
                }
                Action::ClientDone => {
                    check(!session.outcome().client_done_written)?;
                    check(!matches!(case, GradingCase::PrematureEarly) || third_round_observed)?;
                }
                Action::CloseClient { .. } => return Err(Error::Conflict),
                _ => {}
            }
        }
        done |= receipt(&mut session)? == Some(true);
        if session.is_quiescent() {
            return check(
                next_round_observed
                    && (!matches!(case, GradingCase::PrematureEarly) || third_round_observed)
                    && done
                    && session.outcome().client_done_written
                    && session.outcome().failure.is_none()
                    && elements == usize::from(expected_present),
            );
        }
    }
    Err(Error::Deadline)
}
#[test]
fn absolute_round_tie_includes_remote_value_from_present_and_absent_bases() -> Result<(), Error> {
    // One faulty peer adds x only to peers0/1 in the last initial UNION, then
    // coherently gradecasts the empty set. Four common grade2 proposals are
    // {x},{x},empty,empty; both original bases must adopt x in the next round.
    grading_source_case(GradingCase::TiedRound, 0)?;
    grading_source_case(GradingCase::TiedRound, 2)
}
#[test]
fn contested_payloads_cannot_supply_confirmation_or_round_support() -> Result<(), Error> {
    // For leader3: LEAD gives A,A,B to honest peers. Its ECHO equivocation
    // gives honest confirmations A,contested-A,contested-B; leader3 confirms
    // B without a marker. Only one A and one B are eligible: neither meets
    // t+1=2. Excluding that leader leaves honest proposals A,B,B, hence empty.
    grading_source_case(GradingCase::ContestedConfirm, 0)
}

#[test]
fn two_faults_cannot_make_weak_early_support_abort_or_finish_before_third_round()
-> Result<(), Error> {
    // Eight participants permit two faults. Peers6/7 expose themselves in
    // successive repetitions with genuine marker-limited grade1/0 results.
    // Four winning votes are below n-f=6: the old early4 rule incorrectly
    // aborted peer0 in repetition2 and let peer3 emit525 before repetition3.
    grading_source_case(GradingCase::PrematureEarly, 0)?;
    grading_source_case(GradingCase::PrematureEarly, 3)
}

// Public source-only SET transcripts for a peer that serves leader0's whole
// chain before answering its pending leader1 proposal, as normal C can do.
// Written/Retired below are explicit fixture receipts, never native IO or
// manufactured grade/peer-acceptance evidence.
struct HeldLeaderUnion<'id> {
    task: TaskId<'id>,
    set: SetId<'id>,
    peer: [u8; 32],
    original: Vec<Vec<u8>>,
    deadline: u64,
}
// Independent fixed targets of this two-peer original JOIN: six shared
// round slices, never measured from a later leader's activation time.
fn original_two_peer_target(kind: u16) -> Result<u64, Error> {
    let numerator = match kind {
        0 => 1,
        1 => 2,
        2 => 3,
        3 => 4,
        5 => 5,
        _ => return Err(Error::Conflict),
    };
    Ok(20_000 + 980_000 * numerator / 6)
}
fn original_population<'id>(
    session: &Session<'id>,
    set: SetId<'id>,
) -> Result<Vec<Vec<u8>>, Error> {
    let mut population = Vec::new();
    for index in 0..session.set_len(set)? {
        let element = session.set_element(set, index)?.ok_or(Error::NotReady)?;
        check(element.element_type == 25)?;
        Block::decode(element.data)?;
        population.push(element.data.to_vec());
    }
    Ok(population)
}
fn source_union_done<'id>(
    session: &mut Session<'id>,
    task: TaskId<'id>,
    peer: [u8; 32],
    original: &[Vec<u8>],
    remote: &[Vec<u8>],
) -> Result<(), Error> {
    for raw in remote.iter().filter(|raw| !original.contains(raw)) {
        session.set_result(
            task,
            peer,
            SetEvent::AddLocal {
                element_type: 25,
                data: raw,
            },
            20_000,
            &mut OpaqueApplication,
        )?;
    }
    for raw in original.iter().filter(|raw| !remote.contains(raw)) {
        session.set_result(
            task,
            peer,
            SetEvent::AddRemote {
                element_type: 25,
                data: raw,
            },
            20_000,
            &mut OpaqueApplication,
        )?;
    }
    let union = original.len() + remote.iter().filter(|raw| !original.contains(raw)).count();
    session.set_result(
        task,
        peer,
        SetEvent::Done {
            current_size: union as u64,
        },
        20_000,
        &mut OpaqueApplication,
    )
}
fn application_block(value: u8) -> Result<Vec<u8>, Error> {
    let mut raw = alloc::vec![0; 4];
    Block {
        payload_type: 24,
        marker: 0,
        data: &[value],
    }
    .encode(&mut raw)?;
    Ok(raw)
}
fn coherent_remote_population(kind: u16, sender: u8) -> Result<Vec<Vec<u8>>, Error> {
    if kind == 0 {
        return Ok(alloc::vec![application_block(7)?]);
    }
    let mut population = alloc::vec![application_block(9)?, application_block(7)?];
    if kind == 1 {
        let mut data = [0; 9];
        data[..8].copy_from_slice(&2u64.to_be_bytes());
        data[8] = sender;
        let mut marker = alloc::vec![0; 12];
        Block {
            payload_type: 0,
            marker: 2,
            data: &data,
        }
        .encode(&mut marker)?;
        population.push(marker);
    }
    Ok(population)
}
#[test]
fn lagging_leader_proposal_does_not_block_other_echo_confirm_or_renew_its_source()
-> Result<(), Error> {
    let domain = Instance::new();
    let peers = [[1; 32], [2; 32]];
    let mut session = Session::new(
        &domain,
        peers[0],
        join(&peers),
        Limits {
            tasks: 4,
            sets: 2,
            ..Limits::default()
        },
        Abi::native(),
        10_000,
    )?;
    session.insert(24, &[9], 10_000, &mut OpaqueApplication)?;
    session.conclude(10_000)?;
    let mut source_deadlines = Vec::new();
    let mut proposal0: Option<HeldLeaderUnion<'_>> = None;
    let mut proposal1: Option<HeldLeaderUnion<'_>> = None;
    let mut completed0 = false;
    let mut released1 = false;
    let mut parallel = false;
    let mut proposal0_retired = false;
    let mut echo0 = None;
    let mut echo0_retired = false;
    let mut confirm0 = None;
    let mut confirm0_retired = false;
    let mut elements = 0;
    let mut done = false;
    for _ in 0..16_384 {
        session.step(20_000, 64)?;
        if let Some(held) = proposal1.as_ref().filter(|_| !released1) {
            check(session.task_live(held.task) && session.set_live(held.set))?;
            check(
                session
                    .next_deadline()
                    .is_some_and(|next| next <= held.deadline),
            )?;
        }
        let reconcile = session.effect().and_then(|effect| match &effect.action {
            Action::Reconcile {
                task,
                set,
                peer,
                context,
                ..
            } => Some((*task, *set, *peer, *context, effect.deadline())),
            _ => None,
        });
        if let Some((task, set, peer, key, deadline)) = reconcile {
            check(peer == peers[1] && key.peer1 == 0 && key.peer2 == 1)?;
            let original = original_population(&session, set)?;
            let effect = session.effect().ok_or(Error::NotReady)?.id;
            let deadline = deadline.ok_or(Error::NotReady)?;
            check(deadline == original_two_peer_target(key.kind)?)?;
            check(
                source_deadlines
                    .iter()
                    .any(|(id, bound)| *id == set && *bound == deadline),
            )?;
            session.admit_effect(effect)?;
            let terminal = session.complete_effect(effect, Completion::Written)?;
            check(terminal.effect.id == effect && terminal.effect.deadline() == Some(deadline))?;
            if key.kind == 2 {
                check(key.repetition == 0 && matches!(key.leader, 0 | 1))?;
                let destination = if key.leader == 0 {
                    &mut proposal0
                } else {
                    &mut proposal1
                };
                check(destination.is_none())?;
                *destination = Some(HeldLeaderUnion {
                    task,
                    set,
                    peer,
                    original,
                    deadline,
                });
                if let (Some(first), Some(lagging)) = (&proposal0, &proposal1) {
                    check(!completed0 && first.set != lagging.set)?;
                    check(session.task_live(first.task) && session.task_live(lagging.task))?;
                    parallel = true;
                    source_union_done(
                        &mut session,
                        first.task,
                        first.peer,
                        &first.original,
                        &coherent_remote_population(2, 1)?,
                    )?;
                    completed0 = true;
                }
                continue;
            }
            if key.kind == 3 && key.leader == 0 {
                check(completed0 && proposal0_retired && !released1 && echo0.is_none())?;
                echo0 = Some(set);
            } else if key.kind == 5 && key.leader == 0 {
                check(echo0_retired && !released1 && confirm0.is_none())?;
                confirm0 = Some(set);
            } else if key.kind >= 2 {
                check(released1 && key.leader == 1)?;
            }
            source_union_done(
                &mut session,
                task,
                peer,
                &original,
                &coherent_remote_population(key.kind, 1)?,
            )?;
            continue;
        }
        let closing = session.effect().and_then(|effect| match effect.action {
            Action::CloseSet { set } => Some(set),
            _ => None,
        });
        if let Some(set) = closing {
            if let Some(held) = proposal1.as_ref().filter(|_| !released1) {
                check(set != held.set && session.task_live(held.task))?;
            }
            check(receipt(&mut session)?.is_some() && !session.set_live(set))?;
            if proposal0.as_ref().is_some_and(|held| held.set == set) {
                proposal0_retired = true;
            }
            if echo0 == Some(set) {
                echo0_retired = true;
            }
            if confirm0 == Some(set) {
                check(!released1 && parallel && proposal0_retired && echo0_retired)?;
                confirm0_retired = true;
                let held = proposal1.as_ref().ok_or(Error::NotReady)?;
                check(session.task_live(held.task) && session.set_live(held.set))?;
                source_union_done(
                    &mut session,
                    held.task,
                    held.peer,
                    &held.original,
                    &coherent_remote_population(2, 1)?,
                )?;
                released1 = true;
            }
            continue;
        }
        if let Some(effect) = session.effect() {
            match &effect.action {
                Action::PrepareSet { set } => {
                    check(!source_deadlines.iter().any(|(id, _)| id == set))?;
                    source_deadlines.push((*set, effect.deadline().ok_or(Error::NotReady)?));
                }
                Action::ClientElement { element_type, data } => {
                    check(*element_type == 24 && data.as_slice() == [7])?;
                    elements += 1;
                }
                Action::ClientDone => {
                    check(parallel && released1 && confirm0_retired && !done)?;
                    check(!session.outcome().client_done_written)?;
                }
                Action::CancelTask { .. } | Action::CloseClient { .. } => {
                    return Err(Error::Conflict);
                }
                _ => {}
            }
        }
        done |= receipt(&mut session)? == Some(true);
        if session.is_quiescent() {
            return check(
                parallel
                    && proposal0_retired
                    && echo0_retired
                    && confirm0_retired
                    && released1
                    && done
                    && elements == 1
                    && session.outcome().failure.is_none()
                    && session.outcome().client_done_written
                    && session.task_failures().1 == 0,
            );
        }
    }
    Err(Error::Deadline)
}

#[test]
fn later_leader_proposal_offer_is_live_while_earlier_echo_is_active() -> Result<(), Error> {
    let domain = Instance::new();
    let peers = [[1; 32], [2; 32]];
    let mut session = Session::new(
        &domain,
        peers[1],
        join(&peers),
        Limits {
            tasks: 4,
            sets: 2,
            ..Limits::default()
        },
        Abi::native(),
        10_000,
    )?;
    session.insert(24, &[9], 10_000, &mut OpaqueApplication)?;
    // Actual public pending offers, including future phases. Only leader1's
    // proposal arrives later; none authorizes a result or supplies a grade.
    for (kind, repetition, leader) in [
        (0, -1, -1),
        (1, -1, -1),
        (2, 0, 0),
        (3, 0, 0),
        (5, 0, 0),
        (3, 0, 1),
        (5, 0, 1),
    ] {
        session.offer(
            peers[0],
            RoundContext {
                kind,
                peer1: 0,
                peer2: 1,
                repetition,
                leader,
                contested: 0,
            },
            10_000,
        )?;
    }
    session.conclude(10_000)?;
    let mut source_deadlines = Vec::new();
    let mut late_offer = None;
    let mut late_claimed = false;
    let mut elements = 0;
    let mut done = false;
    for _ in 0..16_384 {
        session.step(20_000, 64)?;
        let reconcile = session.effect().and_then(|effect| match &effect.action {
            Action::Reconcile {
                task,
                set,
                peer,
                context,
                incoming,
                ..
            } => Some((*task, *set, *peer, *context, *incoming, effect.deadline())),
            _ => None,
        });
        if let Some((task, set, peer, key, incoming, deadline)) = reconcile {
            check(peer == peers[0] && key.peer1 == 0 && key.peer2 == 1)?;
            let original = original_population(&session, set)?;
            let deadline = deadline.ok_or(Error::NotReady)?;
            check(deadline == original_two_peer_target(key.kind)?)?;
            check(
                source_deadlines
                    .iter()
                    .any(|(id, bound)| *id == set && *bound == deadline),
            )?;
            let id = session.effect().ok_or(Error::NotReady)?.id;
            session.admit_effect(id)?;
            let terminal = session.complete_effect(id, Completion::Written)?;
            check(terminal.effect.id == id && terminal.effect.deadline() == Some(deadline))?;
            if key.kind == 3 && key.leader == 0 {
                check(late_offer.is_none() && session.task_live(task))?;
                let context = RoundContext {
                    kind: 2,
                    leader: 1,
                    ..key
                };
                let accepted = session.offer(peers[0], context, 20_000)?;
                check(session.offer_live(accepted) && session.task_live(task))?;
                // The same original pending context cannot be admitted twice.
                check(session.offer(peers[0], context, 20_000) == Err(Error::Replay))?;
                late_offer = Some(accepted);
            }
            if key.kind == 2 && key.leader == 1 {
                let accepted = late_offer.ok_or(Error::NotReady)?;
                check(incoming == Some(accepted) && !late_claimed)?;
                check(!session.offer_live(accepted))?;
                late_claimed = true;
            }
            source_union_done(
                &mut session,
                task,
                peer,
                &original,
                &coherent_remote_population(key.kind, 0)?,
            )?;
            continue;
        }
        if let Some(effect) = session.effect() {
            match &effect.action {
                Action::PrepareSet { set } => {
                    check(!source_deadlines.iter().any(|(id, _)| id == set))?;
                    source_deadlines.push((*set, effect.deadline().ok_or(Error::NotReady)?));
                }
                Action::ClientElement { element_type, data } => {
                    check(*element_type == 24 && data.as_slice() == [7])?;
                    elements += 1;
                }
                Action::ClientDone => {
                    check(late_claimed && !done && !session.outcome().client_done_written)?;
                }
                Action::CancelTask { .. } | Action::CloseClient { .. } => {
                    return Err(Error::Conflict);
                }
                _ => {}
            }
        }
        done |= receipt(&mut session)? == Some(true);
        if session.is_quiescent() {
            return check(
                late_offer.is_some()
                    && late_claimed
                    && done
                    && elements == 1
                    && session.outcome().client_done_written
                    && session.outcome().failure.is_none()
                    && session.task_failures().1 == 0,
            );
        }
    }
    Err(Error::Deadline)
}

#[path = "session/gradecast_tests.rs"]
mod gradecast_tests;

#[path = "session/failure_tests.rs"]
mod failure_tests;
