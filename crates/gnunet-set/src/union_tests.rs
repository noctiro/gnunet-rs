//! Bounded pure transcript cases. These do not execute a native peer or prove C interoperability.
use super::*;
use crate::{
    Compression, Content, ContentLimits, Random,
    wire::{Abi, Element, Options, Order},
};
struct Scripted;
impl Random for Scripted {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        out.fill(3);
        Ok(())
    }
}
impl Compression for Scripted {
    fn compress(&mut self, _: &[u8], _: usize) -> Result<Vec<u8>, Error> {
        Err(Error::Unsupported)
    }
    fn decompress_exact(&mut self, _: &[u8], _: usize, _: usize) -> Result<Vec<u8>, Error> {
        Err(Error::Unsupported)
    }
}
fn check(v: bool) -> Result<(), Error> {
    if v { Ok(()) } else { Err(Error::Conflict) }
}
fn snapshot(values: &[u8], abi: Abi) -> Result<Snapshot, Error> {
    let mut c = Content::new(ContentLimits::default(), abi)?;
    for n in values {
        c.add(Element {
            element_type: 1,
            data: core::slice::from_ref(n),
        })?;
    }
    c.snapshot()
}

#[test]
fn remote_body_charge_follows_original_output_after_engine_drop() -> Result<(), Error> {
    use crate::content::{Body, BodyLedger};
    let mut union = Union::new(
        snapshot(&[], Abi::native())?,
        Role::Acceptor,
        ResultMode::Added,
        Options::default(),
        Limits::default(),
    )?;
    let ledger = BodyLedger::share(&union.snapshot.ledger)?;
    let empty = ledger.charged_bytes()?;
    union.growth = Growth::new(1024 * 1024);
    union.add_remote(
        Element {
            element_type: 7,
            data: &[1, 2, 3],
        },
        true,
    )?;
    let charged = ledger.charged_bytes()?;
    check(charged == empty + Body::allocation_overhead() + 3)?;
    union.add_remote(
        Element {
            element_type: 7,
            data: &[1, 2, 3],
        },
        true,
    )?;
    check(ledger.charged_bytes()? == charged)?;
    let original_result = union.out.results.pop_front().ok_or(Error::NotReady)?;
    check(original_result.status == Status::Ok)?;
    drop(union);
    check(ledger.charged_bytes()? == charged)?;
    drop(original_result);
    check(ledger.charged_bytes()? == empty)
}

#[test]
fn remote_body_failed_result_admission_refunds_only_its_actual_allocation() -> Result<(), Error> {
    use crate::content::{Body, BodyLedger};
    let mut union = Union::new(
        snapshot(&[], Abi::native())?,
        Role::Acceptor,
        ResultMode::Added,
        Options::default(),
        Limits::default(),
    )?;
    let ledger = BodyLedger::share(&union.snapshot.ledger)?;
    let empty = ledger.charged_bytes()?;
    // Cover the payload, Rc Body, and original Entry-vector growth, but leave
    // no allowance for allocating the first ResultValue queue. Its failure is
    // after Body::new, so the new lease must refund while the grown Entry
    // metadata remains accounted by its original engine.
    let additional = 3 + Body::allocation_overhead() + 4 * core::mem::size_of::<Entry>();
    union.growth = Growth::new(additional);
    check(
        union.add_remote(
            Element {
                element_type: 7,
                data: &[1, 2, 3],
            },
            true,
        ) == Err(Error::Capacity),
    )?;
    check(
        ledger.charged_bytes()? == empty
            && union.entries.is_empty()
            && union.payload == 0
            && union.out.results.is_empty(),
    )?;
    check(union.entries.capacity() == 4)?;
    check(union.growth.claim(1) == Err(Error::Capacity))?;
    // The logical per-union payload cap remains separate from unique storage.
    union.limits.union_bytes = 2;
    union.growth = Growth::new(1024 * 1024);
    check(
        union.add_remote(
            Element {
                element_type: 7,
                data: &[1, 2, 3],
            },
            true,
        ) == Err(Error::Capacity),
    )?;
    check(ledger.charged_bytes()? == empty)
}

fn deliver(from: &mut Union, to: &mut Union, held: &mut Option<Vec<u8>>) -> Result<bool, Error> {
    if held.is_none() && !from.out.frames.is_empty() {
        *held = Some(from.out.transfer()?);
        from.out.settled()?;
    }
    if let Some(bytes) = held.as_ref() {
        match to.receive(
            PeerMessage::decode(bytes, to.snapshot.abi())?,
            &mut Scripted,
        ) {
            Ok(()) => {
                *held = None;
                return Ok(true);
            }
            Err(Error::WouldBlock | Error::NotReady) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(false)
}
fn transcript(full: bool, abi: Abi) -> Result<(), Error> {
    let options = Options {
        force_full: u8::from(full),
        force_delta: u8::from(!full),
        ..Options::default()
    };
    let mut a = Union::new(
        snapshot(&[1, 2], abi)?,
        Role::Initiator,
        ResultMode::Added,
        options,
        Limits::default(),
    )?;
    let mut b = Union::new(
        snapshot(&[2, 3], abi)?,
        Role::Acceptor,
        ResultMode::Added,
        Options::default(),
        Limits::default(),
    )?;
    a.activate();
    b.activate();
    let (mut ab, mut ba) = (None, None);
    let (mut ar, mut br) = (0, 0);
    for _ in 0..100_000 {
        for e in [&mut a, &mut b] {
            match e.progress(&mut Scripted) {
                Ok(_) | Err(Error::WouldBlock | Error::NotReady) => {}
                Err(e) => return Err(e),
            }
        }
        deliver(&mut a, &mut b, &mut ab)?;
        deliver(&mut b, &mut a, &mut ba)?;
        while let Some(r) = a.out.results.pop_front() {
            check(r.status == Status::Ok)?;
            ar += 1;
        }
        while let Some(r) = b.out.results.pop_front() {
            check(r.status == Status::Ok)?;
            br += 1;
        }
        if a.outcome() == Some(Ok(()))
            && b.outcome() == Some(Ok(()))
            && a.out.drained()
            && b.out.drained()
            && ab.is_none()
            && ba.is_none()
        {
            a.peer_retired(Error::Closed);
            b.peer_retired(Error::Closed);
            return check(
                a.outcome() == Some(Ok(()))
                    && b.outcome() == Some(Ok(()))
                    && a.size() == 3
                    && b.size() == 3
                    && ar == 1
                    && br == 1,
            );
        }
    }
    Err(Error::Deadline)
}
#[test]
fn old_delta_collision_exchange_and_full_missing_return_preserve_native_profiles()
-> Result<(), Error> {
    for order in [Order::Little, Order::Big] {
        for align64 in [4, 8] {
            for full in [false, true] {
                transcript(full, Abi { order, align64 })?;
            }
        }
    }
    Ok(())
}
#[test]
fn early_close_cannot_turn_initial_or_queued_terminal_into_success() -> Result<(), Error> {
    let abi = Abi::native();
    let mut e = Union::new(
        snapshot(&[], abi)?,
        Role::Initiator,
        ResultMode::Added,
        Options::default(),
        Limits::default(),
    )?;
    e.activate();
    e.peer_retired(Error::Closed);
    check(e.outcome() == Some(Err(Error::Closed)))?;
    e.fail(Error::Capacity);
    e.peer_retired(Error::Closed);
    check(e.outcome() == Some(Err(Error::Closed)))
}

#[test]
fn symmetric_full_initiator_receives_complete_peer_set_and_reports_both_directions()
-> Result<(), Error> {
    let abi = Abi::native();
    let mut a = Union::new(
        snapshot(&[1, 2], abi)?,
        Role::Initiator,
        ResultMode::Symmetric,
        Options {
            force_full: 1,
            ..Options::default()
        },
        Limits::default(),
    )?;
    let mut b = Union::new(
        snapshot(&[2, 3], abi)?,
        Role::Acceptor,
        ResultMode::Added,
        Options::default(),
        Limits::default(),
    )?;
    a.activate();
    b.activate();
    let (mut ab, mut ba) = (None, None);
    let mut local = Vec::new();
    let mut remote = Vec::new();
    let mut added = Vec::new();
    for _ in 0..100_000 {
        for engine in [&mut a, &mut b] {
            match engine.progress(&mut Scripted) {
                Ok(_) | Err(Error::WouldBlock | Error::NotReady) => {}
                Err(error) => return Err(error),
            }
        }
        deliver(&mut a, &mut b, &mut ab)?;
        deliver(&mut b, &mut a, &mut ba)?;
        while let Some(row) = a.out.results.pop_front() {
            let body = row.body.ok_or(Error::Conflict)?;
            check(body.data.len() == 1)?;
            match row.status {
                Status::AddLocal => local.push(body.data[0]),
                Status::AddRemote => remote.push(body.data[0]),
                _ => return Err(Error::Conflict),
            }
        }
        while let Some(row) = b.out.results.pop_front() {
            let body = row.body.ok_or(Error::Conflict)?;
            check(row.status == Status::Ok && body.data.len() == 1)?;
            added.push(body.data[0]);
        }
        if a.outcome() == Some(Ok(()))
            && b.outcome() == Some(Ok(()))
            && a.out.drained()
            && b.out.drained()
            && ab.is_none()
            && ba.is_none()
        {
            check(local == [3] && remote == [1] && added == [1])?;
            check(a.size() == 3 && b.size() == 3)?;
            a.peer_retired(Error::Closed);
            b.peer_retired(Error::Closed);
            return check(a.outcome() == Some(Ok(())) && b.outcome() == Some(Ok(())));
        }
    }
    Err(Error::Deadline)
}

// Each native write below is an explicit synthetic settled observation. No
// execution of this transcript is claimed during source preparation.
fn mutual_pair(av: &[u8], bv: &[u8], am: ResultMode, bm: ResultMode) -> Result<(), Error> {
    let abi = Abi::native();
    let options = Options {
        force_full: 1,
        ..Options::default()
    };
    let mut a = Union::new(
        snapshot(av, abi)?,
        Role::Initiator,
        am,
        options,
        Limits::default(),
    )?;
    let mut b = Union::new(
        snapshot(bv, abi)?,
        Role::Acceptor,
        bm,
        options,
        Limits::default(),
    )?;
    a.activate();
    b.activate();
    let (mut ab, mut ba) = (None, None);
    let (mut al, mut ar, mut bl, mut br) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for _ in 0..100_000 {
        for e in [&mut a, &mut b] {
            match e.progress(&mut Scripted) {
                Ok(_) | Err(Error::WouldBlock | Error::NotReady) => {}
                Err(e) => return Err(e),
            }
        }
        deliver(&mut a, &mut b, &mut ab)?;
        deliver(&mut b, &mut a, &mut ba)?;
        // The complete received full set and settled original sends permit only
        // local result work after actual peer close; no additional peer frame.
        for e in [&mut a, &mut b] {
            if e.can_finish_locally() && !e.retired {
                e.peer_retired(Error::Closed);
            }
        }
        for (e, mode, local, remote) in [
            (&mut a, am, &mut al, &mut ar),
            (&mut b, bm, &mut bl, &mut br),
        ] {
            while let Some(row) = e.out.results.pop_front() {
                let body = row.body.ok_or(Error::Conflict)?;
                check(body.data.len() == 1)?;
                match (mode, row.status) {
                    (ResultMode::Added, Status::Ok) | (ResultMode::Symmetric, Status::AddLocal) => {
                        local.push(body.data[0])
                    }
                    (ResultMode::Symmetric, Status::AddRemote) => remote.push(body.data[0]),
                    _ => return Err(Error::Conflict),
                }
            }
        }
        if a.outcome() == Some(Ok(()))
            && b.outcome() == Some(Ok(()))
            && a.out.drained()
            && b.out.drained()
            && ab.is_none()
            && ba.is_none()
        {
            let mut expected_al = bv
                .iter()
                .copied()
                .filter(|v| !av.contains(v))
                .collect::<Vec<_>>();
            let mut expected_bl = av
                .iter()
                .copied()
                .filter(|v| !bv.contains(v))
                .collect::<Vec<_>>();
            expected_al.sort_unstable();
            expected_bl.sort_unstable();
            for list in [&mut al, &mut ar, &mut bl, &mut br] {
                list.sort_unstable();
            }
            check(al == expected_al && bl == expected_bl)?;
            check(
                ar == if am == ResultMode::Symmetric {
                    expected_bl.clone()
                } else {
                    Vec::new()
                },
            )?;
            check(
                br == if bm == ResultMode::Symmetric {
                    expected_al.clone()
                } else {
                    Vec::new()
                },
            )?;
            a.peer_retired(Error::Closed);
            b.peer_retired(Error::Closed);
            return check(a.outcome() == Some(Ok(())) && b.outcome() == Some(Ok(())));
        }
    }
    Err(Error::Deadline)
}
#[test]
fn one_reciprocal_full_request_completes_both_modes_roles_and_empty_sets() -> Result<(), Error> {
    for am in [ResultMode::Added, ResultMode::Symmetric] {
        for bm in [ResultMode::Added, ResultMode::Symmetric] {
            // A>B makes an ADDED evaluator request B as well; equal/smaller
            // exercises the direct first-leg path, with the same public modes.
            mutual_pair(&[1, 2, 4], &[2, 3], am, bm)?;
            mutual_pair(&[1, 2], &[2, 3], am, bm)?;
            mutual_pair(&[], &[2, 3], am, bm)?;
            mutual_pair(&[1, 2], &[], am, bm)?;
            mutual_pair(&[], &[], am, bm)?;
        }
    }
    Ok(())
}
fn mutual_before_local_send() -> Result<Union, Error> {
    let abi = Abi::native();
    let mut a = Union::new(
        snapshot(&[1, 2], abi)?,
        Role::Initiator,
        ResultMode::Symmetric,
        Options {
            force_full: 1,
            ..Options::default()
        },
        Limits::default(),
    )?;
    let mut b = Union::new(
        snapshot(&[], abi)?,
        Role::Acceptor,
        ResultMode::Symmetric,
        Options::default(),
        Limits::default(),
    )?;
    a.activate();
    b.activate();
    let (mut ab, mut ba) = (None, None);
    for _ in 0..100_000 {
        a.progress(&mut Scripted)?;
        b.progress(&mut Scripted)?;
        deliver(&mut b, &mut a, &mut ba)?;
        deliver(&mut a, &mut b, &mut ab)?;
        deliver(&mut b, &mut a, &mut ba)?;
        if a.phase == Phase::FullMutualFirst {
            return Ok(a);
        }
    }
    Err(Error::Deadline)
}
#[test]
fn early_peer_full_done_does_not_settle_local_send_or_retry_a_request() -> Result<(), Error> {
    let mut a = mutual_before_local_send()?;
    check(a.receive(PeerMessage::UnionRequestFull, &mut Scripted) == Err(Error::Malformed))?;
    check(a.phase == Phase::FullMutualFirst && a.full_request_sent && !a.full_local_done)?;
    // Empty peer's full-set boundary can precede our complete response. It is
    // evidence for its set, never a native write receipt for our original set.
    a.receive(PeerMessage::UnionFullDone, &mut Scripted)?;
    check(a.full_peer_done && a.outcome().is_none() && !a.wants_close())?;
    let mut held = Vec::new();
    for _ in 0..100_000 {
        a.progress(&mut Scripted)?;
        while !a.out.frames.is_empty() {
            held.push(a.out.transfer()?);
        }
        if a.phase == Phase::FullMutualResults {
            break;
        }
    }
    check(a.full_local_done && a.out.peer_pending == 3 && !a.can_finish_locally())?;
    check(a.outcome().is_none())?;
    a.peer_retired(Error::Closed);
    check(a.outcome() == Some(Err(Error::Closed)))?;
    while a.out.peer_pending != 0 {
        a.out.settled()?;
    }
    // Settling an unknown/lost operation afterward cannot upgrade its result.
    check(!a.can_finish_locally() && a.outcome() == Some(Err(Error::Closed)))?;
    check(held.len() == 3)?;
    let mut lost = mutual_before_local_send()?;
    lost.receive(PeerMessage::UnionFullDone, &mut Scripted)?;
    for _ in 0..100_000 {
        lost.progress(&mut Scripted)?;
        while !lost.out.frames.is_empty() {
            let _original = lost.out.transfer()?;
            lost.out.settled()?;
        }
        if lost.phase == Phase::FullMutualResults {
            break;
        }
    }
    // The real Service terminal settles its ledger then calls fail_op for
    // Lost/Unsent atomically. A drained ledger alone must not become success.
    lost.fail(Error::Unavailable);
    lost.peer_retired(Error::Closed);
    check(!lost.can_finish_locally() && lost.outcome() == Some(Err(Error::Unavailable)))
}
#[test]
fn explicit_strategy_conflicts_fail_before_processing_the_other_strategy() -> Result<(), Error> {
    let abi = Abi::native();
    let mut delta = Union::new(
        snapshot(&[1], abi)?,
        Role::Acceptor,
        ResultMode::Symmetric,
        Options {
            force_delta: 1,
            ..Options::default()
        },
        Limits::default(),
    )?;
    delta.activate();
    for _ in 0..100_000 {
        delta.progress(&mut Scripted)?;
        if delta.strata_ready {
            break;
        }
    }
    check(delta.receive(PeerMessage::UnionRequestFull, &mut Scripted) == Err(Error::Unsupported))?;
    check(!delta.full_request_sent && delta.phase == Phase::ExpectIbf)?;
    let mut full = Union::new(
        snapshot(&[1], abi)?,
        Role::Acceptor,
        ResultMode::Added,
        Options {
            force_full: 1,
            ..Options::default()
        },
        Limits::default(),
    )?;
    full.activate();
    for _ in 0..100_000 {
        full.progress(&mut Scripted)?;
        if full.strata_ready {
            break;
        }
    }
    let buckets = [0; 13];
    check(
        full.receive(
            PeerMessage::UnionIbf {
                order: 0,
                reserved1: 0,
                reserved2: 0,
                offset: 0,
                salt: 42,
                buckets: wire::IbfSlice::decode(&buckets)?,
            },
            &mut Scripted,
        ) == Err(Error::Unsupported),
    )?;
    check(full.remote_ibf.is_none() && full.build.is_none())
}

#[test]
fn passive_delta_done_keeps_late_original_demand_until_active_peer_closes() -> Result<(), Error> {
    // These ordinary type25 values are the two first-round bodies from the
    // actual failed C public-API profile. Only the pure owners run in this
    // source case; transfer/settled below are explicit scripted observations,
    // not claims of native writes or interoperability.
    fn original(payload: &[u8], abi: Abi) -> Result<Snapshot, Error> {
        let mut content = Content::new(ContentLimits::default(), abi)?;
        let block = gnunet_wire::official::consensus::Block {
            payload_type: 0,
            marker: 0,
            data: payload,
        };
        let mut data = alloc::vec![0; block.encoded_len()?];
        block.encode(&mut data)?;
        content.add(Element {
            element_type: 25,
            data: &data,
        })?;
        content.snapshot()
    }
    let abi = Abi {
        order: Order::Little,
        align64: 8,
    };
    let options = Options {
        force_delta: 1,
        ..Options::default()
    };
    let mut a = Union::new(
        original(b"CONSENSUS-A\0\x01\x7f\x80\xff", abi)?,
        Role::Initiator,
        ResultMode::Symmetric,
        options,
        Limits::default(),
    )?;
    let mut b = Union::new(
        original(b"CONSENSUS-B\0\x02\x7f\x81\xfe", abi)?,
        Role::Acceptor,
        ResultMode::Symmetric,
        Options::default(),
        Limits::default(),
    )?;
    a.activate();
    b.activate();
    let mut ab = alloc::collections::VecDeque::new();
    let mut ba = alloc::collections::VecDeque::new();
    let mut release_offer = false;
    let mut observed_passive_done = false;
    let mut local = [0usize; 2];
    let mut remote = [0usize; 2];
    for _ in 0..100_000 {
        for engine in [&mut a, &mut b] {
            match engine.progress(&mut Scripted) {
                Ok(_) | Err(Error::WouldBlock | Error::NotReady) => {}
                Err(error) => return Err(error),
            }
        }
        for (engine, wire) in [(&mut a, &mut ab), (&mut b, &mut ba)] {
            while !engine.out.frames.is_empty() {
                wire.push_back(engine.out.transfer()?);
                engine.out.settled()?;
            }
        }
        if let Some(bytes) = ab.front() {
            let message = PeerMessage::decode(bytes, abi)?;
            // Preserve A->B FIFO while delaying its already-written offer and
            // every later frame. B->A remains independently ordered and live.
            if release_offer || !matches!(message, PeerMessage::UnionOffer { .. }) {
                match b.receive(message, &mut Scripted) {
                    Ok(()) => {
                        ab.pop_front();
                    }
                    Err(Error::WouldBlock | Error::NotReady) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        if let Some(bytes) = ba.front() {
            match a.receive(PeerMessage::decode(bytes, abi)?, &mut Scripted) {
                Ok(()) => {
                    ba.pop_front();
                }
                Err(Error::WouldBlock | Error::NotReady) => {}
                Err(error) => return Err(error),
            }
        }
        for (index, engine) in [&mut a, &mut b].into_iter().enumerate() {
            while let Some(row) = engine.out.results.pop_front() {
                check(row.body.is_some())?;
                match row.status {
                    Status::AddLocal => local[index] += 1,
                    Status::AddRemote => remote[index] += 1,
                    _ => return Err(Error::Conflict),
                }
            }
        }
        if !release_offer && a.outcome() == Some(Ok(())) && a.out.drained() {
            check(a.phase == Phase::PassiveDone && !a.wants_close())?;
            check(b.outcome().is_none() && b.size() == 1)?;
            let mut own_done_written = false;
            for bytes in &ab {
                own_done_written |=
                    matches!(PeerMessage::decode(bytes, abi)?, PeerMessage::UnionDone);
            }
            check(own_done_written)?;
            observed_passive_done = true;
            release_offer = true;
        }
        if release_offer
            && a.outcome() == Some(Ok(()))
            && b.outcome() == Some(Ok(()))
            && a.out.drained()
            && b.out.drained()
            && ab.is_empty()
            && ba.is_empty()
        {
            check(observed_passive_done && !a.wants_close() && b.wants_close())?;
            check(a.size() == 2 && b.size() == 2)?;
            check(local == [1, 1] && remote == [1, 1])?;
            // Only the active endpoint initiates the terminal physical close.
            // The passive endpoint observes that original peer retirement.
            b.peer_retired(Error::Closed);
            a.peer_retired(Error::Closed);
            return check(a.outcome() == Some(Ok(())) && b.outcome() == Some(Ok(())));
        }
    }
    // The original finite run did not reach its required terminal state.
    Err(Error::Conflict)
}
