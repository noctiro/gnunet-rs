//! Deterministic pure-owner models, with genuine Book source/reset receipts.
//! They demonstrate Rust state invariants, not official C crypto interoperability.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible owner models assert actual original wire/counter/timer observations"
)]
use super::*;
use crate::connection::{
    Authentication, FrameSlot, Instance, Neighbor, NeighborSlot, OriginSlot, RouteSlot,
};
use crate::tunnel::SkippedSlot;
use gnunet_wire::official::cadet_peer::{
    CONNECTION_INITIATOR_PURPOSE, ConnectionInitiatorPurpose, PathPeers,
};

const PLAIN: [u8; 4] = [0, 4, 3, 244];
struct Draw(u8);
impl Entropy for Draw {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), Error> {
        output.fill(self.0);
        self.0 = self.0.checked_add(1).ok_or(Error::Entropy)?;
        Ok(())
    }
}
fn emit_connection<const P: usize>(
    book: &mut Book<'_, '_, '_, P>,
    now: u64,
    output: &mut [u8],
) -> Result<usize, Error> {
    let queued = book.next_frame().ok_or(Error::NotReady)?;
    let length = queued.bytes.len();
    output
        .get_mut(..length)
        .ok_or(Error::Capacity)?
        .copy_from_slice(queued.bytes);
    let frame = queued.frame;
    let original = book.start(frame)?;
    book.exposed(original)?;
    let completion = book.settle(original, true, MonoInstant(now))?;
    assert_eq!(completion.outcome, connection::Outcome::Written);
    book.release_frame(frame)?;
    book.neighbor_ready(original.neighbor(), true)?;
    Ok(length)
}
fn with_pair(
    test: impl for<'id, 'slots, 'route, 'routes, 'bytes> FnOnce(
        &mut Controller<'id, 'slots, 'route>,
        &mut Controller<'id, 'slots, 'route>,
        &mut Book<'route, 'routes, 'bytes, 4>,
        &mut Book<'route, 'routes, 'bytes, 4>,
        [Neighbor<'route>; 2],
        &mut Draw,
    ) -> Result<(), Error>,
) -> Result<(), Error> {
    let first = Identity::from_seed([1; 32]);
    let second = Identity::from_seed([2; 32]);
    let (a, b) = if first.peer() < second.peer() {
        (first, second)
    } else {
        (second, first)
    };
    let domain = crate::tunnel::context::Instance::new();
    let mut context_rows = [const { crate::tunnel::context::Slot::new() }; 2];
    let mut registry = crate::tunnel::context::Registry::new(&domain, &mut context_rows)?;
    let ac = registry.allocate(a.peer(), b.peer())?;
    let bc = registry.allocate(b.peer(), a.peer())?;
    let mut ai = Instance::new();
    let mut bi = Instance::new();
    let mut an = [NeighborSlot::new(); 2];
    let mut bn = [NeighborSlot::new(); 2];
    let mut ar = [RouteSlot::<4>::new(); 4];
    let mut br = [RouteSlot::<4>::new(); 4];
    let mut ao = [OriginSlot::new(); 2];
    let mut bo = [OriginSlot::new(); 2];
    let mut ab = [[0; 512]; 4];
    let mut bb = [[0; 512]; 4];
    let mut af = ab.each_mut().map(|bytes| FrameSlot::new(bytes));
    let mut bf = bb.each_mut().map(|bytes| FrameSlot::new(bytes));
    let mut abook = Book::new(
        &mut ai,
        a.peer(),
        &mut an,
        &mut ar,
        &mut ao,
        &mut af,
        MonoInstant(0),
        connection::Limits::default(),
    )?;
    let mut bbook = Book::new(
        &mut bi,
        b.peer(),
        &mut bn,
        &mut br,
        &mut bo,
        &mut bf,
        MonoInstant(0),
        connection::Limits::default(),
    )?;
    // These are the original CORE-neighbor handles actually delivering the
    // fixture's frames; an incoming source is never rebound by peer lookup.
    let at_a = abook.neighbor_up(b.peer())?;
    let at_b = bbook.neighbor_up(a.peer())?;
    abook.neighbor_ready(at_a, true)?;
    bbook.neighbor_ready(at_b, true)?;
    let path = [a.peer(), b.peer()];
    let route = abook
        .open(
            PathPeers::new(&path),
            [9; 32],
            Authentication::Unsigned,
            MonoInstant(0),
        )?
        .route;
    let mut wire = [0; 512];
    let length = emit_connection(&mut abook, 0, &mut wire)?;
    assert!(matches!(
        bbook.receive(at_b, PeerMessage::decode(&wire[..length])?, MonoInstant(0))?,
        connection::Event::Created { .. }
    ));
    let length = emit_connection(&mut bbook, 0, &mut wire)?;
    assert!(
        matches!(abook.receive(at_a,PeerMessage::decode(&wire[..length])?,MonoInstant(0))?,connection::Event::Ready(found) if found==route)
    );
    let mut as1 = [const { SkippedSlot::new() }; 4];
    let mut at1 = [const { SkippedSlot::new() }; 4];
    let mut as2 = [const { SkippedSlot::new() }; 4];
    let mut at2 = [const { SkippedSlot::new() }; 4];
    let mut bs1 = [const { SkippedSlot::new() }; 4];
    let mut bt1 = [const { SkippedSlot::new() }; 4];
    let mut bs2 = [const { SkippedSlot::new() }; 4];
    let mut bt2 = [const { SkippedSlot::new() }; 4];
    let limits = Limits {
        crypto: CryptoLimits {
            plaintext_bytes: 256,
            maximum_gap: 256,
        },
        maximum_unverified_attempts: 2,
        ..Limits::default()
    };
    let mut a = Controller::new(
        ac,
        &a,
        abook.reset_authority(),
        Stores {
            first: Storage {
                skipped: &mut as1,
                staging: &mut at1,
            },
            second: Storage {
                skipped: &mut as2,
                staging: &mut at2,
            },
        },
        limits,
        MonoInstant(0),
    )?;
    let mut b = Controller::new(
        bc,
        &b,
        bbook.reset_authority(),
        Stores {
            first: Storage {
                skipped: &mut bs1,
                staging: &mut bt1,
            },
            second: Storage {
                skipped: &mut bs2,
                staging: &mut bt2,
            },
        },
        limits,
        MonoInstant(0),
    )?;
    test(
        &mut a,
        &mut b,
        &mut abook,
        &mut bbook,
        [at_a, at_b],
        &mut Draw(17),
    )
}
fn emit_control<'route>(
    controller: &mut Controller<'_, '_, 'route>,
    book: &mut Book<'route, '_, '_, 4>,
    now: u64,
    output: &mut [u8],
    entropy: &mut Draw,
) -> Result<usize, Error> {
    let prepared = controller
        .prepare(controller.scope(), book, MonoInstant(now), output, entropy)?
        .ok_or(Error::NotReady)?;
    let logical = prepared.attempt();
    let length = prepared.bytes().len();
    let frame = book.queue_payload(
        logical.route(),
        PeerMessage::decode(prepared.bytes())?,
        MonoInstant(now),
    )?;
    let physical = book.start(frame)?;
    if let Err(rejected) = controller.submit(prepared, book, physical) {
        return Err(rejected.reason);
    }
    // Real pending connection admission still did not start a retry timer.
    assert!(
        controller
            .snapshot()
            .retry_at
            .is_none_or(|due| due.0 <= now)
    );
    book.exposed(physical)?;
    let completion = book.settle(physical, true, MonoInstant(now))?;
    controller.complete(logical, completion, MonoInstant(now))?;
    book.release_frame(frame)?;
    book.neighbor_ready(physical.neighbor(), true)?;
    Ok(length)
}
fn control<'id, 'route>(
    controller: &mut Controller<'id, '_, 'route>,
    book: &mut Book<'route, '_, '_, 4>,
    source: Neighbor<'route>,
    wire: &[u8],
    now: u64,
    entropy: &mut Draw,
) -> Result<Event<'id>, Error> {
    let connection::Event::Endpoint(endpoint) =
        book.receive(source, PeerMessage::decode(wire)?, MonoInstant(now))?
    else {
        return Err(Error::Malformed);
    };
    controller.control(controller.scope(), endpoint, MonoInstant(now), entropy)
}
fn open<'id, 'route, 'out>(
    controller: &mut Controller<'id, '_, 'route>,
    book: &mut Book<'route, '_, '_, 4>,
    source: Neighbor<'route>,
    wire: &[u8],
    now: u64,
    output: &'out mut [u8],
) -> Result<Received<'id, 'out>, Error> {
    let connection::Event::Endpoint(endpoint) =
        book.receive(source, PeerMessage::decode(wire)?, MonoInstant(now))?
    else {
        return Err(Error::Malformed);
    };
    controller.open(controller.scope(), endpoint, wire, output)
}
fn seal(
    controller: &mut Controller<'_, '_, '_>,
    output: &mut [u8],
    entropy: &mut Draw,
) -> Result<usize, Error> {
    let live = controller.active.as_mut().ok_or(Error::NotReady)?;
    Ok(live
        .session
        .seal(live.session.scope(), [9; 32], &PLAIN, output, entropy)?
        .bytes()
        .len())
}
fn first_proof(controller: &Controller<'_, '_, '_>) -> Result<[u8; 64], Error> {
    match controller
        .active
        .as_ref()
        .ok_or(Error::NotReady)?
        .session
        .initial_auth(controller.scope(), [9; 32], false)?
    {
        PeerMessage::KeyExchangeAuth { auth, .. } => Ok(auth),
        _ => Err(Error::Malformed),
    }
}

#[test]
fn final_original_auth_survives_first_ratchet_and_unverified_rekey_preserves_working_session()
-> Result<(), Error> {
    with_pair(|a, b, abook, bbook, sources, entropy| {
        assert!(matches!(
            a.request(a.scope(), MonoInstant(0), entropy)?,
            Event::Started(_)
        ));
        let mut kx = [0; 168];
        let n = emit_control(a, abook, 0, &mut kx, entropy)?;
        assert!(matches!(
            control(b, bbook, sources[1], &kx[..n], 0, entropy)?,
            Event::Candidate(_)
        ));
        let mut response = [0; 168];
        let n = emit_control(b, bbook, 0, &mut response, entropy)?;
        assert!(matches!(
            control(a, abook, sources[0], &response[..n], 0, entropy)?,
            Event::Confirmed(_)
        ));
        let original_proof = first_proof(a)?;
        let mut packet = [0; 128];
        let pn = seal(a, &mut packet, entropy)?;
        assert_eq!(a.crypto_snapshot().ok_or(Error::NotReady)?.sent, 1);
        // The first Alice packet changed RK, but the queued final auth retains
        // the original initial root proof/exchange needed by Betty's candidate.
        let mut final_auth = [0; 168];
        let n = emit_control(a, abook, 0, &mut final_auth, entropy)?;
        let PeerMessage::KeyExchangeAuth { auth, flags, .. } =
            PeerMessage::decode(&final_auth[..n])?
        else {
            return Err(Error::Malformed);
        };
        assert_eq!(auth, original_proof);
        assert_eq!(flags, 0);
        assert!(matches!(
            control(b, bbook, sources[1], &final_auth[..n], 0, entropy)?,
            Event::Confirmed(_)
        ));
        let mut plain = [0; 32];
        assert!(!open(b, bbook, sources[1], &packet[..pn], 0, &mut plain)?.promoted);
        assert_eq!(&plain[..4], &PLAIN);
        let established = b.crypto_snapshot();
        let confirmed = b.snapshot().confirmed;
        let fresh = LocalKeys::generate(entropy)?.exchange();
        let unsolicited = PeerMessage::KeyExchange {
            connection: [9; 32],
            flags: KX_FORCE_REPLY,
            ephemeral_key: fresh.ephemeral_key,
            ratchet_key: fresh.ratchet_key,
        };
        let n = unsolicited.encode(&mut kx)?;
        assert!(matches!(
            control(b, bbook, sources[1], &kx[..n], 0, entropy)?,
            Event::Candidate(_)
        ));
        assert_eq!(b.snapshot().confirmed, confirmed);
        assert_eq!(b.crypto_snapshot(), established);
        let bad = PeerMessage::KeyExchangeAuth {
            connection: [9; 32],
            flags: 0,
            ephemeral_key: fresh.ephemeral_key,
            ratchet_key: fresh.ratchet_key,
            auth: [0; 64],
        };
        let n = bad.encode(&mut response)?;
        for _ in 0..2 {
            assert!(matches!(
                control(b, bbook, sources[1], &response[..n], 0, entropy),
                Err(Error::Authentication)
            ));
            assert_eq!(b.snapshot().confirmed, confirmed);
            assert_eq!(b.crypto_snapshot(), established);
        }
        assert!(b.snapshot().candidate.is_none());
        // Retried public original proof elicits the original response without
        // changing counters/root, even though Alice has already ratcheted.
        let before = a.crypto_snapshot();
        let live = b.active.as_ref().ok_or(Error::NotReady)?;
        let n = live
            .session
            .initial_auth(live.session.scope(), [9; 32], true)?
            .encode(&mut response)?;
        assert_eq!(
            control(a, abook, sources[0], &response[..n], 0, entropy)?,
            Event::Duplicate
        );
        assert_eq!(a.crypto_snapshot(), before);
        let n = emit_control(a, abook, 0, &mut final_auth, entropy)?;
        assert!(
            matches!(PeerMessage::decode(&final_auth[..n])?,PeerMessage::KeyExchangeAuth{auth,..} if auth==original_proof)
        );
        Ok(())
    })
}

#[test]
fn only_complete_authenticated_packet_promotes_candidate_bad_tag_and_replay_do_not_advance()
-> Result<(), Error> {
    with_pair(|a, b, abook, bbook, sources, entropy| {
        a.request(a.scope(), MonoInstant(0), entropy)?;
        let mut control_wire = [0; 168];
        let n = emit_control(a, abook, 0, &mut control_wire, entropy)?;
        control(b, bbook, sources[1], &control_wire[..n], 0, entropy)?;
        let n = emit_control(b, bbook, 0, &mut control_wire, entropy)?;
        control(a, abook, sources[0], &control_wire[..n], 0, entropy)?;
        assert!(b.snapshot().confirmed.is_none());
        let candidate = b.snapshot().candidate;
        let mut packet = [0; 128];
        let n = seal(a, &mut packet, entropy)?;
        let mut bad = packet;
        bad[n - 1] ^= 1;
        let mut output = [0xa5; 32];
        assert!(matches!(
            open(b, bbook, sources[1], &bad[..n], 0, &mut output),
            Err(Error::Authentication)
        ));
        assert_eq!(&output[..4], &[0; 4]);
        assert_eq!(b.snapshot().candidate, candidate);
        assert!(b.snapshot().confirmed.is_none());
        let received = open(b, bbook, sources[1], &packet[..n], 0, &mut output)?;
        assert!(received.promoted);
        assert_eq!(Some(received.generation), candidate);
        assert_eq!(received.opened.bytes(), &PLAIN);
        let established = b.crypto_snapshot();
        assert!(matches!(
            open(b, bbook, sources[1], &packet[..n], 0, &mut output),
            Err(Error::Replay)
        ));
        assert_eq!(b.crypto_snapshot(), established);
        assert!(b.snapshot().candidate.is_none());
        // Exact received source proof cannot be reused under Alice's Context.
        let connection::Event::Endpoint(endpoint) = bbook.receive(
            sources[1],
            PeerMessage::decode(&packet[..n])?,
            MonoInstant(0),
        )?
        else {
            return Err(Error::Malformed);
        };
        assert!(matches!(
            b.open(a.scope(), endpoint, &packet[..n], &mut output),
            Err(Error::StaleGeneration)
        ));
        let sent = a.crypto_snapshot().ok_or(Error::NotReady)?.sent;
        let _abandoned = seal(a, &mut packet, entropy)?;
        assert_eq!(a.crypto_snapshot().ok_or(Error::NotReady)?.sent, sent + 1);
        let _new_original = seal(a, &mut packet, entropy)?;
        assert_eq!(a.crypto_snapshot().ok_or(Error::NotReady)?.sent, sent + 2);
        Ok(())
    })
}

#[test]
fn actual_original_write_starts_retry_and_only_fresh_book_reset_proof_pauses_generation()
-> Result<(), Error> {
    with_pair(|a, b, abook, _bbook, sources, entropy| {
        a.request(a.scope(), MonoInstant(0), entropy)?;
        let mut wire = [0; 168];
        let prepared = a
            .prepare(a.scope(), abook, MonoInstant(0), &mut wire, entropy)?
            .ok_or(Error::NotReady)?;
        let original = prepared.attempt();
        let original_exchange = PeerMessage::decode(prepared.bytes())?;
        assert!(a.snapshot().retry_at.is_none());
        a.reject_prepared(prepared)?;
        let mut retained = [0; 168];
        let prepared = a
            .prepare(a.scope(), abook, MonoInstant(0), &mut retained, entropy)?
            .ok_or(Error::NotReady)?;
        assert_eq!(prepared.attempt(), original);
        assert_eq!(PeerMessage::decode(prepared.bytes())?, original_exchange);
        let frame = abook.queue_payload(
            original.route(),
            PeerMessage::decode(prepared.bytes())?,
            MonoInstant(0),
        )?;
        let actual = abook.start(frame)?;
        if let Err(rejected) = a.submit(prepared, abook, actual) {
            return Err(rejected.reason);
        }
        assert!(a.snapshot().retry_at.is_none());
        let completion = abook.settle(actual, false, MonoInstant(1))?;
        assert_eq!(completion.outcome, connection::Outcome::Unsent);
        a.complete(original, completion, MonoInstant(1))?;
        abook.release_frame(frame)?;
        abook.neighbor_ready(actual.neighbor(), true)?;
        assert!(a.snapshot().retry_at.is_none());
        let mut retry = [0; 168];
        let prepared = a
            .prepare(a.scope(), abook, MonoInstant(1), &mut retry, entropy)?
            .ok_or(Error::NotReady)?;
        let second = prepared.attempt();
        assert_ne!(original, second);
        assert_eq!(PeerMessage::decode(prepared.bytes())?, original_exchange);
        let frame = abook.queue_payload(
            second.route(),
            PeerMessage::decode(prepared.bytes())?,
            MonoInstant(1),
        )?;
        let actual = abook.start(frame)?;
        if let Err(rejected) = a.submit(prepared, abook, actual) {
            return Err(rejected.reason);
        }
        abook.exposed(actual)?;
        let completion = abook.settle(actual, true, MonoInstant(1))?;
        a.complete(second, completion, MonoInstant(1))?;
        abook.release_frame(frame)?;
        abook.neighbor_ready(actual.neighbor(), true)?;
        assert_eq!(a.snapshot().retry_at, Some(MonoInstant(250_001)));
        assert_eq!(a.tick(a.scope(), MonoInstant(250_000))?, Event::Idle);
        assert_eq!(a.tick(a.scope(), MonoInstant(250_001))?, Event::RetryDue);
        let mut last = [0; 168];
        let prepared = a
            .prepare(a.scope(), abook, MonoInstant(250_001), &mut last, entropy)?
            .ok_or(Error::NotReady)?;
        assert_ne!(prepared.attempt(), second);
        assert_eq!(PeerMessage::decode(prepared.bytes())?, original_exchange);
        // Mint a real purpose38 reset proof from the original peer's signed
        // CREATE. Context/source authority and monotime high-water are checked.
        let one = gnunet_crypto::EddsaPrivateKey::from_seed([1; 32]);
        let two = gnunet_crypto::EddsaPrivateKey::from_seed([2; 32]);
        let key = if *one.public_key().as_bytes() == b.scope().local() {
            one
        } else {
            two
        };
        let mut purpose = [0; 16];
        ConnectionInitiatorPurpose { monotime: 77 }.encode(&mut purpose)?;
        let signature = key.sign(CONNECTION_INITIATOR_PURPOSE, &purpose)?;
        let path = [b.scope().local(), a.scope().local()];
        let create = PeerMessage::ConnectionCreate {
            options_bytes: [2, 0, 0, 0],
            has_monotime_bytes: [1, 0, 0, 0],
            monotime: 77,
            monotime_signature: *signature.as_bytes(),
            connection: [10; 32],
            path: PathPeers::new(&path),
        };
        let connection::Event::Created {
            reset: connection::Reset::Fresh(proof),
            ..
        } = abook.receive(sources[0], create, MonoInstant(250_001))?
        else {
            return Err(Error::Malformed);
        };
        assert!(matches!(
            b.peer_reset(b.scope(), proof, MonoInstant(250_001)),
            Err(Error::Authentication)
        ));
        assert_eq!(
            a.peer_reset(a.scope(), proof, MonoInstant(250_001))?,
            Event::ResetArmed
        );
        assert_eq!(a.snapshot().reset_high_water, 77);
        assert!(a.snapshot().traffic_paused);
        assert!(a.snapshot().candidate.is_none());
        assert_eq!(
            a.peer_reset(a.scope(), proof, MonoInstant(250_001)),
            Err(Error::Replay)
        );
        // Original never-submitted preview still needs explicit retirement;
        // closing does not manufacture a physical write or leave it retained.
        a.close(a.scope())?;
        a.reject_prepared(prepared)?;
        assert!(a.snapshot().pending.is_none());
        assert!(a.snapshot().closed);
        Ok(())
    })
}

fn establish<'route>(
    a: &mut Controller<'_, '_, 'route>,
    b: &mut Controller<'_, '_, 'route>,
    abook: &mut Book<'route, '_, '_, 4>,
    bbook: &mut Book<'route, '_, '_, 4>,
    sources: [Neighbor<'route>; 2],
    entropy: &mut Draw,
) -> Result<(), Error> {
    a.request(a.scope(), MonoInstant(0), entropy)?;
    let mut wire = [0; 168];
    let n = emit_control(a, abook, 0, &mut wire, entropy)?;
    control(b, bbook, sources[1], &wire[..n], 0, entropy)?;
    let n = emit_control(b, bbook, 0, &mut wire, entropy)?;
    control(a, abook, sources[0], &wire[..n], 0, entropy)?;
    let n = emit_control(a, abook, 0, &mut wire, entropy)?;
    control(b, bbook, sources[1], &wire[..n], 0, entropy)?;
    Ok(())
}

#[test]
fn absolute_candidate_lifetime_survives_admission_failure_unknown_and_missing_route_without_key_loss()
-> Result<(), Error> {
    with_pair(|a, b, abook, bbook, sources, entropy| {
        establish(a, b, abook, bbook, sources, entropy)?;
        let working = a.snapshot().confirmed;
        let cipher = a.crypto_snapshot();
        a.limits.negotiation_micros = 10;
        a.request(a.scope(), MonoInstant(0), entropy)?;
        let mut wire = [0; 168];
        let prepared = a
            .prepare(a.scope(), abook, MonoInstant(0), &mut wire, entropy)?
            .ok_or(Error::NotReady)?;
        a.reject_prepared(prepared)?;
        assert_eq!(a.next_deadline(), Some(MonoInstant(10)));
        assert_eq!(a.snapshot().negotiation_deadline, Some(MonoInstant(10)));
        assert!(a.snapshot().retry_at.is_none());
        // Refusal/re-preview cannot extend the original deadline, and an
        // outstanding preview cannot block expiry or become a new-generation
        // output. Its only remaining return operation retires that old output.
        let prepared = a
            .prepare(a.scope(), abook, MonoInstant(9), &mut wire, entropy)?
            .ok_or(Error::NotReady)?;
        assert_eq!(a.tick(a.scope(), MonoInstant(9))?, Event::Idle);
        assert_eq!(a.tick(a.scope(), MonoInstant(10))?, Event::Expired);
        a.reject_prepared(prepared)?;
        assert!(a.snapshot().candidate.is_none());
        assert_eq!(a.snapshot().confirmed, working);
        assert_eq!(a.crypto_snapshot(), cipher);
        assert!(
            a.prepare(a.scope(), abook, MonoInstant(10), &mut wire, entropy)?
                .is_none()
        );
        assert!(a.snapshot().pending.is_none());

        a.request(a.scope(), MonoInstant(11), entropy)?;
        let prepared = a
            .prepare(a.scope(), abook, MonoInstant(11), &mut wire, entropy)?
            .ok_or(Error::NotReady)?;
        let logical = prepared.attempt();
        let frame = abook.queue_payload(
            logical.route(),
            PeerMessage::decode(prepared.bytes())?,
            MonoInstant(11),
        )?;
        let physical = abook.start(frame)?;
        if let Err(rejected) = a.submit(prepared, abook, physical) {
            return Err(rejected.reason);
        }
        abook.exposed(physical)?;
        let completion = abook.settle(physical, false, MonoInstant(12))?;
        assert_eq!(completion.outcome, connection::Outcome::Unknown);
        a.complete(logical, completion, MonoInstant(12))?;
        abook.release_frame(frame)?;
        abook.neighbor_ready(physical.neighbor(), true)?;
        assert_eq!(a.snapshot().negotiation_deadline, Some(MonoInstant(21)));
        assert_eq!(a.next_deadline(), Some(MonoInstant(21)));
        assert!(a.snapshot().retry_at.is_none());
        // The next original physical attempt can still be outstanding when the
        // absolute lifetime ends. Expiry wipes only candidate keys, and the old
        // output's later actual completion cannot revive them or count a write.
        let prepared = a
            .prepare(a.scope(), abook, MonoInstant(20), &mut wire, entropy)?
            .ok_or(Error::NotReady)?;
        let logical = prepared.attempt();
        let frame = abook.queue_payload(
            logical.route(),
            PeerMessage::decode(prepared.bytes())?,
            MonoInstant(20),
        )?;
        let physical = abook.start(frame)?;
        if let Err(rejected) = a.submit(prepared, abook, physical) {
            return Err(rejected.reason);
        }
        abook.exposed(physical)?;
        assert_eq!(a.tick(a.scope(), MonoInstant(21))?, Event::Expired);
        assert_eq!(a.snapshot().pending, Some(logical));
        // A genuinely new candidate may be admitted while the old physical
        // attempt is still outstanding. Its old completion cannot select or
        // reschedule under this replacement generation.
        a.request(a.scope(), MonoInstant(21), entropy)?;
        let replacement = a.snapshot().candidate;
        assert_ne!(replacement, Some(logical.generation()));
        let completion = abook.settle(physical, false, MonoInstant(22))?;
        a.complete(logical, completion, MonoInstant(22))?;
        abook.release_frame(frame)?;
        abook.neighbor_ready(physical.neighbor(), false)?;
        assert_eq!(a.snapshot().confirmed, working);
        assert_eq!(a.crypto_snapshot(), cipher);
        assert_eq!(a.snapshot().candidate, replacement);
        assert!(a.snapshot().pending.is_none());
        assert!(
            a.prepare(a.scope(), abook, MonoInstant(22), &mut wire, entropy)?
                .is_none()
        );
        assert_eq!(a.next_deadline(), Some(MonoInstant(31)));
        assert_eq!(a.tick(a.scope(), MonoInstant(31))?, Event::Expired);
        assert!(a.snapshot().candidate.is_none());
        assert_eq!(a.snapshot().confirmed, working);
        assert_eq!(a.crypto_snapshot(), cipher);
        Ok(())
    })
}

#[test]
fn retained_unadmitted_keepalive_yields_to_auth_and_confirmed_failed_auth_is_new_original_attempt()
-> Result<(), Error> {
    with_pair(|a, b, abook, bbook, sources, entropy| {
        establish(a, b, abook, bbook, sources, entropy)?;
        let now = 30_000_000;
        let route = abook.select(a.scope().peer()).ok_or(Error::NotReady)?;
        a.keepalive(a.scope(), route, abook, MonoInstant(now))?;
        let mut keepalive = [0; 168];
        let prepared = a
            .prepare(a.scope(), abook, MonoInstant(now), &mut keepalive, entropy)?
            .ok_or(Error::NotReady)?;
        let abandoned = prepared.attempt();
        assert_eq!(abandoned.kind(), Kind::KeepAlive);
        let sent = a.crypto_snapshot().ok_or(Error::NotReady)?.sent;
        assert_eq!(sent, 1);
        a.reject_prepared(prepared)?;
        // A real remote KX_AUTH requests a response while the previous lower
        // priority keepalive was explicitly refused before Book admission.
        let live = b.active.as_ref().ok_or(Error::NotReady)?;
        let mut request = [0; 168];
        let n = live
            .session
            .initial_auth(live.session.scope(), [9; 32], true)?
            .encode(&mut request)?;
        assert_eq!(
            control(a, abook, sources[0], &request[..n], now, entropy)?,
            Event::Duplicate
        );
        let proof = first_proof(a)?;
        let mut wire = [0; 168];
        let prepared = a
            .prepare(a.scope(), abook, MonoInstant(now), &mut wire, entropy)?
            .ok_or(Error::NotReady)?;
        let first = prepared.attempt();
        assert_eq!(first.kind(), Kind::Authentication);
        assert_ne!(first, abandoned);
        assert!(
            matches!(PeerMessage::decode(prepared.bytes())?,PeerMessage::KeyExchangeAuth{auth,..} if auth==proof)
        );
        let frame = abook.queue_payload(
            first.route(),
            PeerMessage::decode(prepared.bytes())?,
            MonoInstant(now),
        )?;
        let physical = abook.start(frame)?;
        if let Err(rejected) = a.submit(prepared, abook, physical) {
            return Err(rejected.reason);
        }
        // Terminal original Unsent, then terminal original Unknown: each needs
        // a new auth attempt even though the key generation is already active.
        let completion = abook.settle(physical, false, MonoInstant(now))?;
        assert_eq!(completion.outcome, connection::Outcome::Unsent);
        a.complete(first, completion, MonoInstant(now))?;
        abook.release_frame(frame)?;
        abook.neighbor_ready(physical.neighbor(), true)?;
        let prepared = a
            .prepare(a.scope(), abook, MonoInstant(now + 1), &mut wire, entropy)?
            .ok_or(Error::NotReady)?;
        let second = prepared.attempt();
        assert_ne!(first, second);
        assert_eq!(second.kind(), Kind::Authentication);
        let frame = abook.queue_payload(
            second.route(),
            PeerMessage::decode(prepared.bytes())?,
            MonoInstant(now + 1),
        )?;
        let physical = abook.start(frame)?;
        if let Err(rejected) = a.submit(prepared, abook, physical) {
            return Err(rejected.reason);
        }
        abook.exposed(physical)?;
        let completion = abook.settle(physical, false, MonoInstant(now + 1))?;
        assert_eq!(completion.outcome, connection::Outcome::Unknown);
        a.complete(second, completion, MonoInstant(now + 1))?;
        abook.release_frame(frame)?;
        abook.neighbor_ready(physical.neighbor(), true)?;
        let prepared = a
            .prepare(a.scope(), abook, MonoInstant(now + 2), &mut wire, entropy)?
            .ok_or(Error::NotReady)?;
        let third = prepared.attempt();
        assert_ne!(third, second);
        assert!(
            matches!(PeerMessage::decode(prepared.bytes())?,PeerMessage::KeyExchangeAuth{auth,..} if auth==proof)
        );
        let frame = abook.queue_payload(
            third.route(),
            PeerMessage::decode(prepared.bytes())?,
            MonoInstant(now + 2),
        )?;
        let physical = abook.start(frame)?;
        if let Err(rejected) = a.submit(prepared, abook, physical) {
            return Err(rejected.reason);
        }
        abook.exposed(physical)?;
        let completion = abook.settle(physical, true, MonoInstant(now + 2))?;
        a.complete(third, completion, MonoInstant(now + 2))?;
        abook.release_frame(frame)?;
        abook.neighbor_ready(physical.neighbor(), true)?;
        assert!(
            a.prepare(a.scope(), abook, MonoInstant(now + 3), &mut wire, entropy)?
                .is_none()
        );
        assert_eq!(a.crypto_snapshot().ok_or(Error::NotReady)?.sent, sent);
        assert!(a.snapshot().retry_at.is_none());
        let mut next = [0; 128];
        let _size = seal(a, &mut next, entropy)?;
        assert_eq!(a.crypto_snapshot().ok_or(Error::NotReady)?.sent, sent + 1);
        Ok(())
    })
}

// Append this one model inside the existing controller/tests.rs module.
#[test]
fn close_refuses_unbound_preview_but_keeps_original_bound_receipt_settleable() -> Result<(), Error>
{
    with_pair(|a, _b, abook, _bbook, _sources, entropy| {
        let scope = a.scope();
        a.request(scope, MonoInstant(0), entropy)?;
        let mut wire = [0; 168];
        let prepared = a
            .prepare(scope, abook, MonoInstant(0), &mut wire, entropy)?
            .ok_or(Error::NotReady)?;
        let logical = prepared.attempt();
        a.close(scope)?;
        assert!(!scope.is_live());
        // This real Book admission is still unexposed. The containing adapter
        // must settle it after Controller refuses the revoked preview.
        let frame = abook.queue_payload(
            logical.route(),
            PeerMessage::decode(prepared.bytes())?,
            MonoInstant(0),
        )?;
        let physical = abook.start(frame)?;
        let rejected = match a.submit(prepared, abook, physical) {
            Err(rejected) => rejected,
            Ok(()) => return Err(Error::Authentication),
        };
        assert_eq!(rejected.reason, Error::Closed);
        a.reject_prepared(rejected.prepared)?;
        assert!(a.snapshot().pending.is_none());
        let completion = abook.settle(physical, false, MonoInstant(1))?;
        assert_eq!(completion.outcome, connection::Outcome::Unsent);
        assert!(!completion.exposed);
        abook.release_frame(frame)?;
        abook.neighbor_ready(physical.neighbor(), true)?;
        assert!(a.snapshot().closed);
        assert!(a.snapshot().candidate.is_none());
        Ok(())
    })?;
    with_pair(|a, _b, abook, _bbook, _sources, entropy| {
        let scope = a.scope();
        a.request(scope, MonoInstant(0), entropy)?;
        let mut wire = [0; 168];
        let prepared = a
            .prepare(scope, abook, MonoInstant(0), &mut wire, entropy)?
            .ok_or(Error::NotReady)?;
        let logical = prepared.attempt();
        let frame = abook.queue_payload(
            logical.route(),
            PeerMessage::decode(prepared.bytes())?,
            MonoInstant(0),
        )?;
        let physical = abook.start(frame)?;
        if let Err(rejected) = a.submit(prepared, abook, physical) {
            return Err(rejected.reason);
        }
        abook.exposed(physical)?;
        a.close(scope)?;
        assert!(!scope.is_live());
        assert!(a.snapshot().pending.is_some());
        // Revocation prevents new admission, while this exact already-bound
        // original physical completion remains consumable once after close.
        let completion = abook.settle(physical, true, MonoInstant(1))?;
        assert_eq!(completion.outcome, connection::Outcome::Written);
        assert!(completion.exposed);
        assert_eq!(
            a.complete(logical, completion, MonoInstant(1))?,
            Event::Idle
        );
        abook.release_frame(frame)?;
        abook.neighbor_ready(physical.neighbor(), true)?;
        assert!(a.snapshot().closed);
        assert!(a.snapshot().pending.is_none());
        assert!(a.snapshot().candidate.is_none());
        assert!(a.snapshot().retry_at.is_none());
        Ok(())
    })
}
