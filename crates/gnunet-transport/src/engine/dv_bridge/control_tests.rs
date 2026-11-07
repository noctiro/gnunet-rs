//! Pure Engine tests of the trusted host delivery port. The admitted ingress
//! below exercises local ownership only; it is not an AEAD/signature grant or
//! an end-to-end BOX acceptance receipt. Purpose35 responses use real signatures.
use super::*;
use alloc::vec;
use gnunet_crypto::EddsaPrivateKey;
use gnunet_wire::official::communicator::{
    Characteristics, Queue as WireQueue, Request as WireRequest,
};

struct Key(EddsaPrivateKey);
impl Signer for Key {
    fn identity(&self) -> PeerId {
        PeerId(*self.0.public_key().as_bytes())
    }
    fn sign_validation(&mut self, region: &[u8; 48]) -> Result<[u8; 64], Error> {
        Ok(*self.0.sign(p2p::CHALLENGE_PURPOSE, region)?.as_bytes())
    }
}
struct Random(u8);
impl Entropy for Random {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        self.0 = self.0.wrapping_add(1);
        out.fill(self.0);
        Ok(())
    }
}
fn check(value: bool) -> Result<(), Error> {
    if value { Ok(()) } else { Err(Error::Conflict) }
}
fn wire(request: WireRequest<'_>) -> Result<Vec<u8>, Error> {
    let mut bytes = vec![0; request.encoded_len()?];
    request.encode(&mut bytes)?;
    Ok(bytes)
}
fn times(now: u64) -> Times {
    Times::new(MonoInstant(now), AbsoluteTime::from_micros(1_000_000 + now))
}
fn response(key: &mut Key, challenge: Challenge, validity: u64) -> Result<Validation, Error> {
    Ok(Validation {
        signature: key.sign_validation(&Validation::signed_region(&challenge.nonce, validity))?,
        nonce: challenge.nonce,
        origin: challenge.origin,
        validity,
    })
}
fn add_queue(
    engine: &mut Engine,
    owner: &ClientId,
    peer: PeerId,
    id: u32,
    length: u64,
    key: &mut Key,
    random: &mut Random,
) -> Result<Challenge, Error> {
    let request = WireRequest::QueueSetup(
        WireQueue {
            id,
            peer: peer.0,
            network: 1,
            mtu: 1024,
            length,
            priority: 0,
            status: 0,
        },
        b"unix-/private/engine-control-test",
    );
    engine.receive(owner, &wire(request)?, 10, key, random)?;
    let mut challenge = None;
    while let Some(output) = engine.output() {
        if let Output::Frame { bytes, .. } = output
            && Frame::decode(&bytes)?.header().message_type().value() == 1209
            && bytes.get(16..48) == Some(peer.0.as_slice())
            && Frame::decode(bytes.get(48..).ok_or(Error::Truncated)?)?
                .header()
                .message_type()
                .value()
                == 1303
        {
            challenge = Some(Challenge::decode(&bytes[48..])?);
        }
    }
    challenge.ok_or(Error::NotFound)
}
struct Harness {
    engine: Engine,
    comm: ClientId,
    core: ClientId,
    local: Key,
    carrier: PeerId,
    remote: Key,
    challenge: Challenge,
    random: Random,
    source: Source,
}
impl Harness {
    fn new() -> Result<Self, Error> {
        Self::with_target_credit(u64::MAX)
    }
    fn with_target_credit(target_credit: u64) -> Result<Self, Error> {
        let mut local = Key(EddsaPrivateKey::from_seed([1; 32]));
        let mut carrier = Key(EddsaPrivateKey::from_seed([2; 32]));
        let remote = Key(EddsaPrivateKey::from_seed([3; 32]));
        let mut random = Random(0);
        let mut engine = Engine::new(local.identity(), Limits::default())?;
        let comm = engine.accept()?;
        let core = engine.accept()?;
        engine.receive(
            &comm,
            &wire(WireRequest::Register {
                characteristics: Characteristics::Reliable,
                can_burst: false,
                prefix: b"unix",
            })?,
            10,
            &mut local,
            &mut random,
        )?;
        let mut start = [0; 40];
        CoreRequest::Start(gnunet_client::transport::Start::new(
            Some(local.identity()),
            true,
        ))
        .encode(&mut start)?;
        engine.receive(&core, &start, 10, &mut local, &mut random)?;
        let challenge = add_queue(
            &mut engine,
            &comm,
            carrier.identity(),
            1,
            u64::MAX,
            &mut local,
            &mut random,
        )?;
        let signed = response(&mut carrier, challenge, 1_000_000)?.encode();
        engine.receive(
            &comm,
            &wire(WireRequest::Incoming {
                flow_control: false,
                flow_id: [0; 8],
                validity: 1_000_000,
                peer: carrier.identity().0,
                neighbour: [0; 32],
                message: &signed,
            })?,
            10,
            &mut local,
            &mut random,
        )?;
        let challenge = add_queue(
            &mut engine,
            &comm,
            remote.identity(),
            2,
            target_credit,
            &mut local,
            &mut random,
        )?;
        let source = engine.dv_attach_source(local.identity())?;
        Ok(Self {
            engine,
            comm,
            core,
            local,
            carrier: carrier.identity(),
            remote,
            challenge,
            random,
            source,
        })
    }
    fn port(&mut self, peer: PeerId, input: &[u8], now: u64) -> Result<Delivery, Error> {
        // This header reserves only the production Engine's physical-ingress
        // record. This pure test assumes its caller's separate authentication;
        // no cryptographic BOX acceptance is manufactured by the helper.
        let outer = message(dv::BOX_TYPE, 4)?;
        let incoming = wire(WireRequest::Incoming {
            flow_control: false,
            flow_id: [0; 8],
            validity: 1_000_000,
            peer: self.carrier.0,
            neighbour: [0; 32],
            message: &outer,
        })?;
        let original = self
            .engine
            .dv_prepare_incoming(&self.source, &self.comm, &incoming, times(now))?
            .origin;
        let id = original.id();
        self.engine.dv_input_admitted(&id)?;
        let result = self
            .engine
            .dv_deliver(&id, peer, input, times(now), &mut self.local);
        self.engine
            .dv_finish_incoming(original)
            .map_err(|refused| refused.reason)?;
        result
    }
    fn payloads(&mut self) -> Result<usize, Error> {
        let mut count = 0;
        while let Some(output) = self.engine.output() {
            if let Output::Frame { client, bytes } = output
                && client == self.core
                && Frame::decode(&bytes)?.header().message_type().value() == 365
            {
                count += 1;
            }
        }
        Ok(count)
    }
}
fn reliable(inner: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = vec![0; 24 + inner.len()];
    p2p::Reliable {
        countdown: 0,
        uuid: [7; 16],
        message: inner,
    }
    .encode(&mut out)?;
    Ok(out)
}

#[test]
fn raw_native_bounds_and_fc_survive_duplicates_held_inbox_and_refusal_reset() -> Result<(), Error> {
    let mut h = Harness::new()?;
    // Use the existing two bounded owners, not a test-only staging queue.
    h.engine.limits.messages = 1;
    let outer = message(dv::BOX_TYPE, 4)?;
    let first = wire(WireRequest::Incoming {
        flow_control: true,
        flow_id: [1; 8],
        validity: 1_000_000,
        peer: h.carrier.0,
        neighbour: [0; 32],
        message: &outer,
    })?;
    let second = wire(WireRequest::Incoming {
        flow_control: true,
        flow_id: [2; 8],
        validity: 1_000_000,
        peer: h.carrier.0,
        neighbour: [0; 32],
        message: &outer,
    })?;
    let absolute_until = AbsoluteTime::from_micros(1_000_080);
    for bytes in [&first, &second] {
        h.engine.receive_dv_at(
            NativeInput {
                source: &h.source,
                owner: &h.comm,
                bytes,
                until: MonoInstant(70),
                absolute_until,
            },
            times(10),
            &mut h.local,
            &mut h.random,
        )?;
    }
    check(
        h.engine.dv_inbox().is_some()
            && h.engine.dv_bridge.ingresses.len() == 1
            && h.engine.held.len() == 1,
    )?;
    check(h.engine.dv_source_debts(&h.source) == 2)?;
    // The second token currently lives only in Held, the first in Inbox. Both
    // must reject a duplicate before time/owner/bounds or FC can change.
    for bytes in [&first, &second] {
        check(matches!(
            h.engine.receive_dv_at(
                NativeInput {
                    source: &h.source,
                    owner: &h.comm,
                    bytes,
                    until: MonoInstant(100),
                    absolute_until: AbsoluteTime::from_micros(1_000_100),
                },
                times(11),
                &mut h.local,
                &mut h.random,
            ),
            Err(Error::Conflict)
        ))?;
    }
    check(h.engine.monotonic_now() == MonoInstant(10))?;
    check(h.engine.dv_source_debts(&h.source) == 2 && h.engine.buffered == 8)?;
    // Merely retaining either original must not acknowledge its communicator.
    check(h.engine.output().is_none())?;
    let first_id = h.engine.dv_inbox().ok_or(Error::NotFound)?.id;
    check(h.engine.dv_drop_inbox(&first_id)? == IngressEnd::AckQueued)?;
    let Some(Output::Frame { client, bytes }) = h.engine.output() else {
        return Err(Error::NotFound);
    };
    check(client == h.comm && bytes.get(8..16) == Some([1; 8].as_slice()))?;
    h.engine.pump_held()?;
    check(h.engine.held.is_empty())?;
    let packet = h.engine.dv_inbox().ok_or(Error::NotFound)?;
    check(packet.until == MonoInstant(70) && packet.absolute_until == Some(absolute_until))?;
    check(packet.bytes == outer && packet.id.source() == &h.source)?;
    let old = packet.id;
    let original = h.engine.dv_claim_inbox(&old)?;
    let current = h.engine.dv_reset_inbox(&old)?;
    check(current.serial != old.serial)?;
    let packet = h.engine.dv_inbox_get(&current)?;
    check(packet.until == MonoInstant(70) && packet.absolute_until == Some(absolute_until))?;
    let refused = h
        .engine
        .dv_finish_incoming(original)
        .err()
        .ok_or(Error::Conflict)?;
    check(refused.reason == Error::Stale && h.engine.output().is_none())?;
    check(h.engine.dv_drop_inbox(&current)? == IngressEnd::AckQueued)?;
    let Some(Output::Frame { client, bytes }) = h.engine.output() else {
        return Err(Error::NotFound);
    };
    check(client == h.comm && bytes.get(8..16) == Some([2; 8].as_slice()))?;
    check(h.engine.dv_source_debts(&h.source) == 0 && h.engine.buffered == 0)
}

#[test]
fn raw_native_input_rejects_expired_unbounded_and_replaced_source_before_effects()
-> Result<(), Error> {
    let mut h = Harness::new()?;
    let outer = message(dv::BOX_TYPE, 4)?;
    let bytes = wire(WireRequest::Incoming {
        flow_control: true,
        flow_id: [3; 8],
        validity: 1_000_000,
        peer: h.carrier.0,
        neighbour: [0; 32],
        message: &outer,
    })?;
    for (until, absolute_until) in [
        (10, 1_000_100),
        (u64::MAX, 1_000_100),
        (100, 1_000_010),
        (100, u64::MAX),
    ] {
        check(matches!(
            h.engine.receive_dv_at(
                NativeInput {
                    source: &h.source,
                    owner: &h.comm,
                    bytes: &bytes,
                    until: MonoInstant(until),
                    absolute_until: AbsoluteTime::from_micros(absolute_until),
                },
                times(10),
                &mut h.local,
                &mut h.random,
            ),
            Err(Error::Deadline)
        ))?;
    }
    check(h.engine.dv_source_debts(&h.source) == 0 && h.engine.output().is_none())?;
    h.engine.dv_begin_retire_source(&h.source)?;
    h.engine.dv_retire_source(&h.source)?;
    let replacement = h.engine.dv_attach_source(h.local.identity())?;
    check(matches!(
        h.engine.receive_dv_at(
            NativeInput {
                source: &h.source,
                owner: &h.comm,
                bytes: &bytes,
                until: MonoInstant(100),
                absolute_until: AbsoluteTime::from_micros(1_000_100),
            },
            times(11),
            &mut h.local,
            &mut h.random,
        ),
        Err(Error::Stale)
    ))?;
    check(
        h.engine.monotonic_now() == MonoInstant(10) && h.engine.dv_source_debts(&replacement) == 0,
    )
}

#[test]
fn ordinary_outer_reliable_dv_keeps_original_scheduling_only_bound() -> Result<(), Error> {
    let mut h = Harness::new()?;
    let outer = reliable(&message(dv::BOX_TYPE, 4)?)?;
    h.engine.receive_at(
        &h.comm,
        &wire(WireRequest::Incoming {
            flow_control: false,
            flow_id: [0; 8],
            validity: 1_000_000,
            peer: h.carrier.0,
            neighbour: [0; 32],
            message: &outer,
        })?,
        times(10),
        &mut h.local,
        &mut h.random,
    )?;
    let packet = h.engine.dv_inbox().ok_or(Error::NotFound)?;
    check(
        packet.absolute_until.is_none()
            && packet.until == MonoInstant(10 + crate::fragment::EXPIRY),
    )
}

#[test]
fn boxed_response_preserves_real_signature_nonce_origin_and_original_queue() -> Result<(), Error> {
    let mut h = Harness::new()?;
    let peer = h.remote.identity();
    let valid = response(&mut h.remote, h.challenge, 1_000_000)?;
    let mut bad_signature = valid;
    bad_signature.signature[0] ^= 1;
    check(matches!(
        h.port(peer, &bad_signature.encode(), 10),
        Err(Error::Authentication)
    ))?;
    let mut wrong_nonce = valid;
    wrong_nonce.nonce[0] ^= 1;
    wrong_nonce.signature = h.remote.sign_validation(&Validation::signed_region(
        &wrong_nonce.nonce,
        wrong_nonce.validity,
    ))?;
    check(matches!(
        h.port(peer, &wrong_nonce.encode(), 10),
        Err(Error::Replay)
    ))?;
    let mut wrong_origin = valid;
    wrong_origin.origin = 9;
    check(matches!(
        h.port(peer, &wrong_origin.encode(), 10),
        Err(Error::Replay)
    ))?;
    check(h.engine.snapshot().validations == 1 && !h.engine.dv_bridge.has_peer(peer, 10))?;

    h.engine.receive(
        &h.comm,
        &wire(WireRequest::QueueDown(2, peer.0))?,
        10,
        &mut h.local,
        &mut h.random,
    )?;
    let replacement = add_queue(
        &mut h.engine,
        &h.comm,
        peer,
        3,
        u64::MAX,
        &mut h.local,
        &mut h.random,
    )?;
    check(matches!(
        h.port(peer, &valid.encode(), 10),
        Err(Error::Replay)
    ))?;
    let valid = response(&mut h.remote, replacement, 1_000_000)?;
    check(h.port(peer, &valid.encode(), 10)? == Delivery::Accepted)?;
    check(h.engine.snapshot().validations == 2 && h.engine.snapshot().connected == 2)?;
    check(
        h.engine
            .routes
            .iter()
            .any(|route| route.description.id == 3 && route.valid_until > 10),
    )?;
    check(!h.engine.dv_bridge.has_peer(peer, 10) && h.payloads()? == 0)
}

#[test]
fn boxed_control_without_reverse_route_does_not_authorize_core_payload() -> Result<(), Error> {
    let mut h = Harness::new()?;
    let peer = h.remote.identity();
    let flow = Flow {
        sequence: 1,
        inbound_window: p2p::DEFAULT_WINDOW,
        outbound_sent: 0,
        outbound_window: p2p::DEFAULT_WINDOW,
        sender_time: 12,
        rtt: 0,
        sync_ready: false,
    }
    .encode();
    check(h.port(peer, &flow, 12)? == Delivery::Accepted)?;
    let mut ack = [0; 32];
    p2p::encode_acknowledgements(1, &[(0, [8; 16])], &mut ack)?;
    check(h.port(peer, &ack, 12)? == Delivery::Accepted)?;
    check(h.port(h.carrier, &flow, 12)? == Delivery::Accepted)?;
    check(h.port(peer, &reliable(&flow)?, 12)? == Delivery::Accepted)?;
    check(
        h.engine
            .peers
            .iter()
            .any(|row| row.id == peer && row.remote_time == 12 && !row.connected),
    )?;
    check(!h.engine.dv_bridge.has_peer(peer, 12))?;
    let payload = message(64, 4)?;
    check(matches!(h.port(peer, &payload, 12), Err(Error::NotReady)))?;
    check(matches!(
        h.port(peer, &reliable(&payload)?, 12),
        Err(Error::NotReady)
    ))?;
    check(matches!(
        h.port(peer, &h.challenge.encode(), 12),
        Err(Error::Unsupported)
    ))?;
    check(matches!(
        h.port(peer, &reliable(&h.challenge.encode())?, 12),
        Err(Error::Unsupported)
    ))?;
    check(h.payloads()? == 0)?;
    // A currently validated direct route needs no duplicate DV virtual entry.
    check(h.port(h.carrier, &payload, 12)? == Delivery::Accepted)?;
    check(h.payloads()? == 1)
}

#[test]
fn expired_routes_block_reliable_and_completed_fragment_payloads() -> Result<(), Error> {
    let mut h = Harness::new()?;
    let peer = h.remote.identity();
    let valid = response(&mut h.remote, h.challenge, 10)?.encode();
    check(h.port(peer, &valid, 10)? == Delivery::Accepted)?;
    let payload = message(64, 8)?;
    let mut first = [0; 36];
    p2p::Fragment {
        offset: 0,
        total: 8,
        ack: [1; 16],
        message_id: [4; 8],
        body: &payload[..4],
    }
    .encode(&mut first)?;
    check(h.port(peer, &first, 11)? == Delivery::Accepted)?;
    let mut last = [0; 36];
    p2p::Fragment {
        offset: 4,
        total: 8,
        ack: [2; 16],
        message_id: [4; 8],
        body: &payload[4..],
    }
    .encode(&mut last)?;
    // No maintenance tick has refreshed this old connected bool: the final
    // delivery boundary must check the actual route expiration itself.
    check(
        h.engine
            .peers
            .iter()
            .any(|row| row.id == peer && row.connected),
    )?;
    check(matches!(h.port(peer, &last, 21), Err(Error::NotReady)))?;
    check(h.engine.assemblies.is_empty())?;
    check(matches!(
        h.port(peer, &reliable(&payload)?, 21),
        Err(Error::NotReady)
    ))?;
    check(matches!(h.port(peer, &payload, 21), Err(Error::NotReady)))?;
    check(h.payloads()? == 0)?;

    let virtual_peer = PeerId([4; 32]);
    h.engine.dv_virtual_peer(
        &h.source,
        virtual_peer,
        gnunet_types::Duration(2),
        times(21),
    )?;
    check(matches!(
        h.port(virtual_peer, &payload, 24),
        Err(Error::NotReady)
    ))?;
    check(h.payloads()? == 0)
}

#[test]
fn restored_credit_preserves_successfully_validated_route_schedule() -> Result<(), Error> {
    let mut h = Harness::with_target_credit(1)?;
    let peer = h.remote.identity();
    // The actual initial challenge used the queue's only packet grant. Its
    // genuine signed response validates this route for the ordinary four hours.
    check(
        h.engine.routes.iter().any(|route| {
            route.description.peer == peer && !route.unlimited && route.available == 0
        }),
    )?;
    let signed = response(&mut h.remote, h.challenge, p2p::VALIDATION_INTERVAL)?.encode();
    check(h.port(peer, &signed, 10)? == Delivery::Accepted)?;
    let route = h
        .engine
        .routes
        .iter()
        .find(|route| route.description.peer == peer)
        .ok_or(Error::NotFound)?;
    let next = route.challenge_next;
    let monitor = route.monitor_next_validation;
    check(!route.challenge_pending && route.valid_until > 10 + RETRY && next > 10 + RETRY)?;

    h.engine.receive_at(
        &h.comm,
        &wire(WireRequest::QueueUpdate(WireQueue {
            id: 2,
            peer: peer.0,
            network: 1,
            mtu: 1024,
            length: 1,
            priority: 0,
            status: 0,
        }))?,
        times(11),
        &mut h.local,
        &mut h.random,
    )?;
    let route = h
        .engine
        .routes
        .iter()
        .find(|route| route.description.peer == peer)
        .ok_or(Error::NotFound)?;
    check(route.challenge_next == next && route.monitor_next_validation == monitor)?;

    h.engine.tick_at(times(10 + RETRY), &mut h.random)?;
    while let Some(output) = h.engine.output() {
        if let Output::Frame { bytes, .. } = output
            && Frame::decode(&bytes)?.header().message_type().value() == 1209
            && bytes.get(16..48) == Some(peer.0.as_slice())
        {
            check(
                Frame::decode(bytes.get(48..).ok_or(Error::Truncated)?)?
                    .header()
                    .message_type()
                    .value()
                    != 1303,
            )?;
        }
    }
    let route = h
        .engine
        .routes
        .iter()
        .find(|route| route.description.peer == peer)
        .ok_or(Error::NotFound)?;
    check(
        !route.challenge_pending
            && route.challenge_next == next
            && route.monitor_next_validation == monitor,
    )
}
