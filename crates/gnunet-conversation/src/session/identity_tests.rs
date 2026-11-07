use super::*;
use gnunet_identity::KeyType;

fn check(value: bool) -> Result<(), Error> {
    if value { Ok(()) } else { Err(Error::Conflict) }
}
fn caller(kind: KeyType) -> Result<SecretKey, Error> {
    let mut bytes = [7; 36];
    bytes[..4].copy_from_slice(&kind.value().to_be_bytes());
    SecretKey::new(bytes)
}
fn ring<'a>(signed: &'a crypto::SignedRing) -> Message<'a> {
    Message::PeerRing {
        reserved: 0,
        expiration: signed.expiration(),
        public_key: signed.public_key(),
        signature: signed.signature(),
    }
}

#[test]
fn identity_cut_keeps_each_incoming_rings_original_target() -> Result<(), Error> {
    for kind in [KeyType::Ecdsa, KeyType::Eddsa] {
        let mut instance = Instance::new();
        let a = Identity::new([1; 32], 1)?;
        let b = Identity::new([2; 32], 1)?;
        let mut s = Session::new(&mut instance, a, Limits::default(), 10)?;
        let port = [9; 64];
        let source = Source::new(3)?;
        s.client_request(
            &a,
            Message::Register {
                reserved: 0,
                port: &port,
            },
            10,
            100,
        )?;
        let open = s.effect().ok_or(Error::NotReady)?.id();
        s.admit_effect(open)?;
        s.attach_port(source)?;
        s.complete_effect(open, Completion::Written, 10)?;
        let old = s.incoming(&a, source, source, [8; 32], 11)?;
        s.rebind_identity(&a, b)?;
        let new = s.incoming(&b, source, source, [8; 32], 12)?;
        let key = caller(kind)?;
        let for_a = crypto::SignedRing::sign(&key, &port, a.peer(), 500)?;
        let for_b = crypto::SignedRing::sign(&key, &port, b.peer(), 500)?;
        check(matches!(
            s.receive(&b, old, source, 0, ring(&for_b), 13, 100),
            Err(Error::Authentication)
        ))?;
        check(matches!(
            s.receive(&b, new, source, 0, ring(&for_a), 13, 100),
            Err(Error::Authentication)
        ))?;
        check(s.pending_effects() == 0)?;
        s.receive(&b, old, source, 0, ring(&for_a), 14, 100)?;
        s.receive(&b, new, source, 0, ring(&for_b), 14, 100)?;
        check(s.phase(old)? == Phase::Ringing && s.phase(new)? == Phase::Ringing)?;
        check(s.cid(old)? != s.cid(new)?)?;
        // Returning to A does not change a channel that was accepted under B.
        let awaiting_b = s.incoming(&b, source, source, [8; 32], 15)?;
        s.rebind_identity(&b, a)?;
        check(matches!(
            s.receive(&a, awaiting_b, source, 0, ring(&for_a), 16, 100),
            Err(Error::Authentication)
        ))?;
        s.receive(&a, awaiting_b, source, 0, ring(&for_b), 16, 100)?;
    }
    Ok(())
}

#[test]
fn identity_cut_keeps_original_admitted_open_ring_bytes_and_bounds() -> Result<(), Error> {
    let mut instance = Instance::new();
    let a = Identity::new([1; 32], 1)?;
    let b = Identity::new([2; 32], 1)?;
    let mut s = Session::new(&mut instance, a, Limits::default(), 10)?;
    let key = caller(KeyType::Eddsa)?;
    let target = [8; 32];
    let port = [9; 64];
    let call = match s.client_request(
        &a,
        Message::Call {
            reserved: 0,
            target: &target,
            port: &port,
            private_key: key.expose_serialized(),
        },
        10,
        100,
    )? {
        RequestOutcome::Calling(id) => id,
        _ => return Err(Error::Conflict),
    };
    let open = s.effect().ok_or(Error::NotReady)?;
    let open_id = open.id();
    let bound = open.deadline();
    s.admit_effect(open_id)?;
    let original_ring = s
        .effects
        .iter()
        .find_map(|e| match &e.action {
            Action::PeerFrame { frame, .. } => Some(frame.clone()),
            _ => None,
        })
        .ok_or(Error::NotReady)?;
    s.rebind_identity(&a, b)?;
    check(s.pending_effects() == 2 && s.call(call)?.opening)?;
    let original_open = s.effect().ok_or(Error::NotReady)?;
    check(
        original_open.id() == open_id
            && original_open.admitted()
            && original_open.deadline() == bound,
    )?;
    check(!s.effect_io_allowed(open_id, &a, 11)? && s.effect_io_allowed(open_id, &b, 11)?)?;
    s.attach_channel(call, Source::new(3)?)?;
    s.complete_effect(open_id, Completion::Written, 12)?;
    let frame = s.effect().ok_or(Error::NotReady)?;
    let id = frame.id();
    let Action::PeerFrame { frame, .. } = frame.action() else {
        return Err(Error::Conflict);
    };
    check(frame == &original_ring)?;
    let Message::PeerRing {
        expiration,
        public_key,
        signature,
        ..
    } = Message::decode(frame)?
    else {
        return Err(Error::Malformed);
    };
    crypto::verify(public_key, signature, &port, &target, expiration, 100)?;
    s.admit_effect(id)?;
    s.complete_effect(id, Completion::Written, 13)?;
    check(s.call(call)?.ring_written && s.phase(call)? == Phase::Calling)
}

#[test]
fn physical_source_replacement_or_closing_cannot_rebind() -> Result<(), Error> {
    let mut instance = Instance::new();
    let a = Identity::new([1; 32], 1)?;
    let mut s = Session::new(&mut instance, a, Limits::default(), 10)?;
    check(matches!(
        s.rebind_identity(&a, Identity::new([2; 32], 2)?),
        Err(Error::StaleGeneration)
    ))?;
    check(s.identity() == a && s.pending_effects() == 0)?;
    s.cancel(Error::Cancelled, 11)?;
    let pending = s.pending_effects();
    check(matches!(
        s.rebind_identity(&a, Identity::new([2; 32], 1)?),
        Err(Error::Closed)
    ))?;
    check(s.identity() == a && s.pending_effects() == pending)
}
