use super::*;
fn check(value: bool) -> Result<(), Error> {
    if value { Ok(()) } else { Err(Error::Malformed) }
}
fn identity() -> Result<Identity, Error> {
    Identity::new([7; 32], 1)
}
#[test]
fn port_written_needs_actual_source_and_incoming_keeps_that_source() -> Result<(), Error> {
    let mut instance = Instance::new();
    let identity = identity()?;
    let mut s = Session::new(&mut instance, identity, Limits::default(), 10)?;
    let port = [9; 64];
    s.client_request(
        &identity,
        Message::Register {
            reserved: 0,
            port: &port,
        },
        10,
        100,
    )?;
    let effect = s.effect().ok_or(Error::NotReady)?.id();
    s.admit_effect(effect)?;
    check(matches!(
        s.complete_effect(effect, Completion::Processed, 11),
        Err(Error::InvalidInput)
    ))?;
    check(matches!(
        s.complete_effect(effect, Completion::Written, 11),
        Err(Error::NotReady)
    ))?;
    let source = Source::new(10)?;
    s.attach_port(source)?;
    let terminal = s.complete_effect(effect, Completion::Written, 11)?;
    check(terminal.completion == Completion::Written)?;
    check(matches!(
        s.incoming(&identity, Source::new(11)?, source, [8; 32], 12),
        Err(Error::NotReady)
    ))?;
    let call = s.incoming(&identity, source, source, [8; 32], 12)?;
    check(s.phase(call)? == Phase::AwaitRing)?;
    check(matches!(
        s.receive(
            &identity,
            call,
            Source::new(11)?,
            0,
            Message::PeerAudio(&[]),
            12,
            100
        ),
        Err(Error::StaleGeneration)
    ))?;
    check(matches!(
        s.receive(
            &identity,
            call,
            source,
            0,
            Message::PeerControl(PeerControl::PickUp),
            12,
            100
        ),
        Err(Error::Malformed)
    ))?;
    check(s.phase(call)? == Phase::AwaitRing)
}
#[test]
fn cancellation_retains_admitted_write_and_requires_actual_cleanup() -> Result<(), Error> {
    let mut instance = Instance::new();
    let identity = identity()?;
    let mut s = Session::new(&mut instance, identity, Limits::default(), 10)?;
    let port = [9; 64];
    s.client_request(
        &identity,
        Message::Register {
            reserved: 0,
            port: &port,
        },
        10,
        100,
    )?;
    let id = s.effect().ok_or(Error::NotReady)?.id();
    s.admit_effect(id)?;
    s.attach_port(Source::new(10)?)?;
    s.cancel(Error::Cancelled, 11)?;
    check(!s.effect_io_allowed(id, &identity, 11)? && !s.is_quiescent())?;
    let terminal = s.complete_effect(id, Completion::Written, 11)?;
    check(terminal.completion == Completion::Written && !s.port_ready)?;
    let close_port = s.effect().ok_or(Error::NotReady)?.id();
    s.admit_effect(close_port)?;
    s.complete_effect(close_port, Completion::Written, 12)?;
    check(!s.is_quiescent())?;
    let close_client = s.effect().ok_or(Error::NotReady)?.id();
    s.admit_effect(close_client)?;
    s.complete_effect(close_client, Completion::Written, 12)?;
    check(s.is_quiescent())
}
#[test]
fn idle_does_not_mint_work_and_wrong_identity_does_not_write() -> Result<(), Error> {
    let mut instance = Instance::new();
    let identity = identity()?;
    let mut s = Session::new(&mut instance, identity, Limits::default(), 10)?;
    check(!s.progress(11)? && s.effect().is_none())?;
    s.tick(12)?;
    check(s.effect().is_none())?;
    let port = [9; 64];
    s.client_request(
        &identity,
        Message::Register {
            reserved: 0,
            port: &port,
        },
        12,
        100,
    )?;
    let id = s.effect().ok_or(Error::NotReady)?.id();
    check(!s.effect_io_allowed(id, &Identity::new(*identity.peer(), 2)?, 12)?)?;
    check(matches!(
        s.client_request(
            &Identity::new(*identity.peer(), 2)?,
            Message::Control {
                action: ClientControl::HangUp,
                cid: 0
            },
            12,
            100
        ),
        Err(Error::StaleGeneration)
    ))
}
#[test]
fn bounded_scan_isolates_channel_backpressure_and_freezes_its_round() -> Result<(), Error> {
    let mut instance = Instance::new();
    let identity = identity()?;
    let mut s = Session::new(&mut instance, identity, Limits::default(), 10)?;
    let port = [9; 64];
    s.client_request(
        &identity,
        Message::Register {
            reserved: 0,
            port: &port,
        },
        10,
        100,
    )?;
    let open = s.effect().ok_or(Error::NotReady)?.id();
    s.admit_effect(open)?;
    let source = Source::new(10)?;
    s.attach_port(source)?;
    s.complete_effect(open, Completion::Written, 11)?;
    let a = s.incoming(&identity, source, source, [1; 32], 12)?;
    let b = s.incoming(&identity, source, source, [2; 32], 12)?;
    // Only scheduling is under test. Typed Ring authentication is not bypassed
    // in production; these private states model two already accepted calls.
    s.call_mut(a)?.phase = Phase::Connected;
    s.call_mut(b)?.phase = Phase::Connected;
    s.client_request(
        &identity,
        Message::Audio {
            cid: s.cid(a)?,
            data: &[1],
        },
        13,
        100,
    )?;
    let first = s.effect().ok_or(Error::NotReady)?.id();
    s.admit_effect(first)?;
    s.client_request(
        &identity,
        Message::Audio {
            cid: s.cid(b)?,
            data: &[2],
        },
        13,
        100,
    )?;
    let mut scan = EffectScan::new();
    check(matches!(
        s.scan_effect(&mut scan, 1)?,
        EffectScanStep::Pending
    ))?;
    let second = match s.scan_effect(&mut scan, 1)? {
        EffectScanStep::Ready(e) => e.id(),
        _ => return Err(Error::NotReady),
    };
    s.admit_effect(second)?;
    s.client_request(
        &identity,
        Message::Audio {
            cid: s.cid(b)?,
            data: &[3],
        },
        13,
        100,
    )?;
    check(matches!(s.scan_effect(&mut scan, 1)?, EffectScanStep::End))?;
    check(matches!(s.scan_effect(&mut scan, 1)?, EffectScanStep::End))?;
    s.complete_effect(second, Completion::Written, 14)?;
    scan.reset();
    let mut saw = false;
    for _ in 0..3 {
        if let EffectScanStep::Ready(e) = s.scan_effect(&mut scan, 1)? {
            saw = e.action().call() == Some(b);
            break;
        }
    }
    check(saw)
}
#[test]
fn cancelled_unstarted_port_does_not_require_an_invented_write() -> Result<(), Error> {
    let mut instance = Instance::new();
    let identity = identity()?;
    let mut s = Session::new(&mut instance, identity, Limits::default(), 10)?;
    let port = [9; 64];
    s.client_request(
        &identity,
        Message::Register {
            reserved: 0,
            port: &port,
        },
        10,
        100,
    )?;
    s.cancel(Error::Cancelled, 11)?;
    let original = s.effect().ok_or(Error::NotReady)?.id();
    s.complete_effect(original, Completion::Unsent(Error::Cancelled), 11)?;
    let close = s.effect().ok_or(Error::NotReady)?.id();
    s.complete_effect(close, Completion::Unsent(Error::Closed), 11)?;
    check(!s.is_quiescent())?;
    let local = s.effect().ok_or(Error::NotReady)?.id();
    s.admit_effect(local)?;
    s.complete_effect(local, Completion::Written, 11)?;
    check(s.is_quiescent())
}
#[test]
fn equal_serials_from_independent_instances_cannot_cross_lines() -> Result<(), Error> {
    let mut instance_a = Instance::new();
    let mut instance_b = Instance::new();
    let identity = identity()?;
    let mut a = Session::new(&mut instance_a, identity, Limits::default(), 10)?;
    let mut b = Session::new(&mut instance_b, identity, Limits::default(), 10)?;
    let port = [9; 64];
    a.client_request(
        &identity,
        Message::Register {
            reserved: 0,
            port: &port,
        },
        10,
        100,
    )?;
    b.client_request(
        &identity,
        Message::Register {
            reserved: 0,
            port: &port,
        },
        10,
        100,
    )?;
    let ea = a.effect().ok_or(Error::NotReady)?.id();
    let eb = b.effect().ok_or(Error::NotReady)?.id();
    check(ea.value() == eb.value() && ea != eb)?;
    check(matches!(b.admit_effect(ea), Err(Error::StaleGeneration)))?;
    check(matches!(
        b.complete_effect(ea, Completion::Unsent(Error::Closed), 11),
        Err(Error::StaleGeneration)
    ))?;
    let source = Source::new(10)?;
    a.attach_port(source)?;
    b.attach_port(source)?;
    a.admit_effect(ea)?;
    b.admit_effect(eb)?;
    a.complete_effect(ea, Completion::Written, 11)?;
    b.complete_effect(eb, Completion::Written, 11)?;
    let ca = a.incoming(&identity, source, source, [1; 32], 12)?;
    let cb = b.incoming(&identity, source, source, [1; 32], 12)?;
    check(ca.value() == cb.value() && ca != cb)?;
    check(matches!(b.phase(ca), Err(Error::StaleGeneration)))?;
    check(matches!(
        b.peer_lost(ca, source, Error::Closed),
        Err(Error::StaleGeneration)
    ))?;
    check(b.phase(cb)? == Phase::AwaitRing)
}
