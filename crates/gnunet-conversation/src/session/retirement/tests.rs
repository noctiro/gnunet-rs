//! Public core transcripts with scripted local receipts; no native IO or C peer credit.
use super::*;
use crate::{Completion, Identity, Instance, Limits, RequestOutcome, crypto, wire::PeerControl};
use gnunet_identity::{KeyType, SecretKey};

fn check(value: bool) -> Result<(), Error> {
    if value { Ok(()) } else { Err(Error::Conflict) }
}
fn key() -> Result<SecretKey, Error> {
    let mut bytes = [7; 36];
    bytes[..4].copy_from_slice(&KeyType::Eddsa.value().to_be_bytes());
    SecretKey::new(bytes)
}

#[test]
fn cancelled_admitted_frames_have_only_bounded_drain_permission() -> Result<(), Error> {
    for write_timeout in [20, 100] {
        let mut instance = Instance::new();
        let (mut session, identity, call, source) = calling(
            &mut instance,
            Limits {
                write_timeout,
                ..limits()
            },
        )?;
        connect(&mut session, identity, call, source)?;
        session.client_request(&identity, Message::Audio { cid: 0, data: &[1] }, 16, 1002)?;
        let original = session.effect().ok_or(Error::NotReady)?.id();
        session.admit_effect(original)?;
        session.client_request(
            &identity,
            Message::Control {
                action: ClientControl::HangUp,
                cid: 0,
            },
            17,
            1003,
        )?;
        check(
            session.effect_cancelled(original)?
                && !session.effect_io_allowed(original, &identity, 18)?,
        )?;
        check(session.effect_drain_allowed(original, &identity, 18)?)?;
        let until = (16 + write_timeout).min(17 + limits().close_timeout);
        check(!session.effect_drain_allowed(original, &identity, until)?)?;
        session.complete_effect(original, Completion::Written, 18)?;
        let (report, notices) = retired(&mut session, call, 19)?;
        check(
            notices == 0
                && report.reason == EndReason::LocalHangUp
                && report.failure.is_none()
                && report.local_hangup_written
                && !report.remote_hangup,
        )?;
    }
    Ok(())
}

#[test]
fn new_audio_supersedes_only_an_unadmitted_tail_and_expires_without_hangup() -> Result<(), Error> {
    let mut instance = Instance::new();
    let (mut session, identity, call, source) = calling(&mut instance, limits())?;
    connect(&mut session, identity, call, source)?;
    session.client_request(&identity, Message::Audio { cid: 0, data: &[1] }, 16, 1002)?;
    let original = session.effect().ok_or(Error::NotReady)?.id();
    session.admit_effect(original)?;
    session.client_request(&identity, Message::Audio { cid: 0, data: &[2] }, 17, 1003)?;
    let superseded = session.effects.back().ok_or(Error::NotReady)?.id();
    session.client_request(&identity, Message::Audio { cid: 0, data: &[3] }, 18, 1004)?;
    check(session.pending_effects() == 2)?;
    check(session.effect_cancelled(superseded) == Err(Error::StaleGeneration))?;
    let latest = session.effects.back().ok_or(Error::NotReady)?.id();
    check(latest != original && latest != superseded)?;
    check(session.admit_effect(latest) == Err(Error::NotReady))?;
    let terminal = session.complete_effect(original, Completion::Written, 19)?;
    check(matches!(terminal.action, Action::PeerFrame { frame, .. }
        if matches!(Message::decode(&frame), Ok(Message::PeerAudio(&[1])))))?;
    let queued = session.effect().ok_or(Error::NotReady)?;
    check(matches!(queued.action(), Action::PeerFrame { frame, .. }
        if matches!(Message::decode(frame), Ok(Message::PeerAudio(&[3])))))?;
    let deadline = queued.deadline();
    session.tick(deadline)?;
    check(session.pending_effects() == 0 && session.phase(call)? == Phase::Connected)?;
    check(session.failure().is_none())?;
    session.client_request(
        &identity,
        Message::Control {
            action: ClientControl::HangUp,
            cid: 0,
        },
        deadline,
        1005,
    )?;
    let (report, notices) = retired(&mut session, call, deadline + 1)?;
    check(notices == 0 && report.reason == EndReason::LocalHangUp && report.failure.is_none())
}

#[test]
fn congested_audio_cannot_replace_peer_controls_or_block_local_input() -> Result<(), Error> {
    let mut instance = Instance::new();
    let (mut session, identity, call, source) = calling(
        &mut instance,
        Limits {
            effects: 3,
            ..limits()
        },
    )?;
    connect(&mut session, identity, call, source)?;
    session.client_request(&identity, Message::Audio { cid: 0, data: &[1] }, 16, 1002)?;
    let first = session.effect().ok_or(Error::NotReady)?.id();
    session.admit_effect(first)?;
    for (now, action) in [(17, ClientControl::Suspend), (18, ClientControl::Resume)] {
        session.client_request(&identity, Message::Control { action, cid: 0 }, now, 1002)?;
    }
    check(
        session.client_request(&identity, Message::Audio { cid: 0, data: &[2] }, 19, 1002)?
            == RequestOutcome::Ignored,
    )?;
    check(session.pending_effects() == 3 && session.phase(call)? == Phase::Connected)?;
    session.complete_effect(first, Completion::Written, 20)?;
    for expected in [PeerControl::Suspend, PeerControl::Resume] {
        let next = session.effect().ok_or(Error::NotReady)?;
        check(matches!(next.action(), Action::PeerFrame { frame, .. }
            if matches!(Message::decode(frame), Ok(Message::PeerControl(actual)) if actual == expected)))?;
        let next = next.id();
        session.admit_effect(next)?;
        session.complete_effect(next, Completion::Written, 20)?;
    }
    check(session.pending_effects() == 0 && session.failure().is_none())
}

#[test]
fn cancelled_unwritten_channel_creation_retires_without_a_peer_failure() -> Result<(), Error> {
    let mut instance = Instance::new();
    let identity = Identity::new([1; 32], 1)?;
    let mut session = Session::new(&mut instance, identity, limits(), 10)?;
    let call = match session.client_request(
        &identity,
        Message::Call {
            reserved: 0,
            target: &[2; 32],
            port: &[9; 64],
            private_key: key()?.expose_serialized(),
        },
        10,
        1000,
    )? {
        RequestOutcome::Calling(call) => call,
        _ => return Err(Error::Conflict),
    };
    session.attach_channel(call, Source::new(3)?)?;
    let open = session.effect().ok_or(Error::NotReady)?.id();
    session.admit_effect(open)?;
    session.client_request(
        &identity,
        Message::Control {
            action: ClientControl::HangUp,
            cid: 0,
        },
        11,
        1001,
    )?;
    // Script the actual host's completed native rollback, not source failure.
    session.complete_effect(open, Completion::Unsent(Error::Cancelled), 12)?;
    let (report, notices) = retired(&mut session, call, 13)?;
    check(
        notices == 0
            && report.reason == EndReason::LocalHangUp
            && report.failure.is_none()
            && !report.ring_written
            && !report.local_hangup_written
            && session.failure().is_none(),
    )
}

#[test]
fn transport_replacement_preserves_the_listener_and_retires_a_partial_open() -> Result<(), Error> {
    for already_written in [false, true] {
        let mut instance = Instance::new();
        let identity = Identity::new([1; 32], 1)?;
        let mut session = Session::new(&mut instance, identity, limits(), 10)?;
        let port = [9; 64];
        session.client_request(
            &identity,
            Message::Register {
                reserved: 0,
                port: &port,
            },
            10,
            1000,
        )?;
        let open = session.effect().ok_or(Error::NotReady)?.id();
        let original = Source::new(3)?;
        let replacement = Source::new(4)?;
        session.attach_port(original)?;
        session.admit_effect(open)?;
        if already_written {
            session.complete_effect(open, Completion::Written, 11)?;
        }
        session.transport_lost(original, Error::Closed, None)?;
        if !already_written {
            check(session.restore_port(original, replacement) == Err(Error::NotReady))?;
            session.complete_effect(
                open,
                Completion::Lost {
                    reason: Error::Closed,
                    exposed: true,
                },
                12,
            )?;
        }
        check(session.failure().is_none())?;
        check(matches!(
            session.incoming(&identity, original, original, [2; 32], 13),
            Err(Error::NotReady)
        ))?;
        check(session.restore_port(original, original) == Err(Error::NotReady))?;
        session.restore_port(original, replacement)?;
        check(matches!(
            session.incoming(&identity, original, original, [2; 32], 14),
            Err(Error::NotReady)
        ))?;
        session.incoming(&identity, replacement, replacement, [2; 32], 14)?;
    }
    Ok(())
}

#[test]
fn transport_loss_finishes_the_admitted_local_frame_before_its_hangup() -> Result<(), Error> {
    let mut instance = Instance::new();
    let (mut session, identity, call, source) = calling(&mut instance, limits())?;
    connect(&mut session, identity, call, source)?;
    session.receive(
        &identity,
        call,
        source,
        1,
        Message::PeerAudio(&[1, 2]),
        16,
        1002,
    )?;
    let local = session.effect().ok_or(Error::NotReady)?.id();
    session.admit_effect(local)?;
    session.transport_lost(source, Error::Closed, Some(local))?;
    check(session.effect_io_allowed(local, &identity, 17)?)?;
    session.complete_effect(local, Completion::Written, 17)?;
    session.progress(17)?;
    let (report, notices) = retired(&mut session, call, 18)?;
    check(
        notices == 1
            && report.failure == Some(Error::Closed)
            && !report.remote_hangup
            && session.failure().is_none(),
    )
}

#[test]
fn source_loss_preserves_an_unsubmitted_local_ring_before_its_hangup() -> Result<(), Error> {
    let mut instance = Instance::new();
    let identity = Identity::new([1; 32], 1)?;
    let source = Source::new(3)?;
    let mut session = Session::new(&mut instance, identity, limits(), 10)?;
    let port = [9; 64];
    session.client_request(
        &identity,
        Message::Register {
            reserved: 0,
            port: &port,
        },
        10,
        1000,
    )?;
    session.attach_port(source)?;
    written(&mut session, 11)?;
    let call = session.incoming(&identity, source, source, [2; 32], 12)?;
    let signed = crypto::SignedRing::sign(&key()?, &port, identity.peer(), 1100)?;
    session.receive(
        &identity,
        call,
        source,
        0,
        Message::PeerRing {
            reserved: 0,
            expiration: signed.expiration(),
            public_key: signed.public_key(),
            signature: signed.signature(),
        },
        13,
        1000,
    )?;
    let original = session.effect().ok_or(Error::NotReady)?.id();
    session.transport_lost(source, Error::Closed, None)?;
    check(session.progress(14)?)?;
    let ring = session.effect().ok_or(Error::NotReady)?;
    check(ring.id() == original && !ring.cancelled())?;
    let Action::ClientFrame { frame, .. } = ring.action() else {
        return Err(Error::Conflict);
    };
    check(matches!(Message::decode(frame)?, Message::Ring { cid, .. } if cid==session.cid(call)?))?;
    check(session.effect_io_allowed(original, &identity, 14)?)?;
    check(!session.effect_io_allowed(original, &identity, 13 + limits().write_timeout)?)?;
    written(&mut session, 14)?;
    let (report, notices) = retired(&mut session, call, 15)?;
    check(notices == 1 && report.failure == Some(Error::Closed) && session.failure().is_none())
}
fn limits() -> Limits {
    Limits {
        ring_timeout: 100,
        write_timeout: 20,
        close_timeout: 50,
        ..Limits::default()
    }
}
fn written(session: &mut Session<'_>, now: u64) -> Result<(), Error> {
    let id = session.effect().ok_or(Error::NotReady)?.id();
    session.admit_effect(id)?;
    session.complete_effect(id, Completion::Written, now)?;
    Ok(())
}
fn calling<'id>(
    instance: &'id mut Instance,
    limits: Limits,
) -> Result<(Session<'id>, Identity, CallId<'id>, Source), Error> {
    let identity = Identity::new([1; 32], 1)?;
    let mut session = Session::new(instance, identity, limits, 10)?;
    let call = match session.client_request(
        &identity,
        Message::Call {
            reserved: 0,
            target: &[2; 32],
            port: &[9; 64],
            private_key: key()?.expose_serialized(),
        },
        10,
        1000,
    )? {
        RequestOutcome::Calling(call) => call,
        _ => return Err(Error::Conflict),
    };
    let source = Source::new(3)?;
    session.attach_channel(call, source)?;
    written(&mut session, 11)?;
    written(&mut session, 12)?;
    check(session.phase(call)? == Phase::Calling)?;
    Ok((session, identity, call, source))
}
fn connect<'id>(
    session: &mut Session<'id>,
    identity: Identity,
    call: CallId<'id>,
    source: Source,
) -> Result<(), Error> {
    session.receive(
        &identity,
        call,
        source,
        0,
        Message::PeerControl(PeerControl::PickUp),
        13,
        1001,
    )?;
    written(session, 14)?;
    written(session, 15)?;
    check(session.phase(call)? == Phase::Connected)
}
fn retired<'id>(
    session: &mut Session<'id>,
    call: CallId<'id>,
    now: u64,
) -> Result<(CallReport<'id>, usize), Error> {
    let mut notices = 0;
    for _ in 0..32 {
        let Some(effect) = session.effect() else {
            return Ok((session.take_report(call)?.ok_or(Error::NotReady)?, notices));
        };
        let id = effect.id();
        if let Action::ClientFrame { frame, .. } = effect.action() {
            let Message::Control {
                action: ClientControl::HangUp,
                cid,
            } = Message::decode(frame)?
            else {
                return Err(Error::Conflict);
            };
            check(cid == session.cid(call)?)?;
            check(session.take_report(call)?.is_none())?;
            notices += 1;
        }
        let effect = session.effect().ok_or(Error::NotReady)?;
        let completion = if effect.cancelled() {
            Completion::Unsent(Error::Cancelled)
        } else if matches!(effect.action(), Action::CloseChannel { .. }) && session.call(call)?.gone
        {
            Completion::Unsent(Error::Closed)
        } else {
            session.admit_effect(id)?;
            Completion::Written
        };
        session.complete_effect(id, completion, now)?;
    }
    Err(Error::Deadline)
}

#[test]
fn setup_timeout_notifies_the_local_caller_and_retains_its_cause() -> Result<(), Error> {
    let mut instance = Instance::new();
    let (mut session, _, call, _) = calling(&mut instance, limits())?;
    session.tick(110)?;
    check(session.phase(call)? == Phase::Closing && session.failure().is_none())?;
    check(session.progress(110)? && !session.progress(110)?)?;
    let (report, notices) = retired(&mut session, call, 111)?;
    check(
        notices == 1
            && report.reason == EndReason::Failed(Error::Timeout)
            && report.failure == Some(Error::Timeout)
            && report.ring_written
            && !report.remote_pickup
            && !report.remote_hangup
            && !report.local_hangup_written,
    )
}

#[test]
fn failed_peer_write_and_later_source_loss_produce_one_local_notice() -> Result<(), Error> {
    let mut instance = Instance::new();
    let (mut session, identity, call, source) = calling(&mut instance, limits())?;
    connect(&mut session, identity, call, source)?;
    session.client_request(&identity, Message::Audio { cid: 0, data: &[1] }, 16, 1002)?;
    let id = session.effect().ok_or(Error::NotReady)?.id();
    session.admit_effect(id)?;
    session.complete_effect(
        id,
        Completion::Lost {
            reason: Error::Unavailable,
            exposed: true,
        },
        17,
    )?;
    check(session.progress(17)? && session.failure().is_none())?;
    session.peer_lost(call, source, Error::Closed)?;
    check(!session.progress(17)?)?;
    let (report, notices) = retired(&mut session, call, 18)?;
    check(
        notices == 1
            && report.reason == EndReason::Failed(Error::Unavailable)
            && report.failure == Some(Error::Unavailable)
            && report.remote_pickup
            && !report.remote_hangup
            && !report.local_hangup_written,
    )
}

#[test]
fn notification_pressure_parks_without_failing_the_line_or_losing_the_cause() -> Result<(), Error> {
    let mut instance = Instance::new();
    let (mut session, identity, call, source) = calling(
        &mut instance,
        Limits {
            effects: 3,
            ..limits()
        },
    )?;
    connect(&mut session, identity, call, source)?;
    for action in [
        ClientControl::Suspend,
        ClientControl::Resume,
        ClientControl::Suspend,
    ] {
        session.client_request(&identity, Message::Control { action, cid: 0 }, 16, 1002)?;
    }
    let original = session.effect().ok_or(Error::NotReady)?.id();
    session.admit_effect(original)?;
    session.peer_lost(call, source, Error::Closed)?;
    check(
        !session.progress(17)?
            && session.failure().is_none()
            && session.take_report(call)?.is_none(),
    )?;
    session.complete_effect(
        original,
        Completion::Lost {
            reason: Error::Closed,
            exposed: true,
        },
        17,
    )?;
    check(session.progress(17)? && !session.progress(17)?)?;
    let (report, notices) = retired(&mut session, call, 18)?;
    check(notices == 1 && report.failure == Some(Error::Closed) && !report.remote_hangup)
}

#[test]
fn an_undeliverable_client_notice_fences_the_original_shared_ipc() -> Result<(), Error> {
    let mut instance = Instance::new();
    let (mut session, identity, call, _) = calling(&mut instance, limits())?;
    session.tick(110)?;
    check(session.progress(110)?)?;
    written(&mut session, 111)?;
    let notice = session.effect().ok_or(Error::NotReady)?;
    check(matches!(notice.action(), Action::ClientFrame { .. }))?;
    session.complete_effect(notice.id(), Completion::Unsent(Error::Deadline), 130)?;
    check(
        session.failure() == Some(Error::Deadline)
            && session.client_request(&identity, Message::Audio { cid: 0, data: &[] }, 130, 1003)
                == Err(Error::Closed),
    )?;
    let report = session.take_report(call)?.ok_or(Error::NotReady)?;
    check(
        report.reason == EndReason::Failed(Error::Timeout)
            && report.failure == Some(Error::Timeout)
            && !report.remote_hangup,
    )?;
    written(&mut session, 131)?;
    check(session.is_quiescent())
}

#[test]
fn a_deferred_notice_retains_the_original_close_bound_after_channel_retirement() -> Result<(), Error>
{
    for queued in [false, true] {
        let mut instance = Instance::new();
        let (mut session, identity, call, _) = calling(
            &mut instance,
            Limits {
                close_timeout: 5,
                ..limits()
            },
        )?;
        session.tick(110)?;
        written(&mut session, 111)?;
        check(session.phase(call)? == Phase::Closed && session.next_deadline() == Some(115))?;
        if queued {
            check(session.progress(114)?)?;
            let notice = session.effect().ok_or(Error::NotReady)?;
            check(
                notice.deadline() == 115
                    && !session.effect_io_allowed(notice.id(), &identity, 115)?,
            )?;
            session.complete_effect(notice.id(), Completion::Unsent(Error::Deadline), 115)?;
        } else {
            check(session.progress(115)?)?;
        }
        let report = session.take_report(call)?.ok_or(Error::NotReady)?;
        check(
            session.failure() == Some(Error::Deadline)
                && report.reason == EndReason::Failed(Error::Timeout)
                && report.failure == Some(Error::Timeout)
                && !report.remote_hangup,
        )?;
        let close = session.effect().ok_or(Error::NotReady)?;
        check(matches!(close.action(), Action::CloseClient))?;
        written(&mut session, 116)?;
        check(session.is_quiescent())?;
    }
    Ok(())
}

#[test]
fn local_hangup_can_cancel_unsubmitted_client_audio_without_failing_the_line() -> Result<(), Error>
{
    let mut instance = Instance::new();
    let (mut session, identity, call, source) = calling(&mut instance, limits())?;
    connect(&mut session, identity, call, source)?;
    session.receive(
        &identity,
        call,
        source,
        1,
        Message::PeerAudio(&[1]),
        16,
        1002,
    )?;
    let original = session.effect().ok_or(Error::NotReady)?.id();
    session.admit_effect(original)?;
    session.client_request(
        &identity,
        Message::Control {
            action: ClientControl::HangUp,
            cid: 0,
        },
        17,
        1002,
    )?;
    let old = session.effect().ok_or(Error::NotReady)?;
    check(old.cancelled() && matches!(old.action(), Action::ClientFrame { .. }))?;
    session.complete_effect(old.id(), Completion::Unsent(Error::Cancelled), 18)?;
    check(
        session.failure().is_none()
            && session.call(call)?.failure.is_none()
            && session.call(call)?.reason == Some(EndReason::LocalHangUp)
            && !session.progress(18)?
            && session.client_request(
                &identity,
                Message::Audio {
                    cid: u32::MAX,
                    data: &[],
                },
                18,
                1002,
            ) == Ok(RequestOutcome::Ignored),
    )
}

#[test]
fn only_authenticated_incoming_ringing_needs_a_local_timeout_notice() -> Result<(), Error> {
    for authenticated in [false, true] {
        let mut instance = Instance::new();
        let identity = Identity::new([1; 32], 1)?;
        let source = Source::new(3)?;
        let mut session = Session::new(&mut instance, identity, limits(), 10)?;
        let port = [9; 64];
        session.client_request(
            &identity,
            Message::Register {
                reserved: 0,
                port: &port,
            },
            10,
            1000,
        )?;
        session.attach_port(source)?;
        written(&mut session, 11)?;
        let call = session.incoming(&identity, source, source, [2; 32], 12)?;
        if authenticated {
            let signed = crypto::SignedRing::sign(&key()?, &port, identity.peer(), 1100)?;
            session.receive(
                &identity,
                call,
                source,
                0,
                Message::PeerRing {
                    reserved: 0,
                    expiration: signed.expiration(),
                    public_key: signed.public_key(),
                    signature: signed.signature(),
                },
                13,
                1000,
            )?;
            written(&mut session, 14)?;
            written(&mut session, 15)?;
        }
        let deadline = session.next_deadline().ok_or(Error::NotReady)?;
        session.tick(deadline)?;
        check(session.progress(deadline)? == authenticated)?;
        let (report, notices) = retired(&mut session, call, deadline + 1)?;
        check(
            notices == usize::from(authenticated)
                && report.failure == Some(Error::Timeout)
                && !report.remote_hangup,
        )?;
    }
    Ok(())
}

#[test]
fn an_admitted_close_does_not_hide_another_calls_deadline_or_renew_its_bound() -> Result<(), Error>
{
    let mut instance = Instance::new();
    let identity = Identity::new([1; 32], 1)?;
    let source = Source::new(3)?;
    let mut session = Session::new(&mut instance, identity, limits(), 10)?;
    let port = [9; 64];
    session.client_request(
        &identity,
        Message::Register {
            reserved: 0,
            port: &port,
        },
        10,
        1000,
    )?;
    session.attach_port(source)?;
    written(&mut session, 11)?;
    let mut calls = alloc::vec::Vec::new();
    for _ in 0..2 {
        let call = session.incoming(&identity, source, source, [2; 32], 12)?;
        let signed = crypto::SignedRing::sign(&key()?, &port, identity.peer(), 1100)?;
        session.receive(
            &identity,
            call,
            source,
            0,
            Message::PeerRing {
                reserved: 0,
                expiration: signed.expiration(),
                public_key: signed.public_key(),
                signature: signed.signature(),
            },
            13,
            1000,
        )?;
        written(&mut session, 14)?;
        written(&mut session, 15)?;
        session.client_request(
            &identity,
            Message::Control {
                action: ClientControl::PickUp,
                cid: session.cid(call)?,
            },
            16,
            1000,
        )?;
        written(&mut session, 17)?;
        calls.push(call);
    }
    let (first, second) = (calls[0], calls[1]);
    session.client_request(
        &identity,
        Message::Control {
            action: ClientControl::HangUp,
            cid: session.cid(first)?,
        },
        18,
        1000,
    )?;
    written(&mut session, 19)?;
    let close = session.effect().ok_or(Error::NotReady)?;
    let (original, bound) = (close.id(), close.deadline());
    session.admit_effect(original)?;
    session.client_request(
        &identity,
        Message::Control {
            action: ClientControl::Suspend,
            cid: session.cid(second)?,
        },
        20,
        1000,
    )?;
    session.tick(40)?;
    check(session.phase(second)? == Phase::Closing && session.progress(40)?)?;
    // Re-observing an expired notification may not derive another close bound
    // or introduce an unrelated overflow on an already closing owner.
    session.tick(u64::MAX - 1)?;
    let close = session.effect().ok_or(Error::NotReady)?;
    check(
        close.id() == original
            && close.admitted()
            && close.deadline() == bound
            && session.failure().is_none()
            && session.call(second)?.failure == Some(Error::Deadline)
            && session.take_report(first)?.is_none()
            && session.take_report(second)?.is_none(),
    )
}
