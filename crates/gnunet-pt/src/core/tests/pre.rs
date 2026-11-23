//! PRE admission, same-channel reply correlation and bounded buffer reuse.
use super::*;
use crate::exit;
use gnunet_crypto::EddsaPrivateKey;

const PACKET: usize = 128;

fn query(id: [u8; 2]) -> Vec<u8> {
    let mut bytes = vec![0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 1];
    bytes[..2].copy_from_slice(&id);
    bytes
}

fn answer(wire_id: [u8; 2]) -> Vec<u8> {
    let mut bytes = query(wire_id);
    bytes[2] = 0x81;
    bytes[3] = 0x80;
    bytes[7] = 1;
    bytes.extend_from_slice(&[0, 0, 16, 0, 1, 0, 0, 0, 120, 0, 100, 99]);
    bytes.resize(PACKET, b'x');
    let mut frame = vec![0, 132, 0, 194];
    frame.extend_from_slice(&bytes);
    frame
}

fn advertise(core: &mut Core<'_>) -> Result<(), Error> {
    let discovery = core.begin_discovery(UNTIL, NOW)?;
    advertise_peer(core, discovery, 0x19)
}

fn advertise_peer<'a>(
    core: &mut Core<'a>,
    discovery: Discovery<'a>,
    seed: u8,
) -> Result<(), Error> {
    let key = EddsaPrivateKey::from_seed([seed; 32]);
    let peer = *key.public_key().as_bytes();
    let region = exit::Advertisement::signed_region(peer, UNTIL);
    let signature = key.sign(exit::PURPOSE, &region)?;
    let block = exit::Advertisement::encode_signed(peer, UNTIL, signature.as_bytes(), NOW)?;
    core.advertisement(
        discovery,
        &exit::discovery_key(),
        exit::BLOCK_TYPE,
        &block,
        NOW,
    )
}

fn open<'a>(core: &mut Core<'a>, now: u64) -> Result<Tunnel<'a>, Error> {
    let Some(Work::Open { tunnel, .. }) = core.next_work(now)? else {
        return Err(Error::NotReady);
    };
    core.opened(tunnel)?;
    core.channel_credit(tunnel, 1, now)?;
    Ok(tunnel)
}

fn send(core: &mut Core<'_>, now: u64) -> Result<[u8; 2], Error> {
    let Some(Work::Send {
        attempt, message, ..
    }) = core.next_work(now)?
    else {
        return Err(Error::NotReady);
    };
    let id = message[4..6].try_into().map_err(|_| Error::Truncated)?;
    core.send_queued(attempt)?;
    core.send_written(attempt)?;
    Ok(id)
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Admission must refuse before remote DNS work without storage for a full permitted reply"
)]
fn admission_reserves_reply_capacity_before_exposing_a_query() -> Result<(), Error> {
    let packet = query([0x12, 0x34]);
    let instance = Instance::new();
    let mut core = Core::new(
        &instance,
        limits(PACKET, PACKET + packet.len() - 1),
        FAMILIES,
    )?;
    let source = core.attached(Stage::Pre, ReplyLimit::MAXIMUM)?;
    assert_eq!(
        core.admit(source, ID, &packet, UNTIL, NOW),
        Err(Error::Capacity)
    );
    assert_eq!(core.pending(), 0);
    assert!(core.next_work(NOW)?.is_none());
    Ok(())
}

#[test]
fn pre_reply_exceeding_source_capacity_drains_as_a_drop() -> Result<(), Error> {
    let instance = Instance::new();
    let mut core = Core::new(&instance, limits(PACKET, 2 * PACKET), FAMILIES)?;
    let source = core.attached(Stage::Pre, ReplyLimit::from_frame_bytes(PACKET + 15)?)?;
    advertise(&mut core)?;
    let tunnel = open(&mut core, NOW)?;
    let request = core.admit(source, ID, &query([0x12, 0x34]), UNTIL, NOW)?;
    let id = send(&mut core, NOW)?;
    if !core.response(tunnel, &answer(id), NOW)?
        || !matches!(core.next_work(NOW)?, Some(Work::Reply {request: actual, decision: Decision::Drop, ..}) if request == actual)
    {
        return Err(Error::Conflict);
    }
    core.reply_queued(request)?;
    core.reply_written(source, request)
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Coalesced maximum replies must fit their original reservations and retain exact callback identities"
)]
fn maximum_replies_fit_concurrently_and_reservations_survive_channel_replacement()
-> Result<(), Error> {
    let instance = Instance::new();
    let budget = 2 * (query([0; 2]).len() + PACKET);
    let mut core = Core::new(&instance, limits(PACKET, budget), FAMILIES)?;
    let source = core.attached(Stage::Pre, ReplyLimit::MAXIMUM)?;
    advertise(&mut core)?;
    let tunnel = open(&mut core, NOW)?;
    let first = core.admit(source, [1; 8], &query([0x12, 0x34]), UNTIL, NOW)?;
    let a = send(&mut core, NOW)?;
    core.channel_credit(tunnel, 1, NOW)?;
    let second = core.admit(source, [2; 8], &query([0x56, 0x78]), UNTIL, NOW)?;
    let b = send(&mut core, NOW)?;
    assert_ne!(a, b, "same-channel DNS IDs cannot alias");
    assert!(core.response(tunnel, &answer(a), NOW)?);
    assert!(core.response(tunnel, &answer(b), NOW)?);
    assert_eq!(
        core.bytes, budget,
        "valid replies must not grow the admitted byte budget"
    );
    for (request, id) in [(first, [0x12, 0x34]), (second, [0x56, 0x78])] {
        let Some(Work::Reply {
            request: actual,
            decision: Decision::Answer(bytes),
            ..
        }) = core.next_work(NOW)?
        else {
            return Err(Error::NotReady);
        };
        assert_eq!(actual, request);
        assert_eq!(&bytes[..2], &id);
        assert_eq!(bytes.len(), PACKET);
        core.reply_queued(request)?;
        core.reply_written(source, request)?;
    }
    assert_eq!(core.bytes, 0);

    let original = core.admit(source, ID, &query([0xab, 0xcd]), UNTIL, NOW)?;
    core.channel_credit(tunnel, 1, NOW)?;
    let old_id = send(&mut core, NOW)?;
    core.tunnel_stopped(tunnel, NOW)?;
    assert_eq!(
        core.next_wakeup(NOW),
        Some(NOW + Limits::default().retry),
        "channel retry needs its own wakeup while every native source is idle"
    );
    assert_eq!(
        core.bytes,
        budget / 2,
        "retry retains the already charged reply storage"
    );
    let now = NOW + Limits::default().retry;
    assert_eq!(
        core.next_wakeup(now),
        Some(UNTIL),
        "a due retry cannot hide the request deadline"
    );
    let successor = open(&mut core, now)?;
    assert_ne!(successor, tunnel);
    let new_id = send(&mut core, now)?;
    assert!(!core.response(tunnel, &answer(old_id), now)?);
    assert!(core.response(successor, &answer(new_id), now)?);
    let Some(Work::Reply {
        request,
        decision: Decision::Answer(bytes),
        ..
    }) = core.next_work(now)?
    else {
        return Err(Error::NotReady);
    };
    assert_eq!(request, original);
    assert_eq!(&bytes[..2], &[0xab, 0xcd]);
    core.reply_queued(request)?;
    core.reply_written(source, request)?;
    assert_eq!(core.bytes, 0);
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Ready DNS decisions must drain before exposing additional remote allocation work"
)]
fn a_ready_reply_precedes_new_vpn_allocation_work() -> Result<(), Error> {
    let instance = Instance::new();
    let mut post = query([0xab, 0xcd]);
    post[2] = 0x81;
    post[3] = 0x80;
    post[7] = 1;
    post.extend_from_slice(&[0, 0, 1, 0, 1, 0, 0, 0, 120, 0, 4, 192, 0, 2, 1]);
    let mut core = Core::new(
        &instance,
        limits(PACKET, query([0; 2]).len() + PACKET + 2 * post.len()),
        FAMILIES,
    )?;
    let pre_source = core.attached(Stage::Pre, ReplyLimit::MAXIMUM)?;
    let post_source = core.attached(Stage::Post, ReplyLimit::MAXIMUM)?;
    advertise(&mut core)?;
    let tunnel = open(&mut core, NOW)?;
    let ready = core.admit(pre_source, ID, &query([0x12, 0x34]), UNTIL, NOW)?;
    let id = send(&mut core, NOW)?;
    assert!(core.response(tunnel, &answer(id), NOW)?);
    let pending = core.admit(post_source, [2; 8], &post, UNTIL, NOW)?;
    assert!(matches!(core.next_work(NOW)?, Some(Work::Reply { request, .. }) if request == ready));
    core.reply_queued(ready)?;
    core.reply_written(pre_source, ready)?;
    assert!(
        matches!(core.next_work(NOW)?, Some(Work::Allocate { request, .. }) if request == pending)
    );
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Retiring an original unsent query must not consume real CADET send credit"
)]
fn unsent_preparation_keeps_credit_after_cancel_expiry_or_source_replacement() -> Result<(), Error>
{
    for retirement in 0..3 {
        let instance = Instance::new();
        let mut core = Core::new(&instance, limits(PACKET, 2 * PACKET), FAMILIES)?;
        let mut source = core.attached(Stage::Pre, ReplyLimit::MAXIMUM)?;
        advertise(&mut core)?;
        let tunnel = open(&mut core, NOW)?;
        let request = core.admit(source, ID, &query([0x12, 0x34]), NOW + 1, NOW)?;
        let Some(Work::Send { attempt, .. }) = core.next_work(NOW)? else {
            return Err(Error::NotReady);
        };

        if retirement == 2 {
            core.source_stopped(source)?;
            source = core.attached(Stage::Pre, ReplyLimit::MAXIMUM)?;
        } else {
            if retirement == 0 {
                core.cancel(request)?;
            } else {
                core.expire(NOW + 1)?;
            }
            assert!(matches!(core.next_work(NOW + 1)?, Some(Work::Reply {
                request: actual,
                decision: Decision::Drop,
                ..
            }) if actual == request));
            core.reply_queued(request)?;
            core.reply_written(source, request)?;
        }
        assert_eq!(core.send_queued(attempt), Err(Error::Stale));
        let successor = core.admit(source, ID, &query([0x56, 0x78]), UNTIL, NOW + 1)?;
        assert!(
            matches!(core.next_work(NOW + 1)?, Some(Work::Send {
            request: actual,
            tunnel: original,
            ..
        }) if actual == successor && original == tunnel),
            "retirement case {retirement} lost real unconsumed credit"
        );
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Check retry accounting at actual admission across tunnel replacement"
)]
fn only_an_admitted_send_spends_the_original_request_attempt() -> Result<(), Error> {
    let instance = Instance::new();
    let mut limits = limits(PACKET, 2 * PACKET);
    limits.attempts = 1;
    let mut core = Core::new(&instance, limits, FAMILIES)?;
    let source = core.attached(Stage::Pre, ReplyLimit::MAXIMUM)?;
    advertise(&mut core)?;
    let first = open(&mut core, NOW)?;
    let original = core.admit(source, ID, &query([0x12, 0x34]), UNTIL, NOW)?;
    let Some(Work::Send { attempt, .. }) = core.next_work(NOW)? else {
        return Err(Error::NotReady);
    };
    core.channel_credit(first, 0, NOW)?;
    assert_eq!(core.send_queued(attempt), Err(Error::NotReady));
    core.tunnel_stopped(first, NOW)?;
    assert_eq!(core.send_queued(attempt), Err(Error::Stale));

    let now = NOW + limits.retry;
    let replacement = open(&mut core, now)?;
    let Some(Work::Send {
        attempt: next,
        request,
        tunnel,
        expires,
        ..
    }) = core.next_work(now)?
    else {
        return Err(Error::NotReady);
    };
    assert_ne!(next, attempt);
    assert_ne!(replacement, first);
    assert_eq!((request, tunnel, expires), (original, replacement, UNTIL));
    core.send_queued(next)?;
    core.tunnel_stopped(replacement, now)?;
    assert!(matches!(core.next_work(now)?, Some(Work::Reply {
        request,
        decision: Decision::Drop,
        expires: UNTIL,
        ..
    }) if request == original));
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Prepared queries must retain identity and obey the original native send window"
)]
fn preparation_preserves_packet_identity_and_cannot_restore_revoked_credit() -> Result<(), Error> {
    let instance = Instance::new();
    let mut core = Core::new(&instance, limits(PACKET, 4 * PACKET), FAMILIES)?;
    let source = core.attached(Stage::Pre, ReplyLimit::MAXIMUM)?;
    advertise(&mut core)?;
    let tunnel = open(&mut core, NOW)?;
    core.channel_credit(tunnel, 2, NOW)?;
    let first = core.admit(source, [1; 8], &query([0x12, 0x34]), UNTIL, NOW)?;
    let second = core.admit(source, [2; 8], &query([0x56, 0x78]), UNTIL, NOW)?;
    let Some(Work::Send {
        attempt,
        request,
        message,
        ..
    }) = core.next_work(NOW)?
    else {
        return Err(Error::NotReady);
    };
    assert_eq!(request, first);
    let prepared = message.to_vec();
    let Some(Work::Send {
        attempt: repeated,
        request,
        message,
        ..
    }) = core.next_work(NOW)?
    else {
        return Err(Error::NotReady);
    };
    assert_eq!((repeated, request), (attempt, first));
    assert_eq!(message, prepared);
    core.send_queued(attempt)?;
    core.send_written(attempt)?;

    let Some(Work::Send {
        attempt, request, ..
    }) = core.next_work(NOW)?
    else {
        return Err(Error::NotReady);
    };
    assert_eq!(request, second, "one original native credit remains");
    core.channel_credit(tunnel, 0, NOW)?;
    assert_eq!(core.send_queued(attempt), Err(Error::NotReady));
    assert!(core.next_work(NOW)?.is_none());
    core.cancel(second)?;
    assert!(matches!(core.next_work(NOW)?, Some(Work::Reply {
        request,
        decision: Decision::Drop,
        ..
    }) if request == second));
    core.reply_queued(second)?;
    core.reply_written(source, second)?;

    let third = core.admit(source, [3; 8], &query([0x9a, 0xbc]), UNTIL, NOW)?;
    assert!(
        core.next_work(NOW)?.is_none(),
        "cancel cannot invent credit"
    );
    core.channel_credit(tunnel, 1, NOW)?;
    assert!(matches!(core.next_work(NOW)?, Some(Work::Send { request, .. }) if request == third));
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "A parked original query must not block another exit"
)]
fn zero_credit_parks_only_the_original_tunnel() -> Result<(), Error> {
    let instance = Instance::new();
    let mut core = Core::new(&instance, limits(PACKET, 4 * PACKET), FAMILIES)?;
    let source = core.attached(Stage::Pre, ReplyLimit::MAXIMUM)?;
    let discovery = core.begin_discovery(UNTIL, NOW)?;
    advertise_peer(&mut core, discovery, 0x19)?;
    advertise_peer(&mut core, discovery, 0x29)?;
    open(&mut core, NOW)?;
    open(&mut core, NOW)?;

    let first = core.admit(source, [1; 8], &query([0x12, 0x34]), UNTIL, NOW)?;
    let Some(Work::Send {
        attempt, tunnel, ..
    }) = core.next_work(NOW)?
    else {
        return Err(Error::NotReady);
    };
    core.channel_credit(tunnel, 0, NOW)?;
    let second = core.admit(source, [2; 8], &query([0x56, 0x78]), UNTIL, NOW)?;
    let Some(Work::Send {
        attempt: later,
        request,
        tunnel: other,
        ..
    }) = core.next_work(NOW)?
    else {
        return Err(Error::NotReady);
    };
    assert_eq!(request, second);
    assert_ne!(other, tunnel);
    core.send_queued(later)?;
    core.channel_credit(tunnel, 1, NOW)?;
    assert!(matches!(
        core.next_work(NOW)?,
        Some(Work::Send { attempt: original, request, .. }) if original == attempt && request == first
    ));
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The final distinct channel-local DNS ID must keep its real credit until queue admission"
)]
fn the_final_prepared_wire_id_remains_admissible() -> Result<(), Error> {
    let instance = Instance::new();
    let mut core = Core::new(&instance, limits(PACKET, 2 * PACKET), FAMILIES)?;
    let source = core.attached(Stage::Pre, ReplyLimit::MAXIMUM)?;
    advertise(&mut core)?;
    let tunnel = open(&mut core, NOW)?;
    let exit = core.tunnel(tunnel)?;
    core.exits[exit].next_id = u32::from(u16::MAX);
    core.admit(source, ID, &query([0x12, 0x34]), UNTIL, NOW)?;
    let Some(Work::Send {
        attempt, message, ..
    }) = core.next_work(NOW)?
    else {
        return Err(Error::NotReady);
    };
    assert_eq!(&message[4..6], &u16::MAX.to_be_bytes());
    assert!(
        matches!(core.next_work(NOW)?, Some(Work::Send { attempt: original, .. }) if original == attempt)
    );
    core.send_queued(attempt)?;
    core.send_written(attempt)?;
    assert!(core.response(tunnel, &answer(u16::MAX.to_be_bytes()), NOW)?);
    Ok(())
}
