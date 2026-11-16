//! Real private PILS sockets with pending and already verified original SIGNs.
use super::profile_tests::NoEntropy;
use super::rotation_tests::{apply_next_identity, write_frame, written_request};
use super::*;
use gnunet_pils::{Action, HelloLimits, MasterKey, Profile, Service};
use gnunet_service_runtime::local::{Listener, Stream};

type Failure = Box<dyn std::error::Error>;

pub(super) async fn recover_source<'c, 'slots, 'p>(
    server: &mut Server<'c, 'slots, 'p, NoEntropy, 3>,
    service: &mut Service<4096>,
    stream: Stream,
    listener: &Listener,
    now: u64,
    profile: Profile,
) -> Result<(), Failure> {
    let room = server
        .rooms
        .iter()
        .flatten()
        .next()
        .ok_or(Fault::NotFound)?
        .room;
    let previous = server.active_identity().ok_or(Fault::NotReady)?;
    let mut operations = Vec::new();
    for amount in [8, 9] {
        server.drain_events();
        server.queue_peer_control(room, Body::Connection { amount, flags: 0 })?;
        if !server.signing_work()? || !server.apply_signature(&mut |_| {})? {
            return Err("source recovery setup did not admit the real original SIGN".into());
        }
        let sign = server
            .signs
            .iter()
            .flatten()
            .find(|s| {
                s.original()
                    .is_some_and(|o| !operations.iter().any(|(op, _)| *op == o.operation))
            })
            .ok_or(Fault::NotFound)?;
        let operation = sign.original().ok_or(Fault::NotReady)?.operation;
        operations.push((operation, sign.binding));
        let request = written_request(server, &stream, operation).await?;
        if amount == 9 {
            let mut scratch = [0; 2048];
            let mut output = [0; 104];
            let Action::Reply {
                len,
                crypto_error: None,
            } = service.receive(&request, &mut scratch, now, &mut output)?
            else {
                return Err("real second SIGN did not produce its signature".into());
            };
            write_frame(&stream, &output[..len]).await?;
            loop {
                let progress = server.pils.drive(None).await?;
                let complete = matches!(&progress, pils::Progress::Inbound(pc::Inbound::Complete(c)) if c.operation() == operation);
                server.signer_progress(progress, &mut |_| {})?;
                if complete {
                    break;
                }
            }
        }
    }
    server.queue_peer_control(
        room,
        Body::Connection {
            amount: 10,
            flags: 0,
        },
    )?;
    drop(stream);
    loss(server).await?;
    let first = match server.identity {
        identity::LocalIdentity::Recovering(recovery) => recovery,
        _ => return Err("physical EOF did not enter bounded recovery".into()),
    };
    if server.local_peer().is_some()
        || !server.pils.is_idle()
        || !server.pils.operation_quiescent(operations[0].0)?
    {
        return Err("old written SIGN retained live authority or replay work".into());
    }
    if !server.identity_step()? {
        return Err("unadmitted control was not taken for retirement".into());
    }
    let draft = server
        .signs
        .iter()
        .position(|sign| {
            sign.as_ref()
                .is_some_and(|s| matches!(s.state, SignState::Retiring { original: None, .. }))
        })
        .ok_or(Fault::NotFound)?;
    let draft_binding = server.signs[draft].as_ref().ok_or(Fault::Stale)?.binding;
    // Fill the real Core event queue without altering or replacing its owner.
    // The taken draft must survive repeated failure-admission backpressure.
    loop {
        match server.core.room([0xfe; 64], None) {
            Ok(temporary) => server.core.forget_room(temporary)?,
            Err(core::Error::Protocol(Fault::WouldBlock)) => break,
            Err(error) => return Err(error.into()),
        }
    }
    for _ in 0..2 {
        if server.apply_retired_signature(draft, &mut |_| {})?
            || server.core.operation_phase(draft_binding.operation())?
                != core::OperationPhase::Taken
        {
            return Err(
                "event backpressure discarded or partially failed the original taken draft".into(),
            );
        }
    }
    let mut retired = 0;
    let mut applied = 0;
    let mut drafts = 0;
    loop {
        server.drain_events();
        if server.identity_step()? {
            continue;
        }
        if server.apply_signature(&mut |event| match event {
            Event::SignRetired {
                operation,
                reason: Fault::Closed,
            } if operation == operations[0].0.value() => retired += 1,
            Event::SignApplied { operation } if operation == operations[1].0.value() => {
                applied += 1
            }
            Event::SignDraftRetired {
                operation,
                reason: Fault::StaleGeneration,
            } if operation == draft_binding.operation().observation() => drafts += 1,
            _ => {}
        })? {
            continue;
        }
        break;
    }
    if retired != 1
        || applied != 1
        || drafts != 1
        || server.signs.iter().any(Option::is_some)
        || server
            .core
            .service_attribution(room, operations[1].1.message())?
            .sender
            != gnunet_crypto::hash512(previous.peer().as_bytes())
    {
        return Err(
            "source loss discarded a verified signature or replayed its old unverified sibling"
                .into(),
        );
    }
    // Attaching another socket alone grants no authority. Losing this unsigned
    // successor retains the first cause and the first operation budget.
    let (connected, accepted) = tokio::join!(server.pils.drive(None), listener.accept());
    let progress = connected?;
    if !matches!(&progress, pils::Progress::Connected(_)) {
        return Err("replacement did not attach".into());
    }
    server.signer_progress(progress, &mut |_| {})?;
    let (unsigned, _) = accepted?;
    if server.identity_step()? || server.local_peer().is_some() {
        return Err("socket attachment became signing authority".into());
    }
    drop(unsigned);
    loss(server).await?;
    let identity::LocalIdentity::Recovering(repeated) = server.identity else {
        return Err("second loss discarded recovery".into());
    };
    if repeated.until != first.until
        || repeated.hard != first.hard
        || repeated.deadline != first.deadline
        || !repeated.lost.is_successor_of(first.lost)
        || !matches!(server.pils_recovery_cause, Some(pils::ConnectionLoss::Eof))
    {
        return Err(
            "repeated connection loss renewed its budget or replaced the first cause".into(),
        );
    }
    let replacement = Service::<4096>::new(
        MasterKey::from_seed([0x99; 32]),
        profile,
        now,
        HelloLimits {
            maximum_input_bytes: 4096,
            maximum_address_bytes: 2048,
            maximum_addresses: 16,
        },
    )?;
    let announcement = if profile == Profile::Reference029 {
        service.announcement()
    } else {
        replacement.announcement()
    };
    let announce = async {
        let (stream, _) = listener.accept().await?;
        write_frame(&stream, announcement).await?;
        Ok::<_, io::Error>(stream)
    };
    let (latest, stream) = tokio::join!(apply_next_identity(server), announce);
    let latest = latest?;
    let stream = stream?;
    if !latest.epoch().is_successor_of(repeated.lost)
        || latest.revision() <= previous.revision()
        || server.local_peer().is_some()
        || !server.identity_step()?
        || !server.identity_ready()
        || server.current_peer() != Some(*latest.peer().as_bytes())
        || server.pils_recovery_cause.is_some()
    {
        return Err(
            "verified successor identity did not exclusively restore current authority".into(),
        );
    }
    let mut unexpected = [0; 4];
    if !matches!(stream.try_read(&mut unexpected), Err(e) if e.kind() == io::ErrorKind::WouldBlock)
    {
        return Err("old original SIGN was replayed onto the replacement source".into());
    }
    Ok(())
}

async fn loss<'c, 'slots, 'p>(
    server: &mut Server<'c, 'slots, 'p, NoEntropy, 3>,
) -> Result<(), Failure> {
    loop {
        let progress = server.pils.drive(None).await?;
        let lost = matches!(&progress, pils::Progress::Lost { .. });
        server.signer_progress(progress, &mut |_| {})?;
        if lost {
            return Ok(());
        }
    }
}
