//! Real native PILS MQ observations; the source is a pure-Service component,
//! not a normal CADET/Messenger daemon or a cross-language runtime profile.
use super::profile_tests::{Directory, NoEntropy};
use super::*;
use gnunet_pils::{Action, HelloLimits, MasterKey, Profile, Service};
use gnunet_service_runtime::clock::SystemClock;
use tokio::net::{UnixListener, UnixStream};

type Failure = Box<dyn std::error::Error>;

async fn write_frame(stream: &UnixStream, bytes: &[u8]) -> io::Result<()> {
    let mut cursor = 0;
    while cursor < bytes.len() {
        stream.writable().await?;
        match stream.try_write(&bytes[cursor..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "PILS component write zero",
                ));
            }
            Ok(n) => cursor += n,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
async fn read_exact(stream: &UnixStream, bytes: &mut [u8]) -> io::Result<()> {
    let mut cursor = 0;
    while cursor < bytes.len() {
        stream.readable().await?;
        match stream.try_read(&mut bytes[cursor..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "PILS component EOF",
                ));
            }
            Ok(n) => cursor += n,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
async fn read_frame(stream: &UnixStream) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut header = [0; 4];
    read_exact(stream, &mut header).await?;
    let length = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if length < header.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "PILS component frame length",
        ));
    }
    let mut bytes = Zeroizing::new(vec![0; length]);
    bytes[..4].copy_from_slice(&header);
    read_exact(stream, &mut bytes[4..]).await?;
    Ok(bytes)
}
async fn apply_next_identity<'c, 'slots, 'p>(
    server: &mut Server<'c, 'slots, 'p, NoEntropy, 3>,
) -> Result<pc::Identity<'p>, Failure> {
    loop {
        let progress = server.pils.drive(None).await?;
        let identity = match &progress {
            pils::Progress::Inbound(pc::Inbound::Identity { identity, .. }) => Some(*identity),
            _ => None,
        };
        server.signer_progress(progress, &mut |_| {})?;
        if let Some(identity) = identity {
            return Ok(identity);
        }
    }
}
async fn written_request<'c, 'slots, 'p>(
    server: &mut Server<'c, 'slots, 'p, NoEntropy, 3>,
    stream: &UnixStream,
    operation: pc::OperationId<'p>,
) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let read_request = read_frame(stream);
    let drive_written = async {
        loop {
            let progress = server.pils.drive(None).await?;
            let written =
                matches!(&progress, pils::Progress::Written(w) if w.operation == operation);
            server.signer_progress(progress, &mut |_| {})?;
            if written {
                return Ok::<_, Error>(());
            }
        }
    };
    let (written, request) = tokio::join!(drive_written, read_request);
    written?;
    Ok(request?)
}

async fn complete_control<'c, 'slots, 'p>(
    server: &mut Server<'c, 'slots, 'p, NoEntropy, 3>,
    service: &mut Service<4096>,
    stream: &UnixStream,
    now: u64,
    inject_admission_pressure: bool,
) -> Result<Hash, Failure> {
    if !server.signing_work()? || !server.apply_signature(&mut |_| {})? {
        return Err("actual control did not reach its original PILS owner".into());
    }
    let sign = server
        .signs
        .iter()
        .flatten()
        .next()
        .ok_or(Fault::NotFound)?;
    let room = sign.room;
    let original = sign.phase.original().ok_or(Fault::NotReady)?;
    let hash = *sign.binding.message();
    let request = written_request(server, stream, original.operation).await?;
    let mut scratch = [0; 2048];
    let mut output = [0; 104];
    let Action::Reply {
        len,
        crypto_error: None,
    } = service.receive(&request, &mut scratch, now, &mut output)?
    else {
        return Err("actual control request did not produce a signature result".into());
    };
    write_frame(stream, &output[..len]).await?;
    loop {
        let progress = server.pils.drive(None).await?;
        let completed = matches!(&progress, pils::Progress::Inbound(pc::Inbound::Complete(completion)) if completion.operation() == original.operation);
        server.signer_progress(progress, &mut |_| {})?;
        if completed {
            break;
        }
    }
    for stage in 0..3 {
        if !server.apply_signature(&mut |_| {})? {
            return Err("verified control failed to finish its original local stages".into());
        }
        if inject_admission_pressure && stage == 1 {
            // Saturate only the fixed delivery metadata pool as a fault
            // injection after the real signature/local commit. These markers
            // are not new messages, packet receipts or remote delivery facts.
            let old_hash = *server
                .core
                .retained_messages(room)?
                .next()
                .ok_or(Fault::NotFound)?
                .hash();
            let markers = (0..server.messages.len())
                .map(|_| {
                    Some(MessageWork {
                        room,
                        hash: old_hash,
                        exclude: None,
                        recent: false,
                        fanned: true,
                    })
                })
                .collect();
            let original_table = std::mem::replace(&mut server.messages, markers);
            server.drain_events();
            let blocked = server.apply_signature(&mut |_| {});
            let retained = server.signs.iter().flatten().any(|sign| {
                matches!(sign.phase,
                SignPhase::Committed { original: actual, hash: actual_hash }
                    if actual.operation == original.operation && actual_hash == hash)
            });
            server.messages = original_table;
            if blocked? || !retained {
                return Err("post-commit pressure lost the original committed signature".into());
            }
        }
    }
    Ok(hash)
}

async fn same_mq_rotation(profile: Profile) -> Result<(), Failure> {
    let directory = Directory::new()?;
    let path = directory.0.join("p");
    let listener = UnixListener::bind(&path)?;
    let cadet_path = directory.0.join("c");
    let cadet_listener = UnixListener::bind(&cadet_path)?;
    let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
    let now = clock.sample()?.now.as_micros();
    let mut service = Service::<4096>::new(
        MasterKey::from_seed([0x41; 32]),
        profile,
        now,
        HelloLimits {
            maximum_input_bytes: 4096,
            maximum_address_bytes: 2048,
            maximum_addresses: 16,
        },
    )?;
    let mut core_instance = core::Instance::new();
    let mut cadet_instance = cadet::Instance::new();
    let mut pils_instance = pc::Instance::new();
    let mut ports = [cadet::PortSlot::new()];
    let mut channels = [cadet::ChannelSlot::new()];
    let limits = Limits {
        clients: 1,
        rooms: 1,
        client_rooms: 1,
        tunnels: 1,
        deliveries: 8,
        signatures: 3,
        controls: 2,
        min_routers: 0,
        pils_profile: profile,
        ..Limits::default()
    };
    let mut server = Server::<_, 3>::new(
        &mut core_instance,
        &mut cadet_instance,
        &mut pils_instance,
        &mut ports,
        &mut channels,
        core::Limits::default(),
        limits,
        Ports {
            options: ServiceOptions::default(),
            unix: UnixAccess::default(),
            clock: clock.clone(),
            cadet: EndpointSource::unix_with_clock(cadet_path, clock.clone()),
            pils: EndpointSource::unix_with_clock(path, clock),
        },
        NoEntropy,
    )?;
    server.last_now = now;
    let result = tokio::time::timeout(Duration::from_secs(3), async {
        let send_initial = async {
            let (stream, _) = listener.accept().await?;
            write_frame(&stream, service.announcement()).await?;
            Ok::<_, io::Error>(stream)
        };
        let (original, stream) = tokio::join!(apply_next_identity(&mut server), send_initial);
        let original = original?;
        let stream = stream?;
        if server.identity_ready() || server.current_peer().is_some() {
            return Err("initial observation became Core authority before its install step".into());
        }
        if !server.identity_step(&mut |_| {})? || !server.identity_ready() {
            return Err("actual initial identity did not install".into());
        }
        let room_slot = server.ensure_room([0x52; 64])?;
        let room = server.rooms[room_slot].as_ref().ok_or(Fault::Stale)?.room;
        // Attach the actual local CADET client and observe its real port-open
        // write. This is an IPC component boundary, not a remote CADET tunnel
        // or proof that a later changed PID is a reachable door.
        let (connected, accepted) = tokio::join!(server.cadet.drive(None), cadet_listener.accept());
        if !matches!(connected?, cadet::Step::Connected(_)) {
            return Err("actual CADET component did not attach".into());
        }
        let (cadet_stream, _) = accepted?;
        let port_hash = carrier::port(&[0x52; 64], limits.profile);
        let port = server.cadet.listen(port_hash)?;
        let transmit = server.cadet.pending_transmit().ok_or(Fault::NotReady)?;
        let written = async {
            loop {
                match server.cadet.drive(None).await? {
                    cadet::Step::Written(actual) if actual.transmit == transmit => return Ok::<_, Failure>(()),
                    cadet::Step::Activity { .. } => {},
                    _ => return Err("actual port write was not settled".into()),
                }
            }
        };
        let (written, frame) = tokio::join!(written, read_frame(&cadet_stream));
        written?;
        if !matches!(gnunet_wire::official::cadet::Request::decode(&frame?)?,
            gnunet_wire::official::cadet::Request::PortOpen { port } if port == port_hash)
            || !server.cadet.port_announced(port)?
        {
            return Err("actual original CADET port frame was not observed".into());
        }
        let hosted = server.rooms[room_slot].as_mut().ok_or(Fault::Stale)?;
        hosted.hosting = true;
        hosted.port = Some(port);
        if server.hosting_port(room, Instant::now() + Duration::from_secs(1))? != Some(port) {
            return Err("original logical room port was not reused".into());
        }
        server.queue_peer_control(room, Body::Peer { peer: original.peer().as_bytes() })?;
        if !server.signing_work()? || !server.apply_signature(&mut |_| {})? {
            return Err("original SIGN was not admitted".into());
        }
        let original_sign = server.signs.iter().flatten().next().ok_or(Fault::NotFound)?;
        let operation = original_sign.phase.original().ok_or(Fault::NotReady)?.operation;
        let binding = original_sign.binding;
        let hash = *binding.message();
        let original_until = original_sign.until;
        let original_hard = original_sign.hard;
        let request = written_request(&mut server, &stream, operation).await?;
        let mut scratch = [0; 2048];
        let mut output = [0; 104];
        let Action::Reply { len, crypto_error: None } = service.receive(&request, &mut scratch, now, &mut output)? else {
            return Err("actual original SIGN did not produce its real signature result".into());
        };
        // This is the real old-key result, retained separately from the later
        // verified announcement to exercise an outstanding original callback.
        let old_reply = output[..len].to_vec();
        if profile == Profile::ReferenceDeterministic {
            server.queue_peer_control(room, Body::Connection { amount: 1, flags: 0 })?;
            if !server.signing_work()? { return Err("unadmitted draft absent".into()) }
            server.queue_peer_control(room, Body::Connection { amount: 2, flags: 0 })?;
        }
        let initial = gnunet_wire::official::pils::PeerUpdate::decode(service.announcement())?;
        let empty_block = initial.block.to_vec();
        let mut block = empty_block.clone();
        block.extend_from_slice(b"tcp://127.0.0.1:4321\0");
        let mut feed = vec![0; block.len() + 8];
        let length = gnunet_wire::official::pils::Request::Feed { block: &block }.encode(&mut feed)?;
        if !matches!(service.receive(&feed[..length], &mut scratch, now, &mut output)?, Action::Broadcast { .. }) {
            return Err("actual changed address feed did not broadcast".into());
        }
        write_frame(&stream, service.announcement()).await?;
        let latest = apply_next_identity(&mut server).await?;
        if latest.epoch() != original.epoch() { return Err("healthy update replaced its actual MQ epoch".into()) }
        let rotating = profile == Profile::ReferenceDeterministic;
        if rotating == server.identity_ready() || server.current_peer() != Some(*original.peer().as_bytes()) {
            return Err("current capability/rotation gate was not preserved".into());
        }
        let mut drafts = 0;
        if rotating {
            while server.identity_step(&mut |event| { if matches!(event, Event::SignDraftRetired { .. }) { drafts += 1 } })? {}
            if drafts != 2 || server.control_budgets.iter().any(Option::is_some) || server.signs.iter().flatten().count() != 1 {
                return Err("old unadmitted drafts were not retired independently of original SIGN".into());
            }
            if !matches!(server.queue_peer_control(room, Body::Info { version: carrier::VERSION }), Err(Error::Protocol(Fault::WouldBlock))) {
                return Err("rotation granted fresh old-identity signing authority".into());
            }
        }
        let retained = server.signs.iter().flatten().next().ok_or(Fault::NotFound)?;
        if retained.phase.original().is_none_or(|snapshot| snapshot.identity != original || snapshot.operation != operation) || retained.until != original_until || retained.hard != original_hard {
            return Err("identity update changed the original SIGN identity, operation or bounds".into());
        }
        write_frame(&stream, &old_reply).await?;
        loop {
            let progress = server.pils.drive(None).await?;
            let completed = matches!(&progress, pils::Progress::Inbound(pc::Inbound::Complete(pc::Completion::Signature { operation: actual, announced, .. })) if *actual == operation && (announced.is_none() == rotating));
            server.signer_progress(progress, &mut |_| {})?;
            if completed { break }
        }
        for _ in 0..3 {
            if !server.apply_signature(&mut |_| {})? {
                return Err("real original signature did not advance its retained phase".into());
            }
        }
        if server.core.service_attribution(room, &hash)?.sender != gnunet_crypto::hash512(original.peer().as_bytes()) {
            return Err("original signed message was relabelled as the new author".into());
        }
        if rotating && !server.identity_step(&mut |_| {})? {
            return Err("drained same-MQ transition did not commit".into());
        }
        if !server.identity_ready() || server.current_peer() != Some(*latest.peer().as_bytes()) || !server.core.is_own_signer(original.peer().as_bytes()) || !server.core.is_own_signer(latest.peer().as_bytes()) {
            return Err("healthy transition lost original history or failed to grant current authority".into());
        }
        if server.hosting_port(room, original_until)? != Some(port)
            || !server.cadet.port_announced(port)?
            || server.cadet.port_hash(port)? != port_hash
            || server.cadet.pending_transmit().is_some()
        {
            return Err("healthy PID update replaced or blocked the original port intent".into());
        }

        if rotating {
            if !server.room_announcement(room_slot)? {
                return Err("new identity did not start its PEER announcement".into());
            }
            let peer_hash = complete_control(&mut server, &mut service, &stream, now, false).await?;
            if server.core.service_attribution(room, &peer_hash)?.sender != gnunet_crypto::hash512(latest.peer().as_bytes())
                || !server.core.peers(room)?.any(|(peer, announced, _, _)| peer == original.peer().as_bytes() && announced)
                || !server.core.peers(room)?.any(|(peer, announced, _, _)| peer == latest.peer().as_bytes() && announced)
            {
                return Err("PEER(new) was not committed before retiring old routing candidates".into());
            }
            // A request written under B but actually processed after A returns
            // must receive the SDK's real KeyChanged failure. This is the old
            // MISS(A), so the later rotation must still retire B without losing
            // an earlier announced-own routing debt.
            if !server.room_announcement(room_slot)? {
                return Err("PEER commit did not advance to its original MISS child".into());
            }
            if !server.signing_work()? || !server.apply_signature(&mut |_| {})? {
                return Err("second original SIGN did not admit".into());
            }
            let sign = server.signs.iter().flatten().next().ok_or(Fault::NotFound)?;
            let changed_operation = sign.phase.original().ok_or(Fault::NotReady)?.operation;
            let changed_hash = *sign.binding.message();
            let changed_request = written_request(&mut server, &stream, changed_operation).await?;
            let mut restore = vec![0; empty_block.len() + 8];
            let length = gnunet_wire::official::pils::Request::Feed { block: &empty_block }.encode(&mut restore)?;
            if !matches!(service.receive(&restore[..length], &mut scratch, now, &mut output)?, Action::Broadcast { identity_changed: true }) {
                return Err("actual source did not restore its original deterministic identity".into());
            }
            write_frame(&stream, service.announcement()).await?;
            let restored = apply_next_identity(&mut server).await?;
            if restored.peer() != original.peer() { return Err("real source did not restore A".into()) }
            let Action::Reply { len, crypto_error: None } = service.receive(&changed_request, &mut scratch, now, &mut output)? else {
                return Err("source did not produce actual post-change result".into());
            };
            write_frame(&stream, &output[..len]).await?;
            loop {
                let progress = server.pils.drive(None).await?;
                let rejected = matches!(&progress, pils::Progress::Inbound(pc::Inbound::Complete(pc::Completion::Failed { operation, reason: pc::Failure::KeyChanged, .. })) if *operation == changed_operation);
                server.signer_progress(progress, &mut |_| {})?;
                if rejected { break }
            }
            if server.signs.iter().any(Option::is_some) || server.core.message(room, &changed_hash).is_ok() {
                return Err("KeyChanged installed a message or retained a completed operation".into());
            }
            if !server.identity_step(&mut |_| {})? || server.current_peer() != Some(*original.peer().as_bytes()) {
                return Err("known failed old operation prevented healthy restoration".into());
            }
            if !server.room_announcement(room_slot)? {
                return Err("restored A did not get a new PEER intent".into());
            }
            complete_control(&mut server, &mut service, &stream, now, false).await?;
            if !server.room_announcement(room_slot)? {
                return Err("restored PEER did not retain old own routing debt".into());
            }
            let miss_hash = complete_control(&mut server, &mut service, &stream, now, false).await?;
            if server.core.service_attribution(room, &miss_hash)?.sender != gnunet_crypto::hash512(original.peer().as_bytes())
                || server.core.peers(room)?.any(|(peer, announced, _, _)| peer == latest.peer().as_bytes() && announced)
                || !server.core.peers(room)?.any(|(peer, announced, _, _)| peer == original.peer().as_bytes() && announced)
            {
                return Err("restored identity did not sign and commit MISS for the old own peer".into());
            }
            if !server.room_announcement(room_slot)? || server.room_announcement(room_slot)? {
                return Err("settled room announcement repeated its PEER/MISS transaction".into());
            }
            server.queue_peer_control(room, Body::Connection { amount: 7, flags: 0 })?;
            complete_control(&mut server, &mut service, &stream, now, true).await?;
        }
        // An actual EOF remains a physical source failure, even after a healthy
        // same-MQ transition. It is never accepted as another identity update.
        drop(stream);
        loop {
            let progress = server.pils.drive(None).await?;
            match server.signer_progress(progress, &mut |_| {}) {
                Err(Error::PilsLost(_)) => break,
                Err(error) => return Err(error.into()),
                Ok(()) => {}
            }
        }
        if server.identity_ready() || server.current_peer().is_some() {
            return Err("physical source loss retained live signing authority".into());
        }
        Ok::<(), Failure>(())
    }).await;
    server.close_all(&mut |_| {});
    if let Some(cleanup) = server.take_cleanup_error() {
        return Err(cleanup.into());
    }
    result??;
    Ok(())
}

#[test]
fn native_same_mq_identity_update_preserves_original_signatures_and_retires_only_drafts()
-> Result<(), Failure> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        same_mq_rotation(Profile::Reference029).await?;
        same_mq_rotation(Profile::ReferenceDeterministic).await
    })
}
