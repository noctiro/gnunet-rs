//! One actual private Unix partial-input expiry. No remote SET or CADET peer
//! success is scripted: the real original MQ is physically detached by guards.
use super::*;
use std::{error::Error as StdError, path::PathBuf};
use tokio::net::UnixListener;
type Failure = Box<dyn StdError>;
struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _removed = std::fs::remove_dir_all(&self.0);
    }
}
#[track_caller]
fn check(value: bool) -> Result<(), Failure> {
    if value {
        Ok(())
    } else {
        let at = std::panic::Location::caller();
        Err(format!(
            "original forced CADET trigger changed at {}:{}",
            at.file(),
            at.line()
        )
        .into())
    }
}

#[test]
fn actual_partial_input_detach_retains_forced_trigger_beside_requested() -> Result<(), Failure> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(3), async {
                let stamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_nanos();
                let directory = Directory(
                    std::env::temp_dir().join(format!("set-loss-{}-{stamp:x}", std::process::id())),
                );
                std::fs::create_dir(&directory.0)?;
                let path = directory.0.join("c");
                let listener = UnixListener::bind(&path)?;
                let mut set_instance = gnunet_set::Instance::new();
                let core = Service::new(
                    &mut set_instance,
                    gnunet_set::Limits::default(),
                    gnunet_set::wire::Abi::native(),
                    1,
                )?;
                let mut cadet_instance = cadet::Instance::new();
                let mut ports = [cadet::PortSlot::new()];
                let mut channels = [cadet::ChannelSlot::new()];
                let client = cadet::Client::new(
                    &mut cadet_instance,
                    cadet::EndpointSource::unix(path),
                    &mut ports,
                    &mut channels,
                    cadet::Limits::default(),
                )?;
                let mut server = Server::new(
                    core,
                    client,
                    Limits {
                        partial_input: Duration::from_millis(20),
                        ..Default::default()
                    },
                    ServiceOptions::default(),
                    UnixAccess::default(),
                )?;
                let epoch = match server
                    .cadet
                    .drive(Some(Instant::now() + Duration::from_secs(1)))
                    .await?
                {
                    cadet::Step::Connected(epoch) => epoch,
                    _ => return Err(Failure::from("original Unix MQ did not attach")),
                };
                let (peer, _) = listener.accept().await?;
                peer.writable().await?;
                check(peer.try_write(&[0, 8])? == 2)?;
                let mut actual_loss = None;
                let mut observe = |event| {
                    if let Event::CadetLost {
                        report,
                        cause,
                        forced,
                    } = event
                    {
                        actual_loss = Some((report, cause, forced));
                    }
                };
                poll_fn(|cx| server.poll_cadet(cx, &mut observe)).await?;
                let target = server
                    .read_hard
                    .ok_or("actual partial read did not retain its original target")?;
                check(server.cadet.epoch() == Some(epoch))?;
                tokio::time::sleep_until(target).await;
                check(server.guards(&mut observe)?)?;
                let (report, cause, forced) =
                    actual_loss.ok_or("real detach did not report its loss")?;
                let forced = forced.ok_or("Requested hid the actual native guard")?;
                check(report.epoch == epoch && report.pending.is_none() && report.channels == 0)?;
                check(matches!(cause, cadet::LossCause::Requested))?;
                check(
                    forced.reason == Fault::Deadline
                        && forced.trigger == RetirementTrigger::ReadHard,
                )?;
                check(
                    forced.pending.is_none()
                        && forced.pending_terminal.is_none()
                        && forced.peer.is_none()
                        && forced.channels == 0
                        && forced.queued_sends == 0,
                )?;
                check(server.forced_loss.is_none() && server.cadet.epoch().is_none())?;
                peer.readable().await?;
                check(peer.try_read(&mut [0; 1])? == 0)?;
                let shutdown = server.shutdown(|_| {});
                check(shutdown.drained && shutdown.failure.is_none())
            })
            .await?
        })
}

async fn send_bytes(peer: &tokio::net::UnixStream, bytes: &[u8]) -> Result<(), Failure> {
    let mut at = 0;
    while at < bytes.len() {
        peer.writable().await?;
        match peer.try_write(&bytes[at..]) {
            Ok(0) => return Err("original diagnostic MQ stopped writing".into()),
            Ok(n) => at += n,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}
async fn frame(peer: &tokio::net::UnixStream) -> Result<Vec<u8>, Failure> {
    let mut bytes = Vec::new();
    let mut length = 4;
    loop {
        peer.readable().await?;
        let mut block = [0; 128];
        let available = block.len().min(length - bytes.len());
        match peer.try_read(&mut block[..available]) {
            Ok(0) => return Err("original diagnostic MQ reached EOF before frame".into()),
            Ok(n) => bytes.extend_from_slice(&block[..n]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) => return Err(error.into()),
        }
        if bytes.len() >= 4 {
            length = usize::from(u16::from_be_bytes([bytes[0], bytes[1]]));
        }
        if bytes.len() == length {
            return Ok(bytes);
        }
    }
}
async fn hold_data<'id>(
    server: &mut Server<'id, '_>,
    peer: &tokio::net::UnixStream,
    channel: cadet::Channel<'id>,
) -> Result<Instant, Failure> {
    let mut bytes = [0; 16];
    // A complete original DATA packet is deliberately held before algorithm
    // classification. Its actual native phase target, not a fabricated proof
    // or SET completion, is what this retirement case exercises.
    gnunet_wire::official::cadet::Response::Data {
        channel: channel.wire_id(),
        priority: 0,
        messages: &[0, 4, 1, 0],
    }
    .encode(&mut bytes)?;
    send_bytes(peer, &bytes).await?;
    loop {
        poll_fn(|cx| server.poll_cadet(cx, &mut |_| {})).await?;
        let index = server
            .channel_index(channel)
            .ok_or("actual original channel missing")?;
        if let Some(input) = server.channels[index]
            .as_ref()
            .and_then(|source| source.input.as_ref())
        {
            return input
                .hard
                .ok_or_else(|| "actual held DATA has no original target".into());
        }
    }
}

#[test]
fn expired_channel_gets_independent_cleanup_then_actual_shared_mq_fence() -> Result<(), Failure> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(5), two_channel_retirement()).await?
        })
}
async fn two_channel_retirement() -> Result<(), Failure> {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let directory =
        Directory(std::env::temp_dir().join(format!("set-two-{}-{stamp:x}", std::process::id())));
    std::fs::create_dir(&directory.0)?;
    let path = directory.0.join("c");
    let listener = UnixListener::bind(&path)?;
    let now = cadet::clock::SystemClock.sample()?.now.as_micros();
    let mut set_instance = gnunet_set::Instance::new();
    let mut core = Service::new(
        &mut set_instance,
        gnunet_set::Limits::default(),
        gnunet_set::wire::Abi::native(),
        now,
    )?;
    let application = core.attach_client()?;
    let mut provider = crate::ports::NativePorts::new();
    core.client_request(
        application,
        ClientRequest::Create { operation: 2 },
        now,
        &mut provider,
    )?;
    for rid in [1, 2] {
        core.client_request(
            application,
            ClientRequest::Evaluate {
                result_mode: gnunet_set::ResultMode::Symmetric as u32,
                target: [rid as u8; 32],
                app_id: [9; 64],
                request_id: rid,
                options: gnunet_set::wire::Options::default(),
                context: &[],
            },
            now,
            &mut provider,
        )?;
    }
    let mut cadet_instance = cadet::Instance::new();
    let mut ports = [cadet::PortSlot::new()];
    let mut channel_slots = [cadet::ChannelSlot::new(), cadet::ChannelSlot::new()];
    let client = cadet::Client::new(
        &mut cadet_instance,
        cadet::EndpointSource::unix(path),
        &mut ports,
        &mut channel_slots,
        cadet::Limits::default(),
    )?;
    let mut server = Server::new(
        core,
        client,
        Limits {
            partial_input: Duration::from_millis(20),
            retirement_grace: Duration::from_millis(200),
            ..Default::default()
        },
        ServiceOptions::default(),
        UnixAccess::default(),
    )?;
    let epoch = match server
        .cadet
        .drive(Some(Instant::now() + Duration::from_secs(1)))
        .await?
    {
        cadet::Step::Connected(epoch) => epoch,
        _ => return Err(Failure::from("original two-channel MQ did not attach")),
    };
    let (peer, _) = listener.accept().await?;
    for _ in 0..2 {
        check(server.effect(&mut |_| {})?)?;
        while server.pending.is_some() {
            poll_fn(|cx| server.poll_cadet(cx, &mut |_| {})).await?;
        }
        check(matches!(
            gnunet_wire::official::cadet::Request::decode(&frame(&peer).await?)?,
            gnunet_wire::official::cadet::Request::ChannelCreate { .. }
        ))?;
    }
    let actual: Vec<_> = server
        .channels
        .iter()
        .flatten()
        .map(|channel| channel.channel)
        .collect();
    check(
        actual.len() == 2
            && server.core.peer_owner_live(
                server.channels[1]
                    .as_ref()
                    .and_then(|channel| channel.owner)
                    .ok_or("second actual owner missing")?,
            ),
    )?;
    // Queue one actual original SET request through its real core effect.
    // No service credit exists, so these copied bytes have never been written.
    for _ in 0..8 {
        server.progress()?;
        server.effect(&mut |_| {})?;
        if !server.sends.is_empty() {
            break;
        }
    }
    check(server.sends.len() == 1)?;
    let original_send = server.sends[0].id;
    let original = server.sends[0].channel;
    let send_target = server.sends[0].hard;
    let other = *actual
        .iter()
        .find(|channel| **channel != original)
        .ok_or("second original channel missing")?;
    let other_peer = server.channels[server
        .channel_index(other)
        .ok_or("second original row missing")?]
    .as_ref()
    .ok_or("second original row missing")?
    .peer;
    check(server.timer_target(None) == Some(send_target))?;
    let business = hold_data(&mut server, &peer, original).await?;
    check(server.read_hard.is_none() && server.cadet.pending_transmit().is_none())?;
    tokio::time::sleep_until(business).await;
    check(!server.guards(&mut |_| {})?)?;
    check(server.cadet.epoch() == Some(epoch))?;
    let index = server
        .channel_index(original)
        .ok_or("first original channel disappeared before Destroy")?;
    let cleanup = server.channels[index]
        .as_ref()
        .and_then(|channel| channel.hard)
        .ok_or("first close did not capture cleanup target")?;
    check(cleanup > business && cleanup > Instant::now())?;
    check(server.sends.len() == 1 && server.sends[0].hard == send_target)?;
    // This original send target is earlier than cleanup, but its ended phase
    // cannot wake the reactor once this same channel is closing. The real
    // pending/cleanup targets, rather than retained old business bytes, remain.
    check(send_target < cleanup && server.timer_target(None) == Some(cleanup))?;
    check(
        server.channels[index]
            .as_ref()
            .is_some_and(|channel| channel.input.is_none() && channel.local_closing),
    )?;
    check(server.peer_work(&mut |_| {})?)?;
    check(server.pending.as_ref().is_some_and(|pending| {
        matches!(pending.kind, PendingKind::Destroy(channel) if channel == original)
            && pending.hard == cleanup
    }))?;
    check(server.timer_target(None) == Some(cleanup))?;
    let mut send_terminal = None;
    while server.pending.is_some() {
        poll_fn(|cx| {
            server.poll_cadet(cx, &mut |event| {
                if let Event::EffectTerminal(terminal) = event
                    && terminal.effect.id == original_send
                {
                    send_terminal = Some(terminal.completion);
                }
            })
        })
        .await?;
    }
    check(send_terminal == Some(Completion::Unsent(Fault::Deadline)))?;
    check(
        matches!(gnunet_wire::official::cadet::Request::decode(&frame(&peer).await?)?, gnunet_wire::official::cadet::Request::ChannelDestroy { channel } if channel == original.wire_id()),
    )?;
    check(server.channel_index(original).is_none() && server.cadet.epoch() == Some(epoch))?;
    let index = server
        .channel_index(other)
        .ok_or("unrelated original channel retired")?;
    check(
        server.channels[index]
            .as_ref()
            .is_some_and(|channel| !channel.closing && channel.input.is_none()),
    )?;
    check(server.cadet.channel_info(other).is_ok())?;
    // The second input starts only after the first channel's actual
    // whole Destroy, so no simultaneous phase expiry can mask isolation.
    let second_business = hold_data(&mut server, &peer, other).await?;
    tokio::time::sleep_until(second_business).await;
    check(!server.guards(&mut |_| {})?)?;
    let cleanup = server.channels[index]
        .as_ref()
        .and_then(|channel| channel.hard)
        .ok_or("second close did not capture cleanup target")?;
    check(cleanup > second_business)?;
    tokio::time::sleep_until(cleanup).await;
    let mut loss = None;
    check(server.guards(&mut |event| {
        if let Event::CadetLost {
            report,
            cause,
            forced,
        } = event
        {
            loss = Some((report, cause, forced));
        }
    })?)?;
    let (report, cause, forced) = loss.ok_or("actual cleanup expiry did not detach MQ")?;
    let forced = forced.ok_or("cleanup expiry lost its original trigger")?;
    check(
        report.epoch == epoch
            && report.channels == 1
            && matches!(cause, cadet::LossCause::Requested),
    )?;
    check(
        forced.reason == Fault::Deadline
            && forced.trigger
                == RetirementTrigger::ChannelHard {
                    channel: other.value(),
                    wire: other.wire_id(),
                },
    )?;
    check(forced.peer == Some(other_peer) && forced.channels == 1 && forced.pending.is_none())?;
    check(server.cadet.epoch().is_none())?;
    peer.readable().await?;
    check(peer.try_read(&mut [0; 1])? == 0)?;
    // This fixture created its pure application directly, without a native
    // Server.apps companion. Retire that SAME application explicitly after
    // the real peer sockets are gone, then drive only the original closing
    // bookkeeping. Historical now is not a renewed phase or IO permission.
    server.core.detach_client(application)?;
    server.core.shutdown()?;
    for _ in 0..16 {
        if server.core.is_quiescent() {
            break;
        }
        server.core.progress(now, &mut server.ports_provider)?;
        let queued = server.core.pending_effects();
        for _ in 0..queued {
            let Some(effect) = server.core.effect() else {
                break;
            };
            let id = effect.id;
            // No new sink is used. reject refuses an admitted unknown, so a
            // remaining physical debt cannot become a fabricated Written.
            server.reject(id, Fault::Closed, &mut |_| {})?;
        }
    }
    check(server.core.is_quiescent())?;
    let shutdown = server.shutdown(|_| {});
    check(shutdown.drained && shutdown.failure.is_none())
}
