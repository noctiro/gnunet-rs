#![expect(
    clippy::panic_in_result_fn,
    reason = "Identity-cut models assert original port, channel, output and peer-debt ownership"
)]
use super::*;
const PORT: [u8; 64] = [3; 64];

#[test]
fn identity_cut_reprojects_ports_preserving_original_pairs_and_frozen_output() -> Result<(), Error>
{
    let mut instance = Instance::new();
    let mut clients = [ClientSlot::new(); 2];
    let mut ports = [PortSlot::new(); 1];
    let mut channels = [ChannelSlot::new(); 4];
    let mut bytes = [[0; 16]; 18];
    let mut messages = bytes.each_mut().map(|bytes| MessageSlot::new(bytes));
    let mut service = Service::new(
        &mut instance,
        [1; 32],
        &mut clients,
        &mut ports,
        &mut channels,
        &mut messages,
        Limits {
            loop_payload_bytes: 16,
            remote_payload_bytes: 16,
            ..Limits::default()
        },
    )?;
    let creator = service.attach()?;
    let listener = service.attach()?;
    let Event::PortOpened(port) = service.receive(listener, Request::PortOpen { port: PORT })?
    else {
        return Err(Error::Malformed);
    };
    let Event::ChannelCreated(outgoing) = service.receive(
        creator,
        Request::ChannelCreate {
            channel: CLIENT_CHANNEL_BOUNDARY,
            peer: [1; 32],
            port: PORT,
            options: 0,
        },
    )?
    else {
        return Err(Error::Malformed);
    };
    let incoming = service.progress()?.ok_or(Error::NotReady)?;
    let mut wire = [0; 128];
    let prepared = service
        .prepare_output(listener, &mut wire)?
        .ok_or(Error::NotReady)?;
    let output = prepared.output();
    let length = prepared.bytes().len();
    service.exposed(output)?;
    // Even an exposed, not-yet-complete old frame retains its exact authority.
    service.retire_identity_channels()?;
    service.rebind_local_peer([2; 32])?;
    assert_eq!(service.local_peer(), [2; 32]);
    assert_eq!(service.port_hash(port)?, PORT);
    assert_eq!(
        service.resolve_port_challenge(&peer::hash_port(&PORT, &[1; 32])),
        None
    );
    assert_eq!(
        service.resolve_port_challenge(&peer::hash_port(&PORT, &[2; 32])),
        Some(PORT)
    );
    assert_eq!(
        Response::decode(&wire[..length])?,
        Response::ChannelCreate {
            channel: 0,
            peer: [1; 32],
            port: PORT,
            options: 0,
        }
    );
    assert_eq!(service.channel_info(outgoing)?.peer, [1; 32]);
    assert_eq!(service.channel_info(incoming)?.peer, [1; 32]);
    assert_eq!(service.channel_info(outgoing)?.phase, Phase::Ready);
    assert_eq!(service.channel_info(outgoing)?.allowance, 0);
    service.written(output)?;
    let Event::ChannelCreated(fresh) = service.receive(
        creator,
        Request::ChannelCreate {
            channel: CLIENT_CHANNEL_BOUNDARY + 1,
            peer: [2; 32],
            port: PORT,
            options: 0,
        },
    )?
    else {
        return Err(Error::Malformed);
    };
    let fresh_incoming = service.progress()?.ok_or(Error::NotReady)?;
    assert_eq!(service.channel_info(fresh)?.peer, [2; 32]);
    assert_eq!(service.channel_info(fresh_incoming)?.peer, [2; 32]);
    // A same-peer refresh neither revokes the live port nor retires a channel.
    service.rebind_local_peer([2; 32])?;
    assert_eq!(service.port_hash(port)?, PORT);
    Ok(())
}

#[test]
fn identity_cut_waits_for_original_dispatched_open_before_any_mutation() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut clients = [ClientSlot::new(); 1];
    let mut ports = [PortSlot::new(); 1];
    let mut channels = [ChannelSlot::new(); 3];
    let mut bytes = [[0; 16]; 14];
    let mut messages = bytes.each_mut().map(|bytes| MessageSlot::new(bytes));
    let mut service = Service::new(
        &mut instance,
        [1; 32],
        &mut clients,
        &mut ports,
        &mut channels,
        &mut messages,
        Limits {
            loop_payload_bytes: 16,
            remote_payload_bytes: 16,
            ..Limits::default()
        },
    )?;
    let client = service.attach()?;
    let Event::PortOpened(port) = service.receive(client, Request::PortOpen { port: PORT })? else {
        return Err(Error::Malformed);
    };
    let Event::ChannelCreated(local_wait) = service.receive(
        client,
        Request::ChannelCreate {
            channel: CLIENT_CHANNEL_BOUNDARY,
            peer: [1; 32],
            port: [8; 64],
            options: 0,
        },
    )?
    else {
        return Err(Error::Malformed);
    };
    let Event::ChannelCreated(remote) = service.receive(
        client,
        Request::ChannelCreate {
            channel: CLIENT_CHANNEL_BOUNDARY + 1,
            peer: [7; 32],
            port: PORT,
            options: 0,
        },
    )?
    else {
        return Err(Error::Malformed);
    };
    let open = service.next_open().ok_or(Error::NotReady)?;
    assert_eq!(open.channel(), remote);
    assert_eq!(service.rebind_local_peer([2; 32]), Err(Error::WouldBlock));
    assert_eq!(service.local_peer(), [1; 32]);
    assert_eq!(
        service.resolve_port_challenge(&peer::hash_port(&PORT, &[1; 32])),
        Some(PORT)
    );
    service.retire_identity_channels()?;
    assert_eq!(service.channel_info(local_wait)?.phase, Phase::Closing);
    assert_eq!(service.canceling_open(), Some(open));
    assert_eq!(service.rebind_local_peer([2; 32]), Err(Error::WouldBlock));
    assert_eq!(service.local_peer(), [1; 32]);
    assert_eq!(service.port_hash(port)?, PORT);
    // Only actual retirement of this original dispatched effect clears the cut.
    service.open_failed(open)?;
    service.rebind_local_peer([2; 32])?;
    assert_eq!(service.canceling_open(), None);
    assert_eq!(service.local_peer(), [2; 32]);
    assert_eq!(service.channel_info(remote)?.phase, Phase::Closing);
    assert_eq!(service.channel_info(remote)?.allowance, 0);
    assert_eq!(service.open_failed(open), Err(Error::StaleGeneration));
    Ok(())
}
