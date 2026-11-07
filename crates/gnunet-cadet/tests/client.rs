//! State models for original-source identity, real CADET credit and no replay.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible model tests assert bounded protocol transitions and stale-source refusal"
)]
use gnunet_cadet::client::{
    ChannelSlot, Client, Direction, Ignored, Inbound, Instance, Limits, PortSlot, TransmitKind,
};
use gnunet_types::Error;
use gnunet_wire::official::cadet::{CLIENT_CHANNEL_BOUNDARY, Request, Response};

const MESSAGE: [u8; 4] = [0, 4, 0x12, 0x34];

#[test]
fn actual_ack_owns_send_credit_and_exposed_data_cannot_be_retried() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut ports = [PortSlot::new(); 1];
    let mut channels = [ChannelSlot::new(); 2];
    let mut client = Client::new(&mut instance, &mut ports, &mut channels, Limits::default())?;
    let source = client.connected()?;
    let mut output = [0_u8; 256];
    let (channel, frame) = client.prepare_channel([7; 32], [9; 64], &mut output)?;
    assert_eq!(channel.wire_id(), CLIENT_CHANNEL_BOUNDARY);
    assert_eq!(
        Request::decode(frame.bytes())?,
        Request::ChannelCreate {
            channel: CLIENT_CHANNEL_BOUNDARY,
            peer: [7; 32],
            port: [9; 64],
            options: 0,
        }
    );
    let create = frame.transmit();
    assert_eq!(client.channel_info(channel)?.direction, Direction::Outbound);
    assert!(matches!(
        client.on_response(
            source,
            Response::Ack {
                channel: channel.wire_id()
            }
        ),
        Err(Error::NotReady)
    ));
    client.written(create)?;
    assert!(matches!(
        client.prepare_send(channel, 0, &MESSAGE, &mut output),
        Err(Error::WouldBlock)
    ));
    assert!(matches!(
        client.on_response(source, Response::Ack { channel: channel.wire_id() })?,
        Inbound::Credit { channel: original, available: 1 } if original == channel
    ));
    let concatenated = [0, 4, 0, 1, 0, 4, 0, 2];
    assert!(matches!(
        client.prepare_send(channel, 0, &concatenated, &mut output),
        Err(Error::Malformed)
    ));
    assert_eq!(client.channel_info(channel)?.send_credit, 1);
    assert!(client.pending_transmit().is_none());
    let frame = client.prepare_send(channel, 0xdead_beef, &MESSAGE, &mut output)?;
    assert_eq!(
        Request::decode(frame.bytes())?,
        Request::Data {
            channel: channel.wire_id(),
            priority: 0xdead_beef,
            messages: &MESSAGE
        }
    );
    let data = frame.transmit();
    assert_eq!(data.kind(), TransmitKind::Data);
    client.exposed(data)?;
    assert_eq!(client.discard(data), Err(Error::OutcomeUnknown));
    client.written(data)?;
    assert_eq!(client.channel_info(channel)?.send_credit, 0);
    assert!(matches!(
        client.prepare_send(channel, 0, &MESSAGE, &mut output),
        Err(Error::WouldBlock)
    ));
    let _credit = client.on_response(
        source,
        Response::Ack {
            channel: channel.wire_id(),
        },
    )?;
    let unsent = client
        .prepare_send(channel, 0, &MESSAGE, &mut output)?
        .transmit();
    client.discard(unsent)?;
    assert_eq!(client.channel_info(channel)?.send_credit, 1);
    assert_eq!(client.written(unsent), Err(Error::StaleGeneration));
    Ok(())
}

#[test]
fn incoming_zero_has_one_processing_token_and_port_close_keeps_channel() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut ports = [PortSlot::new(); 1];
    let mut channels = [ChannelSlot::new(); 2];
    let mut client = Client::new(&mut instance, &mut ports, &mut channels, Limits::default())?;
    let source = client.connected()?;
    let mut output = [0_u8; 256];
    let (port, opening) = client.prepare_port_open([2; 64], &mut output)?;
    client.written(opening.transmit())?;
    let incoming = Response::ChannelCreate {
        channel: 0,
        peer: [3; 32],
        port: [2; 64],
        options: 0xaabb_ccdd,
    };
    let Inbound::Incoming {
        channel,
        port: selected_port,
    } = client.on_response(source, incoming)?
    else {
        return Err(Error::Malformed);
    };
    assert_eq!(selected_port, port);
    assert_eq!(channel.wire_id(), 0);
    assert_eq!(client.channel_info(channel)?.options, 0xaabb_ccdd);
    assert!(matches!(
        client.on_response(source, incoming),
        Err(Error::Conflict)
    ));
    let packet = Response::Data {
        channel: 0,
        priority: 0,
        messages: &MESSAGE,
    };
    let Inbound::Data {
        delivery, messages, ..
    } = client.on_response(source, packet)?
    else {
        return Err(Error::Malformed);
    };
    assert_eq!(messages, MESSAGE);
    assert!(matches!(
        client.on_response(source, packet),
        Err(Error::WouldBlock)
    ));
    let receive_done = client
        .prepare_receive_done(delivery, &mut output)?
        .transmit();
    assert!(client.channel_info(channel)?.receive_pending);
    assert!(matches!(
        client.on_response(source, packet),
        Err(Error::WouldBlock)
    ));
    client.discard(receive_done)?;
    assert!(client.channel_info(channel)?.receive_pending);
    let frame = client.prepare_receive_done(delivery, &mut output)?;
    assert_eq!(Request::decode(frame.bytes())?, Request::Ack { channel: 0 });
    client.written(frame.transmit())?;
    assert!(!client.channel_info(channel)?.receive_pending);
    assert!(matches!(
        client.prepare_receive_done(delivery, &mut output),
        Err(Error::StaleGeneration)
    ));

    let closing = client.prepare_port_close(port, &mut output)?.transmit();
    assert!(matches!(
        client.on_response(
            source,
            Response::ChannelCreate {
                channel: 1,
                peer: [4; 32],
                port: [2; 64],
                options: 0
            }
        )?,
        Inbound::RejectedIncoming { channel: 1 }
    ));
    assert!(matches!(
        client.prepare_reject(1, &mut output),
        Err(Error::WouldBlock)
    ));
    client.written(closing)?;
    assert!(client.channel_info(channel).is_ok());
    assert_eq!(client.port_hash(port), Err(Error::StaleGeneration));
    let rejection = client.prepare_reject(1, &mut output)?;
    assert_eq!(
        Request::decode(rejection.bytes())?,
        Request::ChannelDestroy { channel: 1 }
    );
    client.written(rejection.transmit())?;
    assert!(matches!(
        client.on_response(source, Response::Ack { channel: 99 })?,
        Inbound::Ignored(Ignored::UnknownChannel)
    ));
    Ok(())
}

#[test]
fn physical_loss_reannounces_only_ports_and_old_incoming_slot_cannot_ack_new_data()
-> Result<(), Error> {
    let mut instance = Instance::new();
    let mut ports = [PortSlot::new(); 1];
    let mut channels = [ChannelSlot::new(); 1];
    let mut client = Client::new(&mut instance, &mut ports, &mut channels, Limits::default())?;
    let first_source = client.connected()?;
    let mut output = [0_u8; 256];
    let (port, opening) = client.prepare_port_open([5; 64], &mut output)?;
    client.written(opening.transmit())?;
    let (old_channel, creating) = client.prepare_channel([6; 32], [5; 64], &mut output)?;
    client.written(creating.transmit())?;
    let _credit = client.on_response(
        first_source,
        Response::Ack {
            channel: old_channel.wire_id(),
        },
    )?;
    let data = client
        .prepare_send(old_channel, 0, &MESSAGE, &mut output)?
        .transmit();
    client.exposed(data)?;
    let loss = client.lost(first_source)?;
    assert_eq!(loss.epoch, first_source);
    assert_eq!(loss.channels, 1);
    assert!(
        loss.pending
            .is_some_and(|pending| pending.transmit == data && pending.exposed)
    );
    assert_eq!(client.written(data), Err(Error::StaleGeneration));
    assert_eq!(
        client.channel_info(old_channel),
        Err(Error::StaleGeneration)
    );
    let next_source = client.connected()?;
    assert_ne!(first_source, next_source);
    assert_eq!(client.lost(first_source), Err(Error::StaleGeneration));
    assert_eq!(client.pending_port(), Some(port));
    assert!(!client.port_announced(port)?);
    assert!(matches!(
        client.prepare_port_close(port, &mut output),
        Err(Error::NotReady)
    ));
    assert!(client.pending_transmit().is_none());
    let incoming = Response::ChannelCreate {
        channel: 0,
        peer: [8; 32],
        port: [5; 64],
        options: 0,
    };
    assert!(matches!(
        client.on_response(first_source, incoming),
        Err(Error::StaleGeneration)
    ));
    let announcement = client.prepare_announce(port, &mut output)?;
    assert_eq!(
        Request::decode(announcement.bytes())?,
        Request::PortOpen { port: [5; 64] }
    );
    client.written(announcement.transmit())?;
    assert!(client.pending_port().is_none());
    assert!(client.port_announced(port)?);
    assert_eq!(client.retire_unannounced_port(port), Err(Error::Conflict));
    let Inbound::Incoming {
        channel: first_incoming,
        ..
    } = client.on_response(next_source, incoming)?
    else {
        return Err(Error::Malformed);
    };
    let packet = Response::Data {
        channel: 0,
        priority: 0,
        messages: &MESSAGE,
    };
    let Inbound::Data {
        delivery: old_delivery,
        ..
    } = client.on_response(next_source, packet)?
    else {
        return Err(Error::Malformed);
    };
    let _destroyed = client.on_response(next_source, Response::ChannelDestroy { channel: 0 })?;
    let Inbound::Incoming {
        channel: replacement,
        ..
    } = client.on_response(next_source, incoming)?
    else {
        return Err(Error::Malformed);
    };
    assert_eq!(replacement.wire_id(), first_incoming.wire_id());
    assert_ne!(replacement, first_incoming);
    let Inbound::Data {
        delivery: new_delivery,
        ..
    } = client.on_response(next_source, packet)?
    else {
        return Err(Error::Malformed);
    };
    assert!(matches!(
        client.prepare_receive_done(old_delivery, &mut output),
        Err(Error::StaleGeneration)
    ));
    let ack = client
        .prepare_receive_done(new_delivery, &mut output)?
        .transmit();
    client.written(ack)?;
    Ok(())
}

#[test]
fn foreign_owners_and_resource_refusals_do_not_alias_or_consume_state() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut foreign_instance = Instance::new();
    let mut ports = [PortSlot::new(); 1];
    let mut foreign_ports = [PortSlot::new(); 1];
    let mut channels = [ChannelSlot::new(); 1];
    let mut foreign_channels = [ChannelSlot::new(); 1];
    let mut client = Client::new(
        &mut instance,
        &mut ports,
        &mut channels,
        Limits {
            max_payload_bytes: 32,
            max_send_credit: 1,
        },
    )?;
    let mut foreign = Client::new(
        &mut foreign_instance,
        &mut foreign_ports,
        &mut foreign_channels,
        Limits::default(),
    )?;
    let source = client.connected()?;
    let foreign_source = foreign.connected()?;
    assert_eq!(source.value(), foreign_source.value());
    assert_ne!(source, foreign_source);
    assert!(matches!(
        client.on_response(
            foreign_source,
            Response::Ack {
                channel: CLIENT_CHANNEL_BOUNDARY
            }
        ),
        Err(Error::StaleGeneration)
    ));
    let mut output = [0_u8; 256];
    let (foreign_channel, foreign_create) =
        foreign.prepare_channel([0; 32], [0; 64], &mut output)?;
    let foreign_tx = foreign_create.transmit();
    foreign.written(foreign_tx)?;
    assert_eq!(
        client.channel_info(foreign_channel),
        Err(Error::StaleGeneration)
    );
    assert!(client.prepare_port_open([1; 64], &mut [0xaa; 4]).is_err());
    assert!(client.pending_port().is_none());
    assert!(client.pending_transmit().is_none());
    let (port, announcement) = client.prepare_port_open([1; 64], &mut output)?;
    client.discard(announcement.transmit())?;
    assert_eq!(client.port_hash(port), Err(Error::StaleGeneration));
    let (channel, creation) = client.prepare_channel([0; 32], [0; 64], &mut output)?;
    assert_eq!(channel.wire_id(), foreign_channel.wire_id());
    assert_ne!(channel, foreign_channel);
    client.written(creation.transmit())?;
    assert!(matches!(
        client.prepare_channel([1; 32], [1; 64], &mut output),
        Err(Error::Capacity)
    ));
    let _credit = client.on_response(
        source,
        Response::Ack {
            channel: channel.wire_id(),
        },
    )?;
    assert!(matches!(
        client.on_response(
            source,
            Response::Ack {
                channel: channel.wire_id()
            }
        ),
        Err(Error::Capacity)
    ));
    assert_eq!(client.channel_info(channel)?.send_credit, 1);
    let oversized = [0_u8; 33];
    assert!(matches!(
        client.prepare_send(channel, 0, &oversized, &mut output),
        Err(Error::Capacity)
    ));
    assert_eq!(client.channel_info(channel)?.send_credit, 1);
    assert!(client.pending_transmit().is_none());
    let unsent = client
        .prepare_send(channel, 0, &MESSAGE, &mut output)?
        .transmit();
    assert_eq!(client.exposed(foreign_tx), Err(Error::StaleGeneration));
    client.discard(unsent)?;
    assert_eq!(client.channel_info(channel)?.send_credit, 1);
    Ok(())
}
