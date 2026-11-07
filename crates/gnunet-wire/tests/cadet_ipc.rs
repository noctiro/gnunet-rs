//! Exact current C CADET IPC offsets, direction and meaningful rejection cases.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible protocol tests assert independently specified C layouts"
)]
use gnunet_types::Error;
use gnunet_wire::official::{
    MessageHeader, MessageType,
    cadet::{self, PeerIdentities, Request, Response},
};

#[test]
fn channel_ipc_matches_current_c_layout_and_id_direction() -> Result<(), Error> {
    let mut out = [0xa5; 112];
    let open = Request::PortOpen { port: [0x44; 64] };
    assert_eq!(open.encode(&mut out)?, 68);
    assert_eq!(&out[..4], &[0, 68, 3, 254]);
    assert_eq!(&out[4..68], &[0x44; 64]);
    assert_eq!(Request::decode(&out[..68])?, open);
    assert_eq!(
        Request::PortClose { port: [0x44; 64] }.encode(&mut out)?,
        68
    );
    assert_eq!(&out[..4], &[0, 68, 3, 255]);

    let create = Request::ChannelCreate {
        channel: cadet::CLIENT_CHANNEL_BOUNDARY,
        peer: [0x11; 32],
        port: [0x22; 64],
        options: 0x0102_0304,
    };
    assert_eq!(create.encoded_len()?, 108);
    assert_eq!(create.encode(&mut out)?, 108);
    assert_eq!(&out[..8], &[0, 108, 4, 0, 128, 0, 0, 0]);
    assert_eq!(&out[8..40], &[0x11; 32]);
    assert_eq!(&out[40..104], &[0x22; 64]);
    assert_eq!(&out[104..108], &[1, 2, 3, 4]);
    assert_eq!(Request::decode(&out[..108])?, create);
    assert_eq!(Response::decode(&out[..108]), Err(Error::Malformed));
    out[4..8].copy_from_slice(&[0, 0, 0, 0]);
    assert_eq!(Request::decode(&out[..108]), Err(Error::Malformed));
    let incoming = Response::ChannelCreate {
        channel: 0,
        peer: [0x11; 32],
        port: [0x22; 64],
        options: 0x0102_0304,
    };
    assert_eq!(Response::decode(&out[..108])?, incoming);

    assert_eq!(
        Request::Ack {
            channel: 0x1234_5678
        }
        .encode(&mut out)?,
        8
    );
    assert_eq!(&out[..8], &[0, 8, 3, 253, 0x12, 0x34, 0x56, 0x78]);
    assert_eq!(
        Response::decode(&out[..8])?,
        Response::Ack {
            channel: 0x1234_5678
        }
    );
    assert_eq!(
        Response::ChannelDestroy {
            channel: 0x8000_0001
        }
        .encode(&mut out)?,
        8
    );
    assert_eq!(&out[..8], &[0, 8, 4, 1, 128, 0, 0, 1]);
    assert_eq!(
        Request::decode(&out[..8])?,
        Request::ChannelDestroy {
            channel: 0x8000_0001
        }
    );
    Ok(())
}

#[test]
fn data_preserves_complete_messages_and_rejects_before_writing() -> Result<(), Error> {
    let messages = [0, 4, 0, 140, 0, 8, 0, 141, 1, 2, 3, 4];
    let mut out = [0xa5; 64];
    let request = Request::Data {
        channel: 0x8000_0000,
        priority: u32::MAX,
        messages: &messages,
    };
    assert_eq!(request.encode(&mut out)?, 24);
    assert_eq!(
        &out[..12],
        &[0, 24, 3, 252, 128, 0, 0, 0, 255, 255, 255, 255]
    );
    assert_eq!(&out[12..24], &messages);
    assert_eq!(Request::decode(&out[..24])?, request);
    assert_eq!(
        Response::decode(&out[..24])?,
        Response::Data {
            channel: 0x8000_0000,
            priority: u32::MAX,
            messages: &messages,
        }
    );
    assert_eq!(
        Request::Data {
            channel: 7,
            priority: 0,
            messages: &[]
        }
        .encode(&mut out)?,
        12
    );
    assert_eq!(
        Request::decode(&out[..12])?,
        Request::Data {
            channel: 7,
            priority: 0,
            messages: &[]
        }
    );
    assert_eq!(Response::decode(&out[..12]), Err(Error::Malformed));

    out.fill(0xa5);
    let malformed = Request::Data {
        channel: 7,
        priority: 0,
        messages: &[0, 5, 0, 140],
    };
    assert_eq!(malformed.encode(&mut out), Err(Error::Truncated));
    assert_eq!(out, [0xa5; 64]);
    assert_eq!(request.encode(&mut out[..23]), Err(Error::Capacity));
    assert_eq!(out, [0xa5; 64]);
    assert_eq!(cadet::MAX_APPLICATION_MESSAGE_SIZE, 64_348);
    let mut oversized = [0; cadet::MAX_APPLICATION_MESSAGE_SIZE + 1];
    MessageHeader::from_total_size(MessageType::new(140), oversized.len())?
        .encode(&mut oversized)?;
    assert_eq!(
        Request::Data {
            channel: 7,
            priority: 0,
            messages: &oversized
        }
        .encode(&mut out),
        Err(Error::TooLarge)
    );
    assert_eq!(out, [0xa5; 64]);
    Ok(())
}

#[test]
fn monitor_layouts_preserve_raw_state_and_real_end_records() -> Result<(), Error> {
    let mut out = [0xa5; 128];
    let peer = Response::PeerInfo {
        paths: 0x1234,
        tunnel: -1,
        best_path_length: 0x0102_0304,
        peer: [0x33; 32],
    };
    assert_eq!(peer.encode(&mut out)?, 44);
    assert_eq!(
        &out[..12],
        &[0, 44, 4, 10, 0x12, 0x34, 255, 255, 1, 2, 3, 4]
    );
    assert_eq!(&out[12..44], &[0x33; 32]);
    assert_eq!(Response::decode(&out[..44])?, peer);
    let peers = [[0x11; 32], [0x22; 32]];
    let path = Response::PathInfo {
        offset: 99,
        peers: PeerIdentities::new(&peers),
    };
    assert_eq!(path.encode(&mut out)?, 72);
    assert_eq!(&out[..8], &[0, 72, 4, 13, 0, 0, 0, 99]);
    assert_eq!(&out[8..40], &[0x11; 32]);
    assert_eq!(&out[40..72], &[0x22; 32]);
    assert_eq!(Response::decode(&out[..72])?, path);
    let tunnel = Response::TunnelInfo {
        channels: 0x0102_0304,
        peer: [0x55; 32],
        connections: 0x0506_0708,
        encryption_state: 0xabcd,
        connection_state: 0x1234,
    };
    assert_eq!(tunnel.encode(&mut out)?, 48);
    assert_eq!(&out[..8], &[0, 48, 4, 16, 1, 2, 3, 4]);
    assert_eq!(&out[40..48], &[5, 6, 7, 8, 0xab, 0xcd, 0x12, 0x34]);
    assert_eq!(Response::decode(&out[..48])?, tunnel);
    for (end, code) in [
        (Response::PeersEnd, 11),
        (Response::PathsEnd, 14),
        (Response::TunnelsEnd, 17),
        (Response::ChannelsEnd, 8),
    ] {
        assert_eq!(end.encode(&mut out)?, 4);
        assert_eq!(&out[..4], &[0, 4, 4, code]);
        assert_eq!(Response::decode(&out[..4])?, end);
    }
    assert_eq!(Request::GetPath { peer: [0x55; 32] }.encode(&mut out)?, 40);
    assert_eq!(&out[..8], &[0, 40, 4, 12, 0, 0, 0, 0]);
    out[7] = 1;
    assert_eq!(Request::decode(&out[..40]), Err(Error::Malformed));
    let invalid_path = [0, 9, 4, 13, 0, 0, 0, 0, 1];
    assert_eq!(Response::decode(&invalid_path), Err(Error::Malformed));
    Ok(())
}

#[test]
fn native_test_type_and_unspecified_channel_tail_are_lossless() -> Result<(), Error> {
    let mut out = [0xa5; 128];
    // The sole native-order field remains opaque: these are little-endian
    // uint16_t(1007), while the unaligned channel at byte 6 remains BE32.
    let drop = Request::DropMessage {
        channel: 0x8000_0001,
        message_type_bytes: [0xef, 3],
    };
    assert_eq!(drop.encode(&mut out)?, 10);
    assert_eq!(&out[..10], &[0, 10, 4, 18, 0xef, 3, 128, 0, 0, 1]);
    assert_eq!(Request::decode(&out[..10])?, drop);
    let info = Response::ChannelInfo {
        root: [0x11; 32],
        destination: [0x22; 32],
        extra: &[0xab, 0xcd],
    };
    assert_eq!(info.encode(&mut out)?, 70);
    assert_eq!(&out[..4], &[0, 70, 4, 7]);
    assert_eq!(&out[68..70], &[0xab, 0xcd]);
    assert_eq!(Response::decode(&out[..70])?, info);
    Ok(())
}
