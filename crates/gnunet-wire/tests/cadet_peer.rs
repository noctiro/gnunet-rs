//! Exact current C peer layouts; structural codecs grant no crypto authority.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible protocol tests assert independently specified C layouts"
)]
use gnunet_types::Error;
use gnunet_wire::official::{
    MessageHeader, MessageType,
    cadet_peer::{
        self, AxHeader, ChannelMessage, ConnectionInitiatorPurpose, EncryptedBody, PathPeers,
        PeerMessage,
    },
};

#[test]
fn connection_create_preserves_native_fields_and_exact_signed_monotime() -> Result<(), Error> {
    let route = [[0x11; 32], [0x22; 32]];
    let create = PeerMessage::ConnectionCreate {
        options_bytes: [2, 0, 0, 0],
        has_monotime_bytes: [1, 0, 0, 0],
        monotime: 0x0102_0304_0506_0708,
        monotime_signature: [0x44; 64],
        connection: [0x55; 32],
        path: PathPeers::new(&route),
    };
    let mut out = [0xa5; 192];
    assert_eq!(create.encoded_len()?, 180);
    assert_eq!(create.encode(&mut out)?, 180);
    assert_eq!(
        &out[..20],
        &[
            0, 180, 3, 232, 2, 0, 0, 0, 1, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8
        ]
    );
    assert_eq!(&out[20..84], &[0x44; 64]);
    assert_eq!(&out[84..116], &[0x55; 32]);
    assert_eq!(&out[116..148], &[0x11; 32]);
    assert_eq!(&out[148..180], &[0x22; 32]);
    assert_eq!(PeerMessage::decode(&out[..180])?, create);
    let purpose = ConnectionInitiatorPurpose {
        monotime: 0x0102_0304_0506_0708,
    };
    assert_eq!(purpose.encode(&mut out)?, 16);
    assert_eq!(
        &out[..16],
        &[0, 0, 0, 16, 0, 0, 0, 38, 1, 2, 3, 4, 5, 6, 7, 8]
    );
    assert_eq!(ConnectionInitiatorPurpose::decode(&out[..16])?, purpose);
    let broken = PeerMessage::ConnectionBroken {
        reserved: 0x0102_0304,
        connection: [0x11; 32],
        peer1: [0x22; 32],
        peer2: [0; 32],
    };
    assert_eq!(broken.encode(&mut out)?, 104);
    assert_eq!(&out[..8], &[0, 104, 3, 234, 1, 2, 3, 4]);
    assert_eq!(&out[40..72], &[0x22; 32]);
    assert_eq!(&out[72..104], &[0; 32]);
    assert_eq!(PeerMessage::decode(&out[..104])?, broken);
    Ok(())
}

#[test]
fn channel_plaintext_has_exact_offsets_without_private_fragment_fields() -> Result<(), Error> {
    let mut out = [0xa5; 96];
    let open = ChannelMessage::Open {
        options_bytes: [2, 0, 0, 0],
        h_port: [0x11; 64],
        channel: 0x0800_0001,
    };
    assert_eq!(open.encode(&mut out)?, 76);
    assert_eq!(&out[..8], &[0, 76, 3, 245, 2, 0, 0, 0]);
    assert_eq!(&out[8..72], &[0x11; 64]);
    assert_eq!(&out[72..76], &[8, 0, 0, 1]);
    assert_eq!(ChannelMessage::decode(&out[..76])?, open);
    let open_ack = ChannelMessage::OpenAck {
        reserved: 0x1234_5678,
        channel: 0x0800_0001,
        port: [0x22; 64],
    };
    assert_eq!(open_ack.encode(&mut out)?, 76);
    assert_eq!(
        &out[..12],
        &[0, 76, 3, 247, 0x12, 0x34, 0x56, 0x78, 8, 0, 0, 1]
    );
    assert_eq!(&out[12..76], &[0x22; 64]);
    assert_eq!(ChannelMessage::decode(&out[..76])?, open_ack);
    let data = ChannelMessage::Data {
        mid: u32::MAX,
        channel: 7,
        payload: &[0xde, 0xad, 0xbe],
    };
    assert_eq!(data.encode(&mut out)?, 15);
    assert_eq!(
        &out[..15],
        &[
            0, 15, 3, 242, 255, 255, 255, 255, 0, 0, 0, 7, 0xde, 0xad, 0xbe
        ]
    );
    assert_eq!(ChannelMessage::decode(&out[..15])?, data);
    let ack = ChannelMessage::DataAck {
        channel: 7,
        futures: 0x8000_0000_0000_0001,
        mid: 0,
    };
    assert_eq!(ack.encode(&mut out)?, 20);
    assert_eq!(
        &out[..20],
        &[
            0, 20, 3, 243, 0, 0, 0, 7, 128, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0
        ]
    );
    assert_eq!(ChannelMessage::decode(&out[..20])?, ack);
    assert_eq!(ChannelMessage::KeepAlive.encode(&mut out)?, 4);
    assert_eq!(&out[..4], &[0, 4, 3, 244]);
    assert_eq!(
        ChannelMessage::decode(&out[..4])?,
        ChannelMessage::KeepAlive
    );
    let destroy = ChannelMessage::Destroy {
        reserved: 0,
        channel: 7,
    };
    assert_eq!(destroy.encode(&mut out)?, 12);
    assert_eq!(&out[..12], &[0, 12, 3, 246, 0, 0, 0, 0, 0, 0, 0, 7]);
    assert_eq!(ChannelMessage::decode(&out[..12])?, destroy);
    Ok(())
}

#[test]
fn kx_and_encrypted_envelopes_keep_tags_aad_and_ratchet_bytes_separate() -> Result<(), Error> {
    let mut out = [0xa5; 192];
    let kx = PeerMessage::KeyExchangeAuth {
        flags: 0x8000_0001,
        connection: [0x11; 32],
        ephemeral_key: [0x22; 32],
        ratchet_key: [0x33; 32],
        auth: [0x44; 64],
    };
    assert_eq!(kx.encode(&mut out)?, 168);
    assert_eq!(&out[..8], &[0, 168, 3, 241, 128, 0, 0, 1]);
    assert_eq!(&out[8..40], &[0x11; 32]);
    assert_eq!(&out[40..72], &[0x22; 32]);
    assert_eq!(&out[72..104], &[0x33; 32]);
    assert_eq!(&out[104..168], &[0x44; 64]);
    assert_eq!(PeerMessage::decode(&out[..168])?, kx);
    let mut body = [0xee; 20];
    body[..4].copy_from_slice(&[9, 8, 7, 6]);
    let encrypted = PeerMessage::Encrypted {
        reserved: 0x0102_0304,
        connection: [0x11; 32],
        header_mac: [0x22; 16],
        encrypted_header: [0x33; 40],
        body: EncryptedBody::new(&body)?,
    };
    assert_eq!(encrypted.encode(&mut out)?, 116);
    assert_eq!(&out[..8], &[0, 116, 3, 240, 1, 2, 3, 4]);
    assert_eq!(&out[40..56], &[0x22; 16]);
    assert_eq!(&out[56..96], &[0x33; 40]);
    assert_eq!(&out[96..116], &body);
    assert_eq!(PeerMessage::decode(&out[..116])?, encrypted);
    let PeerMessage::Encrypted { body: borrowed, .. } = PeerMessage::decode(&out[..116])? else {
        return Err(Error::Malformed);
    };
    assert_eq!(borrowed.bytes().as_ptr(), out[96..].as_ptr());
    assert_eq!(borrowed.ciphertext(), &[9, 8, 7, 6]);
    assert_eq!(borrowed.mac(), &[0xee; 16]);
    let header = AxHeader {
        sent: 1,
        previous_sent: u32::MAX,
        ratchet_key: [0x55; 32],
    };
    assert_eq!(header.encode(&mut out)?, 40);
    assert_eq!(&out[..8], &[0, 0, 0, 1, 255, 255, 255, 255]);
    assert_eq!(&out[8..40], &[0x55; 32]);
    assert_eq!(AxHeader::decode(&out[..40])?, header);
    Ok(())
}

#[test]
fn malformed_lengths_and_atomic_refusals_do_not_invent_deprecated_records() -> Result<(), Error> {
    let mut out = [0xa5; 128];
    let open = ChannelMessage::Open {
        options_bytes: [2, 0, 0, 0],
        h_port: [0; 64],
        channel: 0,
    };
    assert_eq!(open.encode(&mut out[..75]), Err(Error::Capacity));
    assert_eq!(out, [0xa5; 128]);
    let huge = [0; 65524];
    assert_eq!(
        ChannelMessage::Data {
            mid: 0,
            channel: 0,
            payload: &huge
        }
        .encode(&mut out),
        Err(Error::TooLarge)
    );
    assert_eq!(out, [0xa5; 128]);
    assert_eq!(
        ConnectionInitiatorPurpose { monotime: 0 }.encode(&mut out[..15]),
        Err(Error::Capacity)
    );
    assert_eq!(out, [0xa5; 128]);
    let mut malformed_path = [0; cadet_peer::CONNECTION_CREATE_PREFIX + 1];
    MessageHeader::from_total_size(MessageType::new(1000), malformed_path.len())?
        .encode(&mut malformed_path)?;
    assert_eq!(PeerMessage::decode(&malformed_path), Err(Error::Malformed));
    let mut short_encrypted = [0; cadet_peer::ENCRYPTED_PREFIX + 19];
    MessageHeader::from_total_size(MessageType::new(1008), short_encrypted.len())?
        .encode(&mut short_encrypted)?;
    assert_eq!(PeerMessage::decode(&short_encrypted), Err(Error::Malformed));
    assert_eq!(
        PeerMessage::decode(&[0, 4, 3, 237]),
        Err(Error::Unsupported)
    ); // Deprecated 1005.
    assert_eq!(
        ChannelMessage::decode(&[0, 4, 3, 248]),
        Err(Error::Unsupported)
    ); // Deprecated 1016.
    Ok(())
}
