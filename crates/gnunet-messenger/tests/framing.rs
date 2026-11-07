//! One pure public mock structure model. No real signature/key, crypto hashing,
//! encryption/decryption, native actor, room state or verification is exercised.
use gnunet_messenger::{
    SensitiveBuffer,
    wire::{
        self, PublicKey, Request, Response, Room, SensitiveBytes,
        envelope::{self, Envelope, Header, Kind, ShortMessage, Signature},
        profile::Profile,
    },
};
use gnunet_types::Error;
use gnunet_wire::official::AbsoluteTime;
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The public noncrypto structural model asserts its protocol field boundaries"
)]
fn official_messenger_outer_and_coverage_model() -> Result<(), Error> {
    let key = [0; 64];
    let id = [0; 32];
    let room = Room {
        door: &id,
        key: &key,
        previous: &key,
        epoch: &key,
    };
    let mut public = [0; 36];
    public[..4].copy_from_slice(&65556u32.to_be_bytes());
    let public = PublicKey::new(&public)?;
    let mut frame = SensitiveBuffer::<1024>::new();
    frame.encode_request(Request::Open {
        room,
        public_key: Some(public),
    })?;
    assert_eq!(frame.len(), 264);
    assert_eq!(&frame.expose()[..4], &[1, 8, 6, 74]);
    assert!(matches!(
        frame.request()?,
        Request::Open {
            public_key: Some(_),
            ..
        }
    ));
    assert!(Response::decode(frame.expose(), Profile::LITTLE_255).is_err()); // replies have no appended key
    let mut signature = [0; 68];
    signature[..4].copy_from_slice(&65556u32.to_be_bytes());
    let signature = Signature::new(&signature)?;
    let header = Header {
        signature,
        timestamp: AbsoluteTime::from_micros(42),
        sender_id: &id,
        previous: &key,
        kind: Kind::TEXT,
    };
    let mut encoded = [0; 512];
    let n = envelope::encode(
        header,
        SensitiveBytes::new(b"public-mock\0\x91\x04\0"),
        &mut encoded,
    )?;
    let envelope = Envelope::decode(&encoded[..n])?;
    assert_eq!(envelope.header()?.kind, Kind::TEXT);
    assert_eq!(envelope.header()?.timestamp, AbsoluteTime::from_micros(42));
    assert_eq!(envelope.hash_input().expose(), &encoded[68..n]);
    assert_eq!(envelope.raw_body().expose(), b"public-mock\0\x91\x04\0");
    let mut purpose = [0; 72];
    envelope::signed_hash_payload(&key, &mut purpose)?;
    assert_eq!(&purpose[..8], &[0, 0, 0, 72, 0, 0, 0, 12]);
    frame.encode_request(Request::Send {
        key: &key,
        message: SensitiveBytes::new(&encoded[..n]),
    })?;
    let Request::Send { message, .. } = frame.request()? else {
        return Err(Error::Malformed);
    };
    assert_eq!(message.expose(), &encoded[..n]);
    frame.encode_response(
        Response::Receive {
            key: &key,
            sender: &key,
            context: &key,
            hash: &key,
            epoch: &key,
            flags: 0x80000001,
            message: SensitiveBytes::new(&encoded[..n]),
        },
        Profile::LITTLE_255,
    )?;
    assert_eq!(frame.len(), wire::RECV_PREFIX + n);
    let Response::Receive { flags, message, .. } = frame.response(Profile::LITTLE_255)? else {
        return Err(Error::Malformed);
    };
    assert_eq!(flags, 0x80000001);
    assert_eq!(message.expose(), &encoded[..n]);
    assert_eq!(&frame.expose()[324..328], &[0x80, 0, 0, 1]);
    assert!(matches!(
        frame.response(Profile::BIG_255)?,
        Response::Receive {
            flags: 0x80000001,
            ..
        }
    ));
    for (profile, bytes) in [
        (Profile::LITTLE_255, [1, 0, 0, 0]),
        (Profile::BIG_255, [0, 0, 0, 1]),
    ] {
        frame.encode_response(
            Response::MemberId {
                key: &key,
                id: &id,
                reset: 1,
            },
            profile,
        )?;
        assert_eq!(&frame.expose()[100..104], &bytes);
        assert!(matches!(
            frame.response(profile)?,
            Response::MemberId { reset: 1, .. }
        ));
    }
    let short_len = envelope::encode_short(
        &key,
        Kind::AUTHORIZATION,
        SensitiveBytes::new(b"opaque"),
        &mut encoded,
    )?;
    let short = ShortMessage::decode(&encoded[..short_len])?;
    assert_eq!(short.kind(), Kind::AUTHORIZATION);
    assert_eq!(short.hash_input().expose(), &encoded[64..short_len]);
    let mut small = SensitiveBuffer::<4>::new();
    small.encode_request(Request::Create)?;
    let before = small.expose().to_vec();
    assert_eq!(
        small.encode_request(Request::Get {
            key: &key,
            hash: &key
        }),
        Err(Error::Capacity)
    );
    assert_eq!(small.expose(), before);
    frame.clear();
    assert!(frame.is_empty());
    Ok(())
}
