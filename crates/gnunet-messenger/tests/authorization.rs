//! Independent official-utility byte fixture and adversarial body authentication.
//! Header signatures below are structural placeholders; no signer is certified.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fixed reference vectors and adversarial authentication outcomes are asserted"
)]
use gnunet_messenger::{
    SensitiveBuffer,
    crypto::{
        AeadKey, Error,
        group::{self, Authorization},
    },
    wire::{
        body::Body,
        envelope::{Header, Kind, Signature},
        message::Message,
        padding::{Decode, Encode},
        profile::Profile,
    },
};
use gnunet_types::Error as Fault;
use gnunet_wire::official::AbsoluteTime;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn decode_hex<const N: usize>(text: &str) -> Result<[u8; N]> {
    assert_eq!(text.len(), N * 2);
    let mut output = [0; N];
    for (byte, pair) in output.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
    }
    Ok(output)
}

fn message<'a>(body: Body<'_>, output: &'a mut SensitiveBuffer<512>) -> Result<Message<'a>> {
    let mut signature = [0; 68];
    signature[..4].copy_from_slice(&65556u32.to_be_bytes());
    output.encode_message(
        Header {
            signature: Signature::new(&signature)?,
            timestamp: AbsoluteTime::from_micros(1),
            sender_id: &[0; 32],
            previous: &[0; 64],
            kind: body.kind(),
        },
        body,
        Profile::LITTLE_255,
        Encode::Absent,
    )?;
    Ok(output.message(Profile::LITTLE_255, Decode::Absent)?)
}

fn fixture() -> Result<([u8; 192], AeadKey, AeadKey)> {
    // GNUnet14698f19848af867f48a04521e274abd55972075 normal utility
    // HKDF/AEAD/HMAC functions, with Messenger's exact C struct-prefix coverage.
    let identifier: [u8; 32] = core::array::from_fn(|i| i as u8);
    let event: [u8; 64] = core::array::from_fn(|i| 64 + i as u8);
    let ciphertext =
        decode_hex::<32>("b5c6a9d7032f7814947d49a9fe33e2c2a4af251691720fe9db4260f940877571")?;
    let hmac = decode_hex::<64>(
        "adf3ae68ea1ab77adaef0e3d46b805528023ae4d7bb9e3ffe7ebd2ff5737fbaed4993a925395b9403339341f5020038b311c876f24658a865f6f295912475579",
    )?;
    let mut output = [0; 192];
    Body::Authorization {
        identifier: &identifier,
        event: &event,
        encrypted_key: &ciphertext,
        hmac: &hmac,
    }
    .encode(Profile::LITTLE_255, &mut output)?;
    Ok((
        output,
        AeadKey::from_bytes(core::array::from_fn(|i| 128 + i as u8)),
        AeadKey::from_bytes(core::array::from_fn(|i| 192 + i as u8)),
    ))
}

#[test]
fn official_utility_fixture_recovers_key_and_matches_exact_transmitted_fields() -> Result {
    let (wire, wrapping, shared) = fixture()?;
    let body = Body::decode(Kind::AUTHORIZATION, &wire, Profile::LITTLE_255)?;
    let Body::Authorization {
        identifier, event, ..
    } = body
    else {
        return Err("wrong fixture kind".into());
    };
    let sealed = Authorization::seal(identifier, event, &wrapping, &shared)?;
    let mut encoded = [0; 192];
    assert_eq!(
        sealed.body().encode(Profile::LITTLE_255, &mut encoded)?,
        192
    );
    assert_eq!(
        encoded, wire,
        "official producer fields, including the carried HMAC"
    );
    let mut storage = SensitiveBuffer::new();
    let received = message(body, &mut storage)?;
    assert!(group::open_authorization(received, &wrapping)?.constant_time_eq(&shared));
    group::verify_authorization(received, &wrapping, &shared)?;
    assert!(matches!(
        group::verify_mac(received, &shared),
        Err(Error::GroupKeyRequired)
    ));
    Ok(())
}

#[test]
fn every_carried_byte_and_incorrect_key_is_rejected_before_key_release() -> Result {
    let (wire, wrapping, shared) = fixture()?;
    let wrong = AeadKey::from_bytes([0x35; 32]);
    let mut storage = SensitiveBuffer::new();
    for index in 0..wire.len() {
        let mut damaged = wire;
        damaged[index] ^= 1;
        let received = message(
            Body::decode(Kind::AUTHORIZATION, &damaged, Profile::LITTLE_255)?,
            &mut storage,
        )?;
        assert!(
            matches!(
                group::open_authorization(received, &wrapping),
                Err(Error::Protocol(Fault::Authentication))
            ),
            "changed byte {index}"
        );
        assert!(
            matches!(
                group::verify_authorization(received, &wrapping, &shared),
                Err(Error::Protocol(Fault::Authentication))
            ),
            "changed byte {index} with a known key"
        );
    }
    let received = message(
        Body::decode(Kind::AUTHORIZATION, &wire, Profile::LITTLE_255)?,
        &mut storage,
    )?;
    assert!(matches!(
        group::open_authorization(received, &wrong),
        Err(Error::Protocol(Fault::Authentication))
    ));
    assert!(matches!(
        group::verify_authorization(received, &wrapping, &wrong),
        Err(Error::Protocol(Fault::Authentication))
    ));
    let other = message(Body::Info { version: 8 }, &mut storage)?;
    assert!(matches!(
        group::open_authorization(other, &wrapping),
        Err(Error::Protocol(Fault::InvalidInput))
    ));
    Ok(())
}
