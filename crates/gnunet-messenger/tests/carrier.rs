//! Official room ports and preservation of signed frames through relay padding.

use gnunet_crypto::{EddsaPrivateKey, Entropy};
use gnunet_messenger::{
    carrier::{self, Prepared},
    crypto::signature,
    wire::{
        KeyType, SensitiveBytes,
        envelope::{self, Header, Kind, SIGNATURE_LEN, SIGNATURE_PURPOSE, Signature},
        message::Message,
        padding::{self, Decode, Encode},
        profile::Profile,
    },
};
use gnunet_types::Error;
use gnunet_wire::official::{AbsoluteTime, Frame, HEADER_LEN, MessageType};

struct Filler {
    calls: usize,
    result: Result<(), Error>,
}

impl Entropy for Filler {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        self.calls += 1;
        out.fill(0xa5);
        self.result
    }
}

#[test]
fn room_port_uses_the_listeners_native_word_order() {
    let mut room = [0; 64];
    room[..4].copy_from_slice(&[0xff, 0, 0, 0xff]);
    // SHA512 of the official LE major version (four zero bytes) starts EC2D5769.
    // Adding the first room word crosses a byte boundary in either order.
    let little = carrier::port(&room, Profile::LITTLE_255);
    let big = carrier::port(&room, Profile::BIG_255);
    assert_eq!(&little[..4], &[0xeb, 0x2e, 0x57, 0x68]);
    assert_eq!(&big[..4], &[0xeb, 0x2d, 0x58, 0x68]);
    assert_eq!(&little[4..], &big[4..]);
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The carrier contract asserts byte preservation and fallible output boundaries"
)]
fn repacking_preserves_the_original_signature_with_a_smaller_carrier()
-> Result<(), gnunet_messenger::crypto::Error> {
    const CARRIER_BYTES: usize = 256;
    let key = EddsaPrivateKey::from_seed([0x24; 32]);
    let mut tagged = [0; SIGNATURE_LEN];
    tagged[..4].copy_from_slice(&KeyType::Eddsa.value().to_be_bytes());
    let mut raw = [0; CARRIER_BYTES];
    let original_len = envelope::encode(
        Header {
            signature: Signature::new(&tagged)?,
            timestamp: AbsoluteTime::from_micros(42),
            sender_id: &[0x62; 32],
            previous: &[0x37; 64],
            kind: Kind::TEXT,
        },
        SensitiveBytes::new(b"shared carrier"),
        &mut raw,
    )?;
    let draft = Message::decode(&raw[..original_len], Profile::LITTLE_255, Decode::Absent)?;
    let hash = signature::message_hash(draft);
    let signed = key.sign(SIGNATURE_PURPOSE, &signature::signing_payload(&hash)?)?;
    raw[4..SIGNATURE_LEN].copy_from_slice(signed.as_bytes());
    let original_padded_len = padding::write(
        original_len,
        Encode::ToLength {
            total: original_len + 11,
            noise: SensitiveBytes::new(&[0x51; 8]),
        },
        Profile::LITTLE_255,
        &mut raw,
    )?;
    let original = Message::decode(
        &raw[..original_padded_len],
        Profile::LITTLE_255,
        Decode::Required,
    )?;
    let minimum = carrier::minimum_frame_len(original);
    assert_eq!(minimum, HEADER_LEN + original_len + 3);
    assert!(matches!(
        Prepared::new(original, Profile::BIG_255, minimum - 1),
        Err(Error::TooLarge)
    ));
    let prepared = Prepared::new(original, Profile::BIG_255, CARRIER_BYTES)?;
    assert_eq!(prepared.encoded_len(), CARRIER_BYTES);

    let mut filler = Filler {
        calls: 0,
        result: Err(Error::NotReady),
    };
    let mut output = [0xbb; CARRIER_BYTES + 8];
    assert_eq!(
        prepared.encode_into(&mut output[..CARRIER_BYTES - 1], &mut filler),
        Err(Error::Capacity)
    );
    assert_eq!(filler.calls, 0);
    assert_eq!(output, [0xbb; CARRIER_BYTES + 8]);
    assert_eq!(
        prepared.encode_into(&mut output, &mut filler),
        Err(Error::NotReady)
    );
    assert_eq!(filler.calls, 1);
    assert_eq!(&output[..CARRIER_BYTES], &[0; CARRIER_BYTES]);
    assert_eq!(&output[CARRIER_BYTES..], &[0xbb; 8]);

    filler.result = Ok(());
    assert_eq!(
        prepared.encode_into(&mut output, &mut filler)?,
        CARRIER_BYTES
    );
    let (frame, suffix) = Frame::decode_prefix(&output)?;
    assert_eq!(&output[..HEADER_LEN], &[1, 0, 0x04, 0x23]);
    assert_eq!(suffix, &[0xbb; 8]);
    let payload = carrier::decode(frame)?.expose();
    assert_eq!(&payload[..original_len], &raw[..original_len]);
    let repacked = Message::decode_with_profiles(
        payload,
        Profile::LITTLE_255,
        Profile::BIG_255,
        Decode::Required,
    )?;
    let proof = signature::verify_peer(repacked, key.public_key().as_bytes())?;
    assert_eq!(proof.digest(), &hash);
    let footer = repacked.padding().expose();
    assert_eq!(footer[0], 0);
    assert!(footer[1..footer.len() - 2].iter().all(|&byte| byte == 0xa5));
    assert!(matches!(
        carrier::decode(Frame::new(MessageType::new(0), payload)?),
        Err(Error::Unsupported)
    ));
    Ok(())
}
