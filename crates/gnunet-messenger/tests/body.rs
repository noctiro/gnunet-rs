//! One public opaque structure model for actual28 bodies/records/profiles.
//! Zero arrays are fabricated public tags/ciphertext, never actual private keys
//! or cryptographic acceptance vectors. No hashing/signing/encryption occurs.
use gnunet_messenger::{
    SensitiveBuffer,
    wire::{
        PublicKey, SensitiveBytes,
        body::{Body, Text},
        envelope::{self, Header, Kind, Signature},
        keys::{HpkeCiphertext, HpkePublicKey},
        message,
        padding::{self, Decode, Encode},
        profile::Profile,
        records::Record,
    },
};
use gnunet_types::Error;
use gnunet_wire::official::{AbsoluteTime, RelativeTime};
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The public noncrypto structural model asserts its protocol field boundaries"
)]
fn all_body_fields_record_bytes_and_padding_coverage() -> Result<(), Error> {
    let profile = Profile::LITTLE_255;
    let h64 = [0; 64];
    let a32 = [0; 32];
    let nonce24 = [0; 24];
    let mac16 = [0; 16];
    let access80 = [0; 80];
    let file_name = [0; 255];
    let mut raw_key = [0; 36];
    raw_key[..4].copy_from_slice(&65556u32.to_be_bytes());
    let public_key = PublicKey::new(&raw_key)?;
    let hpke_raw = [0; 36];
    let hpke_key = HpkePublicKey::new(&hpke_raw)?;
    let text = Text::new(b"demo")?;
    let bodies = [
        Body::Info {
            version: 0x11223344,
        },
        Body::Join {
            epoch: &h64,
            public_key,
            hpke_key,
        },
        Body::Leave { epoch: &h64 },
        Body::Name { name: text },
        Body::Key {
            public_key,
            hpke_key,
        },
        Body::Peer { peer: &a32 },
        Body::Id { id: &a32 },
        Body::Miss { peer: &a32 },
        Body::Merge {
            first_epoch: &h64,
            second_epoch: &h64,
            previous: &h64,
        },
        Body::Request { hash: &h64 },
        Body::Invite {
            door: &a32,
            room_key: &h64,
        },
        Body::Text { text },
        Body::File {
            hash: &h64,
            name: SensitiveBytes::new(&file_name),
            uri: text,
        },
        Body::Private {
            data: SensitiveBytes::new(b"data"),
        },
        Body::Deletion {
            hash: &h64,
            delay: RelativeTime::from_micros(0x0102030405060708),
        },
        Body::Connection {
            amount: 0x11223344,
            flags: 0x11223344,
        },
        Body::Ticket { identifier: text },
        Body::Transcript {
            hash: &h64,
            recipient_key: public_key,
            data: SensitiveBytes::new(b"data"),
        },
        Body::Tag {
            hash: &h64,
            tag: text,
        },
        Body::Subscription {
            discourse: &a32,
            time: RelativeTime::from_micros(0x0102030405060708),
            flags: 0x11223344,
        },
        Body::Talk {
            discourse: &a32,
            data: SensitiveBytes::new(b"data"),
        },
        Body::Announcement {
            identifier: &a32,
            public_key: &a32,
            nonce: &a32,
            timeout: RelativeTime::from_micros(0x0102030405060708),
            hmac: &h64,
        },
        Body::Secret {
            identifier: &a32,
            nonce: &nonce24,
            mac: &mac16,
            data: SensitiveBytes::new(b"data"),
        },
        Body::Appeal {
            event: &h64,
            public_key: &a32,
            timeout: RelativeTime::from_micros(0x0102030405060708),
        },
        Body::Access {
            event: &h64,
            encrypted_key: &access80,
            hmac: &h64,
        },
        Body::Revolution {
            identifier: &a32,
            nonce: &a32,
            hmac: &h64,
        },
        Body::Group {
            identifier: &a32,
            initiator: &h64,
            partner: &h64,
            timeout: RelativeTime::from_micros(0x0102030405060708),
        },
        Body::Authorization {
            identifier: &a32,
            event: &h64,
            encrypted_key: &a32,
            hmac: &h64,
        },
    ];
    let expected = [
        4, 136, 64, 4, 72, 32, 32, 32, 192, 64, 96, 4, 323, 4, 72, 8, 4, 104, 68, 44, 36, 168, 76,
        104, 208, 128, 168, 192,
    ];
    for (i, body) in bodies.into_iter().enumerate() {
        assert_eq!(
            body.kind().value(),
            u32::try_from(i + 1).map_err(|_| Error::Overflow)?
        );
        let mut bytes = [0; 512];
        let n = body.encode(profile, &mut bytes)?;
        assert_eq!(n, expected[i]);
        let decoded = Body::decode(body.kind(), &bytes[..n], profile)?;
        let mut round = [0; 512];
        let m = decoded.encode(profile, &mut round)?;
        assert_eq!(&round[..m], &bytes[..n]);
    }
    // The actual producer's kind28 omits its C struct mac16: exactly192 bytes.
    assert_eq!(bodies[27].encoded_len(profile)?, 192);
    assert!(Text::new(b"not\0canonical").is_err());
    let c = Text::from_encoded(b"first\0suffix");
    assert_eq!(c.content().expose(), b"first");
    assert_eq!(c.encoded().expose(), b"first\0suffix");
    let extra = [0, 0, 0, 8, 1];
    let parsed = Body::decode_prefix(Kind::INFO, &extra, profile)?;
    assert_eq!(parsed.consumed, 4);
    assert_eq!(parsed.trailing.expose(), &[1]);
    assert!(Body::decode(Kind::INFO, &extra, profile).is_err());
    let mut raw_sig = [0; 68];
    raw_sig[..4].copy_from_slice(&65556u32.to_be_bytes());
    let sig = Signature::new(&raw_sig)?;
    let header = Header {
        signature: sig,
        timestamp: AbsoluteTime::from_micros(1),
        sender_id: &a32,
        previous: &h64,
        kind: Kind::INFO,
    };
    let body = Body::Info { version: 8 };
    let noise = [0; 512];
    let mut owned = SensitiveBuffer::<1024>::new();
    owned.encode_message(
        header,
        body,
        profile,
        Encode::ToLength {
            total: 512,
            noise: SensitiveBytes::new(&noise[..329]),
        },
    )?;
    let signed = owned.message(profile, Decode::Required)?;
    assert_eq!(signed.padding().len(), 332);
    assert_eq!(signed.hash_input().len(), 112);
    assert_eq!(signed.original().hash_input().len(), 444);
    assert_eq!(&owned.expose()[510..512], &332u16.to_le_bytes());
    assert!(message::Message::decode(owned.expose(), Profile::BIG_255, Decode::Required).is_err());
    owned.encode_short(
        &h64,
        body,
        profile,
        Encode::ToLength {
            total: 512,
            noise: SensitiveBytes::new(&noise[..437]),
        },
    )?;
    let short = owned.short(profile, Decode::Required)?;
    assert_eq!(short.padding().len(), 440);
    assert_eq!(short.hash_input().len(), 448);
    assert_eq!(padding::rounded_length(72, 48, profile)?, 512);
    assert_eq!(padding::usual_minimum(profile)?, 430);
    let mut bad = [0; 180];
    envelope::encode(header, SensitiveBytes::new(&[0, 0, 3, 0]), &mut bad)?;
    assert!(matches!(
        message::Message::decode(&bad, profile, Decode::Detect),
        Err(Error::Truncated)
    ));
    let cipher = [0; 80];
    let packet = HpkeCiphertext::new(SensitiveBytes::new(&cipher))?;
    assert_eq!(packet.encapsulation()?.len(), 32);
    assert_eq!(packet.ciphertext().len(), 32);
    assert_eq!(packet.tag()?.len(), 16);
    assert!(HpkeCiphertext::new(SensitiveBytes::new(b"short")).is_err());
    let name256 = [0; 256];
    let encrypted = [0; 516];
    let records = [
        Record::RoomEntry {
            door: &a32,
            room_key: &h64,
        },
        Record::RoomDetails {
            name: &name256,
            flags: 0x01020304,
        },
        Record::EpochKey {
            room_key: &h64,
            epoch: &h64,
            identifier: &a32,
            nonce: &nonce24,
            mac: &mac16,
            encrypted_shared_key: &a32,
            flags: 0x01020304,
        },
        Record::EncryptionKey {
            room_key: &h64,
            nonce: &nonce24,
            mac: &mac16,
            encrypted_key_length: 36,
            encrypted_private_data: &encrypted,
        },
    ];
    for record in records {
        owned.encode_record(record, profile)?;
        let decoded = Record::decode(record.record_type(), owned.expose(), profile)?;
        let mut round = [0; 1024];
        let n = decoded.encode(profile, &mut round)?;
        assert_eq!(&round[..n], owned.expose());
    }
    owned.encode_record(records[2], profile)?;
    assert_eq!(&owned.expose()[232..236], &[4, 3, 2, 1]);
    owned.encode_record(records[2], Profile::BIG_255)?;
    assert_eq!(&owned.expose()[232..236], &[1, 2, 3, 4]);
    let invalid = Record::EncryptionKey {
        room_key: &h64,
        nonce: &nonce24,
        mac: &mac16,
        encrypted_key_length: 517,
        encrypted_private_data: &encrypted,
    };
    let mut untouched = [0x55; 624];
    assert!(invalid.encode(profile, &mut untouched).is_err());
    assert_eq!(untouched, [0x55; 624]);
    owned.clear();
    assert!(owned.is_empty());
    Ok(())
}
