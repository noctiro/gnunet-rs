//! Vectors emitted by normal unmodified GNUnet v0.29.1 shared libraries.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Independent reference and rejection assertions."
)]
use gnunet_crypto::gns::{EdkeySecret, PkeySecret};
use gnunet_gnscrypto::{Block, Label, ZoneSecret, query};
use gnunet_gnsrecord::{ZoneKey, ZoneKeyType};
use gnunet_types::Error;

fn vector(
    case: &str,
    owner: ZoneSecret,
    input_label: &[u8],
    expected_zone: &[u8],
    expected_block: &[u8],
    expected_records: &[u8],
    expected_query: &[u8],
) -> Result<(), Error> {
    let mut scalars = ['\0'; 256];
    let mut label_storage = [0; 256];
    let label = Label::normalize(
        core::str::from_utf8(input_label).map_err(|_| Error::Malformed)?,
        &mut scalars,
        &mut label_storage,
    )?;
    let zone = ZoneKey::from_wire(expected_zone)?;
    assert_eq!(owner.public_key(), zone);
    let decoded = Block::decode(expected_block)?;
    let expiry = decoded.expiration()?;
    let mut output = [0xa5; 512];
    let sealed = owner.seal(label, expiry, expected_records, &mut output)?;
    assert_eq!(sealed.as_bytes(), expected_block);
    if let Ok(directory) = std::env::var("GNUNET_GNS_VECTOR_OUTPUT") {
        let directory = std::path::Path::new(&directory);
        std::fs::write(
            directory.join(std::format!("{case}.block")),
            sealed.as_bytes(),
        )
        .map_err(|_| Error::Io)?;
        std::fs::write(
            directory.join(std::format!("{case}.records")),
            expected_records,
        )
        .map_err(|_| Error::Io)?;
        std::fs::write(directory.join(std::format!("{case}.zone")), expected_zone)
            .map_err(|_| Error::Io)?;
        std::fs::write(directory.join(std::format!("{case}.label")), input_label)
            .map_err(|_| Error::Io)?;
    }
    assert_eq!(
        &output[expected_block.len()..],
        &[0xa5; 512][expected_block.len()..]
    );
    assert_eq!(query(zone, label)?.as_slice(), expected_query);
    assert_eq!(decoded.query()?.as_slice(), expected_query);
    let verified = decoded.verify_for(zone, label)?;
    let mut plaintext = [0xa5; 512];
    let opened = verified.open_at(expiry, &mut plaintext)?;
    let mut count = 0;
    for record in opened.iter() {
        let record = record?;
        assert_eq!(record.expiration_time, expiry);
        count += 1;
    }
    assert_eq!(count, 2);
    assert_eq!(&plaintext[..expected_records.len()], expected_records);
    assert_eq!(
        &plaintext[expected_records.len()..],
        &[0xa5; 512][expected_records.len()..]
    );
    assert!(matches!(
        verified.open_at(expiry + 1, &mut plaintext),
        Err(Error::Timeout)
    ));
    let mut too_small = [0xa5; 1];
    assert!(matches!(
        verified.open_at(0, &mut too_small),
        Err(Error::Capacity)
    ));
    assert_eq!(too_small, [0xa5; 1]);
    let mut wrong_label_storage = [0; 20];
    let wrong_label = Label::normalize("wrong", &mut scalars, &mut wrong_label_storage)?;
    assert!(matches!(
        decoded.verify_for(zone, wrong_label),
        Err(Error::Authentication)
    ));
    let other_type = if zone.kind() == ZoneKeyType::Pkey {
        ZoneKeyType::Edkey
    } else {
        ZoneKeyType::Pkey
    };
    assert!(matches!(
        decoded.verify_for(ZoneKey::new(other_type, *zone.key()), label),
        Err(Error::Authentication)
    ));
    assert!(matches!(
        decoded.verify_for(ZoneKey::new(zone.kind(), [0; 32]), label),
        Err(Error::Authentication)
    ));
    for length in 0..expected_block.len() {
        assert!(Block::decode(&expected_block[..length]).is_err());
    }
    // Every stored byte is either exact structural framing, authenticated data,
    // or a zone/name-bound signing key. No changed byte may produce plaintext.
    for index in 0..expected_block.len() {
        let mut corrupted = [0; 512];
        corrupted[..expected_block.len()].copy_from_slice(expected_block);
        corrupted[index] ^= 1;
        if let Ok(block) = Block::decode(&corrupted[..expected_block.len()]) {
            assert!(
                block.verify_for(zone, label).is_err(),
                "accepted mutation at {index}"
            );
        }
    }
    Ok(())
}
macro_rules! check_vector {
    ($case:literal, $owner:expr) => {
        vector(
            $case,
            $owner,
            include_bytes!(concat!("fixtures/", $case, "-label_input.bin")),
            include_bytes!(concat!("fixtures/", $case, "-zone.bin")),
            include_bytes!(concat!("fixtures/", $case, "-block.bin")),
            include_bytes!(concat!("fixtures/", $case, "-rdata.bin")),
            include_bytes!(concat!("fixtures/", $case, "-query.bin")),
        )?;
    };
}
#[test]
fn both_official_zone_suites_match_complete_c_blocks() -> Result<(), Error> {
    check_vector!(
        "pkey_ascii",
        ZoneSecret::Pkey(PkeySecret::from_bytes(*include_bytes!(
            "fixtures/pkey_ascii-private_input.bin"
        ))?)
    );
    check_vector!(
        "edkey_ascii",
        ZoneSecret::Edkey(EdkeySecret::from_seed(*include_bytes!(
            "fixtures/edkey_ascii-private_input.bin"
        )))
    );
    check_vector!(
        "pkey_nfc",
        ZoneSecret::Pkey(PkeySecret::from_bytes(*include_bytes!(
            "fixtures/pkey_nfc-private_input.bin"
        ))?)
    );
    check_vector!(
        "edkey_nfc",
        ZoneSecret::Edkey(EdkeySecret::from_seed(*include_bytes!(
            "fixtures/edkey_nfc-private_input.bin"
        )))
    );
    Ok(())
}
