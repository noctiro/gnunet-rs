//! NSE flooding structural boundaries, opaque proof bytes and exact signed span.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Test assertions report contract violations"
)]
use gnunet_types::Error;
use gnunet_wire::official::{AbsoluteTime, nse::flood};

fn fields() -> flood::Fields {
    flood::Fields {
        hops: 0x1020_3040,
        timestamp: AbsoluteTime::from_micros(0x0102_0304_0506_0708),
        matching_bits: 0x5060_7080,
        origin: core::array::from_fn(|i| i as u8),
        proof: [0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
        signature: core::array::from_fn(|i| (255 - i) as u8),
    }
}

#[test]
fn exact_fields_endian_and_original_signed_span() -> Result<(), Error> {
    let value = fields();
    let mut output = [0xa5; 136];
    assert_eq!(value.encode(&mut output)?, 132);
    assert_eq!(
        output[..28],
        [
            0, 132, 1, 66, 0x10, 0x20, 0x30, 0x40, 0, 0, 0, 60, 0, 0, 0, 14, 1, 2, 3, 4, 5, 6, 7,
            8, 0x50, 0x60, 0x70, 0x80
        ]
    );
    assert_eq!(output[60..68], value.proof);
    assert_eq!(output[68..132], value.signature);
    assert_eq!(output[132..], [0xa5; 4]);
    let decoded = flood::Message::decode(&output[..132])?;
    assert_eq!(decoded.fields()?, value);
    assert_eq!(decoded.bytes().as_ptr(), output.as_ptr());
    assert_eq!(decoded.signed_bytes().as_ptr(), output[8..].as_ptr());
    let mut signed = [0xb6; 64];
    assert_eq!(value.encode_signed(&mut signed)?, 60);
    assert_eq!(&signed[..60], decoded.signed_bytes());
    assert_eq!(signed[60..], [0xb6; 4]);
    Ok(())
}

#[test]
fn changing_hops_or_signature_preserves_exact_signed_bytes() -> Result<(), Error> {
    let mut a = [0; 132];
    let mut b = [0; 132];
    let value = fields();
    value.encode(&mut a)?;
    flood::Fields {
        hops: u32::MAX,
        signature: [0; 64],
        ..value
    }
    .encode(&mut b)?;
    assert_ne!(a, b);
    assert_eq!(
        flood::Message::decode(&a)?.signed_bytes(),
        flood::Message::decode(&b)?.signed_bytes()
    );
    for at in [16, 23, 24, 27, 28, 59, 60, 67] {
        b = a;
        b[at] ^= 1;
        assert_ne!(
            flood::Message::decode(&a)?.signed_bytes(),
            flood::Message::decode(&b)?.signed_bytes()
        );
    }
    Ok(())
}

#[test]
fn malformed_envelopes_and_purpose_prefixes_rejected() -> Result<(), Error> {
    let mut original = [0; 132];
    fields().encode(&mut original)?;
    for length in 0..132 {
        assert!(flood::Message::decode(&original[..length]).is_err());
    }
    let mut extra = [0; 133];
    extra[..132].copy_from_slice(&original);
    assert!(flood::Message::decode(&extra).is_err());
    extra[..2].copy_from_slice(&133u16.to_be_bytes());
    assert!(flood::Message::decode(&extra).is_err());
    for at in [0, 1, 2, 3, 8, 11, 12, 15] {
        let mut bad = original;
        bad[at] ^= 1;
        assert!(flood::Message::decode(&bad).is_err());
    }
    Ok(())
}

#[test]
fn capacity_refusal_is_atomic_for_entire_output() {
    for length in 0..132 {
        let mut output = [0xa5; 140];
        assert_eq!(fields().encode(&mut output[..length]), Err(Error::Capacity));
        assert_eq!(output, [0xa5; 140]);
    }
    for length in 0..60 {
        let mut output = [0xb6; 70];
        assert_eq!(
            fields().encode_signed(&mut output[..length]),
            Err(Error::Capacity)
        );
        assert_eq!(output, [0xb6; 70]);
    }
}
