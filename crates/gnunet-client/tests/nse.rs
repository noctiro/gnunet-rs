//! Official NSE wire fields and original-MQ subscription ownership.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible setup followed by explicit protocol and ownership assertions"
)]
use gnunet_client::nse::{Client, Double, ESTIMATE_LEN, Estimate, Instance};
use gnunet_types::Error;
use gnunet_wire::official::{AbsoluteTime, nse};

fn estimate(timestamp: u64, size: u64, deviation: u64) -> Estimate {
    Estimate {
        timestamp: AbsoluteTime::from_micros(timestamp),
        log2_size: Double::from_bits(size),
        deviation: Double::from_bits(deviation),
    }
}

#[test]
fn official_fields_and_nonfinite_double_bits_remain_public_data() -> Result<(), Error> {
    let item = estimate(
        0x0102_0304_0506_0708,
        0x4008_0000_0000_0000,
        0x7ff8_1234_5678_9abc,
    );
    let mut wire = [0xa5; ESTIMATE_LEN + 4];
    assert_eq!(item.encode(&mut wire)?, 32);
    assert_eq!(
        &wire[..24],
        &[
            0, 32, 1, 67, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0x40, 8, 0, 0, 0, 0, 0, 0,
        ]
    );
    assert_eq!(&wire[24..32], &0x7ff8_1234_5678_9abc_u64.to_be_bytes());
    assert_eq!(&wire[32..], &[0xa5; 4]);
    assert_eq!(Estimate::decode(&wire[..32])?, item);
    assert!(item.deviation.value().is_nan());
    assert_eq!(item.log2_size.value().to_bits(), 3.0_f64.to_bits());
    // The reference C client ignores this field; do not invent a wire rejection.
    wire[4..8].copy_from_slice(&[0xff, 0, 0x71, 3]);
    assert_eq!(Estimate::decode(&wire[..32])?, item);
    for bits in [
        0,
        1,
        u64::MAX,
        0x7ff0_0000_0000_0000,
        0xfff0_0000_0000_0000,
        0x7ff0_0000_0000_0001,
        0x8000_0000_0000_0000,
    ] {
        let value = estimate(u64::MAX, bits, bits);
        value.encode(&mut wire)?;
        assert_eq!(Estimate::decode(&wire[..32])?, value);
        assert_eq!(Double::from_value(value.log2_size.value()).bits(), bits);
    }
    Ok(())
}

#[test]
fn exact_start_and_capacity_refusal_never_partially_mutate_output() -> Result<(), Error> {
    let mut bytes = [0xa7; 40];
    assert_eq!(nse::encode_start(&mut bytes)?, 4);
    assert_eq!(&bytes[..4], &[0, 4, 1, 65]);
    nse::decode_start(&bytes[..4])?;
    assert!(nse::decode_start(&bytes[..5]).is_err());
    let mut short = [0xc3; 3];
    assert_eq!(nse::encode_start(&mut short), Err(Error::Capacity));
    assert_eq!(short, [0xc3; 3]);
    let mut short = [0x92; 31];
    assert_eq!(estimate(0, 0, 0).encode(&mut short), Err(Error::Capacity));
    assert_eq!(short, [0x92; 31]);
    assert!(Estimate::decode(&[0, 4, 1, 67]).is_err());
    Ok(())
}

#[test]
fn foreign_brand_rejection_cannot_complete_or_consume_the_real_start() -> Result<(), Error> {
    let mut one = Instance::new();
    let mut two = Instance::new();
    let mut first = Client::new(&mut one);
    let mut second = Client::new(&mut two);
    let a = first.begin_connection()?;
    let b = second.begin_connection()?;
    assert_eq!(a.value(), b.value());
    assert_ne!(a, b);
    let lease = first.prepare_start(a)?;
    assert_eq!(second.written(&lease), Err(Error::Stale));
    first.written(&lease)?;
    assert_eq!(first.written(&lease), Err(Error::Stale));
    assert!(second.prepare_start(b).is_ok());
    Ok(())
}

#[test]
fn original_start_survives_canceled_waits_and_cannot_be_generated_twice() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut client = Client::new(&mut instance);
    let epoch = client.begin_connection()?;
    let start = client.prepare_start(epoch)?;
    let original = *start.bytes();
    // A host may have emitted a prefix and dropped a waiting future. This pure
    // owner cannot make that original partial frame disappear or repeat START.
    assert!(matches!(client.prepare_start(epoch), Err(Error::NotReady)));
    let mut incoming = [0; 32];
    estimate(1, 0, 0).encode(&mut incoming)?;
    assert_eq!(client.receive(epoch, &incoming), Err(Error::NotReady));
    assert_eq!(start.bytes(), &original);
    client.written(&start)?;
    assert!(client.receive(epoch, &incoming)?.is_some());
    assert!(matches!(client.prepare_start(epoch), Err(Error::NotReady)));
    Ok(())
}

#[test]
fn retirement_invalidates_current_observation_and_stale_mq_keeps_its_own_data() -> Result<(), Error>
{
    let mut instance = Instance::new();
    let mut client = Client::new(&mut instance);
    let old = client.begin_connection()?;
    let start = client.prepare_start(old)?;
    client.written(&start)?;
    let mut wire = [0; 32];
    let first = estimate(91, 0, 0);
    first.encode(&mut wire)?;
    let saved = client.receive(old, &wire)?.ok_or(Error::NotReady)?;
    assert_eq!(client.latest(), Some(saved));
    client.retire(old)?;
    assert!(client.latest().is_none());
    let new = client.begin_connection()?;
    assert_ne!(old, new);
    assert_eq!(client.receive(old, &wire), Err(Error::Stale));
    assert_eq!(saved.estimate, first);
    let start = client.prepare_start(new)?;
    client.written(&start)?;
    // Source clock rollback and repeated timestamps do not grant freshness but
    // are legitimate messages. The owner must deliver their raw values.
    let later = estimate(3, 0x8000_0000_0000_0000, 0x7ff0_0000_0000_0000);
    later.encode(&mut wire)?;
    assert_eq!(client.receive(new, &wire)?.map(|v| v.estimate), Some(later));
    assert_eq!(client.receive(new, &wire)?.map(|v| v.estimate), Some(later));
    Ok(())
}

#[test]
fn malformed_known_input_poisoning_requires_original_physical_retirement() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut client = Client::new(&mut instance);
    let epoch = client.begin_connection()?;
    let start = client.prepare_start(epoch)?;
    client.written(&start)?;
    // Well-framed unhandled messages do not become estimates or poison the MQ.
    assert_eq!(client.receive(epoch, &[0, 4, 0x7f, 0xff])?, None);
    assert!(client.receive(epoch, &[0, 4, 1, 67]).is_err());
    assert!(!client.connection_needed());
    assert!(client.latest().is_none());
    let mut wire = [0; 32];
    estimate(0, 0, 0).encode(&mut wire)?;
    assert_eq!(client.receive(epoch, &wire), Err(Error::NotReady));
    client.retire(epoch)?;
    assert!(client.connection_needed());
    client.close();
    assert_eq!(client.begin_connection(), Err(Error::Closed));
    assert_eq!(client.retire(epoch), Err(Error::Closed));
    Ok(())
}
