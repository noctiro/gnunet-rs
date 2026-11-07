//! Exercise the default public API with literal official bytes.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible integration test asserts independently specified public wire bytes"
)]
use gnunet::{
    clients::{resolver, statistics},
    crypto, gnsrecord,
    types::Error,
    wire,
};

#[test]
fn default_sdk_exposes_official_wire_and_gns_records() -> Result<(), Error> {
    let mut output = [0; 64];
    let selector = statistics::Selector {
        subsystem: b"core",
        name: b"peers",
    };
    let len = selector.encode_get(&mut output)?;
    assert_eq!(&output[..len], b"\x00\x0f\x00\xa9core\0peers\0");
    let frame = wire::Frame::decode(&output[..len])?;
    assert_eq!(
        frame.header().message_type(),
        wire::message_type::STATISTICS_GET
    );
    let raw = b"\x01\x02\x03\x04\x05\x06\x07\x08\0\x04\0\0\0\0\0\x01\xc0\0\x02\x01";
    let set = gnsrecord::RecordSet::parse(raw, 1, 1)?;
    let record = set.iter().next().ok_or(Error::NotFound)??;
    assert_eq!(record.expiration_time, 0x0102_0304_0506_0708);
    assert_eq!(record.record_type.value(), 1);
    assert_eq!(record.data, &[192, 0, 2, 1]);
    assert_eq!(crypto::hash512(b"abc").len(), 64);
    let request =
        resolver::Request::forward(resolver::WireId([1, 2, 3, 4]), resolver::Family::V6, b"a")?;
    let size = request.encode(resolver::FamilyProfile::DARWIN, &mut output)?;
    assert_eq!(
        &output[..size],
        b"\0\x12\0\x04\0\0\0\0\0\0\0\x1e\x01\x02\x03\x04a\0"
    );
    Ok(())
}
