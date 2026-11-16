//! Selector/codec tests only; these acquire no native device or cleanup owner.
use super::*;
fn fixture() -> Record {
    let mut name = [0; 16];
    name[..8].copy_from_slice(b"vpn-test");
    let mut device = [0; 16];
    device[..5].copy_from_slice(b"tun17");
    Record {
        name,
        device,
        index: 41,
        birth: [3; 32],
        file: FileIdentity::unix(7, 123),
    }
}
fn check(value: bool) -> io::Result<()> {
    if value {
        Ok(())
    } else {
        Err(io::Error::other("TUN recovery selector contract mismatch"))
    }
}
#[test]
fn fixed_record_preserves_renamed_interface_and_original_devfs_unit() -> io::Result<()> {
    let original = fixture();
    let decoded = Record::decode(&original.encode())?;
    check(decoded == original)?;
    check(decoded.interface_name()? == "vpn-test")?;
    check(decoded.device_name()? == "tun17")?;
    check(decoded.interface_index() == 41)
}
#[test]
fn unknown_or_noncanonical_records_are_refused() -> io::Result<()> {
    let bytes = fixture().encode();
    for short in [0, 8, 12, 44, 76, 108, 127] {
        check(Record::decode(&bytes[..short]).is_err())?;
    }
    for offset in [0, 21, 33, 77, 108, 127] {
        let mut corrupt = bytes;
        corrupt[offset] ^= 1;
        check(Record::decode(&corrupt).is_err())?;
    }
    let mut corrupt = bytes;
    corrupt[8..12].fill(0);
    check(Record::decode(&corrupt).is_err())?;
    corrupt = bytes;
    corrupt[44..76].fill(0);
    check(Record::decode(&corrupt).is_err())?;
    corrupt = bytes;
    corrupt[28..44].fill(0);
    corrupt[28..34].copy_from_slice(b"tun017");
    check(Record::decode(&corrupt).is_err())
}
#[test]
fn every_decoded_record_reencodes_canonically() -> io::Result<()> {
    let bytes = fixture().encode();
    // Correlation/ID/name bits may name a different selector, but the codec
    // never normalizes them into another selector or grants a live capability.
    for offset in 0..RECORD_BYTES {
        for bit in 0..8 {
            let mut changed = bytes;
            changed[offset] ^= 1 << bit;
            if let Ok(record) = Record::decode(&changed) {
                check(record.encode() == changed)?;
            }
        }
    }
    Ok(())
}
