//! Native producer ABIs remain explicit; wrong-family bytes are never normalized.
use gnunet_wire::official::nat::{Address, Endian, Profile, RawAddress};
type Result<T = ()> = std::result::Result<T, gnunet_types::Error>;
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Wire assertions follow fallible native-profile fixture encoding"
)]
fn windows_ipv6_retains_native_fields_and_refuses_unix_producer_profiles() -> Result {
    let address = Address::V6 {
        ip: [0x21; 16],
        port: 2086,
        flow: 0x1234_5678,
        scope: 9,
    };
    let mut bytes = [0; 28];
    address.encode(Profile::windows(Endian::Little), &mut bytes)?;
    assert_eq!(&bytes[..4], &[23, 0, 8, 38]);
    assert_eq!(&bytes[4..8], &[0x78, 0x56, 0x34, 0x12]);
    assert_eq!(&bytes[8..24], &[0x21; 16]);
    assert_eq!(&bytes[24..], &[9, 0, 0, 0]);
    assert_eq!(
        RawAddress::decode(&bytes, Profile::windows(Endian::Little))?.address(),
        address
    );
    for profile in [
        Profile::linux(Endian::Little),
        Profile::darwin(Endian::Little),
        Profile::freebsd(Endian::Little),
    ] {
        assert!(RawAddress::decode(&bytes, profile).is_err());
    }
    Ok(())
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Wire assertions follow fallible native-profile fixture encoding"
)]
fn windows_local_address_preserves_every_native_path_byte() -> Result {
    let mut path = [0; 108];
    path[..4].copy_from_slice(b"C:\\s");
    path[107] = 0xff;
    let address = Address::Unix(&path);
    let mut bytes = [0; 110];
    address.encode(Profile::windows(Endian::Little), &mut bytes)?;
    assert_eq!(&bytes[..2], &[1, 0]);
    assert_eq!(&bytes[2..], &path);
    assert_eq!(
        RawAddress::decode(&bytes, Profile::windows(Endian::Little))?.address(),
        address
    );
    Ok(())
}
