use super::*;

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions compare exact interoperability fixtures after fallible encoding"
)]
fn official_helper_messages_round_trip() -> Result<(), Error> {
    let keys = [[0xa5; 32], [0x5a; 32]];
    let init = ToHelper::Init(Init::new(&keys, c"[BACKBONE]\nCARRIERS=0")?);
    let mut output = [0; 128];
    let size = init.encode(&mut output)?;
    assert_eq!(size, init.encoded_len());
    assert_eq!(&output[..8], &[0, 94, 0x06, 0xa4, 0, 0, 0, 2]);
    assert_eq!(ToHelper::decode(&output[..size]), Ok(init));

    let release = ToHelper::BarrierCrossable(keys[0]);
    let size = release.encode(&mut output)?;
    assert_eq!(&output[..4], &[0, 36, 0x06, 0xad]);
    assert_eq!(ToHelper::decode(&output[..size]), Ok(release));

    for message in [
        FromHelper::BarrierReached(keys[1]),
        FromHelper::Finished(-1),
    ] {
        let size = message.encode(&mut output)?;
        assert_eq!(FromHelper::decode(&output[..size]), Ok(message));
    }
    assert_eq!(&output[..8], &[0, 8, 0x06, 0xaa, 255, 255, 255, 255]);
    Ok(())
}

#[test]
fn init_rejects_interior_nul_and_count_overrun() {
    let mut input = [0, 11, 0x06, 0xa4, 0, 0, 0, 0, b'x', 0, 0];
    assert_eq!(ToHelper::decode(&input), Err(Error::Malformed));
    input[9] = b'y';
    input[7] = 1;
    assert_eq!(ToHelper::decode(&input), Err(Error::Malformed));
    input[7] = 0;
    input[10] = b'z';
    assert_eq!(ToHelper::decode(&input), Err(Error::Malformed));
}
