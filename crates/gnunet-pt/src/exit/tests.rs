use super::*;

const QUERY: [u8; 17] = [
    0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, // header
    0, 0, 1, 0, 1, // root, A, IN
];

#[test]
fn exit_dns_frames_have_distinct_directions_and_preserve_the_datagram() {
    let mut frame = [0; 21];
    assert_eq!(encode_query(&QUERY, &mut frame), Ok(21));
    assert_eq!(&frame[..4], &[0, 21, 0, 193]);
    assert_eq!(decode_query(&frame), Ok(QUERY.as_slice()));
    assert_eq!(decode_response(&frame), Err(Error::Unsupported));

    let mut response = QUERY;
    response[2] = 0x81;
    response[3] = 0x80;
    assert_eq!(encode_response(&response, &mut frame), Ok(21));
    assert_eq!(&frame[..4], &[0, 21, 0, 194]);
    assert_eq!(decode_response(&frame), Ok(response.as_slice()));
    assert_eq!(decode_query(&frame), Err(Error::Unsupported));
}

#[test]
fn exit_dns_requires_one_complete_frame_and_preserves_short_output() {
    let mut frame = [0; 22];
    assert_eq!(encode_query(&QUERY, &mut frame), Ok(21));
    assert_eq!(decode_query(&frame[..20]), Err(Error::Truncated));
    assert_eq!(decode_query(&frame), Err(Error::InvalidInput));
    frame[1] = 15;
    assert_eq!(decode_query(&frame[..15]), Err(Error::Truncated));

    let mut short = [7; 20];
    assert_eq!(encode_response(&QUERY, &mut short), Err(Error::Capacity));
    assert_eq!(short, [7; 20]);
}
