//! Exact official FS CADET application framing; no network/authentication claim.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Wire tests assert exact official C field positions and rejection atomicity"
)]
use gnunet_types::Error;
use gnunet_wire::official::{
    AbsoluteTime,
    fs::BlockType,
    fs_cadet::{MAX_WIRE_BLOCK_BYTES, PORT_LABEL, QUERY_BYTES, Query, REPLY_PREFIX, Reply},
};

#[test]
fn exact_c_query_and_reply_layouts_borrow_unmodified_payloads() -> Result<(), Error> {
    let key = std::array::from_fn(|i| i as u8);
    let q = Query {
        block_type: BlockType::DBLOCK,
        query: &key,
    };
    let mut wire = [0; QUERY_BYTES];
    assert_eq!(q.encoded_len(), 72);
    assert_eq!(q.encode(&mut wire)?, 72);
    assert_eq!(&wire[..8], &[0, 72, 0, 140, 0, 0, 0, 1]);
    assert_eq!(&wire[8..], &key);
    let parsed = Query::decode(&wire)?;
    assert_eq!(parsed, q);
    assert!(std::ptr::eq(parsed.query.as_ptr(), wire[8..].as_ptr()));
    assert_eq!(PORT_LABEL, b"fs-block");
    let payload = [0xaa, 0xbb, 0xcc];
    let reply = Reply {
        block_type: BlockType::UBLOCK,
        expiration: AbsoluteTime::from_micros(0x0102030405060708),
        block: &payload,
    };
    let mut encoded = [0; 19];
    assert_eq!(reply.encode(&mut encoded)?, 19);
    assert_eq!(
        &encoded[..REPLY_PREFIX],
        &[0, 19, 0, 141, 0, 0, 0, 9, 1, 2, 3, 4, 5, 6, 7, 8]
    );
    assert_eq!(&encoded[REPLY_PREFIX..], &payload);
    let actual = Reply::decode(&encoded)?;
    assert_eq!(actual, reply);
    assert!(std::ptr::eq(
        actual.block.as_ptr(),
        encoded[REPLY_PREFIX..].as_ptr()
    ));
    Ok(())
}

#[test]
fn exact_size_refusals_and_reply_preflight_are_atomic() -> Result<(), Error> {
    let key = [7; 64];
    let query = Query {
        block_type: BlockType::ANY,
        query: &key,
    };
    let mut short = [0xa5; 71];
    assert_eq!(query.encode(&mut short), Err(Error::Capacity));
    assert_eq!(short, [0xa5; 71]);
    let mut truncated = [0; 71];
    truncated[..4].copy_from_slice(&[0, 71, 0, 140]);
    assert_eq!(Query::decode(&truncated), Err(Error::Malformed));
    let mut trailing = [0; 73];
    trailing[..4].copy_from_slice(&[0, 73, 0, 140]);
    assert_eq!(Query::decode(&trailing), Err(Error::Malformed));
    let invalid = Reply {
        block_type: BlockType::ANY,
        expiration: AbsoluteTime::NEVER,
        block: &[],
    };
    let mut untouched = [0xa5; 20];
    assert_eq!(invalid.encode(&mut untouched), Err(Error::InvalidInput));
    assert_eq!(untouched, [0xa5; 20]);
    let oversized = vec![0; MAX_WIRE_BLOCK_BYTES + 1];
    let invalid = Reply {
        block_type: BlockType::IBLOCK,
        expiration: AbsoluteTime::NEVER,
        block: &oversized,
    };
    assert_eq!(invalid.encode(&mut untouched), Err(Error::TooLarge));
    assert_eq!(untouched, [0xa5; 20]);
    let mut header = [0; 16];
    header[..4].copy_from_slice(&[0, 16, 0, 141]);
    assert_eq!(Reply::decode(&header), Err(Error::Malformed));
    assert_eq!(Query::decode(&header), Err(Error::Unsupported));
    Ok(())
}
