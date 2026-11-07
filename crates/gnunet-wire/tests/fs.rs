//! Source-layout FS local IPC and encode preflight regressions.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible wire regressions assert independent source-layout outcomes"
)]
use gnunet_types::Error;
use gnunet_wire::official::{
    AbsoluteTime, Frame, MessageHeader, MessageType,
    fs::{
        BlockType, ClientPut, MAX_SEEN_PER_FRAME, Request, Response, SEARCH_CONTINUED,
        SEARCH_LOOPBACK_ONLY, Search,
    },
    message_type as mt,
};

#[test]
fn search_source_offsets_seen_hashes_and_preflight() -> Result<(), Error> {
    let seen = [0x77; 128];
    let request = Request::Search(Search {
        options: SEARCH_LOOPBACK_ONLY | SEARCH_CONTINUED,
        block_type: BlockType::UBLOCK,
        anonymity: 0x1020_3040,
        target: [0; 32],
        query: [0x55; 64],
        seen: &seen,
    });
    let mut out = [0xa5; 256];
    assert_eq!(request.encoded_len()?, 240);
    let n = request.encode(&mut out)?;
    assert_eq!(&out[..4], &[0, 240, 0, 136]);
    assert_eq!(&out[4..8], &[0, 0, 0, 3]);
    assert_eq!(&out[8..12], &[0, 0, 0, 9]);
    assert_eq!(&out[12..16], &[0x10, 0x20, 0x30, 0x40]);
    assert_eq!(&out[16..48], &[0; 32]);
    assert_eq!(&out[48..112], &[0x55; 64]);
    assert_eq!(&out[112..240], &seen);
    assert_eq!(&out[n..], &[0xa5; 16]);
    assert_eq!(Request::decode(&out[..n])?, request);
    let Request::Search(mut search) = request else {
        return Err(Error::InvalidInput);
    };
    let mut sentinel = [0xa5; 256];
    search.seen = &[1; 63];
    assert_eq!(
        Request::Search(search).encode(&mut sentinel),
        Err(Error::InvalidInput)
    );
    assert_eq!(sentinel, [0xa5; 256]);
    search.seen = &[];
    search.target = [1; 32];
    assert_eq!(
        Request::Search(search).encode(&mut sentinel),
        Err(Error::InvalidInput)
    );
    assert_eq!(sentinel, [0xa5; 256]);
    search.target = [0; 32];
    search.options = 4;
    assert_eq!(
        Request::Search(search).encode(&mut sentinel),
        Err(Error::InvalidInput)
    );
    assert_eq!(sentinel, [0xa5; 256]);
    let maximum = [0; MAX_SEEN_PER_FRAME * 64];
    search.options = 0;
    search.seen = &maximum;
    assert_eq!(Request::Search(search).encoded_len()?, 65_520);
    let excessive = [0; (MAX_SEEN_PER_FRAME + 1) * 64];
    search.seen = &excessive;
    assert_eq!(Request::Search(search).encoded_len(), Err(Error::TooLarge));
    assert_eq!(request.encode(&mut [0xa5; 239]), Err(Error::Capacity));
    Ok(())
}

#[test]
fn local_put_is_32_bytes_and_never_a_local_request() -> Result<(), Error> {
    let response = Response::Put(ClientPut {
        block_type: BlockType::IBLOCK,
        expiration: AbsoluteTime::from_micros(0x0102_0304_0506_0708),
        last_transmission: AbsoluteTime::NEVER,
        num_transmissions: 0x1122_3344,
        respect_offered: 0x5566_7788,
        block: b"ciphertext",
    });
    let mut out = [0xa5; 64];
    let n = response.encode(&mut out)?;
    assert_eq!(n, 42);
    assert_eq!(&out[..8], &[0, 42, 0, 138, 0, 0, 0, 2]);
    assert_eq!(&out[8..16], &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(&out[16..24], &[0xff; 8]);
    assert_eq!(&out[24..28], &[0x11, 0x22, 0x33, 0x44]);
    assert_eq!(&out[28..32], &[0x55, 0x66, 0x77, 0x88]);
    assert_eq!(&out[32..n], b"ciphertext");
    assert_eq!(Response::decode(&out[..n])?, response);
    assert_eq!(Request::decode(&out[..n]), Err(Error::Unsupported));
    // A minimum P2P PUT is 16 bytes, unlike the 32-byte local prefix. Longer
    // P2P payloads cannot be distinguished by framing alone: use the local IPC
    // connection and authenticate/type/query-match every returned block.
    let mut p2p = [0; 16];
    MessageHeader::from_total_size(mt::FS_PUT, 16)?.encode(&mut p2p)?;
    p2p[4..8].copy_from_slice(&1_u32.to_be_bytes());
    assert_eq!(Response::decode(&p2p), Err(Error::Truncated));
    let get = Frame::new(mt::FS_GET, &[])?;
    let n = get.encode(&mut out)?;
    assert_eq!(Request::decode(&out[..n]), Err(Error::Unsupported));
    assert_eq!(Response::decode(&out[..n]), Err(Error::Unsupported));
    let future = Response::Unknown(Frame::new(MessageType::new(65000), b"future")?);
    let n = future.encode(&mut out)?;
    assert_eq!(Response::decode(&out[..n])?, future);
    Ok(())
}

#[test]
fn admin_paths_loc_layouts_reserved_and_atomic_capacity() -> Result<(), Error> {
    let requests = [
        Request::LocSign {
            expiration: AbsoluteTime::from_micros(1_234_567),
            key: [0x11; 64],
            query: [0x22; 64],
            file_length: 0x0102_0304_0506_0708,
        },
        Request::IndexStart {
            device: 0x1122_3344_5566_7788,
            inode: 9,
            file_id: [0x33; 64],
            filename: b"/tmp/raw-\xff-file",
        },
        Request::IndexList,
        Request::Unindex {
            file_id: [0x44; 64],
        },
    ];
    for request in requests {
        let mut out = [0xa5; 256];
        let n = request.encode(&mut out)?;
        assert_eq!(Request::decode(&out[..n])?, request);
        let mut short = [0xa5; 256];
        assert_eq!(request.encode(&mut short[..n - 1]), Err(Error::Capacity));
        assert_eq!(short, [0xa5; 256]);
        match request {
            Request::LocSign { .. } => {
                assert_eq!(n, 152);
                assert_eq!(&out[4..8], &[0, 0, 0, 5]);
                assert_eq!(&out[8..16], &1_234_567_u64.to_be_bytes());
                assert_eq!(&out[16..80], &[0x11; 64]);
                assert_eq!(&out[80..144], &[0x22; 64]);
                assert_eq!(&out[144..152], &0x0102_0304_0506_0708_u64.to_ne_bytes());
            }
            Request::IndexStart { filename, .. } => {
                assert_eq!(n, 89 + filename.len());
                assert_eq!(&out[4..8], &[0; 4]);
                assert_eq!(
                    &out[8..16],
                    &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
                );
                assert_eq!(&out[24..88], &[0x33; 64]);
                assert_eq!(out[n - 1], 0);
                out[4] = 1;
                assert_eq!(Request::decode(&out[..n]), Err(Error::Malformed));
            }
            Request::Unindex { .. } => assert_eq!(n, 72),
            Request::IndexList => assert_eq!(n, 4),
            Request::Search(_) => return Err(Error::InvalidInput),
        }
    }
    let responses = [
        Response::LocSignature {
            expiration: AbsoluteTime::from_micros(1_000_000),
            signature: [0x55; 64],
            peer: [0x66; 32],
        },
        Response::IndexStarted,
        Response::IndexFailed {
            message: b"hash mismatch",
        },
        Response::IndexEntry {
            file_id: [0x77; 64],
            filename: b"/tmp/file",
        },
        Response::IndexEnd,
        Response::Unindexed,
    ];
    for response in responses {
        let mut out = [0xa5; 256];
        let n = response.encode(&mut out)?;
        assert_eq!(Response::decode(&out[..n])?, response);
        let mut short = [0xa5; 256];
        assert_eq!(response.encode(&mut short[..n - 1]), Err(Error::Capacity));
        assert_eq!(short, [0xa5; 256]);
        if let Response::LocSignature { .. } = response {
            assert_eq!(n, 112);
            assert_eq!(&out[16..80], &[0x55; 64]);
            assert_eq!(&out[80..112], &[0x66; 32]);
        }
    }
    let mut sentinel = [0xa5; 128];
    assert_eq!(
        Request::IndexStart {
            device: 0,
            inode: 0,
            file_id: [0; 64],
            filename: b"a\0b"
        }
        .encode(&mut sentinel),
        Err(Error::InvalidInput)
    );
    assert_eq!(sentinel, [0xa5; 128]);
    Ok(())
}

// C FileIdentifier keeps file_length in NBO. create_loc_uri applies htonll
// again when constructing RequestLocSignatureMessage, and the service undoes
// that conversion before copying the identifier into the signed LOC region.
#[test]
fn official_c_loc_request_preserves_native_length() -> Result<(), Error> {
    let mut wire = [0; 152];
    MessageHeader::from_total_size(mt::FS_REQUEST_LOC_SIGN, wire.len())?.encode(&mut wire)?;
    wire[4..8].copy_from_slice(&5_u32.to_be_bytes());
    wire[8..16].copy_from_slice(&1_830_297_600_000_000_u64.to_be_bytes());
    wire[16..80].fill(0x11);
    wire[80..144].fill(0x22);
    #[cfg(target_endian = "little")]
    wire[144..152].copy_from_slice(&[0xe1, 0x01, 0x01, 0, 0, 0, 0, 0]);
    #[cfg(target_endian = "big")]
    wire[144..152].copy_from_slice(&[0, 0, 0, 0, 0, 0x01, 0x01, 0xe1]);
    let request = Request::decode(&wire)?;
    assert!(matches!(
        request,
        Request::LocSign {
            file_length: 66_017,
            ..
        }
    ));
    let mut encoded = [0; 152];
    assert_eq!(request.encode(&mut encoded)?, wire.len());
    assert_eq!(encoded, wire);
    Ok(())
}
