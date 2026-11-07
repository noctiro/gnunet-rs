//! Source-layout PILS framing, offsets and atomic encode regressions.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible protocol and real resource regressions assert independent expected outcomes"
)]
use gnunet_types::Error;
use gnunet_wire::official::{
    SignaturePurpose,
    pils::{PeerUpdate, Request, Response},
};
#[test]
fn source_offsets_and_all_request_shapes_roundtrip() -> Result<(), Error> {
    let mut purpose = [0x55; 48];
    SignaturePurpose::new(35, 40)?.encode(&mut purpose)?;
    let requests = [
        Request::Feed { block: b"block" },
        Request::Sign {
            request: 0x11223344,
            region: &purpose,
        },
        Request::Decapsulate {
            request: 0x11223344,
            encapsulation: [6; 32],
        },
        Request::Ecdh {
            request: 0x11223344,
            public: [7; 32],
        },
    ];
    for request in requests {
        let mut out = [0xa5; 128];
        let n = request.encode(&mut out)?;
        assert_eq!(Request::decode(&out[..n])?, request);
        assert!(out[n..].iter().all(|b| *b == 0xa5));
        match request {
            Request::Sign { .. } => assert_eq!(&out[4..8], &[0x11, 0x22, 0x33, 0x44]),
            Request::Decapsulate { .. } | Request::Ecdh { .. } => {
                assert_eq!(n, 40);
                assert_eq!(&out[36..40], &[0x11, 0x22, 0x33, 0x44]);
            }
            _ => {}
        }
    }
    Ok(())
}
#[test]
fn source_responses_have_no_invented_padding_or_secret_debug() -> Result<(), Error> {
    let mut out = [0xa5; 200];
    let n = Response::Signature {
        request: 0x11223344,
        peer: [1; 32],
        signature: [2; 64],
    }
    .encode(&mut out)?;
    assert_eq!(n, 104);
    assert_eq!(&out[100..104], &[0x11, 0x22, 0x33, 0x44]);
    assert!(matches!(
        Response::decode(&out[..n])?,
        Response::Signature {
            request: 0x11223344,
            ..
        }
    ));
    let n = Response::Decapsulation {
        request: 3,
        key: &[4; 32],
    }
    .encode(&mut out)?;
    assert_eq!(n, 40);
    assert!(
        matches!(Response::decode(&out[..n])?,Response::Decapsulation {request:3,key} if *key==[4;32])
    );
    let n = Response::Ecdh {
        request: 5,
        key: &[6; 64],
    }
    .encode(&mut out)?;
    assert_eq!(n, 72);
    assert!(matches!(Response::decode(&out[..n])?,Response::Ecdh {request:5,key} if *key==[6;64]));
    Ok(())
}
#[test]
fn inconsistent_lengths_truncation_and_output_refusal_are_atomic() -> Result<(), Error> {
    let update = PeerUpdate {
        hash: [2; 64],
        block: b"hello",
    };
    let mut out = [0xa5; 128];
    let n = update.encode(&mut out)?;
    assert_eq!(PeerUpdate::decode(&out[..n])?, update);
    for size in 0..n {
        assert!(PeerUpdate::decode(&out[..size]).is_err());
    }
    out[68..72].copy_from_slice(&99_u32.to_be_bytes());
    assert_eq!(PeerUpdate::decode(&out[..n]), Err(Error::Malformed));
    let mut short = [0xa5; 76];
    assert_eq!(update.encode(&mut short), Err(Error::Capacity));
    assert_eq!(short, [0xa5; 76]);
    let mut purpose = [0; 48];
    SignaturePurpose::new(35, 41)?.encode(&mut purpose)?;
    let mut sentinel = [0xa5; 128];
    assert!(
        Request::Sign {
            request: 1,
            region: &purpose
        }
        .encode(&mut sentinel)
        .is_err()
    );
    assert_eq!(sentinel, [0xa5; 128]);
    Ok(())
}
