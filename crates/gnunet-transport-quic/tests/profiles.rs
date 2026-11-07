//! Public metadata/format model only. No runtime, key, TLS or QUIC execution.
use gnunet_transport_quic::{Instance, Role, frame, h3, raw, tx};
use gnunet_types::{Error, MonoInstant};
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions report model invariant failures; Result preserves actual fallible codec errors"
)]
fn split_profiles_and_original_leases() -> Result<(), Error> {
    let original = Instance::new();
    let mut slab = [0u8; 64];
    let mut raw = raw::Connection::new(
        &original,
        b"hq-interop",
        MonoInstant(1),
        &mut slab,
        raw::Options {
            local: [9; 32],
            role: Role::Acceptor,
            until: MonoInstant(1000),
            max_frame: 64,
        },
    )?;
    assert_eq!(raw.push(4, &[7; 13], MonoInstant(2))?.consumed, 13);
    let claim = raw.push(4, &[7; 19], MonoInstant(3))?;
    assert_eq!(claim.claim.map(|p| p.0), Some([7; 32]));
    let message = [0, 6, 0, 1, 42, 43];
    assert!(!raw.push(4, &message[..1], MonoInstant(4))?.frame);
    assert!(raw.push(4, &message[1..], MonoInstant(5))?.frame);
    assert_eq!(raw.frame(MonoInstant(5))?, message);
    assert_eq!(raw.push(4, &message, MonoInstant(5))?.consumed, 0);
    assert_eq!(raw.release_frame()?, 6);
    raw.finish(4)?;
    assert!(raw.finished());
    let mut frame_slab = [0; 64];
    let mut decoder = frame::Decoder::new(&mut frame_slab, 64)?;
    assert_eq!(decoder.push(&[0, 4, 0, 1, 0, 4, 0, 2])?.consumed, 4);
    assert_eq!(decoder.release()?, 4);
    let mut cursor = tx::Cursor::frame(&message)?;
    assert!(!cursor.accepted(2)?);
    assert_eq!(cursor.pending()?, &message[2..]);
    assert_eq!(cursor.cancel(), tx::Canceled::ProviderAccepted { bytes: 2 });
    let mut a = [0; 64];
    let mut b = [0; 64];
    let mut slots = [h3::Slot::new(&mut a), h3::Slot::new(&mut b)];
    let mut h3 = h3::Session::new(
        &original,
        MonoInstant(1),
        b"h3",
        &mut slots,
        h3::Options {
            role: Role::Acceptor,
            until: MonoInstant(1000),
            limits: h3::Limits {
                max_body: 64,
                header_bytes: 4096,
                polls: 2,
            },
        },
    )?;
    let mut digits = [0; 20];
    let identity_headers =
        h3::request_headers(h3::Kind::IdentityPost, b"127.0.0.1:443", 32, &mut digits)?;
    let identity = h3.accept_request(
        0,
        identity_headers.as_slice(),
        MonoInstant(30),
        MonoInstant(2),
    )?;
    assert_eq!(h3.push_body(identity, &[7; 17], MonoInstant(3))?, 17);
    assert_eq!(h3.push_body(identity, &[7; 15], MonoInstant(4))?, 15);
    h3.finish_body(identity, MonoInstant(4))?;
    assert_eq!(h3.peer().map(|p| p.0), Some([7; 32]));
    assert!(h3.delivery(identity, MonoInstant(4))?.is_none());
    assert_eq!(h3.consume(identity)?, 32);
    assert_eq!(h3.start_response(identity, None, MonoInstant(5))?, 200);
    h3.release(identity)?;
    assert_eq!(h3.release(identity), Err(Error::Stale));
    let mut length = [0; 20];
    let headers = h3::request_headers(h3::Kind::MessagePost, b"127.0.0.1:443", 6, &mut length)?;
    let stream = h3.accept_request(4, headers.as_slice(), MonoInstant(30), MonoInstant(6))?;
    h3.push_body(stream, &message[..2], MonoInstant(6))?;
    h3.push_body(stream, &message[2..], MonoInstant(7))?;
    assert!(matches!(
        h3.delivery(stream, MonoInstant(7)),
        Err(Error::NotReady)
    ));
    h3.finish_body(stream, MonoInstant(8))?;
    assert_eq!(
        h3.delivery(stream, MonoInstant(8))?
            .ok_or(Error::NotReady)?
            .frame,
        message
    );
    h3.consume(stream)?;
    h3.start_response(stream, None, MonoInstant(8))?;
    h3.release(stream)?;
    let mut len = [0; 20];
    let get = h3::request_headers(h3::Kind::Get, b"127.0.0.1:443", 0, &mut len)?;
    let poll = h3.accept_request(8, get.as_slice(), MonoInstant(20), MonoInstant(9))?;
    h3.finish_body(poll, MonoInstant(9))?;
    h3.consume(poll)?;
    assert_eq!(h3.next_poll(MonoInstant(10))?, Some(poll));
    assert_eq!(
        h3.start_response(poll, None, MonoInstant(10)),
        Err(Error::NotReady)
    );
    assert_eq!(h3.start_response(poll, None, MonoInstant(20))?, 204);
    h3.release(poll)?;
    h3.retire();
    assert!(matches!(h3.next_poll(MonoInstant(20)), Err(Error::Closed)));
    Ok(())
}
