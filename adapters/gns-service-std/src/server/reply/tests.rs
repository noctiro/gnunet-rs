//! Reply preparation, backpressure and exact FIFO transfer regressions.
use super::*;
use crate::server::PeerId;
use gnunet_gns::Origin;
use gnunet_gnsrecord::{RecordFlags, RecordType};
use gnunet_service_runtime::{
    connection::Connection,
    framing::{Accounting, Budget, Limits},
};
use std::{
    future::poll_fn,
    io::{Read, Result as IoResult},
    net::{Ipv4Addr, TcpListener, TcpStream},
    time::Duration,
};
use tokio::time::Instant;

mod deadline;

fn address() -> Record {
    Record {
        origin: Origin::Literal,
        expiration_time: 0x0102_0304_0506_0708,
        record_type: RecordType::A,
        flags: RecordFlags::NONE,
        data: vec![192, 0, 2, 1],
    }
}

fn connection() -> IoResult<(Connection, TcpStream)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let remote = TcpStream::connect(listener.local_addr()?)?;
    remote.set_read_timeout(Some(Duration::from_secs(2)))?;
    let (stream, _) = listener.accept()?;
    stream.set_nonblocking(true)?;
    Ok((
        Connection::from_tcp(tokio::net::TcpStream::from_std(stream)?),
        remote,
    ))
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions preserve the original completed result through a saturated FIFO and compare exact official reply bytes"
)]
fn blocked_output_retains_result_and_transfers_it_exactly_once()
-> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let (connection, mut remote) = connection()?;
        let mut io = Framed::new(
            connection,
            Limits {
                frame_bytes: 65535,
                ordinary: Budget {
                    frames: 1,
                    bytes: 128,
                },
                reserved: Budget::default(),
                accounting: Accounting::Retained,
                io_slice_bytes: 65535,
            },
        )?;
        let owner = 1;
        let origin = Reply {
            peer: PeerId {
                owner: &owner,
                serial: 1,
            },
            wire: gns::WireId([9, 8, 7, 6]),
            serial: 2,
            hard: Instant::now() + Duration::from_secs(2),
        };
        let placeholder = vec![0, 12, 1, 245, 0, 0, 0, 0, 0, 0, 0, 0];
        io.enqueue_owned(OwnedFrame::new(placeholder), origin, Class::Ordinary)
            .map_err(|rejected| rejected.reason)?;
        let mut state = CallState::Ready(ReplyPlan::new(Ok(vec![address()])));
        let CallState::Ready(plan) = &state else {
            return Err(Fault::Conflict.into());
        };
        let original = plan.records[0].data.as_ptr();
        for _ in 0..32 {
            assert!(state.try_queue(&mut io, origin)?.is_none());
            let CallState::Ready(plan) = &state else {
                return Err(Fault::Conflict.into());
            };
            assert_eq!(plan.records[0].data.as_ptr(), original);
            assert_eq!(plan.encoded_len, 44);
            assert_eq!(io.queued_frames(), 1);
            assert_eq!(io.remaining_bytes(), 12);
        }
        assert!(poll_fn(|cx| io.poll_write(cx)).await?.complete);
        let mut discarded = [0; 12];
        remote.read_exact(&mut discarded)?;
        let queued = state.try_queue(&mut io, origin)?.ok_or(Fault::NotReady)?;
        assert_eq!(queued.records, 1);
        assert_eq!(queued.failure, None);
        assert!(matches!(state, CallState::Queued));
        assert!(state.try_queue(&mut io, origin)?.is_none());
        assert_eq!(
            io.queued_frames(),
            1,
            "repeated polls cannot enqueue another reply"
        );
        assert!(poll_fn(|cx| io.poll_write(cx)).await?.complete);
        let mut received = [0; 44];
        remote.read_exact(&mut received)?;
        let expected = [
            0, 44, 1, 245, 9, 8, 7, 6, 0, 0, 0, 1, 1, 2, 3, 4, 5, 6, 7, 8, 0, 4, 0, 0, 0, 0, 0, 1,
            192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(
            received, expected,
            "response preserves request ID, record order and canonical padding"
        );
        Ok(())
    })
}

#[test]
fn unrepresentable_reply_releases_records_and_retains_empty_failure() {
    let mut oversized = address();
    oversized.data.resize(65536, 1);
    let plan = ReplyPlan::new(Ok(vec![oversized]));
    assert!(plan.records.is_empty());
    assert_eq!(plan.encoded_len, gns::RESULT_HEADER_LEN);
    assert_eq!(plan.failure, Some(Failure::Fault(Fault::TooLarge)));
    let failed = ReplyPlan::new(Err(Failure::Revoked));
    assert!(failed.records.is_empty());
    assert_eq!(failed.failure, Some(Failure::Revoked));
}
