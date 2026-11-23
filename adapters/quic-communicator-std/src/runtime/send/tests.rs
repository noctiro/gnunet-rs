//! Real private-MQ admission; this does not simulate native QUIC acceptance.
use super::*;
use crate::ipc::{
    Step,
    tests::{Directory, TestError, attach, new_ipc, runtime},
};
use gnunet_wire::official::message_type as mt;
use std::{future::poll_fn, task::Poll, time::Duration};
use tokio::io::AsyncWriteExt;

async fn frame(ipc: &mut Ipc) -> Result<(), TestError> {
    tokio::time::timeout(
        Duration::from_secs(2),
        poll_fn(|cx| match ipc.poll_recovering(cx, |_, _, _| {}) {
            Ok(Step::Frame) => Poll::Ready(Ok(())),
            Ok(Step::Activity) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Ok(Step::Pending) => Poll::Pending,
            Ok(_) => Poll::Ready(Err("unexpected private MQ state".into())),
            Err(error) => Poll::Ready(Err(format!("private MQ: {error:?}").into())),
        }),
    )
    .await?
}
fn send() -> [u8; 52] {
    let mut bytes = [0; 52];
    bytes[..2].copy_from_slice(&52_u16.to_be_bytes());
    bytes[2..4].copy_from_slice(&mt::TRANSPORT_SEND_MSG.value().to_be_bytes());
    bytes[4..8].copy_from_slice(&7_u32.to_be_bytes());
    bytes[8..16].copy_from_slice(&[1; 8]);
    bytes[16..48].copy_from_slice(&[2; 32]);
    bytes[48..].copy_from_slice(&[0, 4, 0, 0]);
    bytes
}

#[test]
fn queued_send_releases_shared_mq_for_original_fc_without_native_acceptance()
-> Result<(), TestError> {
    runtime()?.block_on(async {
        let directory = Directory::new()?;
        let (mut ipc, listener, source_hard) = new_ipc(&directory)?;
        let mut peer = attach(&mut ipc, &listener).await?;
        let mut received = [0; 48];
        received[..2].copy_from_slice(&48_u16.to_be_bytes());
        received[2..4].copy_from_slice(&mt::TRANSPORT_INCOMING_MSG_ACK.value().to_be_bytes());
        received[8..16].copy_from_slice(&[3; 8]);
        received[16..].copy_from_slice(&[2; 32]);
        peer.write_all(&send()).await?;
        peer.write_all(&received).await?;
        frame(&mut ipc).await?;
        let original_hard = ipc.input_hard().ok_or("missing original command bound")?;

        // Failed admission must leave the original frame and deadline intact.
        if !matches!(Sending::from_ipc(&mut ipc, raw::SendId(1), 3, source_hard),
            Err(Fault::Protocol(Protocol::TooLarge)))
            || ipc.input_hard() != Some(original_hard)
            || !matches!(ipc.frame(), Ok(Some(Response::Send(7, _, _, _))))
        {
            return Err("failed admission consumed or changed original SEND".into());
        }

        let mut admitted = Sending::from_ipc(&mut ipc, raw::SendId(1), 1000, source_hard)?;
        if admitted.hard != original_hard
            || (admitted.queue, admitted.mid, admitted.total) != (7, [1; 8], 4)
            || !matches!(&admitted.submission, Submission::Queued(bytes) if bytes.as_slice() == [0,4,0,0])
            || admitted.accepted != 0
            || admitted.unknown || admitted.result_queued || admitted.result_written
            || ipc.frame().map_err(|e| format!("frame: {e:?}"))?.is_some()
            || ipc.input_hard().is_some()
        {
            return Err("admission changed original SEND facts or held the shared cursor".into());
        }

        // This original FC callback is physically behind the SEND. Its cursor
        // progresses while that same SEND still owns all admitted bytes.
        frame(&mut ipc).await?;
        if !matches!(ipc.frame(), Ok(Some(Response::Received(flow, peer))) if flow == [3; 8] && peer == [2; 32]) {
            return Err("original FC behind queued SEND could not progress".into());
        }
        ipc.release().map_err(|e| format!("release: {e:?}"))?;
        if !admitted.queued() || admitted.hard != original_hard || admitted.accepted != 0 {
            return Err("FC progress fabricated native SEND acceptance or renewed its bound".into());
        }
        admitted.retire_queued();
        if !matches!(admitted.submission, Submission::Retired) || admitted.accepted != 0 || admitted.unknown {
            return Err("queued retirement retained bytes or claimed native exposure".into());
        }
        ipc.close();
        Ok(())
    })
}

#[test]
fn expired_or_malformed_send_never_acquires_admission() {
    let future = Instant::now() + Duration::from_secs(1);
    assert!(matches!(
        Sending::admit(
            7,
            raw::SendId(1),
            [1; 8],
            &[0, 4, 0, 0],
            1000,
            Instant::now()
        ),
        Err(Protocol::Deadline)
    ));
    assert!(matches!(
        Sending::admit(7, raw::SendId(1), [1; 8], &[0, 5, 0, 0], 1000, future),
        Err(Protocol::Truncated)
    ));
}
