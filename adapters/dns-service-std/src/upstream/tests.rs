//! Standard wrapper observations on ordinary private UDP sockets; no provider runs.
use super::{Event, Flow, Upstream};
use std::{
    io,
    net::Ipv4Addr,
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::{net::UdpSocket, runtime::Builder, time::Instant};

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Actual private UDP sockets verify wrapper payloads and original request/cancellation correlation"
)]
fn standard_wrapper_keeps_actual_callback_and_original_socket_owner()
-> Result<(), Box<dyn std::error::Error>> {
    Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let mut owner = Upstream::start(1, 64)?;
            owner.add_dns_sa(server.local_addr()?)?;
            assert!(!owner.is_provider());
            assert_eq!(owner.slot_count(), 1);
            let request = owner.resolve(&[0x12; 12])?.request;
            let mut sent = false;
            owner
                .drive(
                    Some(Instant::now() + Duration::from_secs(1)),
                    |event| match event {
                        Event::Sent {
                            request: actual,
                            result,
                            ..
                        } => {
                            assert_eq!(actual, request);
                            assert_eq!(result.ok(), Some(12));
                            sent = true;
                            Flow::Return
                        }
                        _ => Flow::Continue,
                    },
                )
                .await?;
            assert!(sent);
            let mut query = [0; 32];
            let (bytes, source) = server.recv_from(&mut query).await?;
            assert_eq!(&query[..bytes], &[0x12; 12]);
            let answer = [0x34; 16];
            server.send_to(&answer, source).await?;
            let mut received = None;
            owner
                .drive(
                    Some(Instant::now() + Duration::from_secs(1)),
                    |event| match event {
                        Event::Datagram(data) => {
                            received = Some((data.request, data.source, data.bytes.to_vec()));
                            Flow::Return
                        }
                        _ => Flow::Continue,
                    },
                )
                .await?;
            assert_eq!(
                received,
                Some((request, server.local_addr()?, answer.to_vec()))
            );
            assert_eq!(owner.pending_requests(), 1);
            owner.resolve_cancel(request)?;
            assert_eq!(owner.pending_requests(), 0);
            assert_eq!(
                owner
                    .standard_owner()
                    .map(gnunet_dnsstub_host::DnsStub::cached_socket_count),
                Some(1)
            );
            owner.stop();
            let receipt = owner
                .take_immediate_retirement()
                .ok_or_else(|| io::Error::other("standard retirement missing"))?;
            assert!(!receipt.has_failure());
            assert!(owner.take_immediate_retirement().is_none());
            assert!(matches!(
                owner.poll_retirement(&mut Context::from_waker(Waker::noop())),
                Poll::Pending
            ));
            assert!(owner.resolve_cancel(request).is_err());
            Ok(())
        })
}
