//! Private loopback UDP exercises all seven stub APIs and persistent host state.
#![expect(
    clippy::panic_in_result_fn,
    reason = "These tests assert original UDP bytes, callback identity and finite resource ownership."
)]
use gnunet_dnsstub_host::{
    Discard, DnsStub, DropReason, Event, Family, Flow, HostError, Progress, RequestId, SocketId,
};
use gnunet_types::{Duration, Error};
use std::{
    future::Future,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    task::Poll,
    time::Duration as StdDuration,
};
use tokio::{
    net::UdpSocket,
    time::{Instant, timeout},
};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
type Stub = DnsStub<1, 64, 8>;
fn runtime() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}
async fn server4() -> io::Result<UdpSocket> {
    UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await
}
async fn server6() -> io::Result<UdpSocket> {
    UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).await
}
async fn recv(server: &UdpSocket) -> Result<(Vec<u8>, SocketAddr)> {
    let mut buf = [0; 256];
    let (len, source) = timeout(StdDuration::from_secs(2), server.recv_from(&mut buf)).await??;
    Ok((buf[..len].to_vec(), source))
}
async fn send_query(h: &mut Stub) -> Result<(RequestId, SocketId)> {
    let mut observed = None;
    let mut opened_error = None;
    let progress = h
        .drive(
            Some(Instant::now() + StdDuration::from_secs(2)),
            |event, _| match event {
                Event::Sent {
                    request,
                    socket,
                    result,
                    ..
                } => {
                    observed = Some((request, socket, result));
                    Flow::Return
                }
                Event::SocketOpened {
                    result: Err(error), ..
                } => {
                    opened_error = Some(error);
                    Flow::Return
                }
                _ => Flow::Continue,
            },
        )
        .await?;
    assert_eq!(progress, Progress::Activity);
    if let Some(error) = opened_error {
        return Err(error.into());
    }
    let (request, socket, result) = observed.ok_or("missing actual send")?;
    result?;
    Ok((request, socket))
}
async fn datagram(h: &mut Stub) -> Result<(RequestId, Vec<u8>, SocketAddr)> {
    let mut actual = None;
    let progress = h
        .drive(
            Some(Instant::now() + StdDuration::from_secs(2)),
            |event, _| {
                if let Event::Datagram(data) = event {
                    actual = Some((data.request, data.bytes.to_vec(), data.source));
                    Flow::Return
                } else {
                    Flow::Continue
                }
            },
        )
        .await?;
    assert_eq!(progress, Progress::Activity);
    actual.ok_or_else(|| "missing datagram".into())
}
#[test]
fn construction_configuration_and_resolve_have_no_network_io() -> Result {
    assert!(matches!(Stub::start(0, 64), Err(Error::Capacity)));
    assert!(matches!(Stub::start(2, 64), Err(Error::Capacity)));
    assert!(matches!(Stub::start(1, 11), Err(Error::InvalidInput)));
    assert!(matches!(Stub::start(1, 65536), Err(Error::InvalidInput)));
    let mut h = Stub::start(1, 64)?; // No Tokio runtime exists here.
    assert!(matches!(
        h.resolve(b"no server"),
        Err(HostError::Core(Error::Unavailable))
    ));
    assert_eq!(h.retry(), Duration(250_000));
    assert_eq!(h.add_dns_ip("localhost"), Err(Error::InvalidInput));
    assert_eq!(h.cached_socket_count(), 0);
    runtime()?.block_on(async {
        let server = server4().await?;
        h.add_dns_sa(server.local_addr()?)?;
        let mut query = [0x56; 12];
        let admitted = h.resolve(&query)?;
        assert_eq!(admitted.evicted, None);
        query.fill(0);
        assert_eq!(h.cached_socket_count(), 0);
        assert_eq!(h.pending_requests(), 1);
        assert_eq!(send_query(&mut h).await?.0, admitted.request);
        assert_eq!(recv(&server).await?.0, [0x56; 12]);
        let stopped = h.stop();
        assert_eq!((stopped.requests, stopped.socket_tokens), (1, 1));
        assert_eq!(h.cached_socket_count(), 0);
        assert_eq!(h.add_dns_ip("127.0.0.1"), Err(Error::Closed));
        assert!(matches!(
            h.resolve(b"closed"),
            Err(HostError::Core(Error::Closed))
        ));
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}
#[test]
fn any_configured_source_repeats_and_id_qr_are_raw_while_short_and_foreign_drop() -> Result {
    runtime()?.block_on(async {
        let (a, b, foreign) = (server4().await?, server4().await?, server4().await?);
        let mut h = Stub::start(1, 64)?;
        h.add_dns_sa(a.local_addr()?)?;
        h.add_dns_sa(b.local_addr()?)?; // head is first destination B
        h.set_retry(Duration(30_000))?;
        let request = h.resolve(b"copied query")?.request;
        let (_, socket) = send_query(&mut h).await?;
        let (query, peer) = recv(&b).await?;
        assert_eq!(query, b"copied query");
        foreign.send_to(&[9; 12], peer).await?;
        a.send_to(&[1; 11], peer).await?;
        let raw = [0xff, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]; // unrelatedID; QR0
        a.send_to(&raw, peer).await?; // A is configured but not yet queried.
        let mut drops = Vec::new();
        let mut response = None;
        h.drive(
            Some(Instant::now() + StdDuration::from_secs(2)),
            |event, _| match event {
                Event::Discarded {
                    socket: actual,
                    reason,
                    ..
                } => {
                    assert_eq!(actual, socket);
                    drops.push(reason);
                    Flow::Continue
                }
                Event::Datagram(data) => {
                    response = Some((data.request, data.source, data.bytes.to_vec()));
                    Flow::Return
                }
                _ => Flow::Continue,
            },
        )
        .await?;
        assert_eq!(
            drops,
            vec![
                Discard::Core(DropReason::UnknownPeer),
                Discard::Core(DropReason::ShortPacket)
            ]
        );
        assert_eq!(response, Some((request, a.local_addr()?, raw.to_vec())));
        b.send_to(&[7; 12], peer).await?;
        assert_eq!(
            datagram(&mut h).await?,
            (request, vec![7; 12], b.local_addr()?)
        );
        assert!(h.owns_request(request));
        assert_eq!(h.pending_requests(), 1);
        let (_, repeated) = send_query(&mut h).await?;
        assert_eq!(repeated, socket);
        assert_eq!(recv(&a).await?.0, b"copied query");
        h.resolve_cancel(request)?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}
#[test]
fn dual_family_sockets_are_v6_only_and_both_survive_cancel_reuse() -> Result {
    runtime()?.block_on(async {
        let (four, six) = (server4().await?, server6().await?);
        let mut h = Stub::start(1, 64)?;
        h.add_dns_sa(four.local_addr()?)?;
        h.add_dns_sa(six.local_addr()?)?;
        h.set_retry(Duration(20_000))?;
        let old = h.resolve(b"old")?.request;
        let (_, v6id) = send_query(&mut h).await?;
        assert_eq!(v6id.family(), Family::V6);
        let (_, sixpeer) = recv(&six).await?;
        let v6local = h.cached_socket(0, Family::V6).ok_or("missingv6")?.1;
        let only6proof = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, v6local.port()))?;
        drop(only6proof); // IPv6 cache does not claim the IPv4 namespace.
        let (_, v4id) = send_query(&mut h).await?;
        let (_, fourpeer) = recv(&four).await?;
        assert_eq!(v4id.family(), Family::V4);
        assert_eq!(h.cached_socket_count(), 2);
        six.send_to(&[6; 12], sixpeer).await?;
        assert_eq!(datagram(&mut h).await?.0, old);
        four.send_to(&[4; 12], fourpeer).await?;
        assert_eq!(datagram(&mut h).await?.0, old);
        let old4 = h.cached_socket(0, Family::V4).ok_or("missingv4")?;
        let old6 = h.cached_socket(0, Family::V6).ok_or("missingv6")?;
        h.resolve_cancel(old)?;
        assert_eq!(h.cached_socket_count(), 2);
        let new = h.resolve(b"new")?.request;
        assert_ne!(new, old);
        let (_, cached6) = send_query(&mut h).await?;
        assert_eq!(cached6, v6id);
        let (query, newpeer) = recv(&six).await?;
        assert_eq!(query, b"new");
        assert_eq!(newpeer, sixpeer);
        assert_eq!(h.cached_socket(0, Family::V4), Some(old4));
        assert_eq!(h.cached_socket(0, Family::V6), Some(old6));
        // A delayed previous-query payload has no DNS-ID match at this layer.
        four.send_to(&[0xab; 12], fourpeer).await?;
        assert_eq!(datagram(&mut h).await?.0, new);
        assert_eq!(h.resolve_cancel(old), Err(Error::StaleGeneration));
        let stopped = h.stop();
        assert_eq!((stopped.requests, stopped.socket_tokens), (1, 2));
        assert_eq!(h.cached_socket_count(), 0);
        let rebound4 = std::net::UdpSocket::bind(old4.1)?;
        let raw6 = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        raw6.set_only_v6(true)?;
        raw6.bind(&old6.1.into())?;
        drop((rebound4, raw6));
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}
#[test]
fn over_limit_datagrams_never_deliver_silently_truncated_payload() -> Result {
    runtime()?.block_on(async {
        let server = server4().await?;
        let mut h = Stub::start(1, 16)?;
        h.add_dns_sa(server.local_addr()?)?;
        h.set_retry(Duration(u64::MAX))?;
        let id = h.resolve(b"q")?.request;
        send_query(&mut h).await?;
        let (_, peer) = recv(&server).await?;
        server.send_to(&[1; 64], peer).await?;
        server.send_to(&[2; 17], peer).await?;
        server.send_to(&[3; 16], peer).await?;
        let (mut dropped, mut delivered) = (0, None);
        h.drive(
            Some(Instant::now() + StdDuration::from_secs(2)),
            |event, _| match event {
                Event::Discarded {
                    reason: Discard::Oversize { limit },
                    ..
                } => {
                    assert_eq!(limit, 16);
                    dropped += 1;
                    Flow::Continue
                }
                Event::Datagram(data) => {
                    delivered = Some((data.request, data.bytes.to_vec()));
                    Flow::Return
                }
                _ => Flow::Continue,
            },
        )
        .await?;
        assert_eq!(dropped, 2);
        assert_eq!(delivered, Some((id, vec![3; 16])));
        assert!(h.owns_request(id));
        assert_eq!(h.next_wakeup(), None);
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}
#[test]
fn callbacks_cancel_resolve_reconfigure_and_stop_synchronously_without_lost_eviction() -> Result {
    runtime()?.block_on(async {
        let (oldserver, newserver) = (server4().await?, server4().await?);
        let mut h = Stub::start(1, 64)?;
        h.add_dns_sa(oldserver.local_addr()?)?;
        let old = h.resolve(b"old")?.request;
        let (_, cache) = send_query(&mut h).await?;
        let (_, peer) = recv(&oldserver).await?;
        oldserver.send_to(&[1; 12], peer).await?;
        let mut new = None;
        let mut callback_error = None;
        h.drive(
            Some(Instant::now() + StdDuration::from_secs(2)),
            |event, ctx| {
                if let Event::Datagram(data) = event {
                    assert_eq!(data.request, old);
                    let result = (|| -> Result<RequestId> {
                        ctx.resolve_cancel(old)?;
                        ctx.add_dns_sa(newserver.local_addr()?)?;
                        ctx.add_dns_ip("127.0.0.1")?; // no lookup or network IO
                        // Insert explicit unprivileged endpoint again as head.
                        ctx.add_dns_sa(newserver.local_addr()?)?;
                        ctx.set_retry(Duration(70_000))?;
                        let admission = ctx.resolve(b"new copied")?;
                        assert_eq!(admission.evicted, None);
                        assert!(!ctx.owns_request(old));
                        assert!(ctx.owns_request(admission.request));
                        assert_eq!(ctx.cached_socket_count(), 1);
                        Ok(admission.request)
                    })();
                    match result {
                        Ok(id) => new = Some(id),
                        Err(e) => callback_error = Some(e),
                    }
                    Flow::Return
                } else {
                    Flow::Continue
                }
            },
        )
        .await?;
        if let Some(error) = callback_error {
            return Err(error);
        }
        let new = new.ok_or("no replacement")?;
        let (sent_id, samecache) = send_query(&mut h).await?;
        assert_eq!((sent_id, samecache), (new, cache));
        let (query, newpeer) = recv(&newserver).await?;
        assert_eq!(query, b"new copied");
        assert_eq!(newpeer, peer);
        newserver.send_to(&[2; 12], newpeer).await?;
        newserver.send_to(&[3; 12], newpeer).await?;
        let mut failures = Vec::new();
        let mut callbacks = 0;
        let progress = h
            .drive(
                Some(Instant::now() + StdDuration::from_secs(2)),
                |event, ctx| {
                    if let Event::Datagram(data) = event {
                        callbacks += 1;
                        assert_eq!(data.request, new);
                        match ctx.resolve(b"evict") {
                            Ok(admission) => {
                                failures.extend(admission.evicted);
                                assert!(!ctx.owns_request(new));
                                assert!(ctx.owns_request(admission.request));
                                let stopped = ctx.stop();
                                assert_eq!((stopped.requests, stopped.socket_tokens), (1, 1));
                                assert_eq!(ctx.cached_socket_count(), 0); // actual drop within callback
                                assert!(!ctx.owns_request(admission.request));
                                assert_eq!(ctx.add_dns_sa(newpeer), Err(Error::Closed));
                                // The exact local port can already be rebound, before callback return.
                                let same_port = std::net::UdpSocket::bind((
                                    Ipv4Addr::UNSPECIFIED,
                                    newpeer.port(),
                                ));
                                assert!(same_port.is_ok());
                            }
                            Err(error) => callback_error = Some(error.into()),
                        }
                    }
                    Flow::Continue
                },
            )
            .await?;
        if let Some(error) = callback_error {
            return Err(error);
        }
        assert_eq!(progress, Progress::Stopped);
        assert_eq!(callbacks, 1); // queued second packet was never dispatched
        assert_eq!(failures, vec![new]); // explicit failure token was observed
        assert!(h.is_stopped());
        let progress = h
            .drive(None, |_, _| {
                callbacks += 1;
                Flow::Continue
            })
            .await?;
        assert_eq!(progress, Progress::Stopped);
        assert_eq!(callbacks, 1);
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}
#[test]
fn future_cancel_and_drive_budget_preserve_original_retry_and_socket() -> Result {
    runtime()?.block_on(async {
        let server = server4().await?;
        let mut h = Stub::start(1, 64)?;
        h.add_dns_sa(server.local_addr()?)?;
        h.set_retry(Duration(80_000))?;
        let id = h.resolve(b"original")?.request;
        let (mut opens, mut sends) = (0, 0);
        let mut future = Box::pin(h.drive(None, |event, _| {
            match event {
                Event::SocketOpened { result, .. } => {
                    assert!(result.is_ok());
                    opens += 1
                }
                Event::Sent { result, .. } => {
                    assert!(result.is_ok());
                    sends += 1
                }
                _ => {}
            }
            Flow::Continue
        }));
        let pending =
            std::future::poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx).is_pending())).await;
        drop(future); // actual cancel while waiting for response/retry
        assert!(pending);
        assert_eq!((opens, sends), (1, 1));
        let (query, peer) = recv(&server).await?;
        assert_eq!(query, b"original");
        let due = h.next_wakeup();
        let cached = h.cached_socket(0, Family::V4);
        let mut events = 0;
        let progress = h
            .drive(
                Some(Instant::now() + StdDuration::from_millis(5)),
                |_, _| {
                    events += 1;
                    Flow::Continue
                },
            )
            .await?;
        assert_eq!(progress, Progress::WaitDeadline);
        assert_eq!(events, 0); // budget isn't a DNS failure callback
        assert!(h.owns_request(id));
        assert_eq!(h.next_wakeup(), due);
        assert_eq!(h.cached_socket(0, Family::V4), cached);
        let mut future = Box::pin(h.drive(None, |_, _| Flow::Continue));
        let pending =
            std::future::poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx).is_pending())).await;
        drop(future);
        assert!(pending);
        assert_eq!(h.next_wakeup(), due);
        assert_eq!(send_query(&mut h).await?.0, id);
        let (retry, repeatpeer) = recv(&server).await?;
        assert_eq!(retry, b"original");
        assert_eq!(repeatpeer, peer);
        assert_eq!(h.cached_socket(0, Family::V4), cached);
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}
#[test]
fn early_return_between_lazy_open_and_send_retains_exact_effect() -> Result {
    runtime()?.block_on(async {
        let server = server4().await?;
        let mut h = Stub::start(1, 64)?;
        h.add_dns_sa(server.local_addr()?)?;
        h.set_retry(Duration(u64::MAX))?;
        let id = h.resolve(b"one send")?.request;
        let mut opened = None;
        let progress = h
            .drive(None, |event, _| {
                if let Event::SocketOpened { socket, result } = event {
                    assert!(result.is_ok());
                    opened = Some(socket)
                }
                Flow::Return
            })
            .await?;
        assert_eq!(progress, Progress::Activity);
        assert_eq!(h.cached_socket_count(), 1);
        let mut buffer = [0; 64];
        assert_eq!(
            server
                .try_recv_from(&mut buffer)
                .map(|v| v.0)
                .unwrap_or_else(|e| if e.kind() == io::ErrorKind::WouldBlock {
                    0
                } else {
                    usize::MAX
                }),
            0
        );
        let (sent, cache) = send_query(&mut h).await?;
        assert_eq!(sent, id);
        assert_eq!(Some(cache), opened);
        assert_eq!(recv(&server).await?.0, b"one send");
        let mut callbacks = 0;
        assert_eq!(
            h.drive(
                Some(Instant::now() + StdDuration::from_millis(5)),
                |_, _| {
                    callbacks += 1;
                    Flow::Continue
                }
            )
            .await?,
            Progress::WaitDeadline
        );
        assert_eq!(callbacks, 0);
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}
#[test]
fn ordinary_send_error_is_observed_without_cancelling_retry_or_closing_socket() -> Result {
    runtime()?.block_on(async {
        let mut h = Stub::start(1, 64)?;
        h.add_dns_sa(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        h.set_retry(Duration(10_000))?;
        let request = h.resolve(b"unreachable port zero")?.request;
        let (mut attempts, mut failures) = (0, 0);
        let mut cache = None;
        h.drive(
            Some(Instant::now() + StdDuration::from_secs(2)),
            |event, _| {
                if let Event::Sent {
                    request: original,
                    socket,
                    result,
                    ..
                } = event
                {
                    assert_eq!(original, request);
                    if let Some(previous) = cache {
                        assert_eq!(previous, socket)
                    }
                    cache = Some(socket);
                    attempts += 1;
                    failures += usize::from(result.is_err());
                    if attempts == 2 {
                        return Flow::Return;
                    }
                }
                Flow::Continue
            },
        )
        .await?;
        assert_eq!(attempts, 2);
        assert_eq!(failures, 2); // actual native sendto(127.0.0.1:0) rejects here
        assert!(h.owns_request(request));
        assert_eq!(h.cached_socket_count(), 1);
        assert!(h.next_wakeup().is_some());
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}
#[test]
fn drop_closes_canceled_slot_socket_without_result_callbacks() -> Result {
    runtime()?.block_on(async {
        let server = server4().await?;
        let mut h = Stub::start(1, 64)?;
        h.add_dns_sa(server.local_addr()?)?;
        let id = h.resolve(b"drop")?.request;
        send_query(&mut h).await?;
        recv(&server).await?;
        let local = h.cached_socket(0, Family::V4).ok_or("missing socket")?.1;
        h.resolve_cancel(id)?;
        assert_eq!(h.cached_socket_count(), 1);
        assert!(std::net::UdpSocket::bind(local).is_err());
        drop(h);
        let rebound = std::net::UdpSocket::bind(local)?;
        drop(rebound);
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}

#[test]
fn readable_backlog_cannot_starve_due_retry_even_across_early_returns() -> Result {
    runtime()?.block_on(async {
        let server = server4().await?;
        let mut h = Stub::start(1, 64)?;
        h.add_dns_sa(server.local_addr()?)?;
        h.set_retry(Duration(15_000))?;
        let request = h.resolve(b"fair retry")?.request;
        let (_, cache) = send_query(&mut h).await?;
        let (_, peer) = recv(&server).await?;
        // This queue remains readable across the driver's32-work poll budget.
        for _ in 0..96 {
            server.send_to(&[0; 11], peer).await?;
        }
        tokio::time::sleep(StdDuration::from_millis(20)).await;
        let (mut reads, mut sends) = (0, 0);
        for _ in 0..2 {
            h.drive(
                Some(Instant::now() + StdDuration::from_secs(1)),
                |event, _| {
                    match event {
                        Event::Discarded {
                            reason: Discard::Core(DropReason::ShortPacket),
                            ..
                        } => reads += 1,
                        Event::Sent {
                            request: actual,
                            socket,
                            result,
                            ..
                        } => {
                            assert_eq!((actual, socket), (request, cache));
                            assert!(result.is_ok());
                            sends += 1
                        }
                        _ => {}
                    }
                    Flow::Return
                },
            )
            .await?;
        }
        assert_eq!((reads, sends), (1, 1)); // fairness bit survives drive return
        assert_eq!(recv(&server).await?.0, b"fair retry");
        tokio::time::sleep(StdDuration::from_millis(20)).await;
        let (mut events, mut first_send) = (0, None);
        assert_eq!(
            h.drive(
                Some(Instant::now() + StdDuration::from_millis(3)),
                |event, _| {
                    if let Event::Sent { .. } = event {
                        first_send.get_or_insert(events);
                    }
                    events += 1;
                    Flow::Continue // only caller budget terminates the drive
                }
            )
            .await?,
            Progress::WaitDeadline
        );
        assert!(first_send.is_some_and(|at| at <= 1));
        assert!(events > 2); // real queued receive work followed the due send
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}

#[test]
fn zero_retry_cannot_starve_readable_results_with_continue_callbacks() -> Result {
    runtime()?.block_on(async {
        let server = server4().await?;
        let mut h = Stub::start(1, 64)?;
        h.add_dns_sa(server.local_addr()?)?;
        h.set_retry(Duration(0))?;
        let request = h.resolve(b"zero retry")?.request;
        send_query(&mut h).await?;
        let (_, peer) = recv(&server).await?;
        server.send_to(&[0xab; 12], peer).await?;
        let (mut responses, mut sends) = (0, 0);
        assert_eq!(
            h.drive(
                Some(Instant::now() + StdDuration::from_secs(2)),
                |event, _| {
                    match event {
                        Event::Datagram(data) => {
                            assert_eq!(data.request, request);
                            assert_eq!(data.bytes, &[0xab; 12]);
                            responses += 1
                        }
                        Event::Sent {
                            request: actual, ..
                        } => {
                            assert_eq!(actual, request);
                            sends += 1;
                            // The result callback continued; a subsequent real
                            // retry proves that it did not complete the request.
                            if responses != 0 {
                                return Flow::Return;
                            }
                        }
                        _ => {}
                    }
                    Flow::Continue // response itself does not stop this raw stub
                }
            )
            .await?,
            Progress::Activity
        );
        assert_eq!(responses, 1);
        assert!(sends > 0);
        assert!(h.owns_request(request));
        // Check the caller budget separately from reactor delivery latency.
        // A loaded host need not publish new readiness within five milliseconds.
        assert_eq!(
            h.drive(
                Some(Instant::now() + StdDuration::from_millis(5)),
                |_, _| Flow::Continue,
            )
            .await?,
            Progress::WaitDeadline
        );
        assert!(h.owns_request(request));
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}
