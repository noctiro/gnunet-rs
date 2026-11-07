//! Actual bounded Resolver Unix/TCP/UDP lifetime and interoperability tests.
#![expect(
    clippy::unwrap_used,
    reason = "Test-only constructors assert fixed valid frame fixtures and local runtime setup"
)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Actual socket tests assert wire bytes, original identities, capacities and physical close outcomes"
)]
use gnunet_client::resolver::{Family, FamilyProfile, Request, Response, WireId};
use gnunet_dns::{AbsoluteTime, Idna};
use gnunet_idna::{Backend, NativeProfile, Workspace};
use gnunet_resolver_host::{
    Host, Limits, Ports,
    storage::{Geometry, Store},
};
use gnunet_resolver_service_core::{owner::Resolver, storage::Limits as CoreLimits};
use gnunet_service_runtime::service::{Listener, ServiceOptions, ShutdownMode};
use gnunet_wire::official::Frame;
use std::{
    future::{Future, poll_fn},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    task::Poll,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket, UnixListener, UnixStream},
    time::Instant,
};
type E = Box<dyn std::error::Error>;
fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}
fn utc() -> Result<AbsoluteTime, gnunet_types::Error> {
    Ok(AbsoluteTime::from_micros(1_000_000_000))
}
fn path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "gnunet-resolver-host-{}-{label}.sock",
        std::process::id()
    ))
}
macro_rules! setup {
    ($host:ident,$limits:expr,$slots:expr,$hosts:expr) => {
        setup!($host, $limits, $slots, $hosts, ServiceOptions::default());
    };
    ($host:ident,$limits:expr,$slots:expr,$hosts:expr,$options:expr) => {
        let g = Geometry {
            clients: 8,
            lookups: 16,
            hosts: 32,
            buckets: 1025,
            records: 128,
            effects: 128,
            byte_pool: 256 * 1024,
        };
        let mut backing = Store::new(g)?;
        let mut staging = Store::new(g)?;
        let core = Resolver::new(
            backing.buffers(),
            CoreLimits {
                max_name_bytes: 65535,
                max_record_bytes: 65535,
                cname_hops: 32,
            },
            1,
        )?;
        let stage = core.make_scratch(staging.buffers())?;
        let mut workspace = Workspace::new();
        let backend = Backend::new(
            &mut workspace,
            gnunet_idna::Limits::GNUNET,
            NativeProfile::Libunistring1_5Unicode18_0,
        );
        let mut $host = Host::<_, 4, 271, 8>::new(
            core,
            stage,
            &backend,
            Ports {
                epoch: Instant::now(),
                utc,
                random_below: gnunet_resolver_host::system_random_below,
            },
            FamilyProfile::DARWIN,
            $limits,
            $options,
            $slots,
        )?;
        $host.load_machine_bytes($hosts, b"")?;
    };
}
async fn driven<I: Idna, F: Future>(
    host: &mut Host<'_, '_, I, 4, 271, 8>,
    listeners: &[Listener<'_>],
    test: F,
) -> Result<F::Output, E> {
    let until = Instant::now() + Duration::from_secs(5);
    let mut h = std::pin::pin!(host.drive(listeners, Some(until), |_| {}));
    let mut t = std::pin::pin!(test);
    poll_fn(|cx| {
        if let Poll::Ready(v) = t.as_mut().poll(cx) {
            return Poll::Ready(Ok(v));
        }
        match h.as_mut().poll(cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(Box::new(e) as E)),
            Poll::Ready(Ok(_)) => Poll::Ready(Err("reactor completed before test".into())),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}
async fn frame(stream: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>, E> {
    let mut h = [0; 4];
    stream.read_exact(&mut h).await?;
    let n = u16::from_be_bytes([h[0], h[1]]) as usize;
    assert!(n >= 4);
    let mut b = vec![0; n];
    b[..4].copy_from_slice(&h);
    stream.read_exact(&mut b[4..]).await?;
    Ok(b)
}
fn req(id: u32, f: Family, name: &[u8]) -> Vec<u8> {
    let r = Request::forward(WireId::from_native(id), f, name).unwrap();
    let mut b = vec![0; r.encoded_len().unwrap()];
    r.encode(FamilyProfile::DARWIN, &mut b).unwrap();
    b
}
fn answer(q: &[u8], kind: u16, data: &[u8]) -> Vec<u8> {
    let mut b = q.to_vec();
    b[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    b[6..8].copy_from_slice(&1u16.to_be_bytes());
    b.extend_from_slice(&[0xc0, 0x0c]);
    b.extend_from_slice(&kind.to_be_bytes());
    b.extend_from_slice(&1u16.to_be_bytes());
    b.extend_from_slice(&3600u32.to_be_bytes());
    b.extend_from_slice(&(data.len() as u16).to_be_bytes());
    b.extend_from_slice(data);
    b
}
fn data(b: &[u8]) -> Vec<u8> {
    Response::decode(Frame::decode(b).unwrap())
        .unwrap()
        .payload()
        .to_vec()
}
fn name_wire(s: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    for l in s.split(|b| *b == b'.') {
        v.push(l.len() as u8);
        v.extend_from_slice(l)
    }
    v.push(0);
    v
}
#[test]
fn actual_unix_partial_io_and_cached_hosts_do_not_open_udp() -> Result<(), E> {
    rt().block_on(async {
        let p = path("partial");
        let listener = UnixListener::bind(&p)?;
        let l = Limits {
            io_slice_bytes: 1,
            ..Limits::default()
        };
        setup!(host, l, 4, b"192.0.2.7 owned.example\n");
        driven(&mut host, &[Listener::Unix(&listener)], async {
            let mut s = UnixStream::connect(&p).await?;
            for b in req(7, Family::V4, b"owned.example") {
                s.write_all(&[b]).await?;
            }
            let first = frame(&mut s).await?;
            assert_eq!(data(&first), [192, 0, 2, 7]);
            assert_eq!(&first[4..8], &7u32.to_ne_bytes());
            assert!(data(&frame(&mut s).await?).is_empty());
            Ok::<_, E>(())
        })
        .await??;
        assert_eq!(host.report().queued_frames, 2);
        assert_eq!(host.report().udp_sends, 0);
        host.shutdown(ShutdownMode::Immediate)?;
        assert!(host.is_stopped());
        assert_eq!(host.connections(), 0);
        drop(listener);
        std::fs::remove_file(p)?;
        Ok(())
    })
}
#[test]
fn actual_tcp_any_a_then_aaaa_and_native_unicode_question() -> Result<(), E> {
    rt().block_on(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        setup!(host, Limits::default(), 4, b"");
        host.add_dns_endpoint(udp.local_addr()?)?;
        driven(&mut host, &[Listener::Tcp(&listener)], async {
            let mut s = TcpStream::connect(addr).await?;
            s.write_all(&req(9, Family::Any, "é.example".as_bytes()))
                .await?;
            let mut q = [0; 512];
            let (n, peer) = udp.recv_from(&mut q).await?;
            assert!(q[..n].windows(7).any(|w| w == b"xn--9ca"));
            assert_eq!(&q[n - 4..n - 2], &1u16.to_be_bytes());
            udp.send_to(&answer(&q[..n], 1, &[192, 0, 2, 8]), peer)
                .await?;
            let (m, peer2) = udp.recv_from(&mut q).await?;
            assert_eq!(&q[m - 4..m - 2], &28u16.to_be_bytes());
            udp.send_to(&answer(&q[..m], 28, &Ipv6Addr::LOCALHOST.octets()), peer2)
                .await?;
            assert_eq!(data(&frame(&mut s).await?), Ipv6Addr::LOCALHOST.octets());
            assert_eq!(data(&frame(&mut s).await?), [192, 0, 2, 8]);
            assert!(data(&frame(&mut s).await?).is_empty());
            Ok::<_, E>(())
        })
        .await??;
        assert_eq!(host.report().udp_sends, 2);
        assert_eq!(host.pending_lookups(), 0);
        assert_eq!(host.pending_stub_requests(), 0);
        host.shutdown(ShutdownMode::Immediate)?;
        Ok(())
    })
}
#[test]
fn actual_ipv6_dns_transport_ptr_and_wrong_id_malformed_are_nonterminal() -> Result<(), E> {
    rt().block_on(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let udp = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).await?;
        setup!(host, Limits::default(), 4, b"");
        host.add_dns_endpoint(udp.local_addr()?)?;
        driven(&mut host, &[Listener::Tcp(&listener)], async {
            let mut s = TcpStream::connect(address).await?;
            let r = Request::reverse(
                WireId::from_native(11),
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            );
            let mut b = [0; 32];
            let n = r.encode(FamilyProfile::DARWIN, &mut b)?;
            s.write_all(&b[..n]).await?;
            let mut q = [0; 512];
            let (n, peer) = udp.recv_from(&mut q).await?;
            assert_eq!(&q[n - 4..n - 2], &12u16.to_be_bytes());
            let mut wrong = answer(&q[..n], 12, &name_wire(b"owned.example"));
            wrong[0] ^= 0x80;
            udp.send_to(&wrong, peer).await?;
            let mut malformed = answer(&q[..n], 12, &[0xc0]);
            malformed[6..8].copy_from_slice(&1u16.to_be_bytes());
            udp.send_to(&malformed, peer).await?;
            let mut impossible = q[..12].to_vec();
            impossible[4..6].copy_from_slice(&65535u16.to_be_bytes());
            udp.send_to(&impossible, peer).await?;
            udp.send_to(&answer(&q[..n], 12, &name_wire(b"owned.example")), peer)
                .await?;
            assert_eq!(data(&frame(&mut s).await?), b"owned.example\0");
            assert!(data(&frame(&mut s).await?).is_empty());
            Ok::<_, E>(())
        })
        .await??;
        assert!(host.report().malformed_dns >= 1);
        assert_eq!(host.report().dns_results, 2);
        host.shutdown(ShutdownMode::Immediate)?;
        Ok(())
    })
}
#[test]
fn actual_two_clients_duplicate_ids_malformed_isolation_and_eof_cancel() -> Result<(), E> {
    rt().block_on(async {
        let p = path("isolation");
        let listener = UnixListener::bind(&p)?;
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        setup!(host, Limits::default(), 4, b"192.0.2.5 hit.example\n");
        host.add_dns_endpoint(udp.local_addr()?)?;
        driven(&mut host, &[Listener::Unix(&listener)], async {
            let mut bad = UnixStream::connect(&p).await?;
            let mut good = UnixStream::connect(&p).await?;
            bad.write_all(&[0, 4, 0, 4]).await?;
            let mut eof = [0];
            assert_eq!(bad.read(&mut eof).await?, 0);
            good.write_all(&req(3, Family::V4, b"hit.example")).await?;
            good.write_all(&req(3, Family::V4, b"miss.example")).await?;
            assert_eq!(data(&frame(&mut good).await?), [192, 0, 2, 5]);
            assert!(data(&frame(&mut good).await?).is_empty());
            let mut q = [0; 512];
            let (_, _) = udp.recv_from(&mut q).await?;
            drop(good);
            tokio::time::sleep(Duration::from_millis(10)).await;
            Ok::<_, E>(())
        })
        .await??;
        host.drive(
            &[Listener::Unix(&listener)],
            Some(Instant::now() + Duration::from_millis(10)),
            |_| {},
        )
        .await?;
        assert_eq!(host.pending_lookups(), 0);
        assert_eq!(host.pending_stub_requests(), 0);
        assert_eq!(host.connections(), 0);
        assert_eq!(host.report().admitted, 2);
        host.shutdown(ShutdownMode::Immediate)?;
        drop(listener);
        std::fs::remove_file(p)?;
        Ok(())
    })
}
#[test]
fn canceled_drive_retains_real_dns_owner_and_resumes_without_replay() -> Result<(), E> {
    rt().block_on(async {
        let p = path("resume");
        let listener = UnixListener::bind(&p)?;
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        setup!(host, Limits::default(), 4, b"");
        host.add_dns_endpoint(udp.local_addr()?)?;
        let mut s = UnixStream::connect(&p).await?;
        s.write_all(&req(23, Family::V4, b"resume.example")).await?;
        let mut q = [0; 512];
        let (n, peer) = driven(
            &mut host,
            &[Listener::Unix(&listener)],
            udp.recv_from(&mut q),
        )
        .await??;
        assert_eq!(host.pending_lookups(), 1);
        assert_eq!(host.pending_stub_requests(), 1);
        assert_eq!(host.report().requests, 1);
        let cached = host.cached_udp_socket(0, gnunet_dnsstub_host::Family::V4);
        assert!(cached.is_some() || host.report().udp_sends == 1);
        udp.send_to(&answer(&q[..n], 1, &[192, 0, 2, 23]), peer)
            .await?;
        driven(&mut host, &[Listener::Unix(&listener)], async {
            assert_eq!(data(&frame(&mut s).await?), [192, 0, 2, 23]);
            assert!(data(&frame(&mut s).await?).is_empty());
            Ok::<_, E>(())
        })
        .await??;
        assert_eq!(host.report().requests, 1);
        assert_eq!(host.report().udp_sends, 1);
        host.shutdown(ShutdownMode::Immediate)?;
        drop(listener);
        std::fs::remove_file(p)?;
        Ok(())
    })
}
#[test]
fn actual_stub_eviction_detaches_old_owner_and_later_request_survives() -> Result<(), E> {
    rt().block_on(async {
        let p = path("eviction");
        let listener = UnixListener::bind(&p)?;
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        setup!(host, Limits::default(), 1, b"");
        host.add_dns_endpoint(udp.local_addr()?)?;
        let mut first = UnixStream::connect(&p).await?;
        first
            .write_all(&req(1, Family::V4, b"first.example"))
            .await?;
        let mut q = [0; 512];
        let (_, _) = driven(
            &mut host,
            &[Listener::Unix(&listener)],
            udp.recv_from(&mut q),
        )
        .await??;
        let mut second = UnixStream::connect(&p).await?;
        second
            .write_all(&req(2, Family::V4, b"second.example"))
            .await?;
        let (n, peer) = driven(
            &mut host,
            &[Listener::Unix(&listener)],
            udp.recv_from(&mut q),
        )
        .await??;
        assert_eq!(host.report().stub_evictions, 1);
        assert_eq!(host.pending_lookups(), 2);
        assert_eq!(host.pending_stub_requests(), 1);
        drop(first);
        host.drive(
            &[Listener::Unix(&listener)],
            Some(Instant::now() + Duration::from_millis(10)),
            |_| {},
        )
        .await?;
        assert_eq!(host.pending_lookups(), 1);
        assert_eq!(host.pending_stub_requests(), 1);
        udp.send_to(&answer(&q[..n], 1, &[192, 0, 2, 2]), peer)
            .await?;
        driven(&mut host, &[Listener::Unix(&listener)], async {
            assert_eq!(data(&frame(&mut second).await?), [192, 0, 2, 2]);
            assert!(data(&frame(&mut second).await?).is_empty());
            Ok::<_, E>(())
        })
        .await??;
        host.shutdown(ShutdownMode::Immediate)?;
        drop(listener);
        std::fs::remove_file(p)?;
        Ok(())
    })
}
#[test]
fn genuine_socket_backpressure_retains_effect_ticket_across_canceled_drive() -> Result<(), E> {
    rt().block_on(async {
        let p = path("backpressure");
        let listener = UnixListener::bind(&p)?;
        socket2::SockRef::from(&listener).set_send_buffer_size(4096)?;
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let limits = Limits {
            max_pending_bytes: 8192,
            ..Limits::default()
        };
        setup!(host, limits, 4, b"");
        host.add_dns_endpoint(udp.local_addr()?)?;
        let mut s = UnixStream::connect(&p).await?;
        socket2::SockRef::from(&s).set_recv_buffer_size(4096)?;
        s.write_all(&req(1, Family::V4, b"large.example")).await?;
        let mut q = [0; 512];
        let (n, peer) = driven(
            &mut host,
            &[Listener::Unix(&listener)],
            udp.recv_from(&mut q),
        )
        .await??;
        let payload = vec![0xa7; 8000];
        udp.send_to(&answer(&q[..n], 1, &payload), peer).await?;
        let mut submitted = Vec::new();
        for id in 2..=30 {
            submitted.extend_from_slice(&req(id, Family::V4, b"large.example"));
        }
        s.write_all(&submitted).await?;
        let canceled = tokio::time::timeout(
            Duration::from_millis(40),
            host.drive(&[Listener::Unix(&listener)], None, |_| {}),
        )
        .await;
        assert!(canceled.is_err());
        assert!(host.current_effect().is_some());
        assert!(host.pending_tx_bytes() > 0);
        assert!(host.pending_tx_bytes() <= 8192);
        let before = host.report().requests;
        driven(&mut host, &[Listener::Unix(&listener)], async {
            for id in 1u32..=30 {
                let b = frame(&mut s).await?;
                assert_eq!(&b[4..8], &id.to_ne_bytes());
                assert_eq!(data(&b), payload);
                let end = frame(&mut s).await?;
                assert_eq!(&end[4..8], &id.to_ne_bytes());
                assert!(data(&end).is_empty());
            }
            Ok::<_, E>(())
        })
        .await??;
        assert!(host.report().requests >= before);
        assert_eq!(host.report().requests, 30);
        assert_eq!(host.report().udp_sends, 1);
        assert_eq!(host.current_effect(), None);
        host.shutdown(ShutdownMode::Immediate)?;
        drop(listener);
        std::fs::remove_file(p)?;
        Ok(())
    })
}
#[test]
fn actual_ipc_no_upstream_uses_original_thirty_second_monotonic_deadline() -> Result<(), E> {
    rt().block_on(async {
        tokio::time::pause();
        let p = path("timeout");
        let listener = UnixListener::bind(&p)?;
        setup!(host, Limits::default(), 4, b"");
        let mut s = UnixStream::connect(&p).await?;
        s.write_all(&req(81, Family::V4, b"not-in-hosts.example"))
            .await?;
        host.drive(
            &[Listener::Unix(&listener)],
            Some(Instant::now() + Duration::from_millis(1)),
            |_| {},
        )
        .await?;
        assert_eq!(host.pending_lookups(), 1);
        assert_eq!(host.pending_stub_requests(), 0);
        assert_eq!(host.report().unavailable_queries, 1);
        tokio::time::advance(Duration::from_secs(29)).await;
        host.drive(&[Listener::Unix(&listener)], Some(Instant::now()), |_| {})
            .await?;
        assert_eq!(host.pending_lookups(), 1);
        tokio::time::advance(Duration::from_secs(1)).await;
        driven(&mut host, &[Listener::Unix(&listener)], async {
            assert!(data(&frame(&mut s).await?).is_empty());
            Ok::<_, E>(())
        })
        .await??;
        assert_eq!(host.pending_lookups(), 0);
        assert_eq!(host.report().queued_frames, 1);
        host.shutdown(ShutdownMode::Immediate)?;
        drop(listener);
        std::fs::remove_file(p)?;
        Ok(())
    })
}
#[test]
fn actual_consumed_dns_capacity_error_retains_datagram_and_original_owner() -> Result<(), E> {
    rt().block_on(async {
        let p = path("resource");
        let listener = UnixListener::bind(&p)?;
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        setup!(host, Limits::default(), 4, b"");
        host.add_dns_endpoint(udp.local_addr()?)?;
        let mut s = UnixStream::connect(&p).await?;
        s.write_all(&req(44, Family::V4, b"capacity.example"))
            .await?;
        let mut q = [0; 512];
        let (n, peer) = driven(
            &mut host,
            &[Listener::Unix(&listener)],
            udp.recv_from(&mut q),
        )
        .await??;
        let one = answer(&q[..n], 1, &[192, 0, 2, 44]);
        let mut response = one.clone();
        response[6..8].copy_from_slice(&129u16.to_be_bytes());
        for _ in 1..129 {
            response.extend_from_slice(&one[n..]);
        }
        udp.send_to(&response, peer).await?;
        let failed = host
            .drive(
                &[Listener::Unix(&listener)],
                Some(Instant::now() + Duration::from_secs(1)),
                |_| {},
            )
            .await;
        assert!(matches!(
            failed,
            Err(gnunet_resolver_host::HostError::Core(
                gnunet_types::Error::Capacity
            ))
        ));
        assert!(host.has_pending_dns_datagram());
        assert_eq!(host.pending_lookups(), 1);
        assert_eq!(host.pending_stub_requests(), 1);
        assert_eq!(host.report().queued_frames, 0);
        let again = host
            .drive(&[Listener::Unix(&listener)], Some(Instant::now()), |_| {})
            .await;
        assert!(matches!(
            again,
            Err(gnunet_resolver_host::HostError::Core(
                gnunet_types::Error::Capacity
            ))
        ));
        assert!(host.has_pending_dns_datagram());
        assert_eq!(host.report().requests, 1);
        assert_eq!(host.report().dns_results, 0);
        host.shutdown(ShutdownMode::Immediate)?;
        assert!(!host.has_pending_dns_datagram());
        assert_eq!(host.connections(), 0);
        assert_eq!(host.pending_stub_requests(), 0);
        let mut b = [0];
        assert_eq!(s.read(&mut b).await?, 0);
        drop(listener);
        std::fs::remove_file(p)?;
        Ok(())
    })
}

#[test]
fn actual_tcp_acl_denial_never_allocates_client_and_unix_still_works() -> Result<(), E> {
    rt().block_on(async {
        let p = path("acl");
        let unix = UnixListener::bind(&p)?;
        let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let mut config = gnunet_config::Configuration::new(Default::default());
        config.set_value(b"resolver", b"REJECT_FROM", Some(b"127.0.0.1;"))?;
        let options = ServiceOptions {
            access: gnunet_service_runtime::acl::AccessPolicy::from_config(&config, b"resolver")?,
            ..ServiceOptions::default()
        };
        setup!(
            host,
            Limits::default(),
            4,
            b"192.0.2.90 acl.example\n",
            options
        );
        driven(
            &mut host,
            &[Listener::Unix(&unix), Listener::Tcp(&tcp)],
            async {
                let mut denied = TcpStream::connect(tcp.local_addr()?).await?;
                let mut end = [0];
                assert_eq!(denied.read(&mut end).await?, 0);
                let mut accepted = UnixStream::connect(&p).await?;
                accepted
                    .write_all(&req(90, Family::V4, b"acl.example"))
                    .await?;
                assert_eq!(data(&frame(&mut accepted).await?), [192, 0, 2, 90]);
                assert!(data(&frame(&mut accepted).await?).is_empty());
                Ok::<_, E>(())
            },
        )
        .await??;
        assert_eq!(host.report().accepted, 2);
        assert_eq!(host.report().admitted, 1);
        assert_eq!(host.report().rejected, 1);
        host.shutdown(ShutdownMode::Immediate)?;
        drop(unix);
        std::fs::remove_file(p)?;
        Ok(())
    })
}
#[test]
fn actual_wall_clock_timer_wakes_no_upstream_lookup_after_thirty_seconds() -> Result<(), E> {
    rt().block_on(async {
        let p = path("real-timeout");
        let listener = UnixListener::bind(&p)?;
        setup!(host, Limits::default(), 4, b"");
        let started = Instant::now();
        let mut client = UnixStream::connect(&p).await?;
        client
            .write_all(&req(99, Family::V4, b"real-timeout.example"))
            .await?;
        let ended = {
            let listeners = [Listener::Unix(&listener)];
            let mut drive = std::pin::pin!(host.drive(&listeners, None, |_| {}));
            let mut result = std::pin::pin!(frame(&mut client));
            tokio::time::timeout(
                Duration::from_secs(35),
                poll_fn(|cx| {
                    if let Poll::Ready(answer) = result.as_mut().poll(cx) {
                        return Poll::Ready(answer);
                    }
                    match drive.as_mut().poll(cx) {
                        Poll::Ready(Err(error)) => Poll::Ready(Err(Box::new(error) as E)),
                        Poll::Ready(Ok(_)) => {
                            Poll::Ready(Err("reactor stopped before original timeout".into()))
                        }
                        Poll::Pending => Poll::Pending,
                    }
                }),
            )
            .await??
        };
        assert!(data(&ended).is_empty());
        assert!(started.elapsed() >= Duration::from_secs(30));
        assert_eq!(host.report().queued_frames, 1);
        assert_eq!(host.report().unavailable_queries, 1);
        assert_eq!(host.pending_lookups(), 0);
        host.shutdown(ShutdownMode::Immediate)?;
        drop(listener);
        std::fs::remove_file(p)?;
        Ok(())
    })
}
#[test]
fn queued_start_never_mints_after_deadline_and_unrelated_buffered_eof_is_cleaned() -> Result<(), E>
{
    rt().block_on(async {
        let p = path("expired-start");
        let listener = UnixListener::bind(&p)?;
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        setup!(
            host,
            Limits {
                max_pending_bytes: 8192,
                ..Limits::default()
            },
            4,
            b""
        );
        host.add_dns_endpoint(udp.local_addr()?)?;
        let mut slow = UnixStream::connect(&p).await?;
        socket2::SockRef::from(&slow).set_recv_buffer_size(4096)?;
        slow.write_all(&req(1, Family::V4, b"large.example"))
            .await?;
        let mut q = [0; 512];
        let (n, peer) = driven(
            &mut host,
            &[Listener::Unix(&listener)],
            udp.recv_from(&mut q),
        )
        .await??;
        let payload = vec![0xb6; 8000];
        udp.send_to(&answer(&q[..n], 1, &payload), peer).await?;
        driven(&mut host, &[Listener::Unix(&listener)], async {
            assert_eq!(data(&frame(&mut slow).await?), payload);
            assert!(data(&frame(&mut slow).await?).is_empty());
            Ok::<_, E>(())
        })
        .await??;
        tokio::time::pause();
        let mut submitted = Vec::new();
        for id in 2..=31 {
            submitted.extend_from_slice(&req(id, Family::V4, b"large.example"));
        }
        slow.write_all(&submitted).await?;
        host.drive(
            &[Listener::Unix(&listener)],
            Some(Instant::now() + Duration::from_millis(5)),
            |_| {},
        )
        .await?;
        assert!(host.current_effect().is_some());
        let mut waiting = UnixStream::connect(&p).await?;
        let mut eof = UnixStream::connect(&p).await?;
        waiting
            .write_all(&req(777, Family::V4, b"must-expire.example"))
            .await?;
        eof.write_all(&req(888, Family::V4, b"must-be-canceled.example"))
            .await?;
        drop(eof);
        host.drive(
            &[Listener::Unix(&listener)],
            Some(Instant::now() + Duration::from_millis(5)),
            |_| {},
        )
        .await?;
        assert_eq!(host.connections(), 2);
        assert_eq!(host.pending_lookups(), 1);
        assert_eq!(host.pending_stub_requests(), 0);
        assert!(host.current_effect().is_some());
        tokio::time::advance(Duration::from_secs(31)).await;
        driven(&mut host, &[Listener::Unix(&listener)], async {
            for id in 2u32..=31 {
                let b = frame(&mut slow).await?;
                assert_eq!(&b[4..8], &id.to_ne_bytes());
                assert_eq!(data(&b), payload);
                assert!(data(&frame(&mut slow).await?).is_empty());
            }
            let end = frame(&mut waiting).await?;
            assert_eq!(&end[4..8], &777u32.to_ne_bytes());
            assert!(data(&end).is_empty());
            Ok::<_, E>(())
        })
        .await??;
        assert_eq!(host.report().udp_sends, 1);
        assert_eq!(host.pending_lookups(), 0);
        assert_eq!(host.pending_stub_requests(), 0);
        assert!(
            matches!(udp.try_recv_from(&mut q),Err(e) if e.kind()==std::io::ErrorKind::WouldBlock)
        );
        host.shutdown(ShutdownMode::Immediate)?;
        drop(listener);
        std::fs::remove_file(p)?;
        Ok(())
    })
}
#[test]
fn consumed_datagram_waits_behind_real_tx_pressure_then_recovers_on_drive() -> Result<(), E> {
    rt().block_on(async {
        let p = path("pending-recover");
        let listener = UnixListener::bind(&p)?;
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        setup!(
            host,
            Limits {
                max_pending_bytes: 8192,
                ..Limits::default()
            },
            4,
            b""
        );
        host.add_dns_endpoint(udp.local_addr()?)?;
        let mut slow = UnixStream::connect(&p).await?;
        socket2::SockRef::from(&slow).set_recv_buffer_size(4096)?;
        slow.write_all(&req(1, Family::V4, b"large.example"))
            .await?;
        let mut q = [0; 512];
        let (n, peer) = driven(
            &mut host,
            &[Listener::Unix(&listener)],
            udp.recv_from(&mut q),
        )
        .await??;
        let payload = vec![0x7d; 8000];
        udp.send_to(&answer(&q[..n], 1, &payload), peer).await?;
        driven(&mut host, &[Listener::Unix(&listener)], async {
            assert_eq!(data(&frame(&mut slow).await?), payload);
            assert!(data(&frame(&mut slow).await?).is_empty());
            Ok::<_, E>(())
        })
        .await??;
        let mut fast = UnixStream::connect(&p).await?;
        fast.write_all(&req(67, Family::V4, b"pending.example"))
            .await?;
        let (n, peer) = driven(
            &mut host,
            &[Listener::Unix(&listener)],
            udp.recv_from(&mut q),
        )
        .await??;
        let mut submitted = Vec::new();
        for id in 2..=31 {
            submitted.extend_from_slice(&req(id, Family::V4, b"large.example"));
        }
        slow.write_all(&submitted).await?;
        host.drive(
            &[Listener::Unix(&listener)],
            Some(Instant::now() + Duration::from_millis(10)),
            |_| {},
        )
        .await?;
        assert!(host.current_effect().is_some());
        assert!(!host.has_pending_dns_datagram());
        udp.send_to(&answer(&q[..n], 1, &[192, 0, 2, 67]), peer)
            .await?;
        host.drive(
            &[Listener::Unix(&listener)],
            Some(Instant::now() + Duration::from_millis(10)),
            |_| {},
        )
        .await?;
        assert!(host.has_pending_dns_datagram());
        assert_eq!(host.pending_lookups(), 1);
        assert_eq!(host.pending_stub_requests(), 1);
        driven(&mut host, &[Listener::Unix(&listener)], async {
            for _ in 2..=31 {
                assert_eq!(data(&frame(&mut slow).await?), payload);
                assert!(data(&frame(&mut slow).await?).is_empty());
            }
            assert_eq!(data(&frame(&mut fast).await?), [192, 0, 2, 67]);
            assert!(data(&frame(&mut fast).await?).is_empty());
            Ok::<_, E>(())
        })
        .await??;
        assert!(!host.has_pending_dns_datagram());
        assert_eq!(host.pending_lookups(), 0);
        assert_eq!(host.pending_stub_requests(), 0);
        assert_eq!(host.report().udp_sends, 2);
        host.shutdown(ShutdownMode::Immediate)?;
        drop(listener);
        std::fs::remove_file(p)?;
        Ok(())
    })
}
