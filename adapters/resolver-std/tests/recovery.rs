//! Independent real-socket regressions for local cleanup budget and UTC failure.
#![expect(
    clippy::panic_in_result_fn,
    reason = "These bounded actual-socket tests assert independently observed lifecycle, wire bytes and cleanup results"
)]

use gnunet_client::resolver::{Family, Request, WireId};
use gnunet_dns::{AbsoluteTime, Idna};
use gnunet_idna::{Backend, NativeProfile, Workspace};
use gnunet_resolver_host::{
    Host, Limits, Ports,
    storage::{Geometry, Store},
};
use gnunet_resolver_service_core::{owner::Resolver, storage::Limits as CoreLimits};
use gnunet_service_runtime::service::{Listener, ServiceOptions, ShutdownMode};
use std::{
    future::{Future, poll_fn},
    net::Ipv4Addr,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    task::Poll,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UdpSocket, UnixListener, UnixStream},
    time::Instant,
};
type E = Box<dyn std::error::Error>;
fn rt() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}
static UTC_FAIL: AtomicBool = AtomicBool::new(false);
static UTC_CALLS: AtomicUsize = AtomicUsize::new(0);
fn clock_utc() -> Result<AbsoluteTime, gnunet_types::Error> {
    UTC_CALLS.fetch_add(1, Ordering::Relaxed);
    if UTC_FAIL.load(Ordering::Relaxed) {
        Err(gnunet_types::Error::TimeUncertain)
    } else {
        Ok(AbsoluteTime::from_micros(1_000_000_000))
    }
}
fn budget_utc() -> Result<AbsoluteTime, gnunet_types::Error> {
    Ok(AbsoluteTime::from_micros(1_000_000_000))
}
fn request(id: u32) -> Result<Vec<u8>, gnunet_types::Error> {
    let name = format!("n{id}.example");
    let r = Request::forward(WireId::from_native(id), Family::V4, name.as_bytes())?;
    let mut bytes = vec![0; r.encoded_len()?];
    r.encode(gnunet_resolver_host::startup::native_family()?, &mut bytes)?;
    Ok(bytes)
}
async fn frame(s: &mut UnixStream) -> Result<Vec<u8>, E> {
    let mut header = [0; 4];
    s.read_exact(&mut header).await?;
    let len = u16::from_be_bytes([header[0], header[1]]) as usize;
    if len < 8 {
        return Err("short official Resolver response".into());
    }
    let mut bytes = vec![0; len];
    bytes[..4].copy_from_slice(&header);
    s.read_exact(&mut bytes[4..]).await?;
    Ok(bytes)
}
fn answer(query: &[u8]) -> Vec<u8> {
    let mut bytes = query.to_vec();
    bytes[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    bytes[6..8].copy_from_slice(&1u16.to_be_bytes());
    bytes.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0x0e, 0x10, 0, 4, 192, 0, 2, 9]);
    bytes
}
macro_rules! setup {
    ($host:ident,$utc:expr) => {
        let g = Geometry {
            clients: 4,
            lookups: 128,
            hosts: 4,
            buckets: 1025,
            records: 128,
            effects: 256,
            byte_pool: 512 * 1024,
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
        let mut $host = Host::<_, 128, 271, 128>::new(
            core,
            stage,
            &backend,
            Ports {
                epoch: Instant::now(),
                utc: $utc,
                random_below: gnunet_resolver_host::system_random_below,
            },
            gnunet_resolver_host::startup::native_family()?,
            Limits::default(),
            ServiceOptions::default(),
            128,
        )?;
        $host.load_machine_bytes(b"", b"")?;
    };
}
async fn driven<I: Idna, F: Future>(
    h: &mut Host<'_, '_, I, 128, 271, 128>,
    l: &[Listener<'_>],
    test: F,
) -> Result<F::Output, E> {
    let mut drive =
        std::pin::pin!(h.drive(l, Some(Instant::now() + Duration::from_secs(5)), |_| {}));
    let mut task = std::pin::pin!(test);
    poll_fn(|cx| {
        if let Poll::Ready(v) = task.as_mut().poll(cx) {
            return Poll::Ready(Ok(v));
        };
        match drive.as_mut().poll(cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(Box::new(e) as E)),
            Poll::Ready(Ok(_)) => Poll::Ready(Err("unexpected drive completion".into())),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}
#[test]
fn eof_cleans_more_than_one_effect_budget_without_external_wakeup() -> Result<(), E> {
    rt()?.block_on(async {
        let path =
            std::env::temp_dir().join(format!("gnunet-review-budget-{}.sock", std::process::id()));
        let listener = UnixListener::bind(&path)?;
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        setup!(host, budget_utc);
        host.add_dns_endpoint(udp.local_addr()?)?;
        host.set_dns_retry(gnunet_types::Duration(100_000_000))?;
        let mut client = UnixStream::connect(&path).await?;
        let mut requests = Vec::new();
        for id in 0..65 {
            requests.extend(request(id)?);
        }
        client.write_all(&requests).await?;
        driven(&mut host, &[Listener::Unix(&listener)], async {
            let mut bytes = [0; 512];
            for _ in 0..65 {
                udp.recv_from(&mut bytes).await?;
            }
            Ok::<_, E>(())
        })
        .await??;
        assert_eq!(host.pending_stub_requests(), 65);
        assert_eq!(host.pending_lookups(), 65);
        drop(client);
        let canceled = tokio::time::timeout(
            Duration::from_millis(250),
            host.drive(&[Listener::Unix(&listener)], None, |_| {}),
        )
        .await;
        assert!(canceled.is_err());
        assert_eq!(host.connections(), 0);
        assert_eq!(host.pending_lookups(), 0);
        // Local cleanup must finish within the same drive despite the64-effect
        // cooperative budget; no DNS retry or outside network event authorizes it.
        assert_eq!(host.pending_stub_requests(), 0);
        assert_eq!(host.report().udp_sends, 65);
        host.shutdown(ShutdownMode::Immediate)?;
        drop(listener);
        std::fs::remove_file(path)?;
        Ok(())
    })
}
#[test]
fn rx_clock_failure_discards_only_undated_packet_then_new_response_recovers() -> Result<(), E> {
    rt()?.block_on(async {
        UTC_FAIL.store(false, Ordering::Relaxed);
        UTC_CALLS.store(0, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("gnunet-review-utc-{}.sock", std::process::id()));
        let listener = UnixListener::bind(&path)?;
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        setup!(host, clock_utc);
        host.add_dns_endpoint(udp.local_addr()?)?;
        let mut client = UnixStream::connect(&path).await?;
        client.write_all(&request(1)?).await?;
        let mut bytes = [0; 512];
        let (n, peer) = driven(
            &mut host,
            &[Listener::Unix(&listener)],
            udp.recv_from(&mut bytes),
        )
        .await??;
        UTC_FAIL.store(true, Ordering::Relaxed);
        udp.send_to(&answer(&bytes[..n]), peer).await?;
        let failed = host
            .drive(
                &[Listener::Unix(&listener)],
                Some(Instant::now() + Duration::from_secs(1)),
                |_| {},
            )
            .await;
        assert!(matches!(
            failed,
            Err(gnunet_resolver_host::HostError::Clock(
                gnunet_types::Error::TimeUncertain
            ))
        ));
        assert!(!host.has_pending_dns_datagram());
        assert_eq!(host.pending_lookups(), 1);
        assert_eq!(host.pending_stub_requests(), 1);
        let calls = UTC_CALLS.load(Ordering::Relaxed);
        UTC_FAIL.store(false, Ordering::Relaxed);
        udp.send_to(&answer(&bytes[..n]), peer).await?;
        driven(&mut host, &[Listener::Unix(&listener)], async {
            let first = frame(&mut client).await?;
            assert_eq!(&first[4..8], &1u32.to_ne_bytes());
            assert_eq!(&first[8..], &[192, 0, 2, 9]);
            let end = frame(&mut client).await?;
            assert_eq!(&end[4..8], &1u32.to_ne_bytes());
            assert_eq!(end.len(), 8);
            Ok::<_, E>(())
        })
        .await??;
        assert!(UTC_CALLS.load(Ordering::Relaxed) > calls);
        assert_eq!(host.pending_lookups(), 0);
        assert_eq!(host.pending_stub_requests(), 0);
        assert_eq!(host.report().udp_sends, 1);
        host.shutdown(ShutdownMode::Immediate)?;
        drop(listener);
        std::fs::remove_file(path)?;
        Ok(())
    })
}

#[test]
fn expired_queued_start_cannot_deadlock_full_effects_with_older_timeouts() -> Result<(), E> {
    rt()?.block_on(async {
        let path = std::env::temp_dir().join(format!(
            "gnunet-review-expired-full-{}.sock",
            std::process::id()
        ));
        let listener = UnixListener::bind(&path)?;
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let g = Geometry {
            clients: 4,
            lookups: 8,
            hosts: 4,
            buckets: 1025,
            records: 128,
            effects: 4,
            byte_pool: 512 * 1024,
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
        let mut host = Host::<_, 128, 271, 128>::new(
            core,
            stage,
            &backend,
            Ports {
                epoch: Instant::now(),
                utc: budget_utc,
                random_below: gnunet_resolver_host::system_random_below,
            },
            gnunet_resolver_host::startup::native_family()?,
            Limits {
                max_pending_bytes: 8192,
                ..Limits::default()
            },
            ServiceOptions::default(),
            128,
        )?;
        host.add_dns_endpoint(udp.local_addr()?)?;
        host.set_dns_retry(gnunet_types::Duration(100_000_000))?;
        let mut slow = UnixStream::connect(&path).await?;
        socket2::SockRef::from(&slow).set_recv_buffer_size(4096)?;
        slow.write_all(&request(1)?).await?;
        let mut packet = [0; 512];
        let (n, peer) = driven(
            &mut host,
            &[Listener::Unix(&listener)],
            udp.recv_from(&mut packet),
        )
        .await??;
        let mut large = packet[..n].to_vec();
        large[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        large[6..8].copy_from_slice(&1u16.to_be_bytes());
        large.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0x0e, 0x10]);
        large.extend_from_slice(&8000u16.to_be_bytes());
        large.extend_from_slice(&[0x6a; 8000]);
        udp.send_to(&large, peer).await?;
        driven(&mut host, &[Listener::Unix(&listener)], async {
            frame(&mut slow).await?;
            frame(&mut slow).await?;
            Ok::<_, E>(())
        })
        .await??;
        let mut older = UnixStream::connect(&path).await?;
        older.write_all(&request(101)?).await?;
        older.write_all(&request(102)?).await?;
        driven(&mut host, &[Listener::Unix(&listener)], async {
            for _ in 0..2 {
                udp.recv_from(&mut packet).await?;
            }
            Ok::<_, E>(())
        })
        .await??;
        assert_eq!(host.pending_lookups(), 2);
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(1)).await;
        let mut submitted = 0;
        for id in 10..110 {
            // Identical cached name with distinct opaque operation IDs.
            let mut query = request(1)?;
            query[12..16].copy_from_slice(&(id as u32).to_ne_bytes());
            slow.write_all(&query).await?;
            submitted += 1;
            host.drive(
                &[Listener::Unix(&listener)],
                Some(Instant::now() + Duration::from_millis(1)),
                |_| {},
            )
            .await?;
            if host.current_effect().is_some() {
                break;
            }
        }
        assert!(host.current_effect().is_some());
        let mut queued = UnixStream::connect(&path).await?;
        queued.write_all(&request(103)?).await?;
        host.drive(
            &[Listener::Unix(&listener)],
            Some(Instant::now() + Duration::from_millis(1)),
            |_| {},
        )
        .await?;
        assert_eq!(host.pending_lookups(), 3);
        let mut fill = UnixStream::connect(&path).await?;
        fill.write_all(&request(1)?).await?;
        host.drive(
            &[Listener::Unix(&listener)],
            Some(Instant::now() + Duration::from_millis(1)),
            |_| {},
        )
        .await?;
        assert_eq!(host.connections(), 4);
        tokio::time::advance(Duration::from_secs(31)).await;
        driven(&mut host, &[Listener::Unix(&listener)], async {
            for _ in 0..submitted {
                assert_eq!(frame(&mut slow).await?.len(), 8008);
                assert_eq!(frame(&mut slow).await?.len(), 8);
            }
            assert_eq!(frame(&mut fill).await?.len(), 8008);
            assert_eq!(frame(&mut fill).await?.len(), 8);
            for id in [101u32, 102] {
                let end = frame(&mut older).await?;
                assert_eq!(end.len(), 8);
                assert_eq!(&end[4..8], &id.to_ne_bytes());
            }
            let end = frame(&mut queued).await?;
            assert_eq!(end.len(), 8);
            assert_eq!(&end[4..8], &103u32.to_ne_bytes());
            Ok::<_, E>(())
        })
        .await??;
        assert_eq!(host.pending_lookups(), 0);
        assert_eq!(host.pending_stub_requests(), 0);
        assert!(host.current_effect().is_none());
        assert_eq!(host.report().udp_sends, 3);
        assert_eq!(host.report().unavailable_queries, 0);
        host.shutdown(ShutdownMode::Immediate)?;
        drop(listener);
        std::fs::remove_file(path)?;
        Ok(())
    })
}
