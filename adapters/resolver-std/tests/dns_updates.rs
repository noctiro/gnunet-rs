//! DNS network changes through the embedded Resolver and its normal IPC.
#![forbid(unsafe_code)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assert exact DNS questions and Resolver output over loopback"
)]

use gnunet_client::resolver::{Family, Request, Response, WireId};
use gnunet_config::Configuration;
use gnunet_resolver_host::{
    MachineInputs,
    startup::{
        EmbeddedDns, EmbeddedSettings, Upstreams, native_family, serve_embedded, upstream_updates,
    },
};
use gnunet_service_runtime::clock::SystemClock;
#[cfg(unix)]
use gnunet_service_runtime::network::SocketPolicy;
use gnunet_wire::official::Frame;
#[cfg(unix)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{
    error::Error,
    future::ready,
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::oneshot,
};

type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;

async fn request(stream: &mut TcpStream, id: WireId, name: &[u8]) -> Result {
    let mut bytes = [0; 128];
    let len = Request::forward(id, Family::V4, name)?.encode(native_family()?, &mut bytes)?;
    stream.write_all(&bytes[..len]).await?;
    Ok(())
}

async fn response(stream: &mut TcpStream, id: WireId, address: Ipv4Addr) -> Result {
    let mut bytes = [0; 128];
    for expected in [Some(address.into()), None] {
        stream.read_exact(&mut bytes[..4]).await?;
        let len = usize::from(u16::from_be_bytes([bytes[0], bytes[1]]));
        let body = bytes
            .get_mut(4..len)
            .ok_or("invalid Resolver frame length")?;
        stream.read_exact(body).await?;
        let reply = Response::decode(Frame::decode(&bytes[..len])?)?;
        assert_eq!(reply.id(), id);
        assert_eq!(reply.is_end(), expected.is_none());
        assert_eq!(reply.address()?, expected);
    }
    Ok(())
}

async fn query(source: &UdpSocket, question: &[u8]) -> Result<(Vec<u8>, SocketAddr)> {
    let mut bytes = [0; 512];
    let (len, peer) = source.recv_from(&mut bytes).await?;
    assert_eq!(bytes.get(12..len), Some(question));
    Ok((bytes[..len].to_vec(), peer))
}

async fn answer(
    source: &UdpSocket,
    query: (Vec<u8>, SocketAddr),
    kind: u16,
    rdata: &[u8],
) -> Result {
    let (mut bytes, peer) = query;
    bytes[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    bytes[6..8].copy_from_slice(&1u16.to_be_bytes());
    bytes.extend_from_slice(&[0xc0, 0x0c]);
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
    bytes.extend_from_slice(&u16::try_from(rdata.len())?.to_be_bytes());
    bytes.extend_from_slice(rdata);
    source.send_to(&bytes, peer).await?;
    Ok(())
}

#[test]
fn changing_dns_retries_pending_queries_and_drops_dynamic_cache_on_the_same_connection() -> Result {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    tokio::task::LocalSet::new().block_on(&runtime, async {
        tokio::time::timeout(Duration::from_secs(5), async {
            let original = UdpSocket::bind("127.0.0.1:0").await?;
            let replacement = UdpSocket::bind("127.0.0.1:0").await?;
            let temporary = std::net::TcpListener::bind("127.0.0.1:0")?;
            let address = temporary.local_addr()?;
            drop(temporary);
            let mut config = Configuration::default();
            config.set_value(b"resolver", b"BINDTO", Some(b"127.0.0.1"))?;
            config.set_number(b"resolver", b"PORT", u64::from(address.port()))?;

            let (updates, upstream_updates) = upstream_updates();
            let (started, initialized) = oneshot::channel();
            let (stop, stopping) = oneshot::channel();
            let first = original.local_addr()?;
            #[cfg(unix)]
            let prepared = Arc::new(AtomicUsize::new(0));
            #[cfg(unix)]
            let socket_policy = SocketPolicy::protected({
                let prepared = prepared.clone();
                move |fd| {
                    let local = socket2::SockRef::from(&fd).local_addr()?.as_socket();
                    if local.is_none_or(|address| address.port() != 0) {
                        return Err(io::Error::other("DNS protection must precede bind"));
                    }
                    prepared.fetch_add(1, Ordering::Relaxed);
                    Ok(())
                }
            });
            #[cfg(windows)]
            let socket_policy = Default::default();
            let server = tokio::task::spawn_local(async move {
                serve_embedded(
                    EmbeddedSettings {
                        config: &config,
                        dns: EmbeddedDns::Datagram {
                            inputs: MachineInputs {
                                hosts: b"192.0.2.55 static.example\n".to_vec(),
                                dns_endpoints: vec![first],
                                ..MachineInputs::default()
                            },
                            endpoints: &[],
                            updates: upstream_updates,
                        },
                        socket_policy,
                        clock: Arc::new(SystemClock),
                    },
                    |_| {
                        ready(
                            started
                                .send(())
                                .map_err(|_| io::Error::other("readiness closed")),
                        )
                    },
                    async move { stopping.await.map_err(io::Error::other) },
                    |_| {},
                )
                .await
            });
            initialized.await?;
            let mut stream = TcpStream::connect(address).await?;

            let cached = b"\x05cache\x07example\0\0\x01\0\x01";
            let pending = b"\x07pending\x07example\0\0\x01\0\x01";
            let alias = b"\x05alias\x07example\0\0\x01\0\x01";
            let old_target = b"\x08internal\x07example\0";
            let old_target_question = b"\x08internal\x07example\0\0\x01\0\x01";
            let old_ip = Ipv4Addr::new(192, 0, 2, 1);
            let new_ip = Ipv4Addr::new(192, 0, 2, 2);
            let first = WireId::from_native(1);
            request(&mut stream, first, b"cache.example").await?;
            answer(
                &original,
                query(&original, cached).await?,
                1,
                &old_ip.octets(),
            )
            .await?;
            response(&mut stream, first, old_ip).await?;

            let second = WireId::from_native(2);
            request(&mut stream, second, b"pending.example").await?;
            let delayed = query(&original, pending).await?;

            let third = WireId::from_native(3);
            request(&mut stream, third, b"alias.example").await?;
            answer(&original, query(&original, alias).await?, 5, old_target).await?;
            let delayed_alias = query(&original, old_target_question).await?;

            #[cfg(unix)]
            let previous = prepared.load(Ordering::Relaxed);
            #[cfg(unix)]
            assert!(previous > 0);

            updates.replace(Upstreams::new([replacement.local_addr()?])?);
            let retried = query(&replacement, pending).await?;
            assert_ne!(delayed.0[..2], retried.0[..2]);
            let retried_alias = query(&replacement, alias).await?;
            #[cfg(unix)]
            assert!(prepared.load(Ordering::Relaxed) > previous);
            answer(&original, delayed, 1, &old_ip.octets()).await?;
            answer(&original, delayed_alias, 1, &old_ip.octets()).await?;
            answer(&replacement, retried, 1, &new_ip.octets()).await?;
            response(&mut stream, second, new_ip).await?;
            answer(&replacement, retried_alias, 1, &new_ip.octets()).await?;
            response(&mut stream, third, new_ip).await?;

            let fourth = WireId::from_native(4);
            request(&mut stream, fourth, b"cache.example").await?;
            answer(
                &replacement,
                query(&replacement, cached).await?,
                1,
                &new_ip.octets(),
            )
            .await?;
            response(&mut stream, fourth, new_ip).await?;

            let fifth = WireId::from_native(5);
            request(&mut stream, fifth, b"static.example").await?;
            response(&mut stream, fifth, Ipv4Addr::new(192, 0, 2, 55)).await?;

            stop.send(()).map_err(|_| "Resolver stop receiver closed")?;
            let _report = server.await??;
            Ok::<_, Box<dyn Error>>(())
        })
        .await?
    })
}
