//! Native official Resolver IPC over the same TCP path on every desktop target.
#![forbid(unsafe_code)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions check actual native TCP frames, echoed request IDs and original callback completion"
)]
use gnunet_client::resolver::{Query as WireQuery, Reply as WireReply, Request, encode_response};
use gnunet_config::Configuration;
use gnunet_resolver_broker::{
    Completion, Family, LiveConfiguration, Reply, SystemClock, broker, native_profile,
};
use gnunet_wire::official::Frame;
use std::{error::Error, io, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

#[test]
fn native_tcp_resolver_keeps_fifo_ids_family_and_real_end() -> TestResult {
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        tokio::time::timeout(Duration::from_secs(5), async {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let profile = native_profile()?;
            let mut config = Configuration::default();
            config.set_value(b"resolver", b"HOSTNAME", Some(b"127.0.0.1"))?;
            config.set_number(b"resolver", b"PORT", u64::from(listener.local_addr()?.port()))?;
            let (context, mut driver) = broker::<4, 128>(LiveConfiguration::new(config), Default::default(), profile, Arc::new(SystemClock))?;
            let address = "2001:db8::1".parse()?;
            let peer = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await?;
                let mut previous = None;
                for hostname in [b"first.example".as_slice(), b"second.example".as_slice()] {
                    let mut header = [0; 4];
                    stream.read_exact(&mut header).await?;
                    let length = usize::from(u16::from_be_bytes([header[0], header[1]]));
                    assert!((16..=128).contains(&length));
                    let mut bytes = vec![0; length];
                    bytes[..4].copy_from_slice(&header);
                    stream.read_exact(&mut bytes[4..]).await?;
                    let request = Request::decode(Frame::decode(&bytes)?, profile)?;
                    assert!(matches!(request.query(), WireQuery::Forward { hostname: name, family: Family::V6 } if name == hostname));
                    assert_ne!(previous, Some(request.id()));
                    previous = Some(request.id());
                    for reply in [WireReply::Address(address), WireReply::End] {
                        let mut response = [0; 32];
                        let length = encode_response(request.id(), reply, &mut response)?;
                        // Split the actual frame prefix at every byte boundary.
                        for byte in &response[..length] {
                            stream.write_all(std::slice::from_ref(byte)).await?;
                            tokio::task::yield_now().await;
                        }
                    }
                }
                Ok::<_, Box<dyn Error + Send + Sync>>(())
            });
            let reactor: tokio::task::JoinHandle<Result<(), gnunet_resolver_broker::BrokerError>> = tokio::spawn(async move {
                loop {
                    driver.drive_waiting(None, |_| {}).await?;
                }
            });
            for hostname in [b"first.example".as_slice(), b"second.example".as_slice()] {
                let mut query = context.ip_get(hostname, Family::V6, gnunet_types::Duration(4_000_000))?;
                let delivery = query.next().await?.ok_or("missing address callback")?;
                assert!(matches!(delivery.reply()?, Reply::Address(got) if got == address));
                drop(delivery);
                let delivery = query.next().await?.ok_or("missing END callback")?;
                assert!(matches!(delivery.reply()?, Reply::Complete(Completion::End)));
                drop(delivery);
                assert!(query.next().await?.is_none());
            }
            peer.await??;
            reactor.abort();
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        }).await.map_err(io::Error::other)?
    })
}
