//! The real Resolver service host serves official frames on each native OS.
#![forbid(unsafe_code)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assert exact native service replies, original request IDs and normal shutdown"
)]
use gnunet_client::resolver::{Family, Request, Response, WireId};
use gnunet_config::Configuration;
use gnunet_resolver_host::{
    MachineFiles,
    startup::{foreground_tcp, native_family},
};
use gnunet_wire::official::Frame;
use std::{error::Error, io, net::IpAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::oneshot,
};
type TestResult<T = ()> = Result<T, Box<dyn Error>>;

async fn response(stream: &mut TcpStream) -> TestResult<Vec<u8>> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let length = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if !(8..=128).contains(&length) {
        return Err("invalid Resolver response length".into());
    }
    let mut frame = vec![0; length];
    frame[..4].copy_from_slice(&header);
    stream.read_exact(&mut frame[4..]).await?;
    Ok(frame)
}

#[test]
fn actual_tcp_service_answers_both_families_and_shuts_down() -> TestResult {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    tokio::task::LocalSet::new().block_on(&runtime, async {
        let stage = std::cell::Cell::new("startup readiness");
        tokio::time::timeout(Duration::from_secs(5), async {
            let available = std::net::TcpListener::bind("127.0.0.1:0")?;
            let port = available.local_addr()?.port();
            drop(available);
            let mut config = Configuration::default();
            config.set_value(b"resolver", b"BINDTO", Some(b"127.0.0.1"))?;
            config.set_number(b"resolver", b"PORT", u64::from(port))?;
            let (ready, readiness) = oneshot::channel();
            let (stop, stopping) = oneshot::channel();
            let task = tokio::task::spawn_local(async move {
                foreground_tcp(
                    &config,
                    MachineFiles {
                        hosts: b"192.0.2.7 native4.example\n2001:db8::7 native6.example\n".to_vec(),
                        resolv: Vec::new(),
                        diagnostics: Vec::new(),
                    },
                    &[],
                    move |_| {
                        ready
                            .send(())
                            .map_err(|_| io::Error::other("readiness receiver closed"))
                    },
                    async move { stopping.await.map_err(io::Error::other) },
                    |_| {},
                )
                .await
            });
            readiness.await?;
            stage.set("TCP connect");
            let mut stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).await?;
            for (serial, family, hostname, expected) in [
                (
                    1,
                    Family::V4,
                    b"native4.example".as_slice(),
                    "192.0.2.7".parse::<IpAddr>()?,
                ),
                (
                    2,
                    Family::V6,
                    b"native6.example".as_slice(),
                    "2001:db8::7".parse::<IpAddr>()?,
                ),
            ] {
                stage.set(if serial == 1 {
                    "IPv4 address"
                } else {
                    "IPv6 address"
                });
                let id = WireId::from_native(serial);
                let mut bytes = [0; 128];
                let length =
                    Request::forward(id, family, hostname)?.encode(native_family()?, &mut bytes)?;
                // Exercise retained service RX instead of delivering a whole fixture at once.
                for part in bytes[..length].chunks(3) {
                    stream.write_all(part).await?;
                }
                let frame =
                    match tokio::time::timeout(Duration::from_secs(2), response(&mut stream)).await
                    {
                        Ok(frame) => frame?,
                        Err(_) => {
                            drop(stop);
                            return Err(format!("{}: {:?}", stage.get(), task.await?).into());
                        }
                    };
                let reply = Response::decode(Frame::decode(&frame)?)?;
                assert_eq!(reply.id(), id);
                assert_eq!(reply.address()?, Some(expected));
                stage.set("END reply");
                let frame = response(&mut stream).await?;
                let end = Response::decode(Frame::decode(&frame)?)?;
                assert_eq!(end.id(), id);
                assert!(end.is_end());
            }
            stop.send(()).map_err(|_| "shutdown receiver closed")?;
            stage.set("service shutdown");
            let _report = task.await??;
            assert_eq!(stream.read(&mut [0; 1]).await?, 0);
            Ok::<(), Box<dyn Error>>(())
        })
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("Resolver service stalled at {}", stage.get()),
            )
        })?
    })
}
