//! The real Resolver service host serves official frames on each native OS.
#![forbid(unsafe_code)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assert exact native service replies, original request IDs and normal shutdown"
)]
use gnunet_client::resolver::{Family, Request, Response, WireId};
use gnunet_config::Configuration;
use gnunet_resolver_host::{
    MachineInputs,
    startup::{foreground_configured, foreground_tcp, native_family},
};
use gnunet_wire::official::Frame;
use std::{
    error::Error,
    io,
    net::IpAddr,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::oneshot,
};
type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct Directory(std::path::PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_dir_all(&self.0);
    }
}
fn local_configuration() -> TestResult<(Directory, std::path::PathBuf, Configuration)> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "gr-{}-{nonce:x}-{:x}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&path)?;
    let directory = Directory(path);
    let path = directory.0.join("resolver.sock");
    let mut config = Configuration::default();
    config.set_value(
        b"resolver",
        b"UNIXPATH",
        Some(
            path.to_str()
                .ok_or("fixture path is not Unicode")?
                .as_bytes(),
        ),
    )?;
    config.set_number(b"resolver", b"PORT", 0)?;
    Ok((directory, path, config))
}

async fn response(stream: &mut (impl AsyncRead + Unpin)) -> TestResult<Vec<u8>> {
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
fn native_inputs_preserve_search_domain_dns_order_and_nondefault_port() -> TestResult {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    tokio::task::LocalSet::new().block_on(&runtime, async {
        tokio::time::timeout(Duration::from_secs(5), async {
            let primary = UdpSocket::bind("127.0.0.1:0").await?;
            let secondary = UdpSocket::bind("127.0.0.1:0").await?;
            let available = std::net::TcpListener::bind("127.0.0.1:0")?;
            let port = available.local_addr()?.port();
            drop(available);
            let mut config = Configuration::default();
            config.set_value(b"resolver", b"BINDTO", Some(b"127.0.0.1"))?;
            config.set_number(b"resolver", b"PORT", u64::from(port))?;
            let inputs = MachineInputs {
                search_domain: Some(b"owned.example".to_vec()),
                dns_endpoints: vec![primary.local_addr()?, secondary.local_addr()?],
                ..Default::default()
            };
            let (ready, readiness) = oneshot::channel();
            let (stop, stopping) = oneshot::channel();
            let task = tokio::task::spawn_local(async move {
                foreground_tcp(
                    &config,
                    inputs,
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
            let mut stream = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).await?;
            let mut query = [0; 512];
            for (name, question) in [
                (
                    b"native".as_slice(),
                    b"\x06native\x05owned\x07example\0\0\x01\0\x01".as_slice(),
                ),
                (
                    b"native.absolute".as_slice(),
                    b"\x06native\x08absolute\0\0\x01\0\x01".as_slice(),
                ),
            ] {
                let id = WireId::from_native(77);
                let mut request = [0; 128];
                let length = Request::forward(id, Family::V4, name)?
                    .encode(native_family()?, &mut request)?;
                stream.write_all(&request[..length]).await?;
                let (length, peer) = primary.recv_from(&mut query).await?;
                assert_eq!(&query[12..length], question);
                let mut answer = query[..length].to_vec();
                answer[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
                answer[6..8].copy_from_slice(&1u16.to_be_bytes());
                answer
                    .extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 53]);
                primary.send_to(&answer, peer).await?;
                let frame = response(&mut stream).await?;
                let reply = Response::decode(Frame::decode(&frame)?)?;
                assert_eq!(reply.id(), id);
                assert_eq!(reply.address()?, Some("192.0.2.53".parse()?));
                let frame = response(&mut stream).await?;
                assert!(Response::decode(Frame::decode(&frame)?)?.is_end());
            }
            assert_eq!(
                secondary.try_recv_from(&mut query).err().map(|e| e.kind()),
                Some(io::ErrorKind::WouldBlock)
            );
            stop.send(()).map_err(|_| "shutdown receiver closed")?;
            let _report = task.await??;
            Ok::<_, Box<dyn Error>>(())
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "native DNS endpoint input stalled"))?
    })
}

#[test]
fn configured_local_service_answers_real_frames_and_retires_its_node() -> TestResult {
    let (_directory, _path, config) = local_configuration()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    tokio::task::LocalSet::new().block_on(&runtime, async {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (ready, readiness) = oneshot::channel();
            let (stop, stopping) = oneshot::channel();
            let task = tokio::task::spawn_local(async move {
                foreground_configured(
                    &config,
                    MachineInputs {
                        hosts: b"2001:db8::7 native6.example\n".to_vec(),
                        ..Default::default()
                    },
                    &[],
                    move |bound| {
                        let path = bound
                            .unix_paths()
                            .next()
                            .ok_or_else(|| io::Error::other("no owned local listener"))?
                            .to_path_buf();
                        ready
                            .send(path)
                            .map_err(|_| io::Error::other("readiness receiver closed"))
                    },
                    async move { stopping.await.map_err(io::Error::other) },
                    |_| {},
                )
                .await
            });
            let bound_path = readiness.await?;
            let mut stream = gnunet_service_runtime::local::Stream::connect(&bound_path).await?;
            let id = WireId::from_native(42);
            let mut bytes = [0; 128];
            let length = Request::forward(id, Family::V6, b"native6.example")?
                .encode(native_family()?, &mut bytes)?;
            stream.write_all(&bytes[..length]).await?;
            let frame = response(&mut stream).await?;
            let reply = Response::decode(Frame::decode(&frame)?)?;
            assert_eq!(reply.id(), id);
            assert_eq!(reply.address()?, Some("2001:db8::7".parse()?));
            let frame = response(&mut stream).await?;
            let end = Response::decode(Frame::decode(&frame)?)?;
            assert!(end.is_end());
            assert_eq!(end.id(), id);
            stop.send(()).map_err(|_| "shutdown receiver closed")?;
            let _report = task.await??;
            assert_eq!(stream.read(&mut [0; 1]).await?, 0);
            #[cfg(unix)]
            assert_eq!(
                std::fs::symlink_metadata(bound_path)
                    .err()
                    .map(|e| e.kind()),
                Some(io::ErrorKind::NotFound)
            );
            #[cfg(windows)]
            assert!(!gnunet_native::paths::exists(&bound_path)?);
            Ok::<_, Box<dyn Error>>(())
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "configured local Resolver stalled"))?
    })
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
                    MachineInputs {
                        hosts: b"192.0.2.7 native4.example\n2001:db8::7 native6.example\n".to_vec(),
                        search_domain: None,
                        resolv: Vec::new(),
                        dns_endpoints: Vec::new(),
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

#[test]
fn configured_construction_failure_closes_node_without_a_fabricated_host_report() -> TestResult {
    let (_directory, path, mut config) = local_configuration()?;
    config.set_value(b"resolver", b"TOLERANT", Some(b"invalid"))?;
    let called = std::cell::Cell::new(false);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let error = runtime
        .block_on(foreground_configured(
            &config,
            MachineInputs::default(),
            &[],
            |_| {
                called.set(true);
                Ok(())
            },
            std::future::pending(),
            |_| {},
        ))
        .err()
        .ok_or("invalid policy was accepted")?;
    let failure = error
        .downcast::<gnunet_resolver_host::startup::ForegroundFailure>()
        .map_err(|_| "failure lost its native cleanup structure")?;
    assert!(!called.get());
    assert!(failure.original.is_some());
    assert!(failure.report.is_none());
    assert!(failure.listener_cleanup.is_none());
    #[cfg(unix)]
    assert_eq!(
        std::fs::symlink_metadata(path).err().map(|e| e.kind()),
        Some(io::ErrorKind::NotFound)
    );
    #[cfg(windows)]
    assert!(!gnunet_native::paths::exists(&path)?);
    Ok(())
}

#[cfg(windows)]
#[test]
fn ready_failure_and_node_sharing_failure_retain_both_errors_and_retry_owner() -> TestResult {
    use std::os::windows::fs::OpenOptionsExt;
    let (_directory, path, config) = local_configuration()?;
    let blocker = std::cell::RefCell::new(None);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let error = runtime
        .block_on(foreground_configured(
            &config,
            MachineInputs::default(),
            &[],
            |bound| {
                let path = bound
                    .unix_paths()
                    .next()
                    .ok_or_else(|| io::Error::other("no owned endpoint"))?;
                // READ_CONTROL, read/write sharing without delete, and no reparse following.
                *blocker.borrow_mut() = Some(
                    std::fs::OpenOptions::new()
                        .access_mode(0x0002_0000)
                        .share_mode(3)
                        .custom_flags(0x0020_0000)
                        .open(path)?,
                );
                Err(io::Error::other("intentional ready failure"))
            },
            std::future::pending(),
            |_| {},
        ))
        .err()
        .ok_or("Ready failure was lost")?;
    let mut failure = error
        .downcast::<gnunet_resolver_host::startup::ForegroundFailure>()
        .map_err(|_| "failure lost its native cleanup structure")?;
    assert_eq!(
        failure
            .original
            .as_ref()
            .map(ToString::to_string)
            .as_deref(),
        Some("intentional ready failure")
    );
    assert!(failure.report.is_some());
    let cleanup = failure
        .listener_cleanup
        .as_mut()
        .ok_or("sharing failure owner was lost")?;
    assert_eq!(
        cleanup.errors.first().and_then(io::Error::raw_os_error),
        Some(32)
    );
    assert!(cleanup.remaining.listeners().is_empty());
    assert_eq!(cleanup.remaining.unix_paths().count(), 1);
    drop(blocker.into_inner());
    cleanup
        .remaining
        .close()
        .map_err(|errors| io::Error::other(format!("{errors:?}")))?;
    assert!(!gnunet_native::paths::exists(&path)?);
    Ok(())
}

#[test]
fn awaited_ready_failure_closes_original_listeners_and_preserves_cause() -> TestResult {
    use gnunet_resolver_host::startup::{ForegroundFailure, foreground_listening_with_async_ready};
    use gnunet_service_runtime::{BoundListeners, clock::SystemClock};
    let (_directory, path, config) = local_configuration()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let bound =
            BoundListeners::bind_configured(&config, b"resolver", Default::default()).await?;
        assert!(path.try_exists()?);
        let resumed = std::cell::Cell::new(false);
        let error = foreground_listening_with_async_ready(
            &config,
            bound,
            MachineInputs::default(),
            &[],
            |_| async {
                tokio::task::yield_now().await;
                resumed.set(true);
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "original asynchronous ready failure",
                ))
            },
            std::future::pending(),
            |_| {},
            std::sync::Arc::new(SystemClock),
        )
        .await
        .err()
        .ok_or("failed ready publication became success")?;
        let failure = error
            .downcast::<ForegroundFailure>()
            .map_err(|_| "lost startup failure ownership")?;
        assert!(resumed.get());
        let original = failure
            .original
            .as_ref()
            .and_then(|error| error.downcast_ref::<io::Error>())
            .ok_or("lost original asynchronous publication error")?;
        assert_eq!(original.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(original.to_string(), "original asynchronous ready failure");
        assert!(failure.cleanup.is_none());
        assert!(failure.listener_cleanup.is_none());
        assert!(!path.try_exists()?);
        Ok(())
    })
}
