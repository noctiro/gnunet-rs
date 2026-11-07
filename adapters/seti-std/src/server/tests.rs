#![expect(
    clippy::panic_in_result_fn,
    reason = "Actual two-service socket model checks official results and original physical cleanup"
)]
use super::*;
use gnunet_cadet::service as cadet_core;
use gnunet_cadet_host::server as cadet_server;
use gnunet_service_runtime::clock::SystemClock;
use gnunet_wire::official::seti::{ADD_LOCAL, DEL_LOCAL, DONE, Response};
use std::{error::Error as StdError, path::PathBuf};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UnixListener},
};
type Failure = Box<dyn StdError>;
struct Directory(PathBuf);
impl Directory {
    fn new() -> Result<Self, Failure> {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let path = PathBuf::from(format!("/tmp/gsi-{}-{stamp:x}", std::process::id()));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_dir_all(&self.0);
    }
}
struct Random(u32);
impl Entropy for Random {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), ProtocolError> {
        for b in output {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 17;
            self.0 ^= self.0 << 5;
            *b = self.0 as u8;
        }
        Ok(())
    }
}
async fn request(stream: &mut TcpStream, request: Request<'_>) -> Result<(), Failure> {
    let mut bytes = [0; 256];
    let n = request.encode(&mut bytes)?;
    for part in bytes[..n].chunks(3) {
        stream.write_all(part).await?;
    }
    Ok(())
}
async fn frame(stream: &mut TcpStream) -> Result<Vec<u8>, Failure> {
    let mut head = [0; 4];
    stream.read_exact(&mut head).await?;
    let n = usize::from(u16::from_be_bytes([head[0], head[1]]));
    if n < 4 {
        return Err("short official frame".into());
    }
    let mut bytes = vec![0; n];
    bytes[..4].copy_from_slice(&head);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(bytes)
}
struct OpBacking {
    members: [u8; 1],
    active: [u8; 1],
    reported: [u8; 1],
    bloom: [u8; 512],
    context: [u8; 32],
}
#[test]
fn actual_ipc_and_cadet_service_reconcile_then_close_original_sources() -> Result<(), Failure> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(8), async {
                let directory = Directory::new()?;
                let backend_path = directory.0.join("c");
                let backend_listener = UnixListener::bind(&backend_path)?;
                let backend_listeners = [Listener::Unix(&backend_listener)];
                let app_listener = TcpListener::bind("127.0.0.1:0").await?;
                let app_listeners = [Listener::Tcp(&app_listener)];
                let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
                // The carrier is the actual production CADET SERVICE in own-peer
                // mode, not an actor synthesizing SETI credit/results or peer data.
                let mut carrier_domain = cadet_core::Instance::new();
                let mut carrier_clients = [cadet_core::ClientSlot::new(); 1];
                let mut carrier_ports = [cadet_core::PortSlot::new(); 1];
                let mut carrier_channels = [cadet_core::ChannelSlot::new(); 4];
                let mut carrier_bytes = [[0; 1024]; 8];
                let mut carrier_messages = carrier_bytes
                    .each_mut()
                    .map(|b| cadet_core::MessageSlot::new(b));
                let carrier = cadet_core::Service::new(
                    &mut carrier_domain,
                    [1; 32],
                    &mut carrier_clients,
                    &mut carrier_ports,
                    &mut carrier_channels,
                    &mut carrier_messages,
                    cadet_core::Limits {
                        window: 1,
                        loop_payload_bytes: 1024,
                        remote_payload_bytes: 1024,
                    },
                )?;
                let mut carrier = cadet_server::Server::new(
                    carrier,
                    cadet_server::Limits {
                        clients: 1,
                        io_slice_bytes: 3,
                    },
                    ServiceOptions::default(),
                    UnixAccess::default(),
                    clock.clone(),
                )?;
                let mut cadet_domain = cadet::Instance::new();
                let mut cadet_ports = [cadet::PortSlot::new(); 1];
                let mut cadet_channels = [cadet::ChannelSlot::new(); 4];
                let backend = cadet::Client::new(
                    &mut cadet_domain,
                    cadet::EndpointSource::unix_with_clock(backend_path, clock),
                    &mut cadet_ports,
                    &mut cadet_channels,
                    cadet::Limits {
                        io_slice_bytes: 3,
                        ..cadet::Limits::default()
                    },
                )?;
                let mut domain = core::Instance::new();
                let mut clients = [core::ClientSlot::new(); 3];
                let mut sets = [core::SetSlot::new(); 2];
                let mut listeners = [core::ListenerSlot::new(); 1];
                let mut payloads = [[0; 8]; 4];
                let mut elements = payloads.each_mut().map(|b| core::ElementSlot::new(b));
                let mut buffers = std::array::from_fn::<_, 4, _>(|_| OpBacking {
                    members: [0; 1],
                    active: [0; 1],
                    reported: [0; 1],
                    bloom: [0; 512],
                    context: [0; 32],
                });
                let mut operations = buffers.each_mut().map(|b| {
                    core::OperationSlot::new(
                        &mut b.members,
                        &mut b.active,
                        &mut b.reported,
                        &mut b.bloom,
                        &mut b.context,
                    )
                });
                let core = core::Service::new(
                    &mut domain,
                    &mut clients,
                    &mut sets,
                    &mut listeners,
                    &mut elements,
                    &mut operations,
                    core::Limits {
                        element_bytes: 8,
                        bloom_bytes: 512,
                        ..core::Limits::default()
                    },
                )?;
                let mut server = Server::new(
                    core,
                    backend,
                    Limits {
                        clients: 3,
                        listeners: 1,
                        operations: 4,
                        io_slice_bytes: 3,
                        ..Limits::default()
                    },
                    ServiceOptions::default(),
                    UnixAccess::default(),
                )?;
                let mut random = Random(0x1234_5678);
                macro_rules! poll_both {
                    ($cx:expr) => {{
                        let a = server.poll($cx, &app_listeners, &mut random, None, &mut |_| {});
                        let b = carrier.poll($cx, &backend_listeners, None, &mut |_| {});
                        match (a, b) {
                            (Poll::Ready(Err(e)), _) => {
                                return Poll::Ready(Err(Box::new(e) as Failure));
                            }
                            (_, Poll::Ready(Err(e))) => {
                                return Poll::Ready(Err(Box::new(e) as Failure));
                            }
                            (Poll::Ready(Ok(_)), _) | (_, Poll::Ready(Ok(_))) => true,
                            _ => false,
                        }
                    }};
                }
                macro_rules! until {
                    ($condition:expr) => {{
                        while !$condition {
                            poll_fn(|cx| {
                                if poll_both!(cx) {
                                    Poll::Ready(Ok::<(), Failure>(()))
                                } else {
                                    Poll::Pending
                                }
                            })
                            .await?;
                        }
                    }};
                }
                macro_rules! read_driven {
                    ($stream:expr) => {{
                        let mut reading = std::pin::pin!(frame($stream));
                        poll_fn(|cx| {
                            let active = poll_both!(cx);
                            match reading.as_mut().poll(cx) {
                                Poll::Ready(result) => Poll::Ready(result),
                                Poll::Pending => {
                                    if active {
                                        cx.waker().wake_by_ref();
                                    }
                                    Poll::Pending
                                }
                            }
                        })
                        .await?
                    }};
                }
                let mut a = TcpStream::connect(app_listener.local_addr()?).await?;
                let mut b = TcpStream::connect(app_listener.local_addr()?).await?;
                let mut listening = TcpStream::connect(app_listener.local_addr()?).await?;
                request(&mut a, Request::Create).await?;
                request(&mut b, Request::Create).await?;
                for value in [b"a", b"b"] {
                    request(
                        &mut a,
                        Request::Add {
                            element_type: 0x1234,
                            reserved: 0,
                            data: value,
                        },
                    )
                    .await?;
                }
                for value in [b"b", b"c"] {
                    request(
                        &mut b,
                        Request::Add {
                            element_type: 0x1234,
                            reserved: 0,
                            data: value,
                        },
                    )
                    .await?;
                }
                request(
                    &mut listening,
                    Request::Listen {
                        operation: 0,
                        app_id: [9; 64],
                    },
                )
                .await?;
                until!(server.listeners.iter().flatten().any(|l| l.bound.is_some()));
                let context = [0, 4, 0x12, 0x34];
                request(
                    &mut a,
                    Request::Evaluate {
                        request_id: 11,
                        peer: [1; 32],
                        app_id: [9; 64],
                        return_intersection: 1,
                        context: Some(&context),
                    },
                )
                .await?;
                let suggestion = read_driven!(&mut listening);
                let Response::Request {
                    accept_id,
                    peer,
                    context: actual_context,
                } = Response::decode(&suggestion)?
                else {
                    return Err("expected actual incoming suggestion".into());
                };
                assert_eq!(peer, [1; 32]);
                assert_eq!(actual_context, Some(context.as_slice()));
                request(
                    &mut b,
                    Request::Accept {
                        accept_id,
                        request_id: 22,
                        return_intersection: 0,
                    },
                )
                .await?;
                let mut a_done = false;
                let mut b_done = false;
                let mut a_result = 0;
                let mut b_result = 0;
                while !a_done {
                    let bytes = read_driven!(&mut a);
                    let Response::Result {
                        request_id,
                        status,
                        element_type,
                        data,
                        current_size,
                    } = Response::decode(&bytes)?
                    else {
                        return Err("expected original A result".into());
                    };
                    assert_eq!(request_id, 11);
                    assert_eq!(current_size, 1);
                    if status == DONE {
                        a_done = true;
                    } else {
                        assert_eq!(status, ADD_LOCAL);
                        assert_eq!(element_type, 0x1234);
                        assert_eq!(data, b"b");
                        a_result += 1;
                    }
                }
                while !b_done {
                    let bytes = read_driven!(&mut b);
                    let Response::Result {
                        request_id,
                        status,
                        element_type,
                        data,
                        ..
                    } = Response::decode(&bytes)?
                    else {
                        return Err("expected original B result".into());
                    };
                    assert_eq!(request_id, 22);
                    if status == DONE {
                        b_done = true;
                    } else {
                        assert_eq!(status, DEL_LOCAL);
                        assert_eq!(element_type, 0x1234);
                        assert_eq!(data, b"c");
                        b_result += 1;
                    }
                }
                assert_eq!((a_result, b_result), (1, 1));
                assert!(server.report().peer_frames >= 3);
                assert_eq!(server.report().backend_losses, 0);
                // Actual independent physical cleanup remains callable without a
                // logical clock tick or a fresh admission/peer-credit assumption.
                let stopped = server.close(&mut |_| {});
                assert!(stopped.failure.is_none());
                assert!(stopped.backend.is_some());
                assert_eq!(stopped.report.closed, 3);
                assert_eq!(stopped.retained, 0);
                carrier.close_all(&mut |_| {})?;
                drop(server);
                drop(carrier);
                drop(a);
                drop(b);
                drop(listening);
                drop(app_listener);
                drop(backend_listener);
                drop(directory);
                Ok::<(), Failure>(())
            })
            .await?
        })
}
