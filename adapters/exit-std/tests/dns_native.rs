//! Actual EXIT Driver + production own-peer CADET SERVICE + loopback DNS.
//! No TUN, administrative network mutation, C peer or encrypted underlay claim.
#![expect(
    clippy::panic_in_result_fn,
    reason = "One native composition checks packed original receive credit, real UDP results and independent cleanup"
)]
use gnunet_cadet::service as carrier;
use gnunet_cadet_host::{self as cadet, server as carrier_host};
use gnunet_exit::{
    AfProfile,
    engine::{Config, Engine, Limits as CoreLimits},
    nat::Entropy,
    policy::Policy,
};
use gnunet_exit_host::runtime::{Binding, Driver, Limits, Resolver};
use gnunet_service_runtime::{
    clock::{RuntimeClock, SystemClock},
    credentials::UnixAccess,
    service::{Listener, ServiceOptions},
};
use gnunet_types::Error as Fault;
use gnunet_wire::official::{
    Frames,
    cadet::{CLIENT_CHANNEL_BOUNDARY, Request, Response},
    vpn::PeerMessage,
};
use std::{
    error::Error,
    future::{Future, poll_fn},
    path::PathBuf,
    sync::Arc,
    task::Poll,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UdpSocket, UnixListener, UnixStream},
};
type Failure = Box<dyn Error>;
struct Directory(PathBuf);
impl Directory {
    fn new() -> Result<Self, Failure> {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let path = std::env::temp_dir().join(format!("gexit-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_dir_all(&self.0);
    }
}
struct Random(u8);
impl Entropy for Random {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Fault> {
        for byte in bytes {
            self.0 = self.0.wrapping_add(17);
            *byte = self.0;
        }
        Ok(())
    }
}
fn query(id: u16) -> Vec<u8> {
    let mut bytes = vec![0; 12];
    bytes[..2].copy_from_slice(&id.to_be_bytes());
    bytes[2] = 1;
    bytes[5] = 1;
    bytes.extend_from_slice(b"\x05alpha\x04test\x00\x00\x01\x00\x01");
    bytes
}
async fn write(stream: &mut UnixStream, request: Request<'_>) -> Result<(), Failure> {
    let mut bytes = vec![0; request.encoded_len()?];
    request.encode(&mut bytes)?;
    for part in bytes.chunks(3) {
        stream.write_all(part).await?;
    }
    Ok(())
}
async fn frame(stream: &mut UnixStream) -> Result<Vec<u8>, Failure> {
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
#[test]
fn actual_packed_dns_queries_complete_before_one_outer_ack_and_close() -> Result<(), Failure> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(8), async {
                let directory = Directory::new()?;
                let path = directory.0.join("c");
                let listener = UnixListener::bind(&path)?;
                let listeners = [Listener::Unix(&listener)];
                let resolver = UdpSocket::bind("127.0.0.1:0").await?;
                let endpoint = resolver.local_addr()?;
                let responder = tokio::spawn(async move {
                    let mut replies = Vec::new();
                    let mut buffer = [0; 512];
                    for _ in 0..2 {
                        let (n, peer) = resolver.recv_from(&mut buffer).await?;
                        let mut response = buffer[..n].to_vec();
                        if n < 12 || response[2] & 0x80 != 0 {
                            return Err(std::io::Error::other("not an actual DNS query"));
                        }
                        response[2] |= 0x80;
                        response[3] = 0x80;
                        let mut wrong = response.clone();
                        wrong[0] ^= 0x80;
                        let bad = resolver.send_to(&wrong, peer).await?;
                        let sent = resolver.send_to(&response, peer).await?;
                        if bad != n || sent != n {
                            return Err(std::io::Error::other("short DNS datagram"));
                        }
                        replies.push(response);
                    }
                    Ok::<_, std::io::Error>(replies)
                });
                let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
                let mut carrier_id = carrier::Instance::new();
                let mut clients = [carrier::ClientSlot::new(); 2];
                let mut ports = [carrier::PortSlot::new(); 1];
                let mut channels = [carrier::ChannelSlot::new(); 4];
                let mut bytes = [[0; 1024]; 8];
                let mut messages = bytes.each_mut().map(|b| carrier::MessageSlot::new(b));
                let core = carrier::Service::new(
                    &mut carrier_id,
                    [1; 32],
                    &mut clients,
                    &mut ports,
                    &mut channels,
                    &mut messages,
                    carrier::Limits {
                        window: 1,
                        loop_payload_bytes: 1024,
                        remote_payload_bytes: 1024,
                    },
                )?;
                let mut service = carrier_host::Server::new(
                    core,
                    carrier_host::Limits {
                        clients: 2,
                        io_slice_bytes: 3,
                    },
                    ServiceOptions::default(),
                    UnixAccess::default(),
                    clock.clone(),
                )?;
                let mut native_id = cadet::Instance::new();
                let mut native_ports = [cadet::PortSlot::new(); 1];
                let mut native_channels = [cadet::ChannelSlot::new(); 2];
                let native = cadet::Client::new(
                    &mut native_id,
                    cadet::EndpointSource::unix_with_clock(path.clone(), clock),
                    &mut native_ports,
                    &mut native_channels,
                    cadet::Limits {
                        io_slice_bytes: 3,
                        ..cadet::Limits::default()
                    },
                )?;
                let core = Engine::new(
                    Config {
                        policy: Policy {
                            ipv4: false,
                            ipv6: false,
                            rules: gnunet_exit::policy::InternetRules::Ordered {
                                rules: &[],
                                default_allow: false,
                            },
                        },
                        ipv4: None,
                        ipv6: None,
                        services: &[],
                        dns: true,
                        af: AfProfile::native(),
                    },
                    CoreLimits {
                        flows: 2,
                        processing_receipts: 4,
                        output_frames: 4,
                        output_bytes: 4096,
                        ..CoreLimits::default()
                    },
                )?;
                let mut driver = Driver::new(
                    core,
                    native,
                    None,
                    &[Binding::dns()],
                    Some(Resolver {
                        server: endpoint,
                        retry: Duration::from_millis(200),
                    }),
                    Limits {
                        ports: 1,
                        channels: 1,
                        inner_frames: 2,
                        dns_jobs: 1,
                        dns_bytes: 512,
                        io_grace: Duration::from_secs(2),
                        ..Limits::default()
                    },
                    Random(3),
                )?;
                let mut discarded = 0;
                macro_rules! poll_all {
                    ($cx:expr) => {{
                        let a = driver.poll($cx, None, &mut |event| {
                            if matches!(
                                event,
                                gnunet_exit_host::runtime::Event::DnsDiscarded { .. }
                            ) {
                                discarded += 1;
                            }
                        });
                        let report = driver.report();
                        if report.receive_done > 1
                            || (report.receive_done != 0 && report.dns_written != 2)
                        {
                            return Poll::Ready(Err(
                                "outer receive_done preceded original DNS writes or was duplicated"
                                    .into(),
                            ));
                        }
                        let b = service.poll($cx, &listeners, None, &mut |_| {});
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
                while !driver.binding_status(0)?.announced {
                    poll_fn(|cx| {
                        if poll_all!(cx) {
                            Poll::Ready(Ok::<(), Failure>(()))
                        } else {
                            Poll::Pending
                        }
                    })
                    .await?;
                }
                let mut actor = UnixStream::connect(&path).await?;
                write(
                    &mut actor,
                    Request::ChannelCreate {
                        channel: CLIENT_CHANNEL_BOUNDARY,
                        peer: [1; 32],
                        port: Binding::dns().hash,
                        options: 0,
                    },
                )
                .await?;
                macro_rules! read_driven {
                    () => {{
                        let mut reading = std::pin::pin!(frame(&mut actor));
                        poll_fn(|cx| {
                            let active = poll_all!(cx);
                            match reading.as_mut().poll(cx) {
                                Poll::Ready(r) => Poll::Ready(r),
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
                assert!(matches!(
                    Response::decode(&read_driven!())?,
                    Response::Ack {
                        channel: CLIENT_CHANNEL_BOUNDARY
                    }
                ));
                let mut packed = Vec::new();
                for id in [0x1201, 0x1202] {
                    let q = query(id);
                    let m = PeerMessage::Dns {
                        reply: false,
                        packet: &q,
                    };
                    let at = packed.len();
                    packed.resize(at + m.encoded_len()?, 0);
                    m.encode(&mut packed[at..])?;
                }
                write(
                    &mut actor,
                    Request::Data {
                        channel: CLIENT_CHANNEL_BOUNDARY,
                        priority: 0,
                        messages: &packed,
                    },
                )
                .await?;
                let mut answers = Vec::new();
                let mut acknowledgements = 0;
                while answers.len() != 2 || acknowledgements != 1 {
                    let bytes = read_driven!();
                    match Response::decode(&bytes)? {
                        Response::Data {
                            channel: CLIENT_CHANNEL_BOUNDARY,
                            messages,
                            ..
                        } => {
                            for inner in Frames::new(messages) {
                                let inner = inner?;
                                if inner.header().message_type()
                                    != gnunet_wire::official::message_type::VPN_DNS_FROM_INTERNET
                                {
                                    return Err("not an actual EXIT DNS response".into());
                                }
                                let packet = inner.payload();
                                answers.push(u16::from_be_bytes([packet[0], packet[1]]));
                                assert_eq!(&packet[12..], &query(0)[12..]);
                                assert_ne!(packet[2] & 0x80, 0);
                            }
                            write(
                                &mut actor,
                                Request::Ack {
                                    channel: CLIENT_CHANNEL_BOUNDARY,
                                },
                            )
                            .await?;
                        }
                        Response::Ack {
                            channel: CLIENT_CHANNEL_BOUNDARY,
                        } => {
                            // Sender credit is not the downstream processing ACK.
                            acknowledgements += 1;
                        }
                        _ => return Err("unexpected original CADET response".into()),
                    }
                }
                answers.sort_unstable();
                assert_eq!(answers, [0x1201, 0x1202]);
                assert!(discarded >= 2);
                assert_eq!(driver.report().dns_replies, 2);
                // Finish the real outer receive_done write even if its resulting
                // sender credit was already transferred by the production carrier.
                while driver.report().receive_done != 1 {
                    poll_fn(|cx| {
                        if poll_all!(cx) {
                            Poll::Ready(Ok::<(), Failure>(()))
                        } else {
                            Poll::Pending
                        }
                    })
                    .await?;
                }
                let replies = responder.await??;
                assert_eq!(replies.len(), 2);
                let stopped = driver.shutdown(|_| {});
                assert!(stopped.failure.is_none());
                assert!(stopped.quiescent);
                assert_eq!(stopped.report.tun_written, 0);
                assert_eq!(stopped.report.tun_read, 0);
                assert_eq!(stopped.report.peer_written, 2);
                assert_eq!(stopped.report.receive_done, 1);
                service.close_all(&mut |_| {})?;
                Ok::<(), Failure>(())
            })
            .await?
        })
}
