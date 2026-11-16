//! Actual native IPC owners with synthetic DNS/DHT/CADET loopback peers.
use super::super::{
    testing::{Ports, frame, notify, source},
    *,
};
use gnunet_crypto::EddsaPrivateKey;
use gnunet_pt::exit;
use gnunet_service_runtime::clock::SystemClock;
use gnunet_wire::official::{
    cadet as channel_wire,
    dht::{Path, ipc},
    dns as dns_wire,
};
use std::net::Ipv4Addr;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
};

const PACKET: usize = 128;

fn query(id: [u8; 2]) -> Vec<u8> {
    let mut bytes = vec![0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 1];
    bytes[..2].copy_from_slice(&id);
    bytes
}

fn answer(id: [u8; 2]) -> Vec<u8> {
    let mut bytes = query(id);
    bytes[2] = 0x81;
    bytes[3] = 0x80;
    bytes[7] = 1;
    bytes.extend_from_slice(&[0, 0, 16, 0, 1, 0, 0, 0, 120, 0, 100, 99]);
    bytes.resize(PACKET, b'x');
    bytes
}

fn application(dns: &[u8]) -> Result<Vec<u8>, Failure> {
    let mut bytes = vec![0; dns.len() + 4];
    gnunet_wire::official::Frame::new(
        gnunet_wire::official::message_type::VPN_DNS_FROM_INTERNET,
        dns,
    )?
    .encode(&mut bytes)?;
    Ok(bytes)
}

async fn respond(
    stream: &mut TcpStream,
    message: channel_wire::Response<'_>,
) -> Result<(), Failure> {
    let mut bytes = vec![0; message.encoded_len()?];
    message.encode(&mut bytes)?;
    for chunk in bytes.chunks(7) {
        stream.write_all(chunk).await?;
    }
    Ok(())
}

async fn sent_query(stream: &mut TcpStream, channel: u32) -> Result<[u8; 2], Failure> {
    let bytes = frame(stream).await?;
    let channel_wire::Request::Data {
        channel: actual,
        messages,
        ..
    } = channel_wire::Request::decode(&bytes)?
    else {
        return Err("expected original CADET DNS query".into());
    };
    if actual != channel || messages.len() != query([0; 2]).len() + 4 {
        return Err("wrong original channel or query extent".into());
    }
    let mut expected = vec![0; messages.len()];
    exit::encode_query(&query(messages[4..6].try_into()?), &mut expected)?;
    if messages != expected {
        return Err("unexpected CADET query bytes".into());
    }
    Ok(messages[4..6].try_into()?)
}

async fn dns_reply(stream: &mut TcpStream, id: [u8; 8], dns: Option<&[u8]>) -> Result<(), Failure> {
    let bytes = frame(stream).await?;
    match (dns_wire::Request::decode(&bytes)?, dns) {
        (
            dns_wire::Request::Reply {
                id: actual,
                decision: dns_wire::Decision::Answer(bytes),
            },
            Some(expected),
        ) if actual == id && bytes == expected => Ok(()),
        (
            dns_wire::Request::Reply {
                id: actual,
                decision: dns_wire::Decision::Drop,
            },
            None,
        ) if actual == id => Ok(()),
        _ => Err("wrong original PRE DNS decision".into()),
    }
}

async fn peers(
    dns: TcpListener,
    cadet: TcpListener,
    dht: TcpListener,
    now: u64,
) -> Result<(), Failure> {
    let key = EddsaPrivateKey::from_seed([0x19; 32]);
    let peer = *key.public_key().as_bytes();
    let expires = now.checked_add(60_000_000).ok_or(Fault::Overflow)?;
    let signature = key.sign(
        exit::PURPOSE,
        &exit::Advertisement::signed_region(peer, expires),
    )?;
    let block = exit::Advertisement::encode_signed(peer, expires, signature.as_bytes(), now)?;
    let (mut dht, _) = dht.accept().await?;
    let get_bytes = frame(&mut dht).await?;
    let ipc::Request::Get(get) = ipc::Request::decode(&get_bytes)? else {
        return Err("missing original native DHT GET".into());
    };
    if *get.key != exit::discovery_key()
        || get.block_type != exit::BLOCK_TYPE
        || get.replication != 1
        || get.options != 1
        || !get.extended_query.is_empty()
    {
        return Err("wrong exit discovery selector".into());
    }
    let result = ipc::ResultMessage {
        block_type: exit::BLOCK_TYPE,
        options: 0,
        put_path: Path::new(&[])?,
        get_path: Path::new(&[])?,
        id: get.id,
        expiration: gnunet_types::AbsoluteTime::from_micros(expires),
        key: get.key,
        truncated_peer: None,
        payload: &block,
    };
    let mut bytes = vec![0; result.encoded_len()?];
    result.encode(&mut bytes)?;
    dht.write_all(&bytes).await?;
    let (mut cadet, _) = cadet.accept().await?;
    let channel = match channel_wire::Request::decode(&frame(&mut cadet).await?)? {
        channel_wire::Request::ChannelCreate {
            channel,
            peer: actual,
            port,
            options: 0,
        } if actual == peer && port == exit::port_hash() => channel,
        _ => return Err("wrong original exit channel".into()),
    };
    respond(&mut cadet, channel_wire::Response::Ack { channel }).await?;
    let (mut dns, _) = dns.accept().await?;
    if !matches!(
        dns_wire::Request::decode(&frame(&mut dns).await?)?,
        dns_wire::Request::Init {
            flags: dns_wire::PRE_RESOLUTION
        }
    ) {
        return Err("missing native PRE INIT".into());
    }
    notify(&mut dns, [1; 8], &query([0x12, 0x34])).await?;
    let first = sent_query(&mut cadet, channel).await?;
    respond(&mut cadet, channel_wire::Response::Ack { channel }).await?;
    notify(&mut dns, [2; 8], &query([0x56, 0x78])).await?;
    let second = sent_query(&mut cadet, channel).await?;
    if first == second {
        return Err("same-channel DNS IDs were reused".into());
    }
    let mut messages = application(&answer(first))?;
    messages.extend_from_slice(&application(&answer(second))?);
    respond(
        &mut cadet,
        channel_wire::Response::Data {
            channel,
            priority: 0,
            messages: &messages,
        },
    )
    .await?;
    dns_reply(&mut dns, [1; 8], Some(&answer([0x12, 0x34]))).await?;
    dns_reply(&mut dns, [2; 8], Some(&answer([0x56, 0x78]))).await?;
    if channel_wire::Request::decode(&frame(&mut cadet).await?)?
        != (channel_wire::Request::Ack { channel })
    {
        return Err("coalesced input did not receive its one original acknowledgement".into());
    }
    respond(&mut cadet, channel_wire::Response::Ack { channel }).await?;
    notify(&mut dns, [3; 8], &query([0xab, 0xcd])).await?;
    let third = sent_query(&mut cadet, channel).await?;
    respond(
        &mut cadet,
        channel_wire::Response::ChannelDestroy { channel },
    )
    .await?;
    // All three peers remain idle. Only the original retry timer may authorize
    // this fresh channel and retry of the still-live third callback.
    let successor = match channel_wire::Request::decode(&frame(&mut cadet).await?)? {
        channel_wire::Request::ChannelCreate {
            channel: new,
            peer: actual,
            port,
            options: 0,
        } if new != channel && actual == peer && port == exit::port_hash() => new,
        _ => return Err("idle exit recovery did not create a fresh native channel".into()),
    };
    respond(
        &mut cadet,
        channel_wire::Response::Ack { channel: successor },
    )
    .await?;
    let retried = sent_query(&mut cadet, successor).await?;
    if retried == third {
        return Err("old channel DNS ID leaked into its replacement".into());
    }
    respond(
        &mut cadet,
        channel_wire::Response::Data {
            channel: successor,
            priority: 0,
            messages: &application(&answer(retried))?,
        },
    )
    .await?;
    dns_reply(&mut dns, [3; 8], Some(&answer([0xab, 0xcd]))).await?;
    if channel_wire::Request::decode(&frame(&mut cadet).await?)?
        != (channel_wire::Request::Ack { channel: successor })
    {
        return Err("replacement input lost its original acknowledgement".into());
    }
    respond(
        &mut cadet,
        channel_wire::Response::Ack { channel: successor },
    )
    .await?;
    notify(&mut dns, [4; 8], &query([0xde, 0xad])).await?;
    let fourth = sent_query(&mut cadet, successor).await?;
    let mut rejected = query(fourth);
    rejected[2] = 0x81;
    rejected[3] = 0x80;
    rejected[5] = 2;
    rejected.extend_from_slice(&query([0; 2])[12..]);
    respond(
        &mut cadet,
        channel_wire::Response::Data {
            channel: successor,
            priority: 0,
            messages: &application(&rejected)?,
        },
    )
    .await?;
    if channel_wire::Request::decode(&frame(&mut cadet).await?)?
        != (channel_wire::Request::ChannelDestroy { channel: successor })
    {
        return Err("fixed parser refusal was retried or granted receive credit".into());
    }
    // The fourth callback remains bounded until retry/expiry or explicit stop;
    // rejecting its exit must not retire the independent healthy DNS source.
    notify(&mut dns, [5; 8], &query([0xef, 0x01])).await?;
    dns_reply(&mut dns, [5; 8], None).await?;
    Ok(())
}

#[test]
fn native_pre_reuses_reserved_replies_and_retires_a_policy_violating_exit() -> Result<(), Failure> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let dns_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let cadet_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let dht_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
            let now = clock.sample()?.now.as_micros();
            let ports = Arc::new(Ports(clock.clone()));
            let core = core::Instance::new();
            let dns = dns::Instance::new();
            let mut vpn = vpn::Instance::new();
            let mut cadet = cadet::Instance::new();
            let mut dht = gnunet_dht_client_host::Instance::new();
            let mut discovery = discovery::Native::new(
                &mut dht,
                source(dht_listener.local_addr()?, b"dht", ports.clone())?,
            )?;
            let mut port_slots = [];
            let mut channel_slots = [cadet::ChannelSlot::new()];
            let mut limits = Limits::default();
            limits.dns.io_slice_bytes = 3;
            limits.cadet.io_slice_bytes = 7;
            let mut owner = Owner::new(
                Identities {
                    core: &core,
                    dns: &dns,
                    vpn: &mut vpn,
                    cadet: &mut cadet,
                    ports: &mut port_slots,
                    channels: &mut channel_slots,
                },
                Sources {
                    pre: Some(source(dns_listener.local_addr()?, b"dns", ports.clone())?),
                    post: None,
                    vpn: None,
                    cadet: Some(source(cadet_listener.local_addr()?, b"cadet", ports)?),
                    discovery: Some(&mut discovery),
                },
                clock,
                core::Limits {
                    requests: 2,
                    packet_bytes: PACKET,
                    payload_bytes: 2 * (17 + PACKET),
                    questions: 1,
                    exits: 1,
                    tunnels: 1,
                    ..core::Limits::default()
                },
                gnunet_pt::packet::Families {
                    ipv4: false,
                    ipv6: false,
                },
                limits,
                vpn::AfProfile::native(),
            )?;
            let mut actor = std::pin::pin!(peers(dns_listener, cadet_listener, dht_listener, now));
            let result = tokio::time::timeout(
                Duration::from_secs(20),
                poll_fn(|cx| {
                    let progress = match owner.poll(cx) {
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(Event::CleanupFailure(error))) => {
                            return Poll::Ready(Err(error));
                        }
                        Poll::Ready(Ok(Event::DnsLost { .. } | Event::Stopped)) => {
                            return Poll::Ready(Err(
                                "healthy original PRE source was retired".into()
                            ));
                        }
                        Poll::Ready(Ok(_)) => true,
                        Poll::Pending => false,
                    };
                    if let Poll::Ready(result) = actor.as_mut().poll(cx) {
                        return Poll::Ready(result);
                    }
                    if progress {
                        cx.waker().wake_by_ref();
                    }
                    Poll::Pending
                }),
            )
            .await;
            let cleanup = owner.stop();
            if !cleanup.is_empty() {
                return Err(format!("original PRE cleanup failed: {cleanup:?}").into());
            }
            result.map_err(|error| Box::new(error) as Failure)?
        })
}
