//! Real loopback TCP IPC with synthetic USE_IP results, not a VPN/device or C-service test.
use super::super::super::testing::{Ports, frame, notify, source};
use super::*;
use gnunet_pt::{core, packet};
use gnunet_wire::official::{dns as dns_wire, vpn as vpn_wire};
use std::{
    cell::Cell,
    future::{Future, poll_fn},
    net::Ipv4Addr,
    task::Poll,
    time::Duration,
};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    time::Instant,
};

mod source_replacement;

fn packet(address: vpn_wire::Address, large: bool) -> Vec<u8> {
    let mut bytes = vec![
        0x12, 0x34, 0x81, 0xa0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1,
    ];
    let (kind, raw): (u16, &[u8]) = match &address {
        vpn_wire::Address::V4(raw) => (1, raw),
        vpn_wire::Address::V6(raw) => (28, raw),
    };
    bytes.push(0);
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(&[0, 1, 0, 0, 0, 120]);
    let length = if kind == 1 { 4_u16 } else { 16 };
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(raw);
    if large {
        bytes[7] = 2;
        bytes.extend_from_slice(&[0, 0, 16, 0, 1, 0, 0, 0, 120, 3, 0]);
        for _ in 0..3 {
            bytes.push(255);
            bytes.extend_from_slice(&[b'x'; 255]);
        }
    }
    bytes
}

async fn allocation(
    stream: &mut TcpStream,
    expected: vpn_wire::Address,
) -> Result<[u8; 8], Failure> {
    match vpn_wire::Request::decode_with_profile(&frame(stream).await?, vpn::AfProfile::native())? {
        vpn_wire::Request::Internet {
            reserved: 0,
            destination,
            result_af,
            request_id,
            expires,
        } if destination == expected
            && result_af == vpn::AfProfile::native().value(expected.family())
            && expires != u64::MAX =>
        {
            Ok(request_id)
        }
        _ => Err("wrong original VPN allocation request".into()),
    }
}

async fn use_ip(
    stream: &mut TcpStream,
    request_id: [u8; 8],
    address: vpn_wire::Address,
) -> Result<(), Failure> {
    let response = vpn_wire::Response {
        request_id,
        address: Some(address),
    };
    let mut bytes = vec![0; response.encoded_len()?];
    response.encode_with_profile(&mut bytes, vpn::AfProfile::native())?;
    for chunk in bytes.chunks(3) {
        stream.write_all(chunk).await?;
    }
    Ok(())
}

async fn reply(
    stream: &mut TcpStream,
    id: [u8; 8],
    expected: Option<vpn_wire::Address>,
) -> Result<(), Failure> {
    let bytes = frame(stream).await?;
    match (dns_wire::Request::decode(&bytes)?, expected) {
        (
            dns_wire::Request::Reply {
                id: actual,
                decision: dns_wire::Decision::Drop,
            },
            None,
        ) if actual == id => Ok(()),
        (
            dns_wire::Request::Reply {
                id: actual,
                decision: dns_wire::Decision::Answer(bytes),
            },
            Some(address),
        ) if actual == id => {
            if bytes[..2] != [0x12, 0x34] || bytes[3] & 0x20 != 0 {
                return Err("rewritten DNS identity or AD flag changed".into());
            }
            let mut records = [packet::AddressRecord::EMPTY; 4];
            let mut scratch = [0; 4096];
            let count = packet::scan(
                bytes,
                packet::Families {
                    ipv4: true,
                    ipv6: true,
                },
                &mut records,
                &mut scratch,
                gnunet_dns::Limits::DNS,
            )?;
            let expected = super::super::allocated(address);
            if count != 1 || records[0].address() != expected || records[0].ttl_seconds() != 0 {
                return Err("wrong synthetic address or nonzero rewritten TTL".into());
            }
            Ok(())
        }
        _ => Err("unexpected original DNS decision".into()),
    }
}

async fn peers(
    dns: TcpListener,
    vpn: TcpListener,
    queued: &Cell<bool>,
    sent: &Cell<bool>,
) -> Result<(), Failure> {
    let (mut dns, _) = dns.accept().await?;
    dns.set_nodelay(true)?;
    if !matches!(
        dns_wire::Request::decode(&frame(&mut dns).await?)?,
        dns_wire::Request::Init {
            flags: dns_wire::POST_RESOLUTION
        }
    ) {
        return Err("missing original POST INIT".into());
    }
    let original = vpn_wire::Address::V4([192, 0, 2, 1]);
    let mapped = vpn_wire::Address::V4([10, 99, 0, 1]);
    notify(&mut dns, [1; 8], &packet(original, true)).await?;
    let (mut first, _) = vpn.accept().await?;
    first.set_nodelay(true)?;
    let a = allocation(&mut first, original).await?;
    use_ip(&mut first, a, mapped).await?;
    poll_fn(|_| {
        if queued.get() {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
    // All native callback slots remain usable even when the one core request
    // and the output budget are occupied by the first response.
    for id in [[2; 8], [5; 8], [6; 8]] {
        notify(&mut dns, id, &packet(original, false)).await?;
    }
    sent.set(true);
    reply(&mut dns, [1; 8], Some(mapped)).await?;
    for id in [[2; 8], [5; 8], [6; 8]] {
        reply(&mut dns, id, None).await?;
    }

    let original = vpn_wire::Address::V6([0x20; 16]);
    let mapped = vpn_wire::Address::V6([0xfd; 16]);
    notify(&mut dns, [1; 8], &packet(original, false)).await?;
    let b = allocation(&mut first, original).await?;
    if a == b {
        return Err("VPN ID reused for a later callback".into());
    }
    use_ip(&mut first, b, mapped).await?;
    reply(&mut dns, [1; 8], Some(mapped)).await?;

    let lost = vpn_wire::Address::V6([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10]);
    notify(&mut dns, [3; 8], &packet(lost, false)).await?;
    let c = allocation(&mut first, lost).await?;
    drop(first);
    reply(&mut dns, [3; 8], None).await?;

    let fresh = vpn_wire::Address::V6([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99]);
    notify(&mut dns, [4; 8], &packet(fresh, false)).await?;
    let (mut second, _) = vpn.accept().await?;
    second.set_nodelay(true)?;
    // The successor must see the new request, never a replay of `lost`.
    let d = allocation(&mut second, fresh).await?;
    if [a, b, c].contains(&d) {
        return Err("successor VPN reused an old request ID".into());
    }
    let mapped = vpn_wire::Address::V6([0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99]);
    use_ip(&mut second, d, mapped).await?;
    reply(&mut dns, [4; 8], Some(mapped)).await
}

#[test]
fn enabled_post_preserves_the_dns_source_through_refusal_and_vpn_replacement() -> Result<(), Failure>
{
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let dns_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let vpn_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
            let ports = Arc::new(Ports(clock.clone()));
            let core = core::Instance::new();
            let dns = gnunet_dns_client_host::Instance::new();
            let mut vpn = vpn::Instance::new();
            let mut cadet = super::super::super::cadet::Instance::new();
            let mut port_slots = [];
            let mut channel_slots = [];
            let mut limits = Limits::default();
            limits.dns.io_slice_bytes = 1;
            limits.dns.requests = 4;
            limits.dns.source_bytes =
                packet(vpn_wire::Address::V4([192, 0, 2, 1]), true).len() + 16;
            limits.vpn.io_slice_bytes = 3;
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
                    pre: None,
                    post: Some(source(dns_listener.local_addr()?, b"dns", ports.clone())?),
                    vpn: Some(source(vpn_listener.local_addr()?, b"vpn", ports)?),
                    cadet: None,
                    discovery: None,
                },
                clock,
                core::Limits {
                    requests: 1,
                    packet_bytes: 1024,
                    payload_bytes: 4096,
                    ..core::Limits::default()
                },
                packet::Families {
                    ipv4: true,
                    ipv6: true,
                },
                limits,
                vpn::AfProfile::native(),
            )?;
            let queued = Cell::new(false);
            let sent = Cell::new(false);
            let mut actor = std::pin::pin!(peers(dns_listener, vpn_listener, &queued, &sent));
            let result = tokio::time::timeout_at(
                Instant::now() + Duration::from_secs(20),
                poll_fn(|cx| {
                    let mut progress = false;
                    if !queued.get() || sent.get() {
                        match owner.poll(cx) {
                            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                            Poll::Ready(Ok(super::super::super::Event::CleanupFailure(error))) => {
                                return Poll::Ready(Err(error));
                            }
                            Poll::Ready(Ok(
                                super::super::super::Event::DnsLost { .. }
                                | super::super::super::Event::Stopped,
                            )) => {
                                return Poll::Ready(Err(
                                    "healthy original DNS source was retired".into()
                                ));
                            }
                            Poll::Ready(Ok(_)) => progress = true,
                            Poll::Pending => {}
                        }
                        if owner.callbacks.iter().any(|row| {
                            row.core.is_some()
                                && row.resolution == super::super::super::Resolution::Queued
                        }) {
                            queued.set(true);
                        }
                    }
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
                return Err(format!("original PT cleanup failed: {cleanup:?}").into());
            }
            result.map_err(|error| Box::new(error) as Failure)?
        })
}
