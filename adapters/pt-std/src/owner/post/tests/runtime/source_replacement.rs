//! Replacement DNS callbacks cannot adopt an older VPN result.
use super::*;
use crate::owner::Event;

async fn post_init(stream: &mut TcpStream) -> Result<(), Failure> {
    if !matches!(
        dns_wire::Request::decode(&frame(stream).await?)?,
        dns_wire::Request::Init {
            flags: dns_wire::POST_RESOLUTION
        }
    ) {
        return Err("replacement source did not begin with a fresh POST INIT".into());
    }
    Ok(())
}
async fn peers(dns: TcpListener, vpn: TcpListener) -> Result<(), Failure> {
    let id = [0x5a; 8];
    let old_address = vpn_wire::Address::V4([192, 0, 2, 1]);
    let fresh_address = vpn_wire::Address::V4([203, 0, 113, 2]);
    let mapped = vpn_wire::Address::V4([10, 99, 0, 2]);
    let (mut old, _) = dns.accept().await?;
    post_init(&mut old).await?;
    notify(&mut old, id, &packet(old_address, false)).await?;
    let (mut original_vpn, _) = vpn.accept().await?;
    let old_rid = allocation(&mut original_vpn, old_address).await?;
    drop(old);
    let (mut fresh, _) = dns.accept().await?;
    post_init(&mut fresh).await?;
    notify(&mut fresh, id, &packet(fresh_address, false)).await?;
    // The healthy VPN MQ survives. Its next request must be a new operation,
    // rather than replaying the old intent into the successor DNS callback.
    let fresh_rid = allocation(&mut original_vpn, fresh_address).await?;
    if fresh_rid == old_rid {
        return Err("replacement reused an old VPN request ID".into());
    }
    use_ip(
        &mut original_vpn,
        old_rid,
        vpn_wire::Address::V4([10, 66, 0, 1]),
    )
    .await?;
    use_ip(
        &mut original_vpn,
        old_rid,
        vpn_wire::Address::V4([10, 66, 0, 99]),
    )
    .await?;
    use_ip(&mut original_vpn, fresh_rid, mapped).await?;
    reply(&mut fresh, id, Some(mapped)).await
}

#[test]
fn a_replacement_dns_source_cannot_adopt_a_late_vpn_result() -> Result<(), Failure> {
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
            let mut cadet = crate::owner::cadet::Instance::new();
            let mut port_slots = [];
            let mut channel_slots = [];
            let mut limits = Limits::default();
            limits.dns.io_slice_bytes = 3;
            limits.vpn.io_slice_bytes = 3;
            limits.vpn.operations = 1;
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
                    packet_bytes: 128,
                    payload_bytes: 256,
                    ..core::Limits::default()
                },
                packet::Families {
                    ipv4: true,
                    ipv6: true,
                },
                limits,
                vpn::AfProfile::native(),
            )?;
            let mut actor = std::pin::pin!(peers(dns_listener, vpn_listener));
            let mut losses = 0;
            let result = tokio::time::timeout(
                Duration::from_secs(20),
                poll_fn(|cx| {
                    let progressed = match owner.poll(cx) {
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(Event::CleanupFailure(error))) => {
                            return Poll::Ready(Err(error));
                        }
                        Poll::Ready(Ok(Event::DnsLost {
                            stage: core::Stage::Post,
                            ..
                        })) => {
                            losses += 1;
                            true
                        }
                        Poll::Ready(Ok(Event::DnsLost { .. } | Event::Stopped)) => {
                            return Poll::Ready(Err("unexpected source retirement".into()));
                        }
                        Poll::Ready(Ok(_)) => true,
                        Poll::Pending => false,
                    };
                    if let Poll::Ready(result) = actor.as_mut().poll(cx) {
                        return Poll::Ready(result);
                    }
                    if progressed {
                        cx.waker().wake_by_ref();
                    }
                    Poll::Pending
                }),
            )
            .await;
            let cleanup = owner.stop();
            if !cleanup.is_empty() {
                return Err(format!("original source cleanup failed: {cleanup:?}").into());
            }
            result.map_err(|error| Box::new(error) as Failure)??;
            if losses != 1 {
                return Err(format!("expected one DNS replacement, got {losses}").into());
            }
            Ok(())
        })
}
