//! Actual DNS/CADET TCP epochs; discovery stays idle and returns no peer fixture.
use super::*;
use tokio::io::AsyncReadExt;

struct Discovery<'a> {
    clock: Arc<dyn RuntimeClock>,
    original: Option<core::Discovery<'a>>,
}
impl<'a> discovery::Port<'a> for Discovery<'a> {
    fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.clock.clone()
    }
    fn start(&mut self, query: discovery::Query<'a>) -> Result<(), Failure> {
        if self.original.is_some() {
            return Err(Fault::Conflict.into());
        }
        self.original = Some(query.original);
        Ok(())
    }
    fn poll(&mut self, _: &mut Context<'_>) -> Poll<Result<discovery::Event<'a>, Failure>> {
        Poll::Pending
    }
    fn stop(&mut self, original: core::Discovery<'a>) -> Result<(), Failure> {
        if self.original != Some(original) {
            return Err(Fault::Stale.into());
        }
        self.original = None;
        Ok(())
    }
}

async fn drive_until<'a, T>(
    owner: &mut Owner<'a, '_>,
    losses: &mut usize,
    mut ready: impl FnMut(&Owner<'a, '_>, &mut Context<'_>) -> Poll<T>,
) -> Result<T, Failure> {
    poll_fn(|cx| {
        let progress = match owner.poll(cx) {
            Poll::Ready(Err(error) | Ok(Event::CleanupFailure(error))) => {
                return Poll::Ready(Err(error));
            }
            Poll::Ready(Ok(Event::DnsLost {
                stage: Stage::Pre,
                cause: dns::Cause::Eof,
            })) => {
                *losses += 1;
                true
            }
            Poll::Ready(Ok(Event::DnsLost { .. } | Event::Stopped)) => {
                return Poll::Ready(Err("unexpected original PRE source retirement".into()));
            }
            Poll::Ready(Ok(_)) => true,
            Poll::Pending => false,
        };
        if let Poll::Ready(value) = ready(owner, cx) {
            return Poll::Ready(Ok(value));
        }
        if progress {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    })
    .await
}

async fn during<T>(
    owner: &mut Owner<'_, '_>,
    losses: &mut usize,
    future: impl Future<Output = T>,
) -> Result<T, Failure> {
    let mut future = std::pin::pin!(future);
    drive_until(owner, losses, |_, cx| future.as_mut().poll(cx)).await
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assert actual original TCP EOF and independent successor DNS/CADET epochs"
)]
fn pre_source_loss_physically_retires_the_original_cadet_epoch() -> Result<(), Failure> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let dns_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let cadet_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
            let ports = Arc::new(Ports(clock.clone()));
            let core = core::Instance::new();
            let dns = dns::Instance::new();
            let mut vpn = vpn::Instance::new();
            let mut cadet = cadet::Instance::new();
            let mut discovery = Discovery {
                clock: clock.clone(),
                original: None,
            };
            let mut port_slots = [];
            let mut channel_slots = [cadet::ChannelSlot::new()];
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
                    tunnels: 1,
                    ..core::Limits::default()
                },
                gnunet_pt::packet::Families {
                    ipv4: false,
                    ipv6: false,
                },
                Limits::default(),
                vpn::AfProfile::native(),
            )?;
            let mut losses = 0;
            let result = tokio::time::timeout(Duration::from_secs(10), async {
                let (mut original_dns, _) =
                    during(&mut owner, &mut losses, dns_listener.accept()).await??;
                let (mut original_cadet, _) =
                    during(&mut owner, &mut losses, cadet_listener.accept()).await??;
                let init = during(&mut owner, &mut losses, frame(&mut original_dns)).await??;
                assert!(matches!(
                    dns_wire::Request::decode(&init)?,
                    dns_wire::Request::Init {
                        flags: dns_wire::PRE_RESOLUTION,
                    }
                ));
                let original = drive_until(&mut owner, &mut losses, |owner, _| {
                    match (
                        owner.pre_source,
                        owner.cadet.as_ref().and_then(cadet::Client::epoch),
                    ) {
                        (Some((dns, source)), Some(cadet)) => Poll::Ready((dns, source, cadet)),
                        _ => Poll::Pending,
                    }
                })
                .await?;
                let query = owner.discovery.ok_or(Fault::NotReady)?;
                drop(original_dns);
                // The unchanged code kept this actual socket open indefinitely.
                // No successor query is submitted before its physical EOF.
                assert_eq!(
                    during(&mut owner, &mut losses, original_cadet.read(&mut [0; 1])).await??,
                    0
                );
                let (mut successor_dns, _) =
                    during(&mut owner, &mut losses, dns_listener.accept()).await??;
                let (_successor_cadet, _) =
                    during(&mut owner, &mut losses, cadet_listener.accept()).await??;
                let init = during(&mut owner, &mut losses, frame(&mut successor_dns)).await??;
                assert!(matches!(
                    dns_wire::Request::decode(&init)?,
                    dns_wire::Request::Init {
                        flags: dns_wire::PRE_RESOLUTION,
                    }
                ));
                let successor = drive_until(&mut owner, &mut losses, |owner, _| {
                    match (
                        owner.pre_source,
                        owner.cadet.as_ref().and_then(cadet::Client::epoch),
                    ) {
                        (Some((dns, source)), Some(cadet)) => Poll::Ready((dns, source, cadet)),
                        _ => Poll::Pending,
                    }
                })
                .await?;
                assert_ne!(original.0, successor.0);
                assert_ne!(original.1, successor.1);
                assert_ne!(original.2, successor.2);
                let retained = owner.discovery.ok_or(Fault::NotReady)?;
                assert_eq!(
                    (query.0, query.1.expires, query.1.hard),
                    (retained.0, retained.1.expires, retained.1.hard)
                );
                assert_eq!(losses, 1);
                during(
                    &mut owner,
                    &mut losses,
                    notify(&mut successor_dns, [9; 8], &super::query([1, 2])),
                )
                .await??;
                during(
                    &mut owner,
                    &mut losses,
                    dns_reply(&mut successor_dns, [9; 8], None),
                )
                .await??;
                Ok::<_, Failure>(())
            })
            .await;
            let cleanup = owner.stop();
            if !cleanup.is_empty() {
                return Err(
                    format!("original source-retirement cleanup failed: {cleanup:?}").into(),
                );
            }
            result.map_err(|error| Box::new(error) as Failure)?
        })
}
