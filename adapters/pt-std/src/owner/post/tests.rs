//! POST construction and separate enabled IPC models.
use super::*;
use crate::{Identities, Limits, Sources};
use gnunet_service_runtime::clock::{RuntimeClock, SystemClock};
use std::sync::Arc;

#[cfg(feature = "program")]
mod runtime;

#[test]
fn post_only_owner_needs_no_cadet_storage_or_disabled_provider_capacity() -> Result<(), Failure> {
    let core = gnunet_pt::core::Instance::new();
    let dns = gnunet_dns_client_host::Instance::new();
    let mut vpn = vpn::Instance::new();
    let mut cadet = super::super::cadet::Instance::new();
    let mut ports = [];
    let mut channels = [];
    let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
    let endpoint = |name| {
        gnunet_client_host::EndpointSource::unix_with_clock(
            std::path::PathBuf::from(name),
            clock.clone(),
        )
    };
    let mut native = Limits::default();
    native.cadet.frame_bytes = 0;
    let mut owner = Owner::new(
        Identities {
            core: &core,
            dns: &dns,
            vpn: &mut vpn,
            cadet: &mut cadet,
            ports: &mut ports,
            channels: &mut channels,
        },
        Sources {
            pre: None,
            post: Some(endpoint("unused-pt-post-dns")),
            vpn: Some(endpoint("unused-pt-post-vpn")),
            cadet: None,
            discovery: None,
        },
        clock,
        gnunet_pt::core::Limits::default(),
        gnunet_pt::packet::Families {
            ipv4: true,
            ipv6: true,
        },
        native,
        vpn::AfProfile::native(),
    )?;
    if !owner.stop().is_empty() {
        return Err("unconnected POST-only owner produced cleanup failure".into());
    }
    Ok(())
}

#[test]
fn invalid_core_settings_are_refused_before_native_subscriptions() -> Result<(), Failure> {
    struct NoSubscriptions;
    impl RuntimeClock for NoSubscriptions {
        fn sample(&self) -> Result<gnunet_service_runtime::clock::ClockSample, Fault> {
            SystemClock.sample()
        }
        fn subscribe(
            &self,
        ) -> Result<Box<dyn gnunet_service_runtime::clock::ClockSubscription>, Fault> {
            Err(Fault::Unavailable)
        }
    }
    for pure in [
        gnunet_pt::core::Limits {
            packet_bytes: usize::MAX,
            payload_bytes: usize::MAX,
            ..Default::default()
        },
        gnunet_pt::core::Limits {
            requests: 0,
            ..Default::default()
        },
        gnunet_pt::core::Limits {
            records: 0,
            ..Default::default()
        },
        gnunet_pt::core::Limits {
            tunnels: 5,
            ..Default::default()
        },
    ] {
        let core = gnunet_pt::core::Instance::new();
        let dns = gnunet_dns_client_host::Instance::new();
        let mut vpn = vpn::Instance::new();
        let mut cadet = super::super::cadet::Instance::new();
        let mut ports = [];
        let mut channels = [];
        let clock: Arc<dyn RuntimeClock> = Arc::new(NoSubscriptions);
        let endpoint = |name| {
            gnunet_client_host::EndpointSource::unix_with_clock(
                std::path::PathBuf::from(name),
                clock.clone(),
            )
        };
        let result = Owner::new(
            Identities {
                core: &core,
                dns: &dns,
                vpn: &mut vpn,
                cadet: &mut cadet,
                ports: &mut ports,
                channels: &mut channels,
            },
            Sources {
                pre: None,
                post: Some(endpoint("unused-invalid-pt-dns")),
                vpn: Some(endpoint("unused-invalid-pt-vpn")),
                cadet: None,
                discovery: None,
            },
            clock,
            pure,
            gnunet_pt::packet::Families {
                ipv4: true,
                ipv6: true,
            },
            Limits::default(),
            vpn::AfProfile::native(),
        );
        match result {
            Err(error) if error.downcast_ref::<Fault>() == Some(&Fault::InvalidInput) => {}
            Err(error) => {
                return Err(format!("invalid core bounds reached native setup: {error}").into());
            }
            Ok(_) => return Err("invalid core settings were accepted".into()),
        }
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Verify original IPv6 job identity and deadline across zero-byte VPN loss"
)]
fn vpn_retirement_preserves_queued_and_provably_unsent_ipv6_allocations() -> Result<(), Failure> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let core = gnunet_pt::core::Instance::new();
            let dns = gnunet_dns_client_host::Instance::new();
            let mut vpn = vpn::Instance::new();
            let mut cadet = super::super::cadet::Instance::new();
            let mut ports = [];
            let mut channels = [];
            let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
            let endpoint = |name| {
                gnunet_client_host::EndpointSource::unix_with_clock(
                    std::path::PathBuf::from(name),
                    clock.clone(),
                )
            };
            let mut owner = Owner::new(
                Identities {
                    core: &core,
                    dns: &dns,
                    vpn: &mut vpn,
                    cadet: &mut cadet,
                    ports: &mut ports,
                    channels: &mut channels,
                },
                Sources {
                    pre: None,
                    post: Some(endpoint("unused-pt-post-dns")),
                    vpn: Some(endpoint("unused-pt-post-vpn")),
                    cadet: None,
                    discovery: None,
                },
                clock,
                gnunet_pt::core::Limits::default(),
                gnunet_pt::packet::Families {
                    ipv4: false,
                    ipv6: true,
                },
                Limits::default(),
                vpn::AfProfile::native(),
            )?;
            let now = owner.clock.sample()?.now.as_micros();
            let bounds = Bound::after(now, std::time::Duration::from_secs(60))?;
            let stage = gnunet_pt::core::Stage::Post;
            let replies = owner.dns(stage)?.reply_limit();
            let source = owner.core.attached(stage, replies)?;
            let mut packet = vec![
                0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 28, 0, 1, 0, 0, 28, 0, 1, 0,
                0, 0, 120, 0, 16,
            ];
            let address = [0x20, 1, 0x0d, 0xb8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
            packet.extend_from_slice(&address);
            for id in [1, 2] {
                owner
                    .core
                    .admit(source, [id; 8], &packet, bounds.expires, now)?;
                let Some(gnunet_pt::core::Work::Allocate {
                    job,
                    request,
                    destination,
                    ..
                }) = owner.core.next_work(now)?
                else {
                    return Err("original POST request did not require allocation".into());
                };
                owner.allocations.push(Allocation {
                    job,
                    request,
                    destination,
                    bounds,
                    operation: None,
                });
            }
            owner.post_allocation(now)?;
            let original = owner.allocations[0]
                .operation
                .ok_or("first allocation was not submitted")?;
            let request = owner.allocations[0].request;
            let job = owner.allocations[0].job;
            let queued = owner.allocations[1].request;
            let lost = owner.vpn.as_mut().ok_or(Fault::Unavailable)?.reconnect()?;
            owner.on_vpn_retirement(lost)?;
            assert_eq!(owner.allocations.len(), 2, "loss is not a bulk completion");
            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
            assert!(matches!(owner.native_step(&mut cx)?, Some(Event::Vpn)));
            assert_eq!(owner.allocations.len(), 2);
            assert_eq!(owner.allocations[0].request, request);
            assert!(owner.allocations[0].operation.is_none());
            assert_eq!(owner.allocations[1].request, queued);
            assert!(owner.allocations[1].operation.is_none());
            assert!(matches!(owner.post_allocation(now)?, Some(Event::Admitted)));
            let replacement = &owner.allocations[0];
            assert_eq!(replacement.job, job);
            assert_eq!(replacement.request, request);
            assert_eq!(replacement.destination, Address::V6(address));
            assert_eq!(replacement.bounds.expires, bounds.expires);
            assert_eq!(replacement.bounds.hard, bounds.hard);
            let successor = replacement
                .operation
                .ok_or("replacement was not submitted")?;
            assert_ne!(successor, original);
            assert!(owner.core.next_work(now)?.is_none());
            if !owner.stop().is_empty() {
                return Err("unconnected PT allocation cleanup failed".into());
            }
            Ok(())
        })
}
