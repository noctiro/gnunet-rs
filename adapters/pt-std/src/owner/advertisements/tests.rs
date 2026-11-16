//! Modeled clock observations and signed advertisements, without native I/O.
use super::*;
use crate::{Identities, Limits, Sources};
use gnunet_crypto::EddsaPrivateKey;
use gnunet_pt::{core, exit, packet::Families};
use gnunet_service_runtime::{
    clock::{RuntimeClock, SystemClock},
    framing::OwnedFrame,
};
use std::{
    sync::Arc,
    task::{Context, Poll},
};

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

fn advertisement<'a>(
    original: core::Discovery<'a>,
    seed: u8,
    expires: u64,
    now: u64,
) -> Result<discovery::Event<'a>, Failure> {
    let key = EddsaPrivateKey::from_seed([seed; 32]);
    let peer = *key.public_key().as_bytes();
    let region = exit::Advertisement::signed_region(peer, expires);
    let signature = key.sign(exit::PURPOSE, &region)?;
    let block = exit::Advertisement::encode_signed(peer, expires, signature.as_bytes(), now)?;
    Ok(discovery::Event::Result {
        original,
        query: exit::discovery_key(),
        block_type: exit::BLOCK_TYPE,
        block: OwnedFrame::new(block.to_vec()),
    })
}

fn lease(peer: u8, expires: u64, hard: Instant) -> Lease {
    Lease {
        peer: [peer; 32],
        expires,
        hard,
    }
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Native expiry must fence the whole expired timestamp range before quota reuse"
)]
fn native_expiry_reclaims_slots_without_per_peer_history() -> Result<(), Fault> {
    let native = Instant::now();
    let first = native + Duration::from_millis(10);
    let later = native + Duration::from_millis(20);
    let mut leases = Leases::new(2)?;
    leases.insert(lease(1, 200, first))?;
    leases.insert(lease(2, 180, later))?;
    let mut withdrawn = Vec::new();
    assert!(
        !leases.expire_native(first - Duration::from_nanos(1), |peer| {
            withdrawn.push(peer);
            Ok(())
        })?
    );
    assert!(withdrawn.is_empty());
    assert!(leases.expire_native(first, |peer| {
        withdrawn.push(peer);
        Ok(())
    })?);
    withdrawn.sort_unstable();
    assert_eq!(
        withdrawn,
        [[1; 32], [2; 32]],
        "a native expiry fences all equal/earlier signed expirations, even with later per-peer hard bounds"
    );
    assert_eq!(leases.iter().count(), 0);
    assert_eq!(leases.admission([1; 32], 200), Err(Fault::Deadline));
    assert_eq!(
        leases.admission([3; 32], 200),
        Err(Fault::Deadline),
        "changing identity cannot revive an expired timestamp"
    );
    assert!(!leases.expire_canonical(50, |_| Err(Fault::Conflict))?);
    leases.insert(lease(3, 201, later))?;
    assert_eq!(leases.iter().count(), 1);
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "A duplicate signed expiration keeps its original hard target; only a strictly later expiration can replace it"
)]
fn duplicates_do_not_renew_bounds_and_newer_signatures_can_renew() -> Result<(), Fault> {
    let native = Instant::now();
    let first = native + Duration::from_millis(10);
    let renewed = native + Duration::from_millis(20);
    let later = native + Duration::from_millis(30);
    let mut leases = Leases::new(1)?;
    leases.insert(lease(1, 200, first))?;
    assert_eq!(leases.insert(lease(2, 201, later)), Err(Fault::Capacity));
    leases.insert(lease(1, 200, later))?;
    leases.insert(lease(1, 190, later))?;
    assert_eq!(leases.iter().next().ok_or(Fault::NotReady)?.hard, first);
    leases.insert(lease(1, 210, renewed))?;
    assert_eq!(leases.iter().next().ok_or(Fault::NotReady)?.hard, renewed);
    assert!(!leases.expire_canonical(205, |_| Err(Fault::Conflict))?);
    assert!(!leases.expire_canonical(100, |_| Err(Fault::Conflict))?);
    assert!(!leases.expire_native(first, |_| Err(Fault::Conflict))?);
    let mut withdrawn = Vec::new();
    assert!(leases.expire_native(renewed, |peer| {
        withdrawn.push(peer);
        Ok(())
    })?);
    assert_eq!(withdrawn, [[1; 32]]);
    assert_eq!(leases.insert(lease(1, 210, later)), Err(Fault::Deadline));
    leases.insert(lease(2, 211, later))?;
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Failed authority withdrawal must retain its original candidate slot and expiration fence"
)]
fn withdrawal_failure_keeps_the_original_slot_owned() -> Result<(), Fault> {
    let hard = Instant::now();
    let mut leases = Leases::new(1)?;
    leases.insert(lease(1, 200, hard))?;
    assert_eq!(
        leases.expire_native(hard, |_| Err(Fault::Io)),
        Err(Fault::Io)
    );
    assert_eq!(leases.iter().count(), 1);
    assert_eq!(leases.admission([2; 32], 201), Err(Fault::Capacity));
    assert_eq!(leases.admission([1; 32], 200), Err(Fault::Deadline));
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Unrelated clock observations must not fabricate history for advertisements never admitted"
)]
fn a_clock_jump_fences_only_expirations_of_admitted_leases() -> Result<(), Fault> {
    let hard = Instant::now() + Duration::from_secs(1);
    let mut leases = Leases::new(1)?;
    assert!(!leases.expire_canonical(10_000, |_| Err(Fault::Conflict))?);
    assert_eq!(
        leases.admission([1; 32], 200),
        Ok(()),
        "an empty table has no admitted lease to expire when the clock jumps"
    );
    leases.insert(lease(1, 200, hard))?;
    assert!(leases.expire_canonical(10_000, |_| Ok(()))?);
    assert!(!leases.expire_canonical(100, |_| Err(Fault::Conflict))?);
    assert_eq!(leases.admission([1; 32], 200), Err(Fault::Deadline));
    leases.insert(lease(2, 201, hard))?;
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Expired candidates must release a finite slot without admitting old signed expirations after rollback"
)]
fn expired_peer_churn_reuses_one_slot_without_reviving_old_advertisements() -> Result<(), Failure> {
    let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
    let now = clock.sample()?.now.as_micros();
    let core = core::Instance::new();
    let dns = gnunet_dns_client_host::Instance::new();
    let mut vpn = gnunet_vpn_client_host::Instance::new();
    let mut cadet = gnunet_cadet_host::Instance::new();
    let mut ports = [];
    let mut channels = [gnunet_cadet_host::ChannelSlot::new()];
    let mut discovery = Discovery {
        clock: clock.clone(),
        original: None,
    };
    let endpoint = |path| {
        gnunet_client_host::EndpointSource::unix_with_clock(
            std::path::PathBuf::from(path),
            clock.clone(),
        )
    };
    let native = Limits {
        discovery_timeout: Duration::from_secs(3600),
        ..Limits::default()
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
            pre: Some(endpoint("unused-lease-dns")),
            post: None,
            vpn: None,
            cadet: Some(endpoint("unused-lease-cadet")),
            discovery: Some(&mut discovery),
        },
        clock.clone(),
        core::Limits {
            exits: 1,
            tunnels: 1,
            ..core::Limits::default()
        },
        Families {
            ipv4: false,
            ipv6: false,
        },
        native,
        gnunet_vpn_client_host::AfProfile::native(),
    )?;
    assert!(matches!(owner.providers(now)?, Some(Event::Admitted)));
    let original = owner.discovery.ok_or(Fault::NotReady)?.0;
    let mut prior = None;
    for seed in 1..=16_u8 {
        let expires = now
            .checked_add(u64::from(seed) * 3_000_000)
            .ok_or(Fault::Overflow)?;
        if let Some((old_seed, old_expiry)) = prior {
            // The trusted source has observed this future time, then rolled back
            // to `now`; only the signed, strictly later expiration is fresh.
            owner.maintain(old_expiry)?;
            assert!(matches!(
                owner.on_discovery(advertisement(original, old_seed, old_expiry, now)?, now)?,
                Event::Activity
            ));
        }
        assert!(
            matches!(
                owner.on_discovery(advertisement(original, seed, expires, now)?, now)?,
                Event::Advertisement
            ),
            "candidate {seed} could not use the released slot"
        );
        assert_eq!(owner.leases.iter().count(), 1);
        prior = Some((seed, expires));
    }
    assert!(owner.stop().is_empty());
    Ok(())
}
