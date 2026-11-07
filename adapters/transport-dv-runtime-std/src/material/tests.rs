//! Fixed lease and actual cache-boundary regressions. These do not create
//! native services, worker receipts, provider secrets or interoperability proof.
use super::*;
use gnunet_crypto::EddsaPrivateKey;
use gnunet_transport_dv_crypto::Instance as CryptoInstance;

fn check(value: bool) -> Result<(), Protocol> {
    if value {
        Ok(())
    } else {
        Err(Protocol::Conflict)
    }
}
fn seconds(value: u64) -> std::time::Duration {
    std::time::Duration::from_secs(value)
}
fn after(now: Instant, value: u64) -> Result<Instant, Protocol> {
    now.checked_add(seconds(value)).ok_or(Protocol::Overflow)
}
fn lease(now: Instant, until: u64) -> Result<MaterialLease, Protocol> {
    MaterialLease::capture(1, now, until, until, after(now, 600)?, seconds(300))
}

#[test]
fn epoch_lease_uses_source_identity_native_and_explicit_caps() -> Result<(), Protocol> {
    let native = Instant::now();
    let natural = MaterialLease::capture(
        10,
        native,
        900_000_000,
        800_000_000,
        after(native, 600)?,
        seconds(300),
    )?;
    check(natural.until == 300_000_010 && natural.hard == after(native, 300)?)?;
    let source = MaterialLease::capture(10, native, 100, 200, after(native, 600)?, seconds(300))?;
    check(source.until == 100)?;
    let identity = MaterialLease::capture(10, native, 200, 100, after(native, 600)?, seconds(300))?;
    check(identity.until == 100)?;
    let hard = after(native, 5)?;
    let native_capped =
        MaterialLease::capture(10, native, 900_000_000, 800_000_000, hard, seconds(300))?;
    check(native_capped.hard == hard)?;
    check(native_capped.check_at(11, hard) == Err(Protocol::Deadline))?;
    check(source.check_at(100, native) == Err(Protocol::Deadline))
}

#[test]
fn nonfinite_or_already_dead_material_cannot_begin() -> Result<(), Protocol> {
    let native = Instant::now();
    let hard = after(native, 600)?;
    for lifetime in [seconds(0), std::time::Duration::from_nanos(1)] {
        check(matches!(
            MaterialLease::capture(1, native, 1000, 1000, hard, lifetime),
            Err(Protocol::InvalidInput)
        ))?;
    }
    check(matches!(
        MaterialLease::capture(u64::MAX - 1, native, u64::MAX, u64::MAX, hard, seconds(1)),
        Err(Protocol::Overflow)
    ))?;
    check(matches!(
        MaterialLease::capture(1, native, 1, 1000, hard, seconds(300)),
        Err(Protocol::Deadline)
    ))?;
    check(matches!(
        MaterialLease::capture(1, native, 1000, 1000, native, seconds(300)),
        Err(Protocol::Deadline)
    ))
}

// Deterministic entropy exists only in this actual KEM/signature/seal fixture.
struct FixtureEntropy(u8);
impl Entropy for FixtureEntropy {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), Protocol> {
        for byte in output {
            self.0 = self.0.wrapping_add(1);
            *byte = self.0;
        }
        Ok(())
    }
}

#[test]
fn cached_send_keeps_fixed_epoch_and_later_packets_keep_their_own_budget() -> Result<(), Protocol> {
    let native = Instant::now();
    let first_route = Bound {
        until: 5,
        hard: after(native, 60)?,
    };
    let later_packet = Bound {
        until: 80,
        hard: after(native, 120)?,
    };
    let fixed = lease(native, 50)?;
    check(fixed.until > first_route.until && fixed.hard > first_route.hard)?;
    let instance = CryptoInstance::new();
    let key = EddsaPrivateKey::from_seed([31; 32]);
    let local = PeerId(*key.public_key().as_bytes());
    let target = PeerId(*EddsaPrivateKey::from_seed([32; 32]).public_key().as_bytes());
    let source = instance.source(local, 0, 100)?;
    let material = source
        .task(7, 1, fixed.until)?
        .prepare_seal(target, 1, &mut FixtureEntropy(11))?
        .certify_local(&key, 2, 4)?;
    let mut slots = [cache::SendSlot::new()];
    let mut cache = SendMaterials::new(&mut slots)?;
    let id = cache.install(material, fixed, &first_route, 2)?;
    for now in [3, 4, 49] {
        check(cache.find(&source, target, now)? == Some(id))?;
        let retained = retained_lease(&cache.leases, id.id).ok_or(Protocol::NotFound)?;
        check(retained.until == fixed.until && retained.hard == fixed.hard)?;
    }
    let original = later_packet.budget();
    let mut scratch = [0; dv::PAYLOAD_PREFIX + 4];
    let mut bytes = [0; dv::BOX_PREFIX + dv::PAYLOAD_PREFIX + 4];
    cache
        .seal(
            id,
            source.task(7, 49, later_packet.until)?,
            49,
            cache::Packet {
                route: &[],
                without_fc: false,
                message: &[0, 4, 0, 0],
            },
            &mut scratch,
            &mut bytes,
        )?
        .ok_or(Protocol::NotReady)?;
    // The material-use lease ends, but immutable output remains owned by the
    // original packet budget. It is neither resealed nor reclassified unsent.
    check(cache.find(&source, target, 50)?.is_none())?;
    // A retained hint must also miss at actual seal; neither fresh output nor
    // a replacement nonce is produced for this expired epoch.
    let mut untouched = [42; dv::BOX_PREFIX + dv::PAYLOAD_PREFIX + 4];
    check(
        cache
            .seal(
                id,
                source.task(7, 50, later_packet.until)?,
                50,
                cache::Packet {
                    route: &[],
                    without_fc: false,
                    message: &[0, 4, 0, 0],
                },
                &mut scratch,
                &mut untouched,
            )?
            .is_none(),
    )?;
    check(untouched.iter().all(|byte| *byte == 42))?;
    cache.close();
    check(cache.leases.iter().all(Option::is_none))?;
    later_packet.check(50)?;
    check(later_packet.until == original.until.as_micros() && later_packet.hard == original.hard)?;
    check(dv::BoxPacket::decode(&bytes)?.encapsulation().is_ok())
}

#[test]
fn stale_receive_hit_preserves_replacement_and_original_packet() -> Result<(), Protocol> {
    let native = Instant::now();
    let packet = Bound {
        until: 80,
        hard: after(native, 60)?,
    };
    let original = packet.budget();
    let instance = CryptoInstance::new();
    let source = instance.source(PeerId([7; 32]), 0, 100)?;
    let fixed = lease(native, 50)?;
    let mut slots = [cache::ReceiveSlot::new()];
    let mut cache = ReceiveMaterials::new(&mut slots)?;
    // This explicit trusted material fixture tests cache provenance only; it
    // makes no claim of real recipient KEM or authentication.
    let old = cache.install(
        cache::ReceiveMaterial::from_shared_secret(
            source.task(0, 1, fixed.until)?,
            [1; 32],
            &[2; 32],
            1,
        )?,
        fixed,
        &packet,
        1,
    )?;
    check(cache.live(old, 2)?)?;
    let replacement = cache.install(
        cache::ReceiveMaterial::from_shared_secret(
            source.task(0, 2, fixed.until)?,
            [3; 32],
            &[4; 32],
            2,
        )?,
        fixed,
        &packet,
        2,
    )?;
    check(!cache.live(old, 3)?)?;
    check(cache.live(replacement, 3)?)?;
    check(cache.find(&source, &[3; 32], 3)? == Some(replacement))?;
    // Last-use preflight recycles the whole loan on a stale hit without AEAD
    // or revocation of the new slot. This structurally valid packet is not an
    // authentication fixture.
    let mut bytes = [0; dv::BOX_PREFIX + dv::PAYLOAD_PREFIX + 4];
    dv::BoxHeader {
        without_fc: false,
        encapsulation: [1; 32],
        nonce: [0; 24],
        mac: [0; 16],
    }
    .encode(&[], &[0; dv::PAYLOAD_PREFIX + 4], &mut bytes)?;
    let request = source
        .task(0, 3, packet.until)?
        .prepare_open(dv::BoxPacket::decode(&bytes)?, 3)?;
    let mut scratch = [42; dv::PAYLOAD_PREFIX + 4];
    let mut loan = [42; 32];
    let buffer = match cache.open(old, request, 3, &mut scratch, &mut loan) {
        ReceiveUse::Miss(buffer) => buffer,
        ReceiveUse::Opened(opened) => {
            drop(opened);
            return Err(Protocol::Conflict);
        }
        ReceiveUse::Failed { .. } => return Err(Protocol::Conflict),
    };
    check(buffer.len() == 32 && buffer.iter().all(|byte| *byte == 0))?;
    check(scratch.iter().all(|byte| *byte == 0))?;
    check(cache.live(replacement, 3)?)?;
    cache.close();
    check(cache.leases.iter().all(Option::is_none) && cache.find(&source, &[3; 32], 3)?.is_none())?;
    packet.check(3)?;
    check(packet.until == original.until.as_micros() && packet.hard == original.hard)
}

#[test]
fn native_expired_receive_epoch_is_real_miss_then_reacquired_in_same_budget() -> Result<(), Protocol>
{
    let native = Instant::now();
    let packet = Bound {
        until: 80,
        hard: after(native, 60)?,
    };
    let original = packet.budget();
    let instance = CryptoInstance::new();
    let source = instance.source(PeerId([8; 32]), 0, 100)?;
    let mut slots = [cache::ReceiveSlot::new()];
    let mut cache = ReceiveMaterials::new(&mut slots)?;
    let fixed = lease(native, 50)?;
    let old = cache.install(
        cache::ReceiveMaterial::from_shared_secret(
            source.task(0, 1, fixed.until)?,
            [5; 32],
            &[6; 32],
            1,
        )?,
        fixed,
        &packet,
        1,
    )?;
    // Advance the observed native instant directly at the production guard;
    // no sleep, mutation of cache metadata or replacement of packet budgets.
    check(!cache.live_at(old, 2, fixed.hard)?)?;
    check(cache.find(&source, &[5; 32], 2)?.is_none())?;
    // Real miss obtains a new material token under the same original Source;
    // it never reassigns or renews the still-live packet operation.
    let fresh = lease(native, 70)?;
    let reacquired = cache.install(
        cache::ReceiveMaterial::from_shared_secret(
            source.task(0, 2, fresh.until)?,
            [5; 32],
            &[6; 32],
            2,
        )?,
        fresh,
        &packet,
        2,
    )?;
    check(reacquired != old && cache.live(reacquired, 2)?)?;
    check(!cache.live(old, 2)?)?;
    packet.check(2)?;
    check(packet.until == original.until.as_micros() && packet.hard == original.hard)
}

#[test]
fn installation_requires_original_packet_and_independent_material_both_live() -> Result<(), Protocol>
{
    let native = Instant::now();
    let fixed = lease(native, 90)?;
    let packet = Bound {
        until: 10,
        hard: after(native, 60)?,
    };
    check_install(&packet, fixed, 9)?;
    check(check_install(&packet, fixed, 10) == Err(Protocol::Deadline))?;
    let native_expired = Bound {
        until: 80,
        hard: native.checked_sub(seconds(1)).ok_or(Protocol::Overflow)?,
    };
    check(check_install(&native_expired, fixed, 2) == Err(Protocol::Deadline))?;
    let later_packet = Bound {
        until: 95,
        hard: after(native, 60)?,
    };
    check(check_install(&later_packet, fixed, 90) == Err(Protocol::Deadline))?;
    let expired_material = MaterialLease {
        until: 90,
        hard: native_expired.hard,
    };
    check(check_install(&later_packet, expired_material, 2) == Err(Protocol::Deadline))?;
    let instance = CryptoInstance::new();
    let source = instance.source(PeerId([9; 32]), 0, 100)?;
    let mut slots = [cache::ReceiveSlot::new()];
    let mut cache = ReceiveMaterials::new(&mut slots)?;
    let live = cache.install(
        cache::ReceiveMaterial::from_shared_secret(
            source.task(0, 1, fixed.until)?,
            [7; 32],
            &[8; 32],
            1,
        )?,
        fixed,
        &later_packet,
        1,
    )?;
    let next = cache.next;
    let late = cache::ReceiveMaterial::from_shared_secret(
        source.task(0, 2, fixed.until)?,
        [9; 32],
        &[10; 32],
        2,
    )?;
    check(cache.install(late, fixed, &packet, 10) == Err(Protocol::Deadline))?;
    check(cache.next == next && cache.live(live, 10)?)
}
