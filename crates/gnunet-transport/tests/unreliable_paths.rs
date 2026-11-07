//! Official unreliable communicator operations; no C or UDP execution claims.
#![cfg(feature = "alloc")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Public wire/owner assertions accompany fallible setup"
)]
use gnunet_crypto::{EddsaPrivateKey, Entropy};
use gnunet_transport::{
    Engine, Limits, Output, PeerId, Signer,
    p2p::{Challenge, Validation},
};
use gnunet_types::Error;

#[path = "support/monotime.rs"]
mod monotime;

struct Key(EddsaPrivateKey);
impl Signer for Key {
    fn identity(&self) -> PeerId {
        PeerId(*self.0.public_key().as_bytes())
    }
    fn sign_validation(&mut self, b: &[u8; 48]) -> Result<[u8; 64], Error> {
        Ok(*self.0.sign(35, b)?.as_bytes())
    }
}
struct Random(u64);
impl Entropy for Random {
    fn fill(&mut self, b: &mut [u8]) -> Result<(), Error> {
        self.0 = self.0.wrapping_add(1);
        for (i, v) in b.iter_mut().enumerate() {
            *v = self.0.to_be_bytes()[i % 8];
        }
        Ok(())
    }
}
fn frame(kind: u16, size: usize) -> Vec<u8> {
    let mut b = vec![0; size];
    b[..2].copy_from_slice(&(size as u16).to_be_bytes());
    b[2..4].copy_from_slice(&kind.to_be_bytes());
    b
}
fn kind(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[2], b[3]])
}
fn incoming(peer: PeerId, body: &[u8], token: u64) -> Vec<u8> {
    let mut b = frame(1202, 88 + body.len());
    b[4..8].copy_from_slice(&1u32.to_be_bytes());
    b[8..16].copy_from_slice(&token.to_ne_bytes());
    b[16..24].copy_from_slice(&10_000_000_000u64.to_be_bytes());
    b[24..56].copy_from_slice(&peer.0);
    b[88..].copy_from_slice(body);
    b
}
struct Harness {
    engine: Engine,
    comm: gnunet_transport::ClientId,
    core: gnunet_transport::ClientId,
    key: Key,
    remote: Key,
    random: Random,
    now: u64,
    auto_local: bool,
}
impl Harness {
    fn new(mtu: u32, characteristics: u32) -> Result<Self, Error> {
        Self::policy(mtu, characteristics, Limits::default(), u64::MAX)
    }
    fn policy(mtu: u32, characteristics: u32, limits: Limits, grant: u64) -> Result<Self, Error> {
        Self::seeded(mtu, characteristics, limits, grant, 3, 5)
    }
    fn seeded(
        mtu: u32,
        characteristics: u32,
        limits: Limits,
        grant: u64,
        local_seed: u8,
        remote_seed: u8,
    ) -> Result<Self, Error> {
        let key = Key(EddsaPrivateKey::from_seed([local_seed; 32]));
        let remote = Key(EddsaPrivateKey::from_seed([remote_seed; 32]));
        let mut engine = Engine::new(key.identity(), limits)?;
        let comm = engine.accept()?;
        let core = engine.accept()?;
        let mut h = Self {
            engine,
            comm,
            core,
            key,
            remote,
            random: Random(0),
            now: 100,
            auto_local: true,
        };
        let mut register = frame(1211, 16);
        register[4..8].copy_from_slice(&characteristics.to_be_bytes());
        register[12..].copy_from_slice(b"udp\0");
        h.receive(false, &register)?;
        let mut start = [0; 40];
        gnunet_client::transport::Request::Start(gnunet_client::transport::Start::new(None, true))
            .encode(&mut start)?;
        h.receive(true, &start)?;
        let mut q = frame(1204, 74);
        q[4..8].copy_from_slice(&3u32.to_be_bytes());
        q[8..40].copy_from_slice(&h.remote.identity().0);
        q[44..48].copy_from_slice(&mtu.to_be_bytes());
        q[48..56].copy_from_slice(&grant.to_be_bytes());
        q[64..].copy_from_slice(b"udp-local\0");
        h.receive(false, &q)?;
        let events = h.drain()?;
        let c = events
            .iter()
            .find(|b| kind(b) == 1209 && kind(&b[48..]) == 1303)
            .ok_or(Error::NotFound)?;
        let c = Challenge::decode(&c[48..])?;
        let validity = 10_000_000_000;
        let response = Validation {
            nonce: c.nonce,
            origin: c.origin,
            validity,
            signature: h
                .remote
                .sign_validation(&Validation::signed_region(&c.nonce, validity))?,
        };
        h.wire(&response.encode())?;
        h.drain()?;
        Ok(h)
    }
    fn receive(&mut self, core: bool, b: &[u8]) -> Result<(), Error> {
        self.now += 1;
        self.engine.receive(
            if core { &self.core } else { &self.comm },
            b,
            self.now,
            &mut self.key,
            &mut self.random,
        )?;
        Ok(())
    }
    fn wire(&mut self, b: &[u8]) -> Result<(), Error> {
        self.receive(false, &incoming(self.remote.identity(), b, self.now))
    }
    fn drain(&mut self) -> Result<Vec<Vec<u8>>, Error> {
        let mut out = Vec::new();
        for _ in 0..8192 {
            let Some(effect) = self.engine.output() else {
                return Ok(out);
            };
            if let Output::Frame { bytes, .. } = effect {
                if self.auto_local && kind(&bytes) == 1209 {
                    let mut ack = frame(1210, 52);
                    ack[4..8].copy_from_slice(&1u32.to_be_bytes());
                    ack[8..16].copy_from_slice(&bytes[8..16]);
                    ack[16..20].copy_from_slice(&bytes[4..8]);
                    ack[20..].copy_from_slice(&bytes[16..48]);
                    self.receive(false, &ack)?;
                }
                out.push(bytes);
            }
        }
        Err(Error::Capacity)
    }
}
#[test]
fn official_unreliable_characteristic_two_validates_and_keeps_the_original_owner()
-> Result<(), Error> {
    let h = Harness::new(256, 2)?;
    assert_eq!(h.engine.snapshot().connected, 1);
    assert_eq!(h.engine.snapshot().queues, 1);
    assert_eq!(h.engine.snapshot().clients, 2);
    Ok(())
}
#[test]
fn official_reliability_box_dispatches_inner_payload_and_acks_its_exact_uuid() -> Result<(), Error>
{
    let mut h = Harness::new(256, 1)?;
    let body = frame(0, 8);
    let mut boxed = frame(1216, 24 + body.len());
    boxed[8..24].fill(0x33);
    boxed[24..].copy_from_slice(&body);
    h.wire(&boxed)?;
    let effects = h.drain()?;
    assert_eq!(
        effects
            .iter()
            .filter(|b| kind(b) == 365 && b[36..] == body)
            .count(),
        1
    );
    let ack = effects
        .iter()
        .find(|b| kind(b) == 1209 && kind(&b[48..]) == 1217)
        .ok_or(Error::NotFound)?;
    assert_eq!(
        gnunet_transport::p2p::acknowledgements(&ack[48..])?.collect::<Vec<_>>(),
        vec![(0, [0x33; 16])]
    );
    Ok(())
}

impl Harness {
    fn send(&mut self, body: &[u8], preferences: u32) -> Result<Vec<Vec<u8>>, Error> {
        let mut b = vec![0; 40 + body.len()];
        gnunet_client::transport::Request::Send {
            peer: self.remote.identity(),
            priority: preferences,
            message: body,
        }
        .encode(&mut b)?;
        self.receive(true, &b)?;
        self.drain()
    }
    fn after(&mut self, delta: u64) -> Result<Vec<Vec<u8>>, Error> {
        self.now += delta;
        self.engine.tick(self.now, &mut self.random)?;
        self.drain()
    }
    fn flow_after(&mut self, delta: u64) -> Result<Vec<Vec<u8>>, Error> {
        self.now += delta;
        monotime::tick_with_monotime_provider(&mut self.engine, self.now, &mut self.random)?;
        self.drain()
    }
    fn remote_ack(&mut self, ids: &[[u8; 16]]) -> Result<Vec<Vec<u8>>, Error> {
        let entries: Vec<_> = ids.iter().map(|id| (0, *id)).collect();
        let mut b = vec![0; 8 + 24 * entries.len()];
        gnunet_transport::p2p::encode_acknowledgements(7, &entries, &mut b)?;
        self.wire(&b)?;
        self.drain()
    }
}
fn network_kind(b: &[u8], expected: u16) -> bool {
    kind(b) == 1209 && kind(&b[48..]) == expected
}
#[test]
fn reliability_retry_uses_original_uuid_and_one_credit_until_remote_ack() -> Result<(), Error> {
    let mut h = Harness::new(256, 2)?;
    let body = frame(0, 32);
    let first = h.send(&body, 0)?;
    let packet = first
        .iter()
        .find(|b| network_kind(b, 1216))
        .ok_or(Error::NotFound)?;
    let original = gnunet_transport::p2p::Reliable::decode(&packet[48..])?;
    assert_eq!(original.message, body);
    assert_eq!(first.iter().filter(|b| kind(b) == 364).count(), 1);
    assert_eq!(h.engine.snapshot().pending_remote_acks, 1);
    assert_eq!(h.engine.snapshot().pending, 1);
    assert!(!h.after(39_000)?.iter().any(|b| network_kind(b, 1216)));
    let retry = h.after(2_000)?;
    let packet = retry
        .iter()
        .find(|b| network_kind(b, 1216))
        .ok_or(Error::NotFound)?;
    let retried = gnunet_transport::p2p::Reliable::decode(&packet[48..])?;
    assert_eq!(retried.uuid, original.uuid);
    assert_eq!(retried.message, body);
    assert_eq!(retry.iter().filter(|b| kind(b) == 364).count(), 0);
    assert_eq!(h.engine.snapshot().retransmissions, 1);
    h.remote_ack(&[[0x77; 16]])?;
    assert_eq!(h.engine.snapshot().pending_remote_acks, 1);
    h.remote_ack(&[original.uuid])?;
    assert_eq!(h.engine.snapshot().pending_remote_acks, 0);
    assert_eq!(h.engine.snapshot().pending, 0);
    h.remote_ack(&[original.uuid])?;
    assert!(!h.after(10_000_000)?.iter().any(|b| network_kind(b, 1216)));
    Ok(())
}
#[test]
fn fragment_retry_keeps_original_message_id_and_consumes_out_of_order_and_old_attempt_acks()
-> Result<(), Error> {
    let mut h = Harness::new(256, 2)?;
    let body = frame(0, 512);
    let first = h.send(&body, 0)?;
    let packets: Vec<_> = first.iter().filter(|b| network_kind(b, 1214)).collect();
    assert_eq!(packets.len(), 3);
    assert_eq!(first.iter().filter(|b| kind(b) == 364).count(), 1);
    let parts: Vec<_> = packets
        .iter()
        .map(|b| gnunet_transport::p2p::Fragment::decode(&b[48..]))
        .collect::<Result<_, _>>()?;
    assert!(parts.iter().all(|p| p.message_id == parts[0].message_id));
    h.remote_ack(&[parts[2].ack, parts[1].ack, parts[1].ack])?;
    assert_eq!(h.engine.snapshot().pending_remote_acks, 1);
    let retry = h.after(41_000)?;
    let packets: Vec<_> = retry.iter().filter(|b| network_kind(b, 1214)).collect();
    assert_eq!(packets.len(), 1);
    let p = gnunet_transport::p2p::Fragment::decode(&packets[0][48..])?;
    assert_eq!(p.offset, 0);
    assert_eq!(p.body, parts[0].body);
    assert_eq!(p.message_id, parts[0].message_id);
    assert_ne!(p.ack, parts[0].ack);
    assert!(!retry.iter().any(|b| kind(b) == 364));
    h.remote_ack(&[parts[0].ack])?;
    assert_eq!(h.engine.snapshot().pending_remote_acks, 0);
    assert_eq!(h.engine.snapshot().pending, 0);
    h.remote_ack(&[p.ack])?;
    assert_eq!(h.engine.snapshot().pending, 0);
    Ok(())
}
#[test]
fn remote_ack_before_local_callback_keeps_original_mid_debt_and_cannot_finish_a_later_job()
-> Result<(), Error> {
    let mut h = Harness::new(256, 2)?;
    h.auto_local = false;
    let first = h.send(&frame(0, 8), 0)?;
    let first = first
        .iter()
        .find(|b| network_kind(b, 1216))
        .ok_or(Error::NotFound)?;
    let uuid = gnunet_transport::p2p::Reliable::decode(&first[48..])?.uuid;
    h.remote_ack(&[uuid])?;
    assert_eq!(h.engine.snapshot().pending, 0);
    assert_eq!(h.engine.snapshot().attempts, 1);
    let later = h.send(&frame(0, 16), 0)?;
    let later = later
        .iter()
        .find(|b| network_kind(b, 1216))
        .ok_or(Error::NotFound)?;
    let later_uuid = gnunet_transport::p2p::Reliable::decode(&later[48..])?.uuid;
    assert_ne!(later_uuid, uuid);
    let mut local = frame(1210, 52);
    local[4..8].copy_from_slice(&1u32.to_be_bytes());
    local[8..16].copy_from_slice(&first[8..16]);
    local[16..20].copy_from_slice(&first[4..8]);
    local[20..].copy_from_slice(&first[16..48]);
    h.receive(false, &local)?;
    h.drain()?;
    h.remote_ack(&[uuid])?;
    assert_eq!(h.engine.snapshot().attempts, 1);
    assert_eq!(h.engine.snapshot().pending_remote_acks, 1);
    h.remote_ack(&[later_uuid])?;
    assert_eq!(h.engine.snapshot().pending, 0);
    assert_eq!(h.engine.snapshot().attempts, 1);
    Ok(())
}
#[test]
fn best_effort_preference_and_later_heartbeat_do_not_wait_for_an_unrelated_remote_ack()
-> Result<(), Error> {
    let mut h = Harness::new(256, 0)?;
    let first = h.send(&frame(0, 512), 0)?;
    assert_eq!(first.iter().filter(|b| network_kind(b, 1214)).count(), 3);
    assert_eq!(h.engine.snapshot().pending_remote_acks, 3);
    let heartbeat = h.send(&frame(84, 8), 0)?;
    assert_eq!(
        heartbeat.iter().filter(|b| network_kind(b, 1216)).count(),
        1
    );
    assert_eq!(heartbeat.iter().filter(|b| kind(b) == 364).count(), 1);
    let best = h.send(&frame(0, 8), 16)?;
    assert_eq!(best.iter().filter(|b| network_kind(b, 0)).count(), 1);
    assert!(!best.iter().any(|b| network_kind(b, 1216)));
    assert_eq!(h.engine.snapshot().pending_remote_acks, 4);
    Ok(())
}

impl Harness {
    fn update(&mut self, mtu: u32, grant: u64) -> Result<Vec<Vec<u8>>, Error> {
        let mut b = frame(1222, 64);
        b[4..8].copy_from_slice(&3u32.to_be_bytes());
        b[8..40].copy_from_slice(&self.remote.identity().0);
        b[44..48].copy_from_slice(&mtu.to_be_bytes());
        b[48..56].copy_from_slice(&grant.to_be_bytes());
        self.receive(false, &b)?;
        self.drain()
    }
    fn sent(&mut self, packet: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        let mut b = frame(1210, 52);
        b[4..8].copy_from_slice(&1u32.to_be_bytes());
        b[8..16].copy_from_slice(&packet[8..16]);
        b[16..20].copy_from_slice(&packet[4..8]);
        b[20..].copy_from_slice(&packet[16..48]);
        self.receive(false, &b)?;
        self.drain()
    }
}
#[test]
fn cached_box_can_change_to_flat_fragments_on_mtu_shrink_and_old_whole_ack_remains_authoritative()
-> Result<(), Error> {
    let mut h = Harness::new(1024, 2)?;
    let body = frame(0, 512);
    let first = h.send(&body, 0)?;
    let boxed = first
        .iter()
        .find(|b| network_kind(b, 1216))
        .ok_or(Error::NotFound)?;
    let uuid = gnunet_transport::p2p::Reliable::decode(&boxed[48..])?.uuid;
    h.update(128, u64::MAX)?;
    let retry = h.after(41_000)?;
    let first = retry
        .iter()
        .find(|b| network_kind(b, 1214))
        .ok_or(Error::NotFound)?;
    let f = gnunet_transport::p2p::Fragment::decode(&first[48..])?;
    assert_eq!(f.offset, 0);
    assert_eq!(f.body, &body[..96]);
    let next = h.remote_ack(&[f.ack])?;
    let next = next
        .iter()
        .find(|b| network_kind(b, 1214))
        .ok_or(Error::NotFound)?;
    let second = gnunet_transport::p2p::Fragment::decode(&next[48..])?;
    assert_eq!(second.offset, 96);
    assert_eq!(second.message_id, f.message_id);
    h.update(1024, u64::MAX)?;
    let next = h.remote_ack(&[second.ack])?;
    let next = next
        .iter()
        .find(|b| network_kind(b, 1214))
        .ok_or(Error::NotFound)?;
    let last = gnunet_transport::p2p::Fragment::decode(&next[48..])?;
    assert_eq!(last.offset, 192);
    assert_eq!(last.message_id, f.message_id);
    assert_eq!(last.body, &body[192..]);
    let done = h.remote_ack(&[uuid])?;
    assert_eq!(h.engine.snapshot().pending_remote_acks, 0);
    assert_eq!(h.engine.snapshot().pending, 0);
    assert!(!done.iter().any(|b| kind(b) == 364));
    Ok(())
}
#[test]
fn local_timeout_retires_only_original_attempt_and_retry_still_requires_new_finite_grant()
-> Result<(), Error> {
    let mut h = Harness::policy(256, 2, Limits::default(), 2)?;
    h.auto_local = false;
    let first = h.send(&frame(0, 16), 0)?;
    let original = first
        .iter()
        .find(|b| network_kind(b, 1216))
        .ok_or(Error::NotFound)?;
    assert!(!h.after(41_000)?.iter().any(|b| network_kind(b, 1216)));
    assert_eq!(h.engine.snapshot().attempts, 1);
    assert!(!h.after(5_000_001)?.iter().any(|b| network_kind(b, 1216)));
    assert_eq!(h.engine.snapshot().attempts, 0);
    assert_eq!(h.engine.snapshot().pending_remote_acks, 1);
    assert_eq!(h.engine.snapshot().expired_attempts, 1);
    let resumed = h.update(256, 1)?;
    assert_eq!(resumed.iter().filter(|b| network_kind(b, 1216)).count(), 1);
    assert_eq!(h.engine.snapshot().attempts, 1);
    assert!(!resumed.iter().any(|b| kind(b) == 364));
    assert!(!h.sent(original)?.iter().any(|b| network_kind(b, 1216)));
    assert_eq!(h.engine.snapshot().attempts, 1);
    assert_eq!(h.engine.snapshot().pending_remote_acks, 1);
    Ok(())
}
#[test]
fn old_core_owner_cancel_and_retention_expiry_never_confirm_or_credit_its_replacement()
-> Result<(), Error> {
    let mut h = Harness::new(256, 2)?;
    let first = h.send(&frame(0, 16), 0)?;
    let old = first
        .iter()
        .find(|b| network_kind(b, 1216))
        .ok_or(Error::NotFound)?;
    let old = gnunet_transport::p2p::Reliable::decode(&old[48..])?.uuid;
    h.engine.close(&h.core)?;
    assert_eq!(h.engine.snapshot().pending_remote_acks, 0);
    assert_eq!(h.engine.snapshot().pending, 0);
    h.core = h.engine.accept()?;
    let mut start = [0; 40];
    gnunet_client::transport::Request::Start(gnunet_client::transport::Start::new(None, true))
        .encode(&mut start)?;
    h.receive(true, &start)?;
    h.drain()?;
    let replacement = h.send(&frame(0, 32), 0)?;
    let fresh = replacement
        .iter()
        .find(|b| network_kind(b, 1216))
        .ok_or(Error::NotFound)?;
    let fresh = gnunet_transport::p2p::Reliable::decode(&fresh[48..])?.uuid;
    assert_ne!(fresh, old);
    h.remote_ack(&[old])?;
    assert_eq!(h.engine.snapshot().pending_remote_acks, 1);
    let expired = h.after(4 * 60 * 1_000_000 + 1)?;
    assert_eq!(h.engine.snapshot().pending_remote_acks, 0);
    assert_eq!(h.engine.snapshot().expired_messages, 1);
    assert!(!expired.iter().any(|b| kind(b) == 364));
    h.remote_ack(&[fresh])?;
    assert_eq!(h.engine.snapshot().pending, 0);
    Ok(())
}
#[test]
fn bounded_remote_records_stop_new_fragments_until_exact_acked_coverage_releases_one_slot()
-> Result<(), Error> {
    let mut h = Harness::policy(
        256,
        2,
        Limits {
            messages: 8,
            ..Limits::default()
        },
        u64::MAX,
    )?;
    h.update(33, u64::MAX)?;
    let first = h.send(&frame(0, 40), 0)?;
    let packets: Vec<_> = first.iter().filter(|b| network_kind(b, 1214)).collect();
    assert_eq!(packets.len(), 2);
    assert_eq!(h.engine.snapshot().pending_remote_acks, 2);
    let first = gnunet_transport::p2p::Fragment::decode(&packets[0][48..])?;
    let next = h.remote_ack(&[first.ack])?;
    let pieces: Vec<_> = next.iter().filter(|b| network_kind(b, 1214)).collect();
    assert_eq!(pieces.len(), 1);
    let f = gnunet_transport::p2p::Fragment::decode(&pieces[0][48..])?;
    assert_eq!(f.offset, 2);
    assert_eq!(f.message_id, first.message_id);
    assert_eq!(h.engine.snapshot().pending_remote_acks, 2);
    assert!(!next.iter().any(|b| kind(b) == 364));
    Ok(())
}
#[test]
fn wrong_peer_ack_cannot_settle_a_known_uuid_but_same_peer_on_a_replacement_communicator_can()
-> Result<(), Error> {
    let mut h = Harness::new(256, 2)?;
    let first = h.send(&frame(0, 32), 0)?;
    let first = first
        .iter()
        .find(|b| network_kind(b, 1216))
        .ok_or(Error::NotFound)?;
    let uuid = gnunet_transport::p2p::Reliable::decode(&first[48..])?.uuid;
    let other = Key(EddsaPrivateKey::from_seed([17; 32]));
    let mut q = frame(1204, 74);
    q[4..8].copy_from_slice(&3u32.to_be_bytes());
    q[8..40].copy_from_slice(&other.identity().0);
    q[44..48].copy_from_slice(&256u32.to_be_bytes());
    q[48..56].copy_from_slice(&u64::MAX.to_be_bytes());
    q[64..].copy_from_slice(b"udp-local\0");
    h.receive(false, &q)?;
    h.drain()?;
    let mut ack = vec![0; 32];
    gnunet_transport::p2p::encode_acknowledgements(0, &[(0, uuid)], &mut ack)?;
    h.receive(false, &incoming(other.identity(), &ack, 5))?;
    h.drain()?;
    assert_eq!(h.engine.snapshot().pending_remote_acks, 1);
    let original = h.comm.clone();
    h.comm = h.engine.accept()?;
    let mut register = frame(1211, 16);
    register[4..8].copy_from_slice(&2u32.to_be_bytes());
    register[12..].copy_from_slice(b"udp\0");
    h.receive(false, &register)?;
    q[4..8].copy_from_slice(&9u32.to_be_bytes());
    q[8..40].copy_from_slice(&h.remote.identity().0);
    h.receive(false, &q)?;
    h.drain()?;
    h.engine.close(&original)?;
    h.drain()?;
    assert_eq!(h.engine.snapshot().connected, 1);
    assert_eq!(h.engine.snapshot().pending_remote_acks, 1);
    h.remote_ack(&[uuid])?;
    assert_eq!(h.engine.snapshot().pending_remote_acks, 0);
    assert_eq!(h.engine.snapshot().pending, 0);
    Ok(())
}

#[test]
fn one_blackholed_original_keeps_retries_without_blocking_explicit_unordered_or_other_peer()
-> Result<(), Error> {
    let mut h = Harness::policy(
        256,
        2,
        Limits {
            messages: 8,
            ..Limits::default()
        },
        u64::MAX,
    )?;
    h.update(33, u64::MAX)?;
    let large = h.send(&frame(0, 40), 0)?;
    assert_eq!(large.iter().filter(|b| network_kind(b, 1214)).count(), 2);
    let prefix = large
        .iter()
        .filter(|b| network_kind(b, 1214))
        .map(|b| gnunet_transport::p2p::Fragment::decode(&b[48..]))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        prefix
            .iter()
            .map(|f| (f.offset, f.body.len()))
            .collect::<Vec<_>>(),
        vec![(0, 1), (1, 1)]
    );
    assert!(prefix.iter().all(|f| f.total == 40));
    // The blackholed original still has38 unsent bytes. This heartbeat
    // deliberately permits out-of-order delivery (official preference256),
    // rather than claiming a default-ordered stream may skip its first pass.
    let heartbeat = h.send(&frame(84, 8), 256)?;
    assert_eq!(
        heartbeat.iter().filter(|b| network_kind(b, 1216)).count(),
        1
    );
    let other = Key(EddsaPrivateKey::from_seed([19; 32]));
    let mut q = frame(1204, 74);
    q[4..8].copy_from_slice(&44u32.to_be_bytes());
    q[8..40].copy_from_slice(&other.identity().0);
    q[44..48].copy_from_slice(&256u32.to_be_bytes());
    q[48..56].copy_from_slice(&u64::MAX.to_be_bytes());
    q[64..].copy_from_slice(b"udp-local\0");
    h.receive(false, &q)?;
    let effects = h.drain()?;
    let c = effects
        .iter()
        .find(|b| network_kind(b, 1303) && b[16..48] == other.identity().0)
        .ok_or(Error::NotFound)?;
    let c = Challenge::decode(&c[48..])?;
    let validity = 1_000_000_000;
    let response = Validation {
        nonce: c.nonce,
        origin: c.origin,
        validity,
        signature: *other
            .0
            .sign(35, &Validation::signed_region(&c.nonce, validity))?
            .as_bytes(),
    };
    h.receive(false, &incoming(other.identity(), &response.encode(), 9))?;
    h.drain()?;
    let mut request = vec![0; 48];
    gnunet_client::transport::Request::Send {
        peer: other.identity(),
        priority: 0,
        message: &frame(0, 8),
    }
    .encode(&mut request)?;
    h.receive(true, &request)?;
    assert!(
        h.drain()?
            .iter()
            .any(|b| network_kind(b, 1216) && b[16..48] == other.identity().0)
    );
    assert_eq!(h.engine.snapshot().pending_remote_acks, 4);
    let retry = h.after(41_000)?;
    assert_eq!(retry.iter().filter(|b| network_kind(b, 1214)).count(), 2);
    assert_eq!(h.engine.snapshot().pending_remote_acks, 4);
    assert!(!retry.iter().any(|b| kind(b) == 364));
    Ok(())
}

#[test]
fn late_failed_callbacks_after_expiry_and_same_queue_generation_change_cannot_retire_new_work()
-> Result<(), Error> {
    let mut h = Harness::new(256, 2)?;
    h.auto_local = false;
    let original = h.send(&frame(0, 16), 0)?;
    let original = original
        .iter()
        .find(|b| network_kind(b, 1216))
        .ok_or(Error::NotFound)?;
    let old_uuid = gnunet_transport::p2p::Reliable::decode(&original[48..])?.uuid;
    let retried = h.after(5_000_001)?;
    assert!(retried.iter().any(|b| network_kind(b, 1216)));
    let mut down = frame(1205, 40);
    down[4..8].copy_from_slice(&3u32.to_be_bytes());
    down[8..40].copy_from_slice(&h.remote.identity().0);
    h.receive(false, &down)?;
    h.drain()?;
    assert_eq!(h.engine.snapshot().pending_remote_acks, 0);
    h.auto_local = true;
    let mut queue = frame(1204, 74);
    queue[4..8].copy_from_slice(&3u32.to_be_bytes());
    queue[8..40].copy_from_slice(&h.remote.identity().0);
    queue[44..48].copy_from_slice(&256u32.to_be_bytes());
    queue[48..56].copy_from_slice(&u64::MAX.to_be_bytes());
    queue[64..].copy_from_slice(b"udp-local\0");
    h.receive(false, &queue)?;
    let events = h.drain()?;
    let c = events
        .iter()
        .find(|b| network_kind(b, 1303))
        .ok_or(Error::NotFound)?;
    let c = Challenge::decode(&c[48..])?;
    let validity = 1_000_000_000;
    let response = Validation {
        nonce: c.nonce,
        origin: c.origin,
        validity,
        signature: h
            .remote
            .sign_validation(&Validation::signed_region(&c.nonce, validity))?,
    };
    h.wire(&response.encode())?;
    h.drain()?;
    let fresh = h.send(&frame(0, 32), 0)?;
    let fresh = fresh
        .iter()
        .find(|b| network_kind(b, 1216))
        .ok_or(Error::NotFound)?;
    let fresh_uuid = gnunet_transport::p2p::Reliable::decode(&fresh[48..])?.uuid;
    assert_ne!(fresh_uuid, old_uuid);
    // Return every original queued envelope, including the separately sent FC
    // control; it has its own local debt, not the data operation's debt.
    for packet in core::iter::once(original).chain(retried.iter().filter(|b| kind(b) == 1209)) {
        let mut late = frame(1210, 52);
        late[8..16].copy_from_slice(&packet[8..16]);
        late[16..20].copy_from_slice(&packet[4..8]);
        late[20..].copy_from_slice(&packet[16..48]);
        h.receive(false, &late)?;
        h.drain()?;
    }
    h.remote_ack(&[old_uuid])?;
    assert_eq!(h.engine.snapshot().queues, 1);
    assert_eq!(h.engine.snapshot().connected, 1);
    assert_eq!(h.engine.snapshot().pending_remote_acks, 1);
    assert_eq!(h.engine.snapshot().attempts, 0);
    h.remote_ack(&[fresh_uuid])?;
    assert_eq!(h.engine.snapshot().pending, 0);
    Ok(())
}
#[test]
fn peer_remote_record_quota_leaves_capacity_for_another_peer_without_releasing_any_lost_ack()
-> Result<(), Error> {
    let mut h = Harness::policy(
        256,
        2,
        Limits {
            messages: 8,
            ..Limits::default()
        },
        u64::MAX,
    )?;
    for _ in 0..4 {
        assert_eq!(
            h.send(&frame(0, 8), 0)?
                .iter()
                .filter(|b| network_kind(b, 1216))
                .count(),
            1
        );
    }
    assert!(
        !h.send(&frame(0, 8), 0)?
            .iter()
            .any(|b| network_kind(b, 1216))
    );
    assert_eq!(h.engine.snapshot().pending_remote_acks, 4);
    let other = Key(EddsaPrivateKey::from_seed([23; 32]));
    let mut q = frame(1204, 74);
    q[4..8].copy_from_slice(&9u32.to_be_bytes());
    q[8..40].copy_from_slice(&other.identity().0);
    q[44..48].copy_from_slice(&256u32.to_be_bytes());
    q[48..56].copy_from_slice(&u64::MAX.to_be_bytes());
    q[64..].copy_from_slice(b"udp-local\0");
    h.receive(false, &q)?;
    let events = h.drain()?;
    let c = events
        .iter()
        .find(|b| network_kind(b, 1303) && b[16..48] == other.identity().0)
        .ok_or(Error::NotFound)?;
    let c = Challenge::decode(&c[48..])?;
    let validity = 1_000_000_000;
    let response = Validation {
        nonce: c.nonce,
        origin: c.origin,
        validity,
        signature: *other
            .0
            .sign(35, &Validation::signed_region(&c.nonce, validity))?
            .as_bytes(),
    };
    h.receive(false, &incoming(other.identity(), &response.encode(), 5))?;
    h.drain()?;
    let mut send = vec![0; 48];
    gnunet_client::transport::Request::Send {
        peer: other.identity(),
        priority: 0,
        message: &frame(0, 8),
    }
    .encode(&mut send)?;
    h.receive(true, &send)?;
    assert!(
        h.drain()?
            .iter()
            .any(|b| network_kind(b, 1216) && b[16..48] == other.identity().0)
    );
    assert_eq!(h.engine.snapshot().pending_remote_acks, 5);
    Ok(())
}

#[test]
fn clock_and_entropy_refusal_keep_original_bytes_offset_credit_and_remote_metadata_uncommitted()
-> Result<(), Error> {
    struct FailAfter(usize);
    impl Entropy for FailAfter {
        fn fill(&mut self, b: &mut [u8]) -> Result<(), Error> {
            if self.0 == 0 {
                return Err(Error::Entropy);
            }
            self.0 -= 1;
            b.fill(0xaa);
            Ok(())
        }
    }
    let mut h = Harness::new(256, 2)?;
    let body = frame(0, 512);
    let mut request = vec![0; 40 + body.len()];
    gnunet_client::transport::Request::Send {
        peer: h.remote.identity(),
        priority: 0,
        message: &body,
    }
    .encode(&mut request)?;
    let before = h.engine.snapshot();
    assert_eq!(
        h.engine
            .receive(&h.core, &request, h.now - 1, &mut h.key, &mut h.random),
        Err(Error::TimeUncertain)
    );
    assert_eq!(h.engine.snapshot(), before);
    h.now += 1;
    let outcome = h
        .engine
        .receive(&h.core, &request, h.now, &mut h.key, &mut FailAfter(1));
    assert!(
        matches!(outcome, Ok(gnunet_transport::ReceiveOutcome::WorkDeferred(reason)) if reason.reason == Error::Entropy && reason.peer == h.remote.identity())
    );
    assert_eq!(h.engine.snapshot().pending_remote_acks, 0);
    assert_eq!(h.engine.snapshot().attempts, 0);
    assert_eq!(h.engine.snapshot().pending, 1);
    assert!(!h.drain()?.iter().any(|b| kind(b) == 364 || kind(b) == 1209));
    assert!(
        !h.after(1)?
            .iter()
            .any(|b| kind(b) == 364 || network_kind(b, 1214))
    );
    assert_eq!(h.engine.deferred_work().count(), 1);
    h.engine.retry_deferred(h.now, &mut h.random)?;
    let resumed = h.drain()?;
    let pieces: Vec<_> = resumed.iter().filter(|b| network_kind(b, 1214)).collect();
    assert_eq!(pieces.len(), 3);
    let first = gnunet_transport::p2p::Fragment::decode(&pieces[0][48..])?;
    assert_eq!(first.offset, 0);
    assert_eq!(first.body, &body[..224]);
    assert_ne!(first.message_id, 0xaaaa_aaaa_aaaa_aaabu64.to_be_bytes());
    assert_eq!(resumed.iter().filter(|b| kind(b) == 364).count(), 1);
    assert_eq!(h.engine.snapshot().pending_remote_acks, 3);
    Ok(())
}

#[test]
fn fully_reserved_payload_budget_cannot_deadlock_initial_retry_metadata_or_core_credit()
-> Result<(), Error> {
    use gnunet_transport::p2p::Flow;
    let mut h = Harness::policy(
        256,
        2,
        Limits {
            bytes: 65535,
            ..Limits::default()
        },
        u64::MAX,
    )?;
    let mut flow = Flow {
        sequence: 1,
        sender_time: 1,
        outbound_sent: 0,
        inbound_window: 0,
        outbound_window: 131072,
        rtt: 0,
        sync_ready: true,
    };
    h.wire(&flow.encode())?;
    h.drain()?;
    for n in [32768, 32767] {
        assert!(!h.send(&frame(0, n), 0)?.iter().any(|b| kind(b) == 364));
    }
    assert_eq!(h.engine.snapshot().pending_remote_acks, 0);
    flow.sequence = 2;
    flow.sender_time = 2;
    flow.inbound_window = 1_000_000;
    h.wire(&flow.encode())?;
    let mut packets = h.drain()?;
    assert_eq!(packets.iter().filter(|b| kind(b) == 364).count(), 1);
    assert_eq!(h.engine.snapshot().retry_bitmap_bytes, 4096);
    let first_id = packets
        .iter()
        .find(|b| network_kind(b, 1214))
        .map(|b| gnunet_transport::p2p::Fragment::decode(&b[48..]).map(|f| f.message_id))
        .transpose()?
        .ok_or(Error::NotFound)?;
    let mut first_pass = 0;
    let mut credits = 0;
    let mut peak_bitmap = h.engine.snapshot().retry_bitmap_bytes;
    for _ in 0..64 {
        for packet in &packets {
            if network_kind(packet, 1214) {
                let fragment = gnunet_transport::p2p::Fragment::decode(&packet[48..])?;
                if fragment.message_id == first_id {
                    assert_eq!(usize::from(fragment.offset), first_pass);
                    first_pass += fragment.body.len();
                } else {
                    assert_eq!(first_pass, 32768);
                }
            } else if kind(packet) == 364 {
                credits += 1;
                assert!(credits <= 2);
                if credits == 2 {
                    assert_eq!(first_pass, 32768);
                }
            }
        }
        let ids: Vec<_> = packets
            .iter()
            .filter(|b| network_kind(b, 1214))
            .map(|b| gnunet_transport::p2p::Fragment::decode(&b[48..]).map(|f| f.ack))
            .collect::<Result<_, _>>()?;
        if ids.is_empty() {
            break;
        }
        // Only UUIDs from real emitted fragments above are acknowledged. The
        // bounded ACK records must keep the full payload reservation moving;
        // a second CORE credit follows its actual ordered first-pass admission.
        packets = h.remote_ack(&ids)?;
        peak_bitmap = peak_bitmap.max(h.engine.snapshot().retry_bitmap_bytes);
    }
    assert_eq!(first_pass, 32768);
    assert_eq!(credits, 2);
    assert_eq!(peak_bitmap, 8192);
    assert_eq!(h.engine.snapshot().pending, 0);
    assert_eq!(h.engine.snapshot().pending_remote_acks, 0);
    assert_eq!(h.engine.snapshot().retry_bitmap_bytes, 0);
    Ok(())
}

#[test]
fn public_queue_add_before_delete_shrinks_mtu_without_transferring_local_mid_authority()
-> Result<(), Error> {
    let mut h = Harness::new(1024, 2)?;
    h.auto_local = false;
    let body = frame(0, 512);
    let effects = h.send(&body, 0)?;
    let old = effects
        .iter()
        .find(|b| network_kind(b, 1216))
        .ok_or(Error::NotFound)?;
    let old_uuid = gnunet_transport::p2p::Reliable::decode(&old[48..])?.uuid;
    let mut queue = frame(1204, 74);
    queue[4..8].copy_from_slice(&9u32.to_be_bytes());
    queue[8..40].copy_from_slice(&h.remote.identity().0);
    queue[44..48].copy_from_slice(&128u32.to_be_bytes());
    queue[48..56].copy_from_slice(&u64::MAX.to_be_bytes());
    queue[64..].copy_from_slice(b"udp-small\0");
    h.receive(false, &queue)?;
    let added = h.drain()?;
    assert_eq!(h.engine.snapshot().queues, 2);
    assert_eq!(h.engine.snapshot().connected, 1);
    let challenge = added
        .iter()
        .find(|b| network_kind(b, 1303))
        .ok_or(Error::NotFound)?;
    let mut down = frame(1205, 40);
    down[4..8].copy_from_slice(&3u32.to_be_bytes());
    down[8..40].copy_from_slice(&h.remote.identity().0);
    h.receive(false, &down)?;
    assert!(!h.drain()?.iter().any(|b| kind(b) == 362));
    h.auto_local = true;
    h.sent(challenge)?;
    let retry = h.after(41_000)?;
    let packet = retry
        .iter()
        .find(|b| network_kind(b, 1214))
        .ok_or(Error::NotFound)?;
    assert_eq!(&packet[4..8], &9u32.to_be_bytes());
    let fragment = gnunet_transport::p2p::Fragment::decode(&packet[48..])?;
    assert_eq!(fragment.offset, 0);
    assert_eq!(fragment.body, &body[..96]);
    assert_ne!(fragment.ack, old_uuid);
    let pending = h.engine.snapshot().pending_remote_acks;
    // Old queue's real local callback cannot settle the new queue's attempt,
    // refund its finite grant, or remove original remote-ACK ownership.
    let mut late = frame(1210, 52);
    late[8..16].copy_from_slice(&old[8..16]);
    late[16..20].copy_from_slice(&old[4..8]);
    late[20..].copy_from_slice(&old[16..48]);
    h.receive(false, &late)?;
    h.drain()?;
    assert_eq!(h.engine.snapshot().queues, 1);
    assert_eq!(h.engine.snapshot().connected, 1);
    assert_eq!(h.engine.snapshot().pending_remote_acks, pending);
    let done = h.remote_ack(&[old_uuid])?;
    assert!(!done.iter().any(|b| kind(b) == 364));
    assert_eq!(h.engine.snapshot().pending_remote_acks, 0);
    assert_eq!(h.engine.snapshot().pending, 0);
    Ok(())
}

// Public queue messages and actual outgoing1209 effects, not private route-table
// inspection: a BOX-like finite grant must be usable without replacing its owner.
fn queue_with_priority(
    message_type: u16,
    id: u32,
    peer: PeerId,
    mtu: u32,
    credit: u64,
    priority: u32,
) -> Vec<u8> {
    let mut q = frame(message_type, if message_type == 1204 { 74 } else { 64 });
    q[4..8].copy_from_slice(&id.to_be_bytes());
    q[8..40].copy_from_slice(&peer.0);
    q[44..48].copy_from_slice(&mtu.to_be_bytes());
    q[48..56].copy_from_slice(&credit.to_be_bytes());
    q[56..60].copy_from_slice(&priority.to_be_bytes());
    if message_type == 1204 {
        q[64..].copy_from_slice(b"udp-local\0");
    }
    q
}

#[test]
fn higher_priority_same_owner_box_grants_are_spent_and_fall_back_without_credit_reset()
-> Result<(), Error> {
    let mut h = Harness::new(1300, 2)?;
    // Queue SETUP's own route-bound reachability challenge spends one of3
    // actual packet credits. The two remaining grants belong to normal sends.
    let setup = queue_with_priority(1204, 9, h.remote.identity(), 1404, 3, 1);
    h.receive(false, &setup)?;
    let announced = h.drain()?;
    let challenge = announced
        .iter()
        .find(|b| network_kind(b, 1303))
        .ok_or(Error::NotFound)?;
    assert_eq!(&challenge[4..8], &9u32.to_be_bytes());
    for expected in [9u32, 9, 3] {
        let effects = h.send(&frame(0, 8), 16)?;
        let packet = effects
            .iter()
            .find(|b| network_kind(b, 0))
            .ok_or(Error::NotFound)?;
        assert_eq!(&packet[4..8], &expected.to_be_bytes());
    }
    // A real additive UPDATE restores exactly one finite packet, not a full
    // window. It uses the same original queue and then falls back again.
    h.receive(
        false,
        &queue_with_priority(1222, 9, h.remote.identity(), 1404, 1, 1),
    )?;
    h.drain()?;
    for expected in [9u32, 3] {
        let effects = h.send(&frame(0, 8), 16)?;
        let packet = effects
            .iter()
            .find(|b| network_kind(b, 0))
            .ok_or(Error::NotFound)?;
        assert_eq!(&packet[4..8], &expected.to_be_bytes());
    }
    Ok(())
}

#[test]
fn queue_priority_stays_with_first_physical_owner_and_bound_validation_route() -> Result<(), Error>
{
    let mut h = Harness::new(1300, 2)?;
    // This case retains local attempts rather than inventing a callback on the
    // wrong owner. A second communicator's priority is not our queue domain.
    h.auto_local = false;
    let other = h.engine.accept()?;
    let mut register = frame(1211, 16);
    register[4..8].copy_from_slice(&1u32.to_be_bytes());
    register[12..].copy_from_slice(b"tcp\0");
    h.now += 1;
    h.engine
        .receive(&other, &register, h.now, &mut h.key, &mut h.random)?;
    h.drain()?;
    let foreign = queue_with_priority(1204, 77, h.remote.identity(), 1500, u64::MAX, u32::MAX);
    h.now += 1;
    h.engine
        .receive(&other, &foreign, h.now, &mut h.key, &mut h.random)?;
    let foreign_setup = h.drain()?;
    let challenge = foreign_setup
        .iter()
        .find(|b| network_kind(b, 1303))
        .ok_or(Error::NotFound)?;
    assert_eq!(&challenge[4..8], &77u32.to_be_bytes());
    h.receive(
        false,
        &queue_with_priority(1204, 9, h.remote.identity(), 1404, u64::MAX, 1),
    )?;
    h.drain()?;
    // An explicitly route-bound challenge remains on its new low-priority
    // queue even while a higher-priority queue of the same owner is available.
    h.receive(
        false,
        &queue_with_priority(1204, 12, h.remote.identity(), 1300, u64::MAX, 0),
    )?;
    let bound = h.drain()?;
    let challenge = bound
        .iter()
        .find(|b| network_kind(b, 1303))
        .ok_or(Error::NotFound)?;
    assert_eq!(&challenge[4..8], &12u32.to_be_bytes());
    let effects = h.send(&frame(0, 8), 16)?;
    let packet = effects
        .iter()
        .find(|b| network_kind(b, 0))
        .ok_or(Error::NotFound)?;
    assert_eq!(&packet[4..8], &9u32.to_be_bytes());
    Ok(())
}

#[test]
fn ineligible_high_priority_queue_preserves_credit_and_control_mtu_guards() -> Result<(), Error> {
    let mut h = Harness::new(1300, 2)?;
    h.receive(
        false,
        &queue_with_priority(1204, 9, h.remote.identity(), 33, 0, 1),
    )?;
    h.drain()?;
    let effects = h.send(&frame(0, 8), 16)?;
    let packet = effects
        .iter()
        .find(|b| network_kind(b, 0))
        .ok_or(Error::NotFound)?;
    assert_eq!(&packet[4..8], &3u32.to_be_bytes());
    h.receive(
        false,
        &queue_with_priority(1222, 9, h.remote.identity(), 33, 1, 1),
    )?;
    h.drain()?;
    // The normal UDP ACK backchannel control is80bytes on the network and cannot
    // use the33-byte higher-priority queue. It must preserve the fitting route.
    let body = frame(1460, 72);
    let mut notify = frame(1212, 40 + body.len() + 4);
    notify[8..40].copy_from_slice(&h.remote.identity().0);
    notify[40..112].copy_from_slice(&body);
    notify[112..].copy_from_slice(b"udp\0");
    h.receive(false, &notify)?;
    let control = h.drain()?;
    let packet = control
        .iter()
        .find(|b| network_kind(b, 1213))
        .ok_or(Error::NotFound)?;
    assert_eq!(&packet[4..8], &3u32.to_be_bytes());
    // Refusing the oversized control did not spend the small queue's original
    // credit; a fitting normal payload still consumes that exact single grant.
    let effects = h.send(&frame(0, 8), 16)?;
    let packet = effects
        .iter()
        .find(|b| network_kind(b, 0))
        .ok_or(Error::NotFound)?;
    assert_eq!(&packet[4..8], &9u32.to_be_bytes());
    Ok(())
}

// Extract actual normal outgoing communicator messages; never synthesize a
// FLOW from private peer state or turn a local callback into a remote receipt.
fn flow_messages(effects: &[Vec<u8>]) -> Result<Vec<gnunet_transport::p2p::Flow>, Error> {
    effects
        .iter()
        .filter(|b| network_kind(b, 1221))
        .map(|b| gnunet_transport::p2p::Flow::decode(&b[48..]))
        .collect()
}

#[test]
fn two_direct_peers_with_no_burst_estimate_settle_without_flow_echo_loop() -> Result<(), Error> {
    let mut alice = Harness::seeded(256, 2, Limits::default(), u64::MAX, 3, 5)?;
    let mut bob = Harness::seeded(256, 2, Limits::default(), u64::MAX, 5, 3)?;
    assert_eq!(alice.key.identity(), bob.remote.identity());
    assert_eq!(bob.key.identity(), alice.remote.identity());
    let initial_at = 500_000;
    let mut initial = Vec::new();
    for h in [&mut alice, &mut bob] {
        h.now = initial_at;
        monotime::tick_with_monotime_provider(&mut h.engine, initial_at, &mut h.random)?;
        let flows = flow_messages(&h.drain()?)?;
        assert_eq!(flows.len(), 1);
        assert!(!flows[0].sync_ready);
        assert_eq!(flows[0].rtt, u64::MAX);
        assert_eq!(flows[0].inbound_window, flows[0].outbound_window);
        initial.push(flows[0]);
    }
    // This one original coordinate is beyond the existing100ms output floor
    // and before the150s keepalive. Repeated valid current FLOWs at that same
    // coordinate must not manufacture another exchange from sync_ready=false.
    let settled_at = initial_at + 200_000;
    for _ in 0..4 {
        for (h, remote_flow) in [(&mut alice, initial[1]), (&mut bob, initial[0])] {
            h.now = settled_at;
            h.engine.receive(
                &h.comm,
                &incoming(h.remote.identity(), &remote_flow.encode(), settled_at),
                settled_at,
                &mut h.key,
                &mut h.random,
            )?;
            monotime::tick_with_monotime_provider(&mut h.engine, settled_at, &mut h.random)?;
            assert!(flow_messages(&h.drain()?)?.is_empty());
            assert_eq!(h.engine.snapshot().connected, 1);
        }
    }
    Ok(())
}

#[test]
fn not_burst_ready_still_answers_initial_stale_echo_and_changed_grant() -> Result<(), Error> {
    use gnunet_transport::p2p::Flow;
    let mut h = Harness::new(256, 2)?;
    let mut remote = Flow {
        // An ordinary initial zero counter/time is accepted independently of
        // burst readiness. Its stale window echo still needs our first reply.
        sequence: 0,
        sender_time: 0,
        inbound_window: 131_072,
        outbound_sent: 0,
        outbound_window: 0,
        rtt: u64::MAX,
        sync_ready: false,
    };
    h.wire(&remote.encode())?;
    let initial = flow_messages(&h.flow_after(200_000)?)?;
    assert_eq!(initial.len(), 1);
    assert_eq!(initial[0].inbound_window, 131_072);
    assert_eq!(initial[0].outbound_window, remote.inbound_window);
    assert!(!initial[0].sync_ready);

    remote.outbound_window = initial[0].inbound_window;
    h.wire(&remote.encode())?;
    assert!(flow_messages(&h.flow_after(200_000)?)?.is_empty());

    // A real new cumulative grant still solicits a reply carrying that grant.
    remote.sequence = 1;
    remote.sender_time = 1;
    remote.inbound_window += 512;
    h.wire(&remote.encode())?;
    let granted = flow_messages(&h.flow_after(200_000)?)?;
    assert_eq!(granted.len(), 1);
    assert_eq!(granted[0].outbound_window, remote.inbound_window);

    // Losing the peer's view of our window also retains ordinary recovery.
    remote.outbound_window = 0;
    h.wire(&remote.encode())?;
    let repaired = flow_messages(&h.flow_after(200_000)?)?;
    assert_eq!(repaired.len(), 1);
    assert_eq!(repaired[0].inbound_window, 131_072);
    assert_eq!(repaired[0].outbound_window, remote.inbound_window);
    assert!(!repaired[0].sync_ready);
    Ok(())
}
