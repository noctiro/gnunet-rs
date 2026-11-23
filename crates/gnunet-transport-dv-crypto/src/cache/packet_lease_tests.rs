extern crate std;

use super::*;
use crate::replay::durable::{self, CommitFailure, Destination, Refusal};
use crate::replay::{Limits, NonceSlot, PeerSlot, Reason, Replay};
use gnunet_wire::official::{MessageHeader, message_type};
use std::vec;

const LEASE: u64 = 10;
const STAMP: u64 = 20;
const MESSAGE: [u8; 4] = [0, 4, 0, 0];
const PLAIN: usize = dv::PAYLOAD_PREFIX + MESSAGE.len();
const ENCODED: usize = dv::BOX_PREFIX + PLAIN;

// Deterministic entropy is confined to these actual KEM/AEAD unit fixtures.
struct FixtureEntropy(u8);
impl Entropy for FixtureEntropy {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), Error> {
        for byte in output {
            self.0 = self.0.wrapping_add(1);
            *byte = self.0;
        }
        Ok(())
    }
}
fn check(value: bool) -> Result<(), Error> {
    if value { Ok(()) } else { Err(Error::Conflict) }
}
fn packet() -> Packet<'static> {
    Packet {
        route: &[],
        without_fc: false,
        message: &MESSAGE,
    }
}
fn recipient(seed: [u8; 32]) -> Result<(PeerId, RecipientKey), Error> {
    let local = PeerId(*EddsaPrivateKey::from_seed(seed).public_key().as_bytes());
    Ok((
        local,
        RecipientKey::new(local, EcdheSecret::from_eddsa_seed(seed))?,
    ))
}
fn certified<'source, 'id>(
    source: &'source Source<'id>,
    key: &EddsaPrivateKey,
    target: PeerId,
) -> Result<SendMaterial<'source, 'id>, Error> {
    source
        .task(STAMP, 1, LEASE)?
        .prepare_seal(target, 1, &mut FixtureEntropy(80))?
        .certify_local(key, 2, 4)
}
fn wire_pair(
    source: &Source<'_>,
    key: &EddsaPrivateKey,
    target: PeerId,
) -> Result<([u8; ENCODED], [u8; ENCODED]), Error> {
    let mut material = certified(source, key, target)?;
    let mut scratch = [0; PLAIN];
    let mut first = [0; ENCODED];
    let mut second = [0; ENCODED];
    material.seal(
        source.task(STAMP, 3, 80)?,
        3,
        packet(),
        &mut scratch,
        &mut first,
    )?;
    material.seal(
        source.task(STAMP, 4, 70)?,
        4,
        packet(),
        &mut scratch,
        &mut second,
    )?;
    check(material.until() == LEASE)?;
    Ok((first, second))
}

#[test]
fn in_place_seal_matches_the_canonical_box_bytes() -> Result<(), Error> {
    // The entire official FS UBLOCK application and recorded DHT path fit
    // through a full virtual CORE record and the longest official BOX route.
    const CORE_BYTES: usize = 62_576;
    const PLAIN_BYTES: usize = dv::PAYLOAD_PREFIX + CORE_BYTES;
    const BOX_BYTES: usize = dv::BOX_PREFIX + dv::MAX_HOPS * 32 + PLAIN_BYTES;
    let instance = Instance::new();
    let key = EddsaPrivateKey::from_seed([61; 32]);
    let sender = PeerId(*key.public_key().as_bytes());
    let source = instance.source(sender, 0, 100)?;
    let (target, _) = recipient([62; 32])?;
    let mut path: [PeerId; dv::MAX_HOPS] = core::array::from_fn(|i| PeerId([i as u8 + 2; 32]));
    path[dv::MAX_HOPS - 1] = target;
    let mut core = vec![0; CORE_BYTES];
    MessageHeader::from_total_size(message_type::CORE_ENCRYPTED_MESSAGE_CAKE, CORE_BYTES)?
        .encode(&mut core)?;
    let packet = || Packet {
        route: &path,
        without_fc: false,
        message: &core,
    };
    let prepare = || {
        source
            .task(STAMP, 1, LEASE)?
            .prepare_seal(target, 1, &mut FixtureEntropy(80))
    };
    let mut copied = vec![0; BOX_BYTES];
    let mut in_place = vec![77; BOX_BYTES + 1];
    let mut scratch = vec![0; PLAIN_BYTES];
    let expected = prepare()?.seal_local(&key, 2, packet(), &mut scratch, &mut copied)?;
    let actual = prepare()?.seal_local_in_place(&key, 2, packet(), &mut in_place)?;
    check(actual.bytes() == BOX_BYTES && expected.bytes() == BOX_BYTES)?;
    check(in_place[..actual.bytes()] == copied[..])?;
    check(in_place[actual.bytes()] == 77)?;
    check(matches!(
        prepare()?.seal_local_in_place(&key, 2, packet(), &mut in_place[..BOX_BYTES - 1]),
        Err(Error::Capacity)
    ))?;
    check(in_place[..actual.bytes()] == copied[..])
}

struct DurableFixture {
    target: PeerId,
    sender: PeerId,
    calls: usize,
}

impl durable::Store for DurableFixture {
    type Error = Error;

    fn commit(&mut self, packet: durable::Packet<'_>) -> Result<(), CommitFailure<Error>> {
        if packet.target() != self.target
            || packet.sender() != self.sender
            || packet.stamp() != STAMP
        {
            return Err(CommitFailure::Rejected(Error::Conflict));
        }
        self.calls += 1;
        match self.calls {
            1 => Err(CommitFailure::Rejected(Error::WouldBlock)),
            2 => Ok(()),
            _ => Err(CommitFailure::OutcomeUnknown(Error::Storage)),
        }
    }
}

#[test]
fn durable_grant_requires_the_original_commit_and_fences_unknown_outcome() -> Result<(), Error> {
    let instance = Instance::new();
    let key = EddsaPrivateKey::from_seed([111; 32]);
    let sender = PeerId(*key.public_key().as_bytes());
    let sending = instance.source(sender, 0, 100)?;
    let (target, keypair) = recipient([112; 32])?;
    let original = instance.source(target, 0, 100)?;
    let other = instance.source(target, 0, 100)?;
    let mut store = Destination::new(
        &original,
        DurableFixture {
            target,
            sender,
            calls: 0,
        },
    )
    .map_err(|failure| failure.reason)?;
    let (first, second) = wire_pair(&sending, &key, target)?;
    let encapsulation = BoxPacket::decode(&first)?.encapsulation()?;
    let mut materials = [ReceiveSlot::new()];
    let mut cache = ReceiveCache::new(&mut materials)?;
    let material = ReceiveMaterial::local(original.task(0, 6, LEASE)?, encapsulation, &keypair, 6)?;
    let key_id = cache.insert(0, material, 6)?;
    let mut scratch = [0; PLAIN];
    let mut buffer = [0; MESSAGE.len()];
    let request = original
        .task(0, 6, 80)?
        .prepare_open(BoxPacket::decode(&first)?, 6)?;
    let opened = cache.open(key_id, request, 6, &mut scratch, &mut buffer)?;
    let denied = match store.admit(opened, 6) {
        Err(denied)
            if denied.reason == Refusal::Store(CommitFailure::Rejected(Error::WouldBlock)) =>
        {
            denied
        }
        _ => return Err(Error::Conflict),
    };
    let first = store.admit(denied.value, 7).map_err(|_| Error::Conflict)?;
    check(first.message(7)? == MESSAGE)?;
    let mut another = [0; MESSAGE.len()];
    let request = other
        .task(0, 7, 80)?
        .prepare_open(BoxPacket::decode(&second)?, 7)?;
    let material = ReceiveMaterial::local(other.task(0, 7, LEASE)?, encapsulation, &keypair, 7)?;
    let mut another_materials = [ReceiveSlot::new()];
    let mut another_cache = ReceiveCache::new(&mut another_materials)?;
    let another_id = another_cache.insert(0, material, 7)?;
    let foreign = another_cache.open(another_id, request, 7, &mut scratch, &mut another)?;
    check(
        matches!(store.admit(foreign, 7), Err(denied) if denied.reason == Refusal::Source(Error::Stale)),
    )?;

    let request = original
        .task(0, 8, 80)?
        .prepare_open(BoxPacket::decode(&second)?, 8)?;
    let opened = cache.open(key_id, request, 8, &mut scratch, &mut another)?;
    check(matches!(store.admit(opened, 8), Err(denied)
        if denied.reason == Refusal::Store(CommitFailure::OutcomeUnknown(Error::Storage))))?;
    check(first.message(8) == Err(Error::Closed))
}

#[test]
fn longer_packet_tasks_keep_send_epoch_and_nonce_guards() -> Result<(), Error> {
    let instance = Instance::new();
    let other_instance = Instance::new();
    let key = EddsaPrivateKey::from_seed([21; 32]);
    let local = PeerId(*key.public_key().as_bytes());
    let source = instance.source(local, 0, 100)?;
    let another_source = instance.source(local, 0, 100)?;
    let another_instance = other_instance.source(local, 0, 100)?;
    let target = PeerId(*EddsaPrivateKey::from_seed([22; 32]).public_key().as_bytes());
    let mut slots = [SendSlot::new()];
    let mut cache = SendCache::new(&mut slots)?;
    let id = cache.insert(0, certified(&source, &key, target)?, 2)?;
    let mut scratch = [0; PLAIN + 8];
    let mut first = [0; ENCODED];
    let task = source.task(STAMP, 3, 80)?;
    let token = task.token();
    let sealed = cache.seal(id, task, 3, packet(), &mut scratch, &mut first)?;
    check(sealed.token() == token && sealed.stamp() == STAMP && sealed.target() == target)?;
    let nonce = BoxPacket::decode(&first)?.nonce()?;
    let next = cache.material(id)?.next;
    let remaining = cache.material(id)?.remaining;
    let mut second = [42; ENCODED];
    // Matching public keys are insufficient: allocation and instance both bind
    // the original source, and refusals must not burn the next nonce.
    for other in [&another_source, &another_instance] {
        check(matches!(
            cache.seal(
                id,
                other.task(STAMP, 4, 80)?,
                4,
                packet(),
                &mut scratch,
                &mut second,
            ),
            Err(Error::Stale)
        ))?;
    }
    check(matches!(
        cache.seal(
            id,
            source.task(STAMP + 1, 4, 80)?,
            4,
            packet(),
            &mut scratch,
            &mut second,
        ),
        Err(Error::InvalidInput)
    ))?;
    check(matches!(
        cache.seal(
            id,
            source.task(STAMP, 3, 4)?,
            4,
            packet(),
            &mut scratch,
            &mut second,
        ),
        Err(Error::NotReady)
    ))?;
    let wrong_route = [local];
    check(matches!(
        cache.seal(
            id,
            source.task(STAMP, 4, 80)?,
            4,
            Packet {
                route: &wrong_route,
                ..packet()
            },
            &mut scratch,
            &mut second,
        ),
        Err(Error::InvalidInput)
    ))?;
    check(cache.material(id)?.next == next && cache.material(id)?.remaining == remaining)?;
    check(second.iter().all(|byte| *byte == 42))?;
    check(scratch.iter().all(|byte| *byte == 0))?;
    let task = source.task(STAMP, 4, 70)?;
    let token = task.token();
    let sealed = cache.seal(id, task, 4, packet(), &mut scratch, &mut second)?;
    check(sealed.token() == token && sealed.stamp() == STAMP)?;
    let next_nonce = BoxPacket::decode(&second)?.nonce()?;
    check(nonce != next_nonce && nonce[..16] == next_nonce[..16])?;
    let mut count = [0; 8];
    count.copy_from_slice(&nonce[16..]);
    let mut next_count = [0; 8];
    next_count.copy_from_slice(&next_nonce[16..]);
    check(u64::from_be_bytes(count).checked_add(1) == Some(u64::from_be_bytes(next_count)))?;
    check(cache.find(&source, target, 9) == Some(id))?;
    check(cache.material(id)?.until() == LEASE && cache.material(id)?.token() == id.token())?;
    check(cache.find(&source, target, LEASE).is_none())?;
    check(matches!(
        cache.seal(
            id,
            source.task(STAMP, LEASE, 80)?,
            LEASE,
            packet(),
            &mut scratch,
            &mut second,
        ),
        Err(Error::NotReady)
    ))?;
    check(cache.material(id)?.until() == LEASE)?;
    check(cache.reap(LEASE) == 1)?;
    check(matches!(cache.material(id), Err(Error::Stale)))
}

#[test]
fn opened_packets_keep_their_tasks_after_material_expires() -> Result<(), Error> {
    let instance = Instance::new();
    let sender_key = EddsaPrivateKey::from_seed([23; 32]);
    let sender = instance.source(PeerId(*sender_key.public_key().as_bytes()), 0, 100)?;
    let (target, key) = recipient([24; 32])?;
    let source = instance.source(target, 0, 100)?;
    let (first, second) = wire_pair(&sender, &sender_key, target)?;
    let encapsulation = BoxPacket::decode(&first)?.encapsulation()?;
    let mut slots = [ReceiveSlot::new()];
    let mut cache = ReceiveCache::new(&mut slots)?;
    let material = ReceiveMaterial::local(source.task(0, 3, LEASE)?, encapsulation, &key, 3)?;
    let id = cache.insert(0, material, 3)?;
    let mut scratch = [0; PLAIN + 8];
    let mut first_out = [42; 12];
    let mut second_out = [42; 12];
    let request = source
        .task(0, 4, 80)?
        .prepare_open(BoxPacket::decode(&first)?, 4)?;
    let first_token = request.token();
    let opened = cache.open(id, request, 4, &mut scratch, &mut first_out)?;
    check(opened.token() == first_token && opened.sender() == sender.local())?;
    let request = source
        .task(0, 5, 70)?
        .prepare_open(BoxPacket::decode(&second)?, 5)?;
    let second_token = request.token();
    let another = cache.open(id, request, 5, &mut scratch, &mut second_out)?;
    check(another.token() == second_token && opened.nonce() != another.nonce())?;
    check(cache.find(&source, &encapsulation, 9) == Some(id))?;
    check(cache.material(id)?.until() == LEASE)?;
    let mut rejected_out = [42; 12];
    let request = source
        .task(0, LEASE, 90)?
        .prepare_open(BoxPacket::decode(&first)?, LEASE)?;
    let failure = match cache.open_recover(id, request, LEASE, &mut scratch, &mut rejected_out) {
        Ok(_) => return Err(Error::Conflict),
        Err(failure) => failure,
    };
    check(failure.error() == Error::NotReady)?;
    check(failure.recycle().iter().all(|byte| *byte == 0))?;
    check(cache.find(&source, &encapsulation, LEASE).is_none())?;
    check(cache.reap(LEASE) == 1)?;
    check(matches!(cache.material(id), Err(Error::Stale)))?;
    // Key erasure prevents future opens, but does not rewrite authenticated
    // packet tasks that already own their original plaintext and source.
    check(opened.message(11)? == MESSAGE && another.message(11)? == MESSAGE)?;
    check(another.message(69)? == MESSAGE)?;
    check(matches!(another.message(70), Err(Error::NotReady)))?;
    check(opened.message(79)? == MESSAGE)?;
    check(matches!(opened.message(80), Err(Error::NotReady)))?;
    check(opened.recycle().iter().all(|byte| *byte == 0))?;
    check(another.recycle().iter().all(|byte| *byte == 0))?;
    check(scratch.iter().all(|byte| *byte == 0))
}

#[test]
fn independent_leases_keep_source_aead_and_live_replay_checks() -> Result<(), Error> {
    let instance = Instance::new();
    let other_instance = Instance::new();
    let sender_key = EddsaPrivateKey::from_seed([25; 32]);
    let sender = instance.source(PeerId(*sender_key.public_key().as_bytes()), 0, 100)?;
    let (target, key) = recipient([26; 32])?;
    let source = instance.source(target, 0, 100)?;
    let another_source = instance.source(target, 0, 100)?;
    let another_instance = other_instance.source(target, 0, 100)?;
    let (first, second) = wire_pair(&sender, &sender_key, target)?;
    let encapsulation = BoxPacket::decode(&first)?.encapsulation()?;
    let mut material = ReceiveMaterial::local(source.task(0, 3, LEASE)?, encapsulation, &key, 3)?;
    let mut scratch = [0; PLAIN];
    let mut rejected_out = [42; 12];
    for other in [&another_source, &another_instance] {
        let request = other
            .task(0, 4, 80)?
            .prepare_open(BoxPacket::decode(&first)?, 4)?;
        let failure = match material.open_recover(request, 4, &mut scratch, &mut rejected_out) {
            Ok(_) => return Err(Error::Conflict),
            Err(failure) => failure,
        };
        check(failure.error() == Error::Stale)?;
        check(failure.recycle().iter().all(|byte| *byte == 0))?;
    }
    let mut peers = [PeerSlot::new()];
    let mut nonces = [NonceSlot::new(), NonceSlot::new()];
    let mut replay = Replay::new(&source, &mut peers, &mut nonces, Limits::default())?;
    let mut first_out = [0; 12];
    let request = source
        .task(0, 4, 80)?
        .prepare_open(BoxPacket::decode(&first)?, 4)?;
    let opened = material.open(request, 4, &mut scratch, &mut first_out)?;
    let admitted = replay.admit(opened, 4).map_err(|_| Error::Conflict)?;
    let mut duplicate_out = [0; 12];
    let request = source
        .task(0, 5, 80)?
        .prepare_open(BoxPacket::decode(&first)?, 5)?;
    let opened = material.open(request, 5, &mut scratch, &mut duplicate_out)?;
    let denied = match replay.admit(opened, 5) {
        Ok(_) => return Err(Error::Conflict),
        Err(denied) => denied,
    };
    check(denied.reason == Reason::Duplicate)?;
    check(denied.value.recycle().iter().all(|byte| *byte == 0))?;
    let mut second_out = [0; 12];
    let request = source
        .task(0, 6, 80)?
        .prepare_open(BoxPacket::decode(&second)?, 6)?;
    let opened = material.open(request, 6, &mut scratch, &mut second_out)?;
    let another = replay.admit(opened, 6).map_err(|_| Error::Conflict)?;
    check(admitted.stamp() == another.stamp() && admitted.nonce() != another.nonce())?;
    check(replay.counts().peers == 1 && replay.counts().nonces == 2)?;
    // A populated signature cache never substitutes for per-packet AEAD.
    let mut tampered = first;
    tampered[ENCODED - 1] ^= 1;
    let request = source
        .task(0, 7, 80)?
        .prepare_open(BoxPacket::decode(&tampered)?, 7)?;
    check(matches!(
        material.open(request, 7, &mut scratch, &mut rejected_out),
        Err(Error::Authentication)
    ))?;
    check(rejected_out.iter().all(|byte| *byte == 0))?;
    check(material.until() == LEASE)?;
    check(material.check(LEASE).is_err())?;
    drop(material);
    check(admitted.message(11)? == MESSAGE && another.message(11)? == MESSAGE)?;
    check(replay.counts().peers == 1 && replay.counts().nonces == 2)?;
    source.retire();
    check(matches!(admitted.message(12), Err(Error::Closed)))?;
    check(matches!(another.message(12), Err(Error::Closed)))?;
    check(admitted.recycle().iter().all(|byte| *byte == 0))?;
    check(another.recycle().iter().all(|byte| *byte == 0))
}

#[test]
fn rebuilding_receive_material_keeps_live_replay_history() -> Result<(), Error> {
    let instance = Instance::new();
    let sender_key = EddsaPrivateKey::from_seed([27; 32]);
    let sender = instance.source(PeerId(*sender_key.public_key().as_bytes()), 0, 100)?;
    let (target, key) = recipient([28; 32])?;
    let source = instance.source(target, 0, 100)?;
    let mut sender_material = certified(&sender, &sender_key, target)?;
    let mut wire = [[0; ENCODED]; 3];
    let mut scratch = [0; PLAIN];
    for (now, out) in [3, 4, 5].into_iter().zip(wire.iter_mut()) {
        sender_material.seal(
            sender.task(STAMP, now, 80)?,
            now,
            packet(),
            &mut scratch,
            out,
        )?;
    }
    let encapsulation = BoxPacket::decode(&wire[0])?.encapsulation()?;
    let nonces = [
        BoxPacket::decode(&wire[0])?.nonce()?,
        BoxPacket::decode(&wire[1])?.nonce()?,
        BoxPacket::decode(&wire[2])?.nonce()?,
    ];
    check(nonces[0] != nonces[1] && nonces[0] != nonces[2] && nonces[1] != nonces[2])?;
    check(BoxPacket::decode(&wire[1])?.encapsulation()? == encapsulation)?;
    check(BoxPacket::decode(&wire[2])?.encapsulation()? == encapsulation)?;
    drop(sender_material);
    let mut slots = [ReceiveSlot::new()];
    let mut cache = ReceiveCache::new(&mut slots)?;
    let material = ReceiveMaterial::local(source.task(0, 6, LEASE)?, encapsulation, &key, 6)?;
    let old_id = cache.insert(0, material, 6)?;
    let mut peers = [PeerSlot::new()];
    let mut nonce_rows = [
        NonceSlot::new(),
        NonceSlot::new(),
        NonceSlot::new(),
        NonceSlot::new(),
    ];
    let mut replay = Replay::new(&source, &mut peers, &mut nonce_rows, Limits::default())?;
    let mut first_out = [0; 12];
    let first_request = source
        .task(0, 6, 80)?
        .prepare_open(BoxPacket::decode(&wire[0])?, 6)?;
    let opened = cache.open(old_id, first_request, 6, &mut scratch, &mut first_out)?;
    let first = replay.admit(opened, 6).map_err(|_| Error::Conflict)?;
    // Retain the actual original packet tasks across key erasure and KEM work;
    // rebuilding material must neither replace nor shorten these packet tasks.
    let second_request = source
        .task(0, 7, 80)?
        .prepare_open(BoxPacket::decode(&wire[1])?, 7)?;
    let second_token = second_request.token();
    let third_request = source
        .task(0, 7, 80)?
        .prepare_open(BoxPacket::decode(&wire[2])?, 7)?;
    let third_token = third_request.token();
    let duplicate_request = source
        .task(0, 7, 80)?
        .prepare_open(BoxPacket::decode(&wire[0])?, 7)?;
    check(cache.reap(LEASE) == 1)?;
    check(matches!(cache.material(old_id), Err(Error::Stale)))?;
    check(cache.find(&source, &encapsulation, LEASE).is_none())?;
    check(replay.counts().peers == 1 && replay.counts().nonces == 1)?;
    // This is a real new local KEM decapsulation for the same public
    // encapsulation. No old signature proof or replay receipt is imported.
    let material = ReceiveMaterial::local(source.task(0, 11, 30)?, encapsulation, &key, 11)?;
    check(material.proof.is_none())?;
    let new_id = cache.insert(0, material, 11)?;
    check(new_id.token() != old_id.token())?;
    check(cache.material(new_id)?.proof.is_none())?;
    let mut second_out = [0; 12];
    let opened = cache.open(new_id, second_request, 11, &mut scratch, &mut second_out)?;
    check(opened.token() == second_token && opened.stamp() == STAMP)?;
    check(cache.material(new_id)?.proof.is_some())?;
    let second = replay.admit(opened, 11).map_err(|_| Error::Conflict)?;
    let mut third_out = [0; 12];
    let opened = cache.open(new_id, third_request, 12, &mut scratch, &mut third_out)?;
    check(opened.token() == third_token && opened.stamp() == STAMP)?;
    let third = replay.admit(opened, 12).map_err(|_| Error::Conflict)?;
    check(replay.counts().peers == 1 && replay.counts().nonces == 3)?;
    let mut duplicate_out = [0; 12];
    let opened = cache.open(
        new_id,
        duplicate_request,
        13,
        &mut scratch,
        &mut duplicate_out,
    )?;
    let denied = match replay.admit(opened, 13) {
        Ok(_) => return Err(Error::Conflict),
        Err(denied) => denied,
    };
    check(denied.reason == Reason::Duplicate)?;
    check(denied.value.recycle().iter().all(|byte| *byte == 0))?;
    check(replay.counts().peers == 1 && replay.counts().nonces == 3)?;
    check(cache.material(new_id)?.until() == 30)?;
    check(
        first.message(13)? == MESSAGE
            && second.message(13)? == MESSAGE
            && third.message(13)? == MESSAGE,
    )?;
    check(first.recycle().iter().all(|byte| *byte == 0))?;
    check(second.recycle().iter().all(|byte| *byte == 0))?;
    check(third.recycle().iter().all(|byte| *byte == 0))
}
