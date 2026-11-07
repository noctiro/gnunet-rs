//! External operations shared with the pre-fragment engine for before witnesses.
#![cfg(feature = "alloc")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Wire/state assertions accompany fallible setup"
)]
use gnunet_crypto::{EddsaPrivateKey, Entropy};
use gnunet_transport::{
    Engine, Limits, Output, PeerId, Signer,
    p2p::{Challenge, Flow, Validation},
};
use gnunet_types::Error;

#[path = "support/monotime.rs"]
mod monotime;

struct Key(EddsaPrivateKey);
impl Signer for Key {
    fn identity(&self) -> PeerId {
        PeerId(*self.0.public_key().as_bytes())
    }
    fn sign_validation(&mut self, region: &[u8; 48]) -> Result<[u8; 64], Error> {
        Ok(*self.0.sign(35, region)?.as_bytes())
    }
}
struct Random(u64);
impl Entropy for Random {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        self.0 = self.0.wrapping_add(1);
        let counter = self.0.to_be_bytes();
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = counter[i % counter.len()];
        }
        Ok(())
    }
}
fn frame(kind: u16, size: usize) -> Vec<u8> {
    let mut bytes = vec![0; size];
    bytes[..2].copy_from_slice(&(size as u16).to_be_bytes());
    bytes[2..4].copy_from_slice(&kind.to_be_bytes());
    bytes
}
fn kind(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[2], bytes[3]])
}
fn incoming(peer: PeerId, message: &[u8], token: u64) -> Vec<u8> {
    let mut bytes = frame(1202, 88 + message.len());
    bytes[4..8].copy_from_slice(&1u32.to_be_bytes());
    bytes[8..16].copy_from_slice(&token.to_ne_bytes());
    bytes[16..24].copy_from_slice(&1_000_000_000u64.to_be_bytes());
    bytes[24..56].copy_from_slice(&peer.0);
    bytes[88..].copy_from_slice(message);
    bytes
}
struct Harness {
    engine: Engine,
    comm: gnunet_transport::ClientId,
    core: gnunet_transport::ClientId,
    key: Key,
    remote: Key,
    random: Random,
    now: u64,
    auto_refill: bool,
    queue_templates: Vec<Vec<u8>>,
}
impl Harness {
    fn new(mtu: u32) -> Result<Self, Error> {
        Self::with_limits(mtu, Limits::default())
    }
    fn with_limits(mtu: u32, limits: Limits) -> Result<Self, Error> {
        let key = Key(EddsaPrivateKey::from_seed([3; 32]));
        let remote = Key(EddsaPrivateKey::from_seed([5; 32]));
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
            auto_refill: true,
            queue_templates: Vec::new(),
        };
        let mut register = frame(1211, 16);
        register[4..8].copy_from_slice(&1u32.to_be_bytes());
        register[12..].copy_from_slice(b"tcp\0");
        h.receive(false, &register)?;
        let mut start = [0; 40];
        gnunet_client::transport::Request::Start(gnunet_client::transport::Start::new(
            Some(h.key.identity()),
            true,
        ))
        .encode(&mut start)?;
        h.receive(true, &start)?;
        let mut queue = frame(1204, 74);
        queue[4..8].copy_from_slice(&3u32.to_be_bytes());
        queue[8..40].copy_from_slice(&h.remote.identity().0);
        queue[44..48].copy_from_slice(&mtu.to_be_bytes());
        queue[48..56].copy_from_slice(&16u64.to_be_bytes());
        queue[64..].copy_from_slice(b"tcp-local\0");
        h.receive(false, &queue)?;
        let events = h.drain()?;
        let challenge = events
            .iter()
            .find(|b| kind(b) == 1209 && kind(&b[48..]) == 1303)
            .ok_or(Error::NotFound)?;
        let challenge = Challenge::decode(&challenge[48..])?;
        let response = Validation {
            nonce: challenge.nonce,
            origin: challenge.origin,
            validity: 10_000_000_000,
            signature: h
                .remote
                .sign_validation(&Validation::signed_region(&challenge.nonce, 10_000_000_000))?,
        };
        h.network(&response.encode())?;
        h.drain()?;
        Ok(h)
    }
    fn receive(&mut self, core: bool, bytes: &[u8]) -> Result<(), Error> {
        self.now += 1;
        self.engine.receive(
            if core { &self.core } else { &self.comm },
            bytes,
            self.now,
            &mut self.key,
            &mut self.random,
        )?;
        // A communicator explicitly returns consumed finite packet capacity.
        // This is a separate1222 operation, never an implicit1210 refund.
        if !core && matches!(kind(bytes), 1204 | 1222) {
            let mut template = bytes[..64].to_vec();
            template[..4].copy_from_slice(&[0, 64, 4, 198]);
            if let Some(existing) = self
                .queue_templates
                .iter_mut()
                .find(|t| t[4..40] == template[4..40])
            {
                *existing = template;
            } else {
                self.queue_templates.push(template);
            }
        } else if !core && kind(bytes) == 1205 {
            self.queue_templates.retain(|t| t[4..40] != bytes[4..40]);
        }
        Ok(())
    }
    fn network(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.receive(false, &incoming(self.remote.identity(), bytes, self.now))
    }
    fn drain(&mut self) -> Result<Vec<Vec<u8>>, Error> {
        let mut events = Vec::new();
        for _ in 0..8192 {
            let Some(output) = self.engine.output() else {
                return Ok(events);
            };
            if let Output::Frame { bytes, .. } = output {
                if kind(&bytes) == 1209 {
                    let mut ack = frame(1210, 52);
                    ack[4..8].copy_from_slice(&1u32.to_be_bytes());
                    ack[8..16].copy_from_slice(&bytes[8..16]);
                    ack[16..20].copy_from_slice(&bytes[4..8]);
                    ack[20..52].copy_from_slice(&bytes[16..48]);
                    self.receive(false, &ack)?;
                    if self.auto_refill
                        && let Some(mut update) = self
                            .queue_templates
                            .iter()
                            .find(|t| t[4..8] == bytes[4..8] && t[8..40] == bytes[16..48])
                            .cloned()
                    {
                        update[48..56].copy_from_slice(&1u64.to_be_bytes());
                        self.receive(false, &update)?;
                    }
                }
                events.push(bytes);
            }
        }
        Err(Error::Capacity)
    }
    fn flow(&mut self, sequence: u32, sender_time: u64, reported: u64) -> Result<(), Error> {
        self.network(
            &Flow {
                sequence,
                sender_time,
                outbound_sent: reported,
                inbound_window: 1_000_000,
                outbound_window: 0,
                rtt: 0,
                sync_ready: true,
            }
            .encode(),
        )
    }
    fn advertised(&mut self) -> Result<Flow, Error> {
        self.now += 150_000_001;
        monotime::tick_with_monotime_provider(&mut self.engine, self.now, &mut self.random)?;
        self.drain()?
            .into_iter()
            .filter(|b| kind(b) == 1209 && kind(&b[48..]) == 1221)
            .map(|b| Flow::decode(&b[48..]))
            .next_back()
            .ok_or(Error::NotFound)?
    }
}
#[test]
fn official_small_mtu_transmits_the_whole_core_send_range_with_one_credit_per_original()
-> Result<(), Error> {
    let mut h = Harness::new(256)?;
    h.flow(1, 1, 0)?;
    h.drain()?;
    for length in 65488..=65495 {
        let mut original = frame(64, length);
        for (i, b) in original[4..].iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let mut request = vec![0; 40 + length];
        gnunet_client::transport::Request::Send {
            peer: h.remote.identity(),
            priority: 0,
            message: &original,
        }
        .encode(&mut request)?;
        h.receive(true, &request)?;
        let events = h.drain()?;
        let credits = events.iter().filter(|b| kind(b) == 364).count();
        assert_eq!(credits, 1);
        let fragments: Vec<_> = events.iter().filter(|b| kind(b) == 1209).collect();
        assert!(fragments.len() > 1);
        let mut body = vec![0; length];
        let mut covered = vec![false; length];
        let mut id = None;
        let mut acks: Vec<[u8; 16]> = Vec::new();
        for bytes in fragments {
            assert!(bytes.len() <= 48 + 256);
            assert_eq!(kind(&bytes[48..]), 1214);
            let f = &bytes[48..];
            let offset = usize::from(u16::from_be_bytes([f[4], f[5]]));
            assert_eq!(usize::from(u16::from_be_bytes([f[6], f[7]])), length);
            let current = &f[24..32];
            if let Some(id) = id {
                assert_eq!(current, id);
            } else {
                id = Some(current);
            }
            let ack: [u8; 16] = f[8..24].try_into().map_err(|_| Error::Malformed)?;
            assert!(!acks.contains(&ack));
            acks.push(ack);
            body[offset..offset + f.len() - 32].copy_from_slice(&f[32..]);
            covered[offset..offset + f.len() - 32].fill(true);
        }
        assert_eq!(body, original);
        assert!(covered.into_iter().all(|b| b));
        assert_eq!(h.engine.snapshot().pending, 0);
    }
    Ok(())
}
#[test]
fn official_flow_loss_reanchors_forward_reverse_duplicate_and_rejects_overflow_atomically()
-> Result<(), Error> {
    let mut h = Harness::new(65535)?;
    h.flow(10, 10, 1000)?;
    h.drain()?;
    assert_eq!(h.advertised()?.inbound_window, 131072 + 1000);
    h.flow(11, 11, 50)?;
    h.drain()?;
    assert_eq!(h.advertised()?.inbound_window, 131072 + 50);
    h.flow(11, 11, 50)?;
    h.drain()?;
    assert_eq!(h.advertised()?.inbound_window, 131072 + 50);
    let body = frame(64, 8);
    let mut request = vec![0; 40 + body.len()];
    gnunet_client::transport::Request::Send {
        peer: h.remote.identity(),
        priority: 0,
        message: &body,
    }
    .encode(&mut request)?;
    h.receive(true, &request)?;
    h.drain()?;
    assert_eq!(h.advertised()?.outbound_sent, 8);
    h.flow(0, 12, u64::MAX)?;
    h.drain()?;
    let after = h.advertised()?;
    assert_eq!(after.inbound_window, 131072 + 50);
    assert_eq!(after.outbound_sent, 8);
    // The rejected packet must not advance sender_time: this original fresh
    // timestamp remains legal despite being older than the rejected overflow.
    h.flow(12, 11, 60)?;
    h.drain()?;
    assert_eq!(h.advertised()?.inbound_window, 131072 + 60);
    // Fresh seq rollback is the official restart signal. Only this accepted
    // packet resets our own actual cumulative debit.
    h.flow(0, 13, 70)?;
    h.drain()?;
    let reset = h.advertised()?;
    assert_eq!(reset.outbound_sent, 0);
    assert_eq!(reset.inbound_window, 131072 + 70);
    // A delayed update from another queue cannot override the fresh timestamp.
    h.flow(99, 12, 9999)?;
    h.drain()?;
    let stale = h.advertised()?;
    assert_eq!(stale.outbound_sent, 0);
    assert_eq!(stale.inbound_window, 131072 + 70);
    Ok(())
}

fn fragment_packet(original: &[u8], start: usize, end: usize, id: u8, ack: u8) -> Vec<u8> {
    let mut bytes = frame(1214, 32 + end - start);
    bytes[4..6].copy_from_slice(&(start as u16).to_be_bytes());
    bytes[6..8].copy_from_slice(&(original.len() as u16).to_be_bytes());
    bytes[8..24].fill(ack);
    bytes[24..32].fill(id);
    bytes[32..].copy_from_slice(&original[start..end]);
    bytes
}
#[test]
fn official_fragment_reassembly_accepts_out_of_order_and_identical_overlap_without_partial_delivery()
-> Result<(), Error> {
    let mut h = Harness::new(256)?;
    let mut original = frame(64, 1024);
    for (i, b) in original[4..].iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    let ranges = [(384, 768), (384, 768), (0, 256), (128, 512), (768, 1024)];
    let mut received = Vec::new();
    let mut ack_ids = Vec::new();
    let mut tokens = Vec::new();
    for (index, (start, end)) in ranges.into_iter().enumerate() {
        let token = h.now;
        h.network(&fragment_packet(
            &original,
            start,
            end,
            7,
            (index + 1) as u8,
        ))?;
        let events = h.drain()?;
        for bytes in events {
            if kind(&bytes) == 365 {
                received.push(bytes[36..].to_vec());
            }
            if kind(&bytes) == 1203 {
                tokens.push(u64::from_ne_bytes(
                    bytes[8..16].try_into().map_err(|_| Error::Malformed)?,
                ));
            }
            if kind(&bytes) == 1209 && kind(&bytes[48..]) == 1217 {
                for entry in bytes[56..].as_chunks::<24>().0 {
                    ack_ids.push(entry[8..24].to_vec());
                }
            }
        }
        if index < 4 {
            assert!(received.is_empty());
        }
        assert_eq!(tokens.iter().filter(|t| **t == token).count(), 1);
    }
    assert_eq!(received, vec![original]);
    assert_eq!(ack_ids.len(), 5);
    for ack in 1..=5 {
        assert_eq!(
            ack_ids
                .iter()
                .filter(|id| id.as_slice() == [ack; 16])
                .count(),
            1
        );
    }
    Ok(())
}
#[test]
fn conflicting_fragment_cannot_poison_valid_coverage_and_nested_control_never_becomes_core_payload()
-> Result<(), Error> {
    let mut h = Harness::new(256)?;
    let original = frame(64, 512);
    h.network(&fragment_packet(&original, 0, 128, 9, 1))?;
    h.drain()?;
    let mut conflict = fragment_packet(&original, 64, 160, 9, 2);
    conflict[32] ^= 1;
    h.network(&conflict)?;
    let events = h.drain()?;
    assert!(!events.iter().any(|b| kind(b) == 365));
    assert_eq!(h.engine.snapshot().remote_dropped, 1);
    h.network(&fragment_packet(&original, 128, 512, 9, 3))?;
    let events = h.drain()?;
    let received: Vec<_> = events
        .iter()
        .filter(|b| kind(b) == 365)
        .map(|b| &b[36..])
        .collect();
    assert_eq!(received, vec![original.as_slice()]);
    for control in [1213, 1214, 1216, 1217, 1218, 1219, 1221, 1303, 1304] {
        let original = frame(control, 8);
        h.network(&fragment_packet(&original, 0, 8, control as u8, 4))?;
        assert!(!h.drain()?.iter().any(|b| kind(b) == 365));
    }
    assert_eq!(h.engine.snapshot().connected, 1);
    Ok(())
}
#[test]
fn complete_fragment_holds_only_its_original_final_fc_token_until_aggregate_capacity_returns()
-> Result<(), Error> {
    let mut h = Harness::new(256)?;
    let original = frame(64, 8);
    let mut final_token = 0;
    for id in 1..=4 {
        h.network(&fragment_packet(&original, 0, 4, id, 2 * id))?;
        let events = h.drain()?;
        assert!(events.iter().any(|b| kind(b) == 1203));
        assert!(!events.iter().any(|b| kind(b) == 365));
        final_token = h.now;
        h.network(&fragment_packet(&original, 4, 8, id, 2 * id + 1))?;
        let events = h.drain()?;
        assert_eq!(events.iter().filter(|b| kind(b) == 365).count(), 1);
        assert_eq!(
            events.iter().filter(|b| kind(b) == 1203).count(),
            usize::from(id < 4)
        );
        assert!(
            events
                .iter()
                .any(|b| kind(b) == 1209 && kind(&b[48..]) == 1217)
        );
    }
    let mut resume = [0; 40];
    gnunet_client::transport::Request::ReceiveContinue {
        peer: h.remote.identity(),
        increase: 1,
    }
    .encode(&mut resume)?;
    h.receive(true, &resume)?;
    let events = h.drain()?;
    let tokens: Vec<_> = events
        .iter()
        .filter(|b| kind(b) == 1203)
        .map(|b| {
            Ok(u64::from_ne_bytes(
                b[8..16].try_into().map_err(|_| Error::Malformed)?,
            ))
        })
        .collect::<Result<_, Error>>()?;
    assert_eq!(tokens, vec![final_token]);
    gnunet_client::transport::Request::ReceiveContinue {
        peer: h.remote.identity(),
        increase: 3,
    }
    .encode(&mut resume)?;
    h.receive(true, &resume)?;
    assert!(!h.drain()?.iter().any(|b| kind(b) == 1203));
    Ok(())
}
#[test]
fn expired_incomplete_original_does_not_supply_coverage_to_a_later_tail() -> Result<(), Error> {
    let mut h = Harness::new(256)?;
    let original = frame(64, 512);
    h.network(&fragment_packet(&original, 0, 256, 11, 1))?;
    h.drain()?;
    h.now += 4 * 60 * 1_000_000;
    h.engine.tick(h.now, &mut h.random)?;
    h.drain()?;
    h.network(&fragment_packet(&original, 256, 512, 11, 2))?;
    assert!(!h.drain()?.iter().any(|b| kind(b) == 365));
    h.network(&fragment_packet(&original, 0, 256, 11, 3))?;
    let events = h.drain()?;
    assert_eq!(events.iter().filter(|b| kind(b) == 365).count(), 1);
    Ok(())
}
#[test]
fn disconnecting_original_core_after_first_credit_cancels_unadmitted_fragment_tail()
-> Result<(), Error> {
    let mut h = Harness::new(256)?;
    let original = frame(64, 1024);
    let mut request = vec![0; 40 + original.len()];
    gnunet_client::transport::Request::Send {
        peer: h.remote.identity(),
        priority: 0,
        message: &original,
    }
    .encode(&mut request)?;
    h.receive(true, &request)?;
    let mut first = None;
    let mut credits = 0;
    while let Some(output) = h.engine.output() {
        if let Output::Frame { bytes, .. } = output {
            if kind(&bytes) == 1209 {
                first = Some(bytes);
            } else if kind(&bytes) == 364 {
                credits += 1;
            }
        }
    }
    assert_eq!(credits, 1);
    assert_eq!(h.engine.snapshot().pending, 1);
    h.engine.close(&h.core)?;
    assert_eq!(h.engine.snapshot().pending, 0);
    let first = first.ok_or(Error::NotFound)?;
    let mut ack = frame(1210, 52);
    ack[4..8].copy_from_slice(&1u32.to_be_bytes());
    ack[8..16].copy_from_slice(&first[8..16]);
    ack[16..20].copy_from_slice(&first[4..8]);
    ack[20..52].copy_from_slice(&first[16..48]);
    h.receive(false, &ack)?;
    assert!(!h.drain()?.iter().any(|b| kind(b) == 1209));
    Ok(())
}

#[test]
fn peer_context_and_declared_byte_limits_drop_only_the_remote_fragment() -> Result<(), Error> {
    let mut h = Harness::with_limits(
        256,
        Limits {
            assemblies: 2,
            assemblies_per_peer: 1,
            ..Limits::default()
        },
    )?;
    let original = frame(64, 512);
    h.network(&fragment_packet(&original, 0, 128, 1, 1))?;
    h.drain()?;
    let before = h.engine.snapshot();
    assert_eq!(before.reassemblies, 1);
    assert_eq!(before.reassembly_bytes, 512 + 64);
    h.network(&fragment_packet(&original, 0, 128, 2, 2))?;
    h.drain()?;
    assert_eq!(h.engine.snapshot().reassemblies, 1);
    assert_eq!(h.engine.snapshot().remote_dropped, 1);
    h.network(&fragment_packet(&original, 128, 512, 1, 3))?;
    assert_eq!(h.drain()?.iter().filter(|b| kind(b) == 365).count(), 1);
    assert_eq!(h.engine.snapshot().reassemblies, 0);
    assert_eq!(h.engine.snapshot().reassembly_bytes, 0);
    let mut h = Harness::with_limits(
        256,
        Limits {
            bytes: 65535,
            ..Limits::default()
        },
    )?;
    let huge = frame(64, 65495);
    h.network(&fragment_packet(&huge, 0, 128, 3, 4))?;
    let events = h.drain()?;
    assert_eq!(h.engine.snapshot().reassemblies, 0);
    assert_eq!(h.engine.snapshot().connected, 1);
    assert!(
        !events
            .iter()
            .any(|b| kind(b) == 1209 && kind(&b[48..]) == 1217)
    );
    assert!(events.iter().any(|b| kind(b) == 1203));
    Ok(())
}
#[test]
fn reserved_ack_progress_survives_four_legal_core_requests_with_full_payload_budget_and_closed_wire_window()
-> Result<(), Error> {
    let mut h = Harness::with_limits(
        256,
        Limits {
            bytes: 65535,
            messages: 8,
            control_messages: 2,
            control_bytes: 120,
            ..Limits::default()
        },
    )?;
    let original = frame(64, 512);
    h.network(&fragment_packet(&original, 0, 128, 5, 1))?;
    h.drain()?;
    h.network(
        &Flow {
            sequence: 1,
            sender_time: 1,
            outbound_sent: 0,
            inbound_window: 0,
            outbound_window: 0,
            rtt: 0,
            sync_ready: true,
        }
        .encode(),
    )?;
    h.drain()?;
    for length in [16240, 16240, 16240, 16239] {
        let body = frame(64, length);
        let mut request = vec![0; 40 + length];
        gnunet_client::transport::Request::Send {
            peer: h.remote.identity(),
            priority: 0,
            message: &body,
        }
        .encode(&mut request)?;
        h.receive(true, &request)?;
        assert!(h.drain()?.is_empty());
    }
    assert_eq!(h.engine.snapshot().pending, 4);
    assert_eq!(h.engine.snapshot().reassembly_bytes, 576);
    h.network(&fragment_packet(&original, 0, 128, 5, 2))?;
    let events = h.drain()?;
    assert!(
        events
            .iter()
            .any(|b| kind(b) == 1209 && kind(&b[48..]) == 1217)
    );
    assert!(!events.iter().any(|b| kind(b) == 364));
    assert_eq!(h.engine.snapshot().pending, 4);
    assert_eq!(h.engine.snapshot().pending_fragment_acks, 0);
    Ok(())
}
#[test]
fn entropy_failure_keeps_original_unadmitted_fragment_and_does_not_return_core_credit()
-> Result<(), Error> {
    struct Failure;
    impl Entropy for Failure {
        fn fill(&mut self, _: &mut [u8]) -> Result<(), Error> {
            Err(Error::Entropy)
        }
    }
    let mut h = Harness::new(256)?;
    let body = frame(64, 1024);
    let mut request = vec![0; 40 + body.len()];
    gnunet_client::transport::Request::Send {
        peer: h.remote.identity(),
        priority: 0,
        message: &body,
    }
    .encode(&mut request)?;
    h.now += 1;
    let outcome = h
        .engine
        .receive(&h.core, &request, h.now, &mut h.key, &mut Failure);
    assert!(
        matches!(outcome, Ok(gnunet_transport::ReceiveOutcome::WorkDeferred(reason)) if reason.reason == Error::Entropy && reason.peer == h.remote.identity())
    );
    assert_eq!(h.engine.snapshot().pending, 1);
    assert_eq!(h.engine.snapshot().outputs, 0);
    h.now += 1;
    h.engine.tick(h.now, &mut h.random)?;
    assert!(
        !h.drain()?
            .iter()
            .any(|b| kind(b) == 364 || (kind(b) == 1209 && kind(&b[48..]) == 1214))
    );
    h.engine.retry_deferred(h.now, &mut h.random)?;
    let events = h.drain()?;
    assert_eq!(events.iter().filter(|b| kind(b) == 364).count(), 1);
    let fragments: Vec<_> = events
        .iter()
        .filter(|b| kind(b) == 1209 && kind(&b[48..]) == 1214)
        .collect();
    assert_eq!(fragments.len(), 5);
    assert_eq!(&fragments[0][52..54], &[0, 0]);
    assert_eq!(h.engine.snapshot().pending, 0);
    Ok(())
}
#[test]
fn actual_link_loss_discards_original_assembly_before_same_peer_queue_replacement()
-> Result<(), Error> {
    let mut h = Harness::new(256)?;
    let original = frame(64, 512);
    h.network(&fragment_packet(&original, 0, 256, 6, 1))?;
    h.drain()?;
    let mut down = frame(1205, 40);
    down[4..8].copy_from_slice(&3u32.to_be_bytes());
    down[8..40].copy_from_slice(&h.remote.identity().0);
    h.receive(false, &down)?;
    h.drain()?;
    assert_eq!(h.engine.snapshot().reassemblies, 0);
    assert_eq!(h.engine.snapshot().connected, 0);
    let mut queue = frame(1204, 74);
    queue[4..8].copy_from_slice(&3u32.to_be_bytes());
    queue[8..40].copy_from_slice(&h.remote.identity().0);
    queue[44..48].copy_from_slice(&256u32.to_be_bytes());
    queue[48..56].copy_from_slice(&16u64.to_be_bytes());
    queue[64..].copy_from_slice(b"tcp-local\0");
    h.receive(false, &queue)?;
    let events = h.drain()?;
    let challenge = events
        .iter()
        .find(|b| kind(b) == 1209 && kind(&b[48..]) == 1303)
        .ok_or(Error::NotFound)?;
    let challenge = Challenge::decode(&challenge[48..])?;
    let reply = Validation {
        nonce: challenge.nonce,
        origin: challenge.origin,
        validity: 10_000_000_000,
        signature: h
            .remote
            .sign_validation(&Validation::signed_region(&challenge.nonce, 10_000_000_000))?,
    };
    h.network(&reply.encode())?;
    h.drain()?;
    h.network(&fragment_packet(&original, 256, 512, 6, 2))?;
    assert!(!h.drain()?.iter().any(|b| kind(b) == 365));
    h.network(&fragment_packet(&original, 0, 256, 6, 3))?;
    assert_eq!(h.drain()?.iter().filter(|b| kind(b) == 365).count(), 1);
    Ok(())
}

#[test]
fn reassembled_valid_flow_challenge_and_ack_dispatch_as_controls_after_assembly_release()
-> Result<(), Error> {
    let mut h = Harness::new(256)?;
    let flow = Flow {
        sequence: 7,
        sender_time: 17,
        outbound_sent: 600,
        inbound_window: 1_000_000,
        outbound_window: 0,
        rtt: 0,
        sync_ready: true,
    }
    .encode();
    for offset in 0..flow.len() {
        h.network(&fragment_packet(
            &flow,
            offset,
            offset + 1,
            23,
            offset as u8,
        ))?;
        assert!(!h.drain()?.iter().any(|b| kind(b) == 365));
    }
    assert_eq!(h.engine.snapshot().reassemblies, 0);
    assert_eq!(h.engine.snapshot().reassembly_bytes, 0);
    assert_eq!(h.advertised()?.inbound_window, 131072 + 600);
    let challenge = Challenge {
        nonce: [0x71; 32],
        origin: 12345,
    }
    .encode();
    let mut responses = Vec::new();
    for (offset, end) in [(0, 24), (24, 48)] {
        h.network(&fragment_packet(&challenge, offset, end, 24, offset as u8))?;
        responses.extend(h.drain()?);
    }
    let response = responses
        .iter()
        .find(|b| kind(b) == 1209 && kind(&b[48..]) == 1304)
        .ok_or(Error::NotFound)?;
    let response = Validation::decode(&response[48..])?;
    response.verify(h.key.identity().0)?;
    assert_eq!(response.nonce, [0x71; 32]);
    assert_eq!(response.origin, 12345);
    assert!(!responses.iter().any(|b| kind(b) == 365));
    let mut ack = [0; 32];
    gnunet_transport::p2p::encode_acknowledgements(1, &[(0, [0x22; 16])], &mut ack)?;
    h.network(&fragment_packet(&ack, 0, 16, 25, 1))?;
    h.drain()?;
    h.network(&fragment_packet(&ack, 16, 32, 25, 2))?;
    assert!(!h.drain()?.iter().any(|b| kind(b) == 365));
    assert_eq!(h.engine.snapshot().remote_dropped, 0);
    assert_eq!(h.engine.snapshot().connected, 1);
    Ok(())
}
#[test]
fn legal_small_queue_does_not_starve_a_later_fitting_control_route_or_retire_the_communicator()
-> Result<(), Error> {
    let mut h = Harness::new(256)?;
    let mut update = frame(1222, 64);
    update[4..8].copy_from_slice(&3u32.to_be_bytes());
    update[8..40].copy_from_slice(&h.remote.identity().0);
    update[44..48].copy_from_slice(&33u32.to_be_bytes());
    update[48..56].copy_from_slice(&16u64.to_be_bytes());
    h.receive(false, &update)?;
    h.drain()?;
    let mut queue = frame(1204, 74);
    queue[4..8].copy_from_slice(&4u32.to_be_bytes());
    queue[8..40].copy_from_slice(&h.remote.identity().0);
    queue[44..48].copy_from_slice(&256u32.to_be_bytes());
    queue[48..56].copy_from_slice(&16u64.to_be_bytes());
    queue[64..].copy_from_slice(b"tcp-local\0");
    h.receive(false, &queue)?;
    h.drain()?;
    let challenge = Challenge {
        nonce: [0x55; 32],
        origin: 123,
    }
    .encode();
    h.network(&challenge)?;
    let events = h.drain()?;
    let response = events
        .iter()
        .find(|b| kind(b) == 1209 && kind(&b[48..]) == 1304)
        .ok_or(Error::NotFound)?;
    assert_eq!(&response[4..8], &4u32.to_be_bytes());
    assert_eq!(response.len(), 48 + 120);
    assert_eq!(h.engine.snapshot().queues, 2);
    assert_eq!(h.engine.snapshot().clients, 2);
    // Ordinary payload still uses the validated MTU33 queue and its legal
    // one-byte fragment body; no extra private protocol framing is introduced.
    let body = frame(64, 48);
    let mut request = vec![0; 40 + body.len()];
    gnunet_client::transport::Request::Send {
        peer: h.remote.identity(),
        priority: 0,
        message: &body,
    }
    .encode(&mut request)?;
    h.receive(true, &request)?;
    let events = h.drain()?;
    let fragments: Vec<_> = events
        .iter()
        .filter(|b| kind(b) == 1209 && kind(&b[48..]) == 1214)
        .collect();
    assert_eq!(fragments.len(), 48);
    assert!(fragments.iter().all(|b| b.len() == 48 + 33));
    assert_eq!(events.iter().filter(|b| kind(b) == 364).count(), 1);
    Ok(())
}

#[test]
fn a_new_lower_grant_cannot_revoke_inflight_data_authorized_by_the_previous_window()
-> Result<(), Error> {
    let mut h = Harness::new(65535)?;
    for _ in 0..3 {
        h.network(&frame(64, 64000))?;
        assert_eq!(h.drain()?.iter().filter(|b| kind(b) == 365).count(), 1);
        let mut resume = [0; 40];
        gnunet_client::transport::Request::ReceiveContinue {
            peer: h.remote.identity(),
            increase: 1,
        }
        .encode(&mut resume)?;
        h.receive(true, &resume)?;
        h.drain()?;
    }
    let authorized = h.advertised()?.inbound_window;
    assert_eq!(authorized, 131072 + 3 * 64000);
    h.flow(1, 1, 0)?;
    h.drain()?;
    assert_eq!(h.advertised()?.inbound_window, 131072);
    assert!(4 * 64000 <= authorized);
    h.network(&frame(64, 64000))?;
    let events = h.drain()?;
    assert_eq!(events.iter().filter(|b| kind(b) == 365).count(), 1);
    assert_eq!(h.engine.snapshot().remote_dropped, 0);
    Ok(())
}

#[test]
fn finite_queue_grants_require_explicit_additive_updates_and_old_send_acks_mint_none()
-> Result<(), Error> {
    let mut h = Harness::new(256)?;
    h.auto_refill = false;
    let body = frame(0, 8);
    let mut request = vec![0; 40 + body.len()];
    gnunet_client::transport::Request::Send {
        peer: h.remote.identity(),
        priority: 0,
        message: &body,
    }
    .encode(&mut request)?;
    let mut last = None;
    for _ in 0..16 {
        h.receive(true, &request)?;
        let events = h.drain()?;
        let packet = events
            .into_iter()
            .find(|b| kind(b) == 1209)
            .ok_or(Error::NotFound)?;
        assert_eq!(&packet[48..], body.as_slice());
        last = Some(packet);
    }
    h.receive(true, &request)?;
    assert!(h.drain()?.is_empty());
    assert_eq!(h.engine.snapshot().pending, 1);
    let last = last.ok_or(Error::NotFound)?;
    let mut duplicate = frame(1210, 52);
    duplicate[4..8].copy_from_slice(&1u32.to_be_bytes());
    duplicate[8..16].copy_from_slice(&last[8..16]);
    duplicate[16..20].copy_from_slice(&last[4..8]);
    duplicate[20..52].copy_from_slice(&last[16..48]);
    h.receive(false, &duplicate)?;
    assert!(h.drain()?.is_empty());
    let mut update = h.queue_templates[0].clone();
    update[48..56].copy_from_slice(&2u64.to_be_bytes());
    h.receive(false, &update)?;
    let events = h.drain()?;
    assert_eq!(events.iter().filter(|b| kind(b) == 1209).count(), 1);
    assert_eq!(events.iter().filter(|b| kind(b) == 364).count(), 1);
    h.receive(true, &request)?;
    assert_eq!(h.drain()?.iter().filter(|b| kind(b) == 1209).count(), 1);
    h.receive(true, &request)?;
    assert!(h.drain()?.is_empty());
    assert_eq!(h.engine.snapshot().pending, 1);
    Ok(())
}
#[test]
fn known_queue_overflow_is_a_typed_atomic_rejection_and_later_valid_update_recovers()
-> Result<(), Error> {
    let mut h = Harness::new(256)?;
    h.auto_refill = false;
    let mut update = h.queue_templates[0].clone();
    update[48..56].copy_from_slice(&(u64::MAX - 17).to_be_bytes());
    h.receive(false, &update)?;
    let mut invalid = update.clone();
    invalid[44..48].copy_from_slice(&33u32.to_be_bytes());
    invalid[48..56].copy_from_slice(&2u64.to_be_bytes());
    invalid[56..60].copy_from_slice(&777u32.to_be_bytes());
    h.now += 1;
    match h
        .engine
        .receive(&h.comm, &invalid, h.now, &mut h.key, &mut h.random)?
    {
        gnunet_transport::ReceiveOutcome::Rejected(rejection) => {
            assert_eq!(rejection.client, h.comm);
            assert_eq!(rejection.peer, h.remote.identity());
            assert_eq!(rejection.queue, 3);
            assert_eq!(rejection.reason, Error::Overflow);
        }
        _ => return Err(Error::Malformed),
    }
    assert!(h.drain()?.is_empty());
    let body = frame(0, 128);
    let mut request = vec![0; 40 + body.len()];
    gnunet_client::transport::Request::Send {
        peer: h.remote.identity(),
        priority: 0,
        message: &body,
    }
    .encode(&mut request)?;
    h.receive(true, &request)?;
    let events = h.drain()?;
    let packet = events
        .iter()
        .find(|b| kind(b) == 1209)
        .ok_or(Error::NotFound)?;
    assert_eq!(&packet[48..], body.as_slice()); // Rejected MTU33 was not committed.
    update[48..56].copy_from_slice(&1u64.to_be_bytes());
    h.receive(false, &update)?;
    assert_eq!(h.engine.snapshot().connected, 1);
    Ok(())
}
#[test]
fn an_unready_legal_tiny_queue_does_not_accumulate_unsendable_control_jobs() -> Result<(), Error> {
    let mut h = Harness::new(256)?;
    let other = Key(EddsaPrivateKey::from_seed([17; 32]));
    let mut queue = frame(1204, 74);
    queue[4..8].copy_from_slice(&99u32.to_be_bytes());
    queue[8..40].copy_from_slice(&other.identity().0);
    queue[44..48].copy_from_slice(&33u32.to_be_bytes());
    queue[48..56].copy_from_slice(&16u64.to_be_bytes());
    queue[64..].copy_from_slice(b"tcp-local\0");
    h.receive(false, &queue)?;
    h.drain()?;
    for _ in 0..30 {
        h.now += 1_000_000;
        h.engine.tick(h.now, &mut h.random)?;
        h.drain()?;
        assert_eq!(h.engine.snapshot().pending, 0);
    }
    assert_eq!(h.engine.snapshot().queues, 2);
    assert_eq!(h.engine.snapshot().connected, 1);
    assert_eq!(h.engine.snapshot().clients, 2);
    Ok(())
}

#[test]
fn sibling_queue_inherits_only_live_same_peer_proof_and_loss_cannot_validate_a_replacement()
-> Result<(), Error> {
    let mut h = Harness::new(256)?;
    h.flow(1, 1, 0)?;
    h.drain()?;
    let mut sibling = frame(1204, 74);
    sibling[4..8].copy_from_slice(&9u32.to_be_bytes());
    sibling[8..40].copy_from_slice(&h.remote.identity().0);
    sibling[44..48].copy_from_slice(&33u32.to_be_bytes());
    sibling[48..56].copy_from_slice(&32u64.to_be_bytes());
    sibling[64..].copy_from_slice(b"tcp-local\0");
    h.receive(false, &sibling)?;
    // Inherited proof creates no peer transition or persisted address result.
    while let Some(event) = h.engine.output() {
        assert!(!matches!(event, Output::Validated { .. }));
        if let Output::Frame { bytes, .. } = event {
            assert_ne!(kind(&bytes), 361);
        }
    }
    let mut down = frame(1205, 40);
    down[4..8].copy_from_slice(&3u32.to_be_bytes());
    down[8..40].copy_from_slice(&h.remote.identity().0);
    h.receive(false, &down)?;
    assert_eq!(h.engine.snapshot().connected, 1);
    assert!(!h.drain()?.iter().any(|b| kind(b) == 362));
    let body = frame(0, 40);
    let mut request = vec![0; 40 + body.len()];
    gnunet_client::transport::Request::Send {
        peer: h.remote.identity(),
        priority: 0,
        message: &body,
    }
    .encode(&mut request)?;
    h.receive(true, &request)?;
    let events = h.drain()?;
    let fragments: Vec<_> = events.iter().filter(|b| kind(b) == 1209).collect();
    assert_eq!(fragments.len(), 40);
    assert!(
        fragments
            .iter()
            .all(|b| b[4..8] == 9u32.to_be_bytes() && b.len() == 81)
    );
    assert_eq!(events.iter().filter(|b| kind(b) == 364).count(), 1);
    h.now += 900_000_001;
    h.engine.tick(h.now, &mut h.random)?;
    assert_eq!(h.engine.snapshot().connected, 0);
    assert_eq!(h.drain()?.iter().filter(|b| kind(b) == 362).count(), 1);
    sibling[4..8].copy_from_slice(&10u32.to_be_bytes());
    h.receive(false, &sibling)?;
    assert_eq!(h.engine.snapshot().connected, 0);
    assert!(!h.drain()?.iter().any(|b| kind(b) == 361));
    Ok(())
}

#[test]
fn original_mid_after_queue_replacement_cannot_refill_or_retire_the_new_generation()
-> Result<(), Error> {
    let mut h = Harness::new(256)?;
    h.auto_refill = false;
    let body = frame(0, 8);
    let mut request = vec![0; 40 + body.len()];
    gnunet_client::transport::Request::Send {
        peer: h.remote.identity(),
        priority: 0,
        message: &body,
    }
    .encode(&mut request)?;
    h.receive(true, &request)?;
    let mut original = None;
    while let Some(event) = h.engine.output() {
        if let Output::Frame { bytes, .. } = event
            && kind(&bytes) == 1209
        {
            original = Some(bytes);
        }
    }
    let original = original.ok_or(Error::NotFound)?;
    let mut down = frame(1205, 40);
    down[4..8].copy_from_slice(&3u32.to_be_bytes());
    down[8..40].copy_from_slice(&h.remote.identity().0);
    h.receive(false, &down)?;
    h.drain()?;
    let mut replacement = frame(1204, 74);
    replacement[4..8].copy_from_slice(&3u32.to_be_bytes());
    replacement[8..40].copy_from_slice(&h.remote.identity().0);
    replacement[44..48].copy_from_slice(&256u32.to_be_bytes());
    replacement[48..56].copy_from_slice(&1u64.to_be_bytes());
    replacement[64..].copy_from_slice(b"tcp-local\0");
    h.receive(false, &replacement)?;
    let events = h.drain()?;
    let challenge = events
        .iter()
        .find(|b| kind(b) == 1209 && kind(&b[48..]) == 1303)
        .ok_or(Error::NotFound)?;
    assert_ne!(challenge[8..16], original[8..16]);
    let c = Challenge::decode(&challenge[48..])?;
    let validity = 1_000_000_000;
    let response = Validation {
        nonce: c.nonce,
        origin: c.origin,
        validity,
        signature: h
            .remote
            .sign_validation(&Validation::signed_region(&c.nonce, validity))?,
    };
    h.network(&response.encode())?;
    h.drain()?;
    let mut old = frame(1210, 52);
    // Even a delayed failure belongs only to the retired original route.
    old[4..8].copy_from_slice(&0u32.to_be_bytes());
    old[8..16].copy_from_slice(&original[8..16]);
    old[16..20].copy_from_slice(&original[4..8]);
    old[20..].copy_from_slice(&original[16..48]);
    h.receive(false, &old)?;
    h.drain()?;
    assert_eq!(h.engine.snapshot().connected, 1);
    assert_eq!(h.engine.snapshot().queues, 1);
    h.receive(true, &request)?;
    assert!(h.drain()?.is_empty());
    h.receive(false, &old)?;
    assert!(h.drain()?.is_empty());
    let mut update = h.queue_templates[0].clone();
    update[48..56].copy_from_slice(&1u64.to_be_bytes());
    h.receive(false, &update)?;
    let events = h.drain()?;
    assert_eq!(events.iter().filter(|b| kind(b) == 1209).count(), 1);
    assert_eq!(events.iter().filter(|b| kind(b) == 364).count(), 1);
    assert_eq!(h.engine.snapshot().pending, 0);
    Ok(())
}

#[test]
fn explicit_unlimited_mode_does_not_spend_finite_balance_and_checked_finite_mode_can_be_replaced()
-> Result<(), Error> {
    let mut h = Harness::new(256)?;
    h.auto_refill = false;
    let mut update = h.queue_templates[0].clone();
    update[48..56].copy_from_slice(&u64::MAX.to_be_bytes());
    h.receive(false, &update)?;
    let body = frame(0, 8);
    let mut request = vec![0; 40 + body.len()];
    gnunet_client::transport::Request::Send {
        peer: h.remote.identity(),
        priority: 0,
        message: &body,
    }
    .encode(&mut request)?;
    for _ in 0..32 {
        h.receive(true, &request)?;
        assert_eq!(h.drain()?.iter().filter(|b| kind(b) == 1209).count(), 1);
    }
    // Rust treats MAX as an explicit mode, never C's wrapping += MAX.
    // Positive finite deltas cannot turn that sentinel into a small fake grant.
    update[48..56].copy_from_slice(&1u64.to_be_bytes());
    assert!(matches!(
        h.engine
            .receive(&h.comm, &update, h.now, &mut h.key, &mut h.random)?,
        gnunet_transport::ReceiveOutcome::Rejected(_)
    ));
    update[48..56].copy_from_slice(&0u64.to_be_bytes());
    h.receive(false, &update)?; // Explicitly leave unlimited with finite MAX.
    h.receive(true, &request)?;
    h.drain()?; // Finite debit now leaves MAX-1.
    update[48..56].copy_from_slice(&1u64.to_be_bytes());
    h.receive(false, &update)?;
    assert!(matches!(
        h.engine
            .receive(&h.comm, &update, h.now, &mut h.key, &mut h.random)?,
        gnunet_transport::ReceiveOutcome::Rejected(_)
    ));
    let mut down = frame(1205, 40);
    down[4..8].copy_from_slice(&3u32.to_be_bytes());
    down[8..40].copy_from_slice(&h.remote.identity().0);
    h.receive(false, &down)?;
    h.drain()?;
    let mut setup = frame(1204, 74);
    setup[4..8].copy_from_slice(&3u32.to_be_bytes());
    setup[8..40].copy_from_slice(&h.remote.identity().0);
    setup[44..48].copy_from_slice(&256u32.to_be_bytes());
    setup[64..].copy_from_slice(b"tcp-local\0");
    h.receive(false, &setup)?;
    assert!(h.drain()?.is_empty());
    assert_eq!(h.engine.snapshot().queues, 1);
    assert_eq!(h.engine.snapshot().connected, 0);
    update[48..56].copy_from_slice(&1u64.to_be_bytes());
    h.receive(false, &update)?;
    h.now += 1;
    h.engine.tick(h.now, &mut h.random)?;
    let events = h.drain()?;
    assert_eq!(
        events
            .iter()
            .filter(|b| kind(b) == 1209 && kind(&b[48..]) == 1303)
            .count(),
        1
    );
    Ok(())
}

#[test]
fn full_output_fifo_defers_the_entire_core_fanout_without_a_partial_copy_or_double_delivery()
-> Result<(), Error> {
    let mut h = Harness::with_limits(
        256,
        Limits {
            messages: 8,
            ..Limits::default()
        },
    )?;
    let second = h.engine.accept()?;
    let mut start = [0; 40];
    gnunet_client::transport::Request::Start(gnunet_client::transport::Start::new(None, true))
        .encode(&mut start)?;
    h.engine
        .receive(&second, &start, h.now, &mut h.key, &mut h.random)?;
    h.drain()?;
    // Fill15 of16 output slots with real original communicator ACK effects.
    // A two-recipient fanout must retain its complete body instead of emitting
    // one copy and failing halfway through admission.
    for _ in 0..15 {
        h.network(&frame(1218, 4))?;
    }
    assert_eq!(h.engine.snapshot().outputs, 15);
    let body = frame(0, 8);
    let admission = h.network(&body);
    let first = h.drain()?;
    assert_eq!(first.iter().filter(|b| kind(b) == 365).count(), 0);
    admission?;
    assert_eq!(first.iter().filter(|b| kind(b) == 1203).count(), 15);
    assert_eq!(h.engine.snapshot().connected, 1);
    assert_eq!(h.engine.snapshot().clients, 3);
    h.now += 1;
    h.engine.tick(h.now, &mut h.random)?;
    let copies = h.drain()?;
    assert_eq!(copies.iter().filter(|b| kind(b) == 365).count(), 2);
    assert!(
        copies
            .iter()
            .filter(|b| kind(b) == 365)
            .all(|b| b[36..] == body)
    );
    assert_eq!(copies.iter().filter(|b| kind(b) == 1203).count(), 1);
    h.now += 1;
    h.engine.tick(h.now, &mut h.random)?;
    assert!(!h.drain()?.iter().any(|b| kind(b) == 365));
    Ok(())
}

#[test]
fn refused_invalid_characteristics_cannot_create_a_route_or_block_the_reliable_owner()
-> Result<(), Error> {
    let mut h = Harness::new(256)?;
    let rejected = h.engine.accept()?;
    let mut register = frame(1211, 16);
    register[4..8].copy_from_slice(&3u32.to_be_bytes());
    register[12..].copy_from_slice(b"udp\0");
    assert_eq!(
        h.engine
            .receive(&rejected, &register, h.now, &mut h.key, &mut h.random),
        Err(Error::Malformed)
    );
    let mut setup = frame(1204, 74);
    setup[4..8].copy_from_slice(&3u32.to_be_bytes());
    setup[8..40].copy_from_slice(&h.remote.identity().0);
    setup[44..48].copy_from_slice(&256u32.to_be_bytes());
    setup[48..56].copy_from_slice(&32u64.to_be_bytes());
    setup[64..].copy_from_slice(b"udp-local\0");
    assert_eq!(
        h.engine
            .receive(&rejected, &setup, h.now, &mut h.key, &mut h.random),
        Err(Error::PermissionDenied)
    );
    let body = frame(0, 8);
    let mut request = vec![0; 40 + body.len()];
    gnunet_client::transport::Request::Send {
        peer: h.remote.identity(),
        priority: 0,
        message: &body,
    }
    .encode(&mut request)?;
    h.receive(true, &request)?;
    assert_eq!(
        h.drain()?
            .iter()
            .filter(|b| kind(b) == 1209 && b[48..] == body)
            .count(),
        1
    );
    assert_eq!(h.engine.snapshot().queues, 1);
    assert_eq!(h.engine.snapshot().connected, 1);
    Ok(())
}
