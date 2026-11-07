//! Unequal official CORE/communicator prefixes and deferred-window safety.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions check actual public admission and frame limits"
)]
use gnunet_crypto::{EddsaPrivateKey, Entropy};
use gnunet_transport::{
    Engine, Limits, Output, PeerId, Signer,
    p2p::{Challenge, Flow, Validation},
};
use gnunet_types::Error;
struct Key(EddsaPrivateKey);
impl Signer for Key {
    fn identity(&self) -> PeerId {
        PeerId(*self.0.public_key().as_bytes())
    }
    fn sign_validation(&mut self, region: &[u8; 48]) -> Result<[u8; 64], Error> {
        Ok(*self.0.sign(35, region)?.as_bytes())
    }
}
struct Random;
impl Entropy for Random {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        out.fill(3);
        Ok(())
    }
}
fn frame(kind: u16, size: usize) -> Vec<u8> {
    let mut out = vec![0; size];
    out[..2].copy_from_slice(&(size as u16).to_be_bytes());
    out[2..4].copy_from_slice(&kind.to_be_bytes());
    out
}
fn incoming(peer: PeerId, message: &[u8], id: u64) -> Vec<u8> {
    let mut out = frame(1202, 88 + message.len());
    out[4..8].copy_from_slice(&1u32.to_be_bytes());
    out[8..16].copy_from_slice(&id.to_ne_bytes());
    out[16..24].copy_from_slice(&1_000_000u64.to_be_bytes());
    out[24..56].copy_from_slice(&peer.0);
    out[88..].copy_from_slice(message);
    out
}
#[test]
fn full_core_range_defers_without_poisoning_tick_and_both_physical_envelopes_fit()
-> Result<(), Error> {
    let mut local = Key(EddsaPrivateKey::from_seed([5; 32]));
    let mut remote = Key(EddsaPrivateKey::from_seed([6; 32]));
    let peer = remote.identity();
    let mut random = Random;
    let mut engine = Engine::new(local.identity(), Limits::default())?;
    let comm = engine.accept()?;
    let core = engine.accept()?;
    let other = engine.accept()?;
    let mut register = frame(1211, 16);
    register[4..8].copy_from_slice(&1u32.to_be_bytes());
    register[12..].copy_from_slice(b"tcp\0");
    engine.receive(&comm, &register, 100, &mut local, &mut random)?;
    for id in [&core, &other] {
        let mut start = [0; 40];
        gnunet_client::transport::Request::Start(gnunet_client::transport::Start::new(
            Some(local.identity()),
            true,
        ))
        .encode(&mut start)?;
        engine.receive(id, &start, 100, &mut local, &mut random)?;
    }
    let mut queue = frame(1204, 74);
    queue[4..8].copy_from_slice(&3u32.to_be_bytes());
    queue[8..40].copy_from_slice(&peer.0);
    queue[44..48].copy_from_slice(&65535u32.to_be_bytes());
    queue[48..56].copy_from_slice(&u64::MAX.to_be_bytes());
    queue[64..].copy_from_slice(b"tcp-local\0");
    engine.receive(&comm, &queue, 100, &mut local, &mut random)?;
    let mut challenge = None;
    while let Some(output) = engine.output() {
        if let Output::Frame { bytes, .. } = output
            && bytes[2..4] == 1209u16.to_be_bytes()
        {
            challenge = Some(Challenge::decode(&bytes[48..])?);
        }
    }
    let challenge = challenge.ok_or(Error::NotFound)?;
    let response = Validation {
        nonce: challenge.nonce,
        origin: challenge.origin,
        validity: 1_000_000,
        signature: remote
            .sign_validation(&Validation::signed_region(&challenge.nonce, 1_000_000))?,
    };
    engine.receive(
        &comm,
        &incoming(peer, &response.encode(), 1),
        101,
        &mut local,
        &mut random,
    )?;
    while engine.output().is_some() {}
    let mut flow = Flow {
        sequence: 0,
        inbound_window: 0,
        outbound_sent: 0,
        outbound_window: 131072,
        sender_time: 100,
        rtt: 0,
        sync_ready: true,
    };
    engine.receive(
        &comm,
        &incoming(peer, &flow.encode(), 2),
        102,
        &mut local,
        &mut random,
    )?;
    while engine.output().is_some() {}
    for size in 65488..=65495 {
        let raw = frame(64, size);
        let mut request = vec![0; 40 + size];
        gnunet_client::transport::Request::Send {
            peer,
            priority: 0,
            message: &raw,
        }
        .encode(&mut request)?;
        engine.receive(&core, &request, 103, &mut local, &mut random)?;
    }
    assert_eq!(engine.snapshot().pending, 8);
    // Closing the original CORE owner cancels all still-unadmitted originals,
    // without poisoning later shared ticks or another CORE owner.
    engine.close(&core)?;
    assert_eq!(engine.snapshot().pending, 0);
    flow.sequence = 1;
    flow.inbound_window = u64::MAX;
    flow.sender_time = 101;
    engine.receive(
        &comm,
        &incoming(peer, &flow.encode(), 3),
        104,
        &mut local,
        &mut random,
    )?;
    engine.tick(105, &mut random)?;
    while engine.output().is_some() {}
    let raw = frame(64, 65487);
    let mut request = vec![0; 40 + raw.len()];
    gnunet_client::transport::Request::Send {
        peer,
        priority: 0,
        message: &raw,
    }
    .encode(&mut request)?;
    engine.receive(&other, &request, 106, &mut local, &mut random)?;
    for now in 107..111 {
        engine.tick(now, &mut random)?;
    }
    let mut body = vec![0; raw.len()];
    let mut fragments = 0;
    while let Some(output) = engine.output() {
        if let Output::Frame { client, bytes } = output
            && client == comm
            && bytes[2..4] == 1209u16.to_be_bytes()
        {
            assert!(bytes.len() <= 65535);
            assert!(88 + bytes.len() - 48 <= 65535);
            let fragment = gnunet_transport::p2p::Fragment::decode(&bytes[48..])?;
            let offset = usize::from(fragment.offset);
            body[offset..offset + fragment.body.len()].copy_from_slice(fragment.body);
            fragments += 1;
        }
    }
    assert_eq!(body, raw);
    assert_eq!(fragments, 2);
    assert_eq!(engine.snapshot().connected, 1);
    // Complete INCOMING1202 has the larger prefix88. Its largest legal raw
    // frame65447 becomes a valid RECV365 of size65483, below65535.
    let raw = frame(64, 65447);
    let request = incoming(peer, &raw, 4);
    assert_eq!(request.len(), 65535);
    engine.receive(&comm, &request, 111, &mut local, &mut random)?;
    let mut received = false;
    while let Some(output) = engine.output() {
        if let Output::Frame { client, bytes } = output
            && client == other
            && bytes[2..4] == 365u16.to_be_bytes()
        {
            assert_eq!(bytes.len(), 65483);
            assert_eq!(&bytes[36..], &raw);
            received = true;
        }
    }
    assert!(received);
    assert_eq!(engine.snapshot().clients, 2);
    Ok(())
}
