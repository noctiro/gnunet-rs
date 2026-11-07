//! Signed reachability and exact receive-token ownership regression.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions verify independent protocol and owner boundaries"
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
struct Random(u8);
impl Entropy for Random {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        self.0 = self.0.wrapping_add(1);
        out.fill(self.0);
        Ok(())
    }
}
fn frame(kind: u16, size: usize) -> Vec<u8> {
    let mut v = vec![0; size];
    v[..2].copy_from_slice(&(size as u16).to_be_bytes());
    v[2..4].copy_from_slice(&kind.to_be_bytes());
    v
}
fn incoming(peer: PeerId, inner: &[u8], id: u64) -> Vec<u8> {
    let mut v = frame(1202, 88 + inner.len());
    v[4..8].copy_from_slice(&1u32.to_be_bytes());
    v[8..16].copy_from_slice(&id.to_ne_bytes());
    v[16..24].copy_from_slice(&1_000_000u64.to_be_bytes());
    v[24..56].copy_from_slice(&peer.0);
    v[88..].copy_from_slice(inner);
    v
}
#[test]
fn only_fresh_signed_challenge_connects_and_original_credit_lease_survives_control()
-> Result<(), Error> {
    let mut local = Key(EddsaPrivateKey::from_seed([7; 32]));
    let mut remote = Key(EddsaPrivateKey::from_seed([9; 32]));
    let peer = remote.identity();
    let mut random = Random(0);
    let mut engine = Engine::new(local.identity(), Limits::default())?;
    let comm = engine.accept()?;
    let core = engine.accept()?;
    let mut register = frame(1211, 16);
    register[4..8].copy_from_slice(&1u32.to_be_bytes());
    register[12..].copy_from_slice(b"tcp\0");
    engine.receive(&comm, &register, 100, &mut local, &mut random)?;
    let mut start = [0; 40];
    gnunet_client::transport::Request::Start(gnunet_client::transport::Start::new(
        Some(local.identity()),
        true,
    ))
    .encode(&mut start)?;
    engine.receive(&core, &start, 100, &mut local, &mut random)?;
    let mut queue = frame(1204, 74);
    queue[4..8].copy_from_slice(&3u32.to_be_bytes());
    queue[8..40].copy_from_slice(&peer.0);
    queue[44..48].copy_from_slice(&u32::MAX.to_be_bytes());
    queue[48..56].copy_from_slice(&u64::MAX.to_be_bytes());
    queue[64..].copy_from_slice(b"tcp-local\0");
    engine.receive(&comm, &queue, 100, &mut local, &mut random)?;
    assert_eq!(engine.snapshot().connected, 0);
    let mut challenge = None;
    let mut original_mid = [0; 8];
    while let Some(output) = engine.output() {
        if let Output::Frame { client, bytes } = output {
            assert_ne!(client, core);
            if bytes[2..4] == 1209u16.to_be_bytes() {
                challenge = Some(Challenge::decode(&bytes[48..])?);
                original_mid.copy_from_slice(&bytes[8..16]);
            }
        }
    }
    let challenge = challenge.ok_or(Error::NotFound)?;
    let mut response = Validation {
        nonce: challenge.nonce,
        origin: challenge.origin,
        validity: 1_000_000,
        signature: remote
            .sign_validation(&Validation::signed_region(&challenge.nonce, 1_000_000))?,
    };
    response.origin = 99;
    engine.receive(
        &comm,
        &incoming(peer, &response.encode(), 1),
        101,
        &mut local,
        &mut random,
    )?;
    assert_eq!(engine.snapshot().connected, 0);
    response.origin = 100;
    engine.receive(
        &comm,
        &incoming(peer, &response.encode(), 2),
        102,
        &mut local,
        &mut random,
    )?;
    assert_eq!(engine.snapshot().connected, 1);
    let mut sent = frame(1210, 52);
    sent[4..8].copy_from_slice(&1u32.to_be_bytes());
    sent[8..16].copy_from_slice(&original_mid);
    sent[16..20].copy_from_slice(&3u32.to_be_bytes());
    sent[20..52].copy_from_slice(&peer.0);
    engine.receive(&comm, &sent, 102, &mut local, &mut random)?;
    assert_eq!(engine.snapshot().connected, 1);
    // A duplicated original callback has no new operation authority.
    engine.receive(&comm, &sent, 102, &mut local, &mut random)?;
    assert_eq!(engine.snapshot().connected, 1);
    while engine.output().is_some() {}
    for id in 10..14 {
        engine.receive(
            &comm,
            &incoming(peer, &[0, 4, 0, 64], id),
            103,
            &mut local,
            &mut random,
        )?;
    }
    let mut data_ack = Vec::new();
    while let Some(output) = engine.output() {
        if let Output::Frame { bytes, .. } = output
            && bytes[2..4] == 1203u16.to_be_bytes()
        {
            data_ack.push(u64::from_ne_bytes(
                bytes[8..16].try_into().map_err(|_| Error::Malformed)?,
            ));
        }
    }
    assert_eq!(data_ack, vec![10, 11, 12]);
    let flow = Flow {
        sequence: 0,
        inbound_window: 131072,
        outbound_sent: 0,
        outbound_window: 131072,
        sender_time: 200,
        rtt: 0,
        sync_ready: true,
    }
    .encode();
    engine.receive(
        &comm,
        &incoming(peer, &flow, 99),
        104,
        &mut local,
        &mut random,
    )?;
    let mut control_ack = false;
    while let Some(output) = engine.output() {
        if let Output::Frame { bytes, .. } = output
            && bytes[2..4] == 1203u16.to_be_bytes()
        {
            assert_eq!(&bytes[8..16], &99u64.to_ne_bytes());
            control_ack = true;
        }
    }
    assert!(control_ack);
    let mut credit = [0; 40];
    gnunet_client::transport::Request::ReceiveContinue { peer, increase: 4 }.encode(&mut credit)?;
    engine.receive(&core, &credit, 105, &mut local, &mut random)?;
    let mut released = None;
    while let Some(output) = engine.output() {
        if let Output::Frame { bytes, .. } = output
            && bytes[2..4] == 1203u16.to_be_bytes()
        {
            released = Some(bytes[8..16].to_vec());
        }
    }
    assert_eq!(released, Some(13u64.to_ne_bytes().to_vec()));
    // A foreign physical communicator cannot complete this process's MID.
    let foreign = engine.accept()?;
    engine.receive(&foreign, &register, 106, &mut local, &mut random)?;
    assert_eq!(
        engine.receive(&foreign, &sent, 106, &mut local, &mut random),
        Err(Error::Stale)
    );
    let mut request = vec![0; 44];
    gnunet_client::transport::Request::Send {
        peer,
        priority: 0,
        message: &[0, 4, 0, 64],
    }
    .encode(&mut request)?;
    engine.receive(&core, &request, 107, &mut local, &mut random)?;
    let mut failed_mid = None;
    while let Some(output) = engine.output() {
        if let Output::Frame { bytes, .. } = output
            && bytes[2..4] == 1209u16.to_be_bytes()
        {
            failed_mid = Some(bytes[8..16].to_vec());
        }
    }
    let failed_mid = failed_mid.ok_or(Error::NotFound)?;
    sent[8..16].copy_from_slice(&failed_mid);
    sent[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
    engine.receive(&comm, &sent, 108, &mut local, &mut random)?;
    assert_eq!(engine.snapshot().connected, 0);
    let mut disconnected = 0;
    while let Some(output) = engine.output() {
        if let Output::Frame { client, bytes } = output
            && client == core
            && bytes[2..4] == 362u16.to_be_bytes()
        {
            disconnected += 1;
        }
    }
    assert_eq!(disconnected, 1);
    engine.receive(&comm, &queue, 109, &mut local, &mut random)?;
    assert_eq!(engine.snapshot().queues, 1);
    // A known original failure arriving after local qid reuse cannot retire its
    // replacement route. Foreign/unknown ids above were not treated as 'late'.
    engine.receive(&comm, &sent, 110, &mut local, &mut random)?;
    assert_eq!(engine.snapshot().queues, 1);
    engine.receive(
        &comm,
        &incoming(peer, &[0, 4, 0, 64], 202),
        110,
        &mut local,
        &mut random,
    )?;
    let mut challenge2 = None;
    let mut challenge2_mid = [0; 8];
    while let Some(output) = engine.output() {
        if let Output::Frame { bytes, .. } = output
            && bytes[2..4] == 1209u16.to_be_bytes()
        {
            challenge2 = Some(Challenge::decode(&bytes[48..])?);
            challenge2_mid.copy_from_slice(&bytes[8..16]);
        }
    }
    let challenge2 = challenge2.ok_or(Error::NotFound)?;
    let response2 = Validation {
        nonce: challenge2.nonce,
        origin: challenge2.origin,
        validity: 1_000_000,
        signature: remote
            .sign_validation(&Validation::signed_region(&challenge2.nonce, 1_000_000))?,
    };
    engine.receive(
        &comm,
        &incoming(peer, &response2.encode(), 201),
        111,
        &mut local,
        &mut random,
    )?;
    assert_eq!(engine.snapshot().connected, 1);
    let mut ordered = Vec::new();
    while let Some(output) = engine.output() {
        if let Output::Frame { client, bytes } = output
            && client == core
        {
            ordered.push(u16::from_be_bytes([bytes[2], bytes[3]]));
        }
    }
    assert_eq!(ordered, vec![361, 365]);
    let old_attempts = engine.snapshot().attempts;
    let mut down = frame(1205, 40);
    down[4..8].copy_from_slice(&3u32.to_be_bytes());
    down[8..40].copy_from_slice(&peer.0);
    engine.receive(&comm, &down, 112, &mut local, &mut random)?;
    engine.receive(&comm, &queue, 113, &mut local, &mut random)?;
    let mut old_ack = frame(1210, 52);
    old_ack[4..8].copy_from_slice(&1u32.to_be_bytes());
    // The still-pending challenge2 attempt is not a generic ignored unknown id.
    // Its registered original MID is found in the first new-route SEND frame.
    // Capture it before reuse by retaining it when challenge2 was sent.
    old_ack[8..16].copy_from_slice(&challenge2_mid);
    old_ack[16..20].copy_from_slice(&3u32.to_be_bytes());
    old_ack[20..52].copy_from_slice(&peer.0);
    engine.receive(&comm, &old_ack, 114, &mut local, &mut random)?;
    assert_eq!(engine.snapshot().queues, 1);
    assert_eq!(engine.snapshot().connected, 0);
    assert_eq!(engine.snapshot().attempts, old_attempts);
    // Raw data can arrive from the peer before our own challenge is answered;
    // reconnect also restores all byte/CORE credit ledgers without old receipts.
    engine.close(&comm)?;
    assert_eq!(engine.snapshot().connected, 0);
    assert_eq!(engine.snapshot().pending, 0);
    Ok(())
}

#[test]
fn aggregate_credit_fans_out_below_zero_and_late_lost_link_delta_is_harmless() -> Result<(), Error>
{
    let mut local = Key(EddsaPrivateKey::from_seed([7; 32]));
    let mut remote = Key(EddsaPrivateKey::from_seed([9; 32]));
    let peer = remote.identity();
    let mut random = Random(0);
    let mut engine = Engine::new(local.identity(), Limits::default())?;
    let comm = engine.accept()?;
    let mut register = frame(1211, 16);
    register[4..8].copy_from_slice(&1u32.to_be_bytes());
    register[12..].copy_from_slice(b"tcp\0");
    engine.receive(&comm, &register, 100, &mut local, &mut random)?;
    let mut cores = Vec::new();
    for _ in 0..5 {
        let core = engine.accept()?;
        let mut start = [0; 40];
        gnunet_client::transport::Request::Start(gnunet_client::transport::Start::new(
            Some(local.identity()),
            true,
        ))
        .encode(&mut start)?;
        engine.receive(&core, &start, 100, &mut local, &mut random)?;
        cores.push(core);
    }
    let mut queue = frame(1204, 74);
    queue[4..8].copy_from_slice(&3u32.to_be_bytes());
    queue[8..40].copy_from_slice(&peer.0);
    queue[44..48].copy_from_slice(&u32::MAX.to_be_bytes());
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
    engine.receive(
        &comm,
        &incoming(peer, &[0, 4, 0, 64], 80),
        102,
        &mut local,
        &mut random,
    )?;
    let mut fanout = Vec::new();
    while let Some(output) = engine.output() {
        if let Output::Frame { client, bytes } = output {
            assert_ne!(&bytes[2..4], &1203u16.to_be_bytes());
            if bytes[2..4] == 365u16.to_be_bytes() {
                fanout.push(client);
            }
        }
    }
    assert_eq!(fanout, cores);
    // Initial global4 - fanout5 = -1 is legal; zero/negative waits for a grant.
    engine.receive(
        &comm,
        &incoming(peer, &[0, 4, 0, 64], 82),
        103,
        &mut local,
        &mut random,
    )?;
    assert!(engine.output().is_none());
    let mut grant = [0; 40];
    gnunet_client::transport::Request::ReceiveContinue { peer, increase: 1 }.encode(&mut grant)?;
    engine.receive(&cores[0], &grant, 104, &mut local, &mut random)?;
    assert!(engine.output().is_none());
    engine.receive(&cores[1], &grant, 105, &mut local, &mut random)?;
    let mut callback = Vec::new();
    let mut second = 0;
    while let Some(output) = engine.output() {
        if let Output::Frame { bytes, .. } = output {
            if bytes[2..4] == 1203u16.to_be_bytes() {
                callback.push(bytes[8..16].to_vec());
            }
            if bytes[2..4] == 365u16.to_be_bytes() {
                second += 1;
            }
        }
    }
    assert_eq!(callback, vec![80u64.to_ne_bytes().to_vec()]);
    assert_eq!(second, 5);
    for core in &cores[2..] {
        engine.close(core)?;
    }
    let mut released = Vec::new();
    while let Some(output) = engine.output() {
        if let Output::Frame { bytes, .. } = output
            && bytes[2..4] == 1203u16.to_be_bytes()
        {
            released.push(bytes[8..16].to_vec());
        }
    }
    assert_eq!(released, vec![82u64.to_ne_bytes().to_vec()]);
    let mut down = frame(1205, 40);
    down[4..8].copy_from_slice(&3u32.to_be_bytes());
    down[8..40].copy_from_slice(&peer.0);
    engine.receive(&comm, &down, 106, &mut local, &mut random)?;
    while engine.output().is_some() {}
    // Different IPC connections may interleave this old delta with queue loss.
    engine.receive(&cores[0], &grant, 107, &mut local, &mut random)?;
    assert_eq!(engine.snapshot().clients, 3);
    assert_eq!(engine.snapshot().connected, 0);
    assert!(engine.output().is_none());
    // Positive deltas do not contain a message id: accept explicit extra
    // capacity on a live link without inventing processing/delivery evidence.
    engine.receive(&comm, &queue, 108, &mut local, &mut random)?;
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
        &incoming(peer, &response.encode(), 3),
        109,
        &mut local,
        &mut random,
    )?;
    gnunet_client::transport::Request::ReceiveContinue {
        peer,
        increase: u32::MAX,
    }
    .encode(&mut grant)?;
    engine.receive(&cores[0], &grant, 110, &mut local, &mut random)?;
    assert_eq!(engine.snapshot().connected, 1);
    engine.close(&comm)?;
    assert_eq!(engine.snapshot().pending, 0);
    Ok(())
}
