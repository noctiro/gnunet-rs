//! Official direct communicator notify/encapsulation/dispatch, no C execution.
#![cfg(feature = "alloc")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Finite official backchannel assertions with fallible setup"
)]
use gnunet_crypto::{EddsaPrivateKey, Entropy};
use gnunet_transport::{
    Engine, Limits, Output, PeerId, Signer,
    p2p::{Challenge, Validation},
};
use gnunet_types::Error;
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
            auto_local: true,
        };
        let mut register = frame(1211, 16);
        register[4..8].copy_from_slice(&characteristics.to_be_bytes());
        register[12..].copy_from_slice(b"tcp\0");
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

fn ack() -> Vec<u8> {
    let mut b = frame(1460, 72);
    b[4..8].copy_from_slice(&128u32.to_be_bytes());
    b[8..].fill(0x44);
    b
}
fn encapsulated() -> Vec<u8> {
    let mut b = frame(1213, 80);
    b[4..76].copy_from_slice(&ack());
    b[76..].copy_from_slice(b"udp\0");
    b
}
fn register_udp(h: &mut Harness) -> Result<gnunet_transport::ClientId, Error> {
    let id = h.engine.accept()?;
    let mut b = frame(1211, 16);
    b[4..8].copy_from_slice(&2u32.to_be_bytes());
    b[12..].copy_from_slice(b"udp\0");
    h.engine
        .receive(&id, &b, h.now, &mut h.key, &mut h.random)?;
    Ok(id)
}
#[test]
fn direct_notify_keeps_official_1212_1213_bytes_and_does_not_return_core_credit()
-> Result<(), Error> {
    let mut h = Harness::new(256, 1)?;
    let udp = register_udp(&mut h)?;
    let mut request = frame(1212, 116);
    request[8..40].copy_from_slice(&h.remote.identity().0);
    request[40..112].copy_from_slice(&ack());
    request[112..].copy_from_slice(b"udp\0");
    h.engine
        .receive(&udp, &request, h.now, &mut h.key, &mut h.random)?;
    let effects = h.drain()?;
    let packets: Vec<_> = effects
        .iter()
        .filter(|b| kind(b) == 1209 && kind(&b[48..]) == 1213)
        .collect();
    assert_eq!(packets.len(), 1);
    assert_eq!(&packets[0][48..], &encapsulated());
    assert!(!effects.iter().any(|b| kind(b) == 364 || kind(b) == 365));
    assert_eq!(h.engine.snapshot().pending_remote_acks, 0);
    Ok(())
}
#[test]
fn incoming_direct_control_dispatches_by_live_prefix_and_preserves_authenticated_peer()
-> Result<(), Error> {
    let mut h = Harness::new(256, 1)?;
    let udp = register_udp(&mut h)?;
    h.wire(&encapsulated())?;
    let mut count = 0;
    while let Some(effect) = h.engine.output() {
        if let Output::Frame { client, bytes } = effect {
            if kind(&bytes) == 1220 {
                assert_eq!(client, udp);
                assert_eq!(&bytes[4..8], &[0; 4]);
                assert_eq!(&bytes[8..40], &h.remote.identity().0);
                assert_eq!(&bytes[40..], &ack());
                count += 1;
            }
            assert_ne!(kind(&bytes), 365);
        }
    }
    assert_eq!(count, 1);
    assert_eq!(h.engine.snapshot().remote_dropped, 0);
    Ok(())
}

#[test]
fn malformed_notify_and_envelope_never_create_jobs_or_turn_control_into_core_payload()
-> Result<(), Error> {
    let mut h = Harness::new(256, 1)?;
    let udp = register_udp(&mut h)?;
    let mut request = frame(1212, 116);
    request[8..40].copy_from_slice(&h.remote.identity().0);
    request[40..112].copy_from_slice(&ack());
    request[112..].copy_from_slice(b"udp\0");
    for offset in [4, 115] {
        let mut bad = request.clone();
        bad[offset] = if offset == 112 { 0 } else { 1 };
        assert!(
            h.engine
                .receive(&udp, &bad, h.now, &mut h.key, &mut h.random)
                .is_err()
        );
        assert_eq!(h.engine.snapshot().pending, 0);
        assert_eq!(h.engine.snapshot().outputs, 0);
    }
    for size in [0u16, 3, 117] {
        let mut bad = request.clone();
        bad[40..42].copy_from_slice(&size.to_be_bytes());
        assert!(
            h.engine
                .receive(&udp, &bad, h.now, &mut h.key, &mut h.random)
                .is_err()
        );
    }
    let mut malformed = encapsulated();
    malformed[79] = 1;
    h.wire(&malformed)?;
    let events = h.drain()?;
    assert!(!events.iter().any(|b| kind(b) == 365 || kind(b) == 1220));
    assert_eq!(h.engine.snapshot().remote_dropped, 1);
    h.wire(&encapsulated())?;
    assert!(h.drain()?.iter().any(|b| kind(b) == 1220));
    Ok(())
}
#[test]
fn backchannel_unknown_prefix_and_no_route_are_observable_best_effort_drops_without_core_credit()
-> Result<(), Error> {
    let mut h = Harness::new(256, 1)?;
    let udp = register_udp(&mut h)?;
    let mut unknown = encapsulated();
    unknown[76..].copy_from_slice(b"xxx\0");
    h.wire(&unknown)?;
    assert!(!h.drain()?.iter().any(|b| kind(b) == 365 || kind(b) == 1220));
    assert_eq!(
        h.engine.snapshot().last_backchannel_drop,
        Some(Error::NotFound)
    );
    let mut request = frame(1212, 116);
    request[8..40].fill(0x77);
    request[40..112].copy_from_slice(&ack());
    request[112..].copy_from_slice(b"udp\0");
    h.engine
        .receive(&udp, &request, h.now, &mut h.key, &mut h.random)?;
    assert!(h.drain()?.is_empty());
    assert_eq!(
        h.engine.snapshot().last_backchannel_drop,
        Some(Error::NotReady)
    );
    assert_eq!(h.engine.snapshot().backchannel_dropped, 2);
    let plain = h.engine.accept()?;
    assert_eq!(
        h.engine
            .receive(&plain, &request, h.now, &mut h.key, &mut h.random),
        Err(Error::PermissionDenied)
    );
    Ok(())
}
#[test]
fn backchannel_codec_refusals_are_atomic_and_the_payload_is_not_interpreted_as_a_name()
-> Result<(), Error> {
    use gnunet_transport::p2p::Backchannel;
    let message = ack();
    let wire = encapsulated();
    let b = Backchannel::decode(&wire)?;
    assert_eq!(b.message, message);
    assert_eq!(b.communicator, b"udp");
    let mut out = [0xa5; 80];
    for n in 0..80 {
        assert_eq!(b.encode(&mut out[..n]), Err(Error::Capacity));
        assert_eq!(out, [0xa5; 80]);
    }
    assert_eq!(b.encode(&mut out)?, 80);
    assert_eq!(out.as_slice(), wire);
    let bad = Backchannel {
        message: &message,
        communicator: b"ud\0p",
    };
    out.fill(0xa5);
    assert_eq!(bad.encode(&mut out), Err(Error::Malformed));
    assert_eq!(out, [0xa5; 80]);
    Ok(())
}

#[test]
fn full_backchannel_output_budget_is_an_observable_drop_and_recovers_without_partial_fanout()
-> Result<(), Error> {
    let mut h = Harness::policy(
        256,
        1,
        Limits {
            messages: 8,
            control_messages: 2,
            ..Limits::default()
        },
        u64::MAX,
    )?;
    let _udp = register_udp(&mut h)?;
    let mut input = incoming(h.remote.identity(), &encapsulated(), 77);
    input[4..8].fill(0); // Actual UDP uses no receive callback.
    for _ in 0..10 {
        h.receive(false, &input)?;
    }
    assert_eq!(h.engine.snapshot().outputs, 10);
    h.receive(false, &input)?;
    assert_eq!(h.engine.snapshot().outputs, 10);
    assert_eq!(h.engine.snapshot().backchannel_dropped, 1);
    assert_eq!(
        h.engine.snapshot().last_backchannel_drop,
        Some(Error::Capacity)
    );
    assert_eq!(h.engine.snapshot().remote_dropped, 0);
    let prior = h.drain()?;
    assert_eq!(prior.iter().filter(|b| kind(b) == 1220).count(), 10);
    assert!(!prior.iter().any(|b| kind(b) == 364 || kind(b) == 365));
    h.wire(&encapsulated())?;
    assert_eq!(h.drain()?.iter().filter(|b| kind(b) == 1220).count(), 1);
    assert_eq!(h.engine.snapshot().connected, 1);
    Ok(())
}

fn named_envelope(inner: &[u8], field: &[u8]) -> Vec<u8> {
    let mut bytes = frame(1213, 4 + inner.len() + field.len());
    bytes[4..4 + inner.len()].copy_from_slice(inner);
    bytes[4 + inner.len()..].copy_from_slice(field);
    bytes
}

#[test]
fn backchannel_byte_prefixes_and_nul_suffixes_match_reference_checks() -> Result<(), Error> {
    use gnunet_transport::p2p::Backchannel;
    let inner = ack();
    for field in [
        b"udp\0ignored\0".as_slice(),
        &[0xff, 0xfe, 0, 0xab, 0],
        b"\0ignored\0",
    ] {
        let mut bytes = named_envelope(&inner, field);
        let original = Backchannel::decode(&bytes)?;
        let end = field.iter().position(|b| *b == 0).ok_or(Error::Malformed)?;
        assert_eq!(original.message, inner);
        assert_eq!(original.message.as_ptr(), bytes[4..].as_ptr());
        assert_eq!(original.communicator, &field[..end]);
        assert_eq!(
            original.communicator.as_ptr(),
            bytes[4 + inner.len()..].as_ptr()
        );
        let mut canonical = vec![0xa5; 4 + inner.len() + end + 1];
        assert_eq!(original.encode(&mut canonical)?, canonical.len());
        assert_eq!(&canonical[4..4 + inner.len()], inner);
        assert_eq!(
            &canonical[4 + inner.len()..canonical.len() - 1],
            &field[..end]
        );
        assert_eq!(canonical.last(), Some(&0));
        *bytes.last_mut().ok_or(Error::Capacity)? = 0xff;
        assert!(Backchannel::decode(&bytes).is_err());
    }
    // Retain the complete u16 wire extent for byte prefixes as well as UTF-8.
    let prefix = vec![0xff; usize::from(u16::MAX) - 4 - inner.len() - 1];
    let mut bytes = vec![0xa5; usize::from(u16::MAX)];
    let message = Backchannel {
        message: &inner,
        communicator: &prefix,
    };
    assert_eq!(message.encode(&mut bytes)?, bytes.len());
    assert_eq!(Backchannel::decode(&bytes)?, message);
    let too_long = vec![0xff; prefix.len() + 1];
    let mut untouched = [0xa5; 80];
    assert_eq!(
        Backchannel {
            message: &inner,
            communicator: &too_long
        }
        .encode(&mut untouched),
        Err(Error::TooLarge)
    );
    assert_eq!(untouched, [0xa5; 80]);
    Ok(())
}

#[test]
fn notify_repackages_the_first_raw_prefix_without_a_hidden_suffix_or_core_credit()
-> Result<(), Error> {
    for field in [
        b"udp\0ignored\0".as_slice(),
        &[0xff, 0xfe, 0, 0xab, 0],
        b"\0ignored\0",
    ] {
        let mut h = Harness::new(256, 1)?;
        let original = register_udp(&mut h)?;
        let inner = ack();
        let mut request = frame(1212, 40 + inner.len() + field.len());
        request[8..40].copy_from_slice(&h.remote.identity().0);
        request[40..40 + inner.len()].copy_from_slice(&inner);
        request[40 + inner.len()..].copy_from_slice(field);
        h.engine
            .receive(&original, &request, h.now, &mut h.key, &mut h.random)?;
        let effects = h.drain()?;
        let packets: Vec<_> = effects
            .iter()
            .filter(|bytes| kind(bytes) == 1209 && kind(&bytes[48..]) == 1213)
            .collect();
        assert_eq!(packets.len(), 1);
        let end = field.iter().position(|b| *b == 0).ok_or(Error::Malformed)?;
        assert_eq!(&packets[0][48..], named_envelope(&inner, &field[..end + 1]));
        assert!(!effects.iter().any(|bytes| matches!(kind(bytes), 364 | 365)));
        assert_eq!(h.engine.snapshot().pending_remote_acks, 0);
    }
    Ok(())
}

#[test]
fn incoming_raw_and_receive_only_prefixes_dispatch_to_the_live_original_communicator()
-> Result<(), Error> {
    for (prefix, suffix) in [
        (b"".as_slice(), b"".as_slice()),
        (b"".as_slice(), b"\0".as_slice()),
        ([0xff, 0xfe].as_slice(), [0xff, 0xfe, 0].as_slice()),
    ] {
        let mut h = Harness::new(256, 1)?;
        let target = h.engine.accept()?;
        let mut register = frame(1211, 12 + suffix.len());
        register[4..8].copy_from_slice(&2u32.to_be_bytes());
        register[12..].copy_from_slice(suffix);
        h.engine
            .receive(&target, &register, h.now, &mut h.key, &mut h.random)?;
        let mut field = prefix.to_vec();
        field.extend_from_slice(b"\0ignored\0");
        let inner = ack();
        h.wire(&named_envelope(&inner, &field))?;
        let mut delivered = 0;
        while let Some(output) = h.engine.output() {
            if let Output::Frame { client, bytes } = output {
                assert!(!matches!(kind(&bytes), 364 | 365));
                if kind(&bytes) == 1220 {
                    assert_eq!(client, target);
                    assert_eq!(&bytes[8..40], &h.remote.identity().0);
                    assert_eq!(&bytes[40..], &inner);
                    delivered += 1;
                }
            }
        }
        assert_eq!(delivered, 1);
        assert_eq!(h.engine.snapshot().remote_dropped, 0);
        assert_eq!(h.engine.snapshot().backchannel_dropped, 0);
    }
    Ok(())
}
