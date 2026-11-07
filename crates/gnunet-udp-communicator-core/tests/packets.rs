//! Rust packet/authentication checks only; actual C packet oracle is separate.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Finite packet boundaries and erasure assertions with fallible setup"
)]
use core::num::NonZeroUsize;
use gnunet_crypto::Entropy;
use gnunet_session_crypto::udp::DatagramKey;
use gnunet_types::Error;
use gnunet_udp_communicator_core::{
    Identity, handshake,
    wire::{self, Ack, Body, Confirmation, Control, Rekey},
};
struct Random(u64);
impl Entropy for Random {
    fn fill(&mut self, b: &mut [u8]) -> Result<(), Error> {
        self.0 = self.0.wrapping_add(1);
        for (i, v) in b.iter_mut().enumerate() {
            *v = self
                .0
                .wrapping_mul(71)
                .wrapping_add(i as u64 * 13)
                .to_le_bytes()[i % 8];
        }
        Ok(())
    }
}
fn frame(kind: u16, body: &[u8]) -> Vec<u8> {
    let n = body.len() + 4;
    let mut b = vec![0; n];
    b[..2].copy_from_slice(&(n as u16).to_be_bytes());
    b[2..4].copy_from_slice(&kind.to_be_bytes());
    b[4..].copy_from_slice(body);
    b
}
fn seal(a: &Identity, b: &Identity) -> Result<(Vec<u8>, handshake::InitialSecret), Error> {
    let mut packet = vec![0; 168];
    let body = frame(0, &[7; 12]);
    let (n, secret) = handshake::seal(
        a,
        b.peer(),
        0x0102030405060708,
        &body,
        &mut packet,
        &mut Random(5),
        NonZeroUsize::new(128).ok_or(Error::InvalidInput)?,
    )?;
    assert_eq!(n, packet.len());
    Ok((packet, secret))
}
#[test]
fn complete_handshake_transcript_is_112_and_fixed_confirmation_has_no_native_padding()
-> Result<(), Error> {
    let region = wire::handshake_region([1; 32], [2; 32], &[3; 32], 0x0102030405060708);
    assert_eq!(&region[..8], &[0, 0, 0, 112, 0, 0, 0, 33]);
    assert_eq!(&region[8..40], &[1; 32]);
    assert_eq!(&region[40..72], &[2; 32]);
    assert_eq!(&region[72..104], &[3; 32]);
    assert_eq!(&region[104..], &[1, 2, 3, 4, 5, 6, 7, 8]);
    let c = Confirmation {
        sender: [1; 32],
        signature: [2; 64],
        monotonic: u64::MAX,
    };
    let mut b = [0xa5; 111];
    for n in 0..104 {
        assert_eq!(c.encode(&mut b[..n]), Err(Error::Capacity));
        assert_eq!(b, [0xa5; 111]);
    }
    assert_eq!(c.encode(&mut b)?, 104);
    assert_eq!(Confirmation::decode(&b)?, c);
    assert_eq!(&b[104..], &[0xa5; 7]);
    Ok(())
}
#[test]
fn real_elligator_gcm_and_signature_open_exact_body_then_drop_erases_only_its_scratch()
-> Result<(), Error> {
    let a = Identity::from_seed([3; 32]);
    let b = Identity::from_seed([5; 32]);
    let (packet, secret) = seal(&a, &b)?;
    let mut scratch = [0xa5; 132];
    {
        let opened = handshake::open(&b, &packet, &mut scratch)?;
        assert_eq!(opened.confirmation.sender, a.peer());
        assert_eq!(opened.confirmation.monotonic, 0x0102030405060708);
        assert_eq!(opened.body(), frame(0, &[7; 12]));
        assert_eq!(opened.cmac(), Some(&secret.cmac));
        let remote = opened.into_secret()?;
        assert_eq!(
            DatagramKey::derive(&remote.into_master(), 1)?.kid(),
            DatagramKey::derive(&secret.into_master(), 1)?.kid()
        );
    }
    assert_eq!(&scratch[..120], &[0; 120]);
    assert_eq!(&scratch[120..], &[0xa5; 12]);
    Ok(())
}
#[test]
fn bad_tag_and_valid_gcm_with_invalid_purpose_signature_never_expose_plaintext() -> Result<(), Error>
{
    let a = Identity::from_seed([3; 32]);
    let b = Identity::from_seed([5; 32]);
    let (mut packet, secret) = seal(&a, &b)?;
    let mut scratch = [0xa5; 132];
    packet[32] ^= 1;
    assert!(matches!(
        handshake::open(&b, &packet, &mut scratch),
        Err(Error::Authentication)
    ));
    assert_eq!(&scratch[..120], &[0; 120]);
    assert_eq!(&scratch[120..], &[0xa5; 12]);
    packet[32] ^= 1;
    let key = DatagramKey::derive(&secret.into_master(), 0)?;
    key.open_initial_payload(&packet, &mut scratch[..120])?;
    scratch[32] ^= 1;
    let tag = key.seal_body(&mut scratch[..120])?;
    packet[32..48].copy_from_slice(&tag);
    packet[48..].copy_from_slice(&scratch[..120]);
    scratch.fill(0xa5);
    assert!(matches!(
        handshake::open(&b, &packet, &mut scratch),
        Err(Error::Authentication)
    ));
    assert_eq!(&scratch[..120], &[0; 120]);
    assert_eq!(&scratch[120..], &[0xa5; 12]);
    Ok(())
}
#[test]
fn receiver_binding_capacity_and_entropy_preflight_never_invent_a_datagram() -> Result<(), Error> {
    struct Refuse;
    impl Entropy for Refuse {
        fn fill(&mut self, _: &mut [u8]) -> Result<(), Error> {
            Err(Error::Entropy)
        }
    }
    let a = Identity::from_seed([3; 32]);
    let b = Identity::from_seed([5; 32]);
    let c = Identity::from_seed([7; 32]);
    let (packet, _) = seal(&a, &b)?;
    let mut scratch = [0xa5; 120];
    assert!(handshake::open(&c, &packet, &mut scratch).is_err());
    assert_eq!(scratch, [0; 120]);
    let mut short = [0xa5; 119];
    assert!(matches!(
        handshake::open(&b, &packet, &mut short),
        Err(Error::Capacity)
    ));
    assert_eq!(short, [0xa5; 119]);
    let mut out = [0xa5; 168];
    let body = frame(0, &[7; 12]);
    assert!(matches!(
        handshake::seal(
            &a,
            b.peer(),
            1,
            &body,
            &mut out,
            &mut Refuse,
            NonZeroUsize::new(1).ok_or(Error::InvalidInput)?
        ),
        Err(Error::Entropy)
    ));
    assert_eq!(out, [0xa5; 168]);
    Ok(())
}
#[test]
fn ack_rekey_and_control_following_payload_preserve_declared_extent_and_padding()
-> Result<(), Error> {
    let ack = Ack {
        allowed: 0x01020304,
        cmac: [0x44; 64],
    };
    let mut b = [0xa5; 72];
    ack.encode(&mut b)?;
    assert_eq!(&b[..8], &[0, 72, 5, 180, 1, 2, 3, 4]);
    assert_eq!(Ack::decode_backchannel(&b)?, ack);
    let mut extended = b.to_vec();
    extended.extend_from_slice(&[5; 4]);
    extended[..2].copy_from_slice(&76u16.to_be_bytes());
    assert_eq!(Ack::decode_prefix(&extended)?, (ack, 76));
    assert_eq!(Ack::decode_backchannel(&extended), Err(Error::Malformed));
    let payload = frame(0, &[9; 8]);
    extended.extend_from_slice(&payload);
    extended.extend_from_slice(&[1, 2, 3]);
    let body = Body::decode(&extended)?;
    assert_eq!(body.control, Some(Control::Ack(ack)));
    assert_eq!(body.message, Some(payload.as_slice()));
    assert_eq!(body.padding, &[1, 2, 3]);
    let mut rekey = [0; 36];
    Rekey([6; 32]).encode(&mut rekey)?;
    assert_eq!(&rekey[..4], &[0, 36, 5, 182]);
    assert_eq!(Rekey::decode_prefix(&rekey)?, (Rekey([6; 32]), 36));
    for n in [0, 1, 2, 3, 71] {
        assert!(Ack::decode_prefix(&b[..n]).is_err());
    }
    for n in [0, 1, 2, 3, 35] {
        assert!(Rekey::decode_prefix(&rekey[..n]).is_err());
    }
    assert!(Body::decode(&[0, 0, 0, 0]).is_err());
    assert!(Body::decode(&[0, 9, 0, 0]).is_err());
    Ok(())
}
#[test]
fn source_kid_formula_is_explicitly_distinct_from_the_lsd0007_expand_only_formula()
-> Result<(), Error> {
    let master = gnunet_session_crypto::Prk::from_bytes([0x33; 32]);
    let actual = gnunet_session_crypto::session::udp_key_id(&master, 1)?;
    let mut draft = [0; 32];
    master.expand(
        &[b"gnunet-communicator-udp-kid", &1u32.to_be_bytes()],
        &mut draft,
    )?;
    assert_ne!(actual, draft);
    Ok(())
}
