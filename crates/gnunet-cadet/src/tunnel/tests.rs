//! Deterministic fixture keys only; no C encrypted interoperability claim.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible crypto tests assert public observations and deterministic fixture vectors"
)]
use super::*;

const PLAIN: [u8; 4] = [0, 4, 3, 244]; // Official header-only channel KEEPALIVE.

struct Draw {
    value: u8,
    calls: usize,
    fail: bool,
}
impl Draw {
    fn new() -> Self {
        Self {
            value: 17,
            calls: 0,
            fail: false,
        }
    }
}
impl Entropy for Draw {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        self.calls += 1;
        out.fill(self.value);
        self.value = self.value.checked_add(1).ok_or(Error::Entropy)?;
        if self.fail {
            Err(Error::Entropy)
        } else {
            Ok(())
        }
    }
}

fn with_pair<const N: usize>(
    test: impl for<'id, 'slots> FnOnce(
        &mut Session<'id, 'slots>,
        &mut Session<'id, 'slots>,
    ) -> Result<(), Error>,
) -> Result<(), Error> {
    let first = Identity::from_seed([1; 32]);
    let second = Identity::from_seed([2; 32]);
    let (alice, betty) = if first.peer() < second.peer() {
        (first, second)
    } else {
        (second, first)
    };
    let domain = context::Instance::new();
    let mut context_rows = [const { context::Slot::new() }; 2];
    let mut registry = context::Registry::new(&domain, &mut context_rows)?;
    let alice_context = registry.allocate(alice.peer(), betty.peer())?;
    let betty_context = registry.allocate(betty.peer(), alice.peer())?;
    assert_eq!(alice_context.role(), Role::Alice);
    assert_eq!(betty_context.role(), Role::Betty);
    let a_keys = LocalKeys {
        ephemeral: EcdheSecret::from_bytes([3; 32]),
        ratchet: EcdheSecret::from_bytes([4; 32]),
    };
    let b_keys = LocalKeys {
        ephemeral: EcdheSecret::from_bytes([5; 32]),
        ratchet: EcdheSecret::from_bytes([6; 32]),
    };
    let a_exchange = a_keys.exchange();
    let b_exchange = b_keys.exchange();
    let mut a_skip = [const { SkippedSlot::new() }; N];
    let mut a_stage = [const { SkippedSlot::new() }; N];
    let mut b_skip = [const { SkippedSlot::new() }; N];
    let mut b_stage = [const { SkippedSlot::new() }; N];
    let limits = Limits {
        plaintext_bytes: 256,
        maximum_gap: 256,
    };
    let mut a = Session::new(
        alice_context,
        &alice,
        a_keys,
        b_exchange,
        Storage {
            skipped: &mut a_skip,
            staging: &mut a_stage,
        },
        limits,
    )?;
    let mut b = Session::new(
        betty_context,
        &betty,
        b_keys,
        a_exchange,
        Storage {
            skipped: &mut b_skip,
            staging: &mut b_stage,
        },
        limits,
    )?;
    test(&mut a, &mut b)
}

fn proof(session: &Session<'_, '_>) -> Result<(Exchange, [u8; 64]), Error> {
    let PeerMessage::KeyExchangeAuth {
        ephemeral_key,
        ratchet_key,
        auth,
        ..
    } = session.initial_auth(session.scope(), [9; 32], false)?
    else {
        return Err(Error::Malformed);
    };
    Ok((
        Exchange {
            ephemeral_key,
            ratchet_key,
        },
        auth,
    ))
}
fn confirm(a: &mut Session<'_, '_>, b: &mut Session<'_, '_>) -> Result<(), Error> {
    let (a_exchange, a_proof) = proof(a)?;
    let (b_exchange, b_proof) = proof(b)?;
    assert_eq!(a_proof, b_proof); // Public proof only, never RK/CK/MK/private bytes.
    a.verify_initial_auth(a.scope(), b_exchange, &b_proof)?;
    b.verify_initial_auth(b.scope(), a_exchange, &a_proof)?;
    Ok(())
}
fn seal(
    session: &mut Session<'_, '_>,
    buffer: &mut [u8],
    entropy: &mut Draw,
) -> Result<usize, Error> {
    Ok(session
        .seal(session.scope(), [9; 32], &PLAIN, buffer, entropy)?
        .bytes()
        .len())
}

#[test]
fn chain_context_nuls_match_independent_standard_hmac_fixture() -> Result<(), Error> {
    // Generated independently with Python stdlib HMAC-SHA512 extract /
    // HMAC-SHA256 expand, including the two exact C context NUL terminators.
    let (message, next) = keys::chain(&Zeroizing::new([7; 32]))?;
    let expected_message = [
        0x12, 0xff, 0x6f, 0x60, 0x46, 0x30, 0xb6, 0x38, 0xdb, 0x23, 0xf1, 0x0d, 0xff, 0xef, 0xa7,
        0x15, 0x02, 0xad, 0x6e, 0x59, 0x09, 0xae, 0xc0, 0x4d, 0x16, 0xe3, 0xdf, 0xd4, 0xdd, 0xf2,
        0x89, 0xc0,
    ];
    let expected_next = [
        0x19, 0xeb, 0x6d, 0xb4, 0xd0, 0x45, 0x65, 0x50, 0x57, 0x01, 0xd7, 0x30, 0x3f, 0x28, 0x33,
        0x1c, 0x93, 0x9d, 0x6e, 0xd3, 0x92, 0x15, 0xd9, 0xc4, 0x68, 0xf7, 0x3a, 0xbc, 0x3a, 0x41,
        0xdc, 0x90,
    ];
    assert!(bool::from(message.ct_eq(&expected_message)));
    assert!(bool::from(next.ct_eq(&expected_next)));
    Ok(())
}

#[test]
fn original_kx_proof_and_source_bind_without_duplicate_reinitialization() -> Result<(), Error> {
    with_pair::<2>(|a, b| {
        let original = a.snapshot();
        let mut output = [0xa5; 128];
        let mut entropy = Draw::new();
        assert!(matches!(
            a.seal(a.scope(), [9; 32], &PLAIN, &mut output, &mut entropy),
            Err(Error::NotReady)
        ));
        assert!(matches!(
            a.seal(b.scope(), [9; 32], &PLAIN, &mut output, &mut entropy),
            Err(Error::StaleGeneration)
        ));
        assert_eq!(output, [0xa5; 128]);
        assert_eq!(entropy.calls, 0);
        let (exchange, correct) = proof(b)?;
        let mut bad = correct;
        bad[0] ^= 1;
        assert_eq!(
            a.verify_initial_auth(a.scope(), exchange, &bad),
            Err(Error::Authentication)
        );
        assert_eq!(a.snapshot(), original);
        let mut wrong_exchange = exchange;
        wrong_exchange.ratchet_key[0] ^= 1;
        assert_eq!(
            a.verify_initial_auth(a.scope(), wrong_exchange, &correct),
            Err(Error::Authentication)
        );
        assert_eq!(a.snapshot(), original);
        confirm(a, b)?;
        let established = a.snapshot();
        assert_eq!(
            a.verify_initial_auth(a.scope(), exchange, &correct),
            Err(Error::Replay)
        );
        assert_eq!(a.snapshot(), established);
        Ok(())
    })
}

#[test]
fn real_dh_ratchets_and_old_skipped_keys_commit_only_after_both_tags() -> Result<(), Error> {
    with_pair::<4>(|a, b| {
        confirm(a, b)?;
        let mut entropy = Draw::new();
        let mut packets = [[0; 128]; 3];
        let mut sizes = [0; 3];
        for (packet, size) in packets.iter_mut().zip(sizes.iter_mut()) {
            *size = seal(a, packet, &mut entropy)?;
        }
        assert_eq!(a.snapshot().sent, 3);
        assert_eq!(entropy.calls, 1); // Only the first forced Alice send ratchets.
        let mut output = [0xa5; 32];
        let before = b.snapshot();
        let mut bad = packets[2];
        bad[40] ^= 1; // The real received header MAC, not an uninitialized tag.
        assert!(matches!(
            b.open(b.scope(), &bad[..sizes[2]], &mut output),
            Err(Error::Authentication)
        ));
        assert_eq!(&output[..4], &[0; 4]);
        assert_eq!(b.snapshot(), before);
        // A malicious fixture peer knows HK: rebuild a valid header MAC over
        // a corrupted body tag. Even this must not commit staged gap/DH keys.
        let mut bad_body = packets[2];
        bad_body[sizes[2] - 1] ^= 1;
        let (prefix, body) = bad_body[..sizes[2]].split_at_mut(ENCRYPTED_PREFIX);
        AxHeader {
            sent: 2,
            previous_sent: 0,
            ratchet_key: a.local_ratchet_public,
        }
        .encode(&mut prefix[56..96])?;
        let header_key = a.keys.send_header.as_ref().ok_or(Error::NotReady)?;
        let nonce = keys::nonce(header_key)?;
        let rebuilt = xchacha20poly1305_seal(header_key, &nonce, body, &mut prefix[56..96])?;
        prefix[40..56].copy_from_slice(&rebuilt);
        assert!(matches!(
            b.open(b.scope(), &bad_body[..sizes[2]], &mut output),
            Err(Error::Authentication)
        ));
        assert_eq!(&output[..4], &[0; 4]);
        assert_eq!(b.snapshot(), before);
        let accepted = b.open(b.scope(), &packets[2][..sizes[2]], &mut output)?;
        assert_eq!(accepted.bytes(), &PLAIN);
        assert_eq!(accepted.header().sent, 2);
        assert_eq!(b.snapshot().received, 3);
        assert_eq!(b.snapshot().skipped, 2);
        assert!(b.snapshot().ratchet_allowed);

        // Betty advances using her original DHR secret and Alice's fresh key.
        b.request_ratchet(b.scope())?;
        let mut reply = [0; 128];
        let reply_len = seal(b, &mut reply, &mut entropy)?;
        assert_eq!(
            a.open(a.scope(), &reply[..reply_len], &mut output)?.bytes(),
            &PLAIN
        );
        assert!(a.snapshot().ratchet_allowed);
        a.request_ratchet(a.scope())?;
        let mut advanced = [0; 128];
        let advanced_len = seal(a, &mut advanced, &mut entropy)?;
        let accepted = b.open(b.scope(), &advanced[..advanced_len], &mut output)?;
        assert_eq!(accepted.header().previous_sent, 3);
        assert_eq!(accepted.header().sent, 0);
        assert_eq!(b.snapshot().received, 1);
        assert_eq!(b.snapshot().skipped, 2);
        assert_eq!(
            b.open(b.scope(), &packets[0][..sizes[0]], &mut output)?
                .bytes(),
            &PLAIN
        );
        assert_eq!(b.snapshot().received, 1); // Old packet did not rewind chain.
        assert_eq!(b.snapshot().skipped, 1);
        let before_replay = b.snapshot();
        assert!(
            b.open(b.scope(), &packets[0][..sizes[0]], &mut output)
                .is_err()
        );
        assert_eq!(b.snapshot(), before_replay);
        assert_eq!(
            b.open(b.scope(), &packets[1][..sizes[1]], &mut output)?
                .bytes(),
            &PLAIN
        );
        assert_eq!(b.snapshot().skipped, 0);
        Ok(())
    })
}

#[test]
fn preflight_entropy_cancel_and_full_cache_never_reuse_or_consume_keys() -> Result<(), Error> {
    with_pair::<1>(|a, b| {
        confirm(a, b)?;
        let original = a.snapshot();
        let mut entropy = Draw::new();
        let mut output = [0xa5; 128];
        assert!(matches!(
            a.seal(a.scope(), [9; 32], &PLAIN, &mut output[..115], &mut entropy),
            Err(Error::Capacity)
        ));
        assert_eq!(output, [0xa5; 128]);
        assert_eq!(entropy.calls, 0);
        entropy.fail = true;
        assert!(matches!(
            a.seal(a.scope(), [9; 32], &PLAIN, &mut output, &mut entropy),
            Err(Error::Entropy)
        ));
        assert_eq!(a.snapshot(), original);
        assert_eq!(output, [0xa5; 128]);
        entropy.fail = false;
        let mut packets = [[0; 128]; 4];
        let mut sizes = [0; 4];
        for (packet, size) in packets.iter_mut().zip(sizes.iter_mut()) {
            *size = seal(a, packet, &mut entropy)?;
        }
        // Dropping each Sealed view did not restore an old message key/counter.
        assert_eq!(a.snapshot().sent, 4);
        assert_ne!(&packets[0][96..sizes[0]], &packets[1][96..sizes[1]]);
        b.open(b.scope(), &packets[1][..sizes[1]], &mut output)?;
        assert_eq!(b.snapshot().skipped, 1);
        let full = b.snapshot();
        output.fill(0xa5);
        assert!(matches!(
            b.open(b.scope(), &packets[3][..sizes[3]], &mut output),
            Err(Error::Capacity)
        ));
        assert_eq!(output, [0xa5; 128]);
        assert_eq!(b.snapshot(), full);
        b.open(b.scope(), &packets[0][..sizes[0]], &mut output)?;
        assert_eq!(b.snapshot().skipped, 0);
        b.open(b.scope(), &packets[3][..sizes[3]], &mut output)?;
        assert_eq!(b.snapshot().received, 4);
        assert_eq!(b.snapshot().skipped, 1);
        Ok(())
    })
}
