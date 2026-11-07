//! Local content artifacts and bounded tree ownership through public APIs.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions check artifact bytes and rejection boundaries"
)]
use gnunet_crypto::{hash512, hkdf_gnunet};
use gnunet_fs::content::{self, BLOCK_BYTES, BlockKey, CHK_BYTES, MAX_CHILDREN, TAG_BYTES};
use gnunet_session_crypto::aead::xchacha20poly1305_seal;
use gnunet_types::Error;

fn pattern(length: usize) -> Vec<u8> {
    (0..length).map(|i| (i % 251) as u8).collect()
}
fn sealed(plaintext: &[u8]) -> Result<(BlockKey, Vec<u8>), Error> {
    let mut output = vec![0; plaintext.len() + TAG_BYTES];
    let key = content::encode_data(plaintext, &mut output)?.key();
    Ok((key, output))
}
fn references(count: usize) -> Vec<BlockKey> {
    (0..count)
        .map(|i| BlockKey {
            key: [i as u8; 64],
            query: [(i as u8).wrapping_add(7); 64],
        })
        .collect()
}

#[test]
fn data_boundaries_are_deterministic_and_capacity_rejection_is_atomic() -> Result<(), Error> {
    for length in [0, 1, 15, 16, 17, 127, 128, BLOCK_BYTES - 1, BLOCK_BYTES] {
        let input = pattern(length);
        let (key, bytes) = sealed(&input)?;
        assert_eq!(key.key, hash512(&input));
        assert_eq!(key.query, hash512(&bytes));
        assert_eq!(sealed(&input)?, (key, bytes.clone()));
        let mut output = vec![0xa7; length + 3];
        assert_eq!(content::open_data(key, &bytes, &mut output)?, input);
        assert_eq!(&output[length..], &[0xa7; 3]);
        for capacity in [0, length + TAG_BYTES - 1] {
            let mut short = vec![0x55; capacity];
            assert!(matches!(
                content::encode_data(&input, &mut short),
                Err(Error::Capacity)
            ));
            assert!(short.iter().all(|b| *b == 0x55));
        }
        if length > 0 {
            let mut short = vec![0x55; length - 1];
            assert_eq!(
                content::open_data(key, &bytes, &mut short),
                Err(Error::Capacity)
            );
            assert!(short.iter().all(|b| *b == 0x55));
        }
    }
    let mut untouched = [0x55; 32];
    assert!(matches!(
        content::encode_data(&vec![0; BLOCK_BYTES + 1], &mut untouched),
        Err(Error::TooLarge)
    ));
    assert_eq!(
        content::open_data(BlockKey::default(), &[0; TAG_BYTES - 1], &mut untouched),
        Err(Error::Truncated)
    );
    assert_eq!(
        content::open_data(
            BlockKey::default(),
            &vec![0; BLOCK_BYTES + TAG_BYTES + 1],
            &mut untouched
        ),
        Err(Error::TooLarge)
    );
    assert_eq!(untouched, [0x55; 32]);
    Ok(())
}

#[test]
fn query_tag_and_plaintext_key_are_three_independent_authentication_checks() -> Result<(), Error> {
    let input = b"a local artifact";
    let (key, bytes) = sealed(input)?;
    let mut wrong_query = key;
    wrong_query.query[0] ^= 1;
    let mut bad_tag = bytes.clone();
    *bad_tag.last_mut().ok_or(Error::Malformed)? ^= 1;
    let tag_key = BlockKey {
        query: hash512(&bad_tag),
        ..key
    };
    let mut wrong_key = key;
    wrong_key.key[0] ^= 1;
    for (reference, ciphertext) in [
        (wrong_query, bytes.as_slice()),
        (tag_key, &bad_tag),
        (wrong_key, &bytes),
    ] {
        let mut output = vec![0xa7; input.len() + 3];
        assert_eq!(
            content::open_data(reference, ciphertext, &mut output),
            Err(Error::Authentication)
        );
        assert!(output[..input.len()].iter().all(|b| *b == 0));
        assert_eq!(&output[input.len()..], &[0xa7; 3]);
    }
    // Forge a valid query AND tag under material from H(A), but encrypt B.
    // Only checking the plaintext hash catches this self-consistent false CHK.
    let mut secret = [0; 32];
    let mut nonce = [0; 24];
    hkdf_gnunet(b"Hash key derivation", &key.key, &[], &mut secret)?;
    hkdf_gnunet(
        b"Initialization vector derivation",
        &key.key,
        &[],
        &mut nonce,
    )?;
    let mut forged = input.to_vec();
    forged[0] ^= 1;
    let tag = xchacha20poly1305_seal(&secret, &nonce, &[], &mut forged)?;
    forged.extend_from_slice(&tag);
    let reference = BlockKey {
        query: hash512(&forged),
        ..key
    };
    let mut output = vec![0xa7; input.len()];
    assert_eq!(
        content::open_data(reference, &forged, &mut output),
        Err(Error::Authentication)
    );
    assert!(output.iter().all(|b| *b == 0));
    Ok(())
}

#[test]
fn index_has_only_ordered_raw_chks_and_rejects_count_shape_or_capacity() -> Result<(), Error> {
    for count in [1, 2, MAX_CHILDREN] {
        let mut children = references(count);
        if count > 1 {
            children[count - 1] = children[0];
        }
        let mut scratch = vec![0xa7; count * CHK_BYTES + 2];
        let mut output = vec![0xa7; count * CHK_BYTES + TAG_BYTES + 3];
        let encoded = content::encode_index(&children, &mut scratch, &mut output)?;
        let mut plain = vec![0xa7; count * CHK_BYTES];
        let index = content::open_index(encoded.key(), encoded.bytes(), &mut plain)?;
        assert_eq!(index.len(), count);
        assert!(!index.is_empty());
        assert_eq!(index.keys().collect::<Vec<_>>(), children);
        for (i, expected) in children.iter().enumerate() {
            assert_eq!(index.key(i)?, *expected);
        }
        assert_eq!(index.key(count), Err(Error::InvalidInput));
        for (chunk, child) in plain.as_chunks::<CHK_BYTES>().0.iter().zip(children) {
            assert_eq!(&chunk[..64], &child.key);
            assert_eq!(&chunk[64..], &child.query);
        }
        assert_eq!(&scratch[count * CHK_BYTES..], &[0xa7; 2]);
        assert_eq!(&output[count * CHK_BYTES + TAG_BYTES..], &[0xa7; 3]);
    }
    for count in [0, MAX_CHILDREN + 1] {
        let mut scratch = vec![0x55; (MAX_CHILDREN + 1) * CHK_BYTES];
        let mut output = scratch.clone();
        assert!(matches!(
            content::encode_index(&references(count), &mut scratch, &mut output),
            Err(Error::InvalidInput)
        ));
        assert!(scratch.iter().chain(&output).all(|b| *b == 0x55));
    }
    for (slen, olen) in [(127, 144), (128, 143)] {
        let mut scratch = vec![0x55; slen];
        let mut output = vec![0x55; olen];
        assert!(matches!(
            content::encode_index(&references(1), &mut scratch, &mut output),
            Err(Error::Capacity)
        ));
        assert!(scratch.iter().chain(&output).all(|b| *b == 0x55));
    }
    for length in [0, 1, CHK_BYTES - 1, CHK_BYTES + 1] {
        let (key, bytes) = sealed(&vec![0; length])?;
        let mut output = [0x55; CHK_BYTES + 1];
        assert!(matches!(
            content::open_index(key, &bytes, &mut output),
            Err(Error::Malformed)
        ));
        assert!(output.iter().all(|b| *b == 0x55));
    }
    Ok(())
}
