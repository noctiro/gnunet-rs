//! Exact purpose region and multi-hop signature authority tests.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible regressions assert independent protocol bytes and original-owner transitions."
)]
use gnunet_crypto::{EddsaPrivateKey, hash512};
use gnunet_dht::path::{self, Failure};
use gnunet_types::Error;
use gnunet_wire::official::dht::Path;
fn entry(
    key: &EddsaPrivateKey,
    pred: &[u8; 32],
    succ: &[u8; 32],
    payload: &[u8],
    exp: u64,
) -> Result<[u8; 96], Error> {
    let sig = key.sign(6, &path::region(&hash512(payload), exp, pred, succ))?;
    let mut out = [0; 96];
    out[..64].copy_from_slice(sig.as_bytes());
    out[64..].copy_from_slice(key.public_key().as_bytes());
    Ok(out)
}
#[test]
fn region_is_exact_purpose_expiration_hash_predecessor_successor() {
    let b = path::region(&[5; 64], 0x0102030405060708, &[7; 32], &[9; 32]);
    assert_eq!(
        &b[..16],
        &[0, 0, 0, 144, 0, 0, 0, 6, 1, 2, 3, 4, 5, 6, 7, 8]
    );
    assert_eq!(&b[16..80], &[5; 64]);
    assert_eq!(&b[80..112], &[7; 32]);
    assert_eq!(&b[112..], &[9; 32]);
}
#[test]
fn put_get_chain_binds_actual_signers_all_links_payload_and_recipient() -> Result<(), Error> {
    let a = EddsaPrivateKey::from_seed([1; 32]);
    let b = EddsaPrivateKey::from_seed([2; 32]);
    let c = EddsaPrivateKey::from_seed([3; 32]);
    let a_id = *a.public_key().as_bytes();
    let b_id = *b.public_key().as_bytes();
    let c_id = *c.public_key().as_bytes();
    let payload = b"real original block";
    let exp = 0x0102030405060708;
    let pp = entry(&a, &[0; 32], &b_id, payload, exp)?;
    let gp = entry(&b, &a_id, &c_id, payload, exp)?;
    path::verify(payload, exp, None, Path::new(&pp)?, Path::new(&gp)?, &c_id)
        .map_err(|_| Error::Authentication)?;
    assert!(path::verify(b"other", exp, None, Path::new(&pp)?, Path::new(&gp)?, &c_id).is_err());
    assert!(
        path::verify(
            payload,
            exp + 1,
            None,
            Path::new(&pp)?,
            Path::new(&gp)?,
            &c_id
        )
        .is_err()
    );
    assert!(path::verify(payload, exp, None, Path::new(&pp)?, Path::new(&gp)?, &a_id).is_err());
    // Last sender is C, whose separate signature is not already part of either path.
    let recipient = [4; 32];
    let sig = c.sign(6, &path::region(&hash512(payload), exp, &b_id, &recipient))?;
    path::verify_incoming(
        payload,
        exp,
        exp,
        None,
        Path::new(&pp)?,
        Path::new(&gp)?,
        &c_id,
        &recipient,
        sig.as_bytes(),
    )?;
    assert_eq!(
        path::verify_incoming(
            payload,
            exp,
            exp + 1,
            None,
            Path::new(&pp)?,
            Path::new(&gp)?,
            &c_id,
            &recipient,
            sig.as_bytes()
        ),
        Err(Error::Stale)
    );
    assert_eq!(
        path::verify_incoming(
            payload,
            exp,
            0,
            None,
            Path::new(&pp)?,
            Path::new(&gp)?,
            &a_id,
            &recipient,
            sig.as_bytes()
        ),
        Err(Error::Authentication)
    );
    Ok(())
}
#[test]
fn invalid_prefix_requires_explicit_truncation_and_suffix_reverification() -> Result<(), Error> {
    let a = EddsaPrivateKey::from_seed([1; 32]);
    let b = EddsaPrivateKey::from_seed([2; 32]);
    let aid = *a.public_key().as_bytes();
    let bid = *b.public_key().as_bytes();
    let recipient = [3; 32];
    let mut pp = entry(&a, &[0; 32], &bid, b"block", 99)?;
    pp[1] ^= 1;
    let gp = entry(&b, &aid, &recipient, b"block", 99)?;
    let failure = path::verify(
        b"block",
        99,
        None,
        Path::new(&pp)?,
        Path::new(&gp)?,
        &recipient,
    )
    .err()
    .ok_or(Error::InvalidInput)?;
    assert_eq!(
        failure,
        Failure {
            index: 0,
            reason: gnunet_types::Error::Authentication
        }
    );
    let suffix = path::suffix(Path::new(&pp)?, Path::new(&gp)?, failure)?;
    assert!(suffix.put.is_empty());
    assert_eq!(suffix.get.len(), 1);
    assert_eq!(suffix.truncated, aid);
    path::verify(
        b"block",
        99,
        Some(&suffix.truncated),
        suffix.put,
        suffix.get,
        &recipient,
    )
    .map_err(|_| Error::Authentication)?;
    assert!(path::verify(b"block", 99, None, suffix.put, suffix.get, &recipient).is_err());
    assert_eq!(
        path::suffix(
            Path::empty(),
            Path::empty(),
            Failure {
                index: 0,
                reason: gnunet_types::Error::Authentication
            }
        ),
        Err(Error::InvalidInput)
    );
    Ok(())
}
