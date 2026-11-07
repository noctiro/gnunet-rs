//! One structural public model. No signature, hash, PoW, entropy or key runs.
use gnunet_gnsrecord::{ZoneKey, ZoneKeyType};
use gnunet_revocation::{
    Certificate, NONCES, PROOF_BYTES, Proof,
    ipc::{Request, Response},
};
use gnunet_types::Error;
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "One public structural codec model uses fallible setup and assertions"
)]
fn original_public_certificate_framing_and_raw_status() -> Result<(), Error> {
    let zone = ZoneKey::new(ZoneKeyType::Edkey, [0x42; 32]);
    let nonces = core::array::from_fn::<_, NONCES, _>(|i| i as u64 + 7);
    // Public zero bytes are deliberately not presented as a valid signature.
    let certificate = Certificate::from_parts(zone, 100, 999, &nonces, &[0; 64]);
    let proof = certificate.proof()?;
    assert_eq!(proof.timestamp(), 100);
    assert_eq!(proof.ttl(), 999);
    assert!(proof.ordered());
    assert_eq!(proof.nonce(31)?, 38);
    assert_eq!(proof.public()?, zone);
    let signed = proof.signing_message();
    assert_eq!(&signed[..8], &[0, 0, 0, 52, 0, 0, 0, 3]);
    assert_eq!(&signed[8..16], &100u64.to_be_bytes());
    assert_eq!(&signed[16..], &zone.to_wire());
    let mut wire = [0; 380];
    assert_eq!(Request::Query(zone).encode(&mut wire)?, 44);
    assert_eq!(&wire[..8], &[0, 44, 2, 124, 0, 0, 0, 36]);
    assert!(matches!(Request::decode(&wire[..44])?, Request::Query(key) if key==zone));
    let n = Request::Revoke(proof).encode(&mut wire)?;
    assert_eq!(n, 380);
    assert_eq!(&wire[..8], &[1, 124, 2, 126, 0, 0, 1, 116]);
    assert!(
        matches!(Request::decode(&wire)?,Request::Revoke(actual) if actual.bytes()==proof.bytes())
    );
    wire[7] = 115;
    assert!(Request::decode(&wire).is_err());
    assert!(Proof::parse(&certificate.bytes()[..PROOF_BYTES - 1]).is_err());
    let mut short = [0xaa; 7];
    assert_eq!(
        Request::Revoke(proof).encode(&mut short),
        Err(Error::Capacity)
    );
    assert_eq!(short, [0xaa; 7]);
    assert_eq!(Response::Query(0).revoked(), Some(true));
    assert_eq!(Response::Query(1).revoked(), Some(false));
    assert_eq!(Response::Revoke(0).accepted(), Some(true));
    assert_eq!(Response::Revoke(1).accepted(), Some(false));
    for response in [Response::Query(u32::MAX), Response::Revoke(u32::MAX)] {
        let mut encoded = [0; 8];
        response.encode(&mut encoded)?;
        assert_eq!(Response::decode(&encoded)?, response);
        assert_eq!(response.revoked(), None);
        assert_eq!(response.accepted(), None);
    }
    Ok(())
}
