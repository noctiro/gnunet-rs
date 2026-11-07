//! Public bytes only: no private seed, entropy, crypto, hash, store or native IO.
use gnunet_did::{self as did, Did, RecordForm};
use gnunet_gnsrecord::{RecordData, RecordFlags, RecordSet, RecordType, ZoneKey, ZoneKeyType};
use gnunet_json::{Nest, Token, Workspace};
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "One public format model asserts actual codec and document selection with fallible setup"
)]
fn actual_method_template_and_current_producer_selection() -> Result<(), gnunet_types::Error> {
    // Deliberately unvalidated public bytes, never a private key or point proof.
    let zone = ZoneKey::new(ZoneKeyType::Edkey, [0x42; 32]);
    let id = Did::from_public(zone);
    let mut name = [0; did::DID_BYTES];
    assert_eq!(Did::parse(id.write(&mut name)?)?, id);
    let mut document = [0; did::TEMPLATE_BYTES];
    did::template(id, &mut document)?;
    let mut payload = [0; 2048];
    let mut tokens = [Token::EMPTY; 128];
    let mut stack = [Nest::EMPTY; 16];
    let limits = gnunet_json::Limits {
        bytes: 2048,
        nodes: 128,
        depth: 16,
        work: 100_000,
    };
    let mut workspace = Workspace::new(&mut payload, &mut tokens, &mut stack);
    did::check_document(id, &document, &mut workspace, limits)?;
    let mut encoded = [0; 2048];
    let txt = RecordData {
        expiration_time: 1,
        record_type: RecordType::TXT,
        flags: RecordFlags::from_bits_preserve(0),
        data: &document,
    };
    let authoritative = RecordData {
        record_type: RecordType::DID_DOCUMENT,
        ..txt
    };
    let bytes = gnunet_gnsrecord::serialize(&[txt], &mut encoded)?;
    let chosen = did::select(
        RecordSet::parse(&encoded[..bytes], 1, 4)?,
        id,
        &mut workspace,
        limits,
    )?
    .ok_or(gnunet_types::Error::NotFound)?;
    assert_eq!(chosen.form(), RecordForm::CurrentProducerTxt);
    let bytes = gnunet_gnsrecord::serialize(&[txt, authoritative], &mut encoded)?;
    let chosen = did::select(
        RecordSet::parse(&encoded[..bytes], 2, 4)?,
        id,
        &mut workspace,
        limits,
    )?
    .ok_or(gnunet_types::Error::NotFound)?;
    assert_eq!(chosen.form(), RecordForm::Authoritative);
    // A second valid matching-ID authoritative document with different bytes
    // cannot be silently selected in place of the original one.
    let mut padded = [0; did::TEMPLATE_BYTES + 1];
    padded[0] = b' ';
    padded[1..].copy_from_slice(&document);
    let conflicting = RecordData {
        data: &padded,
        ..authoritative
    };
    let bytes = gnunet_gnsrecord::serialize(&[authoritative, conflicting], &mut encoded)?;
    assert!(matches!(
        did::select(
            RecordSet::parse(&encoded[..bytes], 2, 4)?,
            id,
            &mut workspace,
            limits
        ),
        Err(gnunet_types::Error::Conflict)
    ));
    Ok(())
}
