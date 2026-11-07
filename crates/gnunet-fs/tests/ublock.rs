//! Official C API vectors and focused UBLOCK authentication/refusal controls.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions compare real C UBLOCK vectors and tamper boundaries"
)]
use gnunet_crypto::gns::EdkeySecret;
use gnunet_fs::{
    Content, Uri, metadata as md,
    ublock::{Context, Error, Limits, PURPOSE, Publisher, verify_block},
};
type TestResult = Result<(), Box<dyn std::error::Error>>;
const LABEL: &[u8] = b"\xffx\x80";
const UPDATE: &[u8] = b"\xfenext";
const C_NAMESPACE: &[u8] = include_bytes!("ublock_vectors/c-namespace.bin");
const C_NAMESPACE_PLAIN: &[u8] = include_bytes!("ublock_vectors/c-namespace.plain");
const C_KEYWORD: &[u8] = include_bytes!("ublock_vectors/c-keyword.bin");
const C_KEYWORD_PLAIN: &[u8] = include_bytes!("ublock_vectors/c-keyword.plain");
fn uri() -> Uri<'static> {
    Content {
        key: [0; 64],
        query: [0; 64],
        size: 0,
    }
    .uri()
}

#[test]
fn official_c_raw_label_signature_encryption_and_complete_wire_match() -> TestResult {
    let secret = EdkeySecret::from_seed([17; 32]);
    let publisher = Publisher::namespace(&secret, LABEL, Limits::default())?;
    let lookup = Context::namespace(&secret.public_key(), LABEL, Limits::default())?;
    assert_eq!(lookup.query(), publisher.context().query());
    assert_eq!(lookup.verification_key().as_slice(), &C_NAMESPACE[72..104]);
    let mut order = [];
    let mut plain = [];
    let metadata = md::plan_uncompressed(
        &[],
        &mut order,
        &mut plain,
        md::Limits::default(),
        md::Options::default(),
    )?;
    let mut wire = vec![0xa7; C_NAMESPACE.len() + 5];
    let sealed = publisher.seal(UPDATE, uri(), Some(&metadata), &mut wire)?;
    assert_eq!(sealed.bytes(), C_NAMESPACE);
    assert_eq!(
        sealed
            .metadata_selection()
            .ok_or(Error::Framing)?
            .selected_entries,
        0
    );
    verify_block(
        sealed.bytes(),
        lookup.query(),
        Limits::default().max_wire_bytes,
    )?;
    assert_eq!(&wire[C_NAMESPACE.len()..], &[0xa7; 5]);
    let mut decrypted = vec![0xa7; C_NAMESPACE_PLAIN.len() + 5];
    let opened = lookup.open(C_NAMESPACE, &mut decrypted)?;
    assert_eq!(opened.bytes(), C_NAMESPACE_PLAIN);
    let mut metadata_plain = [];
    let record = opened.decode(&mut metadata_plain, &mut md::NoCodec, md::Mode::Strict)?;
    assert_eq!(record.update_identifier(), UPDATE);
    assert!(
        matches!(record.uri()?, Uri::Content(c) if c.size == 0 && c.key == [0;64] && c.query == [0;64])
    );
    assert!(
        record
            .metadata()
            .is_some_and(|value| value.is_complete() && value.accepted_entries() == 0)
    );
    assert_eq!(&decrypted[C_NAMESPACE_PLAIN.len()..], &[0xa7; 5]);
    Ok(())
}

#[test]
fn anonymous_keyword_absence_and_present_empty_are_distinct_and_refusals_are_atomic() -> TestResult
{
    let publisher = Publisher::keyword(b"keyword", Limits::default())?;
    let lookup = Context::keyword(b"keyword", Limits::default())?;
    let mut wire = vec![0xa7; 1024];
    let sealed = publisher.seal(b"", uri(), None, &mut wire)?;
    assert_eq!(sealed.bytes(), C_KEYWORD);
    assert!(sealed.metadata_selection().is_none());
    let mut decrypted = [0; 1024];
    let opened = lookup.open(C_KEYWORD, &mut decrypted)?;
    assert_eq!(opened.bytes(), C_KEYWORD_PLAIN);
    let mut scratch = [];
    let record = opened.decode(&mut scratch, &mut md::NoCodec, md::Mode::Strict)?;
    assert!(record.update_identifier().is_empty() && record.metadata().is_none());
    let mut order = [];
    let mut metadata_scratch = [];
    let empty = md::plan_uncompressed(
        &[],
        &mut order,
        &mut metadata_scratch,
        md::Limits::default(),
        md::Options::default(),
    )?;
    let present = publisher.seal(b"", uri(), Some(&empty), &mut wire)?;
    assert_eq!(present.bytes().len(), C_KEYWORD.len() + 12);
    let opened = lookup.open(present.bytes(), &mut decrypted)?;
    assert!(
        opened
            .decode(&mut scratch, &mut md::NoCodec, md::Mode::Strict)?
            .metadata()
            .is_some()
    );
    let mut refused = [0xa7; 32];
    assert!(matches!(
        publisher.seal(b"", uri(), None, &mut refused),
        Err(Error::Capacity)
    ));
    assert_eq!(refused, [0xa7; 32]);
    assert!(matches!(
        publisher.seal(b"update", uri(), None, &mut refused),
        Err(Error::Update)
    ));
    assert_eq!(refused, [0xa7; 32]);
    assert!(matches!(
        Context::keyword(b"bad\0label", Limits::default()),
        Err(Error::Label)
    ));
    let secret = EdkeySecret::from_seed([17; 32]);
    assert_ne!(
        Context::namespace(&secret.public_key(), b"e\xcc\x81", Limits::default())?.query(),
        Context::namespace(&secret.public_key(), b"\xc3\xa9", Limits::default())?.query()
    );
    Ok(())
}

#[test]
fn query_signature_and_purpose_fail_before_decryption_but_authenticated_bad_tag_wipes() -> TestResult
{
    let secret = EdkeySecret::from_seed([17; 32]);
    let context = Context::namespace(&secret.public_key(), LABEL, Limits::default())?;
    for offset in [0, 64, 68, 72, 104, C_NAMESPACE.len() - 1] {
        let mut bad = C_NAMESPACE.to_vec();
        bad[offset] ^= 1;
        let mut output = vec![0xa7; C_NAMESPACE_PLAIN.len() + 5];
        assert!(context.open(&bad, &mut output).is_err());
        assert!(output.iter().all(|b| *b == 0xa7));
    }
    let wrong = Context::namespace(&secret.public_key(), b"other", Limits::default())?;
    let mut output = vec![0xa7; C_NAMESPACE_PLAIN.len() + 5];
    assert!(matches!(
        wrong.open(C_NAMESPACE, &mut output),
        Err(Error::Authentication)
    ));
    assert!(output.iter().all(|b| *b == 0xa7));
    let mut bad = C_NAMESPACE.to_vec();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    let signer = secret.derive_bytes(LABEL, b"fs-ublock")?;
    let signature = signer.sign(PURPOSE, &[&bad[64..]])?;
    bad[..64].copy_from_slice(&signature);
    verify_block(&bad, context.query(), Limits::default().max_wire_bytes)?;
    assert!(matches!(
        context.open(&bad, &mut output),
        Err(Error::Crypto(gnunet_types::Error::Authentication))
    ));
    assert!(output[..C_NAMESPACE_PLAIN.len()].iter().all(|b| *b == 0));
    assert_eq!(&output[C_NAMESPACE_PLAIN.len()..], &[0xa7; 5]);
    Ok(())
}
