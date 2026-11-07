//! Public nonsecret shape cases only. No actual key, signing, proof or native
//! producer is executed by these source cases, and no authenticity is inferred.
use crate::{AbdLayout, Error, RecordType, abd, helpers::Writer};
use gnunet_wire::official::abd::{Delegate, EDKEY, Key, Policy, SignedDelegate};
fn key(byte: u8) -> [u8; 36] {
    let mut bytes = [byte; 36];
    bytes[..4].copy_from_slice(&EDKEY.to_be_bytes());
    bytes
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Independent original signed-field/grammar assertions, not signature verification"
)]
fn delegate_preserves_original_case_unicode_subject_role_and_internal_bar() -> Result<(), Error> {
    let issuer = key(1);
    let subject = key(2);
    let mut signature = [0xa5; 68];
    signature[..4].copy_from_slice(&EDKEY.to_be_bytes());
    let value = Delegate {
        signature: &signature,
        issuer: Key::new(&issuer)?,
        subject: Key::new(&subject)?,
        expiration_us: 1_900_000_000_000_001,
        issuer_attribute: b"Owner|Admin",
        subject_attribute: Some("membre.Café".as_bytes()),
    };
    let mut original = [0; 1024];
    let n = value.encode_record(&mut original)?;
    let mut text = [0; 2048];
    let text_len = {
        let mut out = Writer::new(&mut text);
        abd::format(
            RecordType::DELEGATE,
            &original[..n],
            &mut out,
            AbdLayout { align64: 4 },
        )?;
        out.len()
    };
    let text = core::str::from_utf8(&text[..text_len]).map_err(|_| Error::Malformed)?;
    assert!(text.contains(".Owner|Admin -> "));
    assert!(text.contains(".membre.Café | "));
    assert!(text.ends_with(" | 1900000000000001"));
    let mut restored = [0; 1024];
    let m = {
        let mut out = Writer::new(&mut restored);
        abd::parse(
            RecordType::DELEGATE,
            text,
            &mut out,
            AbdLayout { align64: 8 },
        )?;
        out.len()
    };
    assert_eq!(&restored[..m], &original[..n]);
    let parsed = SignedDelegate::decode(&restored[..m])?.delegate();
    assert_eq!(parsed.issuer_attribute, b"Owner|Admin");
    assert_eq!(parsed.subject_attribute, Some("membre.Café".as_bytes()));
    assert_eq!(parsed.signature, &signature);
    Ok(())
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Independent count/header/ABI/conjunction shape assertions, with no policy authorization"
)]
fn conjunction_uses_selected_header_and_exact_term_order_without_layout_guessing()
-> Result<(), Error> {
    let a = key(3);
    let b = key(4);
    let mut text = [0; 512];
    let size = {
        let mut out = Writer::new(&mut text);
        out.b32(&a)?;
        out.bytes(b" member.editor,")?;
        out.b32(&b)?;
        out.len()
    };
    let text = core::str::from_utf8(&text[..size]).map_err(|_| Error::Malformed)?;
    for align64 in [4, 8] {
        let layout = AbdLayout { align64 };
        let prefix = if align64 == 8 { 16 } else { 12 };
        let mut encoded = [0xff; 1024];
        let n = {
            let mut out = Writer::new(&mut encoded);
            abd::parse(RecordType::ATTRIBUTE, text, &mut out, layout)?;
            out.len()
        };
        assert_eq!(&encoded[..4], &2u32.to_be_bytes());
        assert_eq!(n, prefix + 40 + b"member.editor\0".len() + 40);
        assert_eq!(&encoded[prefix..prefix + 36], &a);
        let policy = Policy::decode(&encoded[..n], layout)?;
        let mut terms = policy.iter();
        let first = terms.next().ok_or(Error::NotReady)?;
        let second = terms.next().ok_or(Error::NotReady)?;
        assert_eq!(first.attribute, Some(b"member.editor".as_slice()));
        assert_eq!(second.subject.bytes(), &b);
        assert_eq!(second.attribute, None);
        assert!(terms.next().is_none());
        assert!(
            Policy::decode(
                &encoded[..n],
                AbdLayout {
                    align64: if align64 == 8 { 4 } else { 8 }
                }
            )
            .is_err()
        );
        let mut restored = [0; 512];
        let m = {
            let mut out = Writer::new(&mut restored);
            abd::format(RecordType::ATTRIBUTE, &encoded[..n], &mut out, layout)?;
            out.len()
        };
        assert_eq!(&restored[..m], text.as_bytes());
    }
    Ok(())
}
