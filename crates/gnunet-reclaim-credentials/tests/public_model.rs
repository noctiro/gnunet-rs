//! One source-only aggregate PUBLIC MOCK model. No real credential, private key,
//! signature/proof/crypto, issuer network, store, plugin ABI or native process.
use gnunet_reclaim::{
    AttributeList, AttributeType, Credential, CredentialType, Identifier, Name, Sensitive,
};
use gnunet_reclaim_credentials::{
    Assurance, Limits, Nest, Stage, Token, ValueKind, Workspace, attribute_from_string,
    check_binding, credential_from_string, credential_value_string, presentation,
};
use gnunet_types::Error;

fn jwt(json: &[u8]) -> Vec<u8> {
    // Only source for encoding a public mock JSON document; not executed here.
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = b"e30.".to_vec();
    let mut acc = 0u32;
    let mut bits = 0;
    for byte in json {
        acc = (acc << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            out.push(alphabet[((acc >> bits) & 63) as usize]);
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(alphabet[((acc << (6 - bits)) & 63) as usize]);
    }
    out.extend_from_slice(b".NOT-SIGNED\0");
    out
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "observations of this one public nonsecret aggregate model"
)]
fn public_claims_presentation_capacities_and_erasure() -> Result<(), Box<dyn std::error::Error>> {
    let body=br#"{"iss":"issuer.example","exp":9,"iat":1,"aud":"mock","Name":"A\n\u00e9","sub":"42","roles":["a",1],"address":{"Street":"Main","nested":{"x":[true,null,2,1.0]}},"\u00c9\u03a3":"z"}"#;
    let raw = jwt(body);
    let credential = Credential::new(
        Identifier::new([3; 32]),
        CredentialType::JWT,
        Name::new(b"public-mock")?,
        Sensitive::new(&raw),
    );
    let mut text = [0xaa; 256];
    let n = attribute_from_string(AttributeType::STRING, b"hello", &mut text)?;
    assert_eq!(&text[..n], b"hello\0");
    let n = credential_from_string(CredentialType::PABC, b"OPAQUE-NOT-A-PROOF", &mut text)?;
    assert_eq!(
        credential_value_string(CredentialType::PABC, Sensitive::new(&text[..n]))?.expose(),
        b"OPAQUE-NOT-A-PROOF"
    );
    let unsupported = credential_from_string(CredentialType::new(0x12345678), b"x", &mut text)
        .err()
        .ok_or(Error::NotFound)?;
    assert_eq!(unsupported.kind, 0x12345678);
    assert_eq!(unsupported.cause, Error::Unsupported);
    let pres = presentation(credential, AttributeList::empty())?;
    assert_eq!(pres.credential, credential.id);
    assert_eq!(pres.value.expose(), raw.as_slice());
    assert_eq!(check_binding(pres, credential)?, Assurance::Unverified);
    let pabc = Credential::new(
        Identifier::ZERO,
        CredentialType::PABC,
        Name::new(b"opaque")?,
        Sensitive::new(b"NOT-A-PABC\0"),
    );
    assert_eq!(
        presentation(pabc, AttributeList::empty())
            .err()
            .ok_or(Error::NotFound)?
            .cause,
        Error::Unavailable
    );
    let mut payload = [0x55; 4096];
    let mut tokens = [Token::EMPTY; 256];
    let mut stack = [Nest::EMPTY; 64];
    {
        let mut workspace = Workspace::new(&mut payload, &mut tokens, &mut stack);
        let claims = workspace.credential(credential, Limits::default())?;
        assert_eq!(claims.assurance(), Assurance::Unverified);
        assert_eq!(claims.expiration()?.as_micros(), 9_000_000);
        let mut issuer = [0; 64];
        let n = claims.issuer()?.decode(&mut issuer)?;
        assert_eq!(&issuer[..n], b"issuer.example");
        assert_eq!(claims.attributes().count(), 6);
        assert_eq!(
            claims.lookup(b"roles").ok_or(Error::NotFound)?.kind(),
            ValueKind::Array
        );
        let name = claims
            .attributes()
            .find(|c| c.name.eq_ascii(b"Name"))
            .ok_or(Error::NotFound)?;
        let mut value = [0; 512];
        let n = name.value.write_attribute(&mut value)?;
        assert_eq!(&value[..n], "A\\né\0".as_bytes());
        let nested = claims
            .attributes()
            .find(|c| c.name.eq_ascii(b"nested"))
            .ok_or(Error::NotFound)?;
        let n = nested.value.write_attribute(&mut value)?;
        assert_eq!(&value[..n], br#"{"x": [true, null, 2, 1.0]}"#);
        assert!(claims.lookup(b"missing").is_none());
        #[cfg(feature = "attributes")]
        {
            use gnunet_reclaim_credentials::NameScratch;
            let mut decoded = [0; 256];
            let mut lowered = [0; 256];
            let mut nfd = [0; 1024];
            let mut ordering = [0; 1024];
            let mut scratch = NameScratch::new(&mut decoded, &mut lowered, &mut nfd, &mut ordering);
            let mut name_out = [0; 256];
            let mut value_out = [0; 512];
            let attr = name.attribute(&mut name_out, &mut value_out, &mut scratch)?;
            assert_eq!(attr.name.bytes(), b"name");
            assert!(attr.id.is_zero());
            assert!(attr.credential.is_zero());
            let greek = claims
                .attributes()
                .find(|c| c.name.chars().eq("ÉΣ".chars()))
                .ok_or(Error::NotFound)?;
            let attr = greek.attribute(&mut name_out, &mut value_out, &mut scratch)?;
            assert_eq!(attr.name.bytes(), "e\u{301}ς".as_bytes());
            let mut short = [0x55; 1];
            let mut private_out = [0x66; 8];
            assert!(
                name.attribute(&mut short, &mut private_out, &mut scratch)
                    .is_err()
            );
            assert!(short.iter().all(|v| *v == 0));
            assert!(private_out.iter().all(|v| *v == 0));
        }
    }
    assert!(payload.iter().all(|v| *v == 0));
    {
        let mut workspace = Workspace::new(&mut payload, &mut tokens, &mut stack);
        for invalid in [
            br#"{"x":1,"x":2}"#.as_slice(),
            br#"{"x":"\ud800"}"#.as_slice(),
            br#"{"x":[1,]}"#.as_slice(),
        ] {
            let raw = jwt(invalid);
            let error = workspace
                .parse(CredentialType::JWT, Sensitive::new(&raw), Limits::default())
                .err()
                .ok_or(Error::NotFound)?;
            assert_eq!(error.stage, Stage::Json);
        }
        let tiny = Limits {
            nodes: 1,
            ..Limits::default()
        };
        assert!(
            workspace
                .parse(CredentialType::JWT, Sensitive::new(&raw), tiny)
                .is_err()
        );
        let tiny = Limits {
            work: 1,
            ..Limits::default()
        };
        assert!(
            workspace
                .parse(CredentialType::JWT, Sensitive::new(&raw), tiny)
                .is_err()
        );
        let negative = jwt(br#"{"exp":-1}"#);
        let whitespace = jwt(b"                                {}");
        let exhausted = workspace
            .parse(
                CredentialType::JWT,
                Sensitive::new(&whitespace),
                Limits {
                    work: 8,
                    ..Limits::default()
                },
            )
            .err()
            .ok_or(Error::NotFound)?;
        assert_eq!(exhausted.stage, Stage::Json);
        assert_eq!(exhausted.cause, Error::Capacity);
        let claims = workspace.parse(
            CredentialType::JWT,
            Sensitive::new(&negative),
            Limits::default(),
        )?;
        assert_eq!(
            claims.expiration().err().ok_or(Error::NotFound)?.cause,
            Error::InvalidInput
        );
    }
    assert!(payload.iter().all(|v| *v == 0));
    Ok(())
}

/// Source-only expected bytes from the active Jansson dump contract. This does
/// not claim execution or an independently run C oracle.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "observations of this source-only public attribute rendering contract"
)]
fn public_real_and_control_attribute_text() -> Result<(), Box<dyn std::error::Error>> {
    let body = br#"{"numbers":[0.1,1.0,-0.0,1e17,1e16,1e-4,1e-5,5e-324,1.7976931348623157e308],"escaped":"\u001b/\u000b"}"#;
    let raw = jwt(body);
    let credential = Credential::new(
        Identifier::new([5; 32]),
        CredentialType::JWT,
        Name::new(b"public-format")?,
        Sensitive::new(&raw),
    );
    let mut payload = [0; 1024];
    let mut tokens = [Token::EMPTY; 64];
    let mut stack = [Nest::EMPTY; 64];
    let mut workspace = Workspace::new(&mut payload, &mut tokens, &mut stack);
    let claims = workspace.credential(credential, Limits::default())?;
    let numbers = claims.lookup(b"numbers").ok_or(Error::NotFound)?;
    let mut out = [0x55; 512];
    let n = numbers.write_attribute(&mut out)?;
    assert_eq!(
        &out[..n],
        b"[0.10000000000000001, 1.0, -0.0, 1e17, 10000000000000000.0, 0.0001, 1.0000000000000001e-5, 4.9406564584124654e-324, 1.7976931348623157e308]"
    );
    let escaped = claims.lookup(b"escaped").ok_or(Error::NotFound)?;
    let n = escaped.write_attribute(&mut out)?;
    assert_eq!(&out[..n], b"\\u001B/\\u000B\0");
    let mut short = [0x55; 1];
    assert_eq!(numbers.write_attribute(&mut short), Err(Error::Capacity));
    assert_eq!(short, [0x55]);
    assert_eq!(claims.expose_payload().expose(), body);
    assert_eq!(
        presentation(credential, AttributeList::empty())?
            .value
            .expose(),
        raw
    );
    Ok(())
}
