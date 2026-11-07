//! Native text, strict validation, resource and atomic-output contracts.
#![expect(
    clippy::unwrap_used,
    reason = "The test and oracle require exact successful fixture parsing or fail immediately."
)]
use gnunet_dns::{Arena, Idna, Name};
use gnunet_idna::{
    Backend, Error, Limits, NativeProfile, Workspace, normalize_nfc, to_ascii, to_unicode,
    validate_idna2008_label,
};
const PROFILE: NativeProfile = NativeProfile::Libunistring1_5Unicode18_0;
fn ascii(s: &str) -> Result<String, Error> {
    let mut w = Workspace::new();
    let mut out = [0; 1024];
    let n = to_ascii(s.as_bytes(), &mut out, &mut w, Limits::GNUNET, PROFILE)?;
    Ok(String::from_utf8(out[..n].to_vec()).unwrap())
}
fn unicode(s: &str) -> Result<String, Error> {
    let mut w = Workspace::new();
    let mut out = [0; 1024];
    let n = to_unicode(s.as_bytes(), &mut out, &mut w, Limits::GNUNET)?;
    Ok(String::from_utf8(out[..n].to_vec()).unwrap())
}
#[test]
fn native_mapping_and_nontransitional_names() {
    for (input, expected) in [
        ("Faß.de", "xn--fa-hia.de"),
        ("e\u{301}", "xn--9ca"),
        ("ẞ", "xn--zca"),
        ("ς", "xn--3xa"),
        ("σ", "xn--4xa"),
        ("a。b", "a.b"),
        ("_SIP._TCP", "_sip._tcp"),
        ("a@b", "a@b"),
        ("a\u{feff}b", "ab"),
        ("\u{ad}", ""),
        ("..", ".."),
        ("XN--BCHER-KVA", "xn--bcher-kva"),
    ] {
        assert_eq!(ascii(input).as_deref(), Ok(expected), "{input}");
    }
}
#[test]
fn emoji_unassigned_and_new_assignments_cannot_bypass_fixed_lookup_tables() {
    for text in [
        "😀",
        "xn--e28h",
        "\u{378}",
        "\u{1c89}",
        "xn--3sf",
        "\u{19da}",
        "a\u{200c}b",
        "-name",
        "name-",
        "ab--cd",
        "\u{301}a",
        "¨",
    ] {
        assert!(ascii(text).is_err(), "{text}");
    }
    assert!(ascii("\u{2ebf0}").is_ok()); // Unicode15.1 CJK ExtensionI.
}
#[test]
fn unicode_is_decode_only_and_keeps_case_normalization_and_invalid_ace_failure() {
    for (input, expected) in [
        ("EXAMPLE", "EXAMPLE"),
        ("e\u{301}", "e\u{301}"),
        ("😀", "😀"),
        ("XN--BCHER-KVA", "BüCHER"),
        ("xn--e28h", "😀"),
        ("xn--_", "\u{80}"),
        ("xn--bcher-kva", "bücher"),
    ] {
        assert_eq!(unicode(input).as_deref(), Ok(expected), "{input}");
    }
    for input in ["xn--", "xn---a", "xn--abc-", "xn--$", "xn--uu0c"] {
        assert!(unicode(input).is_err(), "{input}");
    }
}
#[test]
fn contextj_virama_joining_and_transparency_match_native_profile() {
    for text in ["क्\u{200c}", "क्\u{200d}", "ب\u{200c}ب", "بَ\u{200c}َب"] {
        assert!(ascii(text).is_ok(), "{text}");
    }
    for text in [
        "\u{200c}",
        "\u{200d}",
        "a\u{200c}ب",
        "ب\u{200c}a",
        "ب\u{200d}ب",
        "ب\u{200c}َ",
    ] {
        assert!(ascii(text).is_err(), "{text}");
    }
}
#[test]
fn explicit_strict_contexto_and_bidi_do_not_change_native_lookup() {
    let mut w = Workspace::new();
    for text in ["a·b", "·", "a・b", "ا١۱", "ا1١", "א_\u{5b0}"] {
        assert!(ascii(text).is_ok(), "native {text}");
        assert!(
            validate_idna2008_label(text, false, &mut w).is_err(),
            "strict {text}"
        );
    }
    for text in ["l·l", "͵α", "א׳", "カ・ナ", "ا١", "ا۱"] {
        assert!(
            validate_idna2008_label(text, false, &mut w).is_ok(),
            "strict {text}"
        );
    }
    assert!(validate_idna2008_label("_sip", false, &mut w).is_err());
    assert!(validate_idna2008_label("", false, &mut w).is_err());
    assert!(validate_idna2008_label(&"é".repeat(63), false, &mut w).is_err());
    assert!(validate_idna2008_label("1abc", false, &mut w).is_ok());
    assert!(validate_idna2008_label("1abc", true, &mut w).is_err());
}
#[test]
fn runtime_property_version_is_explicit_and_effective() {
    let mut w = Workspace::new();
    let mut out = [0; 255];
    // Ahom U+1171E changed from NSM/Transparent to L/NonJoining; this changes
    // admission in RTL labels and transparent scans even though it is old PVALID.
    let text = "א𑜞".as_bytes();
    assert!(
        to_ascii(
            text,
            &mut out,
            &mut w,
            Limits::GNUNET,
            NativeProfile::Unicode15_1
        )
        .is_ok()
    );
    assert!(to_ascii(text, &mut out, &mut w, Limits::GNUNET, PROFILE).is_err());
}
#[test]
fn exact_native_label_and_domain_lengths() {
    assert_eq!(ascii(&"a".repeat(63)).unwrap().len(), 63);
    assert!(ascii(&"a".repeat(64)).is_err());
    let max = [
        "a".repeat(63),
        "a".repeat(63),
        "a".repeat(63),
        "a".repeat(61),
    ]
    .join(".");
    assert_eq!(max.len(), 253);
    assert_eq!(ascii(&max).unwrap().len(), 253);
    assert_eq!(ascii(&(max.clone() + ".")).unwrap().len(), 254);
    assert!(ascii(&(max + "a")).is_err());
    assert!(unicode(&"a".repeat(63)).is_ok());
    assert!(unicode(&"a".repeat(64)).is_err());
    assert!(ascii(&"\u{ad}".repeat(32767)).unwrap().is_empty());
}
#[test]
fn output_is_atomic_for_every_capacity_prefix_and_invalid_input() {
    let mut w = Workspace::new();
    let mut full = [0; 1024];
    for source in [
        "faß.de",
        "بَ\u{200c}َب",
        "a",
        "xn--e28h",
        "e\u{301}",
        ".a..b.",
    ] {
        for mode in 0..3 {
            let call = |out: &mut [u8], w: &mut Workspace| match mode {
                0 => to_ascii(source.as_bytes(), out, w, Limits::GNUNET, PROFILE),
                1 => to_unicode(source.as_bytes(), out, w, Limits::GNUNET),
                _ => normalize_nfc(source.as_bytes(), out, w, Limits::GNUNET, PROFILE),
            };
            let Ok(n) = call(&mut full, &mut w) else {
                continue;
            };
            for cap in 0..n {
                let mut out = [0xa5; 1024];
                assert_eq!(call(&mut out[..cap], &mut w), Err(Error::Capacity));
                assert_eq!(out, [0xa5; 1024]);
            }
            let mut out = [0xa5; 1024];
            assert_eq!(call(&mut out[..n], &mut w), Ok(n));
            assert_eq!(&out[..n], &full[..n]);
            assert!(out[n..].iter().all(|b| *b == 0xa5));
        }
    }
    for source in [&b"a\0b"[..], &b"\xff"[..], &b"xn--$"[..]] {
        let mut out = [0xa5; 1024];
        assert!(to_ascii(source, &mut out, &mut w, Limits::GNUNET, PROFILE).is_err());
        assert_eq!(out, [0xa5; 1024]);
        assert!(to_unicode(source, &mut out, &mut w, Limits::GNUNET).is_err());
        assert_eq!(out, [0xa5; 1024]);
    }
}
#[test]
fn resource_failures_never_turn_into_wire_text_fallback() {
    let mut w = Workspace::new();
    let backend = Backend::new(
        &mut w,
        Limits {
            maximum_input_bytes: 2,
        },
        PROFILE,
    );
    assert_eq!(
        backend.to_ascii(b"abc", &mut [0; 255]),
        Err(gnunet_dns::Error::TooLarge)
    );
    let wire = b"\x08xn--e28h\0";
    let name = Name::from_wire(wire).unwrap();
    let mut out = [0xa5; 64];
    assert_eq!(
        name.write_native_text(&backend, &mut [0; 64], &mut out),
        Err(gnunet_dns::Error::TooLarge)
    );
    assert_eq!(out, [0xa5; 64]);
}
#[test]
fn parser_backend_fallback_and_cstring_boundaries_are_explicit() {
    let mut w = Workspace::new();
    let backend = Backend::new(&mut w, Limits::GNUNET, PROFILE);
    for (wire, expected) in [
        (&b"\x05xn--$\0"[..], &b"xn--$"[..]),
        (&b"\x04xn--\0"[..], &b"xn--"[..]),
        (&b"\x03a\0b\0"[..], &b"a"[..]),
        (&b"\x01\xff\0"[..], &b"\xff"[..]),
        (&b"\x08xn--e28h\0"[..], "😀".as_bytes()),
    ] {
        let name = Name::from_wire(wire).unwrap();
        let mut out = [0; 1024];
        let n = name
            .write_native_text(&backend, &mut [0; 1024], &mut out)
            .unwrap();
        assert_eq!(&out[..n], expected);
    }
    let mut storage = [0; 255];
    let mut arena = Arena::new(&mut storage);
    assert_eq!(
        Name::from_native_text(
            b"a\0b",
            &backend,
            &mut [0; 255],
            &mut arena,
            gnunet_dns::Limits::DNS
        ),
        Err(gnunet_dns::Error::InvalidInput)
    );
}
#[test]
fn maximum_workspace_is_fixed_and_contains_no_hidden_punycode_buffer() {
    assert_eq!(core::mem::size_of::<Workspace>(), 6352);
    let mut work = Workspace::new();
    let mut out = [0xa5; 1];
    assert!(
        to_unicode(
            format!("xn--{}", "_".repeat(60000)).as_bytes(),
            &mut out,
            &mut work,
            Limits::GNUNET
        )
        .is_err()
    );
    assert_eq!(out, [0xa5; 1]);
}

#[test]
fn normalization_expansion_uses_full_caller_capacity_and_is_atomic() {
    let mut work = Workspace::new();
    for count in [127, 128, 254] {
        let text = "\u{1d15e}".repeat(count);
        let expected = "\u{1d157}\u{1d165}".repeat(count);
        let mut output = [0xa5; 4064];
        assert_eq!(
            normalize_nfc(
                text.as_bytes(),
                &mut output,
                &mut work,
                Limits::GNUNET,
                PROFILE
            ),
            Ok(expected.len())
        );
        assert_eq!(&output[..expected.len()], expected.as_bytes());
        for cap in 0..expected.len() {
            output.fill(0xa5);
            assert_eq!(
                normalize_nfc(
                    text.as_bytes(),
                    &mut output[..cap],
                    &mut work,
                    Limits::GNUNET,
                    PROFILE
                ),
                Err(Error::Capacity)
            );
            assert_eq!(output, [0xa5; 4064]);
        }
    }
}
