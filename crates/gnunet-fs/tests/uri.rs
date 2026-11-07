//! Pure FS artifact checks over public typed APIs and caller-owned storage.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions compare artifact bytes and retained rejection boundaries"
)]
use gnunet_crypto::{EddsaPrivateKey, EddsaPublicKey, EddsaSignature};
use gnunet_fs::{Content, Keyword, Keywords, Limits, Location, Namespace, PLACEMENT_PURPOSE, Uri};
use gnunet_types::Error;
use gnunet_wire::official::AbsoluteTime;

const SAMPLE: &[u8] = b"gnunet://fs/chk/4QZP479A9SKGFNMQ2ZBCYE71YV2QMTVGWTVPB6A10ASVCKXDHB05DKPSC7ZF6E9P9W1VE47394EQY7NXA47Q6R35M7P1MJPGP59D1Z8.D54QD1K5XCG5878T6YZ19AM60MQ6FC0YNVK7QY08KK0KM0FJJ3KQWYG112FN5T07KN7J0X35DF6WVBT9B8ZMZ3X2BXJ22X3KFQ6MV2G.15999";
fn encoded(uri: Uri<'_>) -> Result<Vec<u8>, Error> {
    let mut bytes = vec![0; uri.encoded_len()?];
    let n = uri.encode(&mut bytes)?;
    assert_eq!(n, bytes.len());
    Ok(bytes)
}
fn content() -> Content {
    Content {
        key: [17; 64],
        query: [33; 64],
        size: 15_999,
    }
}

// Fixture encoding independent of the production stream encoder: visit each
// bit so a self-signed, noncanonical LOC can exercise only the public parser.
fn fixture_base32(bytes: &[u8]) -> Vec<u8> {
    let alphabet = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let bits = bytes.len() * 8;
    (0..bits.div_ceil(5))
        .map(|i| {
            let mut value = 0_u8;
            for bit in 0..5 {
                value <<= 1;
                let offset = i * 5 + bit;
                if offset < bits {
                    value |= (bytes[offset / 8] >> (7 - offset % 8)) & 1;
                }
            }
            alphabet[usize::from(value)]
        })
        .collect()
}

#[test]
fn pinned_chk_sample_and_all_short_output_capacities_are_atomic() -> Result<(), Error> {
    let uri = Uri::parse(SAMPLE, Limits::default())?;
    let Uri::Content(c) = uri else {
        return Err(Error::Malformed);
    };
    assert_eq!(c.size, 15_999);
    assert_eq!(encoded(uri)?, SAMPLE);
    for n in 0..SAMPLE.len() {
        let mut buffer = vec![0xa7; n];
        assert_eq!(uri.encode(&mut buffer), Err(Error::Capacity));
        assert!(buffer.iter().all(|b| *b == 0xa7));
    }
    Ok(())
}

#[test]
fn sks_identifier_is_literal_and_crockford_alias_padding_is_normalized() -> Result<(), Error> {
    for id in [b"".as_slice(), b"path//literal%20name", b"\xff/\xfe"] {
        let n = Namespace::new(EddsaPublicKey::from_bytes([0; 32]), id)?;
        let canonical = encoded(Uri::Namespace(n))?;
        let parsed = Uri::parse(&canonical, Limits::default())?;
        let Uri::Namespace(view) = parsed else {
            return Err(Error::Malformed);
        };
        assert_eq!(view, n);
        let mut alias = canonical.clone();
        for byte in &mut alias[16..68] {
            if *byte == b'0' {
                *byte = b'o';
            }
        }
        alias[67] = b'F'; // Four unused low padding bits have no value.
        assert_eq!(encoded(Uri::parse(&alias, Limits::default())?)?, canonical);
    }
    assert_eq!(
        Namespace::new(EddsaPublicKey::from_bytes([0; 32]), b"a\0b"),
        Err(Error::InvalidInput)
    );
    Ok(())
}

#[test]
fn keyword_terms_preserve_mandatory_order_duplicates_and_percent_payload() -> Result<(), Error> {
    let input = b"gnunet://fs/ksk/foo%20bar+%2Bbaz+foo%20bar+%C3%A4";
    let uri = Uri::parse(input, Limits::default())?;
    let Uri::Keywords(k) = uri else {
        return Err(Error::Malformed);
    };
    assert_eq!(k.len(), 4);
    let actual: Vec<_> = k
        .iter()
        .map(|word| (word.mandatory(), word.bytes().collect::<Vec<_>>()))
        .collect();
    assert_eq!(
        actual,
        [
            (false, b"foo bar".to_vec()),
            (true, b"baz".to_vec()),
            (false, b"foo bar".to_vec()),
            (false, "ä".as_bytes().to_vec())
        ]
    );
    assert_eq!(encoded(uri)?, input);
    let terms = [
        Keyword::new(b"foo bar", false)?,
        Keyword::new(b"baz", true)?,
        Keyword::new(b"a+b", false)?,
    ];
    assert_eq!(
        encoded(Uri::Keywords(Keywords::new(&terms)?))?,
        b"gnunet://fs/ksk/foo%20bar+%2Bbaz+a%2Bb"
    );
    let mut too_short = [0x55; 2];
    assert_eq!(terms[0].write(&mut too_short), Err(Error::Capacity));
    assert_eq!(too_short, [0x55; 2]);
    Ok(())
}

#[test]
fn quoted_keyword_and_c_string_nul_normalization_remain_bounded() -> Result<(), Error> {
    let uri = Uri::parse(b"gnunet://fs/ksk/%22foo+bar%22", Limits::default())?;
    assert_eq!(encoded(uri)?, b"gnunet://fs/ksk/foo%2Bbar");
    let uri = Uri::parse(b"gnunet://fs/ksk/a%00ignored+b", Limits::default())?;
    assert_eq!(encoded(uri)?, b"gnunet://fs/ksk/a+b");
    for invalid in [
        b"gnunet://fs/ksk/%".as_slice(),
        b"gnunet://fs/ksk/%A",
        b"gnunet://fs/ksk/%00ignored",
        b"gnunet://fs/ksk/%00%2B",
        b"gnunet://fs/ksk/a+%00+b",
        b"gnunet://fs/ksk/%22%22",
        b"gnunet://fs/ksk/a\"b",
        b"gnunet://fs/ksk/%GG",
        b"gnunet://fs/ksk/+a",
        b"gnunet://fs/ksk/a++b",
        b"gnunet://fs/ksk/a+",
        b"gnunet://fs/ksk/%22a",
        b"gnunet://fs/ksk/a\0b",
    ] {
        assert!(
            Uri::parse(invalid, Limits::default()).is_err(),
            "{invalid:?}"
        );
    }
    Ok(())
}

#[test]
fn marker_only_mandatory_term_round_trips_and_obeys_public_api_limits() -> Result<(), Error> {
    let marker = Keyword::new(b"", true)?;
    assert!(marker.mandatory());
    assert!(marker.is_empty());
    assert_eq!(marker.len(), 0);
    assert_eq!(marker.bytes().next(), None);
    assert_eq!(marker.write(&mut []), Ok(0));
    let mut untouched = [0x55; 2];
    assert_eq!(marker.write(&mut untouched), Ok(0));
    assert_eq!(untouched, [0x55; 2]);
    let terms = [marker];
    let uri = Uri::Keywords(Keywords::new(&terms)?);
    let canonical = b"gnunet://fs/ksk/%2B";
    assert_eq!(encoded(uri)?, canonical);
    for n in 0..canonical.len() {
        let mut short = vec![0xa7; n];
        assert_eq!(uri.encode(&mut short), Err(Error::Capacity));
        assert!(short.iter().all(|b| *b == 0xa7));
    }
    for input in [
        canonical.as_slice(),
        b"gnunet://fs/ksk/%2b",
        b"gnunet://fs/ksk/%22%2B%22",
        b"gnunet://fs/ksk/%2B%00ignored",
    ] {
        let parsed = Uri::parse(
            input,
            Limits {
                max_keyword_bytes: 0,
                ..Limits::default()
            },
        )?;
        let Uri::Keywords(words) = parsed else {
            return Err(Error::Malformed);
        };
        assert_eq!(words.len(), 1);
        assert!(!words.is_empty());
        let word = words.iter().next().ok_or(Error::Malformed)?;
        assert!(word.mandatory());
        assert!(word.is_empty());
        assert_eq!(encoded(parsed)?, canonical);
    }
    assert!(matches!(
        Uri::parse(
            canonical,
            Limits {
                max_keywords: 0,
                ..Limits::default()
            }
        ),
        Err(Error::Capacity)
    ));
    let pair = b"gnunet://fs/ksk/%2B+%2B";
    let parsed = Uri::parse(pair, Limits::default())?;
    let Uri::Keywords(words) = parsed else {
        return Err(Error::Malformed);
    };
    assert_eq!(words.len(), 2);
    assert!(words.iter().all(|word| word.mandatory() && word.is_empty()));
    assert_eq!(encoded(parsed)?, pair);
    assert!(matches!(
        Uri::parse(
            pair,
            Limits {
                max_keywords: 1,
                ..Limits::default()
            }
        ),
        Err(Error::Capacity)
    ));
    let terms = [
        marker,
        Keyword::new(b"+", true)?,
        Keyword::new(b"literal%2B", false)?,
    ];
    let text = encoded(Uri::Keywords(Keywords::new(&terms)?))?;
    assert_eq!(text, b"gnunet://fs/ksk/%2B+%2B%2B+literal%252B");
    let Uri::Keywords(words) = Uri::parse(&text, Limits::default())? else {
        return Err(Error::Malformed);
    };
    let actual: Vec<_> = words
        .iter()
        .map(|word| (word.mandatory(), word.bytes().collect::<Vec<_>>()))
        .collect();
    assert_eq!(
        actual,
        [
            (true, vec![]),
            (true, b"+".to_vec()),
            (false, b"literal%2B".to_vec())
        ]
    );
    for (text, mandatory) in [
        (b"".as_slice(), false),
        (b"+", false),
        (b"\0", false),
        (b"\0", true),
        (b"\"", false),
        (b"\"", true),
    ] {
        assert!(matches!(
            Keyword::new(text, mandatory),
            Err(Error::InvalidInput)
        ));
    }
    Ok(())
}

#[test]
fn explicit_limits_reject_each_variable_input_boundary() -> Result<(), Error> {
    assert!(matches!(
        Uri::parse(
            SAMPLE,
            Limits {
                max_input_bytes: SAMPLE.len() - 1,
                ..Limits::default()
            }
        ),
        Err(Error::Capacity)
    ));
    assert!(matches!(
        Uri::parse(
            b"gnunet://fs/ksk/a+b",
            Limits {
                max_keywords: 1,
                ..Limits::default()
            }
        ),
        Err(Error::Capacity)
    ));
    assert!(matches!(
        Uri::parse(
            b"gnunet://fs/ksk/abc",
            Limits {
                max_keyword_bytes: 2,
                ..Limits::default()
            }
        ),
        Err(Error::Capacity)
    ));
    let text = encoded(Uri::Namespace(Namespace::new(
        EddsaPublicKey::from_bytes([0; 32]),
        b"abc",
    )?))?;
    assert!(matches!(
        Uri::parse(
            &text,
            Limits {
                max_identifier_bytes: 2,
                ..Limits::default()
            }
        ),
        Err(Error::Capacity)
    ));
    assert!(Keyword::new(b"+optional", false).is_err());
    assert!(Keyword::new(b"literal\"quote", true).is_err());
    assert!(Keyword::new(b"", false).is_err());
    assert!(Keywords::new(&[]).is_err());
    Ok(())
}

#[test]
fn reference_numeric_prefixes_normalize_without_host_scan_or_overread() -> Result<(), Error> {
    let normal = encoded(content().uri())?;
    let prefix = &normal[..normal
        .iter()
        .rposition(|b| *b == b'.')
        .ok_or(Error::Malformed)?
        + 1];
    for (suffix, value) in [
        (b"0".as_slice(), 0),
        (b" +0007ignored", 7),
        (b"-1", u64::MAX),
        (b"18446744073709551615", u64::MAX),
        (b"18446744073709551616", u64::MAX),
    ] {
        let mut input = prefix.to_vec();
        input.extend_from_slice(suffix);
        let Uri::Content(parsed) = Uri::parse(&input, Limits::default())? else {
            return Err(Error::Malformed);
        };
        assert_eq!(parsed.size, value);
    }
    Ok(())
}

#[test]
fn location_binds_exact184_byte_layout_rounds_time_and_authenticates_every_field()
-> Result<(), Error> {
    let signer = EddsaPrivateKey::from_seed([7; 32]);
    let c = content();
    let l = Location::sign(c, &signer, AbsoluteTime::from_micros(12_345_678))?;
    assert_eq!(l.expiration().as_micros(), 12_000_000);
    let region = Location::signing_region(c, l.peer(), l.expiration());
    assert_eq!(&region[..8], &[0, 0, 0, 184, 0, 0, 0, 5]);
    assert_eq!(&region[8..16], &12_000_000_u64.to_be_bytes());
    assert_eq!(&region[16..24], &c.size.to_be_bytes());
    assert_eq!(&region[24..88], &c.key);
    assert_eq!(&region[88..152], &c.query);
    assert_eq!(&region[152..], l.peer().as_bytes());
    l.peer()
        .verify(PLACEMENT_PURPOSE, &region, &l.signature())?;
    let bytes = encoded(Uri::Location(l))?;
    let Uri::Location(parsed) = Uri::parse(&bytes, Limits::default())? else {
        return Err(Error::Malformed);
    };
    assert_eq!(parsed, l);
    for position in [8, 16, 24, 88, 152] {
        let mut changed = region;
        changed[position] ^= 1;
        assert_eq!(
            l.peer().verify(PLACEMENT_PURPOSE, &changed, &l.signature()),
            Err(Error::Authentication)
        );
    }
    let mut sig = *l.signature().as_bytes();
    sig[0] ^= 1;
    assert_eq!(
        Location::from_signed(c, l.peer(), EddsaSignature::from_bytes(sig), l.expiration()),
        Err(Error::Authentication)
    );
    assert_eq!(
        Location::from_signed(
            c,
            l.peer(),
            l.signature(),
            AbsoluteTime::from_micros(12_000_001)
        ),
        Err(Error::InvalidInput)
    );
    Ok(())
}

#[test]
fn expired_location_is_still_a_verifiable_artifact_without_a_clock() -> Result<(), Error> {
    let signer = EddsaPrivateKey::from_seed([9; 32]);
    let location = Location::sign(content(), &signer, AbsoluteTime::from_micros(0))?;
    let input = encoded(Uri::Location(location))?;
    assert!(matches!(
        Uri::parse(&input, Limits::default())?,
        Uri::Location(_)
    ));
    let mut corrupted = input;
    corrupted[16] = if corrupted[16] == b'0' { b'1' } else { b'0' };
    assert!(matches!(
        Uri::parse(&corrupted, Limits::default()),
        Err(Error::Authentication)
    ));
    Ok(())
}

#[test]
fn wrapped_location_timestamp_authenticates_but_cannot_encode_a_broken_signature()
-> Result<(), Error> {
    let seconds = 18_446_744_073_710_u64;
    let expiration = AbsoluteTime::from_micros(seconds.wrapping_mul(1_000_000));
    assert_eq!(expiration.as_micros(), 448_384);
    let signer = EddsaPrivateKey::from_seed([13; 32]);
    let c = content();
    let signature = signer.sign(
        PLACEMENT_PURPOSE,
        &Location::signing_region(c, signer.public_key(), expiration),
    )?;
    assert_eq!(
        Location::from_signed(c, signer.public_key(), signature, expiration),
        Err(Error::InvalidInput)
    );
    let chk = encoded(c.uri())?;
    let mut text = b"gnunet://fs/loc/".to_vec();
    text.extend_from_slice(&chk[b"gnunet://fs/chk/".len()..]);
    text.push(b'.');
    text.extend_from_slice(&fixture_base32(signer.public_key().as_bytes()));
    text.push(b'.');
    text.extend_from_slice(&fixture_base32(signature.as_bytes()));
    text.push(b'.');
    text.extend_from_slice(seconds.to_string().as_bytes());
    let uri = Uri::parse(&text, Limits::default())?;
    let Uri::Location(location) = uri else {
        return Err(Error::Malformed);
    };
    assert_eq!(location.content(), c);
    assert_eq!(location.expiration(), expiration);
    assert_eq!(location.signature(), signature);
    location.peer().verify(
        PLACEMENT_PURPOSE,
        &Location::signing_region(c, location.peer(), location.expiration()),
        &location.signature(),
    )?;
    assert_eq!(uri.encoded_len(), Err(Error::InvalidInput));
    for capacity in [0, 1, text.len(), text.len() + 64] {
        let mut output = vec![0xa7; capacity];
        assert_eq!(uri.encode(&mut output), Err(Error::InvalidInput));
        assert!(output.iter().all(|b| *b == 0xa7));
    }
    Ok(())
}
