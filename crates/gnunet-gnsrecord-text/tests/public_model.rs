//! One pure aggregate record-format model. All bytes are fixed public mock
//! addresses/names/keys/ciphertext, with no key generation/derivation, hash,
//! crypto, files, sockets, private-key fixtures or running C implementation.
use gnunet_gnsrecord::{ZoneKey, ZoneKeyType, encode_base32};
use gnunet_gnsrecord_text::{
    Codec, Error, Limits, Profile, RecordType as T, Workspace, is_critical, type_name,
    typename_to_number,
};
use gnunet_idna::{Backend, Limits as IdnaLimits, NativeProfile, Workspace as IdnaWorkspace};
#[expect(
    clippy::panic_in_result_fn,
    reason = "Public model helper compares independently specified wire bytes and text"
)]
fn check(
    codec: &mut Codec<'_, impl gnunet_gnsrecord_text::Idna>,
    kind: T,
    text: &str,
    expected: &[u8],
) -> Result<(), Error> {
    let mut bytes = [0x55; 4096];
    let n = codec.string_to_value(kind, text, &mut bytes)?;
    assert_eq!(&bytes[..n], expected);
    let mut output = [0x77; 4096];
    let m = codec.value_to_string(kind, &bytes[..n], &mut output)?;
    assert_eq!(&output[..m], text.as_bytes());
    Ok(())
}
#[expect(
    clippy::panic_in_result_fn,
    reason = "Public fixed ciphertext model checks lossless text conversion"
)]
fn round_binary(
    codec: &mut Codec<'_, impl gnunet_gnsrecord_text::Idna>,
    kind: T,
    data: &[u8],
) -> Result<String, Error> {
    let mut text = [0; 4096];
    let n = codec.value_to_string(kind, data, &mut text)?;
    let text = core::str::from_utf8(&text[..n])
        .map_err(|_| Error::Malformed)?
        .to_owned();
    let mut bytes = [0; 4096];
    let n = codec.string_to_value(kind, &text, &mut bytes)?;
    assert_eq!(&bytes[..n], data);
    Ok(text)
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "One public nonsecret aggregate compares actual record schemas, boundaries and erasure"
)]
fn all_active_families_known_wire_layout_nested_limits_and_erasure() -> Result<(), Error> {
    let mut idna_work = IdnaWorkspace::new();
    let idna = Backend::new(
        &mut idna_work,
        IdnaLimits::GNUNET,
        NativeProfile::Libunistring1_5Unicode18_0,
    );
    let mut stage = [0xaa; 4096];
    let mut names = [0xaa; 1024];
    let mut work = [0xaa; 2048];
    let mut codec = Codec::new(
        &idna,
        Workspace::new(&mut stage, &mut names, &mut work),
        Profile::LITTLE_255,
        Limits::default(),
    )?;
    check(&mut codec, T::A, "192.0.2.1", &[192, 0, 2, 1])?;
    check(
        &mut codec,
        T::AAAA,
        "2001:db8::1",
        &[32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
    )?;
    check(&mut codec, T::NS, "ns.example", b"\x02ns\x07example\0")?;
    check(&mut codec, T::CNAME, "a.example", b"\x01a\x07example\0")?;
    check(&mut codec, T::PTR, "ptr.example", b"\x03ptr\x07example\0")?;
    check(&mut codec, T::NS, "faß.de", b"\x0axn--fa-hia\x02de\0")?;
    check(
        &mut codec,
        T::MX,
        "10 mail.example",
        b"\0\x0a\x04mail\x07example\0",
    )?;
    check(
        &mut codec,
        T::SRV,
        "1 2 443 srv.example",
        b"\0\x01\0\x02\x01\xbb\x03srv\x07example\0",
    )?;
    let mut soa = b"\x02ns\x07example\0\x04host\x07example\0".to_vec();
    for n in 1u32..=5 {
        soa.extend_from_slice(&n.to_be_bytes());
    }
    check(
        &mut codec,
        T::SOA,
        "host.example ns.example ( 1 2 3 4 5 )",
        &soa,
    )?;
    check(&mut codec, T::TXT, "hello", b"hello")?;
    check(&mut codec, T::CERT, "1 10 8 YQ==", &[0, 1, 0, 10, 8, b'a'])?;
    let mut alias = [0; 64];
    let n = codec.string_to_value(T::CERT, "PKIX 10 8 YQ==", &mut alias)?;
    assert_eq!(&alias[..n], &[0, 1, 0, 10, 8, b'a']);
    check(
        &mut codec,
        T::URI,
        "1 2 \"https://example/\"",
        b"\0\x01\0\x02https://example/",
    )?;
    check(
        &mut codec,
        T::TLSA,
        "3 1 1 aabbcc",
        &[3, 1, 1, 170, 187, 204],
    )?;
    check(
        &mut codec,
        T::SMIMEA,
        "3 1 1 aabbcc",
        &[3, 1, 1, 170, 187, 204],
    )?;
    check(
        &mut codec,
        T::CAA,
        "0 issue letsencrypt.org",
        b"\0\x05issueletsencrypt.org",
    )?;
    for kind in [
        T::NICK,
        T::LEHO,
        T::REDIRECT,
        T::RECLAIM_TICKET,
        T::RECLAIM_OIDC_CLIENT,
        T::RECLAIM_OIDC_REDIRECT,
    ] {
        check(&mut codec, kind, "public.example", b"public.example")?;
    }
    check(
        &mut codec,
        T::GNS2DNS,
        "example@127.0.0.1",
        b"example\x00127.0.0.1\0",
    )?;
    for family in [ZoneKeyType::Pkey, ZoneKeyType::Edkey] {
        let public = [3; 32];
        let zone = ZoneKey::new(family, public);
        let mut text = [0; 58];
        check(
            &mut codec,
            family.record_type(),
            zone.write_ztld(&mut text)?,
            &public,
        )?;
    }
    let peer = "0".repeat(52);
    let vpn = format!("17 {peer} service");
    let mut vpn_wire = vec![0; 32];
    vpn_wire.extend_from_slice(b"\0\x11service\0");
    check(&mut codec, T::VPN, &vpn, &vpn_wire)?;
    for kind in [
        T::RECLAIM_ATTRIBUTE,
        T::RECLAIM_ATTRIBUTE_REF,
        T::RECLAIM_CREDENTIAL,
        T::RECLAIM_PRESENTATION,
    ] {
        check(&mut codec, kind, "ZW0AM", &[255, 0, 170])?;
    }
    check(
        &mut codec,
        T::BOX,
        "6 443 1 192.0.2.1",
        &[0, 6, 1, 187, 0, 0, 0, 1, 192, 0, 2, 1],
    )?;
    check(
        &mut codec,
        T::SBOX,
        "_smimecert 16 hello",
        b"\0\0\0\x10_smimecert\0hello",
    )?;
    // Exact official SBOX type65547 (0x1000b), nested beneath BOX.
    let nested = b"\0\x06\0\x50\0\x01\0\x0b\0\0\0\x10_svc\0hello";
    check(&mut codec, T::BOX, "6 80 65547 _svc 16 hello", nested)?;
    let mut out = [0; 128];
    let n = codec.string_to_value(T::TOMBSTONE, "ignored", &mut out)?;
    assert_eq!(n, 0);
    let n = codec.value_to_string(T::TOMBSTONE, &[], &mut out)?;
    assert_eq!(
        &out[..n],
        b"This is a memento of an older block for internal maintenance."
    );
    let entry = [0; 96];
    let text = round_binary(&mut codec, T::MESSENGER_ROOM_ENTRY, &entry)?;
    assert_eq!(text, format!("{}-{}", "0".repeat(103), "0".repeat(52)));
    let mut details = [0; 260];
    details[..9].copy_from_slice(b"room-name");
    details[256] = 1;
    assert_eq!(
        round_binary(&mut codec, T::MESSENGER_ROOM_DETAILS, &details)?,
        "0400000-room-name"
    );
    let mut epoch = [0; 236];
    epoch[0] = 1;
    epoch[64] = 2;
    let text = round_binary(&mut codec, T::MESSENGER_ROOM_EPOCH_KEY, &epoch)?;
    assert_eq!(
        text.split('-').map(str::len).collect::<Vec<_>>(),
        [7, 52, 26, 39, 52, 103, 103]
    );
    let mut encoded = [0; 103];
    encode_base32(&epoch[..64], &mut encoded)?;
    assert_eq!(
        text.rsplit('-').next().ok_or(Error::NotFound)?.as_bytes(),
        &encoded
    );
    let mut encryption = [17; 624];
    encryption[104..108].copy_from_slice(&12u32.to_le_bytes());
    let text = round_binary(&mut codec, T::MESSENGER_ENCRYPTION_KEY, &encryption)?;
    assert_eq!(
        text.split('-').map(str::len).collect::<Vec<_>>(),
        [826, 7, 26, 39, 103]
    );
    assert_eq!(typename_to_number("aAaA"), Some(T::AAAA));
    assert_eq!(typename_to_number("ANY"), Some(T::ANY));
    assert_eq!(type_name(T::TOMBSTONE), Some("✞"));
    assert_eq!(type_name(T::FAESTKEY), None);
    assert!(
        is_critical(T::PKEY)
            && is_critical(T::EDKEY)
            && is_critical(T::GNS2DNS)
            && is_critical(T::REDIRECT)
    );
    assert!(!is_critical(T::TXT));
    let mut unchanged = [0x55; 15];
    assert_eq!(
        codec.string_to_value(T::MX, "65536 mail.example", &mut unchanged),
        Err(Error::Malformed)
    );
    assert_eq!(
        codec.value_to_string(T::GNS2DNS, b"missing terminator", &mut unchanged),
        Err(Error::Malformed)
    );
    assert_eq!(
        codec.value_to_string(T::TXT, &[255], &mut unchanged),
        Err(Error::Malformed)
    );
    assert_eq!(
        codec.string_to_value(T::FAESTKEY, "x", &mut unchanged),
        Err(Error::Unsupported)
    );
    assert_eq!(
        codec.string_to_value(T::MX, "10 mail.example", &mut unchanged),
        Err(Error::Capacity)
    );
    assert_eq!(unchanged, [0x55; 15]);
    drop(codec);
    assert!(
        stage
            .iter()
            .chain(names.iter())
            .chain(work.iter())
            .all(|b| *b == 0)
    );
    let mut codec = Codec::new(
        &idna,
        Workspace::new(&mut stage, &mut names, &mut work),
        Profile::LITTLE_255,
        Limits {
            depth: 1,
            ..Limits::default()
        },
    )?;
    assert_eq!(
        codec.string_to_value(T::BOX, "6 80 65541 6 80 16 hello", &mut unchanged),
        Err(Error::Capacity)
    );
    assert_eq!(unchanged, [0x55; 15]);
    drop(codec);
    // Maximum16-bit record data can expand past128KiB in hex. Defaults cover
    // that real format boundary without allocating in production codecs.
    let mut large_stage = vec![0; 262140];
    let mut small_names = [0; 2];
    let mut small_work = [0; 2];
    let mut codec = Codec::new(
        &idna,
        Workspace::new(&mut large_stage, &mut small_names, &mut small_work),
        Profile::LITTLE_255,
        Limits::default(),
    )?;
    let mut binary = vec![0; 65535];
    binary[..3].fill(255);
    let mut text = vec![0; 262140];
    let n = codec.value_to_string(T::TLSA, &binary, &mut text)?;
    assert_eq!(n, 131076);
    let mut restored = vec![0; 65535];
    let text = core::str::from_utf8(&text[..n]).map_err(|_| Error::Malformed)?;
    let n = codec.string_to_value(T::TLSA, text, &mut restored)?;
    assert_eq!(n, 65535);
    assert_eq!(restored, binary);
    Ok(())
}
