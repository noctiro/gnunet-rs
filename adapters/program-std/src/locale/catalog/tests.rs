use super::*;

fn catalog(messages: &[(&[u8], &[u8])], big_endian: bool) -> Vec<u8> {
    let table_size = messages.len() * 8;
    let mut bytes = vec![0; 28 + table_size * 2];
    let word = |bytes: &mut [u8], at: usize, value: u32| {
        let encoded = if big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        };
        bytes[at..at + 4].copy_from_slice(&encoded);
    };
    word(&mut bytes, 0, 0x9504_12de);
    word(&mut bytes, 8, messages.len() as u32);
    word(&mut bytes, 12, 28);
    word(&mut bytes, 16, (28 + table_size) as u32);
    for (index, &(source, translation)) in messages.iter().enumerate() {
        for (at, entry) in [
            (28 + 8 * index, source),
            (28 + table_size + 8 * index, translation),
        ] {
            let start = bytes.len() as u32;
            word(&mut bytes, at, entry.len() as u32);
            word(&mut bytes, at + 4, start);
            bytes.extend_from_slice(entry);
            bytes.push(0);
        }
    }
    bytes
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Check byte-exact plural and locale selection"
)]
fn installed_catalogs_select_a_language_and_the_declared_plural_form() -> io::Result<()> {
    let names = preferences(|variable| match variable {
        "LC_MESSAGES" => Some("sr_RS.UTF-8@latin".to_owned()),
        "LANGUAGE" => Some("sr_RS@latin:fr:C:es".to_owned()),
        _ => None,
    })?;
    assert_eq!(names, ["sr_RS@latin", "sr@latin", "sr_RS", "sr", "fr"]);
    assert!(
        preferences(|variable| match variable {
            "LC_ALL" => Some("C".to_owned()),
            "LANGUAGE" => Some("fr".to_owned()),
            _ => None,
        })?
        .is_empty()
    );
    let header = b"Content-Type: text/plain; charset=UTF-8\nPlural-Forms: nplurals=3; plural=(n%10==1 && n%100!=11 ? 0 : n%10>=2 && n%10<=4 && (n%100<10 || n%100>=20) ? 1 : 2);\n";
    let forms = b"jedan\0nekoliko\0mnogo";
    for big_endian in [true, false] {
        let bytes = catalog(&[(b"", header), (b"record\0records", forms)], big_endian);
        let parsed = mo::Catalog::parse(bytes)?;
        assert_eq!(
            parsed.message(b"record", Some(21)),
            Some(b"jedan".as_slice())
        );
        assert_eq!(
            parsed.message(b"record", Some(24)),
            Some(b"nekoliko".as_slice())
        );
        assert_eq!(
            parsed.message(b"record", Some(14)),
            Some(b"mnogo".as_slice())
        );
        assert_eq!(parsed.message(b"missing", None), None);
    }
    let invalid_rule = b"Plural-Forms: nplurals=2; plural=(n ? 1);\n";
    assert!(mo::Catalog::parse(catalog(&[(b"", invalid_rule)], false)).is_err());
    Ok(())
}
