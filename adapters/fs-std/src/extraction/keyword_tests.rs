//! Source-only cases for standard metadata query labels; not native acceptance.
use super::*;
fn check(value: bool) -> Result<(), Error> {
    if value { Ok(()) } else { Err(Error::Binding) }
}
fn selected(text: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    let p = Policy::default();
    let mut data = text.to_vec();
    data.push(0);
    let values = [Value {
        kind: 180,
        format: md::Format::Utf8,
        data,
        plugin: Some(b"<gnunet-rs-auto>\0".to_vec()),
        mime: None,
    }];
    let wire = encode_values(&values, p)?;
    terms(&wire, p)
}
#[test]
fn filename_token_case_and_bracket_phrase_are_distinct_query_keys() -> Result<(), Error> {
    let words = selected(b"MyVacation (Jane Doe).mp4")?;
    for required in [
        b"MyVacation".as_slice(),
        b"myvacation",
        b"Jane Doe",
        b"jane doe",
        b"Jane",
        b"jane",
    ] {
        check(words.iter().any(|term| term == required))?;
    }
    Ok(())
}
#[test]
fn canonical_decomposition_and_contextual_lowercase_are_real_labels() -> Result<(), Error> {
    let words = selected("RÉSUMÉ ΟΔΟΣ.txt".as_bytes())?;
    check(
        words
            .iter()
            .any(|term| term == "re\u{301}sume\u{301}".as_bytes()),
    )?;
    check(words.iter().any(|term| term == "οδος".as_bytes()))
}
#[test]
fn normalization_capacity_rejects_instead_of_dropping_the_required_key() -> Result<(), Error> {
    let p = Policy {
        max_keyword_bytes: 4,
        ..Policy::default()
    };
    check(matches!(
        add_normalized(&mut Vec::new(), "İab", p),
        Err(Error::Limit)
    ))
}
