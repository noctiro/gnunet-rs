#![expect(
    clippy::panic_in_result_fn,
    reason = "assert DNS SVCB wire and endpoint semantics"
)]

use super::*;

const OWNER: &[u8] = b"\x04_dns\x07example\0";
const AT_OWNER: &[u8] = b"\0\x05\0\0\x01\0\x04\x03dot";
const ALTERNATE: &[u8] = b"\0\x02\x03Alt\x07Example\0\
    \0\0\0\x04\0\x01\0\x03\
    \0\x01\0\x04\x03dot\
    \0\x03\0\x02\x21\x52\
    \0\x04\0\x04\xc0\0\x02\x01";

#[test]
fn dot_uses_priority_and_effective_endpoint_without_rewriting_wire() -> Result<(), Error> {
    let owner = Name::from_wire(OWNER)?;
    let Selection::Service(chosen) = select_dot(owner, [AT_OWNER, ALTERNATE])? else {
        return Err(Error::Conflict);
    };
    assert_eq!(chosen.priority(), 2);
    assert_eq!(chosen.port(), 8530);
    assert_eq!(chosen.target().wire(), b"\x03Alt\x07Example\0");
    assert_eq!(
        chosen.ipv4_hints().next(),
        Some(Ipv4Addr::new(192, 0, 2, 1))
    );

    let Selection::Service(chosen) = select_dot_where(owner, [ALTERNATE, AT_OWNER], |endpoint| {
        endpoint.port() == 853
    })?
    else {
        return Err(Error::Conflict);
    };
    assert_eq!(chosen.target(), owner);
    assert_eq!(chosen.port(), 853);

    let mut canonical = [0; 128];
    for kind in [64, 65] {
        let len = crate::dnssec::canonical_rdata(kind, ALTERNATE, &mut canonical)?;
        assert_eq!(&canonical[..len], ALTERNATE);
    }
    Ok(())
}

#[test]
fn mandatory_and_alpn_select_only_supported_explicit_dot() -> Result<(), Error> {
    let owner = Name::from_wire(OWNER)?;
    let mandatory_opaque: &[u8] = b"\0\x01\0\
        \0\0\0\x02\xff\0\
        \0\x01\0\x04\x03dot\
        \xff\0\0\x01x";
    let optional_opaque: &[u8] = b"\0\x01\0\0\x01\0\x04\x03dot\xff\0\0\x01x";
    let doq: &[u8] = b"\0\x01\0\0\x01\0\x04\x03doq";
    let zero_port: &[u8] = b"\0\x01\0\0\x01\0\x04\x03dot\0\x03\0\x02\0\0";
    assert_eq!(select_dot(owner, [])?, Selection::Absent);
    for data in [mandatory_opaque, b"\0\x01\0", doq, zero_port] {
        assert_eq!(select_dot(owner, [data])?, Selection::Incompatible);
    }
    assert!(matches!(
        select_dot(owner, [mandatory_opaque, AT_OWNER])?,
        Selection::Service(dot) if dot.priority() == 5
    ));
    assert!(matches!(
        select_dot(owner, [AT_OWNER, optional_opaque])?,
        Selection::Service(dot) if dot.priority() == 1
    ));
    Ok(())
}

#[test]
fn alias_takes_precedence_and_its_parameters_do_not_select_transport() -> Result<(), Error> {
    let owner = Name::from_wire(OWNER)?;
    let alias: &[u8] = b"\0\0\x03Alt\0\0\x02\0\x01x";
    let unavailable: &[u8] = b"\0\0\0";
    let looped: &[u8] = b"\0\0\x04_DNS\x07EXAMPLE\0";
    let target = Name::from_wire(b"\x03Alt\0")?;
    assert_eq!(Record::parse(alias)?.mode(), Mode::Alias(Some(target)));
    assert_eq!(
        select_dot(owner, [AT_OWNER, alias])?,
        Selection::Alias(target)
    );
    assert_eq!(
        select_dot(owner, [AT_OWNER, unavailable])?,
        Selection::Unavailable
    );
    assert_eq!(select_dot(owner, [AT_OWNER, looped]), Err(Error::Malformed));
    Ok(())
}

#[test]
fn malformed_service_values_or_structural_errors_reject_the_set() -> Result<(), Error> {
    let owner = Name::from_wire(OWNER)?;
    let cases: &[(&[u8], Error)] = &[
        (b"\0\x01\xc0\x12", Error::Malformed),
        (b"\0\x01\0\0", Error::Truncated),
        (b"\0\x01\0\0\x01\0\x04\x03do", Error::Truncated),
        (b"\0\x01\0\0\x01\0\x03\x03do", Error::Malformed),
        (b"\0\x01\0\0\x01\0\x01\0", Error::Malformed),
        (b"\0\x01\0\0\x01\0\x04\x03dot\0\x01\0\0", Error::Malformed),
        (b"\0\x01\0\0\x02\0\0\0\x01\0\x04\x03dot", Error::Malformed),
        (b"\0\x01\0\xff\xff\0\0", Error::Malformed),
        (b"\0\x01\0\0\0\0\x02\0\0", Error::Malformed),
        (b"\0\x01\0\0\0\0\x02\0\x03", Error::Malformed),
        (b"\0\x01\0\0\x02\0\0", Error::Malformed),
        (b"\0\x01\0\0\x03\0\x01x", Error::Malformed),
        (b"\0\x01\0\0\x04\0\0", Error::Malformed),
        (b"\0\x01\0\0\x06\0\x01x", Error::Malformed),
        (b"\0\x01\0\0\x01\0\x07\x03dot\x02h2", Error::Malformed),
    ];
    for &(invalid, error) in cases {
        assert_eq!(select_dot(owner, [AT_OWNER, invalid]), Err(error));
    }
    Ok(())
}
