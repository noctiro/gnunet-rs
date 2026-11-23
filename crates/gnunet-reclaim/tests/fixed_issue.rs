//! Issuance uses active authority rows and the official record and IPC forms.

use gnunet_gnsrecord::{RecordData, RecordFlags, RecordType, ZoneKey, ZoneKeyType};
use gnunet_reclaim::{
    Attribute, AttributeList, AttributeType, CredentialType, Identifier, ListLimits, Name,
    Presentation, Sensitive, Uri,
    fixed::{Issue, ValidatedIssue},
    ipc::{Request, Response},
    sequence,
};
use gnunet_types::{Error, RelativeTime};
use gnunet_wire::official::{identity::SecretKeyView, namestore::Records};

const AUTHORITY: [u8; 36] = {
    let mut bytes = [17; 36];
    bytes[0] = 0;
    bytes[1] = 1;
    bytes[2] = 0;
    bytes[3] = 20;
    bytes
};
const ISSUER: ZoneKey = ZoneKey::new(ZoneKeyType::Edkey, [4; 32]);
const OTHER_ISSUER: ZoneKey = ZoneKey::new(ZoneKeyType::Edkey, [5; 32]);
const RP: &[u8] = b"https://rp.example.invalid/";
const FRESH: Identifier = Identifier::new([6; 32]);
const FIRST: Identifier = Identifier::new([7; 32]);
const SECOND: Identifier = Identifier::new([8; 32]);
const REFRESH: RelativeTime = RelativeTime::from_micros(1234);

fn selection<'a>(
    ids: &[(u8, Identifier)],
    uri: &'a [u8],
    output: &'a mut [u8],
) -> Result<Issue<'a>, Error> {
    let name = Name::new(b"name")?;
    let mut n = 0;
    for (id, credential) in ids {
        n += Attribute::new(
            Identifier::new([*id; 32]),
            *credential,
            AttributeType::STRING,
            name,
            Sensitive::new(b"value"),
        )
        .encode(output.get_mut(n..).ok_or(Error::Capacity)?)?;
    }
    Issue::from_request(Request::IssueTicket {
        rid: 42,
        key: SecretKeyView::new(&AUTHORITY)?,
        uri: Uri::new(uri)?,
        attributes: AttributeList::new(&output[..n], ListLimits::IPC)?,
        reserved: 0,
    })
    .ok_or(Error::InvalidInput)
}

fn provider(
    id: Identifier,
    _: AttributeList<'_>,
    out: &mut [u8],
) -> Result<(CredentialType, usize), Error> {
    let kind = CredentialType::JWT;
    let n = Presentation::new(id, kind, Sensitive::new(b"proof")).encode(out)?;
    Ok((kind, n))
}

fn selected(output: &mut [u8]) -> Result<ValidatedIssue<'_>, Error> {
    selection(
        &[(1, FIRST), (2, Identifier::ZERO), (3, FIRST), (4, SECOND)],
        RP,
        output,
    )?
    .validate(8, 512)
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "asserts issue record and response framing"
)]
fn prepares_official_record_order_and_one_presentation_per_credential() -> Result<(), Error> {
    let mut request = [0; 512];
    let issue = selected(&mut request)?;
    let mut row = [0xa5; 1024];
    let mut calls = [Identifier::ZERO; 2];
    let mut next = 0;
    let issued = issue.build(ISSUER, FRESH, REFRESH, &mut row, |id, attributes, out| {
        *calls.get_mut(next).ok_or(Error::Conflict)? = id;
        next += 1;
        if attributes.len() != 4 {
            return Err(Error::InvalidInput);
        }
        provider(id, attributes, out)
    })?;
    assert_eq!(issue.rid(), 42);
    assert_eq!(issue.key().expose_serialized(), &AUTHORITY);
    assert_eq!(calls, [FIRST, SECOND]);

    let row = issued.records();
    let ordered = [
        RecordType::RECLAIM_ATTRIBUTE_REF,
        RecordType::RECLAIM_PRESENTATION,
        RecordType::RECLAIM_ATTRIBUTE_REF,
        RecordType::RECLAIM_ATTRIBUTE_REF,
        RecordType::RECLAIM_ATTRIBUTE_REF,
        RecordType::RECLAIM_PRESENTATION,
        RecordType::RECLAIM_TICKET,
        RecordType::TXT,
    ];
    assert_eq!(usize::from(row.count()), ordered.len());
    for (record, kind) in row.records().iter().zip(ordered) {
        let record = record?;
        assert_eq!(record.record_type, kind);
        assert_eq!(record.expiration_time, REFRESH.as_micros());
        assert_eq!(
            record.flags,
            if kind == RecordType::RECLAIM_TICKET {
                RecordFlags::RELATIVE_EXPIRATION.union(RecordFlags::PRIVATE)
            } else {
                RecordFlags::RELATIVE_EXPIRATION
            }
        );
        if kind == RecordType::TXT {
            assert_eq!(record.data, RP);
        }
    }
    assert_eq!(row.bytes().len(), 512);
    assert_eq!(
        issued.result().ticket().capability()?,
        (issued.label(), ISSUER)
    );
    assert_eq!(issued.result().uri().expose(), RP);

    let mut frame = [0; 512];
    let n = issued.result().encode_response(42, &mut frame)?;
    let Response::Ticket {
        rid,
        ticket: Some(ticket),
        uri: None,
        presentations,
    } = Response::decode(&frame[..n])?
    else {
        return Err(Error::Malformed);
    };
    assert_eq!(rid, 42);
    assert_eq!(ticket.expose(), issued.result().ticket().expose());
    assert_eq!(presentations.len(), 2);
    assert!(
        presentations
            .iter()
            .zip([FIRST, SECOND])
            .all(|(p, expected)| p.credential == expected)
    );
    let mut row_presentations = issued.result().presentations();
    let values = [
        row_presentations
            .next()
            .transpose()?
            .ok_or(Error::NotFound)?,
        row_presentations
            .next()
            .transpose()?
            .ok_or(Error::NotFound)?,
    ];
    assert!(row_presentations.next().is_none());
    let mut packed = [0; 256];
    let size = sequence::encode(&values, ListLimits::IPC, &mut packed)?;
    let mut reference = [0; 512];
    let expected = Response::Ticket {
        rid: 42,
        ticket: Some(issued.result().ticket()),
        uri: None,
        presentations: gnunet_reclaim::PresentationList::new(&packed[..size], ListLimits::IPC)?,
    }
    .encode(&mut reference)?;
    assert_eq!(frame[..n], reference[..expected]);
    Ok(())
}

#[test]
#[expect(clippy::panic_in_result_fn, reason = "checks exact reuse and refusal")]
fn reuse_requires_the_private_descriptor_rp_and_exact_selection() -> Result<(), Error> {
    let mut request = [0; 512];
    let issue = selected(&mut request)?;
    let mut original = [0; 512];
    let issued = issue.build(ISSUER, FRESH, REFRESH, &mut original, provider)?;
    let label = issued.label();
    let records = issued.records();
    let valid = issue
        .matching_ticket(ISSUER, label, records)?
        .ok_or(Error::NotFound)?;
    let mut reply = [0; 512];
    let mut reused = [0; 512];
    let n = issued.result().encode_response(42, &mut reply)?;
    let m = valid.encode_response(42, &mut reused)?;
    assert_eq!(reply[..n], reused[..m]);
    assert!(
        issue
            .matching_ticket(OTHER_ISSUER, label, records)?
            .is_none()
    );
    assert!(
        issue
            .matching_ticket(ISSUER, b"elsewhere", records)?
            .is_none()
    );

    let original = records.records().iter().collect::<Result<Vec<_>, _>>()?;
    let nickname = RecordData {
        expiration_time: 100,
        flags: RecordFlags::SUPPLEMENTAL,
        record_type: RecordType::NICK,
        data: b"nickname",
    };
    for (index, replacement) in [
        (0, original[2]),
        (1, original[5]),
        (
            6,
            RecordData {
                flags: RecordFlags::NONE,
                ..original[6]
            },
        ),
        (
            7,
            RecordData {
                data: &RP[..RP.len() - 1],
                ..original[7]
            },
        ),
        (7, original[6]),
    ] {
        let mut changed = original.clone();
        changed[index] = replacement;
        assert!(!matches_row(issue, label, &changed)?);
    }
    let mut changed = original;
    changed.push(nickname);
    assert!(matches_row(issue, label, &changed)?);
    changed.push(changed[1]);
    assert!(!matches_row(issue, label, &changed)?);
    Ok(())
}

fn matches_row(
    issue: ValidatedIssue<'_>,
    label: &[u8],
    row: &[RecordData<'_>],
) -> Result<bool, Error> {
    let mut bytes = [0; 1024];
    let n = gnunet_gnsrecord::serialize(row, &mut bytes)?;
    let count = u16::try_from(row.len()).map_err(|_| Error::TooLarge)?;
    let records = Records::new(&bytes[..n], count)?;
    Ok(issue.matching_ticket(ISSUER, label, records)?.is_some())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "asserts input, capacity and provider failures"
)]
fn validates_limits_and_provider_binding() -> Result<(), Error> {
    let mut request = [0; 512];
    assert!(matches!(
        selection(&[(1, FIRST), (1, SECOND)], RP, &mut request)?.validate(8, 512),
        Err(Error::Conflict)
    ));
    assert!(matches!(
        selection(&[(0, FIRST)], RP, &mut request)?.validate(8, 512),
        Err(Error::InvalidInput)
    ));
    let issue = selection(&[(1, FIRST)], RP, &mut request)?;
    assert!(matches!(issue.validate(3, 512), Err(Error::TooLarge)));
    assert!(matches!(issue.validate(4, 511), Err(Error::TooLarge)));

    let issue = issue.validate(4, 512)?;
    let mut row = [0x5a; 512];
    assert!(matches!(
        issue.build(ISSUER, FRESH, REFRESH, &mut row[..255], |_, _, _| Err(
            Error::Conflict
        )),
        Err(Error::Capacity)
    ));
    assert_eq!(row, [0x5a; 512]);
    assert!(matches!(
        issue.build(ISSUER, FRESH, REFRESH, &mut row, |_, _, _| Err(
            Error::Unavailable
        )),
        Err(Error::Unavailable)
    ));
    assert!(matches!(
        issue.build(ISSUER, FRESH, REFRESH, &mut row, |_, attrs, out| provider(
            SECOND, attrs, out
        )),
        Err(Error::Authentication)
    ));
    assert!(matches!(
        issue.build(ISSUER, FRESH, REFRESH, &mut row, |id, attrs, out| {
            let (_, n) = provider(id, attrs, out)?;
            Ok((CredentialType::new(42), n))
        }),
        Err(Error::Authentication)
    ));
    assert!(matches!(
        issue.build(ISSUER, FRESH, REFRESH, &mut row, |_, _, out| Ok((
            CredentialType::JWT,
            out.len() + 1
        ))),
        Err(Error::Capacity)
    ));
    Ok(())
}
