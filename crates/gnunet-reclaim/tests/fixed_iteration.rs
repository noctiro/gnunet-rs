//! Credited iteration over borrowed, publicly constructed record fixtures.

use gnunet_gnsrecord::{RecordData, RecordFlags, RecordType, ZoneKey, ZoneKeyType};
use gnunet_reclaim::{
    Attribute, AttributeType, Credential, CredentialType, Identifier, Name, Sensitive,
    fixed::{Cursor, IDENTIFIER_LABEL_BYTES, identifier_label, iteration_row},
    ipc::{Iteration, Response},
};
use gnunet_types::Error;
use gnunet_wire::official::namestore::Records;

const ID: Identifier = Identifier::new([3; 32]);
const ISSUER: ZoneKey = ZoneKey::new(ZoneKeyType::Edkey, [4; 32]);

fn row<'a>(records: &[RecordData<'_>], output: &'a mut [u8]) -> Result<Records<'a>, Error> {
    let len = gnunet_gnsrecord::serialize(records, output)?;
    let count = u16::try_from(records.len()).map_err(|_| Error::TooLarge)?;
    Records::new(&output[..len], count)
}

fn record(kind: RecordType, flags: RecordFlags, data: &[u8]) -> RecordData<'_> {
    RecordData {
        record_type: kind,
        expiration_time: u64::MAX,
        flags,
        data,
    }
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "asserts issuer, cursor and frames"
)]
fn row_errors_and_other_objects_do_not_consume_credit() -> Result<(), Error> {
    let mut label = [0; IDENTIFIER_LABEL_BYTES];
    identifier_label(ID, &mut label)?;
    let mut attribute_wire = [0; 256];
    let attribute = Attribute::new(
        ID,
        Identifier::ZERO,
        AttributeType::STRING,
        Name::new(b"email")?,
        Sensitive::new(b"public@example.invalid\0"),
    );
    let n = attribute.encode(&mut attribute_wire)?;
    let attribute = record(
        RecordType::RECLAIM_ATTRIBUTE,
        RecordFlags::NONE,
        &attribute_wire[..n],
    );
    let mut attributes_wire = [0; 512];
    let singleton = row(&[attribute], &mut attributes_wire)?;
    let mut mixed_wire = [0; 512];
    let mixed = row(
        &[
            attribute,
            record(RecordType::NICK, RecordFlags::SUPPLEMENTAL, b"nickname"),
        ],
        &mut mixed_wire,
    )?;

    let mut cursor = Cursor::new(Iteration::Attributes, 9, ISSUER);
    assert!(cursor.matches(Iteration::Attributes, 9));
    assert!(!cursor.matches(Iteration::Tickets, 9));
    assert!(!cursor.matches(Iteration::Attributes, 10));
    assert_eq!(cursor.after(), Some(0));
    assert!(cursor.visit(2, &label, mixed)?.is_none());
    assert_eq!(cursor.after(), Some(2));
    assert!(matches!(
        cursor.visit(2, &label, singleton),
        Err(Error::Stale)
    ));
    assert!(matches!(
        cursor.visit(3, b"different-label", singleton),
        Err(Error::Malformed)
    ));
    assert_eq!(cursor.after(), Some(2));
    let item = cursor.visit(3, &label, singleton)?.ok_or(Error::NotFound)?;
    let mut frame = [0; 256];
    let n = item.encode(&mut frame)?;
    assert!(
        matches!(Response::decode(&frame[..n])?, Response::Attribute {
        rid: 9, identity: Some(ISSUER), attribute: Some(attribute), ..
    } if attribute.id == ID)
    );
    assert_eq!(cursor.after(), None);
    assert!(matches!(cursor.finish(), Err(Error::NotReady)));
    cursor.grant_next()?;
    assert_eq!(cursor.after(), Some(3));
    assert!(matches!(
        cursor.finish()?,
        Response::Attribute {
            rid: 9,
            identity: None,
            attribute: None,
            ..
        }
    ));
    assert_eq!(cursor.grant_next(), Err(Error::Closed));
    assert!(matches!(cursor.finish(), Err(Error::Closed)));
    Ok(())
}

#[test]
#[expect(clippy::panic_in_result_fn, reason = "asserts the credential frame")]
fn credential_reply_carries_original_typed_issuer() -> Result<(), Error> {
    let issuer = ZoneKey::new(ZoneKeyType::Pkey, [5; 32]);
    let mut label = [0; IDENTIFIER_LABEL_BYTES];
    identifier_label(ID, &mut label)?;
    let mut credential_wire = [0; 256];
    let len = Credential::new(
        ID,
        CredentialType::JWT,
        Name::new(b"example")?,
        Sensitive::new(b"opaque credential bytes"),
    )
    .encode(&mut credential_wire)?;
    let mut row_wire = [0; 512];
    let records = row(
        &[record(
            RecordType::RECLAIM_CREDENTIAL,
            RecordFlags::NONE,
            &credential_wire[..len],
        )],
        &mut row_wire,
    )?;
    let mut cursor = Cursor::new(Iteration::Credentials, 7, issuer);
    cursor.grant_next()?;
    assert!(
        matches!(cursor.visit(1, &label, records)?, Some(Response::Credential {
        rid: 7, identity: Some(original), credential: Some(credential),
    }) if original == issuer && credential.id == ID)
    );
    assert_eq!(cursor.after(), Some(1));
    assert!(matches!(
        cursor.finish()?,
        Response::Credential {
            rid: 7,
            identity: None,
            credential: None,
        }
    ));
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "asserts ticket ownership and result"
)]
fn ticket_iteration_binds_private_ticket_and_txt() -> Result<(), Error> {
    let label = b"some-ticket";
    let mut capability = [0; 128];
    capability[..label.len()].copy_from_slice(label);
    capability[label.len()] = b'.';
    let zone_len = ISSUER.write_ztld(&mut capability[label.len() + 1..])?.len();
    let capability = &capability[..label.len() + zone_len + 2];
    let rp = b"https://rp.example.invalid";
    let private = record(RecordType::RECLAIM_TICKET, RecordFlags::PRIVATE, capability);
    let txt = record(RecordType::TXT, RecordFlags::NONE, rp);
    let mut row_wire = [0; 512];
    let records = row(&[txt, private], &mut row_wire)?;
    let response =
        iteration_row(Iteration::Tickets, 5, ISSUER, label, records)?.ok_or(Error::NotFound)?;
    let mut frame = [0; 512];
    let n = response.encode(&mut frame)?;
    assert!(matches!(Response::decode(&frame[..n])?, Response::Ticket {
        rid: 5, ticket: Some(ticket), uri: Some(uri), presentations,
    } if ticket.expose() == &capability[..capability.len() - 1]
        && uri.expose() == rp && presentations.is_empty()));
    assert!(matches!(
        iteration_row(Iteration::Tickets, 5, ISSUER, b"wrong", records),
        Err(Error::Authentication)
    ));
    let other_issuer = ZoneKey::new(ZoneKeyType::Pkey, [4; 32]);
    assert!(matches!(
        iteration_row(Iteration::Tickets, 5, other_issuer, label, records),
        Err(Error::Authentication)
    ));
    let public = record(RecordType::RECLAIM_TICKET, RecordFlags::NONE, capability);
    let records = row(&[public, txt], &mut row_wire)?;
    assert!(iteration_row(Iteration::Tickets, 5, ISSUER, label, records)?.is_none());
    let records = row(&[private, txt, txt], &mut row_wire)?;
    assert!(matches!(
        iteration_row(Iteration::Tickets, 5, ISSUER, label, records),
        Err(Error::Malformed)
    ));
    Ok(())
}
