//! Allocation-free Store preparation without a live authority or entropy source.

use gnunet_gnsrecord::{RecordFlags, RecordType};
use gnunet_reclaim::{
    Attribute, AttributeType, Credential, CredentialType, Identifier, Name, Sensitive,
    fixed::{IDENTIFIER_LABEL_BYTES, Store},
    ipc::Request,
};
use gnunet_types::{Error, RelativeTime};
use gnunet_wire::official::identity::SecretKeyView;

const AUTHORITY: [u8; 36] = {
    let mut bytes = [17; 36];
    bytes[0] = 0;
    bytes[1] = 1;
    bytes[2] = 0;
    bytes[3] = 20;
    bytes
};

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "asserts Store metadata and encoding"
)]
fn unset_attribute_id_uses_the_supplied_assignment() -> Result<(), Error> {
    let key = SecretKeyView::new(&AUTHORITY)?;
    let credential_id = Identifier::new([4; 32]);
    let attribute = Attribute::new(
        Identifier::ZERO,
        credential_id,
        AttributeType::STRING,
        Name::new(b"example")?,
        Sensitive::new(b"example value\0"),
    );
    let store = Store::from_request(Request::StoreAttribute {
        rid: 0,
        expiration: RelativeTime::from_micros(987),
        key,
        attribute,
    })
    .ok_or(Error::NotFound)?;
    assert!(store.requested_id().is_zero());
    assert!(matches!(store.assign_id(None), Err(Error::NotReady)));
    assert!(matches!(
        store.assign_id(Some(Identifier::ZERO)),
        Err(Error::InvalidInput)
    ));
    let mut id = [0; 32];
    id[31] = 1;
    let id = Identifier::new(id);
    let assigned = store.assign_id(Some(id))?;
    assert_eq!(assigned.rid(), 0);
    assert_eq!(assigned.key().expose_serialized(), &AUTHORITY);
    assert_eq!(assigned.id(), id);
    let mut label = [0; IDENTIFIER_LABEL_BYTES + 1];
    let n = assigned.label(&mut label)?;
    assert_eq!(n, IDENTIFIER_LABEL_BYTES);
    assert_eq!(label[..n - 1], [b'0'; IDENTIFIER_LABEL_BYTES - 1]);
    assert_eq!(&label[n - 1..], b"G\0");
    let mut payload = [0xa5; 128];
    assert!(matches!(
        assigned.encode_record(&mut payload[..79]),
        Err(Error::Capacity)
    ));
    assert_eq!(payload, [0xa5; 128]);
    let record = assigned.encode_record(&mut payload)?;
    assert_eq!(record.record_type, RecordType::RECLAIM_ATTRIBUTE);
    assert_eq!(record.flags, RecordFlags::RELATIVE_EXPIRATION);
    assert_eq!(record.expiration_time, 987);
    assert_eq!(record.data.len(), assigned.encoded_len()?);
    let encoded = Attribute::decode(record.data)?;
    assert_eq!(encoded.id, id);
    assert_eq!(encoded.credential, credential_id);
    assert_eq!(encoded.value.expose(), attribute.value.expose());
    Ok(())
}

#[test]
#[expect(clippy::panic_in_result_fn, reason = "asserts the original credential")]
fn supplied_credential_id_and_expiration_are_preserved() -> Result<(), Error> {
    let id = Identifier::new([8; 32]);
    let credential = Credential::new(
        id,
        CredentialType::new(42),
        Name::new(b"token")?,
        Sensitive::new(b"opaque\0value"),
    );
    let store = Store::from_request(Request::StoreCredential {
        rid: 5,
        expiration: RelativeTime::from_micros(u64::MAX),
        key: SecretKeyView::new(&AUTHORITY)?,
        credential,
    })
    .ok_or(Error::NotFound)?;
    assert_eq!(store.rid(), 5);
    assert_eq!(store.requested_id(), id);
    assert!(matches!(
        store.assign_id(Some(Identifier::new([1; 32]))),
        Err(Error::InvalidInput)
    ));
    let assigned = store.assign_id(None)?;
    let mut payload = [0; 128];
    let record = assigned.encode_record(&mut payload)?;
    assert_eq!(record.record_type, RecordType::RECLAIM_CREDENTIAL);
    assert_eq!(record.flags, RecordFlags::RELATIVE_EXPIRATION);
    assert_eq!(record.expiration_time, u64::MAX);
    let encoded = Credential::decode(record.data)?;
    assert_eq!(encoded.id, id);
    assert_eq!(encoded.kind, credential.kind);
    assert_eq!(encoded.value.expose(), credential.value.expose());
    Ok(())
}
