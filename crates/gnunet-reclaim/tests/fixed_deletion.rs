//! Fixed plans for whole-label deletions and surviving ticket authorities.

use gnunet_gnsrecord::{RecordData, RecordFlags, RecordType, ZoneKey, ZoneKeyType};
use gnunet_reclaim::{
    Attribute, AttributeType, Credential, CredentialType, Identifier, Name, Presentation,
    Sensitive,
    fixed::{Delete, DeletePlan, IDENTIFIER_LABEL_BYTES, RowPresence, identifier_label},
    ipc::Request,
    objects::TICKET_NAME_BYTES,
};
use gnunet_types::Error;
use gnunet_wire::official::identity::SecretKeyView;

const AUTHORITY: [u8; 36] = {
    let mut bytes = [17; 36];
    bytes[0] = 0;
    bytes[1] = 1;
    bytes[2] = 0;
    bytes[3] = 20;
    bytes
};

fn attribute(id: Identifier, credential: Identifier) -> Result<Attribute<'static>, Error> {
    Ok(Attribute::new(
        id,
        credential,
        AttributeType::STRING,
        Name::new(b"attribute")?,
        Sensitive::new(b"value"),
    ))
}

fn credential(id: Identifier) -> Result<Credential<'static>, Error> {
    Ok(Credential::new(
        id,
        CredentialType::JWT,
        Name::new(b"credential")?,
        Sensitive::new(b"value"),
    ))
}

fn label(id: Identifier) -> Result<[u8; IDENTIFIER_LABEL_BYTES], Error> {
    let mut bytes = [0; IDENTIFIER_LABEL_BYTES];
    identifier_label(id, &mut bytes)?;
    Ok(bytes)
}

fn record(kind: RecordType, data: &[u8]) -> RecordData<'_> {
    RecordData {
        record_type: kind,
        expiration_time: 701,
        flags: RecordFlags::from_bits_preserve(0x8000),
        data,
    }
}

fn ticket<'a>(label: &[u8], out: &'a mut [u8; TICKET_NAME_BYTES]) -> Result<RecordData<'a>, Error> {
    out[..label.len()].copy_from_slice(label);
    out[label.len()] = b'.';
    let head = label.len() + 1;
    let issuer = ZoneKey::new(ZoneKeyType::Edkey, [17; 32]);
    let len = head + issuer.write_ztld(&mut out[head..])?.len();
    out[len] = 0;
    Ok(RecordData {
        flags: RecordFlags::PRIVATE,
        ..record(RecordType::RECLAIM_TICKET, &out[..=len])
    })
}

fn retained<'a>(
    plan: &DeletePlan<8>,
    records: &[RecordData<'a>],
) -> Result<Vec<RecordData<'a>>, Error> {
    let mut kept = Vec::new();
    for record in records.iter().copied() {
        if plan.retains_record(record)? {
            kept.push(record);
        }
    }
    Ok(kept)
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "asserts exact removal and surviving records"
)]
fn both_delete_opcodes_close_dependencies_across_the_whole_zone() -> Result<(), Error> {
    let [a, b, c, d, e, h, missing] = [2, 3, 4, 5, 6, 9, 10].map(|id| Identifier::new([id; 32]));
    let [a_label, b_label, c_label, d_label, e_label, h_label] = [
        label(a)?,
        label(b)?,
        label(c)?,
        label(d)?,
        label(e)?,
        label(h)?,
    ];
    let key = SecretKeyView::new(&AUTHORITY)?;
    let requests = [
        Request::DeleteAttribute {
            rid: u32::MAX,
            key,
            attribute: attribute(a, Identifier::ZERO)?,
        },
        Request::DeleteCredential {
            rid: u32::MAX,
            key,
            credential: credential(a)?,
        },
    ];

    let mut a_attr = [0; 128];
    let mut a_cred = [0; 128];
    let mut b_attr = [0; 128];
    let mut b_cred = [0; 128];
    let mut c_attr = [0; 128];
    let mut d_attr = [0; 128];
    let mut d_cred = [0; 128];
    let mut e_attr = [0; 128];
    let mut h_attr = [0; 128];
    let mut h_cred = [0; 128];
    let a_attr_len = attribute(a, Identifier::ZERO)?.encode(&mut a_attr)?;
    let a_cred_len = credential(a)?.encode(&mut a_cred)?;
    let b_attr_len = attribute(b, a)?.encode(&mut b_attr)?;
    let b_cred_len = credential(b)?.encode(&mut b_cred)?;
    let c_attr_len = attribute(c, b)?.encode(&mut c_attr)?;
    let d_attr_len = attribute(d, missing)?.encode(&mut d_attr)?;
    let d_cred_len = credential(d)?.encode(&mut d_cred)?;
    let e_attr_len = attribute(e, d)?.encode(&mut e_attr)?;
    let h_attr_len = attribute(h, h)?.encode(&mut h_attr)?;
    let h_cred_len = credential(h)?.encode(&mut h_cred)?;
    let a_records = [
        record(RecordType::RECLAIM_ATTRIBUTE, &a_attr[..a_attr_len]),
        record(RecordType::RECLAIM_CREDENTIAL, &a_cred[..a_cred_len]),
    ];
    let b_records = [
        record(RecordType::RECLAIM_ATTRIBUTE, &b_attr[..b_attr_len]),
        record(RecordType::RECLAIM_CREDENTIAL, &b_cred[..b_cred_len]),
    ];
    let c_records = [record(RecordType::RECLAIM_ATTRIBUTE, &c_attr[..c_attr_len])];
    let d_records = [
        record(RecordType::RECLAIM_ATTRIBUTE, &d_attr[..d_attr_len]),
        record(RecordType::RECLAIM_CREDENTIAL, &d_cred[..d_cred_len]),
    ];
    let e_records = [record(RecordType::RECLAIM_ATTRIBUTE, &e_attr[..e_attr_len])];
    let h_records = [
        record(RecordType::RECLAIM_ATTRIBUTE, &h_attr[..h_attr_len]),
        record(RecordType::RECLAIM_CREDENTIAL, &h_cred[..h_cred_len]),
        record(RecordType::RECLAIM_ATTRIBUTE_REF, e.bytes()),
    ];

    let mut first_ticket = [0; TICKET_NAME_BYTES];
    let mut second_ticket = [0; TICKET_NAME_BYTES];
    let mut dead_presentation = [0; 128];
    let mut good_presentation = [0; 128];
    let dead_len = Presentation::new(b, CredentialType::JWT, Sensitive::new(b"opaque"))
        .encode(&mut dead_presentation)?;
    let good_len = Presentation::new(h, CredentialType::JWT, Sensitive::new(b"opaque"))
        .encode(&mut good_presentation)?;
    let first_ticket = ticket(b"first", &mut first_ticket)?;
    let second_ticket = ticket(b"second", &mut second_ticket)?;
    let extension = record(RecordType::new(65517), b"extension\0bytes");
    let living_ref = record(RecordType::RECLAIM_ATTRIBUTE_REF, h.bytes());
    let living_presentation = record(
        RecordType::RECLAIM_PRESENTATION,
        &good_presentation[..good_len],
    );
    let first_records = [
        first_ticket,
        record(RecordType::RECLAIM_ATTRIBUTE_REF, a.bytes()),
        record(RecordType::RECLAIM_ATTRIBUTE_REF, c.bytes()),
        extension,
        record(
            RecordType::RECLAIM_PRESENTATION,
            &dead_presentation[..dead_len],
        ),
        living_ref,
        extension,
        living_presentation,
    ];
    let second_records = [
        second_ticket,
        record(RecordType::RECLAIM_ATTRIBUTE_REF, e.bytes()),
        record(RecordType::RECLAIM_ATTRIBUTE_REF, missing.bytes()),
        living_ref,
    ];
    // A dependent precedes its credential in each chain, exercising closure
    // across both the original target and the already missing credential.
    let rows: [(&[u8], &[RecordData<'_>]); 8] = [
        (&c_label, &c_records),
        (&b_label, &b_records),
        (&e_label, &e_records),
        (&d_label, &d_records),
        (&a_label, &a_records),
        (b"first", &first_records),
        (b"second", &second_records),
        (&h_label, &h_records),
    ];
    for request in requests {
        let mut frame = [0; 256];
        let len = request.encode(&mut frame)?;
        let delete =
            Delete::from_request(Request::decode(&frame[..len])?).ok_or(Error::NotFound)?;
        assert_eq!(delete.rid(), u32::MAX);
        assert_eq!(delete.key().expose_serialized(), &AUTHORITY);
        let mut scan = delete.scan::<8>()?;
        for (index, (label, records)) in rows.iter().enumerate() {
            scan.visit(
                index as u64 + 1,
                label,
                RowPresence::Records,
                records.iter().copied().map(Ok),
            )?;
        }
        let mut dependencies = scan.dependencies()?;
        for (index, (_, records)) in rows.iter().enumerate() {
            dependencies.visit(index as u64 + 1, records.iter().copied().map(Ok))?;
        }
        let plan = dependencies.finish()?;
        for serial in 1..=8 {
            assert_eq!(plan.removes_row(serial), Ok(serial <= 5));
        }
        assert_eq!(
            retained(&plan, &first_records)?,
            [
                first_ticket,
                extension,
                living_ref,
                extension,
                living_presentation
            ]
        );
        assert_eq!(
            retained(&plan, &second_records)?,
            [second_ticket, living_ref]
        );
        assert_eq!(retained(&plan, &h_records)?, &h_records[..2]);
        assert_eq!(plan.removes_row(9), Err(Error::Stale));
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "asserts no plan from invalid snapshot"
)]
fn deletion_requires_a_present_target_and_both_complete_scans() -> Result<(), Error> {
    let id = Identifier::new([3; 32]);
    let target_label = label(id)?;
    let key = SecretKeyView::new(&AUTHORITY)?;
    let make_delete = |id| {
        Delete::from_request(Request::DeleteAttribute {
            rid: 9,
            key,
            attribute: attribute(id, Identifier::ZERO)?,
        })
        .ok_or(Error::NotFound)
    };
    assert!(matches!(
        make_delete(Identifier::ZERO)?.scan::<1>(),
        Err(Error::InvalidInput)
    ));
    let delete = make_delete(id)?;
    let empty = core::iter::empty;
    let mut scan = delete.scan::<1>()?;
    scan.visit(1, &target_label, RowPresence::TombstonesOnly, empty())?;
    assert!(matches!(scan.dependencies(), Err(Error::NotFound)));
    assert!(matches!(
        delete.scan::<1>()?.dependencies(),
        Err(Error::NotFound)
    ));

    let mut scan = delete.scan::<1>()?;
    assert_eq!(
        scan.visit(
            1,
            &target_label,
            RowPresence::Records,
            [Ok(record(RecordType::RECLAIM_TICKET, b"unterminated"))]
        ),
        Err(Error::Malformed),
    );
    let mut payload = [0; 128];
    let size = attribute(id, Identifier::ZERO)?.encode(&mut payload)?;
    assert_eq!(
        scan.visit(
            1,
            b"noncanonical",
            RowPresence::Records,
            [Ok(record(RecordType::RECLAIM_ATTRIBUTE, &payload[..size]))]
        ),
        Err(Error::Malformed),
    );
    // This physically retained, expired row has no active records, but it can
    // still be removed; only tombstone-only labels fail the original DELETE.
    scan.visit(1, &target_label, RowPresence::Records, empty())?;
    assert_eq!(
        scan.visit(2, b"other", RowPresence::Records, empty()),
        Err(Error::Capacity)
    );
    let mut dependencies = scan.dependencies()?;
    assert_eq!(dependencies.visit(2, empty()), Err(Error::Stale));
    assert!(matches!(dependencies.finish(), Err(Error::NotReady)));
    let mut scan = delete.scan::<1>()?;
    scan.visit(1, &target_label, RowPresence::Records, empty())?;
    let mut dependencies = scan.dependencies()?;
    dependencies.visit(1, empty())?;
    assert_eq!(dependencies.finish()?.removes_row(1), Ok(true));
    Ok(())
}
