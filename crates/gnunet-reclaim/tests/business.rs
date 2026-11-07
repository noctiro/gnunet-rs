//! One pure public-mock business model. No provider socket, resolver, store,
//! entropy, key derivation, hash, crypto, C library or key file is used here.
//! bind/admitted/written/complete are explicit MODELED provider facts, not native
//! interoperability evidence. Every identifier/key/value below is a public mock.
#![cfg(feature = "alloc")]
#![forbid(unsafe_code)]
use gnunet_gnsrecord::{RecordFlags, ZoneKey, ZoneKeyType};
use gnunet_reclaim::{
    business::{Action, Completion, Effect, End, Factory, Job, Limits, Provider, Source},
    ipc::{Request, Response},
    *,
};
use gnunet_types::Error;
use gnunet_wire::official::{RelativeTime, identity::SecretKeyView, namestore::Records};
const MOCK_KEY: [u8; 36] = {
    let mut b = [0x42; 36];
    b[0] = 0;
    b[1] = 1;
    b[2] = 0;
    b[3] = 20;
    b
};
fn key() -> Result<SecretKeyView<'static>, Error> {
    SecretKeyView::new(&MOCK_KEY)
}
struct Row {
    label: Vec<u8>,
    data: Vec<u8>,
    count: u16,
}
impl Row {
    fn view(&self) -> Result<Records<'_>, Error> {
        Records::new(&self.data, self.count)
    }
}
fn prepared_row(job: &Job) -> Result<Row, Error> {
    let Action::Store { label, records, .. } = job.prepared()?.ok_or(Error::NotReady)?.action
    else {
        return Err(Error::Conflict);
    };
    Ok(Row {
        label: label.to_vec(),
        data: records.bytes().to_vec(),
        count: records.count(),
    })
}
fn admitted(job: &mut Job, source: &Source) -> Result<Effect, Error> {
    let token = job.prepared()?.ok_or(Error::NotReady)?.effect.clone();
    job.admitted(&token, source, 10)?;
    if matches!(source.provider(), Provider::Namestore | Provider::Gns) {
        job.exposed(&token, source, 1)?;
        job.written(&token, source, 1)?;
    }
    Ok(token)
}
fn complete(job: &mut Job, source: &Source, result: Completion<'_>) -> Result<(), Error> {
    let token = admitted(job, source)?;
    job.complete(&token, source, result, 10)
}
fn scan(job: &mut Job, source: &Source, rows: &[&Row]) -> Result<(), Error> {
    let token = admitted(job, source)?;
    for row in rows {
        job.row(&token, source, key()?, &row.label, row.view()?, 10)?;
    }
    job.complete(&token, source, Completion::ScanEnd, 10)
}
fn output_written(job: &mut Job) -> Result<(), Error> {
    let view = job.response().ok_or(Error::NotReady)?;
    let token = view.output.clone();
    let size = view.bytes.len();
    job.output_queued(&token)?;
    job.output_exposed(&token, size)?;
    job.output_written(&token)
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "One pure model asserts actual plan ordering and original token retirement using only public fixed mocks"
)]
fn mutable_name_capability_issue_consume_and_partial_revoke_keep_original_receipts()
-> Result<(), Error> {
    let factory = Factory::new(Limits::default())?;
    let retained = factory.retained_bytes();
    assert!(matches!(
        factory.start(
            Request::ConsumeTicket {
                rid: 77,
                ticket: Ticket::new(b"missing-issuer")?,
                uri: Uri::new(b"https://public.example")?,
            },
            10,
            100,
        ),
        Err(Error::Malformed)
    ));
    assert_eq!(factory.retained_bytes(), retained);
    let ns = factory.bind(Provider::Namestore)?;
    let gns = factory.bind(Provider::Gns)?;
    let identity = factory.bind(Provider::Identity)?;
    let entropy = factory.bind(Provider::Entropy)?;
    let public = ZoneKey::new(ZoneKeyType::Edkey, [0x11; 32]);
    let attribute = Attribute::new(
        Identifier::new([2; 32]),
        Identifier::ZERO,
        AttributeType::STRING,
        Name::new(b"name")?,
        Sensitive::new(b"public mock\0"),
    );
    let mut stored = factory.start(
        Request::StoreAttribute {
            rid: 1,
            expiration: RelativeTime::from_micros(1000),
            key: key()?,
            attribute,
        },
        10,
        1000,
    )?;
    let attribute_row = prepared_row(&stored)?;
    assert!(stored.response().is_none());
    complete(&mut stored, &ns, Completion::Stored(0))?;
    assert!(matches!(
        stored.response().ok_or(Error::NotReady)?.response()?,
        Response::Success { rid: 1, result: 1 }
    ));
    output_written(&mut stored)?;
    assert!(stored.quiescent());
    drop(stored);
    let mut selected = [0; 256];
    let size = attribute.encode(&mut selected)?;
    let attributes = AttributeList::new(&selected[..size], ListLimits::IPC)?;
    let uri = Uri::new(b"https://rp.example/callback")?;
    let mut issued = factory.start(
        Request::IssueTicket {
            rid: 2,
            key: key()?,
            uri,
            attributes,
            reserved: 0,
        },
        10,
        1000,
    )?;
    complete(&mut issued, &identity, Completion::PublicKey(public))?;
    scan(&mut issued, &ns, &[&attribute_row])?;
    assert!(matches!(
        issued.prepared()?.ok_or(Error::NotReady)?.action,
        Action::Identifier
    ));
    complete(
        &mut issued,
        &entropy,
        Completion::Identifier(Identifier::new([3; 32])),
    )?;
    let ticket_row = prepared_row(&issued)?;
    assert!(issued.response().is_none());
    complete(&mut issued, &ns, Completion::Stored(0))?;
    let Response::Ticket {
        ticket: Some(ticket),
        presentations,
        ..
    } = issued.response().ok_or(Error::NotReady)?.response()?
    else {
        return Err(Error::Malformed);
    };
    assert!(presentations.is_empty());
    let capability = ticket.expose().to_vec();
    let (label, zone) = business::capability(ticket)?;
    assert_eq!(zone, public);
    assert_eq!(label, ticket_row.label);
    output_written(&mut issued)?;
    drop(issued);
    // Real GNS does not return the private local TICKET record. Model only the
    // actual public attribute-ref and RP TXT authorization data.
    let public_records = ticket_row
        .view()?
        .records()
        .iter()
        .collect::<Result<Vec<_>, _>>()?;
    let public_records = public_records
        .into_iter()
        .filter(|r| !r.flags.contains(RecordFlags::PRIVATE))
        .collect::<Vec<_>>();
    let mut public_bytes = vec![0; gnunet_gnsrecord::serialized_len(&public_records)?];
    gnunet_gnsrecord::serialize(&public_records, &mut public_bytes)?;
    let auth = Records::new(
        &public_bytes,
        u16::try_from(public_records.len()).map_err(|_| Error::Capacity)?,
    )?;
    let mut consume = factory.start(
        Request::ConsumeTicket {
            rid: 3,
            ticket: Ticket::new(&capability)?,
            uri,
        },
        10,
        1000,
    )?;
    let Action::Lookup { record_type, .. } = consume.prepared()?.ok_or(Error::NotReady)?.action
    else {
        return Err(Error::Conflict);
    };
    assert_eq!(record_type.value(), 0);
    let token = admitted(&mut consume, &gns)?;
    let foreign = factory.bind(Provider::Gns)?;
    assert!(matches!(
        consume.complete(&token, &foreign, Completion::Records(auth), 10),
        Err(Error::StaleGeneration)
    ));
    consume.complete(&token, &gns, Completion::Records(auth), 10)?;
    assert!(consume.response().is_none());
    complete(
        &mut consume,
        &gns,
        Completion::Records(attribute_row.view()?),
    )?;
    let Response::Consumed {
        rid: 3,
        result: 1,
        identity: Some(actual),
        attributes,
        ..
    } = consume.response().ok_or(Error::NotReady)?.response()?
    else {
        return Err(Error::Malformed);
    };
    assert_eq!(actual, public);
    assert_eq!(attributes.len(), 1);
    assert_eq!(
        attributes.iter().next().ok_or(Error::NotFound)?.id,
        attribute.id
    );
    output_written(&mut consume)?;
    drop(consume);
    let mut revoke = factory.start(
        Request::RevokeTicket {
            rid: 4,
            key: key()?,
            ticket: Ticket::new(&capability)?,
        },
        10,
        1000,
    )?;
    complete(&mut revoke, &identity, Completion::PublicKey(public))?;
    scan(&mut revoke, &ns, &[&attribute_row, &ticket_row])?;
    complete(
        &mut revoke,
        &entropy,
        Completion::Identifier(Identifier::new([4; 32])),
    )?;
    assert_eq!(prepared_row(&revoke)?.count, 0); // First delete the target ticket.
    complete(&mut revoke, &ns, Completion::Stored(0))?;
    assert_eq!(revoke.status().committed_stores, 1);
    assert!(revoke.response().is_none());
    let moved = prepared_row(&revoke)?;
    let moved_attribute = moved
        .view()?
        .records()
        .iter()
        .next()
        .ok_or(Error::NotFound)??;
    assert_eq!(
        Attribute::decode(moved_attribute.data)?.id,
        Identifier::new([4; 32])
    );
    let original = admitted(&mut revoke, &ns)?;
    revoke.cancel();
    assert!(revoke.status().provider_debt);
    assert!(!revoke.quiescent());
    ns.lost(); // Physical source/cancel settlement is a separate original fact.
    revoke.complete(&original, &ns, Completion::Stored(0), 10)?;
    assert_eq!(revoke.status().end, Some(End::Cancelled));
    assert_eq!(revoke.status().committed_stores, 2);
    assert_eq!(revoke.status().provider_code, Some(0));
    assert!(revoke.response().is_none());
    assert!(revoke.quiescent());
    Ok(())
}

#[path = "business/revocation.rs"]
mod revocation;
