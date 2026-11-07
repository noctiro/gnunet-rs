//! One focused pure model: official framing, names, and truthful transactions.
//! The all-zero scalar body below is an explicitly public, noncryptographic
//! opaque mock. No entropy, key derivation, signing, filesystem, or socket runs.
#![cfg(feature = "alloc")]
use gnunet_identity::{
    Code, Core, Decision, Ego, KeyType, Limits, Mutation, SecretKey, SecretKeyView, Transaction,
};
use gnunet_types::Error;
use gnunet_wire::official::identity::{Request, Response};
const PUBLIC_MOCK: [u8; 36] = [
    0, 1, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0,
];
fn prepared(decision: Decision) -> Result<Transaction, Error> {
    match decision {
        Decision::Prepared(t) => Ok(t),
        Decision::Immediate(_) => Err(Error::InvalidInput),
    }
}
fn create(core: &mut Core, name: &[u8]) -> Result<(), Error> {
    let key = SecretKeyView::new(&PUBLIC_MOCK)?;
    let t = prepared(core.begin(Mutation::Create { name, key })?)?;
    core.queued(&t)?;
    core.commit(&t)?;
    Ok(())
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The focused model asserts wire/name/transaction facts while propagating setup errors"
)]
fn official_identity_transaction_model() -> Result<(), Error> {
    let key = SecretKeyView::new(&PUBLIC_MOCK)?;
    assert_eq!(key.key_type(), KeyType::Eddsa);
    let mut bytes = [0x55; 128];
    let n = Request::Create { name: b"A", key }.encode(&mut bytes)?;
    assert_eq!(n, 46);
    assert_eq!(&bytes[..8], &[0, 46, 2, 117, 0, 2, 0, 36]);
    assert_eq!(&bytes[8..44], &PUBLIC_MOCK);
    assert_eq!(&bytes[44..46], b"A\0");
    assert!(matches!(
        Request::decode(&bytes[..n])?,
        Request::Create { name: b"A", .. }
    ));
    bytes[4..6].fill(0);
    assert!(Request::decode(&bytes[..n]).is_err());
    let untouched = bytes;
    assert!(
        Request::Rename {
            old: b"a\0x",
            new: b"b"
        }
        .encode(&mut bytes)
        .is_err()
    );
    assert_eq!(bytes, untouched);
    assert_eq!(Response::EndOfList.encode(&mut bytes)?, 12);
    assert_eq!(&bytes[..12], &[0, 12, 2, 114, 0, 0, 0, 1, 0, 0, 0, 0]);
    assert!(matches!(
        Response::decode(&bytes[..12])?,
        Response::EndOfList
    ));
    let n = Response::Update { name: None, key }.encode(&mut bytes)?;
    assert_eq!(n, 48);
    assert!(matches!(
        Response::decode(&bytes[..n])?,
        Response::Update { name: None, .. }
    ));
    let n = Response::Update {
        name: Some(b""),
        key,
    }
    .encode(&mut bytes)?;
    assert_eq!(n, 49);
    assert!(matches!(
        Response::decode(&bytes[..n])?,
        Response::Update {
            name: Some(b""),
            ..
        }
    ));
    let n = Response::ResultCode { code: 200 }.encode(&mut bytes)?;
    assert!(matches!(
        Response::decode(&bytes[..n])?,
        Response::ResultCode { code: 200 }
    ));

    let mut core = Core::new(Limits::default(), Vec::new())?;
    let original = core.snapshot();
    let t = prepared(core.begin(Mutation::Create {
        name: "\u{00c9}GO".as_bytes(),
        key,
    })?)?;
    assert_eq!(core.snapshot().egos().len(), 0);
    assert!(matches!(core.commit(&t), Err(Error::NotReady)));
    assert_eq!(
        core.staged().ok_or(Error::NotReady)?.after.egos()[0].name(),
        "e\u{0301}go".as_bytes()
    );
    core.queued(&t)?;
    let change = core.commit(&t)?;
    assert_eq!(change.after.revision(), 1);
    assert!(original.egos().is_empty());
    assert!(matches!(core.commit(&t), Err(Error::Stale)));
    assert_eq!(core.lookup("E\u{0301}GO".as_bytes(), false)?, Some(0));
    assert_eq!(core.lookup("\u{00c9}GO".as_bytes(), false)?, None); // lookup does not normalize.
    assert!(matches!(
        core.begin(Mutation::Create {
            name: "e\u{0301}go".as_bytes(),
            key
        })?,
        Decision::Immediate(Code::NAME_CONFLICT)
    ));
    assert!(matches!(
        core.begin(Mutation::Rename {
            old: b"missing",
            new: "e\u{0301}go".as_bytes()
        })?,
        Decision::Immediate(Code::NAME_CONFLICT)
    ));
    create(&mut core, b"example")?;
    create(&mut core, b"sub.example")?;
    assert_eq!(core.lookup(b"x.sub.example", true)?, Some(0));
    assert_eq!(core.lookup(b"x.SUB.EXAMPLE", true)?, None);
    assert_eq!(core.lookup(b"notexample", true)?, None);
    create(&mut core, "\u{039f}\u{03a3}".as_bytes())?;
    assert_eq!(
        core.snapshot().egos()[0].name(),
        "\u{03bf}\u{03c2}".as_bytes()
    );
    create(&mut core, "A\u{0315}\u{0300}\u{0301}".as_bytes())?;
    assert_eq!(
        core.snapshot().egos()[0].name(),
        "a\u{0300}\u{0301}\u{0315}".as_bytes()
    );
    create(&mut core, "\u{0130}".as_bytes())?;
    assert_eq!(core.snapshot().egos()[0].name(), "i\u{0307}".as_bytes());
    let token = prepared(core.begin(Mutation::Delete { name: b"example" })?)?;
    core.queued(&token)?;
    assert_eq!(core.abort(&token, Code::UNKNOWN)?, Code::UNKNOWN);
    assert!(core.lookup(b"example", false)?.is_some());
    let token = prepared(core.begin(Mutation::Delete { name: b"example" })?)?;
    core.queued(&token)?;
    core.unknown(&token)?;
    assert_eq!(core.lookup(b"example", false), Err(Error::OutcomeUnknown));
    assert!(matches!(
        core.begin(Mutation::Delete { name: b"example" }),
        Err(Error::OutcomeUnknown)
    ));

    let rows = vec![Ego::new(b"one".to_vec(), SecretKey::new(PUBLIC_MOCK)?)?];
    // A budget allowing the committed image but no second image rejects staging.
    let mut small = Core::new(
        Limits {
            egos: 2,
            name_bytes: 32,
            snapshot_bytes: 240,
        },
        rows,
    )?;
    assert!(matches!(
        small.begin(Mutation::Create { name: b"two", key }),
        Err(Error::Capacity)
    ));
    assert_eq!(small.snapshot().egos().len(), 1);
    Ok(())
}
