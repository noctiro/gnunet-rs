use super::*;
use crate::verify_lookup;

extern crate std;

const PKEY: &[u8] = include_bytes!("../../../gnunet-gnscrypto/tests/fixtures/pkey_ascii-block.bin");
const EDKEY: &[u8] =
    include_bytes!("../../../gnunet-gnscrypto/tests/fixtures/edkey_ascii-block.bin");

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "compare exact original ciphertext, IPC results and slot retirement"
)]
fn retains_full_width_and_expires_only_before_qualified_time() -> Result<(), Error> {
    let mut ordinary = [0; PKEY.len()];
    let mut wide = std::vec![0; wire::MAX_VALUE_SIZE];
    let mut cache = Cache::new([Slot::new(&mut wide)?, Slot::new(&mut ordinary)?]);
    let pquery = Block::decode(PKEY)?.query()?;
    let equery = Block::decode(EDKEY)?.query()?;
    let first = AbsoluteTime::from_micros(Block::decode(PKEY)?.expiration()?);
    let next = AbsoluteTime::from_micros(first.as_micros() + 1);
    let old = AbsoluteTime::from_micros(first.as_micros() - 1);

    let original = Request::Cache {
        rid: 7,
        expiration: AbsoluteTime::NEVER,
        block: PKEY,
    };
    assert!(matches!(
        cache.handle(original, first)?,
        Response::Cache {
            rid: 7,
            result: wire::OK
        }
    ));
    assert_eq!(cache.insert(PKEY, first)?, InsertOutcome::AlreadyPresent);
    assert_eq!(cache.expire_before(first)?, 0);
    let Response::Lookup {
        rid,
        expiration,
        block,
    } = cache.handle(
        Request::Lookup {
            rid: 19,
            query: &pquery,
        },
        first,
    )?
    else {
        return Err(Error::Conflict);
    };
    assert_eq!((rid, expiration, block), (19, first, PKEY));
    assert!(verify_lookup(&pquery, expiration, block)?.is_some());

    let mut equal_expiry = [0; PKEY.len()];
    equal_expiry.copy_from_slice(PKEY);
    equal_expiry[PKEY.len() - 1] ^= 1;
    assert_eq!(cache.insert(&equal_expiry, first)?, InsertOutcome::Replaced);
    assert_eq!(cache.insert(PKEY, first)?, InsertOutcome::Replaced);

    assert_eq!(cache.insert(EDKEY, first)?, InsertOutcome::Inserted);
    let mut replacement = std::vec![0; wire::MAX_VALUE_SIZE];
    replacement[..PKEY.len()].copy_from_slice(PKEY);
    replacement[..4].copy_from_slice(&(wire::MAX_VALUE_SIZE as u32).to_be_bytes());
    replacement[104..112].copy_from_slice(&next.to_be_bytes());
    assert_eq!(cache.insert(&replacement, first), Err(Error::Capacity));
    assert_eq!(
        cache
            .lookup(&pquery, first)?
            .ok_or(Error::NotFound)?
            .as_bytes(),
        PKEY
    );
    assert!(cache.delete(&equery, first)?);
    assert_eq!(cache.insert(&replacement, first)?, InsertOutcome::Replaced);
    assert_eq!(cache.insert(PKEY, first)?, InsertOutcome::RetainedNewer);
    assert_eq!(
        cache
            .lookup(&pquery, next)?
            .ok_or(Error::NotFound)?
            .as_bytes(),
        replacement.as_slice()
    );
    assert!(verify_lookup(&pquery, next, &replacement).is_err());
    assert_eq!(cache.blocks().count(), 1);

    let after = AbsoluteTime::from_micros(next.as_micros() + 1);
    assert!(cache.lookup(&pquery, after)?.is_none());
    assert_eq!(cache.expire_before(after)?, 1);
    assert!(matches!(
        cache.handle(original, after)?,
        Response::Cache {
            rid: 7,
            result: wire::NO
        }
    ));
    assert_eq!(cache.blocks().count(), 0);
    assert_eq!(cache.lookup(&pquery, old)?.map(Block::as_bytes), None);
    assert!(matches!(
        cache.lookup(&pquery, AbsoluteTime::NEVER),
        Err(Error::TimeUncertain)
    ));
    Ok(())
}
