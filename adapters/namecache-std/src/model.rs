//! One focused pure production-dispatch model. Published ciphertext/query only;
//! no native socket, key fixture, signature operation, entropy or filesystem.
use crate::dispatch;
use gnunet_namecache::{Cache, Limits};
use gnunet_types::Error;
use gnunet_wire::official::{
    AbsoluteTime,
    namecache::{NO, OK, Request, Response, SYSERR},
};
const PKEY: &[u8] =
    include_bytes!("../../../crates/gnunet-gnscrypto/tests/fixtures/pkey_ascii-block.bin");
const PQUERY: &[u8; 64] =
    include_bytes!("../../../crates/gnunet-gnscrypto/tests/fixtures/pkey_ascii-query.bin");
const EDKEY: &[u8] =
    include_bytes!("../../../crates/gnunet-gnscrypto/tests/fixtures/edkey_ascii-block.bin");
fn request(request: Request<'_>) -> Result<Vec<u8>, Error> {
    let mut bytes = dispatch::allocate(request.encoded_len()?)?;
    request.encode(&mut bytes)?;
    Ok(bytes)
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The dispatch model asserts original RID and real mutation/capacity behavior"
)]
fn original_rid_preallocation_and_real_memory_results() -> Result<(), Error> {
    let mut cache = Cache::new(Limits {
        entries: 1,
        bytes: 1024,
        block_bytes: 512,
    })?;
    let create = request(Request::Cache {
        rid: 0xfedcba98,
        expiration: AbsoluteTime::NEVER,
        block: PKEY,
    })?;
    assert_eq!(dispatch::response_size(&cache, &create)?, 12);
    assert!(matches!(
        dispatch::apply(&mut cache, &create, &mut [0; 11]),
        Err(Error::Capacity)
    ));
    assert_eq!(cache.stats().entries, 0); // no mutation before final frame capacity
    let mut out = dispatch::allocate(12)?;
    let applied = dispatch::apply(&mut cache, &create, &mut out)?;
    assert_eq!(applied.rid, 0xfedcba98);
    assert_eq!(applied.result, Some(OK));
    assert!(matches!(
        Response::decode(&out)?,
        Response::Cache {
            rid: 0xfedcba98,
            result: OK
        }
    ));
    assert_eq!(cache.stats().entries, 1);
    let expiry = cache.lookup(PQUERY)?.ok_or(Error::NotFound)?.expiration()?;
    assert_eq!(expiry, 17999736901000000); // inner block, not outer NEVER
    let lookup = request(Request::Lookup {
        rid: 7,
        query: PQUERY,
    })?;
    let needed = dispatch::response_size(&cache, &lookup)?;
    let mut reply = dispatch::allocate(needed)?;
    dispatch::apply(&mut cache, &lookup, &mut reply)?;
    match Response::decode(&reply)? {
        Response::Lookup {
            rid: 7,
            expiration,
            block,
        } => {
            assert_eq!(expiration.as_micros(), expiry);
            assert_eq!(block, PKEY);
        }
        _ => return Err(Error::Malformed),
    }
    let full = request(Request::Cache {
        rid: 8,
        expiration: AbsoluteTime::UNIX_EPOCH,
        block: EDKEY,
    })?;
    let failed = dispatch::apply(&mut cache, &full, &mut out)?;
    assert_eq!(failed.rid, 8);
    assert_eq!(failed.result, Some(SYSERR));
    assert_eq!(cache.stats().entries, 1);
    let delete = request(Request::Delete {
        rid: 9,
        query: PQUERY,
    })?;
    assert!(matches!(
        dispatch::apply(&mut cache, &delete, &mut [0; 11]),
        Err(Error::Capacity)
    ));
    assert_eq!(cache.stats().entries, 1);
    dispatch::apply(&mut cache, &delete, &mut out)?;
    assert!(matches!(
        Response::decode(&out)?,
        Response::Delete { rid: 9, result: OK }
    ));
    dispatch::apply(&mut cache, &delete, &mut out)?;
    assert!(matches!(
        Response::decode(&out)?,
        Response::Delete { rid: 9, result: NO }
    ));
    let mut miss = dispatch::allocate(dispatch::response_size(&cache, &lookup)?)?;
    dispatch::apply(&mut cache, &lookup, &mut miss)?;
    assert!(matches!(
        Response::decode(&miss)?,
        Response::Lookup {
            rid: 7,
            expiration: AbsoluteTime::UNIX_EPOCH,
            block: b""
        }
    ));
    Ok(())
}
