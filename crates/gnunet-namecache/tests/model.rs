//! One focused pure model with preexisting published ciphertext/query fixtures.
//! No private fixture, entropy, key generation, decryption, native I/O or socket.
#![cfg(feature = "alloc")]
use gnunet_namecache::{Block, Cache, InsertOutcome, Limits, verify_lookup};
use gnunet_types::Error;
use gnunet_wire::official::{
    AbsoluteTime,
    namecache::{NO, OK, Request, Response, SYSERR},
};
const PKEY: &[u8] = include_bytes!("../../gnunet-gnscrypto/tests/fixtures/pkey_ascii-block.bin");
const PQUERY: &[u8; 64] =
    include_bytes!("../../gnunet-gnscrypto/tests/fixtures/pkey_ascii-query.bin");
const EDKEY: &[u8] = include_bytes!("../../gnunet-gnscrypto/tests/fixtures/edkey_ascii-block.bin");
const EQUERY: &[u8; 64] =
    include_bytes!("../../gnunet-gnscrypto/tests/fixtures/edkey_ascii-query.bin");
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The public-cipher model asserts wire, verification and actual cache behavior"
)]
fn official_namecache_block_model() -> Result<(), Error> {
    let original = Block::decode(PKEY)?;
    let expiry = AbsoluteTime::from_micros(original.expiration()?);
    // Both official key constructions need public-only cache-client verification.
    for (query, bytes) in [(PQUERY, PKEY), (EQUERY, EDKEY)] {
        let block = Block::decode(bytes)?;
        block.verify_signature()?;
        assert_eq!(block.query()?, *query);
        assert!(
            verify_lookup(query, AbsoluteTime::from_micros(block.expiration()?), bytes)?.is_some()
        );
    }
    assert!(verify_lookup(PQUERY, AbsoluteTime::UNIX_EPOCH, b"ignored-tail")?.is_none());
    assert!(matches!(
        verify_lookup(EQUERY, expiry, PKEY),
        Err(Error::Authentication)
    ));
    assert!(matches!(
        verify_lookup(
            PQUERY,
            AbsoluteTime::from_micros(expiry.as_micros() + 1),
            PKEY
        ),
        Err(Error::Malformed)
    ));
    let mut frame = [0x55; 512];
    let n = Request::Cache {
        rid: 0x01020304,
        expiration: AbsoluteTime::UNIX_EPOCH,
        block: PKEY,
    }
    .encode(&mut frame)?;
    assert_eq!(n, 192);
    assert_eq!(
        &frame[..16],
        &[0, 192, 1, 177, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0]
    );
    assert!(matches!(
        Request::decode(&frame[..n])?,
        Request::Cache {
            rid: 0x01020304,
            ..
        }
    ));
    let n = Request::Lookup {
        rid: 5,
        query: PQUERY,
    }
    .encode(&mut frame)?;
    assert_eq!(n, 72);
    assert_eq!(&frame[..8], &[0, 72, 1, 175, 0, 0, 0, 5]);
    assert!(matches!(
        Request::decode(&frame[..n])?,
        Request::Lookup { rid: 5, .. }
    ));
    let n = Response::Delete { rid: 7, result: -7 }.encode(&mut frame)?;
    assert_eq!(n, 12);
    assert_eq!(
        &frame[..12],
        &[0, 12, 7, 59, 0, 0, 0, 7, 255, 255, 255, 249]
    );
    assert!(matches!(
        Response::decode(&frame[..n])?,
        Response::Delete { rid: 7, result: -7 }
    ));
    let n = Response::Lookup {
        rid: 8,
        expiration: AbsoluteTime::UNIX_EPOCH,
        block: b"ignored",
    }
    .encode(&mut frame)?;
    assert!(matches!(
        Response::decode(&frame[..n])?,
        Response::Lookup {
            rid: 8,
            block: b"ignored",
            ..
        }
    ));

    let mut cache = Cache::new(Limits {
        entries: 1,
        bytes: 1024,
        block_bytes: 512,
    })?;
    assert_eq!(cache.insert(PKEY)?, InsertOutcome::Inserted);
    assert_eq!(cache.insert(PKEY)?, InsertOutcome::AlreadyPresent);
    let mut older = PKEY.to_vec();
    older[104..112].copy_from_slice(&(expiry.as_micros() - 1).to_be_bytes());
    assert_eq!(cache.insert(&older)?, InsertOutcome::RetainedNewer);
    assert_eq!(
        cache.lookup(PQUERY)?.ok_or(Error::NotFound)?.as_bytes(),
        PKEY
    );
    assert!(matches!(
        cache.handle(Request::Cache {
            rid: 9,
            expiration: AbsoluteTime::NEVER,
            block: EDKEY
        })?,
        Response::Cache {
            rid: 9,
            result: SYSERR
        }
    ));
    assert_eq!(cache.stats().entries, 1);
    let mut newer = PKEY.to_vec();
    newer[104..112].copy_from_slice(&(expiry.as_micros() + 2).to_be_bytes());
    // Mutated unsigned ciphertext is only the opaque backend model, not a
    // cryptographic acceptance vector. A client still rejects invalid signatures.
    assert_eq!(cache.insert(&newer)?, InsertOutcome::Replaced);
    assert_eq!(
        cache.expire_before(AbsoluteTime::from_micros(expiry.as_micros() + 2)),
        0
    );
    assert_eq!(
        cache.expire_before(AbsoluteTime::from_micros(expiry.as_micros() + 3)),
        1
    );
    assert!(matches!(
        cache.handle(Request::Lookup {
            rid: 10,
            query: PQUERY
        })?,
        Response::Lookup {
            rid: 10,
            expiration: AbsoluteTime::UNIX_EPOCH,
            block: b""
        }
    ));
    assert!(matches!(
        cache.handle(Request::Delete {
            rid: 11,
            query: PQUERY
        })?,
        Response::Delete {
            rid: 11,
            result: NO
        }
    ));
    assert!(matches!(
        cache.handle(Request::Cache {
            rid: 12,
            expiration: AbsoluteTime::NEVER,
            block: PKEY
        })?,
        Response::Cache {
            rid: 12,
            result: OK
        }
    ));
    assert_eq!(
        cache.lookup(PQUERY)?.ok_or(Error::NotFound)?.expiration()?,
        expiry.as_micros()
    );
    assert!(matches!(
        cache.handle(Request::Delete {
            rid: 13,
            query: PQUERY
        })?,
        Response::Delete {
            rid: 13,
            result: OK
        }
    ));
    Ok(())
}
