//! Database replay follows official SET arithmetic without a synthetic client.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible tests assert official file replay behavior"
)]
use gnunet_statistics::{Reply, Selector, Set, Statistics};
use gnunet_types::Error;

#[test]
fn replay_accepts_noncanonical_set_flags_and_needs_no_client_capacity() -> Result<(), Error> {
    let mut core = Statistics::<1, 4, 0, 0, 0>::new();
    let selector = Selector {
        subsystem: b"s",
        name: b"n",
    };
    let mut bytes = [0; 20];
    let n = Set {
        selector,
        flags: 2,
        value: 9,
    }
    .encode(&mut bytes)?;
    core.replay(&bytes[..n])?;
    let n = Set {
        selector,
        flags: 0x8000_0001,
        value: (-3i64) as u64,
    }
    .encode(&mut bytes)?;
    assert_eq!(core.restore(&bytes[..n]), Err(Error::InvalidInput));
    let outcome = core.replay(&bytes[..n])?;
    assert_eq!(outcome.value, 6);
    assert!(!outcome.persistent);
    assert_eq!(core.persistent().next(), None);
    assert_eq!(core.client_count(), 0);
    assert_eq!(core.replay(b"\0\x04\0\xab"), Err(Error::Unsupported));
    Ok(())
}

#[test]
fn a_live_client_prevents_replay_and_rejection_preserves_the_value() -> Result<(), Error> {
    let mut core = Statistics::<1, 4, 1, 0, 0>::new();
    let selector = Selector {
        subsystem: b"s",
        name: b"n",
    };
    let mut bytes = [0; 20];
    let n = Set {
        selector,
        flags: 2,
        value: 9,
    }
    .encode(&mut bytes)?;
    core.replay(&bytes[..n])?;
    let client = core.connect()?;
    let n = Set {
        selector,
        flags: 0,
        value: 99,
    }
    .encode(&mut bytes)?;
    assert_eq!(core.replay(&bytes[..n]), Err(Error::Conflict));
    let Some(Reply::Value(value)) = core.get(client, selector)?.next() else {
        return Err(Error::NotFound);
    };
    assert_eq!(value.value, 9);
    assert!(value.persistent());
    core.disconnect(client)?;
    assert_eq!(core.replay(&bytes[..n])?.value, 99);
    Ok(())
}
