//! One public framing/scheduling model. No signature, hashing, keys, files or I/O.
use crate::*;
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Public framing and scheduling assertions must fail the model while propagating setup errors"
)]
fn public_framing_and_failed_test_preserves_history() -> Result<(), Error> {
    let ad = Advertisement::new(b"https://host.invalid/list")?;
    let mut encoded = [0; 128];
    let length = ad.encode(&mut encoded)?;
    assert_eq!(&encoded[2..4], &[0, 160]);
    assert_eq!(Advertisement::decode(&encoded[..length])?.uri(), ad.uri());
    assert!(Advertisement::decode(&encoded[..length - 1]).is_err());
    let mut frames = Frames::new(&[0, 4, 0, 16, 0, 4, 0, 16], 8)?;
    assert_eq!(frames.next().transpose()?.map(<[u8]>::len), Some(4));
    assert_eq!(frames.next().transpose()?.map(<[u8]>::len), Some(4));
    assert!(frames.next().is_none());
    assert!(Frames::new(&[0, 8, 0, 16], 8)?.next().transpose().is_err());
    let limits = Limits {
        urls: 1,
        learned: 1,
        hellos: 1,
        hello_bytes: 256,
        ..Default::default()
    };
    let modes = Modes {
        learning: true,
        ..Default::default()
    };
    let mut core = Core::new(limits, modes, &[], 0)?;
    let old = Uri::copy_from(b"https://old.invalid/")?;
    core.restore(Learned {
        uri: old.clone(),
        quality: 10,
        times_used: 0,
        created: 0,
        last_used: 0,
        hello_count: 0,
    })?;
    let new = Uri::copy_from(b"https://new.invalid/")?;
    let origin = Advertiser {
        source: 7,
        peer: [0x13; 32],
    };
    assert!(core.advertise(new.clone(), origin, true, 3_000_000)?);
    assert_eq!(
        core.learned().next().map(|row| row.uri.bytes()),
        Some(old.bytes())
    );
    let fetch = core
        .next(3_000_000, 0, 60_000_000)?
        .ok_or(Error::NotReady)?;
    core.finish(&fetch.job, DownloadOutcome::default(), 4_000_000)?;
    assert_eq!(
        core.learned().next().map(|row| row.uri.bytes()),
        Some(old.bytes())
    );
    assert_eq!(core.retire_without_time(&fetch.job), Err(Error::Stale));
    assert!(core.advertise(new.clone(), origin, true, 6_000_000)?);
    let next = core
        .next(6_000_000, 0, 60_000_000)?
        .ok_or(Error::NotReady)?;
    assert_ne!(fetch.job, next.job);
    core.finish(
        &next.job,
        DownloadOutcome {
            complete: true,
            ..Default::default()
        },
        7_000_000,
    )?;
    assert_eq!(
        core.learned().next().map(|row| row.uri.bytes()),
        Some(new.bytes())
    );
    assert_eq!(core.restore_retry_delay(u64::MAX), Err(Error::InvalidInput));
    Ok(())
}
