//! A local publisher reuses one compiled expression and waits for real receipts.
#![cfg(feature = "alloc")]

use gnunet_crypto::EddsaPrivateKey;
use gnunet_regex::accept::ACCEPT_PURPOSE;
use gnunet_regex_service::{Core, Error, Times, Work};
use gnunet_wire::official::regex::StringBytes;

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Check explicit compiler and lifecycle results"
)]
fn each_local_round_requires_the_original_put_and_sign_completions() -> Result<(), Error> {
    let mut core = Core::new(Default::default())?;
    let publisher = core.prepare_local_announcement(StringBytes::new(b"GNVPN0123456789")?, 8)?;
    let identity = EddsaPrivateKey::from_seed([42; 32]);
    let peer = *identity.public_key().as_bytes();
    let now = Times {
        monotonic: 8,
        absolute: 15,
    };
    core.set_identity(Some(peer), now)?;
    core.tick(now)?;
    assert!(core.next_work()?.is_none());

    for count in 1..=3 {
        core.announce_local(&publisher, now)?;
        assert_eq!(core.announce_local(&publisher, now), Err(Error::Order));
        assert_eq!(core.local_rounds(&publisher)?, count - 1);
        let mut signed = 0;
        let mut states = 0;
        for _ in 0..128 {
            core.tick(now)?;
            match core.next_work()? {
                Some(Work::Put { job, kind, .. }) => {
                    assert!(matches!(kind, 22 | 23));
                    states += usize::from(kind == 22);
                    assert!(core.put_admitted(&job));
                    core.put_complete(&job)?;
                }
                Some(Work::Sign { job, material, .. }) => {
                    signed += 1;
                    let signature = *identity.sign(ACCEPT_PURPOSE, material)?.as_bytes();
                    core.complete_signature(&job, peer, signature, now)?;
                }
                None => break,
                Some(_) => return Err(Error::Order),
            }
        }
        assert!(signed > 0 && states > 0);
        assert_eq!(core.local_rounds(&publisher)?, count);
        core.set_identity(Some(peer), now)?;
        core.tick(now)?;
        assert!(core.next_work()?.is_none());
    }
    assert!(core.retire_local(&publisher)?);
    assert!(core.quiescent());
    Ok(())
}
