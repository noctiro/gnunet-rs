use super::*;
use crate::{HostError, test_support::pair};
use gnunet_crypto::{EddsaPublicKey, EddsaSignature};
use gnunet_hello::{HelloBuilder, Limits as HelloLimits};
use gnunet_pils::MasterKey;
use gnunet_pils::{Action, Service};
use gnunet_service_runtime::clock::SystemClock;
use gnunet_types::Error;
use gnunet_wire::official::{AbsoluteTime, pils::Request};
use std::{future::poll_fn, time::Duration};
use tokio::{io::AsyncWriteExt, time::timeout};

#[tokio::test(flavor = "current_thread")]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The finite Unix component checks verified actual source announcements and rejects a mismatched profile without fallback"
)]
async fn configured_deterministic_core_feed_adopts_address_changes_without_default_fallback()
-> Result<(), Box<dyn StdError>> {
    // Actual pure PILS generation/EdDSA and native Unix framing. This is
    // neither a normal PILS daemon nor a C interoperability observation.
    let mut config = Configuration::create(Arc::new(ProjectData::default()), Default::default())?;
    config.set_value(b"PILS", b"PROFILE", Some(b"deterministic"))?;
    let profile = ForegroundPolicy::read(&config)?.profile;
    let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
    let now = clock.sample()?.now.as_micros();
    let limits = HelloLimits {
        maximum_input_bytes: 4096,
        maximum_address_bytes: 2048,
        maximum_addresses: 16,
    };
    let master = MasterKey::from_seed([93; 32]);
    let mut service = Service::<4096>::new(MasterKey::from_seed([93; 32]), profile, now, limits)?;
    let (local, mut remote) = pair().await?;
    let mut feed = PilsFeed::with_profile(local, clock.clone(), profile)?;
    remote.write_all(service.announcement()).await?;
    let mut previous = timeout(
        Duration::from_secs(2),
        poll_fn(|cx| feed.poll_identity(cx, &master)),
    )
    .await??;
    assert_eq!(previous.public_key(), service.identity().public_key());
    for address in [
        b"tcp://127.0.0.1:1234".as_slice(),
        b"tcp://127.0.0.1:5678".as_slice(),
    ] {
        let mut addresses = [0; 2048];
        let mut builder = HelloBuilder::new(&mut addresses, limits);
        builder.add_address(address)?;
        // FEED carries unsigned address material; only the real Service
        // derives the active identity and produces the signed announcement.
        let unsigned = builder.with_signature(
            EddsaPublicKey::from_bytes([0; 32]),
            EddsaSignature::from_bytes([0; 64]),
            AbsoluteTime::from_micros(now + 1_000_000),
        );
        let mut block = vec![0; unsigned.block_len()?];
        unsigned.encode_block(&mut block)?;
        let mut input = vec![0; block.len() + 8];
        Request::Feed { block: &block }.encode(&mut input)?;
        let mut scratch = [0; 2048];
        let mut output = [0; 4096];
        assert!(matches!(
            service.receive(&input, &mut scratch, now, &mut output)?,
            Action::Broadcast {
                identity_changed: true
            }
        ));
        for part in service.announcement().chunks(3) {
            remote.write_all(part).await?;
        }
        let changed = timeout(
            Duration::from_secs(2),
            poll_fn(|cx| feed.poll_identity(cx, &master)),
        )
        .await??;
        assert_ne!(changed.public_key(), previous.public_key());
        assert_eq!(changed.public_key(), service.identity().public_key());
        previous = changed;
    }
    let (local, mut remote) = pair().await?;
    let mut default_feed = PilsFeed::with_clock(local, clock)?;
    remote.write_all(service.announcement()).await?;
    assert!(matches!(
        timeout(
            Duration::from_secs(2),
            poll_fn(|cx| default_feed.poll_identity(cx, &master))
        )
        .await?,
        Err(HostError::Protocol(Error::Authentication))
    ));
    Ok(())
}
