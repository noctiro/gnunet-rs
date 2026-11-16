//! Real private Unix application writes, with explicit modeled desired CORE IDs.
//! This is not a normal TRANSPORT daemon or C interoperability profile.
use super::*;
use crate::test_support::Directory;
use gnunet_client_host::EndpointSource;
use gnunet_service_runtime::clock::{RuntimeClock, SystemClock};
use gnunet_transport_application_host::{Application, Bounds, Step};
use gnunet_wire::official::Frame;
use std::{future::poll_fn, io, sync::Arc, time::Duration};
use tokio::{io::AsyncReadExt, time::timeout};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

async fn next(application: &mut Application) -> TestResult<Step> {
    Ok(timeout(Duration::from_secs(2), poll_fn(|cx| application.poll(cx))).await??)
}
async fn written(application: &mut Application, preferences: &mut Preferences) -> TestResult {
    loop {
        match next(application).await? {
            Step::Written { epoch, bytes: 44 } => {
                preferences.written(epoch)?;
                return Ok(());
            }
            Step::Activity => {}
            _ => {
                return Err(
                    io::Error::other("unexpected original preference write outcome").into(),
                );
            }
        }
    }
}
async fn read_frame(stream: &mut gnunet_service_runtime::local::Stream) -> TestResult<[u8; 44]> {
    let mut bytes = [0; 44];
    timeout(Duration::from_secs(2), stream.read_exact(&mut bytes)).await??;
    Ok(bytes)
}

fn admit(
    application: &mut Application,
    preferences: &mut Preferences,
    change: Change,
    clock: &dyn RuntimeClock,
) -> TestResult {
    application.preference(
        change.peer,
        change.cancel,
        Bounds::new(clock, Duration::from_secs(2))?,
    )?;
    preferences.admitted(change)?;
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "This finite real Unix fixture asserts original application epochs and observed standard preference opcodes"
)]
fn retired_application_never_carries_an_old_cancel_into_the_replacement_mq() -> TestResult {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            timeout(Duration::from_secs(10), async {
                let directory = Directory::new()?;
                let path = directory.0.join("t.sock");
                let listener = crate::test_support::Listener::bind(&path).await?;
                let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
                let source = EndpointSource::unix_with_clock(path, clock.clone());
                let mut application =
                    Application::new(source, 4, Duration::from_secs(2), Duration::from_secs(20))?;
                let mut preferences = Preferences::new(1)?;
                let capacity = preferences.registered.capacity();
                let old = [3; 32];
                let live = [4; 32];
                let Step::Attached(first) = next(&mut application).await? else {
                    return Err(io::Error::other("original application did not attach").into());
                };
                preferences.attached(first)?;
                let (mut original, _) =
                    timeout(Duration::from_secs(2), listener.accept()).await??;
                let change = preferences.next([old].into_iter()).ok_or(Error::NotReady)?;
                admit(&mut application, &mut preferences, change, clock.as_ref())?;
                written(&mut application, &mut preferences).await?;
                let frame = read_frame(&mut original).await?;
                assert_eq!(Frame::decode(&frame)?.header().message_type().value(), 1300);
                assert_eq!(&frame[8..40], &old);
                // This cancel has not been admitted; the actual original source is
                // lost before it can write. It must disappear with that MQ.
                assert!(
                    preferences
                        .next(std::iter::empty())
                        .is_some_and(|change| change.cancel && change.epoch == first)
                );
                drop(original);
                let Step::Lost {
                    report,
                    cause: None,
                } = next(&mut application).await?
                else {
                    return Err(io::Error::other("original Unix EOF was not retained").into());
                };
                assert_eq!(report.epoch, first);
                assert!(!report.submitted);
                preferences.retired(report.epoch)?;
                application.restart(Duration::from_secs(2))?;
                let Step::Attached(second) = next(&mut application).await? else {
                    return Err(io::Error::other("replacement application did not attach").into());
                };
                preferences.attached(second)?;
                assert!(second > first);
                let (mut replacement, _) =
                    timeout(Duration::from_secs(2), listener.accept()).await??;
                let change = preferences
                    .next([live].into_iter())
                    .ok_or(Error::NotReady)?;
                assert!(!change.cancel);
                admit(&mut application, &mut preferences, change, clock.as_ref())?;
                // A CORE disconnect while the positive is still pending cannot
                // overlap a cancel or forget that original partial-frame debt.
                assert!(preferences.next(std::iter::empty()).is_none());
                written(&mut application, &mut preferences).await?;
                let frame = read_frame(&mut replacement).await?;
                assert_eq!(Frame::decode(&frame)?.header().message_type().value(), 1300);
                assert_eq!(&frame[8..40], &live);
                let change = preferences
                    .next(std::iter::empty())
                    .ok_or(Error::NotReady)?;
                assert!(change.cancel && change.epoch == second && change.peer == live);
                admit(&mut application, &mut preferences, change, clock.as_ref())?;
                written(&mut application, &mut preferences).await?;
                let frame = read_frame(&mut replacement).await?;
                assert_eq!(Frame::decode(&frame)?.header().message_type().value(), 1301);
                assert_eq!(&frame[8..40], &live);
                assert!(preferences.registered.is_empty());
                assert_eq!(preferences.registered.capacity(), capacity);
                let report = application.close();
                preferences.retired(report.epoch)?;
                assert_eq!(report.epoch, second);
                assert!(!report.submitted);
                Ok::<_, Box<dyn std::error::Error>>(())
            })
            .await?
        })
}
