use super::{Outcome, Source};
use crate::{Bounds, Close, Value, native::Report};
use gnunet_types::AbsoluteTime;
use std::{future::poll_fn, io, time::Duration};
use tokio::time::Instant;

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Verify the actual result and join receipts"
)]
fn native_registry_reports_results_and_retires_its_original_worker()
-> Result<(), Box<dyn std::error::Error>> {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()?
        .block_on(async {
            let hard = Instant::now() + Duration::from_secs(3);
            let bounds = Bounds::new(AbsoluteTime::from_micros(1), hard)?;
            let mut source = Source::native();
            if let Some(error) = source.preparation_error() {
                return Err(Box::<dyn std::error::Error>::from(io::Error::other(
                    error.clone(),
                )));
            }
            for (service, protocol, expected) in [
                ("443", "tcp", Some((6, 443))),
                ("scheme", "trust", Some((49152, 49152))),
                ("gnunet-registry-test-missing-58ba4b", "tcp", None),
            ] {
                let mut query = source.start(service, protocol, bounds)?;
                let value = tokio::time::timeout_at(hard, poll_fn(|cx| query.poll(cx))).await??;
                let Value::Service(actual) = value else {
                    return Err(io::Error::other("registry returned a different value kind").into());
                };
                assert_eq!(
                    actual.map(|value| (value.protocol().get(), value.port().get())),
                    expected
                );
                query.begin_close();
                let receipt = poll_fn(|cx| query.poll_close(cx)).await;
                assert!(matches!(
                    receipt,
                    Close::Closed(Report::Registry { outcome: Outcome::Resolved(reported) })
                        if reported == actual
                ));
            }
            source.begin_close();
            tokio::time::timeout_at(hard, poll_fn(|cx| source.poll_stopped(cx))).await??;
            assert!(source.is_stopped());
            Ok(())
        })
}
