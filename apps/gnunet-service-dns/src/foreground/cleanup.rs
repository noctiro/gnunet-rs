//! One fixed grace interval for original native and service-owner retirement.
use super::{
    observe,
    owners::{Failures, Owners},
};
use crate::{
    Failure,
    statistics::{self, Publisher},
};
use gnunet_dns_service_host::{Gateway, GatewayProgress};
use gnunet_program_host::{policy::Level, reporting::Reporter};
use std::{
    future::{Future, poll_fn},
    task::Poll,
    time::Duration,
};
use tokio::time::Instant;

pub(super) async fn finish(
    owners: &mut Owners<'_, '_>,
    reports: &Reporter,
    outcome: Result<(), Failure>,
    grace: Duration,
    #[cfg(all(
        any(target_os = "macos", target_os = "ios"),
        feature = "apple-dns-proxy"
    ))]
    mut provider: Option<&mut crate::provider::Runtime<'_>>,
) -> Result<(), Failure> {
    // No fallible early return below this point. Every failure retains the same
    // helper and original MQ/Resolver/statistics owners through retirement.
    if let Some(gateway) = owners.gateway.as_mut() {
        gateway.close(None, &mut |event| observe(reports, event));
    }
    #[cfg(all(
        any(target_os = "macos", target_os = "ios"),
        feature = "apple-dns-proxy"
    ))]
    if let Some(native) = provider.as_deref_mut() {
        native.close();
    }
    // Failed main work never creates a fresh statistics drain. Retire this
    // same publisher without sampling its logical clock or replacing its MQ.
    let publish_final = outcome.is_ok();
    if !publish_final || reports.failed() {
        owners.abort_statistics();
    } else {
        let counts = owners.gateway.as_ref().map_or([0; 6], Gateway::statistics);
        if let Some(publisher) = owners.statistics.as_mut()
            && let Err(error) = publisher.begin_close(statistics::snapshot(counts), grace)
        {
            owners.statistics_failed(error);
        }
    }
    if reports.failed() {
        owners.abort_statistics();
    }
    let now = Instant::now();
    let target = now.checked_add(grace);
    let until = target.unwrap_or(now);
    let mut cleanup: Option<Failure> = target
        .is_none()
        .then(|| Box::new(gnunet_types::Error::Overflow) as Failure);
    let mut resolver_error: Option<Failure> = None;
    let mut gateway_done = owners.gateway.is_none();
    #[cfg(all(
        any(target_os = "macos", target_os = "ios"),
        feature = "apple-dns-proxy"
    ))]
    let mut provider_done = provider.is_none();
    #[cfg(not(all(
        any(target_os = "macos", target_os = "ios"),
        feature = "apple-dns-proxy"
    )))]
    let provider_done = true;
    let drained = tokio::time::timeout_at(
        until,
        poll_fn(|cx| {
            reports.register(cx);
            let mut activity = false;
            // Original publisher hard deadlines precede every provider/helper
            // wait. This guard performs no canonical sample or native IO.
            if let Some(publisher) = owners.statistics.as_mut()
                && !publisher.is_closed()
            {
                match publisher.poll_native_guard(cx) {
                    Poll::Ready(Err(error)) => owners.statistics_failed(error),
                    Poll::Ready(Ok(_)) => activity = true,
                    Poll::Pending => {}
                }
            }
            if reports.failed() {
                owners.abort_statistics();
            }
            // Closing Gateway polls only its original helper's exit/force-stop
            // obligations. A permanently failed Reporter must not suppress that
            // poll or manufacture local Ready progress/busy-looping.
            if !gateway_done && let Some(gateway) = owners.gateway.as_mut() {
                match gateway.poll(cx, &[], Some(until), &mut |event| observe(reports, event)) {
                    Poll::Ready(Ok(GatewayProgress::Stopped)) => gateway_done = true,
                    Poll::Ready(Ok(GatewayProgress::WaitDeadline)) | Poll::Pending => {}
                    Poll::Ready(Ok(_)) => activity = true,
                    Poll::Ready(Err(error)) => {
                        if cleanup.is_none() {
                            cleanup = Some(Box::new(error));
                        }
                    }
                }
            }
            // A helper/old-source diagnostic can fail during the preceding
            // poll; fence before any following statistics or Resolver class.
            if reports.failed() {
                owners.abort_statistics();
            }
            if publish_final
                && !reports.failed()
                && let Some(publisher) = owners.statistics.as_mut()
                && !publisher.is_closed()
            {
                match publisher.poll(cx, Some(until)) {
                    Poll::Ready(Err(error)) => owners.statistics_failed(error),
                    Poll::Ready(Ok(_)) => activity = true,
                    Poll::Pending => {}
                }
            }
            if reports.failed() {
                owners.abort_statistics();
            }
            let stats_done = owners.statistics.as_ref().is_none_or(Publisher::is_closed);
            #[cfg(all(
                any(target_os = "macos", target_os = "ios"),
                feature = "apple-dns-proxy"
            ))]
            if !provider_done && let Some(native) = provider.as_deref_mut() {
                match native.poll_cleanup(cx, gateway_done && stats_done, reports) {
                    Poll::Ready(Ok(())) => provider_done = true,
                    Poll::Ready(Err(error)) => {
                        if cleanup.is_none() {
                            cleanup = Some(error);
                        }
                    }
                    Poll::Pending => {}
                }
            }
            if gateway_done && stats_done && provider_done {
                return Poll::Ready(());
            }
            if publish_final && !reports.failed() && !stats_done && resolver_error.is_none() {
                let progress = {
                    let mut resolving =
                        std::pin::pin!(owners.resolver.drive_waiting(Some(until), |event| {
                            reports.debug(
                                "dns.resolver.cleanup.activity",
                                format_args!("dns cleanup Resolver: {event:?}"),
                            )
                        }));
                    resolving.as_mut().poll(cx)
                };
                match progress {
                    Poll::Ready(Err(error)) => {
                        resolver_error = Some(Box::new(error));
                        owners.abort_statistics();
                    }
                    Poll::Ready(Ok(_)) => activity = true,
                    Poll::Pending => {}
                }
                // The drive future's borrow has ended before physical abort.
                // A diagnostic emitted by that exact poll may have failed.
                if reports.failed() {
                    owners.abort_statistics();
                }
            }
            if activity {
                cx.waker().wake_by_ref();
            }
            Poll::Pending
        }),
    )
    .await;
    if drained.is_err() {
        // A caller timeout may win before the helper's native force-stop guard.
        // Poll it once without canonical time; absent actual exit stays unknown.
        if let Some(gateway) = owners.gateway.as_mut() {
            poll_fn(|cx| {
                let _actual =
                    gateway.poll(cx, &[], Some(until), &mut |event| observe(reports, event));
                Poll::Ready(())
            })
            .await;
        }
    }
    let retirement = drained.err().map(|error| -> Failure { format!("dns packet source/statistics retirement unconfirmed within fixed native grace: {error}; privileged cleanup remains unclaimed").into() });
    owners.abort_statistics();
    let publisher = owners.statistics.as_ref().map(Publisher::report);
    let gateway = owners.gateway.take().map(Gateway::into_report);
    reports.message(
        Level::INFO,
        "dns.stopped",
        format_args!("STOPPED dns gateway={gateway:?} statistics={publisher:?}"),
    );
    let resolver_close = owners
        .resolver
        .disconnect()
        .err()
        .map(|e| Box::new(e) as Failure);
    let resolver_io = owners.resolver.take_io_error();
    let resolver_connect = owners.resolver.take_connect_error();
    owners.done = true;
    Failures {
        original: outcome.err(),
        cleanup,
        statistics: owners.stats_error.take(),
        statistics_cleanup: owners.stats_cleanup.take(),
        resolver_drain: resolver_error,
        resolver_close,
        resolver_io,
        resolver_connect,
        retirement,
        gateway,
        publisher,
    }
    .finish()
}
