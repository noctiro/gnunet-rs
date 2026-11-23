//! Fair polling of original gateway, resolver, statistics and provider owners.
use super::{observe, owners::Owners};
use crate::Failure;
use gnunet_dns_service_host::GatewayProgress;
use gnunet_service_runtime::service::Listener;
use gnunet_service_startup::StopSignals as Signals;
use std::{
    future::{Future, poll_fn},
    task::Poll,
};

#[cfg(all(
    any(target_os = "macos", target_os = "ios"),
    feature = "apple-dns-proxy"
))]
pub(super) const TURN_CLASSES: usize = 4;
#[cfg(not(all(
    any(target_os = "macos", target_os = "ios"),
    feature = "apple-dns-proxy"
)))]
pub(super) const TURN_CLASSES: usize = 3;

pub(super) enum Turn<'id> {
    Stop,
    Resolver,
    Statistics,
    Gateway(GatewayProgress<'id>),
    #[cfg(all(
        any(target_os = "macos", target_os = "ios"),
        feature = "apple-dns-proxy"
    ))]
    Provider,
}
pub(super) async fn turn<'id>(
    owners: &mut Owners<'id, '_>,
    signals: &mut Option<Signals>,
    listeners: &[Listener<'_>],
    first: usize,
    #[cfg(all(
        any(target_os = "macos", target_os = "ios"),
        feature = "apple-dns-proxy"
    ))]
    mut provider: Option<&mut crate::provider::Runtime<'_>>,
) -> Result<Turn<'id>, Failure> {
    // A temporary drive future borrows only this original Resolver. It is dropped
    // before caller cleanup/disconnect or any owned event is applied elsewhere.
    let reports = owners.reports.clone();
    let (gateway, resolver, publisher, stats_error, stats_cleanup) = (
        &mut owners.gateway,
        &mut owners.resolver,
        &mut owners.statistics,
        &mut owners.stats_error,
        &mut owners.stats_cleanup,
    );
    let gateway = gateway.as_mut().ok_or("DNS gateway not constructed")?;
    let mut resolving = std::pin::pin!(resolver.drive_waiting(None, |event| reports.debug(
        "dns.resolver.activity",
        format_args!("dns shared Resolver: {event:?}")
    )));
    poll_fn(|cx| {
        reports.register(cx);
        // Only original native deadlines are checked before any canonical-clock
        // wait. A publisher failure fences itself; it does not fail interception.
        if let Some(publisher) = publisher.as_mut()
            && !publisher.is_closed()
            && let Poll::Ready(Err(error)) = publisher.poll_native_guard(cx)
        {
            reports.warning(
                "dns.statistics.failure",
                format_args!("dns original statistics publisher: {error}"),
            );
            if stats_error.is_none() {
                *stats_error = Some(error);
            } else if stats_cleanup.is_none() {
                *stats_cleanup = Some(error);
            }
        }
        if reports.failed() {
            return Poll::Ready(Err("DNS selected diagnostic destination failed".into()));
        }
        if let Some(signals) = signals.as_mut()
            && let Poll::Ready(signal) = signals.poll_stop(cx)
        {
            return Poll::Ready(signal.map(|()| Turn::Stop).map_err(Into::into));
        }
        for n in 0..TURN_CLASSES {
            if reports.failed() {
                return Poll::Ready(Err("DNS selected diagnostic destination failed".into()));
            }
            let step = match (first + n) % TURN_CLASSES {
                0 => gateway
                    .poll(cx, listeners, None, &mut |event| observe(&reports, event))
                    .map(|v| v.map(Turn::Gateway).map_err(|e| Box::new(e) as Failure)),
                1 => resolving.as_mut().poll(cx).map(|v| {
                    v.map(|_| Turn::Resolver)
                        .map_err(|e| Box::new(e) as Failure)
                }),
                2 => {
                    if let Some(publisher) = publisher.as_mut()
                        && !publisher.is_closed()
                    {
                        match publisher.poll(cx, None) {
                            Poll::Ready(Err(error)) => {
                                reports.warning(
                                    "dns.statistics.failure",
                                    format_args!("dns original statistics publisher: {error}"),
                                );
                                if stats_error.is_none() {
                                    *stats_error = Some(error);
                                } else if stats_cleanup.is_none() {
                                    *stats_cleanup = Some(error);
                                }
                                Poll::Ready(Ok(Turn::Statistics))
                            }
                            Poll::Ready(Ok(_)) => Poll::Ready(Ok(Turn::Statistics)),
                            Poll::Pending => Poll::Pending,
                        }
                    } else {
                        Poll::Pending
                    }
                }
                #[cfg(all(
                    any(target_os = "macos", target_os = "ios"),
                    feature = "apple-dns-proxy"
                ))]
                3 => match provider.as_deref_mut() {
                    Some(native) => native.poll(cx, gateway, &reports).map(|result| {
                        result.map(|progress| match progress {
                            crate::provider::Progress::Activity => Turn::Provider,
                            crate::provider::Progress::Stop => Turn::Stop,
                        })
                    }),
                    None => Poll::Pending,
                },
                _ => Poll::Pending,
            };
            // Preserve any actual failure before observing the later diagnostic
            // latch. No following class can admit work after its logger failed.
            if step.is_ready() {
                return step;
            }
        }
        if reports.failed() {
            return Poll::Ready(Err("DNS selected diagnostic destination failed".into()));
        }
        Poll::Pending
    })
    .await
}
