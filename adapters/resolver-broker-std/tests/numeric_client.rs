//! Exact local CLIENT callback stack uses real socket effect before NULL/free.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Actual loopback and original-slot sequencing assertions"
)]
use gnunet_config::Configuration;
use gnunet_resolver_broker::{FamilyProfile, LiveConfiguration, Progress, SystemClock, broker};
use std::{
    error::Error,
    future::{Future, poll_fn},
    net::Ipv4Addr,
    sync::Arc,
    task::Poll,
    time::Duration,
};
use tokio::{
    net::TcpListener,
    time::{Instant, timeout},
};
type Result<T = ()> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
#[test]
fn numeric_client_starts_real_socket_then_finishes_own_callback_stack_before_connection_notice()
-> Result {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let mut cfg = Configuration::default();
            cfg.set_value(b"owned", b"HOSTNAME", Some(b"127.0.0.1"))?;
            cfg.set_value(
                b"owned",
                b"PORT",
                Some(listener.local_addr()?.port().to_string().as_bytes()),
            )?;
            let native = gnunet_resolver_broker::native_profile()?;
            let profile = FamilyProfile::new(
                native.encode(gnunet_resolver_broker::Family::V4),
                native.encode(gnunet_resolver_broker::Family::V6),
            )?;
            let (ctx, mut driver) = broker::<2, 64>(
                LiveConfiguration::new(Configuration::default()),
                Default::default(),
                profile,
                Arc::new(SystemClock),
            )?;
            let endpoint = gnunet_client_host::Endpoint::configuration(
                cfg,
                b"owned",
                ctx.resolution_context(),
            )?;
            let mut attempt = Box::pin(endpoint.attempt(0));
            poll_fn(|cx| {
                assert!(attempt.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            assert_eq!(ctx.pending_requests()?, 1);
            assert_eq!(
                driver
                    .drive(Some(Instant::now() + Duration::from_secs(1)), |_| {})
                    .await?,
                Progress::Activity
            );
            // Deliver the first address to the real generic CLIENT. No Driver poll is
            // allowed between its native effect and the following own NULL callback.
            let mut ready = None;
            poll_fn(|cx| {
                if let Poll::Ready(value) = attempt.as_mut().poll(cx) {
                    ready = Some(value);
                }
                Poll::Ready(())
            })
            .await;
            assert_eq!(
                ctx.pending_requests()?,
                0,
                "own NULL/free must finish before a later write-ready connection notice"
            );
            // No subsequent polling initiates this connection: the first address effect
            // already caused the actual loopback kernel connection in the prior poll.
            let (_accepted, _) = timeout(Duration::from_secs(1), listener.accept()).await??;
            let connection = match ready {
                Some(value) => value?,
                None => timeout(Duration::from_secs(1), attempt).await??,
            };
            drop(connection);
            driver.disconnect()?;
            Ok(())
        })
}

#[test]
fn numeric_address_hold_precedes_real_socket_and_only_own_null_continues() -> Result {
    use gnunet_resolver_broker::{Family, Reply};
    use gnunet_types::Duration as CoreDuration;
    use tokio::io::AsyncReadExt;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let native = gnunet_resolver_broker::native_profile()?;
            let profile = FamilyProfile::new(
                native.encode(gnunet_resolver_broker::Family::V4),
                native.encode(gnunet_resolver_broker::Family::V6),
            )?;
            let (ctx, mut driver) = broker::<4, 64>(
                LiveConfiguration::new(Configuration::default()),
                Default::default(),
                profile,
                Arc::new(SystemClock),
            )?;
            let provider = ctx.resolution_context();
            let mut lookup = provider
                .lookup(b"127.0.0.1", Duration::from_secs(5))?
                .ok_or("numeric lookup denied")?;
            assert_eq!(
                driver
                    .drive(Some(Instant::now() + Duration::from_secs(1)), |_| {})
                    .await?,
                Progress::Activity
            );
            let address = poll_fn(|cx| lookup.poll_next(cx))
                .await?
                .ok_or("no numeric address")?;
            let mut unrelated = ctx.ip_get(b"localhost", Family::Any, CoreDuration(0))?;
            assert_eq!(ctx.pending_requests()?, 2);
            assert_eq!(
                driver
                    .drive(Some(Instant::now() + Duration::from_millis(10)), |_| {})
                    .await?,
                Progress::WaitDeadline,
                "the actual address callback has not returned yet"
            );
            let stream =
                tokio::net::TcpStream::connect((address, listener.local_addr()?.port())).await?;
            let (mut accepted, _) = timeout(Duration::from_secs(1), listener.accept()).await??;
            assert_eq!(ctx.pending_requests()?, 2);
            lookup.address_effect_done()?;
            // No broker drive is allowed here. Only this original local callback
            // stack resumes, including its actual NULL/free; the other task stays.
            assert_eq!(poll_fn(|cx| lookup.poll_next(cx)).await?, None);
            assert_eq!(ctx.pending_requests()?, 1);
            assert!(
                timeout(Duration::from_millis(1), unrelated.next())
                    .await
                    .is_err()
            );
            unrelated.cancel()?;
            assert_eq!(ctx.pending_requests()?, 0);
            drop(lookup);
            drop(stream);
            assert_eq!(accepted.read(&mut [0]).await?, 0);
            // The public callback API and its borrow contract remain independent.
            let mut public = ctx.ip_get(b"127.0.0.1", Family::Any, CoreDuration(0))?;
            assert_eq!(
                driver
                    .drive(Some(Instant::now() + Duration::from_secs(1)), |_| {})
                    .await?,
                Progress::Activity
            );
            let lease = public.next().await?.ok_or("missing public value")?;
            assert!(matches!(lease.reply()?, Reply::Address(_)));
            assert_eq!(ctx.pending_requests()?, 1);
            drop(lease);
            assert_eq!(
                ctx.pending_requests()?,
                1,
                "public Query/Delivery must keep its prior explicit-driver semantics"
            );
            public.cancel()?;
            Ok(())
        })
}
