//! Original resolver streams, authority, FIFO and cancellation contracts.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Actual owned stream and original request assertions"
)]
#[path = "../../ipc-unix/tests/support/clock_source.rs"]
pub mod clock_source;
#[path = "support/assertions.rs"]
mod support;
use clock_source::Adjustable;
use gnunet_client::resolver::{Reply as WireReply, Request};
use gnunet_client_host::ConnectError;
use gnunet_config::Configuration;
use gnunet_resolver_broker::{
    BrokerError, Completion, Driver, DriverEvent, Family, Limits, LiveConfiguration, Progress,
    SystemClock, broker,
};
use gnunet_types::{Duration as QueryDuration, Error as CoreError};
use gnunet_wire::official::Frame;
use std::{
    future::{Future, poll_fn},
    net::Ipv4Addr,
    sync::Arc,
    task::Poll,
    time::Duration,
};
#[path = "support/local.rs"]
mod local;
use local::Listener as LocalListener;
use support::{Dir, Result, Value, cfg, frame, next, profile, response, runtime, setup};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::{Instant, sleep, timeout},
};

const CLOCK_START: u64 = 1_000_000;
const QUERY_TIMEOUT: QueryDuration = QueryDuration(15_000);

async fn drive_until_event<const R: usize, const N: usize, T>(
    driver: &mut Driver<R, N>,
    mut select: impl FnMut(DriverEvent) -> Option<T>,
) -> Result<T> {
    let until = Instant::now() + Duration::from_secs(3);
    loop {
        let mut event = None;
        let progress = driver.drive(Some(until), |e| event = select(e)).await?;
        if let Some(event) = event {
            return Ok(event);
        }
        if progress != Progress::Activity {
            return Err(format!("expected resolver event, driver returned {progress:?}").into());
        }
    }
}

#[test]
fn invalid_configuration_fastpaths_are_lazy_async_and_cancel_between_callbacks() -> Result {
    runtime()?.block_on(async {
        let (ctx, mut driver) = broker::<8, 128>(
            LiveConfiguration::new(Configuration::default()),
            Limits {
                max_frame_bytes: 8,
                io_chunk_bytes: 1,
                ..Default::default()
            },
            profile()?,
            Arc::new(SystemClock),
        )?;
        assert!(matches!(
            ctx.ip_get(b"arbitrary.invalid", Family::Any, QueryDuration(10_000)),
            Err(BrokerError::Core(CoreError::Capacity))
        ));
        let mut local = ctx.ip_get(b"LoCaLhOsT", Family::Any, QueryDuration(0))?;
        let original = local.token();
        assert_eq!(
            next(&mut driver, &mut local).await?,
            Value::Address("::1".parse()?)
        );
        ctx.request_cancel(&original)?;
        assert!(local.next().await?.is_none());
        assert_eq!(ctx.pending_requests()?, 0);
        let (ctx, _driver) = setup::<8, 128>(LiveConfiguration::new(Configuration::default()))?;
        assert!(matches!(
            ctx.ip_get(b"arbitrary.invalid", Family::Any, QueryDuration(10_000)),
            Err(BrokerError::Core(CoreError::Unavailable))
        ));
        assert!(matches!(
            ctx.hostname_get(Ipv4Addr::LOCALHOST.into(), false, QueryDuration(0)),
            Err(BrokerError::Core(CoreError::Unavailable))
        ));
        Ok(())
    })
}
#[test]
fn unix_fifo_sent_cancel_drains_without_an_extra_cancel_frame() -> Result {
    runtime()?.block_on(async {
        let dir = Dir::new()?;
        let listener = LocalListener::bind(dir.0.join("r")).await?;
        let peer = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await?;
            let a = frame(&mut s).await?;
            let a = Request::decode(Frame::decode(&a)?, profile()?)?;
            s.write_all(&response(a.id(), WireReply::Address("127.0.0.1".parse()?))?)
                .await?;
            sleep(Duration::from_millis(15)).await;
            s.write_all(
                &[
                    response(a.id(), WireReply::Address("127.0.0.2".parse()?))?,
                    response(a.id(), WireReply::End)?,
                ]
                .concat(),
            )
            .await?;
            let b = frame(&mut s).await?;
            let b = Request::decode(Frame::decode(&b)?, profile()?)?;
            assert!(matches!(
                b.query(),
                gnunet_client::resolver::Query::Forward {
                    hostname: b"second",
                    ..
                }
            ));
            s.write_all(
                &[
                    response(b.id(), WireReply::Address("127.0.0.3".parse()?))?,
                    response(b.id(), WireReply::End)?,
                ]
                .concat(),
            )
            .await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
        let (ctx, mut driver) = setup::<8, 128>(LiveConfiguration::new(cfg(&dir.0.join("r"))?))?;
        let mut a = ctx.ip_get(b"first", Family::Any, QueryDuration(1_000_000))?;
        let mut b = ctx.ip_get(b"second", Family::Any, QueryDuration(1_000_000))?;
        assert_eq!(
            next(&mut driver, &mut a).await?,
            Value::Address("127.0.0.1".parse()?)
        );
        a.cancel()?;
        assert!(a.next().await?.is_none());
        assert_eq!(
            next(&mut driver, &mut b).await?,
            Value::Address("127.0.0.3".parse()?)
        );
        assert_eq!(
            next(&mut driver, &mut b).await?,
            Value::Complete(Completion::End)
        );
        peer.await??;
        Ok(())
    })
}
#[test]
fn dropping_pending_drive_preserves_partial_response_header_and_body() -> Result {
    runtime()?.block_on(async {
        let dir = Dir::new()?;
        let listener = LocalListener::bind(dir.0.join("r")).await?;
        let peer = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await?;
            let q = frame(&mut s).await?;
            let q = Request::decode(Frame::decode(&q)?, profile()?)?;
            let data = response(q.id(), WireReply::Address(Ipv4Addr::LOCALHOST.into()))?;
            s.write_all(&data[..1]).await?;
            sleep(Duration::from_millis(40)).await;
            s.write_all(&data[1..6]).await?;
            sleep(Duration::from_millis(20)).await;
            s.write_all(&data[6..]).await?;
            s.write_all(&response(q.id(), WireReply::End)?).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
        let (ctx, mut driver) = setup::<8, 128>(LiveConfiguration::new(cfg(&dir.0.join("r"))?))?;
        let mut query = ctx.ip_get(b"fixture.invalid", Family::Any, QueryDuration(1_000_000))?;
        assert!(
            timeout(Duration::from_millis(15), async {
                for _ in 0..20_000 {
                    driver.drive_waiting(None, |_| {}).await?;
                }
                Ok::<(), BrokerError>(())
            })
            .await
            .is_err()
        );
        assert!(
            timeout(Duration::from_millis(1), query.next())
                .await
                .is_err()
        );
        assert_eq!(
            next(&mut driver, &mut query).await?,
            Value::Address(Ipv4Addr::LOCALHOST.into())
        );
        assert_eq!(
            next(&mut driver, &mut query).await?,
            Value::Complete(Completion::End)
        );
        peer.await??;
        Ok(())
    })
}
#[test]
fn dropping_drive_after_real_short_writes_preserves_immutable_tx_cursor() -> Result {
    runtime()?.block_on(async {
        let dir = Dir::new()?;
        let listener = LocalListener::bind(dir.0.join("r")).await?;
        let name = vec![b'x'; 1024];
        let expected = name.clone();
        let peer = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await?;
            let q = frame(&mut s).await?;
            assert_eq!(&q[16..q.len() - 1], expected);
            assert_eq!(q.last(), Some(&0));
            let q = Request::decode(Frame::decode(&q)?, profile()?)?;
            s.write_all(
                &[
                    response(q.id(), WireReply::Address(Ipv4Addr::LOCALHOST.into()))?,
                    response(q.id(), WireReply::End)?,
                ]
                .concat(),
            )
            .await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
        let (ctx, mut driver) = broker::<2, 1024>(
            LiveConfiguration::new(cfg(&dir.0.join("r"))?),
            Limits {
                max_frame_bytes: 2048,
                io_chunk_bytes: 1,
                ..Default::default()
            },
            profile()?,
            Arc::new(SystemClock),
        )?;
        let mut query = ctx.ip_get(&name, Family::Any, QueryDuration(1_000_000))?;
        drive_until_event(&mut driver, |event| {
            matches!(event, DriverEvent::Connected(_)).then_some(())
        })
        .await?;
        for _ in 0..3 {
            let mut step = Box::pin(driver.drive(None, |_| {}));
            poll_fn(|cx| {
                assert!(step.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            drop(step);
        }
        assert_eq!(
            next(&mut driver, &mut query).await?,
            Value::Address(Ipv4Addr::LOCALHOST.into())
        );
        assert_eq!(
            next(&mut driver, &mut query).await?,
            Value::Complete(Completion::End)
        );
        peer.await??;
        Ok(())
    })
}
#[test]
fn configured_mq_failure_times_out_without_blocking_local_fast_requests() -> Result {
    runtime()?.block_on(async {
        let mut cfg = Configuration::default();
        cfg.set_value(b"resolver", b"HOSTNAME", Some(b"127.0.0.1"))?;
        assert!(gnunet_resolver_broker::check_config(&cfg));
        let clock = Arc::new(Adjustable::frozen(CLOCK_START, 4)?);
        let (ctx, mut driver) = broker::<8, 128>(
            LiveConfiguration::new(cfg),
            Limits::default(),
            profile()?,
            clock.clone(),
        )?;
        let mut remote = ctx.ip_get(b"missing", Family::Any, QUERY_TIMEOUT)?;
        // Make MQ creation due while the original request deadline is still in the future.
        clock.set(CLOCK_START + QUERY_TIMEOUT.0 / 2)?;
        drive_until_event(&mut driver, |event| {
            matches!(event, DriverEvent::Unavailable).then_some(())
        })
        .await?;
        assert!(matches!(
            driver.take_connect_error(),
            Some(BrokerError::Ipc(ConnectError::Configuration(
                gnunet_config::Error::InvalidValue
            )))
        ));
        let mut local = ctx.ip_get(b"localhost", Family::Any, QueryDuration(0))?;
        assert_eq!(
            next(&mut driver, &mut local).await?,
            Value::Address("::1".parse()?)
        );
        assert_eq!(
            next(&mut driver, &mut local).await?,
            Value::Address(Ipv4Addr::LOCALHOST.into())
        );
        assert_eq!(
            next(&mut driver, &mut local).await?,
            Value::Complete(Completion::End)
        );
        assert_eq!(ctx.pending_requests()?, 1);
        clock.set(CLOCK_START + QUERY_TIMEOUT.0)?;
        assert_eq!(
            next(&mut driver, &mut remote).await?,
            Value::Complete(Completion::Timeout)
        );
        Ok(())
    })
}
#[test]
fn tcp_reverse_uses_raw_ip_and_name_callback_cancel_suppresses_end() -> Result {
    runtime()?.block_on(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let mut cfg = Configuration::default();
        cfg.set_value(b"resolver", b"HOSTNAME", Some(b"127.0.0.1"))?;
        cfg.set_value(
            b"resolver",
            b"PORT",
            Some(listener.local_addr()?.port().to_string().as_bytes()),
        )?;
        let peer = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await?;
            let bytes = frame(&mut s).await?;
            assert_eq!(&bytes[4..12], &[0, 0, 0, 1, 0, 0, 0, 2]);
            assert_eq!(&bytes[16..], &[127, 0, 0, 1]);
            let q = Request::decode(Frame::decode(&bytes)?, profile()?)?;
            s.write_all(
                &[
                    response(q.id(), WireReply::Hostname(b"fixture.local"))?,
                    response(q.id(), WireReply::End)?,
                ]
                .concat(),
            )
            .await?;
            match timeout(Duration::from_secs(1), s.read(&mut [0])).await? {
                Ok(0) => {}
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
                result => return Err(format!("canceled socket stayed open: {result:?}").into()),
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
        let (ctx, mut driver) = setup::<8, 128>(LiveConfiguration::new(cfg))?;
        let mut query =
            ctx.hostname_get(Ipv4Addr::LOCALHOST.into(), true, QueryDuration(u64::MAX))?;
        assert_eq!(
            next(&mut driver, &mut query).await?,
            Value::Name(b"fixture.local".to_vec())
        );
        query.cancel()?;
        assert!(query.next().await?.is_none());
        let until = Instant::now() + Duration::from_secs(1);
        while driver.drive(Some(until), |_| {}).await? != Progress::Idle {}
        peer.await??;
        Ok(())
    })
}
#[test]
fn initial_socket_retries_keep_original_virtual_epoch_and_request() -> Result {
    runtime()?.block_on(async {
        let dir = Dir::new()?;
        let path = dir.0.join("r");
        let (ctx, mut driver) = setup::<8, 128>(LiveConfiguration::new(cfg(&path)?))?;
        let mut q = ctx.ip_get(b"fixture.invalid", Family::Any, QueryDuration(u64::MAX))?;
        let failed_epoch = drive_until_event(&mut driver, |event| match event {
            DriverEvent::SocketRetry { epoch, .. } => Some(epoch),
            _ => None,
        })
        .await?;
        let listener = LocalListener::bind(&path).await?;
        let peer = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await?;
            let bytes = frame(&mut s).await?;
            assert_eq!(&bytes[12..16], &1u32.to_ne_bytes());
            let q = Request::decode(Frame::decode(&bytes)?, profile()?)?;
            s.write_all(&response(q.id(), WireReply::End)?).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
        let connected_epoch = drive_until_event(&mut driver, |event| match event {
            DriverEvent::SocketRetry { epoch, .. } => {
                assert_eq!(epoch, failed_epoch);
                None
            }
            DriverEvent::Connected(epoch) => Some(epoch),
            _ => None,
        })
        .await?;
        assert_eq!(connected_epoch, failed_epoch);
        assert_eq!(
            next(&mut driver, &mut q).await?,
            Value::Complete(Completion::End)
        );
        peer.await??;
        Ok(())
    })
}
#[test]
fn late_timed_out_id_reconnects_next_query_with_its_original_id() -> Result {
    runtime()?.block_on(async {
        let dir = Dir::new()?;
        let listener = LocalListener::bind(dir.0.join("r")).await?;
        let clock = Arc::new(Adjustable::frozen(CLOCK_START, 4)?);
        let peer_clock = clock.clone();
        let peer = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await?;
            let a = frame(&mut s).await?;
            peer_clock.set(CLOCK_START + QUERY_TIMEOUT.0)?;
            let b = frame(&mut s).await?;
            assert_ne!(&a[12..16], &b[12..16]);
            s.write_all(
                &[0, 12, 0, 5]
                    .into_iter()
                    .chain(a[12..16].iter().copied())
                    .chain([127, 0, 0, 1])
                    .collect::<Vec<_>>(),
            )
            .await?;
            let (mut reconnected, _) = listener.accept().await?;
            assert_eq!(frame(&mut reconnected).await?, b);
            let q = Request::decode(Frame::decode(&b)?, profile()?)?;
            reconnected
                .write_all(&response(q.id(), WireReply::End)?)
                .await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
        let (ctx, mut driver) = broker::<8, 128>(
            LiveConfiguration::new(cfg(&dir.0.join("r"))?),
            Limits::default(),
            profile()?,
            clock.clone(),
        )?;
        let mut a = ctx.ip_get(b"a.invalid", Family::Any, QUERY_TIMEOUT)?;
        clock.set(CLOCK_START + QUERY_TIMEOUT.0 / 2)?;
        assert_eq!(
            next(&mut driver, &mut a).await?,
            Value::Complete(Completion::Timeout)
        );
        let mut b = ctx.ip_get(b"b.invalid", Family::Any, QueryDuration(u64::MAX))?;
        let cause = drive_until_event(&mut driver, |event| match event {
            DriverEvent::Lost { cause, .. } => Some(cause),
            _ => None,
        })
        .await?;
        assert_eq!(cause, CoreError::Malformed);
        clock.set(CLOCK_START + 2 * QUERY_TIMEOUT.0)?;
        assert_eq!(
            next(&mut driver, &mut b).await?,
            Value::Complete(Completion::End)
        );
        peer.await??;
        Ok(())
    })
}
#[test]
fn oversized_response_is_explicit_capacity_loss_and_never_successful_empty_result() -> Result {
    runtime()?.block_on(async {
        let dir = Dir::new()?;
        let listener = LocalListener::bind(dir.0.join("r")).await?;
        let peer = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await?;
            frame(&mut s).await?;
            s.write_all(&[0, 64, 0, 5]).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
        let clock = Arc::new(Adjustable::frozen(CLOCK_START, 4)?);
        let (ctx, mut driver) = broker::<8, 128>(
            LiveConfiguration::new(cfg(&dir.0.join("r"))?),
            Limits {
                max_frame_bytes: 32,
                io_chunk_bytes: 32,
                ..Default::default()
            },
            profile()?,
            clock.clone(),
        )?;
        let mut q = ctx.ip_get(b"fixture", Family::Any, QUERY_TIMEOUT)?;
        clock.set(CLOCK_START + QUERY_TIMEOUT.0 / 2)?;
        let cause = drive_until_event(&mut driver, |event| match event {
            DriverEvent::Lost { cause, .. } => Some(cause),
            _ => None,
        })
        .await?;
        assert_eq!(cause, CoreError::Capacity);
        clock.set(CLOCK_START + QUERY_TIMEOUT.0)?;
        assert_eq!(
            next(&mut driver, &mut q).await?,
            Value::Complete(Completion::Timeout)
        );
        peer.await??;
        Ok(())
    })
}
#[test]
fn dropping_owner_closes_its_socket_and_does_not_dispatch_a_completion() -> Result {
    runtime()?.block_on(async {
        let dir = Dir::new()?;
        let listener = LocalListener::bind(dir.0.join("r")).await?;
        let peer = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await?;
            frame(&mut s).await?;
            assert_eq!(timeout(Duration::from_secs(1), s.read(&mut [0])).await??, 0);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
        let (ctx, mut driver) = setup::<8, 128>(LiveConfiguration::new(cfg(&dir.0.join("r"))?))?;
        let mut q = ctx.ip_get(b"fixture", Family::Any, QueryDuration(u64::MAX))?;
        let until = Instant::now() + Duration::from_millis(15);
        while driver.drive(Some(until), |_| {}).await? != Progress::WaitDeadline {}
        drop(driver);
        assert!(matches!(q.next().await, Err(BrokerError::OwnerLost)));
        peer.await??;
        Ok(())
    })
}
#[test]
fn callback_reconfiguration_preserves_old_mq_then_uses_new_endpoint_after_idle_close() -> Result {
    runtime()?.block_on(async{let dir=Dir::new()?;let old=LocalListener::bind(dir.0.join("old")).await?;let new=LocalListener::bind(dir.0.join("new")).await?;let first_peer=tokio::spawn(async move{let(mut s,_)=old.accept().await?;for name in [b"first".as_slice(),b"queued"]{let bytes=frame(&mut s).await?;let q=Request::decode(Frame::decode(&bytes)?,profile()?)?;assert!(matches!(q.query(),gnunet_client::resolver::Query::Forward{hostname,..}if hostname==name));s.write_all(&[response(q.id(),WireReply::Address("127.0.0.11".parse()?))?,response(q.id(),WireReply::End)?].concat()).await?;}assert_eq!(s.read(&mut[0]).await?,0);Ok::<_,Box<dyn std::error::Error+Send+Sync>>(())});let next_peer=tokio::spawn(async move{let(mut s,_)=new.accept().await?;let bytes=frame(&mut s).await?;let q=Request::decode(Frame::decode(&bytes)?,profile()?)?;assert!(matches!(q.query(),gnunet_client::resolver::Query::Forward{hostname:b"after",..}));s.write_all(&response(q.id(),WireReply::End)?).await?;Ok::<_,Box<dyn std::error::Error+Send+Sync>>(())});let(ctx,mut driver)=setup::<8,128>(LiveConfiguration::new(cfg(&dir.0.join("old"))?))?;let mut first=ctx.ip_get(b"first",Family::Any,QueryDuration(1_000_000))?;assert_eq!(next(&mut driver,&mut first).await?,Value::Address("127.0.0.11".parse()?));ctx.connect(cfg(&dir.0.join("new"))?)?;let mut queued=ctx.ip_get(b"queued",Family::Any,QueryDuration(1_000_000))?;assert_eq!(next(&mut driver,&mut first).await?,Value::Complete(Completion::End));assert_eq!(next(&mut driver,&mut queued).await?,Value::Address("127.0.0.11".parse()?));assert_eq!(next(&mut driver,&mut queued).await?,Value::Complete(Completion::End));let until=Instant::now()+Duration::from_secs(1);while driver.drive(Some(until), |_|{}).await?!=Progress::Idle{}first_peer.await??;let mut after=ctx.ip_get(b"after",Family::Any,QueryDuration(1_000_000))?;assert_eq!(next(&mut driver,&mut after).await?,Value::Complete(Completion::End));next_peer.await??;Ok(())})
}
#[test]
fn invalid_to_valid_connect_restores_future_admission_without_losing_local_task() -> Result {
    runtime()?.block_on(async {
        let dir = Dir::new()?;
        let listener = LocalListener::bind(dir.0.join("r")).await?;
        let peer = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await?;
            let bytes = frame(&mut s).await?;
            let q = Request::decode(Frame::decode(&bytes)?, profile()?)?;
            s.write_all(&response(q.id(), WireReply::End)?).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
        let (ctx, mut driver) = setup::<8, 128>(LiveConfiguration::new(Configuration::default()))?;
        assert!(
            ctx.ip_get(b"before", Family::Any, QueryDuration(1_000_000))
                .is_err()
        );
        let mut local = ctx.ip_get(b"ip6-localnet", Family::Any, QueryDuration(0))?;
        ctx.connect(cfg(&dir.0.join("r"))?)?;
        let mut remote = ctx.ip_get(b"after", Family::Any, QueryDuration(1_000_000))?;
        assert_eq!(
            next(&mut driver, &mut local).await?,
            Value::Address("::1".parse()?)
        );
        assert_eq!(
            next(&mut driver, &mut local).await?,
            Value::Address(Ipv4Addr::LOCALHOST.into())
        );
        assert_eq!(
            next(&mut driver, &mut local).await?,
            Value::Complete(Completion::End)
        );
        assert_eq!(
            next(&mut driver, &mut remote).await?,
            Value::Complete(Completion::End)
        );
        peer.await??;
        Ok(())
    })
}
