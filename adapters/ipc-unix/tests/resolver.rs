//! Preserved stream/authority assertions ported to the shared Query/Driver API.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Actual owned stream and original request assertions"
)]
#[path = "../../resolver-broker-std/tests/support/assertions.rs"]
mod support;
use gnunet_client::resolver::{Reply as WireReply, Request};
use gnunet_config::Configuration;
use gnunet_resolver_broker::{
    BrokerError, Completion, DriverEvent, Family, Limits, LiveConfiguration, Progress, SystemClock,
    broker,
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
use support::{Dir, Result, Value, cfg, frame, next, profile, response, runtime, setup};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UnixListener},
    time::{Instant, sleep, timeout},
};

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
        let listener = UnixListener::bind(dir.socket("r"))?;
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
        let (ctx, mut driver) = setup::<8, 128>(LiveConfiguration::new(cfg(&dir.socket("r"))?))?;
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
        let listener = UnixListener::bind(dir.socket("r"))?;
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
        let (ctx, mut driver) = setup::<8, 128>(LiveConfiguration::new(cfg(&dir.socket("r"))?))?;
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
        let listener = UnixListener::bind(dir.socket("r"))?;
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
            LiveConfiguration::new(cfg(&dir.socket("r"))?),
            Limits {
                max_frame_bytes: 2048,
                io_chunk_bytes: 1,
                ..Default::default()
            },
            profile()?,
            Arc::new(SystemClock),
        )?;
        let mut query = ctx.ip_get(&name, Family::Any, QueryDuration(1_000_000))?;
        let mut connected = false;
        while !connected {
            driver
                .drive(Some(Instant::now() + Duration::from_secs(1)), |event| {
                    if matches!(event, DriverEvent::Connected(_)) {
                        connected = true;
                    }
                })
                .await?;
        }
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
fn configured_mq_failure_times_out_without_blocking_numeric_fast_requests() -> Result {
    runtime()?.block_on(async {
        let mut cfg = Configuration::default();
        cfg.set_value(b"resolver", b"HOSTNAME", Some(b"127.0.0.1"))?;
        assert!(gnunet_resolver_broker::check_config(&cfg));
        let (ctx, mut driver) = setup::<8, 128>(LiveConfiguration::new(cfg))?;
        let mut remote = ctx.ip_get(b"missing", Family::Any, QueryDuration(15_000))?;
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
        assert_eq!(
            next(&mut driver, &mut remote).await?,
            Value::Complete(Completion::Timeout)
        );
        assert!(driver.take_connect_error().is_some());
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
        let path = dir.socket("r");
        let peer = tokio::spawn(async move {
            sleep(Duration::from_millis(25)).await;
            let listener = UnixListener::bind(path)?;
            let (mut s, _) = listener.accept().await?;
            let bytes = frame(&mut s).await?;
            assert_eq!(&bytes[12..16], &1u32.to_ne_bytes());
            let q = Request::decode(Frame::decode(&bytes)?, profile()?)?;
            s.write_all(&response(q.id(), WireReply::End)?).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
        let (ctx, mut driver) = setup::<8, 128>(LiveConfiguration::new(cfg(&dir.socket("r"))?))?;
        let mut q = ctx.ip_get(b"fixture.invalid", Family::Any, QueryDuration(1_000_000))?;
        let mut epochs: Vec<(gnunet_client::resolver_handle::ConnectionEpoch, bool)> = Vec::new();
        let until = Instant::now() + Duration::from_secs(1);
        while epochs.iter().all(|(_, connected)| !*connected) {
            driver
                .drive(Some(until), |event| match event {
                    DriverEvent::SocketRetry { epoch, .. } => epochs.push((epoch, false)),
                    DriverEvent::Connected(epoch) => epochs.push((epoch, true)),
                    _ => {}
                })
                .await?;
        }
        assert!(epochs.len() > 1);
        assert!(epochs.iter().all(|(epoch, _)| *epoch == epochs[0].0));
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
        let listener = UnixListener::bind(dir.socket("r"))?;
        let peer = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await?;
            let a = frame(&mut s).await?;
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
            drop(s);
            let (mut s, _) = listener.accept().await?;
            assert_eq!(frame(&mut s).await?, b);
            let q = Request::decode(Frame::decode(&b)?, profile()?)?;
            s.write_all(&response(q.id(), WireReply::End)?).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
        let (ctx, mut driver) = setup::<8, 128>(LiveConfiguration::new(cfg(&dir.socket("r"))?))?;
        let mut a = ctx.ip_get(b"a.invalid", Family::Any, QueryDuration(15_000))?;
        assert_eq!(
            next(&mut driver, &mut a).await?,
            Value::Complete(Completion::Timeout)
        );
        let mut b = ctx.ip_get(b"b.invalid", Family::Any, QueryDuration(u64::MAX))?;
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
        let listener = UnixListener::bind(dir.socket("r"))?;
        let peer = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await?;
            frame(&mut s).await?;
            s.write_all(&[0, 64, 0, 5]).await?;
            sleep(Duration::from_millis(50)).await;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
        let (ctx, mut driver) = broker::<8, 128>(
            LiveConfiguration::new(cfg(&dir.socket("r"))?),
            Limits {
                max_frame_bytes: 32,
                io_chunk_bytes: 32,
                ..Default::default()
            },
            profile()?,
            Arc::new(SystemClock),
        )?;
        let mut q = ctx.ip_get(b"fixture", Family::Any, QueryDuration(20_000))?;
        let until = Instant::now() + Duration::from_secs(1);
        let mut cap = 0;
        while cap == 0 {
            driver
                .drive(Some(until), |e| {
                    if matches!(
                        e,
                        DriverEvent::Lost {
                            cause: CoreError::Capacity,
                            ..
                        }
                    ) {
                        cap += 1;
                    }
                })
                .await?;
        }
        assert_eq!(
            next(&mut driver, &mut q).await?,
            Value::Complete(Completion::Timeout)
        );
        assert_eq!(cap, 1);
        peer.await??;
        Ok(())
    })
}
#[test]
fn dropping_owner_closes_its_socket_and_does_not_dispatch_a_completion() -> Result {
    runtime()?.block_on(async {
        let dir = Dir::new()?;
        let listener = UnixListener::bind(dir.socket("r"))?;
        let peer = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await?;
            frame(&mut s).await?;
            assert_eq!(timeout(Duration::from_secs(1), s.read(&mut [0])).await??, 0);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
        let (ctx, mut driver) = setup::<8, 128>(LiveConfiguration::new(cfg(&dir.socket("r"))?))?;
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
    runtime()?.block_on(async{let dir=Dir::new()?;let old=UnixListener::bind(dir.socket("old"))?;let new=UnixListener::bind(dir.socket("new"))?;let first_peer=tokio::spawn(async move{let(mut s,_)=old.accept().await?;for name in [b"first".as_slice(),b"queued"]{let bytes=frame(&mut s).await?;let q=Request::decode(Frame::decode(&bytes)?,profile()?)?;assert!(matches!(q.query(),gnunet_client::resolver::Query::Forward{hostname,..}if hostname==name));s.write_all(&[response(q.id(),WireReply::Address("127.0.0.11".parse()?))?,response(q.id(),WireReply::End)?].concat()).await?;}assert_eq!(s.read(&mut[0]).await?,0);Ok::<_,Box<dyn std::error::Error+Send+Sync>>(())});let next_peer=tokio::spawn(async move{let(mut s,_)=new.accept().await?;let bytes=frame(&mut s).await?;let q=Request::decode(Frame::decode(&bytes)?,profile()?)?;assert!(matches!(q.query(),gnunet_client::resolver::Query::Forward{hostname:b"after",..}));s.write_all(&response(q.id(),WireReply::End)?).await?;Ok::<_,Box<dyn std::error::Error+Send+Sync>>(())});let(ctx,mut driver)=setup::<8,128>(LiveConfiguration::new(cfg(&dir.socket("old"))?))?;let mut first=ctx.ip_get(b"first",Family::Any,QueryDuration(1_000_000))?;assert_eq!(next(&mut driver,&mut first).await?,Value::Address("127.0.0.11".parse()?));ctx.connect(cfg(&dir.socket("new"))?)?;let mut queued=ctx.ip_get(b"queued",Family::Any,QueryDuration(1_000_000))?;assert_eq!(next(&mut driver,&mut first).await?,Value::Complete(Completion::End));assert_eq!(next(&mut driver,&mut queued).await?,Value::Address("127.0.0.11".parse()?));assert_eq!(next(&mut driver,&mut queued).await?,Value::Complete(Completion::End));let until=Instant::now()+Duration::from_secs(1);while driver.drive(Some(until), |_|{}).await?!=Progress::Idle{}first_peer.await??;let mut after=ctx.ip_get(b"after",Family::Any,QueryDuration(1_000_000))?;assert_eq!(next(&mut driver,&mut after).await?,Value::Complete(Completion::End));next_peer.await??;Ok(())})
}
#[test]
fn invalid_to_valid_connect_restores_future_admission_without_losing_local_task() -> Result {
    runtime()?.block_on(async {
        let dir = Dir::new()?;
        let listener = UnixListener::bind(dir.socket("r"))?;
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
        ctx.connect(cfg(&dir.socket("r"))?)?;
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
