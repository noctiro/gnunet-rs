//! Real owned Unix peers for the one shared Resolver MQ and callback authority.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible OS tests assert real original-connection and callback invariants"
)]
use gnunet_client::resolver::{FamilyProfile, Reply as WireReply, Request, encode_response};
use gnunet_config::Configuration;
use gnunet_resolver_broker::{
    Completion, Context, Driver, Family, Hostname, Limits, LiveConfiguration, Progress, Query,
    Reply, SystemClock, broker,
};
use gnunet_types::Duration as CoreDuration;
use gnunet_wire::official::Frame;
use std::{
    error::Error,
    future::{Future, poll_fn},
    io,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::Poll,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::{Instant, timeout},
};
type Result<T = ()> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Dir(PathBuf);
impl Dir {
    fn new() -> io::Result<Self> {
        let p = std::env::temp_dir().join(format!(
            "rb-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&p)?;
        Ok(Self(p))
    }
    fn socket(&self, n: &str) -> PathBuf {
        self.0.join(n)
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.0));
    }
}
fn runtime() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}
fn profile() -> Result<FamilyProfile> {
    let profile = gnunet_resolver_broker::native_profile()?;
    Ok(FamilyProfile::new(
        profile.encode(gnunet_resolver_broker::Family::V4),
        profile.encode(gnunet_resolver_broker::Family::V6),
    )?)
}
fn cfg(path: &Path) -> Result<Configuration> {
    let mut c = Configuration::default();
    c.set_value(
        b"resolver",
        b"UNIXPATH",
        Some(path.as_os_str().as_encoded_bytes()),
    )?;
    Ok(c)
}
fn setup<const R: usize, const N: usize>(
    store: LiveConfiguration,
) -> Result<(Context<R, N>, Driver<R, N>)> {
    Ok(broker(
        store,
        Limits {
            io_chunk_bytes: 1,
            ..Default::default()
        },
        profile()?,
        Arc::new(SystemClock),
    )?)
}
async fn frame(s: &mut UnixStream) -> Result<Vec<u8>> {
    let mut h = [0; 4];
    s.read_exact(&mut h).await?;
    let n = usize::from(u16::from_be_bytes([h[0], h[1]]));
    if !(4..=65535).contains(&n) {
        return Err("bad frame".into());
    }
    let mut data = vec![0; n];
    data[..4].copy_from_slice(&h);
    s.read_exact(&mut data[4..]).await?;
    Ok(data)
}
fn response(id: gnunet_client::resolver::WireId, value: WireReply<'_>) -> Result<Vec<u8>> {
    let mut bytes = vec![0; 65535];
    let len = encode_response(id, value, &mut bytes)?;
    bytes.truncate(len);
    Ok(bytes)
}
#[derive(Debug, PartialEq)]
enum Value {
    Address(std::net::IpAddr),
    Name(Vec<u8>),
    Numeric(std::net::IpAddr),
    Complete(Completion),
    Closed,
}
async fn next<const R: usize, const N: usize>(
    driver: &mut Driver<R, N>,
    query: &mut Query<R, N>,
) -> Result<Value> {
    let until = Instant::now() + Duration::from_secs(3);
    loop {
        let mut wait = Box::pin(query.next());
        let mut drive = Box::pin(driver.drive(Some(until), |_| {}));
        let result = poll_fn(|cx| {
            if let Poll::Ready(result) = wait.as_mut().poll(cx) {
                return Poll::Ready(result.map(|lease| {
                    Some(lease.map(|lease| {
                        let result = lease.reply().map(|reply| match reply {
                            Reply::Address(a) => Value::Address(a),
                            Reply::Hostname(Hostname::Resolved(n)) => Value::Name(n.to_vec()),
                            Reply::Hostname(Hostname::Numeric(a)) => Value::Numeric(a),
                            Reply::Complete(reason) => Value::Complete(reason),
                        });
                        drop(lease);
                        result
                    }))
                }));
            }
            match drive.as_mut().poll(cx) {
                Poll::Ready(Ok(Progress::WaitDeadline)) => Poll::Ready(Err(
                    gnunet_resolver_broker::BrokerError::Io(io::Error::other("test wait deadline")),
                )),
                Poll::Ready(Ok(_)) => Poll::Ready(Ok(None)),
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await?;
        if let Some(value) = result {
            return match value {
                Some(value) => Ok(value?),
                None => Ok(Value::Closed),
            };
        }
    }
}
#[test]
fn cloned_contexts_share_one_fifo_mq_and_end_advances_original_tail() -> Result {
    runtime()?.block_on(async {
        let dir = Dir::new()?;
        let listener = UnixListener::bind(dir.socket("a"))?;
        let peer = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await?;
            let a = frame(&mut s).await?;
            let a = Request::decode(Frame::decode(&a)?, profile()?)?;
            assert!(matches!(
                a.query(),
                gnunet_client::resolver::Query::Forward {
                    hostname: b"first",
                    ..
                }
            ));
            assert!(
                timeout(Duration::from_millis(15), frame(&mut s))
                    .await
                    .is_err()
            );
            let payload = [
                response(a.id(), WireReply::Address("192.0.2.1".parse()?))?,
                response(a.id(), WireReply::End)?,
            ]
            .concat();
            s.write_all(&payload).await?;
            let b = frame(&mut s).await?;
            let b = Request::decode(Frame::decode(&b)?, profile()?)?;
            assert!(matches!(
                b.query(),
                gnunet_client::resolver::Query::Forward {
                    hostname: b"second",
                    ..
                }
            ));
            s.write_all(&response(b.id(), WireReply::End)?).await?;
            assert_eq!(timeout(Duration::from_secs(2), s.read(&mut [0])).await??, 0);
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });
        let (ctx, mut driver) = setup::<4, 64>(LiveConfiguration::new(cfg(&dir.socket("a"))?))?;
        let cloned = ctx.clone();
        let mut first = ctx.ip_get(b"first", Family::Any, CoreDuration(1_000_000))?;
        let mut second = cloned.ip_get(b"second", Family::Any, CoreDuration(1_000_000))?;
        assert_eq!(
            next(&mut driver, &mut first).await?,
            Value::Address("192.0.2.1".parse()?)
        );
        assert_eq!(
            next(&mut driver, &mut first).await?,
            Value::Complete(Completion::End)
        );
        assert_eq!(
            next(&mut driver, &mut second).await?,
            Value::Complete(Completion::End)
        );
        assert_eq!(ctx.pending_requests()?, 0);
        let until = Instant::now() + Duration::from_secs(2);
        while driver.drive(Some(until), |_| {}).await? != Progress::Idle {}
        peer.await?.map_err(|e| e.to_string())?;
        Ok(())
    })
}
#[test]
fn transmitted_cancel_drains_original_end_without_private_connection_or_callback() -> Result {
    runtime()?.block_on(async {
        let dir = Dir::new()?;
        let listener = UnixListener::bind(dir.socket("a"))?;
        let peer = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await?;
            let a = frame(&mut s).await?;
            let a = Request::decode(Frame::decode(&a)?, profile()?)?;
            s.write_all(&response(a.id(), WireReply::Address("192.0.2.2".parse()?))?)
                .await?;
            tokio::time::sleep(Duration::from_millis(15)).await;
            s.write_all(
                &[
                    response(a.id(), WireReply::Address("192.0.2.3".parse()?))?,
                    response(a.id(), WireReply::End)?,
                ]
                .concat(),
            )
            .await?;
            let b = frame(&mut s).await?;
            let b = Request::decode(Frame::decode(&b)?, profile()?)?;
            s.write_all(&response(b.id(), WireReply::End)?).await?;
            assert_eq!(timeout(Duration::from_secs(2), s.read(&mut [0])).await??, 0);
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });
        let (ctx, mut driver) = setup::<4, 64>(LiveConfiguration::new(cfg(&dir.socket("a"))?))?;
        let mut first = ctx.ip_get(b"cancelled", Family::Any, CoreDuration(1_000_000))?;
        let mut second = ctx.ip_get(b"kept", Family::Any, CoreDuration(1_000_000))?;
        assert_eq!(
            next(&mut driver, &mut first).await?,
            Value::Address("192.0.2.2".parse()?)
        );
        first.cancel()?;
        assert!(first.next().await?.is_none());
        assert_eq!(
            next(&mut driver, &mut second).await?,
            Value::Complete(Completion::End)
        );
        let until = Instant::now() + Duration::from_secs(2);
        while driver.drive(Some(until), |_| {}).await? != Progress::Idle {}
        peer.await?.map_err(|e| e.to_string())?;
        Ok(())
    })
}

#[test]
fn callback_return_lease_blocks_next_effect_but_allows_cancellation_then_safe_pool_reuse() -> Result
{
    runtime()?.block_on(async {
        let dir = Dir::new()?;
        let listener = UnixListener::bind(dir.socket("a"))?;
        let peer = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await?;
            let a = frame(&mut s).await?;
            let a = Request::decode(Frame::decode(&a)?, profile()?)?;
            s.write_all(
                &[
                    response(a.id(), WireReply::Hostname(b"first-name"))?,
                    response(a.id(), WireReply::Hostname(b"second-name"))?,
                    response(a.id(), WireReply::End)?,
                ]
                .concat(),
            )
            .await?;
            assert_eq!(timeout(Duration::from_secs(2), s.read(&mut [0])).await??, 0);
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });
        let (ctx, mut driver) = setup::<2, 64>(LiveConfiguration::new(cfg(&dir.socket("a"))?))?;
        let mut query = ctx.hostname_get("192.0.2.9".parse()?, true, CoreDuration(1_000_000))?;
        let token = query.token();
        let mut pending = Box::pin(query.next());
        let until = Instant::now() + Duration::from_secs(2);
        let lease = loop {
            let mut drive = Box::pin(driver.drive(Some(until), |_| {}));
            let observed = poll_fn(|cx| {
                if let Poll::Ready(result) = pending.as_mut().poll(cx) {
                    return Poll::Ready(result.map(Some));
                }
                match drive.as_mut().poll(cx) {
                    Poll::Ready(Ok(Progress::WaitDeadline)) => Poll::Ready(Err(
                        gnunet_resolver_broker::BrokerError::Io(io::Error::other("lease deadline")),
                    )),
                    Poll::Ready(Ok(_)) => Poll::Ready(Ok(None)),
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Pending => Poll::Pending,
                }
            })
            .await?;
            if let Some(value) = observed {
                break value.ok_or("missing callback")?;
            }
        };
        drop(pending);
        assert!(matches!(
            lease.reply()?,
            Reply::Hostname(Hostname::Resolved(b"first-name"))
        ));
        assert_eq!(
            driver
                .drive(Some(Instant::now() + Duration::from_millis(15)), |_| {})
                .await?,
            Progress::WaitDeadline
        );
        ctx.request_cancel(&token)?;
        assert!(matches!(
            lease.reply()?,
            Reply::Hostname(Hostname::Resolved(b"first-name"))
        ));
        drop(lease);
        assert!(query.next().await?.is_none());
        let until = Instant::now() + Duration::from_secs(2);
        while driver.drive(Some(until), |_| {}).await? != Progress::Idle {}
        peer.await?.map_err(|e| e.to_string())?;
        Ok(())
    })
}

#[test]
fn local_fast_callbacks_are_deferred_shared_cancellable_and_reverse_requires_current_config()
-> Result {
    runtime()?.block_on(async {
        let (ctx, mut driver) = setup::<3, 64>(LiveConfiguration::new(Configuration::default()))?;
        assert!(
            ctx.hostname_get("127.0.0.1".parse()?, false, CoreDuration(0))
                .is_err()
        );
        let mut query = ctx.ip_get(b"localhost", Family::Any, CoreDuration(0))?;
        assert_eq!(ctx.pending_requests()?, 1);
        assert_eq!(
            next(&mut driver, &mut query).await?,
            Value::Address("::1".parse()?)
        );
        query.cancel()?;
        assert!(query.next().await?.is_none());
        assert_eq!(ctx.pending_requests()?, 0);
        let mut next_query = ctx.ip_get(b"127.0.0.1", Family::V4, CoreDuration(0))?;
        assert_eq!(
            next(&mut driver, &mut next_query).await?,
            Value::Address("127.0.0.1".parse()?)
        );
        assert_eq!(
            next(&mut driver, &mut next_query).await?,
            Value::Complete(Completion::End)
        );
        assert!(next_query.next().await?.is_none());
        Ok(())
    })
}

#[test]
fn driver_drop_reports_owner_loss_and_preserves_no_fake_dns_terminal() -> Result {
    runtime()?.block_on(async {
        let (ctx, driver) = setup::<2, 64>(LiveConfiguration::new(Configuration::default()))?;
        let mut query = ctx.ip_get(b"127.0.0.1", Family::Any, CoreDuration(1_000_000))?;
        drop(driver);
        assert!(matches!(
            query.next().await,
            Err(gnunet_resolver_broker::BrokerError::OwnerLost)
        ));
        assert!(matches!(
            ctx.ip_get(b"127.0.0.1", Family::Any, CoreDuration(1)),
            Err(gnunet_resolver_broker::BrokerError::OwnerLost)
        ));
        Ok(())
    })
}

#[test]
fn expired_then_canceled_unsent_envelopes_retain_exact_mq_ownership_with_bounded_credits() -> Result
{
    runtime()?.block_on(async {
        let dir = Dir::new()?;
        let path = dir.socket("late");
        let (ctx, mut driver) = broker::<4, 64>(
            LiveConfiguration::new(cfg(&path)?),
            Limits {
                io_chunk_bytes: 1,
                max_queued_frames: 4,
                ..Default::default()
            },
            profile()?,
            Arc::new(SystemClock),
        )?;
        let mut expired = ctx.ip_get(b"expired", Family::Any, CoreDuration(20_000))?;
        let mut canceled = ctx.ip_get(b"canceled", Family::Any, CoreDuration(1_000_000))?;
        assert_eq!(
            next(&mut driver, &mut expired).await?,
            Value::Complete(Completion::Timeout)
        );
        let until = Instant::now() + Duration::from_secs(2);
        while driver.queued_frames()? != 2 {
            assert_ne!(
                driver.drive(Some(until), |_| {}).await?,
                Progress::WaitDeadline
            );
        }
        let mut kept = ctx.ip_get(b"kept", Family::Any, CoreDuration(1_000_000))?;
        assert!(matches!(
            ctx.ip_get(b"no-credit", Family::Any, CoreDuration(1_000_000)),
            Err(gnunet_resolver_broker::BrokerError::Core(
                gnunet_types::Error::Capacity
            ))
        ));
        canceled.cancel()?;
        let listener = UnixListener::bind(&path)?;
        let peer = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await?;
            let first = frame(&mut s).await?;
            let first = Request::decode(Frame::decode(&first)?, profile()?)?;
            let second = frame(&mut s).await?;
            let second = Request::decode(Frame::decode(&second)?, profile()?)?;
            assert!(matches!(
                first.query(),
                gnunet_client::resolver::Query::Forward {
                    hostname: b"expired",
                    ..
                }
            ));
            assert_eq!(first.id().0, 1u32.to_ne_bytes());
            assert!(matches!(
                second.query(),
                gnunet_client::resolver::Query::Forward {
                    hostname: b"canceled",
                    ..
                }
            ));
            assert_eq!(second.id().0, 2u32.to_ne_bytes());
            s.write_all(&response(second.id(), WireReply::End)?).await?;
            let third = frame(&mut s).await?;
            let third = Request::decode(Frame::decode(&third)?, profile()?)?;
            assert!(matches!(
                third.query(),
                gnunet_client::resolver::Query::Forward {
                    hostname: b"kept",
                    ..
                }
            ));
            assert_eq!(third.id().0, 3u32.to_ne_bytes());
            s.write_all(&response(third.id(), WireReply::End)?).await?;
            assert_eq!(timeout(Duration::from_secs(2), s.read(&mut [0])).await??, 0);
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });
        assert_eq!(
            next(&mut driver, &mut kept).await?,
            Value::Complete(Completion::End)
        );
        assert!(canceled.next().await?.is_none());
        let until = Instant::now() + Duration::from_secs(2);
        while driver.drive(Some(until), |_| {}).await? != Progress::Idle {}
        assert_eq!(ctx.pending_requests()?, 0);
        peer.await?.map_err(|e| e.to_string())?;
        Ok(())
    })
}

#[test]
fn tcp_resolver_own_numeric_lookup_uses_shared_core_without_self_deadlock() -> Result {
    runtime()?.block_on(async{
  let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let port=listener.local_addr()?.port();let peer=tokio::spawn(async move{
   let (mut stream,_)=listener.accept().await?;
   for (id,name) in [(1u32,b"first".as_slice()),(3u32,b"second".as_slice())] {
    let mut header=[0;4];stream.read_exact(&mut header).await?;let len=usize::from(u16::from_be_bytes([header[0],header[1]]));let mut bytes=vec![0;len];bytes[..4].copy_from_slice(&header);stream.read_exact(&mut bytes[4..]).await?;let request=Request::decode(Frame::decode(&bytes)?,profile()?)?;assert_eq!(request.id().0,id.to_ne_bytes());assert!(matches!(request.query(),gnunet_client::resolver::Query::Forward{hostname,..}if hostname==name));stream.write_all(&response(request.id(),WireReply::End)?).await?;
   }
   assert_eq!(timeout(Duration::from_secs(2),stream.read(&mut[0])).await??,0);Ok::<_,Box<dyn Error+Send+Sync>>(())
  });
  let mut config=Configuration::default();config.set_value(b"resolver",b"HOSTNAME",Some(b"127.0.0.1"))?;config.set_value(b"resolver",b"PORT",Some(port.to_string().as_bytes()))?;let(ctx,mut driver)=setup::<3,64>(LiveConfiguration::new(config))?;
  let mut first=ctx.ip_get(b"first",Family::Any,CoreDuration(1_000_000))?;assert_eq!(next(&mut driver,&mut first).await?,Value::Complete(Completion::End));let mut second=ctx.ip_get(b"second",Family::Any,CoreDuration(1_000_000))?;assert_eq!(next(&mut driver,&mut second).await?,Value::Complete(Completion::End));let until=Instant::now()+Duration::from_secs(2);while driver.drive(Some(until), |_|{}).await?!=Progress::Idle{};peer.await?.map_err(|e|e.to_string())?;Ok(())
 })
}

#[test]
fn existing_mq_admission_owns_frame_before_immediate_cancel_or_another_drive() -> Result {
    runtime()?.block_on(async {
        let dir = Dir::new()?;
        let listener = UnixListener::bind(dir.socket("inline"))?;
        let peer = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await?;
            for expected in [b"warm".as_slice(), b"instant-cancel", b"kept"] {
                let bytes = frame(&mut s).await?;
                let request = Request::decode(Frame::decode(&bytes)?, profile()?)?;
                assert!(matches!(request.query(), gnunet_client::resolver::Query::Forward { hostname, .. } if hostname == expected));
                s.write_all(&response(request.id(), WireReply::End)?).await?;
            }
            assert_eq!(timeout(Duration::from_secs(2), s.read(&mut [0])).await??, 0);
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });
        let (ctx, mut driver) = setup::<4, 64>(LiveConfiguration::new(cfg(&dir.socket("inline"))?))?;
        let mut warm = ctx.ip_get(b"warm", Family::Any, CoreDuration(1_000_000))?;
        assert_eq!(next(&mut driver, &mut warm).await?, Value::Complete(Completion::End));
        assert_eq!(driver.queued_frames()?, 0);
        let mut cancelled = ctx.ip_get(b"instant-cancel", Family::Any, CoreDuration(1_000_000))?;
        // No drive/poll occurs between admission and cancellation.
        assert_eq!(driver.queued_frames()?, 1);
        cancelled.cancel()?;
        assert_eq!(driver.queued_frames()?, 1);
        let mut kept = ctx.ip_get(b"kept", Family::Any, CoreDuration(1_000_000))?;
        assert!(cancelled.next().await?.is_none());
        assert_eq!(next(&mut driver, &mut kept).await?, Value::Complete(Completion::End));
        let until = Instant::now() + Duration::from_secs(2);
        while driver.drive(Some(until), |_| {}).await? != Progress::Idle {}
        peer.await?.map_err(|e| e.to_string())?;
        Ok(())
    })
}

#[path = "../../ipc-unix/tests/support/clock_source.rs"]
pub mod clock_source;
use clock_source::Adjustable as SourceClock;
#[test]
fn callback_stack_survives_source_clock_backwards_before_other_due_timeout() -> Result {
    runtime()?.block_on(async {
        let dir = Dir::new()?;
        let clock = Arc::new(SourceClock::frozen(5_000_000, 8)?);
        let (ctx, mut driver) = broker::<4, 64>(
            LiveConfiguration::new(cfg(&dir.socket("never"))?),
            Limits::default(),
            profile()?,
            clock.clone(),
        )?;
        let mut local = ctx.ip_get(b"localhost", Family::Any, CoreDuration(0))?;
        assert_eq!(
            next(&mut driver, &mut local).await?,
            Value::Address("::1".parse()?)
        );
        let mut remote = ctx.ip_get(b"due", Family::Any, CoreDuration(0))?;
        clock.set(2_000_000)?;
        assert_eq!(
            next(&mut driver, &mut local).await?,
            Value::Address("127.0.0.1".parse()?)
        );
        assert_eq!(
            next(&mut driver, &mut local).await?,
            Value::Complete(Completion::End)
        );
        // add_delayed(ZERO) was already ready when admitted at5M. The
        // complete local callback stack retains priority, then that same remote
        // timeout must run now2M without waiting for time to recover.
        assert_eq!(
            next(&mut driver, &mut remote).await?,
            Value::Complete(Completion::Timeout)
        );
        clock.set(5_000_000)?;
        assert_eq!(ctx.pending_requests()?, 0);
        assert_eq!(next(&mut driver, &mut remote).await?, Value::Closed);
        Ok(())
    })
}

#[test]
fn logical_clock_revision_wakes_unbounded_drive_and_timeout_keeps_original_deadline() -> Result {
    runtime()?.block_on(async {
        let dir = Dir::new()?;
        let clock = Arc::new(SourceClock::frozen(1_000_000, 8)?);
        let (ctx, mut driver) = broker::<3, 64>(
            LiveConfiguration::new(cfg(&dir.socket("absent"))?),
            Limits::default(),
            profile()?,
            clock.clone(),
        )?;
        let mut query = ctx.ip_get(b"waiting", Family::Any, CoreDuration(60_000_000))?;
        // First drive arms the source-clock listener without advancing to retry.
        let mut drive = Box::pin(driver.drive(None, |_| {}));
        poll_fn(|cx| {
            assert!(drive.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        clock.set(61_000_000)?;
        assert_eq!(
            timeout(Duration::from_secs(1), drive).await??,
            Progress::Activity
        );
        assert_eq!(
            next(&mut driver, &mut query).await?,
            Value::Complete(Completion::Timeout)
        );
        Ok(())
    })
}

#[test]
fn client_tcp_success_retains_dns_drain_until_actual_end_and_ignores_later_addresses() -> Result {
    runtime()?.block_on(async {
        let dir = Dir::new()?;
        let resolver = UnixListener::bind(dir.socket("resolver"))?;
        let service = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let port = service.local_addr()?.port();
        let (mut control, mut peer_control) = UnixStream::pair()?;
        let peer = tokio::spawn(async move {
            let (mut s, _) = resolver.accept().await?;
            let bytes = frame(&mut s).await?;
            let request = Request::decode(Frame::decode(&bytes)?, profile()?)?;
            assert!(matches!(
                request.query(),
                gnunet_client::resolver::Query::Forward {
                    hostname: b"owned-service",
                    ..
                }
            ));
            s.write_all(&response(
                request.id(),
                WireReply::Address("127.0.0.1".parse()?),
            )?)
            .await?;
            assert_eq!(peer_control.read_u8().await?, 1);
            // CLIENT has a connected service socket. Its still-live DNS handle
            // ignores this value, rather than creating a second TCP probe.
            s.write_all(&response(
                request.id(),
                WireReply::Address("127.0.0.1".parse()?),
            )?)
            .await?;
            assert_eq!(peer_control.read_u8().await?, 2);
            s.write_all(&response(request.id(), WireReply::End)?)
                .await?;
            assert_eq!(timeout(Duration::from_secs(2), s.read(&mut [0])).await??, 0);
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });
        let (ctx, mut driver) =
            setup::<4, 64>(LiveConfiguration::new(cfg(&dir.socket("resolver"))?))?;
        let mut c = Configuration::default();
        c.set_value(b"owned", b"HOSTNAME", Some(b"owned-service"))?;
        c.set_value(b"owned", b"PORT", Some(port.to_string().as_bytes()))?;
        let endpoint =
            gnunet_client_host::Endpoint::configuration(c, b"owned", ctx.resolution_context())?;
        let mut attempt = Box::pin(endpoint.attempt(0));
        let until = Instant::now() + Duration::from_secs(2);
        let connection = loop {
            let mut drive = Box::pin(driver.drive(Some(until), |_| {}));
            let result = poll_fn(|cx| {
                if let Poll::Ready(result) = attempt.as_mut().poll(cx) {
                    return Poll::Ready(result.map(Some));
                }
                match drive.as_mut().poll(cx) {
                    Poll::Ready(Ok(Progress::WaitDeadline)) => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "CLIENT connect deadline",
                    ))),
                    Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e))),
                    Poll::Ready(Ok(_)) => Poll::Ready(Ok(None)),
                    Poll::Pending => Poll::Pending,
                }
            })
            .await?;
            if let Some(connection) = result {
                break connection;
            }
        };
        assert!(connection.retains_lease());
        let (mut accepted, _) = timeout(Duration::from_secs(1), service.accept()).await??;
        assert_eq!(ctx.pending_requests()?, 1);
        assert!(matches!(
            driver.disconnect(),
            Err(gnunet_resolver_broker::BrokerError::Core(
                gnunet_types::Error::WouldBlock
            ))
        ));
        control.write_u8(1).await?;
        let until = Instant::now() + Duration::from_millis(30);
        while driver.drive(Some(until), |_| {}).await? != Progress::WaitDeadline {}
        assert_eq!(ctx.pending_requests()?, 1);
        assert!(
            timeout(Duration::from_millis(15), service.accept())
                .await
                .is_err()
        );
        assert!(matches!(
            driver.disconnect(),
            Err(gnunet_resolver_broker::BrokerError::Core(
                gnunet_types::Error::WouldBlock
            ))
        ));
        control.write_u8(2).await?;
        let until = Instant::now() + Duration::from_secs(2);
        while driver.drive(Some(until), |_| {}).await? != Progress::Idle {}
        assert_eq!(ctx.pending_requests()?, 0);
        peer.await?.map_err(|e| e.to_string())?;
        // DNS END retires only the subscription. The actual service connection
        // remains usable until its independently owned Connection is dropped.
        let mut connection = connection;
        connection.write_all(b"live").await?;
        let mut bytes = [0; 4];
        accepted.read_exact(&mut bytes).await?;
        assert_eq!(&bytes, b"live");
        drop(connection);
        assert_eq!(
            timeout(Duration::from_secs(1), accepted.read(&mut [0])).await??,
            0
        );
        Ok(())
    })
}

#[test]
fn selected_configuration_changes_only_next_mq_while_old_unix_identity_remains_live() -> Result {
    runtime()?.block_on(async {
        let dir=Dir::new()?;
        let old_path=dir.socket("old-live");let new_path=dir.socket("new-live");
        let old_listener=UnixListener::bind(&old_path)?;let new_listener=UnixListener::bind(&new_path)?;
        let old_store=LiveConfiguration::new(cfg(&dir.socket("absent"))?);
        let new_store=LiveConfiguration::new(cfg(&new_path)?);
        let (ctx,mut driver)=setup::<4,64>(old_store.clone())?;
        let mut first=ctx.ip_get(b"first",Family::Any,CoreDuration(1_000_000))?;
        let until=Instant::now()+Duration::from_secs(2);let mut retry=false;
        while !retry {assert_ne!(driver.drive(Some(until),|event|{if matches!(event,gnunet_resolver_broker::DriverEvent::SocketRetry{..}){retry=true;}}).await?,Progress::WaitDeadline);}
        ctx.connect_live(new_store)?;
        old_store.replace(cfg(&old_path)?)?;
        let old_peer=tokio::spawn(async move {let(mut s,_)=old_listener.accept().await?;for expected in [b"first".as_slice(),b"second"]{let bytes=frame(&mut s).await?;let q=Request::decode(Frame::decode(&bytes)?,profile()?)?;assert!(matches!(q.query(),gnunet_client::resolver::Query::Forward{hostname,..}if hostname==expected));s.write_all(&response(q.id(),WireReply::End)?).await?;}assert_eq!(timeout(Duration::from_secs(2),s.read(&mut[0])).await??,0);Ok::<_,Box<dyn Error+Send+Sync>>(())});
        let mut second=ctx.ip_get(b"second",Family::Any,CoreDuration(1_000_000))?;
        assert_eq!(next(&mut driver,&mut first).await?,Value::Complete(Completion::End));assert_eq!(next(&mut driver,&mut second).await?,Value::Complete(Completion::End));
        let until=Instant::now()+Duration::from_secs(2);while driver.drive(Some(until),|_|{}).await?!=Progress::Idle{}
        old_peer.await?.map_err(|e|e.to_string())?;
        assert!(timeout(Duration::from_millis(15),new_listener.accept()).await.is_err());
        let new_peer=tokio::spawn(async move {let(mut s,_)=new_listener.accept().await?;let bytes=frame(&mut s).await?;let q=Request::decode(Frame::decode(&bytes)?,profile()?)?;assert!(matches!(q.query(),gnunet_client::resolver::Query::Forward{hostname:b"third",..}));s.write_all(&response(q.id(),WireReply::End)?).await?;assert_eq!(timeout(Duration::from_secs(2),s.read(&mut[0])).await??,0);Ok::<_,Box<dyn Error+Send+Sync>>(())});
        let mut third=ctx.ip_get(b"third",Family::Any,CoreDuration(1_000_000))?;assert_eq!(next(&mut driver,&mut third).await?,Value::Complete(Completion::End));
        let until=Instant::now()+Duration::from_secs(2);while driver.drive(Some(until),|_|{}).await?!=Progress::Idle{}
        new_peer.await?.map_err(|e|e.to_string())?;Ok(())
    })
}

#[test]
fn stale_foreign_capacity_and_clock_failure_drop_do_not_alias_callback_authority() -> Result {
    struct FailingClock {
        failed: std::sync::atomic::AtomicBool,
    }
    impl gnunet_resolver_broker::RuntimeClock for FailingClock {
        fn sample(
            &self,
        ) -> std::result::Result<gnunet_resolver_broker::ClockSample, gnunet_types::Error> {
            if self.failed.load(Ordering::Relaxed) {
                Err(gnunet_types::Error::Unavailable)
            } else {
                Ok(gnunet_resolver_broker::ClockSample {
                    now: gnunet_types::AbsoluteTime::from_micros(10),
                    revision: 0,
                })
            }
        }
        fn subscribe(
            &self,
        ) -> std::result::Result<
            Box<dyn gnunet_resolver_broker::ClockSubscription>,
            gnunet_types::Error,
        > {
            gnunet_resolver_broker::RuntimeClock::subscribe(
                &gnunet_service_runtime::clock::SystemClock,
            )
        }
    }
    runtime()?.block_on(async {
        let clock = Arc::new(FailingClock {
            failed: std::sync::atomic::AtomicBool::new(false),
        });
        let (ctx, mut driver) = broker::<2, 64>(
            LiveConfiguration::new(Configuration::default()),
            Limits::default(),
            profile()?,
            clock.clone(),
        )?;
        let (other, _other_driver) =
            setup::<2, 64>(LiveConfiguration::new(Configuration::default()))?;
        let query = ctx.ip_get(b"localhost", Family::Any, CoreDuration(0))?;
        let old = query.token();
        assert!(matches!(
            other.request_cancel(&old),
            Err(gnunet_resolver_broker::BrokerError::Core(
                gnunet_types::Error::StaleGeneration
            ))
        ));
        assert!(matches!(
            ctx.ip_get(b"127.0.0.1", Family::Any, CoreDuration(0)),
            Err(gnunet_resolver_broker::BrokerError::Core(
                gnunet_types::Error::Capacity
            ))
        ));
        clock.failed.store(true, Ordering::Relaxed);
        drop(query);
        assert_eq!(ctx.pending_requests()?, 0);
        clock.failed.store(false, Ordering::Relaxed);
        let mut next_query = ctx.ip_get(b"127.0.0.1", Family::Any, CoreDuration(0))?;
        assert_ne!(old, next_query.token());
        assert!(matches!(
            ctx.request_cancel(&old),
            Err(gnunet_resolver_broker::BrokerError::Core(
                gnunet_types::Error::StaleGeneration
            ))
        ));
        assert_eq!(
            next(&mut driver, &mut next_query).await?,
            Value::Address("127.0.0.1".parse()?)
        );
        assert_eq!(
            next(&mut driver, &mut next_query).await?,
            Value::Complete(Completion::End)
        );
        Ok(())
    })
}

#[test]
fn maximum_65535_frame_reaches_shared_mq_and_rejected_names_preserve_admission() -> Result {
    runtime()?.block_on(async {
        let dir = Dir::new()?;
        let listener = UnixListener::bind(dir.socket("maximum"))?;
        let (ctx, mut driver) = broker::<2, 65518>(
            LiveConfiguration::new(cfg(&dir.socket("maximum"))?),
            Limits::default(),
            profile()?,
            Arc::new(SystemClock),
        )?;
        assert!(
            ctx.ip_get(&vec![b'a'; 65519], Family::Any, CoreDuration(2_000_000))
                .is_err()
        );
        assert!(
            ctx.ip_get(b"a\0b", Family::Any, CoreDuration(2_000_000))
                .is_err()
        );
        assert_eq!(ctx.pending_requests()?, 0);
        assert!(
            timeout(Duration::from_millis(5), listener.accept())
                .await
                .is_err()
        );
        let peer = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await?;
            let bytes = frame(&mut s).await?;
            assert_eq!(bytes.len(), 65535);
            assert_eq!(&bytes[..4], b"\xff\xff\0\x04");
            assert_eq!(&bytes[12..16], &1u32.to_ne_bytes());
            assert_eq!(bytes.last(), Some(&0));
            assert!(bytes[16..65534].iter().all(|b| *b == b'a'));
            let query = Request::decode(Frame::decode(&bytes)?, profile()?)?;
            s.write_all(&response(query.id(), WireReply::End)?).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });
        let mut query = ctx.ip_get(&vec![b'a'; 65518], Family::Any, CoreDuration(2_000_000))?;
        assert_eq!(
            next(&mut driver, &mut query).await?,
            Value::Complete(Completion::End)
        );
        peer.await?.map_err(|e| e.to_string())?;
        Ok(())
    })
}

#[test]
fn client_zero_timer_registration_remains_ready_after_source_clock_rollback() -> Result {
    runtime()?.block_on(async {
        let clock = Arc::new(SourceClock::frozen(1000, 8)?);
        let (ctx, _driver) = broker::<2, 64>(
            LiveConfiguration::new(Configuration::default()),
            Limits::default(),
            profile()?,
            clock.clone(),
        )?;
        let mut timer = ctx.resolution_context().timer(Duration::ZERO)?;
        clock.set(500)?;
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(
            matches!(timer.as_mut().poll(&mut cx), Poll::Ready(Ok(()))),
            "source add_delayed0 was already registered ready before rollback"
        );
        clock.set(u64::MAX)?;
        let mut forever = ctx.resolution_context().timer(Duration::ZERO)?;
        clock.set(u64::MAX - 1)?;
        assert!(
            forever.as_mut().poll(&mut cx).is_pending(),
            "MAX+ZERO keeps the explicit FOREVER profile"
        );
        Ok(())
    })
}
