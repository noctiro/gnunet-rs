//! Observable public Rust broker actor for paired owned-peer tests.
use gnunet_config::Configuration;
use gnunet_resolver_broker::{
    Driver, Family, FamilyProfile, Hostname, Limits, LiveConfiguration, Progress, Query, Reply,
    broker,
};
use gnunet_types::{Duration, Error as CoreError};
use std::{
    error::Error,
    future::{Future, poll_fn},
    io::{self, Write},
    sync::Arc,
    task::Poll,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::Instant,
};
type Result<T = ()> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
fn line(s: &str) -> io::Result<()> {
    let mut out = io::stdout().lock();
    writeln!(out, "{s}")?;
    out.flush()
}
#[path = "../../ipc-unix/tests/support/clock_source.rs"]
pub mod clock_source;
use clock_source::Adjustable as Clock;
#[derive(Debug)]
enum Value {
    Address(std::net::IpAddr),
    Name,
    End,
}
async fn next(driver: &mut Driver<8, 64>, query: &mut Query<8, 64>, id: u8) -> Result<Value> {
    let until = Instant::now() + std::time::Duration::from_secs(4);
    loop {
        let mut q = Box::pin(query.next());
        let mut d = Box::pin(driver.drive(Some(until), |_| {}));
        let result = poll_fn(|cx| {
            if let Poll::Ready(v) = q.as_mut().poll(cx) {
                return Poll::Ready(v.map(Some));
            }
            match d.as_mut().poll(cx) {
                Poll::Ready(Ok(Progress::WaitDeadline)) => {
                    Poll::Ready(Err(CoreError::Deadline.into()))
                }
                Poll::Ready(Ok(_)) => Poll::Ready(Ok(None)),
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await?;
        if let Some(lease) = result {
            let lease = lease.ok_or("query ended without callback")?;
            let value = match lease.reply()? {
                Reply::Address(a) => {
                    line(&format!("ADDR|{id}|{a}"))?;
                    Value::Address(a)
                }
                Reply::Complete(_) => {
                    line(&format!("END|{id}"))?;
                    Value::End
                }
                Reply::Hostname(Hostname::Resolved(bytes)) => {
                    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
                    line(&format!("NAME|{id}|{hex}"))?;
                    Value::Name
                }
                Reply::Hostname(Hostname::Numeric(address)) => {
                    let text = address.to_string();
                    let hex: String = text.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
                    line(&format!("NAME|{id}|{hex}"))?;
                    Value::Name
                }
            };
            drop(lease);
            return Ok(value);
        }
    }
}
async fn driving<T>(
    driver: &mut Driver<8, 64>,
    future: impl Future<Output = io::Result<T>>,
) -> Result<T> {
    let mut future = Box::pin(future);
    let until = Instant::now() + std::time::Duration::from_secs(4);
    loop {
        let mut drive = Box::pin(driver.drive(Some(until), |_| {}));
        let mut idle = false;
        let result = poll_fn(|cx| {
            if let Poll::Ready(r) = future.as_mut().poll(cx) {
                return Poll::Ready(r.map(Some));
            }
            match drive.as_mut().poll(cx) {
                Poll::Ready(Ok(Progress::WaitDeadline)) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "service deadline",
                ))),
                Poll::Ready(Ok(Progress::Idle)) => {
                    idle = true;
                    Poll::Ready(Ok(None))
                }
                Poll::Ready(Ok(Progress::Activity)) => Poll::Ready(Ok(None)),
                Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e))),
                Poll::Pending => Poll::Pending,
            }
        })
        .await?;
        if let Some(value) = result {
            return Ok(value);
        }
        if idle {
            return Ok(tokio::time::timeout_at(until, future).await??);
        }
    }
}
fn main() -> Result {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 3 {
        return Err("config mode required".into());
    }
    let mode = args[2].to_str().ok_or("mode is not UTF8")?;
    let mut cfg = Configuration::default();
    cfg.deserialize(&std::fs::read(&args[1])?, None)?;
    let p = gnunet_resolver_broker::native_profile()?;
    let profile = FamilyProfile::new(
        p.encode(gnunet_resolver_broker::Family::V4),
        p.encode(gnunet_resolver_broker::Family::V6),
    )?;
    let clock = Arc::new(Clock::advancing(5_000_000, 8)?);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let (ctx, mut driver) = broker::<8, 64>(
                LiveConfiguration::new(cfg.duplicate()?),
                Limits {
                    io_chunk_bytes: 1,
                    ..Default::default()
                },
                profile,
                clock.clone(),
            )?;
            match mode {
                "client" => {
                    let endpoint = gnunet_client_host::Endpoint::configuration(
                        cfg,
                        b"owned",
                        ctx.resolution_context(),
                    )?;
                    let mut connection = driving(&mut driver, endpoint.attempt(0)).await?;
                    if !connection.retains_lease() {
                        return Err("DNS subscription was lost before service success".into());
                    }
                    let header = [0u8, 4, 0, 0];
                    driving(&mut driver, connection.write_all(&header)).await?;
                    for n in 1..=2 {
                        let mut bytes = [0; 4];
                        driving(&mut driver, connection.read_exact(&mut bytes)).await?;
                        if bytes != header {
                            return Err("unexpected TEST response".into());
                        }
                        line(&format!("SERVICE|{n}"))?;
                    }
                    drop(connection);
                }
                "stack" => {
                    let mut q = ctx.ip_get(b"localhost", Family::Any, Duration(0))?;
                    if !matches!(next(&mut driver,&mut q,1).await?,Value::Address(a) if a.is_ipv6())
                    {
                        return Err("missing first v6".into());
                    }
                    let mut other = ctx.ip_get(b"due", Family::Any, Duration(0))?;
                    clock.offset(-3_000_000)?;
                    let _observed = next(&mut driver, &mut q, 1).await?;
                    let _observed = next(&mut driver, &mut q, 1).await?;
                    clock.offset(0)?;
                    let _observed = next(&mut driver, &mut other, 2).await?;
                }
                "instant" => {
                    let mut q = ctx.ip_get(b"warm", Family::Any, Duration(2_000_000))?;
                    let _observed = next(&mut driver, &mut q, 1).await?;
                    let mut cancel =
                        ctx.ip_get(b"instant-cancel", Family::Any, Duration(2_000_000))?;
                    cancel.cancel()?;
                    line("CANCEL|2")?;
                    let mut kept = ctx.ip_get(b"kept", Family::Any, Duration(2_000_000))?;
                    let _observed = next(&mut driver, &mut kept, 3).await?;
                }
                "orphan" => {
                    let mut q = ctx.ip_get(b"expired", Family::Any, Duration(50_000))?;
                    let mut cancel = ctx.ip_get(b"canceled", Family::Any, Duration(2_000_000))?;
                    let _observed = next(&mut driver, &mut q, 1).await?;
                    let mut kept = ctx.ip_get(b"kept", Family::Any, Duration(2_000_000))?;
                    cancel.cancel()?;
                    line("CANCEL|2")?;
                    let _observed = next(&mut driver, &mut kept, 3).await?;
                }
                "hosts" => {
                    let mut first =
                        ctx.ip_get(b"broadcasthost", Family::Any, Duration(2_000_000))?;
                    let mut second =
                        ctx.ip_get(b"broadcasthost", Family::Any, Duration(2_000_000))?;
                    while !matches!(next(&mut driver, &mut first, 1).await?, Value::End) {}
                    while !matches!(next(&mut driver, &mut second, 2).await?, Value::End) {}
                }
                "reverse" => {
                    let mut q =
                        ctx.hostname_get("192.0.2.9".parse()?, true, Duration(2_000_000))?;
                    while !matches!(next(&mut driver, &mut q, 1).await?, Value::End) {}
                }
                "retry" => {
                    let mut q = ctx.ip_get(b"retry", Family::Any, Duration(2_000_000))?;
                    while !matches!(next(&mut driver, &mut q, 1).await?, Value::End) {}
                }
                _ => return Err("unknown mode".into()),
            };
            let until = Instant::now() + std::time::Duration::from_secs(1);
            while driver.drive(Some(until), |_| {}).await? != Progress::Idle {}
            Ok(())
        })
}
