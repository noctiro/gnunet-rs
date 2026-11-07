//! Selected cfg identity and per-MQ read-point actor for real C/R pairing.
use gnunet_config::Configuration;
use gnunet_resolver_broker::{
    Driver, Family, FamilyProfile, Hostname, Limits, LiveConfiguration, Progress, Query, Reply,
    SystemClock, broker,
};
use gnunet_types::{Duration, Error as CoreError};
use std::{
    error::Error,
    future::{Future, poll_fn},
    io::{self, Write},
    sync::Arc,
    task::Poll,
};
use tokio::time::Instant;
type Result<T = ()> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
fn line(s: &str) -> io::Result<()> {
    let mut out = io::stdout().lock();
    writeln!(out, "{s}")?;
    out.flush()
}
#[derive(Debug)]
enum Value {
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
                    return Err(format!("unexpected DNS address {a}").into());
                }
                Reply::Complete(_) => {
                    line(&format!("END|{id}"))?;
                    Value::End
                }
                Reply::Hostname(Hostname::Resolved(_) | Hostname::Numeric(_)) => {
                    return Err("unexpected reverse callback".into());
                }
            };
            drop(lease);
            return Ok(value);
        }
    }
}
fn main() -> Result {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 4 {
        return Err("config-a config-b live-path required".into());
    }
    let mut a = Configuration::default();
    a.deserialize(&std::fs::read(&args[1])?, None)?;
    let mut b = Configuration::default();
    b.deserialize(&std::fs::read(&args[2])?, None)?;
    let store = LiveConfiguration::new(a);
    let p = gnunet_resolver_broker::native_profile()?;
    let profile = FamilyProfile::new(
        p.encode(gnunet_resolver_broker::Family::V4),
        p.encode(gnunet_resolver_broker::Family::V6),
    )?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let (ctx, mut driver) = broker::<8, 64>(
                store.clone(),
                Limits {
                    io_chunk_bytes: 1,
                    ..Default::default()
                },
                profile,
                Arc::new(SystemClock),
            )?;
            let mut first = ctx.ip_get(b"first", Family::Any, Duration(3_000_000))?;
            let until = Instant::now() + std::time::Duration::from_secs(2);
            let mut retried = false;
            while !retried {
                if driver
                    .drive(Some(until), |event| {
                        if matches!(
                            event,
                            gnunet_resolver_broker::DriverEvent::SocketRetry { .. }
                        ) {
                            retried = true;
                        }
                    })
                    .await?
                    == Progress::WaitDeadline
                {
                    return Err("original logical MQ not established".into());
                }
            }
            ctx.connect(b)?;
            line("SELECT")?;
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            let mut changed = store.snapshot()?;
            changed.set_value(b"resolver", b"UNIXPATH", Some(args[3].as_encoded_bytes()))?;
            store.replace(changed)?;
            line("MUTATE")?;
            let mut second = ctx.ip_get(b"second", Family::Any, Duration(3_000_000))?;
            let _first = next(&mut driver, &mut first, 1).await?;
            let _second = next(&mut driver, &mut second, 2).await?;
            let until = Instant::now() + std::time::Duration::from_secs(2);
            while driver.drive(Some(until), |_| {}).await? != Progress::Idle {}
            line("THIRD")?;
            let mut third = ctx.ip_get(b"third", Family::Any, Duration(3_000_000))?;
            let _third = next(&mut driver, &mut third, 3).await?;
            let until = Instant::now() + std::time::Duration::from_secs(2);
            while driver.drive(Some(until), |_| {}).await? != Progress::Idle {}
            Ok(())
        })
}
