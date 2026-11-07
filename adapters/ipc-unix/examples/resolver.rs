//! Shared Resolver-owner probe. CONFIG MODE VALUE; no native FQDN lookup.
#![forbid(unsafe_code)]
use gnunet_config::Configuration;
use gnunet_resolver_broker::{
    Completion, DriverEvent, Family, Hostname, LiveConfiguration, Progress, Reply, SystemClock,
    broker,
};
use gnunet_types::Duration as QueryDuration;
use std::{
    error::Error,
    future::{Future, poll_fn},
    io::{self, Write},
    net::IpAddr,
    os::unix::ffi::OsStrExt,
    path::PathBuf,
    sync::Arc,
    task::Poll,
    time::Duration,
};
use tokio::time::Instant;
type Result<T> = std::result::Result<T, Box<dyn Error>>;
fn emit(args: std::fmt::Arguments<'_>) -> io::Result<()> {
    writeln!(io::stdout().lock(), "{args}")
}
async fn run(path: PathBuf, mode: &str, value: &[u8]) -> Result<()> {
    let mut cfg = Configuration::default();
    cfg.parse(path)?;
    let p = gnunet_resolver_broker::native_profile()?;
    let (ctx, mut driver) = broker::<16, 1024>(
        LiveConfiguration::new(cfg),
        gnunet_resolver_broker::Limits {
            io_chunk_bytes: 1,
            ..Default::default()
        },
        gnunet_resolver_broker::FamilyProfile::new(
            p.encode(gnunet_resolver_broker::Family::V4),
            p.encode(gnunet_resolver_broker::Family::V6),
        )?,
        Arc::new(SystemClock),
    )?;
    let timeout = QueryDuration(if mode == "reverse" { 80_000 } else { 1_000_000 });
    let mut query = match mode {
        "forward" | "forward4" | "forward6" | "cancel-first" | "cancel-before" => ctx.ip_get(
            value,
            match mode {
                "forward4" => Family::V4,
                "forward6" => Family::V6,
                _ => Family::Any,
            },
            timeout,
        )?,
        "reverse" | "numeric-reverse" => ctx.hostname_get(
            std::str::from_utf8(value)?.parse::<IpAddr>()?,
            mode == "reverse",
            timeout,
        )?,
        _ => return Err("unknown resolver probe mode".into()),
    };
    let original = query.token();
    let mut receiving = true;
    if mode == "cancel-before" {
        query.cancel()?;
        receiving = false;
        emit(format_args!("cancel|before"))?;
    }
    let until = Instant::now() + Duration::from_secs(3);
    let (mut connected, mut values, mut complete, mut cancelled) = (0, 0, 0, false);
    while ctx.pending_requests()? != 0 {
        let mut observer_error = None;
        let mut waiting = if receiving {
            Some(Box::pin(query.next()))
        } else {
            None
        };
        let mut drive = Box::pin(driver.drive(Some(until), |event| {
            let result = match event {
                DriverEvent::Connected(_) => {
                    connected += 1;
                    emit(format_args!("connected"))
                }
                DriverEvent::Lost { cause, .. } => emit(format_args!("lost|{cause:?}")),
                DriverEvent::Unavailable => emit(format_args!("unavailable")),
                DriverEvent::SocketRetry { .. } => emit(format_args!("retry")),
                DriverEvent::IdleClosed(_) => Ok(()),
            };
            if let Err(e) = result {
                observer_error = Some(e);
            }
        }));
        let mut progress = Progress::Activity;
        let step = poll_fn(|cx| {
            if let Some(q) = &mut waiting
                && let Poll::Ready(result) = q.as_mut().poll(cx)
            {
                return Poll::Ready(result.map(Some));
            }
            match drive.as_mut().poll(cx) {
                Poll::Ready(result) => Poll::Ready(result.map(|value| {
                    progress = value;
                    None
                })),
                Poll::Pending => Poll::Pending,
            }
        })
        .await?;
        drop(drive);
        drop(waiting);
        if let Some(e) = observer_error {
            return Err(e.into());
        }
        if let Some(lease) = step {
            let Some(lease) = lease else {
                receiving = false;
                continue;
            };
            if lease.token() != &original {
                return Err("foreign query callback".into());
            }
            match lease.reply()? {
                Reply::Address(address) => {
                    values += 1;
                    emit(format_args!("address|{address}"))?;
                    if mode == "cancel-first" && !cancelled {
                        ctx.request_cancel(&original)?;
                        cancelled = true;
                        receiving = false;
                        emit(format_args!("cancel|value"))?;
                    }
                }
                Reply::Hostname(hostname) => {
                    values += 1;
                    match hostname {
                        Hostname::Numeric(a) => emit(format_args!("numeric|{a}"))?,
                        Hostname::Resolved(bytes) => {
                            let mut out = io::stdout().lock();
                            out.write_all(b"name|")?;
                            out.write_all(bytes)?;
                            out.write_all(b"\n")?;
                        }
                    }
                }
                Reply::Complete(reason) => {
                    complete += 1;
                    receiving = false;
                    emit(format_args!(
                        "end|{}",
                        match reason {
                            Completion::End => "end",
                            Completion::Timeout => "timeout",
                            Completion::Malformed => "malformed",
                        }
                    ))?;
                }
            }
            drop(lease);
        } else if progress != Progress::Activity {
            return Err("drive stopped before pending requests completed".into());
        }
    }
    driver.disconnect()?;
    emit(format_args!("summary|{connected}|{values}|{complete}"))?;
    Ok(())
}
fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let cfg = PathBuf::from(args.next().ok_or("missing CONFIG")?);
    let mode = args.next().ok_or("missing MODE")?;
    let value = args.next().ok_or("missing VALUE")?;
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run(
            cfg,
            mode.to_str().ok_or("mode UTF8")?,
            value.as_bytes(),
        ))
}
