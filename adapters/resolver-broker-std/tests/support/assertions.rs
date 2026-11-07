//! Actual shared broker assertions reused by constructor migration tests.
use gnunet_client::resolver::{FamilyProfile, Reply as WireReply, encode_response};
use gnunet_config::Configuration;
use gnunet_resolver_broker::{
    Completion, Context, Driver, Hostname, Limits, LiveConfiguration, Progress, Query, Reply,
    SystemClock, broker,
};
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
use tokio::{io::AsyncReadExt, time::Instant};
pub type Result<T = ()> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
static NEXT: AtomicU64 = AtomicU64::new(0);
pub struct Dir(PathBuf);
impl Dir {
    pub fn new() -> io::Result<Self> {
        let p = std::env::temp_dir().join(format!(
            "rb-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&p)?;
        Ok(Self(p))
    }
    pub fn socket(&self, n: &str) -> PathBuf {
        self.0.join(n)
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.0));
    }
}
pub fn runtime() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}
pub fn profile() -> Result<FamilyProfile> {
    let profile = gnunet_resolver_broker::native_profile()?;
    Ok(FamilyProfile::new(
        profile.encode(gnunet_resolver_broker::Family::V4),
        profile.encode(gnunet_resolver_broker::Family::V6),
    )?)
}
pub fn cfg(path: &Path) -> Result<Configuration> {
    let mut c = Configuration::default();
    c.set_value(
        b"resolver",
        b"UNIXPATH",
        Some(path.as_os_str().as_encoded_bytes()),
    )?;
    Ok(c)
}
pub fn setup<const R: usize, const N: usize>(
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
pub async fn frame(s: &mut (impl tokio::io::AsyncRead + Unpin)) -> Result<Vec<u8>> {
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
pub fn response(id: gnunet_client::resolver::WireId, value: WireReply<'_>) -> Result<Vec<u8>> {
    let mut bytes = vec![0; 65535];
    let len = encode_response(id, value, &mut bytes)?;
    bytes.truncate(len);
    Ok(bytes)
}
#[derive(Debug, PartialEq)]
pub enum Value {
    Address(std::net::IpAddr),
    Name(Vec<u8>),
    Numeric(std::net::IpAddr),
    Complete(Completion),
    Closed,
}
pub async fn next<const R: usize, const N: usize>(
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
