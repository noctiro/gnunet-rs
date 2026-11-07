//! Source-only controlled Unix IPC model; never runs crypto, keys or stores.
#![cfg(unix)]
use gnunet_gnsrecord::ZoneKeyType;
use gnunet_revocation_client_host::{
    Client, Deadlines, EndpointSource, Instance, Limits, Progress, ZoneKey, ipc,
};
use std::{
    error::Error,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixListener,
};
type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _removed = std::fs::remove_file(self.0.join("service.sock"));
        let _removed = std::fs::remove_dir(&self.0);
    }
}
struct Task(Option<tokio::task::JoinHandle<Result<()>>>);
impl Drop for Task {
    fn drop(&mut self) {
        if let Some(task) = &self.0 {
            task.abort();
        }
    }
}
#[test]
#[ignore = "source-only native ownership model; no execution authorized in this handoff"]
fn partial_reply_is_not_a_result_and_fresh_job_has_distinct_authority() -> Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(model())
}
async fn model() -> Result<()> {
    static SERIAL: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "gnunet-revocation-mq-{}-{}",
        std::process::id(),
        SERIAL.fetch_add(1, Ordering::Relaxed)
    ));
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().mode(0o700).create(&path)?;
    let directory = Directory(path);
    let endpoint = directory.0.join("service.sock");
    let listener = UnixListener::bind(&endpoint)?;
    let mut task = Task(Some(tokio::spawn(async move {
        let (mut first, _) = listener.accept().await?;
        let mut request = [0; ipc::QUERY_BYTES];
        first.read_exact(&mut request).await?;
        if !matches!(ipc::Request::decode(&request)?, ipc::Request::Query(_)) {
            return Err("expected query".into());
        }
        let mut response = [0; ipc::RESPONSE_BYTES];
        ipc::Response::Query(0).encode(&mut response)?;
        first.write_all(&response[..7]).await?;
        let mut eof = [0; 1];
        if first.read(&mut eof).await? != 0 {
            return Err("expired original MQ did not close".into());
        }
        let (mut second, _) = listener.accept().await?;
        second.read_exact(&mut request).await?;
        second.write_all(&response).await?;
        if second.read(&mut eof).await? != 0 {
            return Err("completed dedicated MQ did not close".into());
        }
        Ok(())
    })));
    let result = tokio::time::timeout(Duration::from_secs(3), async {
        let domain = Instance::new();
        let key = ZoneKey::new(ZoneKeyType::Edkey, [0; 32]); // public structural mock only
        let source = EndpointSource::unix(endpoint.clone());
        let now = source.clock().sample()?.now.as_micros();
        let until = now.checked_add(200_000).ok_or("deadline overflow")?;
        let mut first = Client::query(
            &domain,
            source,
            key,
            Deadlines {
                send_until: until,
                until,
            },
            Limits {
                io_slice_bytes: 3,
                ..Default::default()
            },
        )?;
        let old = first.job();
        let mut saw_end = false;
        for _ in 0..256 {
            match first.drive(None).await? {
                Progress::Reply(_) => {
                    return Err("7-byte suffix was fabricated into a response".into());
                }
                Progress::Ended(end) => {
                    if end.job != old {
                        return Err("wrong original job".into());
                    }
                    saw_end = true;
                    break;
                }
                Progress::Unavailable(e) => return Err(e.into()),
                Progress::Closed => break,
                _ => {}
            }
        }
        if !saw_end || !first.closed() {
            return Err("original deadline did not retire original MQ".into());
        }
        let source = EndpointSource::unix(endpoint);
        let now = source.clock().sample()?.now.as_micros();
        let until = now.checked_add(1_000_000).ok_or("deadline overflow")?;
        let mut second = Client::query(
            &domain,
            source,
            key,
            Deadlines {
                send_until: until,
                until,
            },
            Limits::default(),
        )?;
        if second.job() == old {
            return Err("fresh allocation reused old job authority".into());
        }
        loop {
            match second.drive(None).await? {
                Progress::Reply(reply) => {
                    if reply.response != ipc::Response::Query(0)
                        || reply.job != second.job()
                        || !second.closed()
                    {
                        return Err("raw query0/source ownership changed".into());
                    }
                    break;
                }
                Progress::Ended(_) | Progress::Closed => {
                    return Err("fresh actual response missing".into());
                }
                Progress::Unavailable(e) => return Err(e.into()),
                _ => {}
            }
        }
        task.0.as_mut().ok_or("task missing")?.await??;
        let _completed = task.0.take();
        Ok::<(), Box<dyn Error + Send + Sync>>(())
    })
    .await;
    // Every timeout/error drops the original socket owners and aborts the one
    // owned actor. No background test task is intentionally detached.
    result??;
    Ok(())
}
