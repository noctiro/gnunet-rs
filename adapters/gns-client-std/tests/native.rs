//! Real Unix framing, original query debt and independent reply budgets.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Actual native IO assertions verify original ownership and independent query progress"
)]
use gnunet_client::gns::{Lookup, encode_result};
use gnunet_gns_client_host::{
    BoundedClient, EndpointSource, Instance, Limits, LocalOptions, LossCause, Parameters, Progress,
    RecordData, RecordFlags, RecordType, ZoneKey, ZoneKeyType,
};
use std::{
    error::Error,
    future::Future,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};
type Failure = Box<dyn Error + Send + Sync>;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Result<Self, Failure> {
        let p = std::env::temp_dir().join(format!(
            "gnrs-gns-client-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir(&p)?;
        Ok(Self(p))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _removed = std::fs::remove_dir_all(&self.0);
    }
}
fn parameters() -> Parameters {
    Parameters {
        zone: ZoneKey::new(ZoneKeyType::Edkey, [7; 32]),
        options: LocalOptions::NO_DHT,
        recursion_depth: 64,
        record_type: RecordType::A,
    }
}
async fn frame(stream: &mut UnixStream) -> Result<Vec<u8>, Failure> {
    let mut h = [0; 4];
    stream.read_exact(&mut h).await?;
    let len = usize::from(u16::from_be_bytes([h[0], h[1]]));
    if len < 4 {
        return Err("invalid native frame".into());
    }
    let mut bytes = vec![0; len];
    bytes[..4].copy_from_slice(&h);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(bytes)
}
fn reply(request: &[u8], count: usize) -> Result<Vec<u8>, Failure> {
    let id = Lookup::decode(request)?.id();
    let record = RecordData {
        expiration_time: u64::MAX,
        record_type: RecordType::A,
        flags: RecordFlags::from_bits_preserve(0),
        data: &[192, 0, 2, 17],
    };
    let records = vec![record; count];
    let mut output = vec![0; 1024];
    let len = encode_result(id, &records, &mut output)?;
    output.truncate(len);
    Ok(output)
}
async fn step<'a, const R: usize, const N: usize>(
    client: &mut BoundedClient<'a, R, N>,
) -> Result<Option<Progress<'a>>, Failure> {
    let result = {
        let future = client.drive(None);
        let mut future = std::pin::pin!(future);
        let mut cx = Context::from_waker(Waker::noop());
        future.as_mut().poll(&mut cx)
    };
    tokio::time::sleep(Duration::from_millis(1)).await;
    match result {
        Poll::Ready(result) => Ok(Some(result?)),
        Poll::Pending => Ok(None),
    }
}
#[tokio::test(flavor = "current_thread")]
async fn canceled_partial_frame_drains_same_mq_then_live_reply_survives_close()
-> Result<(), Failure> {
    let d = Directory::new()?;
    let path = d.0.join("gns");
    let listener = UnixListener::bind(&path)?;
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await?;
        let first = frame(&mut socket).await?;
        let second = frame(&mut socket).await?;
        assert_eq!(Lookup::decode(&first)?.name(), b"canceled");
        assert_eq!(Lookup::decode(&second)?.name(), b"healthy");
        socket.write_all(&reply(&first, 1)?).await?;
        socket.write_all(&reply(&second, 1)?).await?;
        assert_eq!(socket.read(&mut [0]).await?, 0);
        Ok::<_, Failure>(())
    });
    let mut instance = Instance::new();
    let mut limits = Limits {
        io_slice_bytes: 1,
        ..Limits::default()
    };
    limits.output.frames = 2;
    let mut client =
        BoundedClient::<4, 32>::new(&mut instance, EndpointSource::unix(path), limits)?;
    let old = client.lookup(parameters(), b"canceled")?;
    let healthy = client.lookup(parameters(), b"healthy")?;
    let until = Instant::now() + Duration::from_secs(5);
    let mut canceled = false;
    let mut ignored = 0;
    let mut receipt = false;
    let mut answer = None;
    while answer.is_none() && Instant::now() < until {
        match step(&mut client).await? {
            Some(Progress::Activity {
                written_bytes: 1, ..
            }) if !canceled => {
                client.cancel(old)?;
                canceled = true;
                assert!(!client.live(old));
                assert!(client.pending_writes() > 0);
            }
            Some(Progress::Written { query, .. }) if query == old => receipt = true,
            Some(Progress::Ignored(_)) => ignored += 1,
            Some(Progress::Answer(value)) => {
                assert_eq!(value.query(), healthy);
                answer = Some(value);
            }
            Some(Progress::Lost { .. }) => {
                return Err("partial cancellation replaced original physical MQ".into());
            }
            _ => {}
        }
    }
    let answer = answer.ok_or("live answer timeout")?;
    assert!(canceled && receipt);
    assert_eq!(ignored, 1);
    assert!(!client.live(healthy));
    assert_eq!(client.pending_queries(), 0);
    assert_eq!(client.pending_writes(), 0);
    assert!(matches!(
        client.close(),
        Some(Progress::Lost {
            cause: LossCause::Closed,
            ..
        })
    ));
    assert!(matches!(client.drive(None).await?, Progress::Closed));
    assert_eq!(
        answer
            .result()?
            .records()
            .iter()
            .next()
            .ok_or("record")??
            .data,
        &[192, 0, 2, 17]
    );
    server.await??;
    Ok(())
}
#[tokio::test(flavor = "current_thread")]
async fn partial_reply_eof_retires_exact_epoch_and_restores_only_original_live_lookup()
-> Result<(), Failure> {
    let d = Directory::new()?;
    let path = d.0.join("gns");
    let listener = UnixListener::bind(&path)?;
    let server = tokio::spawn(async move {
        let (mut old, _) = listener.accept().await?;
        let original = frame(&mut old).await?;
        let bytes = reply(&original, 1)?;
        old.write_all(&bytes[..17]).await?;
        drop(old);
        let (mut next, _) = listener.accept().await?;
        let restored = frame(&mut next).await?;
        assert_eq!(original, restored);
        next.write_all(&reply(&restored, 1)?).await?;
        assert_eq!(next.read(&mut [0]).await?, 0);
        Ok::<_, Failure>(())
    });
    let mut instance = Instance::new();
    let limits = Limits {
        io_slice_bytes: 1,
        ..Limits::default()
    };
    let mut client =
        BoundedClient::<2, 32>::new(&mut instance, EndpointSource::unix(path), limits)?;
    let suppressed = client.lookup(parameters(), b"queued-cancel")?;
    client.cancel(suppressed)?;
    let live = client.lookup(parameters(), b"retained")?;
    let until = Instant::now() + Duration::from_secs(5);
    let mut epochs = Vec::new();
    let mut losses = 0;
    let mut done = false;
    while !done && Instant::now() < until {
        match step(&mut client).await? {
            Some(Progress::Connected(epoch)) => epochs.push(epoch),
            Some(Progress::Lost {
                epoch,
                cause: LossCause::Io(error),
                retained_queries,
            }) => {
                assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
                assert_eq!(Some(&epoch), epochs.first());
                assert_eq!(retained_queries, 1);
                assert!(client.live(live));
                losses += 1;
            }
            Some(Progress::Answer(answer)) => {
                assert_eq!(answer.query(), live);
                assert_eq!(epochs.len(), 2);
                assert_ne!(epochs[0], epochs[1]);
                assert_eq!(answer.epoch(), epochs[1]);
                done = true;
            }
            Some(Progress::Lost { .. }) => return Err("unexpected original loss cause".into()),
            _ => {}
        }
    }
    assert!(done);
    assert_eq!(losses, 1);
    let _original = client.close();
    server.await??;
    Ok(())
}
#[tokio::test(flavor = "current_thread")]
async fn observation_wait_deadline_does_not_cancel_a_live_original_query() -> Result<(), Failure> {
    let d = Directory::new()?;
    let path = d.0.join("gns");
    let listener = UnixListener::bind(&path)?;
    let (release, waiting) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await?;
        let request = frame(&mut socket).await?;
        waiting.await?;
        socket.write_all(&reply(&request, 1)?).await?;
        assert_eq!(socket.read(&mut [0]).await?, 0);
        Ok::<_, Failure>(())
    });
    let mut instance = Instance::new();
    let mut client =
        BoundedClient::<2, 32>::new(&mut instance, EndpointSource::unix(path), Limits::default())?;
    let original = client.lookup(parameters(), b"wait")?;
    let until = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        match client.drive(Some(until)).await? {
            Progress::Written { query, .. } => {
                assert_eq!(query, original);
                break;
            }
            Progress::WaitDeadline => return Err("write timeout".into()),
            _ => {}
        }
    }
    let budget = tokio::time::Instant::now() + Duration::from_millis(15);
    assert!(matches!(
        client.drive(Some(budget)).await?,
        Progress::WaitDeadline
    ));
    assert!(client.live(original));
    release.send(()).map_err(|_| "server lost release")?;
    loop {
        match client.drive(Some(until)).await? {
            Progress::Answer(answer) => {
                assert_eq!(answer.query(), original);
                break;
            }
            Progress::WaitDeadline => return Err("reply timeout".into()),
            _ => {}
        }
    }
    let _original = client.close();
    server.await??;
    Ok(())
}
#[tokio::test(flavor = "current_thread")]
async fn one_record_budget_refusal_keeps_another_original_query_on_the_same_mq()
-> Result<(), Failure> {
    let d = Directory::new()?;
    let path = d.0.join("gns");
    let listener = UnixListener::bind(&path)?;
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await?;
        let large = frame(&mut socket).await?;
        let healthy = frame(&mut socket).await?;
        let mut bytes = reply(&large, 2)?;
        bytes.extend_from_slice(&reply(&healthy, 1)?);
        socket.write_all(&bytes).await?;
        assert_eq!(socket.read(&mut [0]).await?, 0);
        Ok::<_, Failure>(())
    });
    let mut instance = Instance::new();
    let limits = Limits {
        records: 1,
        ..Limits::default()
    };
    let mut client =
        BoundedClient::<2, 32>::new(&mut instance, EndpointSource::unix(path), limits)?;
    let large = client.lookup(parameters(), b"large")?;
    let healthy = client.lookup(parameters(), b"healthy")?;
    let until = Instant::now() + Duration::from_secs(3);
    let mut done = false;
    let mut refused = 0;
    let mut original_epoch = None;
    while !done && Instant::now() < until {
        match step(&mut client).await? {
            Some(Progress::Connected(epoch)) => {
                assert!(original_epoch.is_none());
                original_epoch = Some(epoch);
            }
            Some(Progress::Refused {
                epoch,
                query,
                reason,
            }) => {
                assert_eq!(Some(epoch), original_epoch);
                assert_eq!(query, large);
                assert_eq!(reason, gnunet_types::Error::Capacity);
                assert!(!client.live(large));
                assert!(client.live(healthy));
                refused += 1;
            }
            Some(Progress::Answer(answer)) => {
                assert_eq!(answer.query(), healthy);
                assert_eq!(Some(answer.epoch()), original_epoch);
                done = true;
            }
            Some(Progress::Lost { .. }) => {
                return Err("one local reply budget retired unrelated original query/MQ".into());
            }
            _ => {}
        }
    }
    assert!(
        done,
        "healthy query must finish despite another query exceeding the local record budget"
    );
    assert_eq!(refused, 1);
    let _original = client.close();
    server.await??;
    Ok(())
}
