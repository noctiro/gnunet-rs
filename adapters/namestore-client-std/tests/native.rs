//! One controlled original-MQ model. All zone-shaped fields are this published
//! synthetic mock; no key file, generation, crypto, decryption or C process.
#![cfg(unix)]
use gnunet_gnsrecord::ZoneKeyType;
use gnunet_namestore_client_host::{
    Cancellation, Client, ControlKind, EndpointSource, Instance, Limits, LocalReason, Monitor,
    Operation, Outcome, Progress, Reply, SecretKey, Submission, ZoneIterator, ZoneKey,
    clock::{RuntimeClock, SystemClock},
    ipc::{CString, Records, Request, Response, StoreSet},
};
use gnunet_types::{AbsoluteTime, Error as Fault};
use gnunet_wire::official::{MessageHeader, identity::SecretKeyView};
use std::{error::Error, path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::Instant,
};
use zeroize::Zeroizing;
type Failure = Box<dyn Error + Send + Sync>;
// Public mock only. No key arithmetic, public-key derivation, hashing or actual
// private material is used; structural typed-key encoding is all that matters.
const MOCK: [u8; 36] = [
    0, 1, 0, 20, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3,
];
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Result<Self, Failure> {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let p = std::env::temp_dir().join(format!("gnsc-{}-{t}", std::process::id()));
        std::fs::create_dir(&p)?;
        Ok(Self(p))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_dir_all(&self.0);
    }
}
async fn frame(s: &mut UnixStream) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let mut h = [0; 4];
    s.read_exact(&mut h).await?;
    let mut b = Zeroizing::new(vec![0; MessageHeader::decode(&h)?.size()]);
    b[..4].copy_from_slice(&h);
    s.read_exact(&mut b[4..]).await?;
    Ok(b)
}
async fn send(s: &mut UnixStream, r: Response<'_>) -> Result<(), Failure> {
    let mut b = Zeroizing::new(vec![0; r.encoded_len()?]);
    r.encode(&mut b)?;
    for part in b.chunks(5) {
        s.write_all(part).await?;
    }
    Ok(())
}
async fn record(s: &mut UnixStream, rid: u32, label: &'static [u8]) -> Result<(), Failure> {
    send(
        s,
        Response::Records {
            rid,
            zone: SecretKeyView::new(&MOCK)?,
            label: CString::new(label)?,
            expires: AbsoluteTime::from_micros(123),
            records: Records::empty()?,
        },
    )
    .await
}
async fn eof(s: &mut UnixStream) -> Result<(), Failure> {
    let mut b = [0];
    assert_eq!(s.read(&mut b).await?, 0);
    Ok(())
}
async fn actor(listener: UnixListener) -> Result<(), Failure> {
    let (mut general, _) = listener.accept().await?;
    let rid = {
        let b = frame(&mut general).await?;
        let Request::Store {
            rid,
            single_tx,
            sets,
            ..
        } = Request::decode(&b)?
        else {
            return Err(Fault::Malformed.into());
        };
        assert_eq!(single_tx, 1);
        assert_eq!(sets.count(), 2);
        rid
    };
    send(&mut general, Response::Generic { rid, code: 0 }).await?;
    let rid = {
        let b = frame(&mut general).await?;
        let Request::Lookup { rid, label, .. } = Request::decode(&b)? else {
            return Err(Fault::Malformed.into());
        };
        assert_eq!(label.bytes(), b"alpha");
        rid
    };
    send(
        &mut general,
        Response::Lookup {
            rid,
            zone: SecretKeyView::new(&MOCK)?,
            label: CString::new(b"alpha")?,
            found: 0,
            reserved: 0,
            records: Records::empty()?,
        },
    )
    .await?;
    let rid = {
        let b = frame(&mut general).await?;
        let Request::ZoneToName { rid, .. } = Request::decode(&b)? else {
            return Err(Fault::Malformed.into());
        };
        rid
    };
    send(
        &mut general,
        Response::ZoneToName {
            rid,
            code: 5010,
            zone: None,
            label: None,
            records: Records::empty()?,
        },
    )
    .await?;
    let rid = {
        let b = frame(&mut general).await?;
        let Request::EditBegin { rid, hint, .. } = Request::decode(&b)? else {
            return Err(Fault::Malformed.into());
        };
        assert_eq!(hint.bytes(), b"editor");
        rid
    };
    send(
        &mut general,
        Response::Edit {
            rid,
            code: 0,
            hint: None,
            records: Records::empty()?,
        },
    )
    .await?;
    let rid = {
        let b = frame(&mut general).await?;
        let Request::EditCancel {
            rid, replacement, ..
        } = Request::decode(&b)?
        else {
            return Err(Fault::Malformed.into());
        };
        assert_eq!(replacement.bytes(), b"");
        rid
    };
    send(&mut general, Response::Generic { rid, code: 5013 }).await?;
    let rid = {
        let b = frame(&mut general).await?;
        let Request::EditBegin { rid, .. } = Request::decode(&b)? else {
            return Err(Fault::Malformed.into());
        };
        rid
    };
    send(
        &mut general,
        Response::Edit {
            rid,
            code: 0,
            hint: Some(CString::new(b"other")?),
            records: Records::empty()?,
        },
    )
    .await?;
    let b = frame(&mut general).await?;
    assert!(matches!(Request::decode(&b)?, Request::Store { .. }));
    drop(general); // Unknown mutating write: no replay or invented rollback.
    let (mut iteration, _) = listener.accept().await?;
    let rid = {
        let b = frame(&mut iteration).await?;
        let Request::IterateStart {
            rid, zone: None, ..
        } = Request::decode(&b)?
        else {
            return Err(Fault::Malformed.into());
        };
        rid
    };
    record(&mut iteration, rid, b"alpha").await?;
    let b = frame(&mut iteration).await?;
    assert!(matches!(Request::decode(&b)?,Request::IterateNext{rid:r,limit:1}if r==rid));
    record(&mut iteration, rid, b"beta").await?;
    let b = frame(&mut iteration).await?;
    assert!(matches!(Request::decode(&b)?,Request::IterateStop{rid:r}if r==rid));
    eof(&mut iteration).await?;
    let (mut natural, _) = listener.accept().await?;
    let rid = {
        let b = frame(&mut natural).await?;
        let Request::IterateStart {
            rid, zone: Some(_), ..
        } = Request::decode(&b)?
        else {
            return Err(Fault::Malformed.into());
        };
        rid
    };
    send(&mut natural, Response::End { rid }).await?;
    eof(&mut natural).await?;
    let (mut monitor, _) = listener.accept().await?;
    let b = frame(&mut monitor).await?;
    assert!(matches!(
        Request::decode(&b)?,
        Request::MonitorStart {
            iterate_first: 1,
            zone: Some(_),
            ..
        }
    ));
    record(&mut monitor, 0, b"alpha").await?;
    send(&mut monitor, Response::MonitorSync).await?;
    let b = frame(&mut monitor).await?;
    assert!(matches!(
        Request::decode(&b)?,
        Request::MonitorNext {
            limit: 1,
            reserved: 0
        }
    ));
    record(&mut monitor, 0, b"gamma").await?;
    eof(&mut monitor).await?;
    Ok(())
}
async fn done<'id>(
    client: &mut Client<'id>,
    op: Operation<'id>,
    budget: Option<Instant>,
) -> Result<Reply, Failure> {
    loop {
        if let Progress::Completed(c) = client.drive(budget).await? {
            assert_eq!(c.operation, op);
            let Outcome::Reply(reply) = c.outcome else {
                return Err(Fault::Malformed.into());
            };
            return Ok(reply);
        }
    }
}
async fn model() -> Result<(), Failure> {
    let scratch = Scratch::new()?;
    let path = scratch.0.join("s");
    let listener = UnixListener::bind(&path)?;
    let actor = tokio::spawn(actor(listener));
    let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
    let instance = Instance::new();
    let zone = SecretKey::from_serialized(&MOCK)?;
    let limits = Limits {
        io_slice_bytes: 1,
        retirement_grace: Duration::from_secs(2),
        ..Limits::default()
    };
    let until = clock
        .sample()?
        .now
        .as_micros()
        .checked_add(10_000_000)
        .ok_or(Fault::Overflow)?;
    let budget = Some(Instant::now() + Duration::from_secs(11));
    let mut client = Client::new(
        &instance,
        EndpointSource::unix_with_clock(path.clone(), clock.clone()),
        limits,
    )?;
    let sets = [
        StoreSet {
            label: CString::new(b"alpha")?,
            records: Records::empty()?,
            reserved: 0,
        },
        StoreSet {
            label: CString::new(b"beta")?,
            records: Records::empty()?,
            reserved: 0,
        },
    ];
    let stored = client.store_batch(&zone, &sets, true, until)?;
    assert_eq!(stored.sets_sent, 2);
    assert!(matches!(
        done(&mut client, stored.operation, budget).await?.view()?,
        Response::Generic { code: 0, .. }
    ));
    let op = client.lookup(&zone, b"alpha", 0, until)?;
    assert!(matches!(
        done(&mut client, op, budget).await?.view()?,
        Response::Lookup { found: 0, .. }
    ));
    let op = client.zone_to_name(&zone, ZoneKey::new(ZoneKeyType::Edkey, [9; 32]), until)?;
    assert!(matches!(
        done(&mut client, op, budget).await?.view()?,
        Response::ZoneToName {
            code: 5010,
            zone: None,
            label: None,
            ..
        }
    ));
    let op = client.edit_begin(&zone, b"alpha", b"editor", until)?;
    let reply = done(&mut client, op, budget).await?;
    assert!(matches!(
        reply.view()?,
        Response::Edit {
            code: 0,
            hint: None,
            ..
        }
    ));
    assert!(format!("{reply:?}").contains("[REDACTED]"));
    let op = client.edit_cancel(&zone, b"alpha", b"editor", b"", until)?;
    assert!(matches!(
        done(&mut client, op, budget).await?.view()?,
        Response::Generic { code: 5013, .. }
    ));
    let cancelled = client.edit_begin(&zone, b"alpha", b"editor", until)?;
    loop {
        if matches!(
            client.drive(budget).await?,
            Progress::Activity {
                written_bytes: 1,
                ..
            }
        ) {
            break;
        }
    }
    assert_eq!(client.cancel(cancelled)?, Cancellation::Draining);
    loop {
        if let Progress::Completed(c) = client.drive(budget).await? {
            assert_eq!(c.operation, cancelled);
            assert!(matches!(
                c.outcome,
                Outcome::Local {
                    reason: LocalReason::Cancelled,
                    submission: Submission::Written { .. }
                }
            ));
            break;
        }
    }
    loop {
        if matches!(client.drive(budget).await?, Progress::Ignored { .. }) {
            break;
        }
    }
    let unknown = client.store_batch(&zone, &sets, true, until)?.operation;
    loop {
        if let Progress::Completed(c) = client.drive(budget).await? {
            assert_eq!(c.operation, unknown);
            assert!(matches!(
                c.outcome,
                Outcome::Local {
                    reason: LocalReason::Lost,
                    submission: Submission::Written { .. }
                }
            ));
            break;
        }
    }
    let _loss = client.close();
    let mut iter = ZoneIterator::new(
        &instance,
        EndpointSource::unix_with_clock(path.clone(), clock.clone()),
        None,
        0,
        until,
        limits,
    )?;
    loop {
        if let Progress::Record { reply, .. } = iter.drive(budget).await? {
            assert!(matches!(reply.view()?,Response::Records{label,..}if label.bytes()==b"alpha"));
            break;
        }
    }
    assert_eq!(iter.credit(), 0);
    let grant = iter.next(1, until)?;
    assert_eq!(iter.credit(), 0);
    loop {
        if let Progress::ControlWritten {
            control,
            kind: ControlKind::Next { limit: 1 },
            ..
        } = iter.drive(budget).await?
        {
            assert_eq!(control, grant);
            assert_eq!(iter.credit(), 1);
            break;
        }
    }
    loop {
        if let Progress::Record { reply, .. } = iter.drive(budget).await? {
            assert!(matches!(reply.view()?,Response::Records{label,..}if label.bytes()==b"beta"));
            break;
        }
    }
    assert_eq!(iter.credit(), 0);
    let stop = iter.stop(until)?.ok_or(Fault::NotReady)?;
    let mut stop_written = false;
    loop {
        match iter.drive(budget).await? {
            Progress::ControlWritten {
                control,
                kind: ControlKind::Stop,
                ..
            } => {
                assert_eq!(control, stop);
                stop_written = true;
            }
            Progress::Completed(c) => {
                assert!(stop_written);
                assert!(matches!(
                    c.outcome,
                    Outcome::Local {
                        reason: LocalReason::Cancelled,
                        ..
                    }
                ));
                break;
            }
            _ => {}
        }
    }
    assert!(iter.epoch().is_none());
    let mut natural = ZoneIterator::new(
        &instance,
        EndpointSource::unix_with_clock(path.clone(), clock.clone()),
        Some(&zone),
        0,
        until,
        limits,
    )?;
    loop {
        if let Progress::Completed(c) = natural.drive(budget).await? {
            let Outcome::Reply(reply) = c.outcome else {
                return Err(Fault::Malformed.into());
            };
            assert!(matches!(reply.view()?, Response::End { .. }));
            break;
        }
    }
    assert!(natural.epoch().is_none());
    let mut monitor = Monitor::new(
        &instance,
        EndpointSource::unix_with_clock(path, clock),
        Some(&zone),
        true,
        0,
        until,
        limits,
    )?;
    let mut initial = false;
    loop {
        match monitor.drive(budget).await? {
            Progress::Record { .. } => initial = true,
            Progress::Synchronized { .. } => {
                assert!(initial);
                break;
            }
            _ => {}
        }
    }
    assert!(monitor.synchronized());
    assert_eq!(monitor.credit(), 0);
    let grant = monitor.next(1, until)?;
    assert_eq!(monitor.credit(), 0);
    loop {
        if let Progress::ControlWritten { control, .. } = monitor.drive(budget).await? {
            assert_eq!(control, grant);
            assert_eq!(monitor.credit(), 1);
            break;
        }
    }
    loop {
        if let Progress::Record { reply, .. } = monitor.drive(budget).await? {
            assert!(matches!(reply.view()?,Response::Records{label,..}if label.bytes()==b"gamma"));
            break;
        }
    }
    assert_eq!(monitor.credit(), 0);
    let _loss = monitor.stop();
    assert!(!monitor.synchronized());
    loop {
        if let Progress::Completed(c) = monitor.drive(budget).await? {
            assert!(matches!(
                c.outcome,
                Outcome::Local {
                    reason: LocalReason::Closed,
                    ..
                }
            ));
            break;
        }
    }
    actor.await??;
    Ok(())
}
#[test]
fn active_calls_original_sources_and_stream_credit() -> Result<(), Failure> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async { tokio::time::timeout(Duration::from_secs(12), model()).await? })
}
