//! One controlled official Unix IPC model, not a PEERSTORE persistence/C profile.
//! The actor emits only a STORE failure and an unacknowledged loss; no saved
//! success, durable ACK, authenticated peer or backend commit is fabricated.
#![cfg(unix)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Original wire IDs, finite native ownership, real bytes, credit and explicit local outcomes are checked"
)]
use gnunet_peerstore_client_host::{
    Cancel, Client, Command, Filter, Instance, Kind, Limits, Outcome, Progress, Reason, Record,
    RecordPhase, Submission,
    clock::{RuntimeClock, SystemClock},
    ipc::{Envelope, Request, Response},
};
use gnunet_wire::official::MessageHeader;
use std::{error::Error, path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::Instant,
};
type Failure = Box<dyn Error + Send + Sync>;
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Result<Self, Failure> {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let path = std::env::temp_dir().join(format!("gpsc-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_dir_all(&self.0);
    }
}
async fn frame(stream: &mut UnixStream) -> Result<Vec<u8>, Failure> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let size = MessageHeader::decode(&header)?.size();
    let mut bytes = vec![0; size];
    bytes[..4].copy_from_slice(&header);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(bytes)
}
async fn output(stream: &mut UnixStream, response: Response<'_>) -> Result<(), Failure> {
    let mut bytes = vec![0; response.encoded_len()?];
    response.encode(&mut bytes)?;
    for part in bytes.chunks(3) {
        stream.write_all(part).await?;
    }
    Ok(())
}
fn record() -> Record<'static> {
    Record {
        peer: [17; 32],
        expiry: u64::MAX,
        subsystem: Some(b"native-model"),
        key: Some(b"opaque"),
        value: b"ordinary cache bytes",
    }
}
fn filter() -> Filter<'static> {
    Filter {
        peer: Some([17; 32]),
        subsystem: Some(b"native-model"),
        key: Some(b"opaque"),
    }
}
async fn actor(listener: UnixListener) -> Result<(), Failure> {
    let (mut first, _) = listener.accept().await?;
    let request = frame(&mut first).await?;
    let first_rid = match Request::decode(&request)? {
        Request::Store(store) => store.rid,
        _ => return Err("expected actual STORE".into()),
    };
    // Explicit unavailable-storage failure, not fabricated storage success.
    output(
        &mut first,
        Response::StoreResult {
            rid: first_rid,
            result: -1,
        },
    )
    .await?;
    let request = frame(&mut first).await?;
    let lost_rid = match Request::decode(&request)? {
        Request::Store(store) => store.rid,
        _ => return Err("expected second original STORE".into()),
    };
    assert_ne!(first_rid, lost_rid);
    drop(first); // actual complete request, no service result: Unknown, no replay
    let (mut general, _) = listener.accept().await?;
    let request = frame(&mut general).await?;
    let rid = match Request::decode(&request)? {
        Request::IterateStart(start) => start.rid,
        _ => return Err("lost STORE was replayed instead of a fresh iterator".into()),
    };
    assert_ne!(rid, lost_rid);
    output(
        &mut general,
        Response::Record(Envelope {
            rid,
            options: 0,
            reserved: 0,
            record: record(),
        }),
    )
    .await?;
    assert_eq!(
        Request::decode(&frame(&mut general).await?)?,
        Request::IterateNext { rid, limit: 256 }
    );
    output(&mut general, Response::IterateEnd { rid, result: 1 }).await?;
    let request = frame(&mut general).await?;
    let stopped_rid = match Request::decode(&request)? {
        Request::IterateStart(start) => start.rid,
        _ => return Err("fresh cancel iterator start missing".into()),
    };
    assert_eq!(
        Request::decode(&frame(&mut general).await?)?,
        Request::IterateStop { rid: stopped_rid }
    );
    let mut byte = [0; 1];
    assert_eq!(general.read(&mut byte).await?, 0);
    drop(general);
    // Monitor deliberately has its own actual MQ. Each real loss restores the
    // original read-only intent with new credit1 and a fresh initial/SYNC phase.
    let mut previous_start = None;
    for attempt in 0..2 {
        let (mut monitor, _) = listener.accept().await?;
        let start = frame(&mut monitor).await?;
        assert!(
            matches!(Request::decode(&start)?, Request::MonitorStart(start) if start.iterate_first && start.filter == filter())
        );
        if let Some(previous) = &previous_start {
            assert_eq!(previous, &start);
        }
        previous_start = Some(start);
        output(
            &mut monitor,
            Response::Record(Envelope {
                rid: 0,
                options: 0,
                reserved: 0,
                record: record(),
            }),
        )
        .await?;
        assert_eq!(
            Request::decode(&frame(&mut monitor).await?)?,
            Request::MonitorNext { limit: 2 }
        );
        output(&mut monitor, Response::MonitorSync).await?;
        output(
            &mut monitor,
            Response::Record(Envelope {
                rid: 0,
                options: 0,
                reserved: 0,
                record: record(),
            }),
        )
        .await?;
        if attempt == 1 {
            assert_eq!(monitor.read(&mut byte).await?, 0);
        }
        drop(monitor);
    }
    Ok(())
}
#[test]
fn real_original_mqs_failure_no_store_replay_iteration_and_monitor_credit() -> Result<(), Failure> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let scratch = Scratch::new()?;
        let path = scratch.0.join("p");
        let listener = UnixListener::bind(&path)?;
        let server = tokio::spawn(actor(listener));
        let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
        let expires = clock
            .sample()?
            .now
            .as_micros()
            .checked_add(15_000_000)
            .ok_or("deadline overflow")?;
        let source = || {
            gnunet_peerstore_client_host::EndpointSource::unix_with_clock(
                path.clone(),
                clock.clone(),
            )
        };
        let limits = Limits {
            operations: 4,
            io_slice_bytes: 3,
            ..Limits::default()
        };
        let mut instance = Instance::new();
        let mut client = Client::new(&mut instance, source(), limits)?;
        let deadline = Some(Instant::now() + Duration::from_secs(10));
        let first = client.store(record(), 0, expires)?;
        loop {
            match client.drive(deadline).await? {
                Progress::Completed {
                    operation,
                    kind: Kind::Store,
                    outcome: Outcome::StoreResult(result),
                    ..
                } if operation == first => {
                    assert_eq!(result, -1);
                    break;
                }
                Progress::WaitDeadline => return Err("STORE failure reply timed out".into()),
                _ => {}
            }
        }
        let lost = client.store(record(), 1, expires)?;
        let mut physical_loss = false;
        loop {
            match client.drive(deadline).await? {
                Progress::Lost {
                    epoch: Some(_),
                    monitor_retained: false,
                    ..
                } => physical_loss = true,
                Progress::Completed {
                    operation,
                    outcome:
                        Outcome::Local {
                            reason: Reason::Lost,
                            submission: Submission::Unknown,
                        },
                    ..
                } if operation == lost => {
                    assert!(physical_loss);
                    break;
                }
                Progress::WaitDeadline => return Err("original STORE loss timed out".into()),
                _ => {}
            }
        }
        let iterator = client.iterate(filter(), expires)?;
        loop {
            match client.drive(deadline).await? {
                Progress::Record(observation) if observation.operation() == iterator => {
                    assert_eq!(observation.phase(), RecordPhase::Iteration);
                    assert_eq!(observation.record()?.record, record());
                    assert_eq!(client.credit(iterator)?, 0);
                    client.next(iterator, 512)?;
                }
                Progress::Completed {
                    operation,
                    outcome: Outcome::IterationEnd(1),
                    ..
                } if operation == iterator => break,
                Progress::WaitDeadline => return Err("iterator round timed out".into()),
                _ => {}
            }
        }
        let stopped = client.iterate(filter(), expires)?;
        loop {
            match client.drive(deadline).await? {
                Progress::Written {
                    operation,
                    command: Command::Start,
                    ..
                } if operation == stopped => assert_eq!(client.cancel(stopped)?, Cancel::Draining),
                Progress::Completed {
                    operation,
                    outcome:
                        Outcome::Local {
                            reason: Reason::Cancelled,
                            submission: Submission::StopSubmitted,
                        },
                    ..
                } if operation == stopped => break,
                Progress::WaitDeadline => return Err("original STOP submission timed out".into()),
                _ => {}
            }
        }
        let _closed = client.close()?;
        assert_eq!(client.pending(), 0);
        let mut monitor_instance = Instance::new();
        let mut monitor = Client::new_monitor(&mut monitor_instance, source(), limits)?;
        let watched = monitor.monitor(filter(), true, expires)?;
        let mut syncs = 0;
        let mut lives = 0;
        let mut initials = 0;
        let mut previous_epoch = None;
        loop {
            match monitor.drive(deadline).await? {
                Progress::Connected(epoch) => {
                    if let Some(previous) = previous_epoch {
                        assert_ne!(epoch, previous);
                    }
                    previous_epoch = Some(epoch);
                }
                Progress::Record(observation) => {
                    assert_eq!(observation.operation(), watched);
                    assert_eq!(observation.record()?.record, record());
                    match observation.phase() {
                        RecordPhase::Initial => {
                            initials += 1;
                            assert_eq!(monitor.credit(watched)?, 0);
                            monitor.next(watched, 2)?;
                        }
                        RecordPhase::Live => {
                            lives += 1;
                            if lives == 2 {
                                assert_eq!(monitor.cancel(watched)?, Cancel::MonitorClosed);
                                break;
                            }
                        }
                        RecordPhase::Iteration => {
                            return Err("dedicated monitor was rebound to an iterator".into());
                        }
                    }
                }
                Progress::Sync { operation, .. } => {
                    assert_eq!(operation, watched);
                    syncs += 1;
                }
                Progress::Lost {
                    monitor_retained, ..
                } => {
                    assert!(monitor_retained);
                    assert!(monitor.live(watched));
                }
                Progress::WaitDeadline => return Err("monitor reconnect/SYNC timed out".into()),
                _ => {}
            }
        }
        assert_eq!((initials, syncs, lives), (2, 2, 2));
        assert!(!monitor.live(watched));
        assert!(matches!(
            monitor.next_event(),
            Some(Progress::Completed {
                outcome: Outcome::Local {
                    reason: Reason::Cancelled,
                    ..
                },
                ..
            })
        ));
        assert!(matches!(
            monitor.next_event(),
            Some(Progress::Lost {
                monitor_retained: false,
                ..
            })
        ));
        let _closed = monitor.close()?;
        tokio::time::timeout(Duration::from_secs(2), server).await???;
        drop((monitor, client));
        Ok::<_, Failure>(())
    })
}
