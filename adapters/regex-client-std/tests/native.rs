//! One controlled real Unix IPC model, not a REGEX/DHT interoperability profile.
//! Synthetic result bytes exercise original paths/cursors/source fencing only.
#![cfg(unix)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "The one bounded native ownership model asserts exact original protocol observations"
)]
use gnunet_regex_client_host::{
    Announcement, AnnouncementRequest, Deadlines, EndCause, EndpointSource, Instance, Limits,
    Progress, RelativeTime, Search, Submission,
    clock::{RuntimeClock, SystemClock},
    ipc::{Request, SearchResult},
};
use gnunet_types::Error as ProtocolError;
use gnunet_wire::official::MessageHeader;
use std::{
    error::Error,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::oneshot,
    time::Instant,
};
type Failure = Box<dyn Error + Send + Sync>;
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Result<Self, Failure> {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let path = std::env::temp_dir().join(format!("grxc-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_dir_all(&self.0);
    }
}
struct FaultClock {
    fail: AtomicBool,
}
impl RuntimeClock for FaultClock {
    fn sample(&self) -> Result<gnunet_regex_client_host::clock::ClockSample, ProtocolError> {
        if self.fail.load(Ordering::SeqCst) {
            Err(ProtocolError::Unavailable)
        } else {
            SystemClock.sample()
        }
    }
    fn subscribe(
        &self,
    ) -> Result<Box<dyn gnunet_regex_client_host::clock::ClockSubscription>, ProtocolError> {
        SystemClock.subscribe()
    }
}
async fn frame(stream: &mut UnixStream) -> Result<Vec<u8>, Failure> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let mut bytes = vec![0; MessageHeader::decode(&header)?.size()];
    bytes[..4].copy_from_slice(&header);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(bytes)
}
fn result(peer: u8, paths: bool) -> Result<Vec<u8>, Failure> {
    let get = [[8; 32]];
    let put = [[9; 32]];
    let response = SearchResult {
        peer: [peer; 32],
        get_path: if paths { &get } else { &[] },
        put_path: if paths { &put } else { &[] },
    };
    let mut bytes = vec![0; response.encoded_len()?];
    response.encode(&mut bytes)?;
    Ok(bytes)
}
async fn actor(listener: UnixListener, resume: oneshot::Receiver<()>) -> Result<(), Failure> {
    let (mut search, _) = listener.accept().await?;
    let bytes = frame(&mut search).await?;
    assert!(
        matches!(Request::decode(&bytes)?, Request::Search { string } if string.bytes() == b"original-search" && string.is_canonical())
    );
    let first = result(7, true)?;
    search.write_all(&first[..5]).await?;
    resume.await?;
    for part in first[5..].chunks(3) {
        search.write_all(part).await?;
    }
    search.write_all(&result(10, false)?).await?;
    drop(search); // EOF must restore the retained search, never report DONE.
    let (mut restored, _) = listener.accept().await?;
    assert_eq!(frame(&mut restored).await?, bytes);
    restored.write_all(&result(13, false)?).await?;
    let mut byte = [0; 1];
    assert_eq!(restored.read(&mut byte).await?, 0); // Cancel fences the replacement MQ.
    let (mut announce, _) = listener.accept().await?;
    let bytes = frame(&mut announce).await?;
    assert!(
        matches!(Request::decode(&bytes)?, Request::Announce { compression: 2, reserved: 0, refresh_delay, regex }
        if refresh_delay == RelativeTime::from_micros(1234) && regex.bytes() == b"public-expression")
    );
    drop(announce); // The original registration must be restored exactly.
    let (mut announce, _) = listener.accept().await?;
    assert_eq!(frame(&mut announce).await?, bytes);
    assert_eq!(announce.read(&mut byte).await?, 0); // Cancellation really closed its own MQ.
    let (mut cancel_between, _) = listener.accept().await?;
    assert!(
        matches!(Request::decode(&frame(&mut cancel_between).await?)?,
        Request::Search { string } if string.bytes() == b"cancel-between-epochs")
    );
    drop(cancel_between);
    let (mut stop_between, _) = listener.accept().await?;
    assert!(matches!(Request::decode(&frame(&mut stop_between).await?)?,
        Request::Announce { regex, .. } if regex.bytes() == b"stop-between-epochs"));
    drop(stop_between);
    // If cancel/stop had reissued either old registration, the next exact
    // frame check would see that stale request instead of this fresh search.
    let (mut partial, _) = listener.accept().await?;
    let mut prefix = [0; 3];
    partial.read_exact(&mut prefix).await?;
    assert_eq!(partial.read(&mut byte).await?, 0); // Never receive/replay the suffix elsewhere.
    let (mut fault, _) = listener.accept().await?;
    let bytes = frame(&mut fault).await?;
    assert!(
        matches!(Request::decode(&bytes)?, Request::Search { string } if string.bytes() == b"fresh-search")
    );
    assert_eq!(fault.read(&mut byte).await?, 0); // Clock refusal independently fenced the MQ.
    // No canceled/completed job or clock failure creates a ninth MQ.
    assert!(
        tokio::time::timeout(Duration::from_millis(20), listener.accept())
            .await
            .is_err()
    );
    Ok(())
}
fn deadlines(clock: &dyn RuntimeClock, search: bool) -> Result<Deadlines, Failure> {
    let now = clock.sample()?.now.as_micros();
    Ok(Deadlines {
        send_until: now.checked_add(2_000_000).ok_or("send overflow")?,
        first_result_until: search.then_some(now.checked_add(3_000_000).ok_or("first overflow")?),
        until: now.checked_add(4_000_000).ok_or("lifetime overflow")?,
    })
}
#[test]
fn original_intent_restores_search_and_announcement_without_renewal() -> Result<(), Failure> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(8), async {
            let scratch = Scratch::new()?;
            let path = scratch.0.join("r");
            let listener = UnixListener::bind(&path)?;
            let clock = Arc::new(FaultClock {
                fail: AtomicBool::new(false),
            });
            let (resume, resumed) = oneshot::channel();
            let actor = tokio::spawn(actor(listener, resumed));
            let limits = Limits {
                io_slice_bytes: 3,
                ..Limits::default()
            };
            let wait = Some(Instant::now() + Duration::from_secs(5));
            let domain = Instance::new();
            let search_targets = deadlines(clock.as_ref(), true)?;
            let mut search = Search::new(
                &domain,
                EndpointSource::unix_with_clock(path.clone(), clock.clone()),
                b"original-search",
                search_targets,
                limits,
            )?;
            let original_job = search.job();
            let mut read = 0;
            let mut original_write = None;
            loop {
                match search.drive(wait).await? {
                    Progress::Queued { write, .. } => original_write = Some(write),
                    Progress::Activity { read_bytes, .. } => read += read_bytes,
                    Progress::WaitDeadline | Progress::Ended(_) => {
                        return Err("partial first input lost".into());
                    }
                    _ => {}
                }
                if read == 5 {
                    break;
                }
            }
            assert!(
                tokio::time::timeout(Duration::from_millis(2), search.drive(None))
                    .await
                    .is_err()
            );
            resume.send(()).map_err(|()| "resume receiver gone")?;
            loop {
                match search.drive(wait).await? {
                    Progress::ResultReady {
                        ordinal: 1, job, ..
                    } => {
                        assert_eq!(job, original_job);
                        break;
                    }
                    Progress::WaitDeadline | Progress::Ended(_) => {
                        return Err("first result lost after canceled wait".into());
                    }
                    _ => {}
                }
            }
            let view = search.result()?.ok_or("missing borrowed result")?;
            assert_eq!(view.result.peer, [7; 32]);
            assert_eq!(view.result.get_path, &[[8; 32]]);
            assert_eq!(view.result.put_path, &[[9; 32]]);
            let owned = search.take_result()?.ok_or("missing owned result")?;
            let original_epoch = owned.view().epoch;
            loop {
                match search.drive(wait).await? {
                    Progress::ResultReady { ordinal: 2, .. } => break,
                    Progress::WaitDeadline | Progress::Ended(_) => {
                        return Err("second result lost".into());
                    }
                    _ => {}
                }
            }
            assert_eq!(
                search.result()?.ok_or("second result absent")?.result.peer,
                [10; 32]
            );
            search.release_result()?;
            loop {
                match search.drive(wait).await? {
                    Progress::SourceLost { end, .. } => {
                        assert!(matches!(end.cause, EndCause::Eof));
                        assert!(matches!(end.submission, Submission::Written { .. }));
                        assert_eq!(end.job, original_job);
                        assert_eq!(end.epoch, Some(original_epoch));
                        assert!(end.queued);
                        assert_eq!(end.write, original_write);
                        assert_eq!(search.next_deadline(), Some(search_targets.until));
                        break;
                    }
                    Progress::WaitDeadline | Progress::Ended(_) => {
                        return Err("EOF restoration lost".into());
                    }
                    _ => {}
                }
            }
            assert!(search.result()?.is_none());
            loop {
                match search.drive(wait).await? {
                    Progress::Queued { job, epoch, write } => {
                        assert_eq!(job, original_job);
                        assert_ne!(epoch, original_epoch);
                        assert_ne!(Some(write), original_write);
                    }
                    Progress::ResultReady {
                        job,
                        epoch,
                        ordinal: 3,
                    } => {
                        assert_eq!(job, original_job);
                        assert_ne!(epoch, original_epoch);
                        assert_eq!(
                            search
                                .result()?
                                .ok_or("restored result absent")?
                                .result
                                .peer,
                            [13; 32]
                        );
                        assert_eq!(owned.view().epoch, original_epoch);
                        search.release_result()?;
                        break;
                    }
                    Progress::WaitDeadline | Progress::Ended(_) => {
                        return Err("restored search result lost".into());
                    }
                    _ => {}
                }
            }
            assert!(matches!(
                search.cancel().ok_or("restored cancel absent")?.cause,
                EndCause::Cancelled
            ));
            assert!(matches!(search.drive(wait).await?, Progress::Closed));

            let announce_targets = deadlines(clock.as_ref(), false)?;
            let mut announce = Announcement::new(
                &domain,
                EndpointSource::unix_with_clock(path.clone(), clock.clone()),
                AnnouncementRequest {
                    regex: b"public-expression",
                    compression: 2,
                    refresh_delay: RelativeTime::from_micros(1234),
                },
                announce_targets,
                limits,
            )?;
            loop {
                match announce.drive(wait).await? {
                    Progress::Submitted { .. } => break, // Sole local write receipt; actor sends no ACK.
                    Progress::WaitDeadline | Progress::Ended(_) => {
                        return Err("announcement local write failed".into());
                    }
                    _ => {}
                }
            }
            let announce_epoch = announce.epoch();
            loop {
                match announce.drive(wait).await? {
                    Progress::SourceLost { end, .. } => {
                        assert!(matches!(end.cause, EndCause::Eof));
                        assert_eq!(end.epoch, announce_epoch);
                        assert!(matches!(end.submission, Submission::Written { .. }));
                        assert_eq!(announce.next_deadline(), Some(announce_targets.until));
                        break;
                    }
                    Progress::WaitDeadline | Progress::Ended(_) => {
                        return Err("announcement restoration lost".into());
                    }
                    _ => {}
                }
            }
            loop {
                match announce.drive(wait).await? {
                    Progress::Submitted { epoch, .. } => {
                        assert_ne!(Some(epoch), announce_epoch);
                        assert_eq!(announce.next_deadline(), Some(announce_targets.until));
                        break;
                    }
                    Progress::WaitDeadline | Progress::Ended(_) => {
                        return Err("restored announcement write lost".into());
                    }
                    _ => {}
                }
            }
            assert!(matches!(
                announce
                    .cancel()
                    .ok_or("announce cancel missing")?
                    .submission,
                Submission::Written { .. }
            ));

            let mut cancel_between = Search::new(
                &domain,
                EndpointSource::unix_with_clock(path.clone(), clock.clone()),
                b"cancel-between-epochs",
                deadlines(clock.as_ref(), true)?,
                limits,
            )?;
            let old = loop {
                match cancel_between.drive(wait).await? {
                    Progress::SourceLost { end, .. } => break end,
                    Progress::WaitDeadline | Progress::Ended(_) => {
                        return Err("cancel-between source loss absent".into());
                    }
                    _ => {}
                }
            };
            assert!(old.retired_mq && old.queued);
            assert!(matches!(old.submission, Submission::Written { .. }));
            let closed = cancel_between
                .cancel()
                .ok_or("cancel-between receipt absent")?;
            assert!(!closed.retired_mq);
            assert_eq!(closed.epoch, old.epoch);
            assert_eq!(closed.submission, old.submission);
            assert_eq!(closed.write, old.write);
            assert!(matches!(
                cancel_between.drive(wait).await?,
                Progress::Closed
            ));

            let mut stop_between = Announcement::new(
                &domain,
                EndpointSource::unix_with_clock(path.clone(), clock.clone()),
                AnnouncementRequest {
                    regex: b"stop-between-epochs",
                    compression: 3,
                    refresh_delay: RelativeTime::from_micros(9876),
                },
                deadlines(clock.as_ref(), false)?,
                limits,
            )?;
            let old = loop {
                match stop_between.drive(wait).await? {
                    Progress::SourceLost { end, .. } => break end,
                    Progress::WaitDeadline | Progress::Ended(_) => {
                        return Err("stop-between source loss absent".into());
                    }
                    _ => {}
                }
            };
            assert!(old.retired_mq && old.queued);
            assert!(matches!(old.submission, Submission::Written { .. }));
            let closed = stop_between
                .stop_after_send()?
                .ok_or("detached stop must close immediately")?;
            assert!(!closed.retired_mq);
            assert_eq!(closed.epoch, old.epoch);
            assert_eq!(closed.submission, old.submission);
            assert_eq!(closed.write, old.write);
            assert!(matches!(stop_between.drive(wait).await?, Progress::Closed));

            let mut partial = Search::new(
                &domain,
                EndpointSource::unix_with_clock(path.clone(), clock.clone()),
                b"canceled-prefix",
                deadlines(clock.as_ref(), true)?,
                limits,
            )?;
            loop {
                match partial.drive(wait).await? {
                    Progress::Activity {
                        written_bytes: 3, ..
                    } => break,
                    Progress::WaitDeadline | Progress::Ended(_) => {
                        return Err("partial write failed".into());
                    }
                    _ => {}
                }
            }
            let cancel = partial.cancel().ok_or("partial cancel missing")?;
            assert!(matches!(
                cancel.submission,
                Submission::Partial { bytes: 3, .. }
            ));
            assert!(matches!(cancel.cause, EndCause::Cancelled));

            let mut fresh = Search::new(
                &domain,
                EndpointSource::unix_with_clock(path, clock.clone()),
                b"fresh-search",
                deadlines(clock.as_ref(), true)?,
                limits,
            )?;
            loop {
                match fresh.drive(wait).await? {
                    Progress::Submitted { .. } => break,
                    Progress::WaitDeadline | Progress::Ended(_) => {
                        return Err("fresh request failed".into());
                    }
                    _ => {}
                }
            }
            assert_ne!(fresh.job(), owned.view().job);
            assert_ne!(fresh.epoch(), Some(owned.view().epoch));
            assert_eq!(owned.view().result.peer, [7; 32]); // Historical result retains the old source.
            clock.fail.store(true, Ordering::SeqCst);
            assert!(matches!(fresh.drive(wait).await?, Progress::Ended(_)));
            actor.await??;
            Ok::<(), Failure>(())
        })
        .await??;
        Ok(())
    })
}
